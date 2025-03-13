use core::panic;
use std::io::{Read, Write};

use hex_literal::hex;
use libflate::zlib::{Decoder, Encoder};
use num_enum::{FromPrimitive, IntoPrimitive};
use regex::Regex;

#[derive(Debug, FromPrimitive, IntoPrimitive, PartialEq, Eq)]
#[repr(u32)]
enum SectionType {
    Ddr = 1,
    Configuration,
    JumpAddresses,
    EmtService,
    Rom,
    Guid,
    BoardId,
    UserData,
    FirmwareConfiguration,
    ImageInfo,
    DdrZ,
    HashFile,
    #[num_enum(catch_all)]
    Unknown(u32),
}

struct Crc16 {
    crc: u16,
}

impl Crc16 {
    fn new() -> Self {
        Self { crc: 0xffff }
    }

    fn update(&mut self, data: &[u8]) -> &mut Self {
        if data.len() % 4 != 0 {
            panic!("Invalid data length");
        }
        let mut p = 0;
        let mut crc = self.crc as u32;
        while p < data.len() {
            let mut o = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
            for _ in 0..32 {
                if crc & 0x8000 != 0 {
                    crc = (((crc << 1) | (o >> 31)) ^ 0x100b) & 0xffff;
                } else {
                    crc = ((crc << 1) | (o >> 31)) & 0xffff;
                }
                o <<= 1;
            }
            p += 4;
        }

        self.crc = crc as u16;

        self
    }

    fn finalize(self) -> u16 {
        let mut crc = self.crc;
        for _ in 0..16 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x100b;
            } else {
                crc <<= 1;
            }
        }

        crc ^ 0xffff
    }
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc16 = Crc16::new();
    crc16.update(data);
    crc16.finalize()
}

struct Section {
    section_type: SectionType,
    data: Vec<u8>,
}

fn parse_firmware(bytes: &[u8]) -> Vec<Section> {
    if bytes.len() < 0x38 || bytes[0..16] != hex!("4d5446578cdfd000dead92704154beef") {
        panic!("Invalid firmware file");
    }

    if bytes[0x24] != 0 {
        panic!("Not a FS2 file");
    }

    let actual_crc16 = u16::from_be_bytes([bytes[0x22], bytes[0x23]]);

    let expected_crc16 = {
        let mut crc16 = Crc16::new();
        crc16.update(&bytes[0..0x20]);
        crc16.update(&[bytes[0x20], bytes[0x21], 0xff, 0xff]);
        crc16.update(&bytes[0x24..]);
        crc16.finalize()
    };

    if actual_crc16 != expected_crc16 {
        panic!(
            "CRC16 mismatch: expected {:04x}, got {:04x}",
            expected_crc16, actual_crc16
        );
    }

    if bytes[0x28].wrapping_add(bytes[0x29].wrapping_add(bytes[0x2a].wrapping_add(bytes[0x2b])))
        != 0
    {
        panic!("FS_DATA_OFF checksum mismatch");
    }

    let mut sections = Vec::new();
    let mut p = 0x38;
    while p + 16 <= bytes.len() {
        let section_type = SectionType::from(u32::from_be_bytes([
            bytes[p],
            bytes[p + 1],
            bytes[p + 2],
            bytes[p + 3],
        ]));
        let size = u32::from_be_bytes([bytes[p + 4], bytes[p + 5], bytes[p + 6], bytes[p + 7]]);
        let size = if matches!(section_type, SectionType::Unknown(_)) {
            // assume BOOT2
            ((size + 4) * 4) as usize
        } else {
            let size = if section_type == SectionType::EmtService {
                ((size + 3) / 4) * 4
            } else {
                size * 4
            } as usize;

            let actual_crc16 = crc16(&bytes[p..p + 16 + size]);
            let expected_crc16 = u32::from_be_bytes([
                bytes[p + size + 16],
                bytes[p + size + 17],
                bytes[p + size + 18],
                bytes[p + size + 19],
            ]) as u16;
            if actual_crc16 != expected_crc16 {
                panic!(
                    "Section {:?} CRC16 mismatch: expected {:04x}, got {:04x}",
                    section_type, expected_crc16, actual_crc16
                );
            }

            size + 16 + 4
        } as usize;

        sections.push(Section {
            section_type,
            data: bytes[p..p + size].to_vec(),
        });

        p += size;
    }

    sections
}

struct ImageInfo {
    psid: String,
    version: (u16, u16, u16),
}

fn parse_image_info(bytes: &[u8]) -> ImageInfo {
    let psid_bytes = &bytes[60..60 + 16];
    let last_non_zero = psid_bytes.iter().rposition(|&x| x != 0).unwrap();
    let psid = String::from_utf8_lossy(&psid_bytes[0..last_non_zero + 1]).to_string();

    let major = u16::from_be_bytes([bytes[28], bytes[29]]);
    let minor = u16::from_be_bytes([bytes[32], bytes[33]]);
    let patch = u16::from_be_bytes([bytes[34], bytes[35]]);

    ImageInfo {
        psid,
        version: (major, minor, patch),
    }
}

const BASE_ADDR: u32 = 0x0006579C;
fn port_addr(port: u8) -> u32 {
    BASE_ADDR + port as u32 * 132
}

fn patch_ini(ini: &mut Section) -> (Vec<u32>, bool) {
    let mut decompressed = Vec::new();
    let data = &ini.data[16..ini.data.len() - 4];
    Decoder::new(data)
        .unwrap()
        .read_to_end(&mut decompressed)
        .unwrap();

    let original = String::from_utf8_lossy(&decompressed);
    let pattern = Regex::new(r"^\[module(\d+)\]$").unwrap();
    let mut in_module = false;
    let mut has_power_level = false;
    let mut module = None;
    let mut lines = original.split('\n').map(|x| x.trim()).collect::<Vec<_>>();
    let mut i = 0;
    let mut addrs = Vec::new();
    let mut patched = false;
    while i < lines.len() {
        let line = lines[i];

        if line.starts_with("[") {
            if in_module && !has_power_level {
                println!("module[{}] add power level: 5", module.unwrap());
                let mut j = i - 1;
                while j > 0 && lines[j].is_empty() {
                    j -= 1;
                }
                lines.insert(j + 1, "module_power_level_supported=5");
                patched = true;
                i += 1;
            }

            in_module = false;
            module = None;
            has_power_level = false;
        }

        if let Some(caps) = pattern.captures(line) {
            module = Some(caps.get(1).unwrap().as_str().parse::<u8>().unwrap());
        } else if module.is_some() {
            if line == "type=qsfp" {
                in_module = true;
                addrs.push(port_addr(module.unwrap()));
            } else if line.starts_with("module_power_level_supported=") {
                if !line.ends_with("=5") {
                    lines[i] = "module_power_level_supported=5";
                    patched = true;
                }
                has_power_level = true;
            }
        }

        i += 1;
    }

    if patched {
        let mut bytes = vec![0u8; 4 * 4];
        let mut encoder = Encoder::new(&mut bytes).unwrap();
        let patched = lines.join("\n").as_bytes().to_vec();
        encoder.write_all(&patched).unwrap();
        encoder.finish().into_result().unwrap();
        println!("-> {}", bytes.len());
        if bytes.len() % 4 != 0 {
            bytes.resize(bytes.len() + 4 - (bytes.len() % 4), 0);
        }
        let ints = (bytes.len() as u32 - 16) / 4;

        bytes[0..4].copy_from_slice(&u32::from(SectionType::FirmwareConfiguration).to_be_bytes());
        bytes[4..8].copy_from_slice(&ints.to_be_bytes());
        bytes[8..12].copy_from_slice(&0u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&0xFF000000u32.to_be_bytes());

        let crc = crc16(&bytes) as u32;
        bytes.extend_from_slice(&crc.to_be_bytes());
        ini.data = bytes;
    }

    (addrs, patched)
}

fn patch_config(conf: &mut Section, addrs: &[u32]) -> bool {
    let bytes = conf.data.as_mut_slice();
    if (bytes.len() - 16 - 4) % 12 != 0 {
        panic!("Invalid configuration data length");
    }

    let mut patched = false;
    for i in (16..bytes.len() - 4).step_by(12) {
        let addr = u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let value = u32::from_be_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]);
        let mask = u32::from_be_bytes([bytes[i + 8], bytes[i + 9], bytes[i + 10], bytes[i + 11]]);
        if addrs.contains(&addr) && mask == 0xFC3C000F && value == 0x3C000000 {
            bytes[i + 5] = 0x14;
            patched = true;
        }
    }

    if patched {
        let crc = crc16(&bytes[0..bytes.len() - 4]) as u32;
        let len = bytes.len();
        bytes[len - 4..len].copy_from_slice(&crc.to_be_bytes());
    }

    patched
}

fn main() {
    if std::env::args().len() != 3
        || !matches!(
            std::env::args().nth(1).unwrap().as_str(),
            "patch" | "verify"
        )
    {
        println!(
            "Usage: {} <patch|verify> MT_##########.bin",
            std::env::args().next().unwrap()
        );
        return;
    }

    let command = std::env::args().nth(1).unwrap();
    let filename = std::env::args().nth(2).unwrap();

    let bytes = std::fs::read(&filename).unwrap();
    let mut sections = parse_firmware(&bytes);

    let image_info = parse_image_info(&sections.iter().find(|x| x.section_type == SectionType::ImageInfo).unwrap().data);

    println!("PSID:    {}", image_info.psid);
    println!("Version: {}.{}.{}", image_info.version.0, image_info.version.1, image_info.version.2);
    println!();

    let ini = sections
        .iter_mut()
        .find(|x| x.section_type == SectionType::FirmwareConfiguration)
        .unwrap();

    let (addrs, ini_patched) = patch_ini(ini);

    let mut conf_patched = false;
    for conf in sections
        .iter_mut()
        .filter(|x| x.section_type == SectionType::Configuration)
    {
        conf_patched |= patch_config(conf, &addrs);
    }

    if command == "verify" {
        if ini_patched && conf_patched {
            println!("Firmware needs to be patched to enable high power optics on all ports");
        } else if ini_patched {
            println!("High power is enabled on all ports, but the INI should to be patched to reflect this (optional)");
        } else if conf_patched {
            println!("The INI is already patched but the configuration has NOT been patched to enable high power optics on all ports");
            println!();
            println!("Firmware needs to be patched to enable high power optics on all ports");
        } else {
            println!("The firmware is fully patched to enable high power optics on all ports");
        }
    } else if command == "patch" && (ini_patched || conf_patched) {
        let patched_filename = if let Some(last_dot) = filename.rfind('.') {
            format!("{}_patched.bin", &filename[0..last_dot])
        } else {
            format!("{}_patched.bin", filename)
        };
        let mut patched = std::fs::File::create(&patched_filename).unwrap();

        let mut header = bytes[..0x38].to_vec();
        header[0x22] = 0xff;
        header[0x23] = 0xff;

        let mut crc16 = Crc16::new();
        crc16.update(&header[..0x20]);
        crc16.update(&[header[0x20], header[0x21], 0xff, 0xff]);
        crc16.update(&header[0x24..]);
        sections.iter_mut().for_each(|section| {
            crc16.update(&section.data);
        });
        let crc16 = crc16.finalize();

        header[0x22] = (crc16 >> 8) as u8;
        header[0x23] = crc16 as u8;

        patched.write_all(&header).unwrap();

        for section in sections {
            patched.write_all(&section.data).unwrap();
        }

        println!("A patched firmware was created: {}", patched_filename);
    } else {
        println!("A patched fimware was NOT created");
    }
}
