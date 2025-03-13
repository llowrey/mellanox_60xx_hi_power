# Mellanox SX60xx firmware patcher
Mellanox SX6018 and SX6036 only permit high power modules in certain ports. This patcher modifies the firmware to enable high power modules in all ports.

### WARNING
Mellanox probably had a good reason for not enabling high power on all ports. It is possible that loading up your switch with high power modules could damage your switch.

### Usage
Query the firmware to see if it needs to be patched:
```
$ ./mellanox verify MT_1240212020.bin 
PSID:    MT_1240212020
Version: 9.4.5110

Firmware needs to be patched to enable high power optics on all ports
```

Patch the firmware:
```
$ ./mellanox.exe patch MT_1240212020.bin
PSID:    MT_1240212020
Version: 9.4.5110

A patched firmware was created: MT_1240212020_patched.bin
```

Confirm that the patched firmware is good to go:
```
$ ./mellanox.exe verify MT_1240212020_patched.bin
PSID:    MT_1240212020
Version: 9.4.5110

The firmware is fully patched to enable high power optics on all ports
```