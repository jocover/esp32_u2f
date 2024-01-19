| Supported Targets | ESP32-S2 | ESP32-S3 |
| ----------------- | -------- | -------- |

# ESP32 U2F Security Key.

Turns your cheap ESP32 U2F token.

### Hardware Required

Any ESP board that have USB-OTG supported.

### Flash Example

> **WARNING**
> using erase_flash will lose all stored keys

```
# Erase first 1MB size
esptool erase_region 0x0 0x100000
```

Flash binaries:

esp32s2
bootloader address is 0x1000

```
esptool --chip esp32s2  write_flash --flash_mode dio --flash_size 2MB --flash_freq 80m 0x1000 bootloader/bootloader.bin 0x8000 partition_table/partition-table.bin 0x10000 esp32_u2f.bin
```

esp32s3
bootloader address is 0x0

```
esptool --chip esp32s3  write_flash --flash_mode dio --flash_size 2MB --flash_freq 80m 0x0 bootloader/bootloader.bin 0x8000 partition_table/partition-table.bin 0x10000 esp32_u2f.bin
```

### Tools

[espressif esptool](https://github.com/espressif/esptool/releases)

### License

[GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html)
