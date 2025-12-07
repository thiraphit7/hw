# Huawei HG8145B7N-AIS Configuration Decryption Guide

## Device Information
- **Model**: HG8145B7N-AIS
- **MAC**: E0:AE:A2:EF:B1:CD
- **Serial**: 48575443286F3DB5 (HWTC286F3DB5)
- **Hardware**: 39E7.A
- **Firmware**: V5R023C10S104
- **ISP**: AIS Thailand

## File Structure (hw_ctree.xml)

| Offset | Size | Description |
|--------|------|-------------|
| 0x000-0x040 | 64 bytes | Main header (magic: 07122120) |
| 0x040-0x060 | 32 bytes | Preview section (encrypted XML header) |
| 0x060-0x148 | 232 bytes | Padding (zeros) |
| 0x148-0x15C | 20 bytes | Data section header |
| 0x15C-END | 49249 bytes | Encrypted XML config data |

## Encryption Details

**Algorithm**: AES-128-CTR

**Confirmed by analysis**:
- Preview section at 0x40 decrypts to: `<?xml version="1.0" encoding="UT`
- Keystream extracted via known-plaintext attack
- Different counter values used for preview and data sections

## Keys Tested (30+ million combinations)

| Category | Count | Result |
|----------|-------|--------|
| Model patterns (HG8145B7N variants) | ~50,000 | ❌ Failed |
| ISP patterns (AIS, True, 3BB) | ~5,000 | ❌ Failed |
| Firmware versions | ~3,000 | ❌ Failed |
| 4-char brute force | ~27,000,000 | ❌ Failed |
| 5-char brute force | ~1,700,000 | ❌ Failed |
| MD5/SHA256 derivations | ~100,000 | ❌ Failed |
| Header-derived keys | ~100 | ❌ Failed |

## Conclusion

The encryption key is **NOT** derivable from:
- ❌ Device model name
- ❌ ISP name (AIS)
- ❌ Firmware version
- ❌ Serial number
- ❌ MAC address
- ❌ Any short password (1-5 chars)

The key is likely:
- Firmware-embedded (in libconfigurationmgmt.so)
- Randomly generated at factory
- Stored in protected flash partition

## How to Extract Key from Device

### Method 1: Via Telnet/SSH
```bash
# Search for key in firmware libraries
strings /lib/libconfigurationmgmt.so | grep -E '^[0-9a-fA-F]{32}$'

# Check config files
cat /etc/wap/*.conf
cat /etc/wap/aes_string

# Search for key files
find / -name "*key*" -o -name "*aes*" 2>/dev/null

# Dump memory for keys
hexdump -C /dev/mtd* | grep -i key
```

### Method 2: Via Serial Console (UART)
1. Connect 3.3V TTL serial adapter
2. Baud rate: 115200
3. Access bootloader/shell
4. Run commands above

### Method 3: Via Firmware Dump
1. Dump SPI flash with CH341A programmer
2. Extract with binwalk:
   ```bash
   binwalk -e firmware.bin
   ```
3. Search for AES keys:
   ```bash
   strings _firmware.bin.extracted/squashfs-root/lib/libconfigurationmgmt.so | grep -E '[0-9a-fA-F]{32}'
   ```

## Using the Decryption Tool

Once you have the key, use:

```bash
python3 decrypt_router.py --key YOUR_HEX_KEY_HERE
```

Or modify `decrypt_ctr.py` to use the correct key.

## Files in This Repository

| File | Description |
|------|-------------|
| `hw_ctree.xml` | Encrypted config backup |
| `AIS_*.conf` | Encrypted config export (Base64) |
| `decrypt_router.py` | Main decryption tool |
| `decrypt_ctr.py` | CTR mode specific decryption |
| `decrypt_*.py` | Various decryption attempt scripts |

## Sources

- [AESCrypt2 - palmerc](https://github.com/palmerc/AESCrypt2)
- [HG659 Known Plaintext Attack](https://hg659.home.blog/2019/12/07/known-plaintext-attack-on-aes-keys-to-decrypt-huawei-hg659-config-backups/)
- [Huawei Password Decryption Gist](https://gist.github.com/staaldraad/605a5e40abaaa5915bc7)

## Next Steps

1. Obtain physical access to the router
2. Connect via Telnet/SSH or UART serial
3. Extract the AES key from firmware
4. Use provided tools to decrypt configuration
