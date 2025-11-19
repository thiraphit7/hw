# Huawei HG8145B7N Router Configuration Decryption

## Overview

This repository contains research and tools for decrypting configuration files from Huawei HG8145B7N routers (commonly used by AIS Thailand). The tool supports two file formats:

1. **Base64 encoded .conf files** - Configuration backups with AES encryption
2. **Binary hw_ctree.xml files** - Encrypted configuration tree files

## Encryption Methods Research

### Common Encryption Schemes

Based on extensive research of Huawei router configuration encryption, several encryption schemes are used across different models:

#### 1. AES-128-CBC / AES-256-CBC
- **Algorithm**: AES (Advanced Encryption Standard)
- **Mode**: CBC (Cipher Block Chaining)
- **Key Length**: 128-bit or 256-bit
- **Compression**: Usually zlib-compressed before encryption
- **Process**: XML → gzip/zlib compress → AES encrypt → (optional) base64 encode

#### 2. File Structure Variants

**DG8045/HG633/HG630 Format:**
```
[0x00-0x2F] Header (48 bytes)
[0x30-0x3F] IV (16 bytes)  - Dynamic per file
[0x40-0x4F] Additional header
[0x50-EOF]  Encrypted data (AES-256-CBC compressed)
```

**hw_ctree.xml Format:**
```
[0x00-0x07] Magic/signature
[0x08-0x33] Header with metadata
[0x34-0x37] Encrypted data size (little-endian)
[0x38-...]  Variable header
[offset]    Encrypted data starts (offset specified in header)
```

### Known Encryption Keys

**IMPORTANT**: Encryption keys vary by:
- Router model
- ISP customization
- Firmware version
- Regional variants

#### Documented Keys (Hex Format)

| Key | Model/Source | Length |
|-----|--------------|--------|
| `13395537D2730554A176799F6D56A239` | Common ONT, found in `/etc/wap/aes_string` | 128-bit |
| `3E4F5612EF64305955D543B0AE350880` | B593s-22, HG8245 variants | 128-bit |
| `65CE89619D8929CDCF998D42D74C59E3B4E11CFCAE5927760A78E18061D2145C` | DG8045, HG633, HG630 | 256-bit |

#### Common IVs (Initialization Vectors)

| IV | Usage |
|----|-------|
| `8049E91025A6B54876C3B4868090D3FC` | B593s-22 and similar models |
| `9D057CC3E05784F158A972B797E90D3F` | DG8045/HG633 |
| Dynamic (extracted from file at offset 0x30) | DG8045/HG633 format |

### AIS Thailand HG8145B7N Specific Notes

The AIS (Advanced Info Service) customized HG8145B7N routers may use:
- **Custom encryption keys** not publicly documented
- **ISP-specific key derivation** methods
- **Modified file formats** from standard Huawei configurations

To decrypt AIS-specific configurations, you need to:
1. Extract the encryption key from the router's filesystem
2. Access the router via SSH/Telnet (requires admin/root access)
3. Check `/etc/wap/aes_string` or `/online/aes_string` for the key
4. Some keys may be derived from router serial number or MAC address

## Usage

### Basic Usage

```bash
# Decrypt a .conf file with auto-detection
python3 huawei_decrypt.py AIS_8806480495_HG8145B7N_20251118_121144.conf

# Decrypt hw_ctree.xml
python3 huawei_decrypt.py hw_ctree.xml

# Specify output file
python3 huawei_decrypt.py config.conf -o decrypted.xml

# Use a custom encryption key (hex format)
python3 huawei_decrypt.py config.conf -k 13395537D2730554A176799F6D56A239
```

### Finding Your Router's Encryption Key

#### Method 1: Router Filesystem Access
If you have SSH/Telnet access to your router:

```bash
# Common key locations
cat /etc/wap/aes_string
cat /online/aes_string
cat /etc/aescrypt2_key

# Search for aescrypt2 binary and related files
find / -name "*aes*" -type f 2>/dev/null
```

#### Method 2: Firmware Extraction
1. Download the router firmware
2. Extract the firmware image (using binwalk or similar tools)
3. Search for key files or hardcoded keys in binaries
4. Look for `aescrypt2` binary and analyze it

#### Method 3: Network Capture
Monitor the router's update process or backup upload to capture keys in transit (advanced).

## Installation

### Requirements
- Python 3.6+
- pycryptodome library

### Setup

```bash
# Clone the repository
git clone https://github.com/thiraphit7/routerde.git
cd routerde

# Install dependencies
pip3 install -r requirements.txt

# Make the script executable
chmod +x huawei_decrypt.py
```

## File Format Analysis

### .conf File Structure
```
Base64 encoded data containing:
├── [Optional] Header (varies by model)
├── [Optional] IV (16 bytes at specific offset)
├── Encrypted payload (AES-CBC or AES-ECB)
    └── Compressed XML (zlib or gzip)
        └── Configuration XML
            └── [Optional] RSA signature (last 128 bytes)
```

### hw_ctree.xml Structure
```
Binary file containing:
├── File signature/magic bytes
├── Header with offsets and sizes
├── [Optional] Encryption metadata
├── Encrypted data
    └── Compressed XML (zlib)
        └── Configuration tree XML
```

## Decryption Process

The tool attempts decryption using the following strategy:

1. **File Type Detection**
   - Check file extension (.conf or .xml)
   - Examine file content (base64 vs binary)

2. **For .conf Files:**
   - Base64 decode
   - Extract IV if present (DG8045 format at offset 0x30-0x3F)
   - Try AES-CBC with extracted IV
   - Try AES-CBC with known IVs
   - Try AES-ECB mode
   - For each attempt, try both 128-bit and 256-bit keys

3. **For hw_ctree.xml Files:**
   - Parse header to find encrypted data offset
   - Extract potential IV from header region
   - Try AES-CBC with various IV locations
   - Try AES-ECB mode

4. **Post-Decryption:**
   - Attempt zlib decompression
   - Attempt gzip decompression
   - Remove null padding
   - Strip RSA signature if present

## Troubleshooting

### "Failed to decrypt with known keys"

This is the most common issue. Solutions:

1. **Extract the correct key from your router**
   - The tool includes common keys, but your router may use a different one
   - See "Finding Your Router's Encryption Key" above

2. **Try manual key specification**
   ```bash
   python3 huawei_decrypt.py config.conf -k YOUR_HEX_KEY_HERE
   ```

3. **Check if file is encrypted**
   - Some configuration exports may not be encrypted
   - Try opening the file in a text editor to check

### "Base64 decode failed"

- Ensure the file is actually base64 encoded
- Check for file corruption
- Verify you're using the correct file type

### Decryption succeeds but output is garbled

- Wrong key (produces garbage after decryption)
- Missing decompression step
- File may use additional obfuscation (XOR, substitution cipher)

## Security Considerations

- **Legal**: Only decrypt configuration files from routers you own
- **Privacy**: Configuration files contain sensitive information (WiFi passwords, PPPoE credentials, etc.)
- **Warranty**: Accessing router filesystem may void warranty
- **ISP Terms**: May violate terms of service with your ISP

## Research References

### Academic & Technical Resources
- [Decrypt configuration files exactly how Huawei ONT does](https://devilinside.me/blogs/decrypt-configuration-files-exactly-how-huawei-ont-does)
- [Huawei configuration file password encryption - Fayaru](https://blog.fayaru.me/posts/huawei_router_config/)
- [Huawei Config Files - yaleman.org](https://yaleman.org/post/2018/2018-10-01-huawei-config-files/)

### Open Source Tools
- [AESCrypt2](https://github.com/palmerc/AESCrypt2) - AES encryption tool used by Huawei
- [clippit/huawei-hg](https://github.com/clippit/huawei-hg) - Encryption/decryption for HG series
- [DG8045/HG630/HG633 Config Decryption](https://github.com/minanagehsalalma/huawei-dg8045-hg630-hg633-Config-file-decryption-and-password-decode)
- [Ratr - Router Config Extractor](https://jakiboy.github.io/Ratr/) - Web-based tool for Huawei/ZTE

### Community Resources
- [Huawei password utility](https://andreluis034.github.io/huawei-utility-page/) - Password decryption
- [Huawei router password decryption gist](https://gist.github.com/staaldraad/605a5e40abaaa5915bc7)

## Contributing

Contributions welcome! Especially:
- New encryption keys for different models
- Additional file format documentation
- Decryption methods for other Huawei router models

## License

This tool is provided for educational and research purposes. Use responsibly and only on devices you own.

## Disclaimer

This software is provided "as is" without warranty of any kind. The authors are not responsible for any damage or legal issues arising from its use. Always ensure you have proper authorization before attempting to decrypt router configurations.
