# Huawei HG8145B7N Router Configuration Decryption Tool

A research-based decryption tool for Huawei HG8145B7N router configuration files, specifically for AIS Thailand routers.

## 🎯 Purpose

This tool attempts to decrypt configuration files from Huawei HG8145B7N routers using various known encryption methods. It supports:

1. **Base64 encoded `.conf` files** - Configuration backups with AES encryption
2. **Binary `hw_ctree.xml` files** - Encrypted configuration tree files

## ⚠️ Important Note

**The encryption key varies by router model, ISP, and firmware version.** This tool includes commonly documented keys, but your specific router may require a custom key extracted from the device filesystem (typically found at `/etc/wap/aes_string`).

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
pip3 install -r requirements.txt

# Make script executable
chmod +x huawei_decrypt.py
```

### Usage

```bash
# Decrypt a .conf file
python3 huawei_decrypt.py AIS_8806480495_HG8145B7N_20251118_121144.conf

# Decrypt hw_ctree.xml
python3 huawei_decrypt.py hw_ctree.xml

# Use custom encryption key (hex format)
python3 huawei_decrypt.py config.conf -k 13395537D2730554A176799F6D56A239

# Specify output file
python3 huawei_decrypt.py config.conf -o decrypted.xml
```

## 📚 Documentation

For detailed research findings, encryption methods, and troubleshooting:
- **[DECRYPTION_RESEARCH.md](DECRYPTION_RESEARCH.md)** - Comprehensive encryption method documentation
- **[KEY_EXTRACTION_GUIDE.md](KEY_EXTRACTION_GUIDE.md)** - Detailed guide for extracting AES keys (NEW!)
- **[DECRYPTION_METHODS_SUMMARY.md](DECRYPTION_METHODS_SUMMARY.md)** - Research findings summary

## 🔑 Finding Your Encryption Key

If decryption fails with default keys, you need to extract the key from your router.

**See the comprehensive [KEY_EXTRACTION_GUIDE.md](KEY_EXTRACTION_GUIDE.md) for 5 detailed methods:**

1. **Direct Filesystem Access** (SSH/Telnet - Recommended)
2. **Firmware Analysis** (Extract from firmware file)
3. **Memory Dump Analysis** (Advanced - UART access)
4. **Network Traffic Capture** (During backup operations)
5. **Community Tools** (Automated extraction scripts)

### Quick Method (SSH/Telnet):
```bash
# Connect to router
telnet 192.168.1.1
# Login with: telecomadmin / (check router label)

# Extract key
cat /etc/wap/aes_string
cat /online/aes_string
```

## 🛠️ Features

- ✅ Supports multiple AES encryption modes (ECB, CBC)
- ✅ Handles both 128-bit and 256-bit AES keys
- ✅ Automatic IV (Initialization Vector) extraction from file
- ✅ Multiple decompression methods (zlib, gzip)
- ✅ Base64 decoding for .conf files
- ✅ Binary header parsing for hw_ctree.xml
- ✅ Auto-detection of file type
- ✅ Comprehensive error messages and troubleshooting hints

## 📋 Requirements

- Python 3.6 or higher
- pycryptodome library

## ⚖️ Legal & Ethics

- ✅ Only use on routers you own
- ✅ Respect privacy of configuration data
- ⚠️ May void warranty or violate ISP terms of service
- ⚠️ Use responsibly and legally

## 🤝 Contributing

Contributions welcome! Especially:
- New encryption keys for different models/ISPs
- Additional file format documentation  
- Decryption methods for other Huawei models

## 📖 References

Based on research from:
- [Decrypt configuration files exactly how Huawei ONT does](https://devilinside.me/blogs/decrypt-configuration-files-exactly-how-huawei-ont-does)
- [AESCrypt2 GitHub](https://github.com/palmerc/AESCrypt2)
- [Huawei configuration file encryption research](https://blog.fayaru.me/posts/huawei_router_config/)
- Various open-source Huawei decryption tools and community research

## 📄 License

Educational and research purposes only. See disclaimer in [DECRYPTION_RESEARCH.md](DECRYPTION_RESEARCH.md#disclaimer).


