# Huawei HG8145B7N Router Decryption Tool

This repository contains tools to decrypt configuration files from Huawei HG8145B7N routers, specifically:
- Base64 encoded `.conf` files (e.g., `AIS_8806480495_HG8145B7N_20251118_121144.conf`)
- Binary encrypted `hw_ctree.xml` files

## Features

- **Auto-detection**: Automatically detects file type (base64 or binary)
- **Multiple encryption methods**: Supports AES (ECB/CBC modes) and XOR decryption
- **Device-specific keys**: Generates potential keys from device serial numbers and model information
- **Comprehensive key database**: Includes known Huawei encryption keys
- **Raw data export**: Saves raw decrypted data for manual analysis when automatic decryption fails

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or manually install:

```bash
pip install pycryptodome
```

## Usage

### Unified Decryption Tool (Recommended)

The `decrypt_router.py` script automatically detects the file type and attempts decryption:

```bash
python3 decrypt_router.py <input_file> [output_file]
```

**Examples:**

```bash
# Decrypt .conf file (auto-detects output filename)
python3 decrypt_router.py AIS_8806480495_HG8145B7N_20251118_121144.conf

# Decrypt hw_ctree.xml file
python3 decrypt_router.py hw_ctree.xml

# Specify custom output filename
python3 decrypt_router.py config.conf my_decrypted_config.xml
```

### Specialized Tools

#### For Base64 .conf Files

```bash
python3 decrypt_conf.py <input_conf_file> [output_file]
```

#### For Binary hw_ctree.xml Files

```bash
python3 decrypt_ctree.py <input_xml_file> [output_file]
```

## How It Works

### Base64 .conf Files

1. **Base64 Decoding**: The tool first decodes the base64-encoded content
2. **AES Decryption**: Attempts AES decryption (ECB and CBC modes) with known keys
3. **XOR Decryption**: Falls back to XOR-based decryption if AES fails
4. **Validation**: Checks if the decrypted data contains valid XML patterns

### Binary hw_ctree.xml Files

1. **Header Parsing**: Identifies Huawei hw_ctree.xml format (magic: `0x07122120`)
2. **Data Extraction**: Extracts encrypted data from offset 64 (after header)
3. **Decryption Attempts**: Tries multiple encryption methods and keys
4. **Validation**: Verifies the output is valid XML configuration

## Encryption Keys

The tool includes several known Huawei encryption keys and also attempts to generate device-specific keys from:
- Device serial number
- Router model number
- Filename metadata

### Supported Keys

- Standard Huawei keys (Z0BSIryhmGWFYL8e, Wj-lIdpEoH1kOiJ0, etc.)
- Model-specific keys
- Device serial-based keys (MD5/SHA256 derived)

## Output Files

### Successful Decryption

When decryption succeeds:
- Output file: `<input_name>_decrypted.xml`
- Contains the decrypted XML configuration
- Preview is shown in console

### Failed Decryption

When automatic decryption fails:
- Raw data file: `<input_name>_decrypted_raw.bin`
- Contains raw AES-decrypted bytes for manual analysis
- First 200 bytes shown as hex dump in console

## Troubleshooting

### "No known key produced valid XML"

This means the automatic decryption didn't find the correct key. Options:

1. **Check raw decrypted data**: Look at the `_raw.bin` file for patterns
2. **Find device-specific key**: The encryption key might be unique to your device
3. **Try alternative tools**: Some devices may use custom encryption

### "Error decoding base64"

The .conf file might not be base64 encoded. Try:
- Verify the file is correct and not corrupted
- Check if it's already in a different format

### File Format Not Recognized

Ensure you're using the correct file:
- `.conf` files should be base64-encoded text
- `hw_ctree.xml` files should be binary with Huawei header

## Security Note

⚠️ **Warning**: Decrypting router configuration files may expose sensitive information including:
- Wi-Fi passwords
- Admin credentials
- ISP settings
- Private network configuration

**Keep decrypted files secure and never share them publicly.**

### About Weak Cryptographic Algorithms

This tool intentionally uses weak cryptographic algorithms (AES-ECB and AES-CBC with zero IV) because these are the algorithms used by Huawei routers to encrypt their configuration files. We are **decrypting** existing data, not encrypting new data. This is a legitimate use case for:
- Security research
- Device administration
- Data recovery
- Forensic analysis

The tool does not introduce new security vulnerabilities; it only works with the encryption methods already in use by the devices.

## Example Files

This repository includes example encrypted files for testing:
- `AIS_8806480495_HG8145B7N_20251118_121144.conf` - Base64 encoded configuration
- `hw_ctree.xml` - Binary encrypted configuration tree

## Contributing

If you have additional encryption keys or improvements to the decryption algorithms, please:
1. Test thoroughly with your specific router model
2. Document the key source and applicable models
3. Submit a pull request

## Disclaimer

This tool is for educational and legitimate administrative purposes only. Users are responsible for:
- Having proper authorization to decrypt configuration files
- Complying with local laws and regulations
- Securing sensitive information obtained through decryption

## License

This project is provided as-is for educational purposes.

## Support

For issues specific to:
- **Huawei HG8145B7N**: Check device documentation
- **AIS Thailand routers**: Contact ISP support
- **Tool bugs**: Open an issue in this repository

