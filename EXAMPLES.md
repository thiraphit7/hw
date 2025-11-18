# Usage Examples

This document provides practical examples for using the Huawei router decryption tools.

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Basic Usage

Decrypt a base64 encoded .conf file:
```bash
python3 decrypt_router.py AIS_8806480495_HG8145B7N_20251118_121144.conf
```

Decrypt a binary hw_ctree.xml file:
```bash
python3 decrypt_router.py hw_ctree.xml
```

## Detailed Examples

### Example 1: Decrypt with Custom Output Filename

```bash
python3 decrypt_router.py AIS_8806480495_HG8145B7N_20251118_121144.conf my_router_config.xml
```

### Example 2: Using Specialized Tools

For more control, use the specialized tools:

Decrypt only .conf files:
```bash
python3 decrypt_conf.py router_backup.conf
```

Decrypt only hw_ctree.xml files:
```bash
python3 decrypt_ctree.py hw_ctree.xml
```

### Example 3: Batch Processing

Decrypt multiple configuration files:

```bash
#!/bin/bash
for conf_file in *.conf; do
    echo "Decrypting $conf_file..."
    python3 decrypt_router.py "$conf_file"
done
```

### Example 4: Analyzing Raw Decrypted Data

When automatic decryption fails, the tool saves raw data for analysis:

```bash
# Decrypt the file (may fail with unknown key)
python3 decrypt_router.py config.conf

# Analyze the raw binary output
hexdump -C config_decrypted_raw.bin | less

# Try to extract readable strings
strings config_decrypted_raw.bin > extracted_strings.txt
```

## Expected Output

### Successful Decryption

```
============================================================
Huawei HG8145B7N Router Configuration Decryption Tool
============================================================

[*] Reading file: config.conf
[*] File size: 6080 bytes
[*] Detected base64 encoded file
[*] Base64 decoding...
[+] Decoded 4560 bytes
[*] Attempting decryption with 14 keys...
[*] Trying standard key 1/8 with ECB mode...
[+] Successfully decrypted with key 1 (ECB mode)!
[+] Decrypted file saved to: config_decrypted.xml

[*] Preview:
<?xml version="1.0" encoding="UTF-8"?>
<InternetGatewayDevice>
  <DeviceInfo>
    <Manufacturer>Huawei</Manufacturer>
    ...
  </DeviceInfo>
</InternetGatewayDevice>

============================================================
[+] Decryption completed successfully!
============================================================
```

### Failed Decryption (Unknown Key)

```
============================================================
Huawei HG8145B7N Router Configuration Decryption Tool
============================================================

[*] Reading file: config.conf
[*] File size: 6080 bytes
[*] Detected base64 encoded file
[*] Base64 decoding...
[+] Decoded 4560 bytes
[*] Attempting decryption with 14 keys...
[*] Trying standard key 1/8 with ECB mode...
[*] Trying standard key 1/8 with CBC mode...
...
[*] Trying XOR-based decryption...

[!] No known key produced valid XML
[*] Saving raw AES-decrypted data for analysis...
[*] Raw data saved to: config_decrypted_raw.bin
[*] First 200 bytes (hex): ef7ca5686626cd316c9682090109f2dc...

============================================================
[-] Decryption failed. The file may use an unknown key.
[!] You may need to find the specific encryption key for this device.
============================================================
```

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'Crypto'"

**Solution:**
```bash
pip install pycryptodome
```

### Issue: Decryption fails with all keys

**Possible causes:**
1. Device uses a custom encryption key
2. File is corrupted
3. Different encryption method than expected

**Solutions:**
1. Check the raw decrypted data for patterns
2. Try to obtain the device-specific key from router firmware
3. Search for model-specific decryption tools

### Issue: Permission denied when running scripts

**Solution:**
```bash
chmod +x decrypt_router.py decrypt_conf.py decrypt_ctree.py
```

Or run with python explicitly:
```bash
python3 decrypt_router.py config.conf
```

## Advanced Usage

### Finding Custom Keys

If standard keys don't work, you can modify the `HUAWEI_KEYS` list in `decrypt_router.py`:

```python
HUAWEI_KEYS = [
    b'Z0BSIryhmGWFYL8e',  # Standard key 1
    b'YourCustomKey123',   # Your custom key
    # Add more keys here
]
```

### Understanding the Output

The decrypted XML typically contains:
- Device information (model, serial, firmware version)
- Network configuration (WAN, LAN, DHCP settings)
- Wi-Fi settings (SSID, password, encryption)
- VoIP configuration (if applicable)
- User accounts and passwords
- TR-069 ACS settings

**Remember:** This is sensitive information! Keep it secure.

## Integration Examples

### Python Script Integration

```python
import subprocess
import json

def decrypt_router_config(conf_file):
    """Decrypt Huawei router config and return status"""
    result = subprocess.run(
        ['python3', 'decrypt_router.py', conf_file],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print(f"Successfully decrypted {conf_file}")
        return True
    else:
        print(f"Failed to decrypt {conf_file}")
        return False

# Usage
decrypt_router_config('router_backup.conf')
```

### Shell Script Integration

```bash
#!/bin/bash

CONF_FILE="$1"
OUTPUT_DIR="./decrypted_configs"

mkdir -p "$OUTPUT_DIR"

if python3 decrypt_router.py "$CONF_FILE"; then
    # Move decrypted file to output directory
    mv *_decrypted.xml "$OUTPUT_DIR/"
    echo "Decryption successful! Check $OUTPUT_DIR"
else
    echo "Decryption failed. Check raw data in *_raw.bin"
fi
```

## Performance Notes

- Base64 decoding: Very fast (< 1 second)
- AES decryption: Fast, scales with file size
- Key testing: Multiple keys tested automatically, typically completes in < 30 seconds
- Large files (> 1MB): May take longer but should complete within a minute

## Security Best Practices

1. **Run in a secure environment**: Don't decrypt on shared systems
2. **Delete decrypted files**: After extracting needed information
3. **Use encrypted storage**: If you must keep decrypted files
4. **Don't commit to git**: The .gitignore is configured to prevent this
5. **Verify file integrity**: Compare checksums before/after transfer

## Getting Help

If you encounter issues:
1. Check this examples file
2. Read the main README.md
3. Review the error messages carefully
4. Check the raw output files for patterns
5. Open an issue on GitHub with details
