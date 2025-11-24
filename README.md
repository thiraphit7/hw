# Huawei Router Configuration Decryptor

This repository contains tools to decrypt Huawei HG8145B7N router configuration files from AIS.

## 📁 Files

- **AIS_8806480495_HG8145B7N_20251118_121144.conf** - Router configuration file (Base64-encoded, AES-encrypted)
- **hw_ctree.xml** - Corrupted binary file (not usable - damaged from opening in text editor)
- **decrypt_router_config.py** - Python script to extract Base64 and decode to binary

## 🔓 Decryption Process

The router configuration is protected by **two layers of encryption**:

```
[HTML/conf file] → [Base64 encoding] → [AES encryption] → [XML configuration]
```

### Step 1: Extract Base64 and Decode (This Script)

Use the provided Python script to extract and decode the Base64 data:

```bash
python decrypt_router_config.py AIS_8806480495_HG8145B7N_20251118_121144.conf
```

This will create a `.bin` file that is still AES-encrypted.

**Optional**: Specify custom output filename:
```bash
python decrypt_router_config.py AIS_8806480495_HG8145B7N_20251118_121144.conf my_router_config.bin
```

### Step 2: Decrypt AES (External Tool Required)

The `.bin` file from Step 1 is still encrypted with AES. You need to use a specialized tool:

1. **Download** a Huawei Router Config Decrypter tool:
   - Search for `huawei-config-utility` or `huawei_xml_decrypt` on GitHub
   - Example: [Huawei Config Decryptor](https://github.com/search?q=huawei+config+decrypt)

2. **Decrypt** the `.bin` file using one of these keys:
   - `$HuaweiHg8245Q`
   - Empty/null key
   - Model-specific keys for HG8245Q/HG8145B7N

3. **Extract** credentials from the resulting XML file:
   - **Internet username/password**: Look for `<WANPPPConnection>` tags
   - **WiFi password**: Look for `<WLANConfiguration>` tags with `PreSharedKey`

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/thiraphit7/routerde.git
cd routerde

# Run the decryption script
python decrypt_router_config.py AIS_8806480495_HG8145B7N_20251118_121144.conf

# Follow the on-screen instructions for Step 2
```

## 📋 Requirements

- Python 3.x (standard library only - no external dependencies)
- For Step 2: Huawei Router Config Decrypter tool (separate download)

## ⚠️ Important Notes

- **File 1** (AIS conf): ✅ Usable - Contains complete configuration data
- **File 2** (hw_ctree.xml): ❌ Damaged - Do not use (corrupted from text editor)
- The script only performs Base64 decoding (Step 1)
- AES decryption (Step 2) requires a separate specialized tool
- Keep your router credentials secure after extraction

## 📖 How It Works

1. **Base64 Extraction**: The script searches for Base64-encoded data in the HTML/conf file
2. **Decoding**: Converts the Base64 string to binary data
3. **Output**: Saves the binary data as a `.bin` file (still AES-encrypted)
4. **Next Step**: User must decrypt the AES layer using external tools

## 🔐 Security Notice

This tool is for legitimate router configuration backup and recovery purposes only. Always:
- Keep your router credentials secure
- Change default passwords
- Use strong WiFi encryption
- Only decrypt your own router configurations

