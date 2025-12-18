# AES Key Extraction Guide for Huawei HG8145B7N

## Overview

This guide provides detailed methods for extracting the AES encryption key from your Huawei HG8145B7N router. **The key is required to decrypt configuration files** and is stored on the device itself.

## ⚠️ Important Notes

- Keys are **device and ISP-specific** - AIS Thailand routers use custom keys
- You must have **legitimate access** to your own router
- Key extraction requires **admin/root privileges**
- For research and backup purposes only

---

## Method 1: Direct Filesystem Access (Recommended)

### Requirements:
- SSH or Telnet access to your router
- Admin credentials (default: `telecomadmin` / password varies)
- Root access (may require privilege escalation)

### Steps:

#### 1.1 Access Router via SSH/Telnet

```bash
# SSH (if enabled)
ssh telecomadmin@192.168.1.1

# Or Telnet (often enabled by default)
telnet 192.168.1.1
```

**Common AIS Router Credentials:**
- Username: `telecomadmin` or `admin`
- Password: Often printed on router label or `nE7jA%5m` (varies)

#### 1.2 Locate AES Key File

Once logged in, try these commands:

```bash
# Primary location (most common)
cat /etc/wap/aes_string

# Alternative locations
cat /online/aes_string
cat /etc/aescrypt2_key
cat /mnt/jffs2/aes_string

# Search all possible locations
find / -name "*aes*" -type f 2>/dev/null
find / -name "aescrypt*" 2>/dev/null
```

#### 1.3 Copy the Key

The key will be displayed as a **hexadecimal string** (32 or 64 characters).

Example output:
```
65CE89619D8929CDCF998D42D74C59E3B4E11CFCAE5927760A78E18061D2145C
```

**Save this key** - you'll use it with the decryption tool.

---

## Method 2: Firmware Analysis

If you cannot access the router directly, you can extract the key from firmware.

### Requirements:
- Firmware file for your router model
- `binwalk` tool
- `strings` and `grep` utilities

### Steps:

#### 2.1 Download Firmware

**Option A:** From manufacturer:
```bash
# Check Huawei support site for HG8145B7N firmware
# AIS-specific firmware may be on AIS support pages
```

**Option B:** Extract from router (if you have access):
```bash
# On router, find firmware partition
cat /proc/mtd

# Common firmware location
dd if=/dev/mtdblock2 of=/tmp/firmware.bin
# Transfer file to your computer via SCP/SFTP
```

#### 2.2 Extract Firmware

```bash
# Install binwalk
sudo apt-get install binwalk

# Extract firmware
binwalk -e firmware.bin
cd _firmware.bin.extracted
```

#### 2.3 Search for AES Key

```bash
# Search for aes_string file
find . -name "*aes*" -type f

# Search for key in configuration files
grep -r "aes" . --include="*.conf" --include="*.cfg"

# Look for aescrypt2 binary
find . -name "aescrypt*"

# Search for hex strings (keys are typically 32 or 64 hex chars)
strings * | grep -E '^[0-9A-F]{32,64}$'
```

#### 2.4 Analyze aescrypt2 Binary

If you find the `aescrypt2` binary:

```bash
# Extract strings that might be keys
strings aescrypt2 | grep -E '^[0-9A-F]{32,64}$'

# Use a disassembler (advanced)
objdump -d aescrypt2 | less
# or
ghidra aescrypt2  # Using Ghidra reverse engineering tool
```

---

## Method 3: Memory Dump Analysis (Advanced)

For experienced users with physical access to the device.

### Requirements:
- UART/JTAG access to router
- Memory dump tools
- Python 3 with analysis scripts

### Community Tools:

**GitHub Project:** [huawei_router_aes_keys](https://github.com/jameskeenan295/huawei_router_aes_keys)

This project provides scripts to extract keys from memory dumps:

```bash
# Clone the repository
git clone https://github.com/jameskeenan295/huawei_router_aes_keys.git
cd huawei_router_aes_keys

# Use with your memory dump
python3 find_config_keys_from_memdump.py <memory_dump_file>
```

### UART Access:

1. Open router case (voids warranty)
2. Locate UART pins (usually labeled TX, RX, GND, VCC)
3. Connect UART adapter (3.3V TTL)
4. Use terminal software (minicom, PuTTY) at 115200 baud
5. Interrupt boot process to access bootloader
6. Dump memory or filesystem

---

## Method 4: Network Traffic Analysis

### Requirements:
- Wireshark or tcpdump
- Router performing backup/restore operation

### Steps:

1. **Capture traffic during config backup:**
   ```bash
   # Start packet capture
   sudo tcpdump -i eth0 -w router_traffic.pcap host 192.168.1.1
   ```

2. **Trigger backup/restore operation** from router web interface

3. **Analyze captured traffic:**
   ```bash
   # Open in Wireshark
   wireshark router_traffic.pcap
   
   # Search for:
   # - HTTP POST/GET to config backup endpoints
   # - Base64 encoded data
   # - Potential key transmission (rare, but possible)
   ```

4. **Look for unencrypted key transmission** (uncommon but check firmware update traffic)

---

## Method 5: Social Engineering / ISP Support (Least Recommended)

### Approach:
- Contact AIS technical support
- Explain you need the decryption key for legitimate backup purposes
- Provide router serial number and account verification

**Success Rate:** Very low - ISPs typically don't share encryption keys

---

## Using the Extracted Key

Once you have the key, use it with the decryption tool:

```bash
# Decrypt .conf file
python3 huawei_decrypt.py config.conf -k YOUR_HEX_KEY_HERE

# Example with actual key
python3 huawei_decrypt.py AIS_config.conf -k 65CE89619D8929CDCF998D42D74C59E3B4E11CFCAE5927760A78E18061D2145C
```

---

## Key Format Verification

Valid AES keys are hexadecimal strings:

- **AES-128:** 32 hex characters (16 bytes)
  - Example: `13395537D2730554A176799F6D56A239`
  
- **AES-256:** 64 hex characters (32 bytes)
  - Example: `65CE89619D8929CDCF998D42D74C59E3B4E11CFCAE5927760A78E18061D2145C`

**Valid characters:** 0-9, A-F (uppercase or lowercase)

---

## Troubleshooting

### Issue: "Permission Denied" when accessing files

```bash
# Try with sudo (if available)
sudo cat /etc/wap/aes_string

# Or escalate privileges
su root
# Then try accessing the file
```

### Issue: File not found

```bash
# The key might be in a different location
# Search entire filesystem (takes time)
find / -type f -exec grep -l "aes" {} \; 2>/dev/null

# Check if aescrypt2 binary exists
which aescrypt2
```

### Issue: SSH/Telnet access disabled

1. Check router documentation for enabling SSH/Telnet
2. Some routers require web interface configuration
3. Try default Telnet port (23) and SSH port (22)
4. Check if router has "Developer Mode" or "Debug Mode"

### Issue: Extracted key doesn't work

1. **Verify key format:** Ensure it's pure hex (no spaces, newlines)
2. **Check key length:** Should be 32 or 64 characters
3. **Try different keys:** Router might have multiple keys
4. **Verify file format:** Ensure config file isn't corrupted

---

## Known Key Locations by Firmware Version

Based on community research:

| Firmware Version | Key Location | Notes |
|------------------|--------------|-------|
| V3R017C00S115 | `/etc/wap/aes_string` | Standard location |
| V3R017C10S205 | `/etc/wap/aes_string` | Standard location |
| V5R020C00S125 | `/mnt/jffs2/aes_string` | Newer firmware |
| Custom AIS | `/online/aes_string` | AIS-specific builds |

---

## Security & Legal Considerations

### ✅ Legitimate Uses:
- Backing up your own router configuration
- Recovering from failed configuration
- Security research on devices you own
- Educational purposes

### ❌ Do Not:
- Extract keys from routers you don't own
- Share extracted keys publicly
- Use keys to access others' configurations
- Violate ISP terms of service

### Legal Notice:
This guide is for **educational and legitimate backup purposes only**. Unauthorized access to network devices or decryption of others' configurations may violate computer fraud laws in your jurisdiction.

---

## Additional Resources

### Community Projects:
1. **Huawei Router AES Keys Extraction**
   - https://github.com/jameskeenan295/huawei_router_aes_keys
   - Memory dump analysis tools

2. **Huawei Config Decryption (DG8045/HG633)**
   - https://github.com/minanagehsalalma/huawei-dg8045-hg630-hg633-Config-file-decryption-and-password-decode
   - Alternative decryption methods

3. **AESCrypt2 Emulation**
   - https://devilinside.me/blogs/decrypt-configuration-files-exactly-how-huawei-ont-does
   - Detailed technical analysis

### Tools:
- **binwalk:** Firmware analysis and extraction
- **Ghidra:** Reverse engineering (NSA's tool)
- **IDA Pro:** Professional disassembler
- **Wireshark:** Network traffic analysis
- **minicom/PuTTY:** UART terminal access

---

## FAQ

**Q: Can I brute-force the AES key?**  
A: No. AES-256 is cryptographically secure. Brute-forcing would take billions of years with current technology.

**Q: Are there universal keys that work for all AIS routers?**  
A: No. Each router or firmware version may use different keys. ISPs often customize keys.

**Q: Will extracting the key void my warranty?**  
A: Accessing the router via SSH/Telnet: Usually no. Opening the case for UART access: Yes.

**Q: Can AIS detect if I've extracted the key?**  
A: Simply reading files via SSH is unlikely to be detected. Modifying configurations may be logged.

**Q: Is this legal?**  
A: Extracting keys from your own device for backup purposes is generally legal. Check your local laws and ISP terms of service.

---

## Success Stories & Tips

### Reported Working Methods (Community):

1. **Telnet + Default Password (Most Common)**
   - Access via Telnet to 192.168.1.1
   - Username: `telecomadmin`
   - Check router label for password
   - Navigate to `/etc/wap/aes_string`

2. **Web Interface Debug Mode**
   - Some users report finding keys in web interface debug logs
   - Access router admin panel
   - Look for "System Log" or "Debug Information"
   - Search logs for "aes" or "key"

3. **Firmware Update Files**
   - ISP firmware updates sometimes contain keys
   - Download AIS firmware update file
   - Extract and analyze contents

---

## Contact & Contributions

If you successfully extract a key or find new methods:

1. Document your method (without sharing the actual key)
2. Contribute to the repository with improved documentation
3. Help others in the community (without compromising security)

**Repository:** https://github.com/thiraphit7/routerde

---

**Last Updated:** 2024-12-18  
**Status:** Active Research - Community Contributions Welcome
