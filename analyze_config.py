#!/usr/bin/env python3
"""
Huawei Configuration File Analyzer

This script analyzes encrypted Huawei configuration files to help identify:
- File format and structure
- Potential IV locations
- Encrypted data offsets
- File characteristics

Use this to understand your specific file format before attempting decryption.
"""

import sys
import struct
import base64
from pathlib import Path


def hex_dump(data, length=256, bytes_per_line=16):
    """Pretty print hex dump of data"""
    for i in range(0, min(length, len(data)), bytes_per_line):
        hex_str = ' '.join(f'{b:02x}' for b in data[i:i+bytes_per_line])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+bytes_per_line])
        print(f"  {i:04x}: {hex_str:<48} {ascii_str}")


def analyze_conf_file(file_path):
    """Analyze base64 encoded .conf file"""
    print(f"\n{'='*70}")
    print(f"Analyzing .conf file: {file_path}")
    print(f"{'='*70}\n")
    
    with open(file_path, 'r') as f:
        base64_data = f.read().strip()
    
    print(f"1. File Size (base64): {len(base64_data)} characters")
    
    try:
        decoded = base64.b64decode(base64_data)
        print(f"2. Decoded Size: {len(decoded)} bytes")
        print(f"3. AES Block Alignment: {'✓ Yes' if len(decoded) % 16 == 0 else '✗ No'} (divisible by 16)")
    except Exception as e:
        print(f"ERROR: Failed to decode base64: {e}")
        return
    
    print(f"\n4. First 128 bytes (hex dump):")
    hex_dump(decoded, 128)
    
    # Check for common patterns
    print(f"\n5. Pattern Analysis:")
    
    # Check if it matches DG8045/HG633 format
    if len(decoded) >= 80:
        potential_iv = decoded[48:64]
        print(f"   - Potential IV at offset 0x30 (48-64): {potential_iv.hex()}")
        print(f"   - Data from offset 0x50 (80): {len(decoded[80:])} bytes")
        print(f"     AES aligned: {'✓' if len(decoded[80:]) % 16 == 0 else '✗'}")
    
    # Check for XML markers in plaintext (shouldn't be there if encrypted)
    if b'<?xml' in decoded[:100] or b'<xml' in decoded[:100]:
        print(f"   - ⚠️  Found XML markers - file may not be encrypted!")
    else:
        print(f"   - ✓ No XML markers in header - likely encrypted")
    
    # Entropy check (simple)
    unique_bytes = len(set(decoded[:256]))
    print(f"   - Unique byte values in first 256 bytes: {unique_bytes}/256")
    if unique_bytes > 200:
        print(f"     High entropy - likely encrypted or compressed")
    
    print(f"\n6. Possible Decryption Approaches:")
    print(f"   a) Try AES-256-CBC with IV from offset 0x30, data from 0x50")
    print(f"   b) Try AES-128-CBC with IV from offset 0x30, data from 0x50")
    print(f"   c) Try AES-ECB (no IV) on entire decoded data")
    print(f"   d) Try AES-CBC with static IV on entire decoded data")


def analyze_xml_file(file_path):
    """Analyze binary hw_ctree.xml file"""
    print(f"\n{'='*70}")
    print(f"Analyzing hw_ctree.xml file: {file_path}")
    print(f"{'='*70}\n")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    print(f"1. File Size: {len(data)} bytes")
    
    print(f"\n2. File Header (first 128 bytes):")
    hex_dump(data, 128)
    
    # Parse header fields
    print(f"\n3. Header Field Analysis:")
    
    if len(data) >= 4:
        magic = data[0:4]
        print(f"   - Magic/Signature: {magic.hex()} ({magic})")
    
    if len(data) >= 0x40:
        # Common header locations for Huawei files
        val_30 = struct.unpack('<I', data[0x30:0x34])[0]
        val_34 = struct.unpack('<I', data[0x34:0x38])[0]
        val_38 = struct.unpack('<I', data[0x38:0x3C])[0]
        
        print(f"   - Value at 0x30: 0x{val_30:08x} ({val_30})")
        print(f"   - Value at 0x34: 0x{val_34:08x} ({val_34}) - Potential data offset/size")
        print(f"   - Value at 0x38: 0x{val_38:08x} ({val_38})")
    
    # Look for potential IV locations
    print(f"\n4. Potential IV Locations:")
    for offset in [0x30, 0x40, 0x48, 0x50, 0x60, 0x70]:
        if offset + 16 <= len(data):
            iv_candidate = data[offset:offset+16]
            print(f"   - Offset 0x{offset:02x}: {iv_candidate.hex()}")
    
    # Check different data start offsets
    print(f"\n5. Potential Encrypted Data Start Offsets:")
    for offset in [64, 72, 80, 88, 128, 256, 328]:
        if offset < len(data):
            remaining = len(data) - offset
            aligned = "✓" if remaining % 16 == 0 else "✗"
            print(f"   - Offset {offset:4d} (0x{offset:03x}): {remaining:6d} bytes remaining {aligned}")
    
    # If header indicates an offset
    if len(data) >= 0x38:
        indicated_offset = struct.unpack('<I', data[0x34:0x38])[0]
        if 0 < indicated_offset < len(data):
            print(f"\n   ⚠️  Header at 0x34 indicates offset: {indicated_offset} (0x{indicated_offset:x})")
            remaining = len(data) - indicated_offset
            print(f"      Remaining data: {remaining} bytes, AES aligned: {'✓' if remaining % 16 == 0 else '✗'}")
    
    print(f"\n6. Possible Decryption Approaches:")
    print(f"   a) Try AES-CBC with IV from various offsets (0x30, 0x40, 0x48)")
    print(f"   b) Try AES-ECB from offset indicated in header")
    print(f"   c) Use header-indicated offset for encrypted data start")
    print(f"   d) Try both AES-128 and AES-256")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_config.py <config_file>")
        print("\nAnalyzes Huawei router configuration files to help identify:")
        print("  - File structure and format")
        print("  - Encryption parameters")
        print("  - Potential IV locations")
        print("  - Data offsets")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    # Detect file type
    with open(file_path, 'rb') as f:
        first_bytes = f.read(10)
    
    if first_bytes[0:1].isalpha() or (len(first_bytes) > 0 and all(b in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r' for b in first_bytes)):
        # Likely base64 - .conf file
        analyze_conf_file(file_path)
    else:
        # Binary file - hw_ctree.xml or similar
        analyze_xml_file(file_path)
    
    print(f"\n{'='*70}")
    print("Analysis complete. Use this information to:")
    print("  1. Try different offset combinations with huawei_decrypt.py")
    print("  2. Extract the correct encryption key from your router")
    print("  3. Identify the specific encryption format used")
    print(f"{'='*70}\n")


if __name__ == '__main__':
    main()
