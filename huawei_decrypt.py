#!/usr/bin/env python3
"""
Huawei HG8145B7N Router Configuration Decryption Tool

This tool attempts to decrypt Huawei router configuration files using various
known encryption schemes. It supports:
1. Base64 encoded .conf files (AES encrypted, possibly compressed)
2. Binary hw_ctree.xml files (AES encrypted, possibly compressed)

IMPORTANT: This tool requires the correct AES encryption key for your specific
router model and ISP configuration. Keys vary by device and ISP.

Common key locations on router filesystem:
- /etc/wap/aes_string
- /online/aes_string

Based on research from:
- https://devilinside.me/blogs/decrypt-configuration-files-exactly-how-huawei-ont-does
- https://blog.fayaru.me/posts/huawei_router_config/
- https://github.com/palmerc/AESCrypt2
- https://github.com/minanagehsalalma/huawei-dg8045-hg630-hg633-Config-file-decryption-and-password-decode
- https://github.com/clippit/huawei-hg
"""

import sys
import argparse
import base64
import gzip
import zlib
import struct
from pathlib import Path
from Crypto.Cipher import AES


# Known Huawei AES keys (hex format) from various models
# NOTE: Your specific router may use a different key!
DEFAULT_KEYS = [
    # Common ONT keys
    "13395537D2730554A176799F6D56A239",  # Common key found in /etc/wap/aes_string
    "3E4F5612EF64305955D543B0AE350880",  # Alternative key (B593s-22 and others)
    
    # DG8045/HG633/HG630 keys
    "65CE89619D8929CDCF998D42D74C59E3B4E11CFCAE5927760A78E18061D2145C",  # AES-256 key
    
    # Additional documented keys from various models
    "0123456789ABCDEF0123456789ABCDEF",  # Generic test key (some older models)
]

# Known IVs (Initialization Vectors)
DEFAULT_IVS = [
    "8049E91025A6B54876C3B4868090D3FC",  # Common IV
    "9D057CC3E05784F158A972B797E90D3F",  # DG8045/HG633 IV
]


def hex_to_bytes(hex_string):
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_string)


def decrypt_aes_ecb(data, key):
    """Decrypt data using AES ECB mode"""
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)


def decrypt_aes_cbc(data, key, iv):
    """Decrypt data using AES CBC mode"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)


def unpad_pkcs7(data):
    """Remove PKCS7 padding from decrypted data"""
    if len(data) == 0:
        return data
    padding_length = data[-1]
    if padding_length > 16 or padding_length > len(data):
        return data
    # Verify padding
    for i in range(padding_length):
        if data[-(i + 1)] != padding_length:
            return data
    return data[:-padding_length]


def decompress_data(data):
    """Decompress data - try both zlib and gzip"""
    # Try zlib first (more common in Huawei configs)
    try:
        return zlib.decompress(data)
    except Exception:
        pass
    
    # Try gzip
    try:
        return gzip.decompress(data)
    except Exception:
        pass
    
    # Try zlib with negative wbits (raw deflate)
    try:
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except Exception:
        pass
    
    return None


def parse_hw_ctree_header(data):
    """
    Parse hw_ctree.xml binary header
    
    Header structure (approximate):
    - Magic bytes/signature
    - Version info
    - Offsets and sizes
    - Encrypted data starts after header
    """
    if len(data) < 64:
        return None, data
    
    # Check for common signatures
    # Some files have an 8-byte header, some have longer headers
    # Try to detect where encrypted data actually starts
    
    # Try skipping first 8 bytes (common case)
    if data[0:4] == b'\x07\x12\x21\x20':
        # Found potential header signature
        # Look for where actual encrypted data might start
        # Usually after some metadata/header info
        
        # Check offset at position 0x30 (48 decimal)
        if len(data) >= 0x40:
            offset = struct.unpack('<I', data[0x30:0x34])[0]
            if offset > 0 and offset < len(data):
                return data[:offset], data[offset:]
    
    # Default: try skipping first 8 bytes
    return data[:8], data[8:]


def try_decrypt_with_keys(data, keys, ivs=None, use_cbc=False):
    """
    Try to decrypt data with multiple keys
    Returns (decrypted_data, key_used, iv_used) or (None, None, None)
    """
    for key_hex in keys:
        key = hex_to_bytes(key_hex)
        
        if use_cbc and ivs:
            for iv_hex in ivs:
                iv = hex_to_bytes(iv_hex)
                try:
                    decrypted = decrypt_aes_cbc(data, key, iv)
                    decrypted = unpad_pkcs7(decrypted)
                    
                    # Try to decompress
                    decompressed = decompress_data(decrypted)
                    if decompressed and (decompressed.startswith(b'<?xml') or b'<' in decompressed[:100]):
                        return decompressed, key_hex, iv_hex
                except Exception:
                    continue
        else:
            # Try ECB mode
            try:
                decrypted = decrypt_aes_ecb(data, key)
                decrypted = unpad_pkcs7(decrypted)
                
                # Try to decompress
                decompressed = decompress_data(decrypted)
                if decompressed and (decompressed.startswith(b'<?xml') or b'<' in decompressed[:100]):
                    return decompressed, key_hex, None
            except Exception:
                continue
    
    return None, None, None


def decrypt_conf_file(file_path, output_path=None, custom_key=None):
    """
    Decrypt base64 encoded .conf file
    
    Process:
    1. Read file
    2. Base64 decode
    3. Extract IV if present (DG8045 style at bytes 48:64)
    4. AES decrypt (try multiple keys)
    5. Decompress (zlib/gzip)
    6. Output XML
    """
    print(f"Processing .conf file: {file_path}")
    
    # Read and decode base64
    with open(file_path, 'r') as f:
        base64_data = f.read().strip()
    
    try:
        encrypted_data = base64.b64decode(base64_data)
        print(f"Base64 decoded: {len(encrypted_data)} bytes")
    except Exception as e:
        print(f"Error: Failed to decode base64: {e}", file=sys.stderr)
        return False
    
    # Prepare keys to try
    keys = [custom_key] if custom_key else []
    keys.extend(DEFAULT_KEYS)
    
    # Check if this is DG8045/HG633 style with IV at 48:64 and data at 0x50 (80)
    dynamic_ivs = []
    encrypted_payload = encrypted_data
    
    if len(encrypted_data) >= 80:
        # Try extracting IV from bytes 48:64
        potential_iv = encrypted_data[48:64]
        dynamic_ivs.append(potential_iv.hex().upper())
        encrypted_payload_offset = encrypted_data[0x50:]  # Data starts at byte 80
        
        print(f"Detected potential DG8045/HG633 format")
        print(f"Extracted IV from file: {potential_iv.hex()}")
        
        # Try with dynamic IV first
        print("Attempting AES-CBC decryption with extracted IV...")
        decrypted, key_used, iv_used = try_decrypt_with_keys(
            encrypted_payload_offset, keys, dynamic_ivs, use_cbc=True
        )
        
        if decrypted:
            print(f"Success! Decrypted with key: {key_used} and extracted IV")
            # Write output
            if output_path is None:
                output_path = str(file_path).replace('.conf', '_decrypted.xml')
            
            # Remove RSA signature if present (last 128 bytes)
            if len(decrypted) > 128:
                # Check if there's a signature
                potential_sig_start = len(decrypted) - 128
                if b'<?xml' in decrypted[:200]:  # Looks like XML
                    # Try to find the end of XML
                    try:
                        xml_end = decrypted.rindex(b'>')
                        if xml_end < potential_sig_start:
                            # There's extra data after XML, likely signature
                            decrypted = decrypted[:xml_end + 1]
                    except ValueError:
                        pass
            
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            
            print(f"Decrypted configuration saved to: {output_path}")
            print(f"Size: {len(decrypted)} bytes")
            return True
    
    # If DG8045 style didn't work, try standard approaches
    all_ivs = dynamic_ivs + DEFAULT_IVS
    
    # Try ECB mode first with full data
    print("Attempting AES-ECB decryption...")
    decrypted, key_used, _ = try_decrypt_with_keys(encrypted_data, keys, use_cbc=False)
    
    # If ECB failed, try CBC with default IVs
    if not decrypted:
        print("ECB failed, attempting AES-CBC decryption with default IVs...")
        decrypted, key_used, iv_used = try_decrypt_with_keys(encrypted_data, keys, all_ivs, use_cbc=True)
        if decrypted:
            print(f"Success! Decrypted with key: {key_used} and IV: {iv_used}")
    elif decrypted:
        print(f"Success! Decrypted with key: {key_used}")
    
    if not decrypted:
        print("Error: Failed to decrypt file with known keys", file=sys.stderr)
        print("Tips:", file=sys.stderr)
        print("  - Try extracting the AES key from your router's filesystem (/etc/wap/aes_string)", file=sys.stderr)
        print("  - Use -k option to specify a custom key", file=sys.stderr)
        return False
    
    # Write output
    if output_path is None:
        output_path = str(file_path).replace('.conf', '_decrypted.xml')
    
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    
    print(f"Decrypted configuration saved to: {output_path}")
    print(f"Size: {len(decrypted)} bytes")
    
    return True


def decrypt_hw_ctree_file(file_path, output_path=None, custom_key=None):
    """
    Decrypt binary hw_ctree.xml file
    
    Process:
    1. Read file
    2. Parse and skip header
    3. AES decrypt (try multiple keys)
    4. Gunzip
    5. Output XML
    """
    print(f"Processing hw_ctree.xml file: {file_path}")
    
    # Read binary file
    with open(file_path, 'rb') as f:
        data = f.read()
    
    print(f"File size: {len(data)} bytes")
    
    # Parse header
    header, encrypted_data = parse_hw_ctree_header(data)
    if header:
        print(f"Skipped header: {len(header)} bytes")
        print(f"Encrypted data: {len(encrypted_data)} bytes")
    else:
        encrypted_data = data
    
    # Prepare keys to try
    keys = [custom_key] if custom_key else []
    keys.extend(DEFAULT_KEYS)
    
    # Try ECB mode first
    print("Attempting AES-ECB decryption...")
    decrypted, key_used, _ = try_decrypt_with_keys(encrypted_data, keys, use_cbc=False)
    
    # If ECB failed, try CBC
    if not decrypted:
        print("ECB failed, attempting AES-CBC decryption...")
        decrypted, key_used, iv_used = try_decrypt_with_keys(encrypted_data, keys, DEFAULT_IVS, use_cbc=True)
        if decrypted:
            print(f"Success! Decrypted with key: {key_used} and IV: {iv_used}")
    elif decrypted:
        print(f"Success! Decrypted with key: {key_used}")
    
    if not decrypted:
        print("Error: Failed to decrypt file with known keys", file=sys.stderr)
        return False
    
    # Write output
    if output_path is None:
        output_path = str(file_path).replace('.xml', '_decrypted.xml')
        if output_path == str(file_path):  # If no .xml extension
            output_path = str(file_path) + '_decrypted.xml'
    
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    
    print(f"Decrypted configuration saved to: {output_path}")
    print(f"Size: {len(decrypted)} bytes")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Huawei HG8145B7N Router Configuration Decryption Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt a .conf file
  python3 huawei_decrypt.py config.conf
  
  # Decrypt hw_ctree.xml file
  python3 huawei_decrypt.py hw_ctree.xml
  
  # Specify output file
  python3 huawei_decrypt.py config.conf -o decrypted.xml
  
  # Use custom AES key
  python3 huawei_decrypt.py config.conf -k 13395537D2730554A176799F6D56A239
        """
    )
    
    parser.add_argument('input_file', help='Input file (.conf or hw_ctree.xml)')
    parser.add_argument('-o', '--output', help='Output file path (default: auto-generated)')
    parser.add_argument('-k', '--key', help='Custom AES key in hex format')
    parser.add_argument('-t', '--type', choices=['conf', 'xml', 'auto'], default='auto',
                       help='File type (default: auto-detect)')
    
    args = parser.parse_args()
    
    input_file = Path(args.input_file)
    
    if not input_file.exists():
        print(f"Error: File not found: {input_file}", file=sys.stderr)
        return 1
    
    # Auto-detect file type
    file_type = args.type
    if file_type == 'auto':
        if input_file.suffix.lower() == '.conf':
            file_type = 'conf'
        elif 'ctree' in input_file.name.lower() or input_file.suffix.lower() == '.xml':
            file_type = 'xml'
        else:
            # Try to detect by reading first bytes
            with open(input_file, 'rb') as f:
                first_bytes = f.read(100)
                if first_bytes[0:1].isalpha() or first_bytes[0:10].isalnum():
                    file_type = 'conf'  # Likely base64
                else:
                    file_type = 'xml'  # Likely binary
    
    print(f"Detected file type: {file_type}")
    print()
    
    # Decrypt based on file type
    if file_type == 'conf':
        success = decrypt_conf_file(input_file, args.output, args.key)
    else:
        success = decrypt_hw_ctree_file(input_file, args.output, args.key)
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
