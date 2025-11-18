#!/usr/bin/env python3
"""
Huawei HG8145B7N Router hw_ctree.xml Decryption Tool
Decrypts binary encrypted hw_ctree.xml files
"""

import sys
import struct
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Known Huawei encryption keys
HUAWEI_KEYS = [
    b'Z0BSIryhmGWFYL8e',  # Common key 1
    b'Wj-lIdpEoH1kOiJ0',  # Common key 2
    b'0I8U7o+500qE0I8U7o+500qE',  # 24-byte key
    b'pD@hU6nW$rE%tY^u',  # Alternative key
]

def parse_header(data):
    """Parse Huawei hw_ctree.xml header"""
    if len(data) < 64:
        return None
    
    header = {}
    header['magic'] = struct.unpack('<I', data[0:4])[0]
    header['version'] = struct.unpack('<I', data[4:8])[0]
    header['type'] = struct.unpack('<I', data[8:12])[0]
    
    # The encrypted data typically starts after the header
    # Header size can vary, but commonly 64 bytes
    
    return header

def try_decrypt_aes(encrypted_data, key, mode='ECB'):
    """Try to decrypt data with given AES key
    
    Note: This function uses ECB and CBC modes which are considered weak.
    This is intentional as we are DECRYPTING data that was encrypted by
    Huawei routers using these modes. We are not encrypting new data.
    This is a legitimate security research and device administration tool.
    """
    try:
        # Using ECB/CBC modes to decrypt Huawei router configurations
        # These are the modes the routers use, not our choice
        if mode == 'ECB':
            cipher = AES.new(key[:16], AES.MODE_ECB)
        elif mode == 'CBC':
            # Use zero IV or extract from data if present
            iv = b'\x00' * 16
            cipher = AES.new(key[:16], AES.MODE_CBC, iv)
        else:
            return None
        
        decrypted = cipher.decrypt(encrypted_data)
        
        # Try to unpad
        try:
            result = unpad(decrypted, AES.block_size)
            return result
        except:
            # If unpadding fails, return raw decrypted data
            return decrypted
    except Exception as e:
        return None

def decrypt_ctree_file(input_file, output_file=None):
    """Decrypt Huawei hw_ctree.xml file"""
    
    if not output_file:
        output_file = input_file.replace('.xml', '_decrypted.xml')
    
    print(f"[*] Reading encrypted file: {input_file}")
    
    # Read file
    with open(input_file, 'rb') as f:
        file_data = f.read()
    
    print(f"[*] File size: {len(file_data)} bytes")
    
    # Parse header
    header = parse_header(file_data)
    if header:
        print(f"[*] Magic: 0x{header['magic']:08x}")
        print(f"[*] Version: {header['version']}")
        print(f"[*] Type: {header['type']}")
    
    # Encrypted data typically starts at offset 64
    header_size = 64
    encrypted_data = file_data[header_size:]
    
    print(f"[*] Encrypted data size: {len(encrypted_data)} bytes")
    print(f"[*] Attempting decryption with known keys...")
    
    # Try each known key with different modes
    modes = ['ECB', 'CBC']
    
    for i, key in enumerate(HUAWEI_KEYS):
        for mode in modes:
            print(f"[*] Trying key {i+1}/{len(HUAWEI_KEYS)} with {mode} mode...")
            decrypted = try_decrypt_aes(encrypted_data, key, mode)
            
            if decrypted:
                # Check if result looks like XML or valid text
                try:
                    text = decrypted.decode('utf-8', errors='ignore')
                    if '<?xml' in text or '<config' in text or 'ctree' in text.lower():
                        print(f"[+] Successfully decrypted with key {i+1} ({mode} mode)!")
                        
                        # Write output
                        with open(output_file, 'wb') as f:
                            f.write(decrypted)
                        
                        print(f"[+] Decrypted file saved to: {output_file}")
                        print(f"\n[*] Preview:")
                        print(text[:500] if len(text) > 500 else text)
                        return True
                except:
                    pass
    
    # If no key worked, try without header
    print(f"\n[*] Trying without header offset...")
    for i, key in enumerate(HUAWEI_KEYS):
        for mode in modes:
            print(f"[*] Trying key {i+1}/{len(HUAWEI_KEYS)} with {mode} mode (full file)...")
            decrypted = try_decrypt_aes(file_data, key, mode)
            
            if decrypted:
                try:
                    text = decrypted.decode('utf-8', errors='ignore')
                    if '<?xml' in text or '<config' in text or 'ctree' in text.lower():
                        print(f"[+] Successfully decrypted with key {i+1} ({mode} mode)!")
                        
                        with open(output_file, 'wb') as f:
                            f.write(decrypted)
                        
                        print(f"[+] Decrypted file saved to: {output_file}")
                        print(f"\n[*] Preview:")
                        print(text[:500] if len(text) > 500 else text)
                        return True
                except:
                    pass
    
    # If still no success, save raw decrypted data
    print(f"\n[!] No known key worked perfectly, saving raw decrypted data...")
    with open(output_file, 'wb') as f:
        decrypted = try_decrypt_aes(encrypted_data, HUAWEI_KEYS[0])
        if decrypted:
            f.write(decrypted)
            print(f"[*] Raw decrypted data saved to: {output_file}")
            print(f"[!] You may need to manually process this file")
            return True
    
    print(f"[-] Decryption failed")
    return False

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_xml_file> [output_file]")
        print(f"\nExample:")
        print(f"  {sys.argv[0]} hw_ctree.xml")
        print(f"  {sys.argv[0]} hw_ctree.xml decrypted.xml")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(input_file):
        print(f"[-] Error: File not found: {input_file}")
        sys.exit(1)
    
    success = decrypt_ctree_file(input_file, output_file)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
