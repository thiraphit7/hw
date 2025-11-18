#!/usr/bin/env python3
"""
Huawei HG8145B7N Router Configuration Decryption Tool
Decrypts base64 encoded .conf files
"""

import sys
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Known Huawei encryption keys (these are commonly used keys)
HUAWEI_KEYS = [
    b'Z0BSIryhmGWFYL8e',  # Common key 1
    b'Wj-lIdpEoH1kOiJ0',  # Common key 2
    b'0I8U7o+500qE0I8U7o+500qE',  # 24-byte key
    b'pD@hU6nW$rE%tY^u',  # Alternative key
]

def try_decrypt_aes(encrypted_data, key):
    """Try to decrypt data with given AES key"""
    try:
        # Try ECB mode first
        cipher = AES.new(key[:16], AES.MODE_ECB)
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

def decrypt_conf_file(input_file, output_file=None):
    """Decrypt Huawei .conf file"""
    
    if not output_file:
        output_file = input_file.replace('.conf', '_decrypted.xml')
    
    print(f"[*] Reading encrypted file: {input_file}")
    
    # Read and base64 decode
    with open(input_file, 'r') as f:
        base64_data = f.read().strip()
    
    print(f"[*] Base64 decoding...")
    try:
        encrypted_data = base64.b64decode(base64_data)
        print(f"[+] Decoded {len(encrypted_data)} bytes")
    except Exception as e:
        print(f"[-] Error decoding base64: {e}")
        return False
    
    # Try each known key
    print(f"[*] Attempting decryption with known keys...")
    
    for i, key in enumerate(HUAWEI_KEYS):
        print(f"[*] Trying key {i+1}/{len(HUAWEI_KEYS)}...")
        decrypted = try_decrypt_aes(encrypted_data, key)
        
        if decrypted:
            # Check if result looks like XML or valid text
            try:
                text = decrypted.decode('utf-8', errors='ignore')
                if '<?xml' in text or '<config' in text or 'InternetGatewayDevice' in text:
                    print(f"[+] Successfully decrypted with key {i+1}!")
                    
                    # Write output
                    with open(output_file, 'wb') as f:
                        f.write(decrypted)
                    
                    print(f"[+] Decrypted file saved to: {output_file}")
                    print(f"\n[*] Preview:")
                    print(text[:500] if len(text) > 500 else text)
                    return True
            except:
                pass
    
    # If no key worked, save raw decrypted data anyway
    print(f"[!] No known key worked perfectly, saving raw decrypted data...")
    with open(output_file, 'wb') as f:
        # Try first key
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
        print(f"Usage: {sys.argv[0]} <input_conf_file> [output_file]")
        print(f"\nExample:")
        print(f"  {sys.argv[0]} config.conf")
        print(f"  {sys.argv[0]} config.conf decrypted.xml")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(input_file):
        print(f"[-] Error: File not found: {input_file}")
        sys.exit(1)
    
    success = decrypt_conf_file(input_file, output_file)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
