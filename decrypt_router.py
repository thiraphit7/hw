#!/usr/bin/env python3
"""
Huawei HG8145B7N Router Configuration Decryption Tool
Unified tool for decrypting both .conf and hw_ctree.xml files
"""

import sys
import base64
import struct
import os
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Known Huawei encryption keys (these are commonly used keys)
HUAWEI_KEYS = [
    b'Z0BSIryhmGWFYL8e',  # Common key 1
    b'Wj-lIdpEoH1kOiJ0',  # Common key 2
    b'0I8U7o+500qE0I8U7o+500qE',  # 24-byte key
    b'pD@hU6nW$rE%tY^u',  # Alternative key
    b'HG8145B7N_KEY',      # Model-specific
    b'Zte521',             # ZTE/Huawei common
    b'admin',              # Common password
    b'adminHW',            # Huawei admin variant
]

def generate_device_keys(filename):
    """Generate possible keys from device information in filename"""
    import hashlib
    import re
    
    keys = []
    
    # Extract serial number pattern
    serial_match = re.search(r'(\d{10,})', filename)
    if serial_match:
        serial = serial_match.group(1)
        keys.append(serial.encode())
        keys.append(hashlib.md5(serial.encode()).digest())
        keys.append(hashlib.sha256(serial.encode()).digest()[:16])
    
    # Extract model number
    model_match = re.search(r'(HG\w+)', filename)
    if model_match:
        model = model_match.group(1)
        keys.append(model.encode())
        keys.append(hashlib.md5(model.encode()).digest())
    
    # Use full filename
    keys.append(hashlib.md5(os.path.basename(filename).encode()).digest())
    
    return keys

def is_base64(data):
    """Check if data is base64 encoded"""
    try:
        # Try to decode and check if it's mostly ASCII printable
        if isinstance(data, str):
            data = data.encode('ascii')
        decoded = base64.b64decode(data, validate=True)
        return True
    except:
        return False

def try_decrypt_aes(encrypted_data, key, mode='ECB', iv=None):
    """Try to decrypt data with given AES key"""
    try:
        key_bytes = key[:16]  # Use first 16 bytes for AES-128
        
        if mode == 'ECB':
            cipher = AES.new(key_bytes, AES.MODE_ECB)
        elif mode == 'CBC':
            if iv is None:
                iv = b'\x00' * 16
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
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

def is_valid_xml(data):
    """Check if decrypted data looks like valid XML"""
    try:
        text = data.decode('utf-8', errors='ignore')
        # Look for common XML patterns
        xml_indicators = ['<?xml', '<config', '<InternetGatewayDevice', 
                         'ctree', '<X_HW_', '<Device', '<TR069']
        return any(indicator in text for indicator in xml_indicators)
    except:
        return False

def decrypt_base64_conf(file_data, output_file, input_file=""):
    """Decrypt base64 encoded .conf file"""
    print(f"[*] Detected base64 encoded file")
    print(f"[*] Base64 decoding...")
    
    try:
        encrypted_data = base64.b64decode(file_data)
        print(f"[+] Decoded {len(encrypted_data)} bytes")
    except Exception as e:
        print(f"[-] Error decoding base64: {e}")
        return False
    
    # Generate device-specific keys
    device_keys = generate_device_keys(input_file) if input_file else []
    all_keys = HUAWEI_KEYS + device_keys
    
    # Try each known key
    print(f"[*] Attempting decryption with {len(all_keys)} keys...")
    
    modes = ['ECB', 'CBC']
    
    for i, key in enumerate(all_keys):
        for mode in modes:
            if i < len(HUAWEI_KEYS):
                print(f"[*] Trying standard key {i+1}/{len(HUAWEI_KEYS)} with {mode} mode...")
            else:
                print(f"[*] Trying device-specific key {i-len(HUAWEI_KEYS)+1} with {mode} mode...")
            
            decrypted = try_decrypt_aes(encrypted_data, key, mode)
            
            if decrypted and is_valid_xml(decrypted):
                print(f"[+] Successfully decrypted with key {i+1} ({mode} mode)!")
                
                # Write output
                with open(output_file, 'wb') as f:
                    f.write(decrypted)
                
                text = decrypted.decode('utf-8', errors='ignore')
                print(f"[+] Decrypted file saved to: {output_file}")
                print(f"\n[*] Preview:")
                print(text[:500] if len(text) > 500 else text)
                return True
    
    # Try XOR decryption as fallback
    print(f"\n[*] Trying XOR-based decryption...")
    for i, key in enumerate(all_keys):
        result = bytes([encrypted_data[j] ^ key[j % len(key)] for j in range(len(encrypted_data))])
        if is_valid_xml(result):
            print(f"[+] Successfully decrypted with XOR key {i+1}!")
            with open(output_file, 'wb') as f:
                f.write(result)
            text = result.decode('utf-8', errors='ignore')
            print(f"[+] Decrypted file saved to: {output_file}")
            print(f"\n[*] Preview:")
            print(text[:500] if len(text) > 500 else text)
            return True
    
    # Save raw decrypted data for manual analysis
    print(f"\n[!] No known key produced valid XML")
    print(f"[*] Saving raw AES-decrypted data for analysis...")
    raw_file = output_file.replace('.xml', '_raw.bin')
    decrypted = try_decrypt_aes(encrypted_data, all_keys[0], 'ECB')
    if decrypted:
        with open(raw_file, 'wb') as f:
            f.write(decrypted)
        print(f"[*] Raw data saved to: {raw_file}")
        # Show hex dump
        print(f"[*] First 200 bytes (hex): {decrypted[:200].hex()}")
    
    return False

def decrypt_binary_ctree(file_data, output_file, input_file=""):
    """Decrypt binary hw_ctree.xml file"""
    print(f"[*] Detected binary encrypted file")
    
    # Check for Huawei magic header
    if len(file_data) >= 4:
        magic = struct.unpack('<I', file_data[0:4])[0]
        print(f"[*] Magic header: 0x{magic:08x}")
        
        if magic == 0x20211207:  # 07122120 in little-endian
            print(f"[*] Confirmed Huawei hw_ctree.xml format")
            header_size = 64
            encrypted_data = file_data[header_size:]
            print(f"[*] Encrypted data starts at offset {header_size}")
        else:
            print(f"[*] Unknown magic, trying full file decryption")
            encrypted_data = file_data
    else:
        encrypted_data = file_data
    
    # Generate device-specific keys
    device_keys = generate_device_keys(input_file) if input_file else []
    all_keys = HUAWEI_KEYS + device_keys
    
    print(f"[*] Encrypted data size: {len(encrypted_data)} bytes")
    print(f"[*] Attempting decryption with {len(all_keys)} keys...")
    
    modes = ['ECB', 'CBC']
    
    # Try with header offset
    for i, key in enumerate(all_keys):
        for mode in modes:
            if i < len(HUAWEI_KEYS):
                print(f"[*] Trying standard key {i+1}/{len(HUAWEI_KEYS)} with {mode} mode...")
            else:
                print(f"[*] Trying device-specific key {i-len(HUAWEI_KEYS)+1} with {mode} mode...")
            
            decrypted = try_decrypt_aes(encrypted_data, key, mode)
            
            if decrypted and is_valid_xml(decrypted):
                print(f"[+] Successfully decrypted with key {i+1} ({mode} mode)!")
                
                with open(output_file, 'wb') as f:
                    f.write(decrypted)
                
                text = decrypted.decode('utf-8', errors='ignore')
                print(f"[+] Decrypted file saved to: {output_file}")
                print(f"\n[*] Preview:")
                print(text[:500] if len(text) > 500 else text)
                return True
    
    # Try without header offset
    if len(file_data) != len(encrypted_data):
        print(f"\n[*] Trying without header offset...")
        for i, key in enumerate(all_keys):
            for mode in modes:
                print(f"[*] Trying key {i+1}/{len(all_keys)} with {mode} mode (full file)...")
                decrypted = try_decrypt_aes(file_data, key, mode)
                
                if decrypted and is_valid_xml(decrypted):
                    print(f"[+] Successfully decrypted with key {i+1} ({mode} mode)!")
                    
                    with open(output_file, 'wb') as f:
                        f.write(decrypted)
                    
                    text = decrypted.decode('utf-8', errors='ignore')
                    print(f"[+] Decrypted file saved to: {output_file}")
                    print(f"\n[*] Preview:")
                    print(text[:500] if len(text) > 500 else text)
                    return True
    
    # Try XOR decryption
    print(f"\n[*] Trying XOR-based decryption...")
    for i, key in enumerate(all_keys):
        result = bytes([encrypted_data[j] ^ key[j % len(key)] for j in range(len(encrypted_data))])
        if is_valid_xml(result):
            print(f"[+] Successfully decrypted with XOR key {i+1}!")
            with open(output_file, 'wb') as f:
                f.write(result)
            text = result.decode('utf-8', errors='ignore')
            print(f"[+] Decrypted file saved to: {output_file}")
            print(f"\n[*] Preview:")
            print(text[:500] if len(text) > 500 else text)
            return True
    
    # Save raw decrypted data for manual analysis
    print(f"\n[!] No known key produced valid XML")
    print(f"[*] Saving raw AES-decrypted data for analysis...")
    raw_file = output_file.replace('.xml', '_raw.bin')
    decrypted = try_decrypt_aes(encrypted_data, all_keys[0], 'ECB')
    if decrypted:
        with open(raw_file, 'wb') as f:
            f.write(decrypted)
        print(f"[*] Raw data saved to: {raw_file}")
        print(f"[*] First 200 bytes (hex): {decrypted[:200].hex()}")
    
    return False

def decrypt_file(input_file, output_file=None):
    """Auto-detect file type and decrypt"""
    
    if not output_file:
        if input_file.endswith('.conf'):
            output_file = input_file.replace('.conf', '_decrypted.xml')
        else:
            base = os.path.splitext(input_file)[0]
            output_file = base + '_decrypted.xml'
    
    print(f"[*] Reading file: {input_file}")
    
    # Read file
    with open(input_file, 'rb') as f:
        file_data = f.read()
    
    print(f"[*] File size: {len(file_data)} bytes")
    
    # Try to determine file type
    try:
        # Check if it's base64
        file_text = file_data.decode('ascii').strip()
        if is_base64(file_text):
            return decrypt_base64_conf(file_text, output_file, input_file)
    except:
        pass
    
    # If not base64, treat as binary
    return decrypt_binary_ctree(file_data, output_file, input_file)

def main():
    print("=" * 60)
    print("Huawei HG8145B7N Router Configuration Decryption Tool")
    print("=" * 60)
    print()
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <input_file> [output_file]")
        print(f"\nSupported file types:")
        print(f"  - Base64 encoded .conf files")
        print(f"  - Binary encrypted hw_ctree.xml files")
        print(f"\nExamples:")
        print(f"  {sys.argv[0]} AIS_8806480495_HG8145B7N_20251118_121144.conf")
        print(f"  {sys.argv[0]} hw_ctree.xml")
        print(f"  {sys.argv[0]} config.conf decrypted_output.xml")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(input_file):
        print(f"[-] Error: File not found: {input_file}")
        sys.exit(1)
    
    success = decrypt_file(input_file, output_file)
    
    print()
    print("=" * 60)
    if success:
        print("[+] Decryption completed successfully!")
    else:
        print("[-] Decryption failed. The file may use an unknown key.")
        print("[!] You may need to find the specific encryption key for this device.")
    print("=" * 60)
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
