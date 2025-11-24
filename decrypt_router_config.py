#!/usr/bin/env python3
"""
Huawei Router Configuration Decryptor - Full Two-Step Process
==============================================================

This script performs complete decryption of Huawei router configuration files:
1. Extract Base64 data and decode to binary
2. Decrypt AES encryption and decompress to get XML configuration

Usage:
    python decrypt_router_config.py <input_file> [output_file]

Example:
    python decrypt_router_config.py AIS_8806480495_HG8145B7N_20251118_121144.conf
    python decrypt_router_config.py AIS_8806480495_HG8145B7N_20251118_121144.conf my_router_config.xml

Requirements:
    pip install pycryptodome
"""

import base64
import re
import sys
import os
import zlib
import struct

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# Minimum length for Base64 data to be considered valid router config
MIN_BASE64_LENGTH = 100

# Known Huawei router encryption keys
KNOWN_KEYS = [
    b'$HuaweiHg8245Q',           # Common AIS key
    b'\x00' * 16,                 # Null key
    b'hg8245',                    # Simple key
    b'huawei',                    # Simple key
]


def decrypt_aes(encrypted_data, key):
    """
    Decrypt AES-encrypted data using the provided key.
    
    Args:
        encrypted_data: Encrypted binary data
        key: Decryption key (bytes)
        
    Returns:
        bytes: Decrypted data, None if decryption fails
    """
    try:
        # Huawei config files typically use AES-128-ECB
        # Pad or truncate key to 16 bytes
        if len(key) < 16:
            key = key.ljust(16, b'\x00')
        elif len(key) > 16:
            key = key[:16]
        
        # Try ECB mode (most common for Huawei)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted_data)
        
        # Don't unpad yet - return raw decrypted data
        return decrypted
    except Exception as e:
        return None


def decompress_data(data):
    """
    Decompress data if it's compressed (zlib/gzip).
    
    Args:
        data: Binary data that might be compressed
        
    Returns:
        bytes: Decompressed data, or original data if not compressed
    """
    # Try different decompression methods
    try:
        # Try zlib decompression
        return zlib.decompress(data)
    except:
        pass
    
    try:
        # Try zlib with negative wbits (raw deflate)
        return zlib.decompress(data, -zlib.MAX_WBITS)
    except:
        pass
    
    try:
        # Try gzip decompression
        return zlib.decompress(data, zlib.MAX_WBITS | 16)
    except:
        pass
    
    # Return original data if decompression fails
    return data


def try_decrypt_with_keys(encrypted_data):
    """
    Try to decrypt data with known keys.
    
    Args:
        encrypted_data: AES-encrypted binary data
        
    Returns:
        tuple: (decrypted_data, key_used) or (None, None) if all fail
    """
    if not HAS_CRYPTO:
        return None, None
    
    for key in KNOWN_KEYS:
        decrypted = decrypt_aes(encrypted_data, key)
        if not decrypted:
            continue
        
        # Try decompression first
        decompressed = decompress_data(decrypted)
        
        # Check if decompressed data looks like XML
        try:
            text = decompressed.decode('utf-8', errors='ignore')
            if '<?xml' in text[:100] or ('<' in text[:100] and '>' in text[:200]):
                # Additional validation - check for common router config tags
                if any(tag in text for tag in ['WANPPPConnection', 'WLANConfiguration', 'InternetGatewayDevice']):
                    return decompressed, key
        except:
            pass
        
        # Try without decompression
        try:
            text = decrypted.decode('utf-8', errors='ignore')
            if '<?xml' in text[:100] or ('<' in text[:100] and '>' in text[:200]):
                if any(tag in text for tag in ['WANPPPConnection', 'WLANConfiguration', 'InternetGatewayDevice']):
                    return decrypted, key
        except:
            pass
    
    return None, None


def extract_base64_from_file(input_filename):
    """
    Extract Base64-encoded data from HTML/conf file.
    
    Args:
        input_filename: Path to the input HTML/conf file
        
    Returns:
        str: Base64-encoded string if found, None otherwise
    """
    try:
        # Try UTF-8 first, fallback to latin-1 for robustness
        try:
            with open(input_filename, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(input_filename, 'r', encoding='latin-1') as f:
                content = f.read()
        
        # Search for Base64 data (long strings with Base64 characters)
        # Use non-greedy match and ensure we get the longest continuous Base64 string
        pattern = r'([A-Za-z0-9+/=]{' + str(MIN_BASE64_LENGTH) + r',})'
        matches = re.findall(pattern, content)
        
        if matches:
            # Return the longest match (most likely the config data)
            return max(matches, key=len)
        else:
            return None
            
    except FileNotFoundError:
        print(f"❌ ข้อผิดพลาด: ไม่พบไฟล์ '{input_filename}'")
        print(f"❌ Error: File '{input_filename}' not found")
        return None
    except Exception as e:
        print(f"❌ ข้อผิดพลาดในการอ่านไฟล์: {e}")
        print(f"❌ Error reading file: {e}")
        return None


def decode_base64_to_binary(base64_data):
    """
    Decode Base64 string to binary data.
    
    Args:
        base64_data: Base64-encoded string
        
    Returns:
        bytes: Decoded binary data, None if decoding fails
    """
    try:
        binary_data = base64.b64decode(base64_data)
        return binary_data
    except Exception as e:
        print(f"❌ ข้อผิดพลาดในการถอดรหัส Base64: {e}")
        print(f"❌ Error decoding Base64: {e}")
        return None


def save_binary_file(binary_data, output_filename):
    """
    Save binary data to file.
    
    Args:
        binary_data: Binary data to save
        output_filename: Path to output file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        with open(output_filename, 'wb') as f_out:
            f_out.write(binary_data)
        return True
    except Exception as e:
        print(f"❌ ข้อผิดพลาดในการบันทึกไฟล์: {e}")
        print(f"❌ Error saving file: {e}")
        return False


def main():
    """Main function to handle command-line interface."""
    
    # Check command-line arguments
    if len(sys.argv) < 2:
        print("การใช้งาน / Usage:")
        print(f"  python {sys.argv[0]} <input_file> [output_file]")
        print()
        print("ตัวอย่าง / Example:")
        print(f"  python {sys.argv[0]} AIS_8806480495_HG8145B7N_20251118_121144.conf")
        print(f"  python {sys.argv[0]} AIS_8806480495_HG8145B7N_20251118_121144.conf my_router_config.xml")
        sys.exit(1)
    
    input_filename = sys.argv[1]
    
    # Generate output filenames if not provided
    if len(sys.argv) >= 3:
        output_filename = sys.argv[2]
        # Also generate .bin filename
        if output_filename.endswith('.xml'):
            bin_filename = output_filename.replace('.xml', '.bin')
        else:
            bin_filename = output_filename + '.bin'
    else:
        # Default output filenames
        base_name = os.path.splitext(os.path.basename(input_filename))[0]
        output_filename = f"{base_name}_decrypted.xml"
        bin_filename = f"{base_name}_encrypted.bin"
    
    print("=" * 80)
    print("Huawei Router Configuration Decryptor - Two-Step Process")
    print("=" * 80)
    print()
    print(f"📂 ไฟล์ต้นทาง / Input file: {input_filename}")
    print(f"📂 ไฟล์ปลายทาง (XML) / Output file (XML): {output_filename}")
    print(f"📂 ไฟล์ระหว่างกลาง (BIN) / Intermediate file (BIN): {bin_filename}")
    print()
    
    # Step 1: Extract Base64 data
    print("🔍 ขั้นตอนที่ 1/3: กำลังค้นหาและถอดรหัส Base64...")
    print("🔍 Step 1/3: Searching for and decoding Base64 data...")
    base64_data = extract_base64_from_file(input_filename)
    
    if not base64_data:
        print("❌ ไม่พบข้อมูล Config ในไฟล์นี้")
        print("❌ No configuration data found in this file")
        sys.exit(1)
    
    print(f"✅ พบข้อมูล Base64 ({len(base64_data)} ตัวอักษร)")
    print(f"✅ Found Base64 data ({len(base64_data)} characters)")
    
    # Step 2: Decode Base64
    binary_data = decode_base64_to_binary(base64_data)
    
    if not binary_data:
        print("❌ ถอดรหัส Base64 ไม่สำเร็จ")
        print("❌ Base64 decoding failed")
        sys.exit(1)
    
    print(f"✅ ถอดรหัส Base64 สำเร็จ ({len(binary_data)} ไบต์)")
    print(f"✅ Base64 decoded successfully ({len(binary_data)} bytes)")
    
    # Save the binary file (for manual decryption if needed)
    if not save_binary_file(binary_data, bin_filename):
        print("❌ บันทึกไฟล์ .bin ไม่สำเร็จ")
        print("❌ Failed to save .bin file")
        sys.exit(1)
    
    print(f"✅ บันทึกไฟล์เข้ารหัส: {bin_filename}")
    print(f"✅ Saved encrypted binary: {bin_filename}")
    print()
    
    # Step 3: Try AES decryption if library is available
    if not HAS_CRYPTO:
        print("⚠️  ไม่พบไลบรารี pycryptodome - ข้ามการถอดรหัส AES อัตโนมัติ")
        print("⚠️  pycryptodome library not found - skipping automatic AES decryption")
        print()
        print("📦 ติดตั้งเพื่อถอดรหัส AES อัตโนมัติ / Install for automatic AES decryption:")
        print("   pip install pycryptodome")
        print()
        print_manual_decryption_instructions(bin_filename)
        sys.exit(0)
    
    print("🔐 ขั้นตอนที่ 2/3: กำลังพยายามถอดรหัส AES อัตโนมัติ...")
    print("🔐 Step 2/3: Attempting automatic AES decryption...")
    print(f"   ลองใช้ {len(KNOWN_KEYS)} กุญแจที่รู้จัก...")
    print(f"   Trying {len(KNOWN_KEYS)} known keys...")
    
    decrypted_data, key_used = try_decrypt_with_keys(binary_data)
    
    if not decrypted_data:
        print("⚠️  ถอดรหัส AES อัตโนมัติไม่สำเร็จ")
        print("⚠️  Automatic AES decryption failed")
        print()
        print("กุญแจที่ลองแล้ว / Keys tried:")
        for key in KNOWN_KEYS:
            print(f"  - {key}")
        print()
        print_manual_decryption_instructions(bin_filename)
        sys.exit(0)
    
    print(f"✅ ถอดรหัส AES สำเร็จด้วยกุญแจ: {key_used}")
    print(f"✅ AES decryption successful with key: {key_used}")
    print()
    
    # Step 4: Save XML
    print("💾 ขั้นตอนที่ 3/3: กำลังบันทึกไฟล์ XML...")
    print("💾 Step 3/3: Saving XML file...")
    
    if not save_binary_file(decrypted_data, output_filename):
        print("❌ บันทึกไฟล์ไม่สำเร็จ")
        print("❌ File save failed")
        sys.exit(1)
    
    print(f"✅ สำเร็จ! บันทึกไฟล์แล้ว ({len(decrypted_data)} ไบต์)")
    print(f"✅ Success! File saved ({len(decrypted_data)} bytes)")
    print()
    print("=" * 80)
    print("✨ การถอดรหัสเสร็จสมบูรณ์ / Decryption Complete!")
    print("=" * 80)
    print()
    print(f"📄 ไฟล์ XML ที่ถอดรหัสแล้ว: {output_filename}")
    print(f"📄 Decrypted XML file: {output_filename}")
    print()
    print_xml_usage_instructions()


def print_manual_decryption_instructions(bin_filename):
    """Print instructions for manual AES decryption."""
    print("=" * 80)
    print("📋 ขั้นตอนถอดรหัส AES ด้วยมือ / Manual AES Decryption Steps")
    print("=" * 80)
    print()
    print(f"ไฟล์ที่ต้องถอดรหัส / File to decrypt: {bin_filename}")
    print()
    print("1. ดาวน์โหลดเครื่องมือถอดรหัส Huawei:")
    print("   Download Huawei decryption tools:")
    print("   - huawei-config-utility")
    print("   - huawei_xml_decrypt")
    print("   - หรือค้นหา 'Huawei Router Config Decrypter' บน GitHub")
    print("   - or search 'Huawei Router Config Decrypter' on GitHub")
    print()
    print("2. ใช้กุญแจเหล่านี้ในการถอดรหัส:")
    print("   Try these decryption keys:")
    for i, key in enumerate(KNOWN_KEYS, 1):
        print(f"   {i}. {key}")
    print()
    print("3. หลังถอดรหัสสำเร็จ ให้เปิดไฟล์ XML และค้นหา:")
    print("   After successful decryption, open the XML file and search for:")
    print()
    print_xml_usage_instructions()


def print_xml_usage_instructions():
    """Print instructions for using the decrypted XML file."""
    print("  🔐 Username/Password อินเทอร์เน็ต (PPPoE):")
    print("     Internet Username/Password (PPPoE):")
    print("     - ค้นหาแท็ก / Search for tag: <WANPPPConnection>")
    print("     - หรือ / or: <Username> และ <Password>")
    print()
    print("  📶 รหัส WiFi:")
    print("     WiFi Password:")
    print("     - ค้นหาแท็ก / Search for tag: <WLANConfiguration>")
    print("     - หรือ / or: <PreSharedKey> หรือ <KeyPassphrase>")
    print()


if __name__ == "__main__":
    main()
