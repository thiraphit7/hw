#!/usr/bin/env python3
"""
Huawei Router Configuration Decryptor - Step 1: Base64 Extraction
=================================================================

This script extracts the Base64-encoded encrypted configuration from 
Huawei router HTML/conf files and saves it as a binary file.

This is Step 1 of the 2-step decryption process:
1. Extract Base64 data and decode to binary (this script)
2. Decrypt AES encryption using Huawei Router Config Decrypter tool

Usage:
    python decrypt_router_config.py <input_file> [output_file]

Example:
    python decrypt_router_config.py AIS_8806480495_HG8145B7N_20251118_121144.conf
    python decrypt_router_config.py AIS_8806480495_HG8145B7N_20251118_121144.conf my_router_config.bin
"""

import base64
import re
import sys
import os


# Minimum length for Base64 data to be considered valid router config
MIN_BASE64_LENGTH = 100


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
        print(f"  python {sys.argv[0]} AIS_8806480495_HG8145B7N_20251118_121144.conf my_router_config.bin")
        sys.exit(1)
    
    input_filename = sys.argv[1]
    
    # Generate output filename if not provided
    if len(sys.argv) >= 3:
        output_filename = sys.argv[2]
    else:
        # Default output filename
        base_name = os.path.splitext(os.path.basename(input_filename))[0]
        output_filename = f"{base_name}_decrypted.bin"
    
    print("=" * 70)
    print("Huawei Router Configuration Decryptor - Step 1: Base64 Extraction")
    print("=" * 70)
    print()
    print(f"📂 ไฟล์ต้นทาง / Input file: {input_filename}")
    print(f"📂 ไฟล์ปลายทาง / Output file: {output_filename}")
    print()
    
    # Step 1: Extract Base64 data
    print("🔍 ขั้นตอนที่ 1: กำลังค้นหาข้อมูล Base64...")
    print("🔍 Step 1: Searching for Base64 data...")
    base64_data = extract_base64_from_file(input_filename)
    
    if not base64_data:
        print("❌ ไม่พบข้อมูล Config ในไฟล์นี้")
        print("❌ No configuration data found in this file")
        sys.exit(1)
    
    print(f"✅ พบข้อมูล Base64 ({len(base64_data)} ตัวอักษร)")
    print(f"✅ Found Base64 data ({len(base64_data)} characters)")
    print()
    
    # Step 2: Decode Base64
    print("🔓 ขั้นตอนที่ 2: กำลังถอดรหัส Base64...")
    print("🔓 Step 2: Decoding Base64...")
    binary_data = decode_base64_to_binary(base64_data)
    
    if not binary_data:
        print("❌ ถอดรหัส Base64 ไม่สำเร็จ")
        print("❌ Base64 decoding failed")
        sys.exit(1)
    
    print(f"✅ ถอดรหัสสำเร็จ ({len(binary_data)} ไบต์)")
    print(f"✅ Decoded successfully ({len(binary_data)} bytes)")
    print()
    
    # Step 3: Save to file
    print(f"💾 ขั้นตอนที่ 3: กำลังบันทึกไฟล์ '{output_filename}'...")
    print(f"💾 Step 3: Saving file '{output_filename}'...")
    
    if not save_binary_file(binary_data, output_filename):
        print("❌ บันทึกไฟล์ไม่สำเร็จ")
        print("❌ File save failed")
        sys.exit(1)
    
    print(f"✅ สำเร็จ! บันทึกไฟล์แล้ว")
    print(f"✅ Success! File saved")
    print()
    print("=" * 70)
    print("📋 ขั้นตอนต่อไป / Next Steps:")
    print("=" * 70)
    print()
    print("ไฟล์ที่ได้ยังคงเข้ารหัสด้วย AES คุณต้อง:")
    print("The output file is still AES encrypted. You need to:")
    print()
    print("1. ดาวน์โหลดเครื่องมือ 'Huawei Router Config Decrypter'")
    print("   Download 'Huawei Router Config Decrypter' tool")
    print("   (ค้นหา huawei-config-utility หรือ huawei_xml_decrypt)")
    print("   (Search for huawei-config-utility or huawei_xml_decrypt)")
    print()
    print(f"2. ใช้เครื่องมือนั้นถอดรหัสไฟล์ '{output_filename}'")
    print(f"   Use that tool to decrypt '{output_filename}'")
    print()
    print("3. ลองใช้ Decryption Key เหล่านี้:")
    print("   Try these Decryption Keys:")
    print("   - $HuaweiHg8245Q")
    print("   - (empty/null)")
    print()
    print("4. เมื่อถอดรหัสสำเร็จ คุณจะได้ไฟล์ XML ที่มี:")
    print("   After successful decryption, you'll get an XML file with:")
    print("   - Username/Password: <WANPPPConnection>")
    print("   - WiFi Password: <WLANConfiguration>")
    print()


if __name__ == "__main__":
    main()
