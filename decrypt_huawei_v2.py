#!/usr/bin/env python3
"""
Huawei HG8145B7N Config Decryption Tool v2
Supports hw_ctree.xml format and Base64 encoded .conf files
"""

import base64
import hashlib
import zlib
import struct
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import binascii

# Device Information
DEVICE_INFO = {
    "model": "HG8145B7N",
    "mac": "E0:AE:A2:EF:B1:CD",
    "mac_no_colon": "E0AEA2EFB1CD",
    "hardware_version": "39E7.A",
    "firmware": "V5R023C10S104",
    "sn": "48575443286F3DB5",
    "sn_readable": "HWTC286F3DB5",
}

# Common Huawei hw_ctree keys
HWCTREE_KEYS = [
    # Known Huawei keys
    b'$1$YaKi9SFn$'.ljust(16, b'\x00'),
    b'$1$00000000$'.ljust(16, b'\x00'),
    b'HuaweiHomeGateway'.ljust(16, b'\x00')[:16],
    b'huawei'.ljust(16, b'\x00'),
    b'Huawei'.ljust(16, b'\x00'),
    b'HUAWEI'.ljust(16, b'\x00'),
    b'admin'.ljust(16, b'\x00'),
    b'root'.ljust(16, b'\x00'),
    b'HG8145B7N'.ljust(16, b'\x00'),
    b'telecomadmin'.ljust(16, b'\x00')[:16],
    b'admintelecom'.ljust(16, b'\x00')[:16],

    # AES keys often used
    bytes.fromhex('00000000000000000000000000000000'),
    bytes.fromhex('ffffffffffffffffffffffffffffffff'),

    # Various derived keys
    hashlib.md5(b'HG8145B7N').digest(),
    hashlib.md5(b'huawei').digest(),
    hashlib.md5(b'admin').digest(),
    hashlib.md5(b'root').digest(),
    hashlib.md5(b'E0AEA2EFB1CD').digest(),
    hashlib.md5(b'48575443286F3DB5').digest(),
    hashlib.md5(b'HWTC286F3DB5').digest(),
    hashlib.md5(b'hw_ctree').digest(),
    hashlib.md5(b'hwctree').digest(),
    hashlib.md5(b'ctree').digest(),
    hashlib.md5(b'HuaweiHomeGateway').digest(),
    hashlib.md5(b'telecomadmin').digest(),
    hashlib.md5(b'OptiXstar').digest(),
    hashlib.md5(b'AIS').digest(),

    # SHA256 truncated
    hashlib.sha256(b'HG8145B7N').digest()[:16],
    hashlib.sha256(b'huawei').digest()[:16],
    hashlib.sha256(b'hw_ctree').digest()[:16],
]

# Generate more keys from patterns
def generate_all_keys():
    """Generate comprehensive key list"""
    keys = list(HWCTREE_KEYS)

    # Base tokens
    bases = [
        "HG8145B7N", "hg8145b7n", "HuaweiHG8145B7N", "AIS_HG8145B7N",
        "HG8145B7N-AIS", "OptiXstar", "OptiXstarHG8145B7N",
        "E0AEA2EFB1CD", "e0aea2efb1cd", "48575443286F3DB5", "HWTC286F3DB5"
    ]

    keyroles = ["key", "KEY", "aes", "AES", "cfg", "cfgkey", "config", "DecKey", "EncKey", "secret"]
    versions = ["V5R023C10S104", "V5R023C10", "V5", "39E7.A", "39E7A"]
    years = ["2023", "2024", "2025"]

    passwords = set()

    # Pattern 1: base only
    for b in bases:
        passwords.add(b)

    # Pattern 2: base_keyrole
    for b in bases:
        for k in keyroles:
            passwords.add(f"{b}_{k}")
            passwords.add(f"{b}{k}")

    # Pattern 3: keyrole_base
    for k in keyroles:
        for b in bases:
            passwords.add(f"{k}_{b}")
            passwords.add(f"{k}{b}")

    # Pattern 5: base_year
    for b in bases:
        for y in years:
            passwords.add(f"{b}_{y}")

    # Pattern 6: base_firmware_keyrole
    for b in bases:
        for v in versions:
            for k in keyroles:
                passwords.add(f"{b}_{v}_{k}")
                passwords.add(f"{b}{v}{k}")

    # Add common defaults
    defaults = [
        "huawei", "HUAWEI", "Huawei", "admin", "root", "telecomadmin",
        "hw_ctree_key", "hw_config_key", "hwtree", "hwctree", "ctree",
        "aescfgkey", "HuaweiConfigKey", "ConfigEncryptKey", "GPONKey",
        "AISKey", "HuaweiAIS", "ais"
    ]
    passwords.update(defaults)

    # Derive keys from passwords
    for pwd in passwords:
        pwd_bytes = pwd.encode('utf-8')

        # MD5
        keys.append(hashlib.md5(pwd_bytes).digest())

        # SHA256 truncated
        keys.append(hashlib.sha256(pwd_bytes).digest()[:16])
        keys.append(hashlib.sha256(pwd_bytes).digest())

        # Padded to 16
        if len(pwd_bytes) <= 16:
            keys.append(pwd_bytes.ljust(16, b'\x00'))
        else:
            keys.append(pwd_bytes[:16])

        # Padded to 32
        if len(pwd_bytes) <= 32:
            keys.append(pwd_bytes.ljust(32, b'\x00'))
        else:
            keys.append(pwd_bytes[:32])

    # Remove duplicates and filter valid lengths
    unique_keys = []
    seen = set()
    for k in keys:
        if len(k) in [16, 24, 32] and k not in seen:
            seen.add(k)
            unique_keys.append(k)

    return unique_keys

def parse_hwctree_header(data):
    """Parse hw_ctree.xml file header"""
    if len(data) < 72:
        return None

    header = {
        'magic': data[0:4],
        'version': struct.unpack('<I', data[4:8])[0],
        'flags': data[8:48],
        'header_len': struct.unpack('<I', data[48:52])[0],
        'data_len': struct.unpack('<I', data[52:56])[0],
        'unknown1': struct.unpack('<I', data[56:60])[0],
    }

    print(f"  Magic: {header['magic'].hex()}")
    print(f"  Version: {header['version']}")
    print(f"  Header len: {header['header_len']} (0x{header['header_len']:x})")
    print(f"  Data len: {header['data_len']} (0x{header['data_len']:x})")

    return header

def try_decrypt(ciphertext, key, mode='ECB', iv=None):
    """Try decryption with given parameters"""
    try:
        if len(ciphertext) % 16 != 0:
            # Pad to block size
            ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]

        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        elif mode == 'CBC':
            if iv is None:
                iv = b'\x00' * 16
            cipher = AES.new(key, AES.MODE_CBC, iv)
        else:
            return None

        decrypted = cipher.decrypt(ciphertext)
        return decrypted
    except Exception as e:
        return None

def is_valid_decryption(data):
    """Check if decryption produced valid output"""
    if not data or len(data) < 10:
        return False, None

    # Check for XML
    try:
        text = data.decode('utf-8', errors='ignore')
        if '<?xml' in text[:100]:
            return True, 'XML'
        if '<' in text[:50] and '>' in text[:100]:
            # Check for Huawei config tags
            config_tags = ['<config', '<device', '<wan', '<lan', '<wifi', '<ssid',
                           '<password', '<pppoe', '<username', '<huawei', '<ctree',
                           '<hw_ctree', '<X_', '<InternetGatewayDevice', '<DeviceInfo']
            for tag in config_tags:
                if tag.lower() in text.lower()[:500]:
                    return True, 'XML'
    except:
        pass

    # Check for gzip
    if data[:2] == b'\x1f\x8b':
        return True, 'GZIP'

    # Check for zlib
    try:
        zlib.decompress(data)
        return True, 'ZLIB'
    except:
        pass

    # Check for high ASCII printable ratio
    printable = sum(1 for b in data[:500] if 32 <= b < 127 or b in [9, 10, 13])
    ratio = printable / min(len(data), 500)
    if ratio > 0.85:
        return True, 'TEXT'

    return False, None

def decompress_if_needed(data):
    """Try to decompress data if compressed"""
    # Try gzip
    if data[:2] == b'\x1f\x8b':
        try:
            import gzip
            return gzip.decompress(data), 'gzip'
        except:
            pass

    # Try zlib
    try:
        return zlib.decompress(data), 'zlib'
    except:
        pass

    # Try zlib with various window sizes
    for wbits in [15, -15, 31, 47]:
        try:
            return zlib.decompress(data, wbits), f'zlib_w{wbits}'
        except:
            pass

    return data, None

def decrypt_hwctree(filepath):
    """Decrypt hw_ctree.xml file"""
    print(f"\n[*] Decrypting hw_ctree: {filepath}")

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"[*] File size: {len(data)} bytes")

    # Parse header
    print("[*] Parsing header...")
    header = parse_hwctree_header(data)

    if header is None:
        print("[-] Invalid header")
        return False

    # Try different offsets for encrypted data
    offsets_to_try = [
        72,  # After header
        header['header_len'] if header['header_len'] < len(data) else 72,
        100,
        128,
        256,
    ]

    keys = generate_all_keys()
    print(f"[*] Generated {len(keys)} keys to try")

    for offset in offsets_to_try:
        if offset >= len(data):
            continue

        encrypted_data = data[offset:]
        print(f"\n[*] Trying offset: {offset}, data length: {len(encrypted_data)}")

        for i, key in enumerate(keys):
            if i % 500 == 0:
                print(f"[*] Progress: {i}/{len(keys)} keys...")

            # Try ECB
            decrypted = try_decrypt(encrypted_data, key, 'ECB')
            if decrypted:
                # Try decompress
                final_data, comp_type = decompress_if_needed(decrypted)
                valid, dtype = is_valid_decryption(final_data)
                if valid:
                    print(f"\n[+] SUCCESS!")
                    print(f"[+] Key (hex): {key.hex()}")
                    print(f"[+] Mode: ECB")
                    print(f"[+] Offset: {offset}")
                    print(f"[+] Compression: {comp_type}")
                    print(f"[+] Data type: {dtype}")
                    save_result(filepath, final_data, key, 'ECB', offset)
                    return True

            # Try CBC with zero IV
            decrypted = try_decrypt(encrypted_data, key, 'CBC', b'\x00'*16)
            if decrypted:
                final_data, comp_type = decompress_if_needed(decrypted)
                valid, dtype = is_valid_decryption(final_data)
                if valid:
                    print(f"\n[+] SUCCESS!")
                    print(f"[+] Key (hex): {key.hex()}")
                    print(f"[+] Mode: CBC (zero IV)")
                    print(f"[+] Offset: {offset}")
                    print(f"[+] Compression: {comp_type}")
                    print(f"[+] Data type: {dtype}")
                    save_result(filepath, final_data, key, 'CBC', offset)
                    return True

            # Try CBC with first 16 bytes as IV
            if len(encrypted_data) > 16:
                iv = encrypted_data[:16]
                ct = encrypted_data[16:]
                decrypted = try_decrypt(ct, key, 'CBC', iv)
                if decrypted:
                    final_data, comp_type = decompress_if_needed(decrypted)
                    valid, dtype = is_valid_decryption(final_data)
                    if valid:
                        print(f"\n[+] SUCCESS!")
                        print(f"[+] Key (hex): {key.hex()}")
                        print(f"[+] Mode: CBC (IV from data)")
                        print(f"[+] Offset: {offset}")
                        print(f"[+] Compression: {comp_type}")
                        print(f"[+] Data type: {dtype}")
                        save_result(filepath, final_data, key, 'CBC-IV', offset)
                        return True

    print("[-] Could not decrypt hw_ctree.xml")
    return False

def decrypt_conf(filepath):
    """Decrypt Base64 encoded .conf file"""
    print(f"\n[*] Decrypting conf: {filepath}")

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"[*] File size: {len(data)} bytes")

    # Decode Base64
    try:
        encrypted = base64.b64decode(data)
        print(f"[*] Base64 decoded size: {len(encrypted)} bytes")
    except Exception as e:
        print(f"[-] Base64 decode failed: {e}")
        encrypted = data

    keys = generate_all_keys()
    print(f"[*] Generated {len(keys)} keys to try")

    for i, key in enumerate(keys):
        if i % 500 == 0:
            print(f"[*] Progress: {i}/{len(keys)} keys...")

        # Try ECB
        decrypted = try_decrypt(encrypted, key, 'ECB')
        if decrypted:
            final_data, comp_type = decompress_if_needed(decrypted)
            valid, dtype = is_valid_decryption(final_data)
            if valid:
                print(f"\n[+] SUCCESS!")
                print(f"[+] Key (hex): {key.hex()}")
                print(f"[+] Mode: ECB")
                print(f"[+] Compression: {comp_type}")
                print(f"[+] Data type: {dtype}")
                save_result(filepath, final_data, key, 'ECB', 0)
                return True

        # Try CBC with zero IV
        decrypted = try_decrypt(encrypted, key, 'CBC', b'\x00'*16)
        if decrypted:
            final_data, comp_type = decompress_if_needed(decrypted)
            valid, dtype = is_valid_decryption(final_data)
            if valid:
                print(f"\n[+] SUCCESS!")
                print(f"[+] Key (hex): {key.hex()}")
                print(f"[+] Mode: CBC (zero IV)")
                print(f"[+] Compression: {comp_type}")
                print(f"[+] Data type: {dtype}")
                save_result(filepath, final_data, key, 'CBC', 0)
                return True

        # Try CBC with first 16 bytes as IV
        if len(encrypted) > 16:
            iv = encrypted[:16]
            ct = encrypted[16:]
            decrypted = try_decrypt(ct, key, 'CBC', iv)
            if decrypted:
                final_data, comp_type = decompress_if_needed(decrypted)
                valid, dtype = is_valid_decryption(final_data)
                if valid:
                    print(f"\n[+] SUCCESS!")
                    print(f"[+] Key (hex): {key.hex()}")
                    print(f"[+] Mode: CBC (IV from data)")
                    print(f"[+] Compression: {comp_type}")
                    print(f"[+] Data type: {dtype}")
                    save_result(filepath, final_data, key, 'CBC-IV', 0)
                    return True

    print("[-] Could not decrypt .conf file")
    return False

def save_result(filepath, data, key, mode, offset):
    """Save decrypted result"""
    out_path = filepath + ".decrypted"
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"[+] Saved to: {out_path}")

    # Show preview
    print(f"\n[+] Preview (first 1000 chars):")
    print("-" * 60)
    try:
        print(data[:1000].decode('utf-8', errors='replace'))
    except:
        print(data[:1000])
    print("-" * 60)

def main():
    print("=" * 60)
    print("Huawei HG8145B7N Config Decryption Tool v2")
    print("=" * 60)

    conf_file = "/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf"
    xml_file = "/home/user/routerde/hw_ctree.xml"

    # Try conf file first
    if os.path.exists(conf_file):
        decrypt_conf(conf_file)

    # Try hw_ctree.xml
    if os.path.exists(xml_file):
        decrypt_hwctree(xml_file)

    print("\n" + "=" * 60)
    print("[*] Decryption attempts completed")
    print("=" * 60)

if __name__ == "__main__":
    main()
