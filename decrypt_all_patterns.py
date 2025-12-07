#!/usr/bin/env python3
"""
Exhaustive Pattern-Based Key Generation
Following user's exact 6 patterns with all device info
"""

import base64
import gzip
import zlib
import os
import hashlib
import itertools
from Crypto.Cipher import AES
import binascii

# User specified base tokens (11 variants)
BASE_TOKENS = [
    "HG8145B7N",
    "hg8145b7n",
    "HuaweiHG8145B7N",
    "AIS_HG8145B7N",
    "HG8145B7N-AIS",
    "hg8145b7n-ais",
    "Huawei_HG8145B7N",
    "HUAWEI_HG8145B7N",
    "HG8145B7NAIS",
    "OptiXstar",
    "OptiXstarHG8145B7N",
]

# User specified key-role tokens (9 patterns - expanded)
KEYROLE_TOKENS = [
    "key", "KEY", "Key",
    "aes", "AES", "Aes",
    "cfg", "CFG", "Cfg",
    "cfgkey", "CFGKEY", "CfgKey", "CFGKey",
    "config", "CONFIG", "Config",
    "DecKey", "deckey", "DECKEY", "Deckey",
    "EncKey", "enckey", "ENCKEY", "Enckey",
]

# Version tokens
VERSION_TOKENS = [
    "V5R023C10S104",
    "V5R023C10",
    "V5",
    "V5R023",
]

# Year tokens
YEAR_TOKENS = ["2023", "2024", "2025"]

# Device specific info
MAC_TOKENS = [
    "E0AEA2EFB1CD",
    "e0aea2efb1cd",
    "E0:AE:A2:EF:B1:CD",
    "e0:ae:a2:ef:b1:cd",
]

SN_TOKENS = [
    "48575443286F3DB5",
    "HWTC286F3DB5",
    "48575443286f3db5",
]

HW_TOKENS = [
    "39E7.A",
    "39E7A",
]

def generate_all_keys():
    """Generate ALL possible key combinations from patterns"""
    keys = set()

    # Pattern 1: <base>
    for base in BASE_TOKENS:
        keys.add(base)

    # Pattern 2: <base>_<keyrole>
    for base in BASE_TOKENS:
        for keyrole in KEYROLE_TOKENS:
            keys.add(f"{base}_{keyrole}")

    # Pattern 3: <keyrole>_<base>
    for keyrole in KEYROLE_TOKENS:
        for base in BASE_TOKENS:
            keys.add(f"{keyrole}_{base}")

    # Pattern 4: <base><keyrole> (no separator)
    for base in BASE_TOKENS:
        for keyrole in KEYROLE_TOKENS:
            keys.add(f"{base}{keyrole}")

    # Pattern 5: <base>_<year>
    for base in BASE_TOKENS:
        for year in YEAR_TOKENS:
            keys.add(f"{base}_{year}")

    # Pattern 6: <base>_<firmware>_<keyrole>
    for base in BASE_TOKENS:
        for version in VERSION_TOKENS:
            for keyrole in KEYROLE_TOKENS:
                keys.add(f"{base}_{version}_{keyrole}")

    # Additional patterns with device info
    # MAC-based
    for mac in MAC_TOKENS:
        keys.add(mac)
        for keyrole in KEYROLE_TOKENS:
            keys.add(f"{mac}_{keyrole}")
            keys.add(f"{keyrole}_{mac}")
        for base in BASE_TOKENS[:3]:
            keys.add(f"{base}_{mac}")
            keys.add(f"{mac}_{base}")

    # SN-based
    for sn in SN_TOKENS:
        keys.add(sn)
        for keyrole in KEYROLE_TOKENS:
            keys.add(f"{sn}_{keyrole}")
            keys.add(f"{keyrole}_{sn}")
        for base in BASE_TOKENS[:3]:
            keys.add(f"{base}_{sn}")

    # Hardware version based
    for hw in HW_TOKENS:
        for base in BASE_TOKENS[:3]:
            keys.add(f"{base}_{hw}")
            for keyrole in KEYROLE_TOKENS:
                keys.add(f"{base}_{hw}_{keyrole}")

    # Combined patterns (base + MAC + keyrole)
    for base in BASE_TOKENS[:3]:
        for mac in MAC_TOKENS[:2]:
            for keyrole in KEYROLE_TOKENS[:6]:
                keys.add(f"{base}_{mac}_{keyrole}")

    # ISP specific
    isp_patterns = [
        "AIS", "ais", "AIS_KEY", "ais_key", "AISKey", "AISkey",
        "AIS_HG8145B7N", "HG8145B7N_AIS", "AIS_key", "AIS_AES",
        "AIS_config", "AIS_cfgkey", "AISHuawei", "HuaweiAIS",
    ]
    keys.update(isp_patterns)

    # Common Huawei defaults
    defaults = [
        "huawei", "HUAWEI", "Huawei", "admin", "root",
        "telecomadmin", "admintelecom", "hw_ctree",
        "hwctree", "ctree", "hw_ctree_key", "hw_config",
        "$1$YaKi9SFn$", "password", "12345678",
    ]
    keys.update(defaults)

    # Combine defaults with device info
    for d in defaults[:5]:
        for base in BASE_TOKENS[:3]:
            keys.add(f"{d}_{base}")
            keys.add(f"{base}_{d}")

    return list(keys)

def derive_aes_keys(password):
    """Derive various AES keys from a password"""
    if isinstance(password, str):
        pwd_bytes = password.encode('utf-8')
    else:
        pwd_bytes = password

    keys = []

    # MD5 (16 bytes)
    keys.append(hashlib.md5(pwd_bytes).digest())

    # SHA256 truncated (16 bytes)
    keys.append(hashlib.sha256(pwd_bytes).digest()[:16])

    # SHA256 full (32 bytes)
    keys.append(hashlib.sha256(pwd_bytes).digest())

    # SHA1 truncated (16 bytes)
    keys.append(hashlib.sha1(pwd_bytes).digest()[:16])

    # Direct padding to 16 bytes
    if len(pwd_bytes) <= 16:
        keys.append(pwd_bytes.ljust(16, b'\x00'))
    else:
        keys.append(pwd_bytes[:16])

    # Direct padding to 32 bytes
    if len(pwd_bytes) <= 32:
        keys.append(pwd_bytes.ljust(32, b'\x00'))
    else:
        keys.append(pwd_bytes[:32])

    return keys

def aes_decrypt(data, key, mode='ECB', iv=None):
    """AES decryption"""
    try:
        if len(key) not in [16, 24, 32]:
            if len(key) < 16:
                key = key.ljust(16, b'\x00')
            elif len(key) < 24:
                key = key[:16]
            elif len(key) < 32:
                key = key[:24]
            else:
                key = key[:32]

        if len(data) % 16 != 0:
            data = data[:len(data) - (len(data) % 16)]

        if len(data) == 0:
            return None

        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            cipher = AES.new(key, AES.MODE_CBC, iv if iv else bytes(16))
        return cipher.decrypt(data)
    except:
        return None

def try_decompress(data):
    """Try decompression"""
    if not data:
        return None, None

    # GZIP
    if len(data) >= 2 and data[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(data), 'gzip'
        except:
            pass

    # ZLIB variants
    for wbits in [15, -15, 31, 47, -zlib.MAX_WBITS]:
        try:
            return zlib.decompress(data, wbits), f'zlib({wbits})'
        except:
            pass

    return None, None

def is_valid_xml(data):
    """Check if data is valid XML config"""
    if not data or len(data) < 20:
        return False

    try:
        text = data.decode('utf-8', errors='ignore')

        # Check for XML patterns
        xml_patterns = [
            '<?xml',
            '<InternetGatewayDevice',
            '<DeviceInfo',
            '<X_HW_',
            '<WLANConfiguration',
            '<WANDevice',
            '<LANDevice',
            '<Services',
            '<ManagementServer',
            '<config',
            '<Config',
            'Manufacturer',
            'DeviceSummary',
        ]

        for pattern in xml_patterns:
            if pattern in text[:5000]:
                return True

    except:
        pass

    return False

def decrypt_file(filepath, data, offsets):
    """Try to decrypt file with all keys"""

    # Generate passwords from patterns
    passwords = generate_all_keys()
    print(f"[*] Generated {len(passwords)} password patterns")

    # Derive AES keys from passwords
    all_keys = []
    for pwd in passwords:
        derived = derive_aes_keys(pwd)
        all_keys.extend(derived)

    # Remove duplicates
    unique_keys = []
    seen = set()
    for k in all_keys:
        kh = k.hex()
        if kh not in seen and len(k) in [16, 24, 32]:
            seen.add(kh)
            unique_keys.append(k)

    print(f"[*] Total unique AES keys: {len(unique_keys)}")

    total_attempts = len(unique_keys) * len(offsets) * 3  # keys * offsets * modes
    attempt = 0

    for offset in offsets:
        if offset >= len(data):
            continue

        ct = data[offset:]
        print(f"\n[*] Testing offset: {offset}")

        for key in unique_keys:
            attempt += 1
            if attempt % 10000 == 0:
                print(f"    Progress: {attempt}/{total_attempts}")

            # ECB mode
            dec = aes_decrypt(ct, key, 'ECB')
            if dec:
                # Check direct
                if is_valid_xml(dec):
                    return dec, key, 'ECB', offset, None

                # Check after decompress
                decomp, comp = try_decompress(dec)
                if decomp and is_valid_xml(decomp):
                    return decomp, key, 'ECB', offset, comp

            # CBC with zero IV
            dec = aes_decrypt(ct, key, 'CBC', bytes(16))
            if dec:
                if is_valid_xml(dec):
                    return dec, key, 'CBC(0)', offset, None

                decomp, comp = try_decompress(dec)
                if decomp and is_valid_xml(decomp):
                    return decomp, key, 'CBC(0)', offset, comp

            # CBC with IV from data
            if len(data) > offset + 16:
                iv = data[offset:offset+16]
                ct2 = data[offset+16:]
                dec = aes_decrypt(ct2, key, 'CBC', iv)
                if dec:
                    if is_valid_xml(dec):
                        return dec, key, 'CBC(IV)', offset, None

                    decomp, comp = try_decompress(dec)
                    if decomp and is_valid_xml(decomp):
                        return decomp, key, 'CBC(IV)', offset, comp

    return None, None, None, None, None

def main():
    print("=" * 60)
    print("Exhaustive Pattern-Based Key Decryption")
    print("Following user's 6 composition patterns")
    print("=" * 60)

    files = [
        ("/home/user/routerde/hw_ctree.xml", [8, 72, 100, 104, 108, 96, 128]),
        ("/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf", [0, 16]),
    ]

    for filepath, offsets in files:
        if not os.path.exists(filepath):
            continue

        print(f"\n{'='*60}")
        print(f"Processing: {os.path.basename(filepath)}")
        print("=" * 60)

        with open(filepath, 'rb') as f:
            raw_data = f.read()

        print(f"Raw size: {len(raw_data)}")

        # For .conf, try base64 decode
        if filepath.endswith('.conf'):
            try:
                data = base64.b64decode(raw_data)
                print(f"Base64 decoded: {len(data)}")
            except:
                data = raw_data
        else:
            data = raw_data

        result, key, mode, offset, compression = decrypt_file(filepath, data, offsets)

        if result:
            print(f"\n[+] SUCCESS!")
            print(f"[+] Key: {key.hex()}")
            print(f"[+] Mode: {mode}")
            print(f"[+] Offset: {offset}")
            if compression:
                print(f"[+] Compression: {compression}")

            out_path = filepath + ".decrypted.xml"
            with open(out_path, 'wb') as f:
                f.write(result)
            print(f"[+] Saved to: {out_path}")

            print(f"\n{'='*60}")
            print("DECRYPTED CONTENT")
            print("=" * 60)
            try:
                print(result[:5000].decode('utf-8', errors='replace'))
            except:
                print(result[:5000])
            print("=" * 60)
        else:
            print("\n[-] Could not decrypt")

    print("\n" + "=" * 60)
    print("Decryption attempts completed")
    print("=" * 60)

if __name__ == "__main__":
    main()
