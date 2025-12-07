#!/usr/bin/env python3
"""
Huawei HG8145B7N Router Configuration Decryption Tool
=====================================================

Device Information:
- Model: HG8145B7N-AIS
- MAC: E0:AE:A2:EF:B1:CD
- SN: 48575443286F3DB5 (HWTC286F3DB5)
- Hardware: 39E7.A
- Firmware: V5R023C10S104
- ISP: AIS Thailand

Key Generation Patterns (6 Composition Rules):
1. <base> → HG8145B7N
2. <base>_<keyrole> → HG8145B7N_AES
3. <keyrole>_<base> → cfgkey_HG8145B7N
4. <base><keyrole> → HG8145B7Nkey
5. <base>_<year> → HG8145B7N_2024
6. <base>_<firmware>_<keyrole> → HG8145B7N_V5R023C10_AES

Status: Keys generated from patterns did not decrypt files.
AIS Thailand likely uses a custom encryption key.

To get the actual key:
1. Access router via Telnet/SSH
2. Read /etc/wap/aes_string
3. Or extract from firmware binary

Sources:
- https://github.com/palmerc/AESCrypt2
- https://hg659.home.blog/2019/12/07/known-plaintext-attack-on-aes-keys-to-decrypt-huawei-hg659-config-backups/
"""

import base64
import gzip
import zlib
import os
import hashlib
import argparse
from Crypto.Cipher import AES
import binascii

# Base tokens (11 variants)
BASE_TOKENS = [
    "HG8145B7N", "hg8145b7n", "HuaweiHG8145B7N", "AIS_HG8145B7N",
    "HG8145B7N-AIS", "hg8145b7n-ais", "Huawei_HG8145B7N", "HUAWEI_HG8145B7N",
    "HG8145B7NAIS", "OptiXstar", "OptiXstarHG8145B7N",
]

# Key-role tokens (9+ patterns)
KEYROLE_TOKENS = [
    "key", "KEY", "Key", "aes", "AES", "Aes", "cfg", "CFG",
    "cfgkey", "CFGKEY", "config", "CONFIG", "DecKey", "EncKey",
]

# Version tokens
VERSION_TOKENS = ["V5R023C10S104", "V5R023C10", "V5"]

# Year tokens
YEAR_TOKENS = ["2023", "2024", "2025"]

# Device info
DEVICE = {
    "mac": "E0AEA2EFB1CD",
    "sn": "48575443286F3DB5",
    "sn_readable": "HWTC286F3DB5",
    "hw_ver": "39E7.A",
    "fw_ver": "V5R023C10S104",
}

# Known Huawei keys
KNOWN_KEYS = [
    bytes.fromhex("13395537D2730554A176799F6D56A239"),  # Standard Huawei
    bytes.fromhex("6f479607f7a662b26bef918e242295b649e717ed84d80c944fa0aa9a26363f87"),  # HG659
]

def generate_keys():
    """Generate all possible keys from patterns"""
    passwords = set()

    # Pattern 1: <base>
    passwords.update(BASE_TOKENS)

    # Pattern 2: <base>_<keyrole>
    for base in BASE_TOKENS:
        for keyrole in KEYROLE_TOKENS:
            passwords.add(f"{base}_{keyrole}")

    # Pattern 3: <keyrole>_<base>
    for keyrole in KEYROLE_TOKENS:
        for base in BASE_TOKENS:
            passwords.add(f"{keyrole}_{base}")

    # Pattern 4: <base><keyrole>
    for base in BASE_TOKENS:
        for keyrole in KEYROLE_TOKENS:
            passwords.add(f"{base}{keyrole}")

    # Pattern 5: <base>_<year>
    for base in BASE_TOKENS:
        for year in YEAR_TOKENS:
            passwords.add(f"{base}_{year}")

    # Pattern 6: <base>_<firmware>_<keyrole>
    for base in BASE_TOKENS:
        for version in VERSION_TOKENS:
            for keyrole in KEYROLE_TOKENS:
                passwords.add(f"{base}_{version}_{keyrole}")

    # Device-specific
    passwords.add(DEVICE["mac"])
    passwords.add(DEVICE["sn"])
    passwords.add(DEVICE["sn_readable"])

    # Common defaults
    defaults = [
        "huawei", "HUAWEI", "admin", "root", "telecomadmin",
        "hw_ctree", "ctree", "AIS", "ais", "$1$YaKi9SFn$",
    ]
    passwords.update(defaults)

    # Derive AES keys
    keys = list(KNOWN_KEYS)
    for pwd in passwords:
        pwd_bytes = pwd.encode('utf-8')
        keys.append(hashlib.md5(pwd_bytes).digest())
        keys.append(hashlib.sha256(pwd_bytes).digest()[:16])
        keys.append(hashlib.sha256(pwd_bytes).digest())
        if len(pwd_bytes) <= 16:
            keys.append(pwd_bytes.ljust(16, b'\x00'))
        if len(pwd_bytes) <= 32:
            keys.append(pwd_bytes.ljust(32, b'\x00'))

    # Remove duplicates
    unique = []
    seen = set()
    for k in keys:
        if len(k) in [16, 24, 32]:
            kh = k.hex()
            if kh not in seen:
                seen.add(kh)
                unique.append(k)

    return unique

def aes_decrypt(data, key, mode='ECB', iv=None):
    """AES decryption"""
    try:
        if len(key) not in [16, 24, 32]:
            if len(key) < 16:
                key = key.ljust(16, b'\x00')
            else:
                key = key[:32] if len(key) > 24 else key[:16]

        if len(data) % 16 != 0:
            data = data[:len(data) - (len(data) % 16)]

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

    if len(data) >= 2 and data[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(data), 'gzip'
        except:
            pass

    for wbits in [15, -15, 31, 47, -zlib.MAX_WBITS]:
        try:
            return zlib.decompress(data, wbits), f'zlib({wbits})'
        except:
            pass

    return None, None

def is_valid_xml(data):
    """Check if data is valid XML"""
    if not data or len(data) < 20:
        return False
    try:
        text = data.decode('utf-8', errors='ignore')
        patterns = ['<?xml', '<InternetGatewayDevice', '<DeviceInfo',
                    '<X_HW_', '<WLANConfiguration', '<config']
        return any(p in text[:5000] for p in patterns)
    except:
        return False

def decrypt_hwctree(filepath, custom_key=None):
    """Decrypt hw_ctree.xml"""
    print(f"\n{'='*60}")
    print(f"Decrypting: {filepath}")
    print("=" * 60)

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)}")
    print(f"Header: {binascii.hexlify(data[:8]).decode()}")

    keys = [custom_key] if custom_key else generate_keys()
    print(f"Testing {len(keys)} keys...")

    offsets = [8, 72, 100, 104, 96, 128]

    for offset in offsets:
        if offset >= len(data):
            continue

        ct = data[offset:]

        for key in keys:
            for mode in ['ECB', 'CBC']:
                ivs = [bytes(16)] if mode == 'CBC' else [None]
                for iv in ivs:
                    dec = aes_decrypt(ct, key, mode, iv)
                    if not dec:
                        continue

                    if is_valid_xml(dec):
                        return save_result(filepath, dec, key, mode, offset, None)

                    decomp, comp = try_decompress(dec)
                    if decomp and is_valid_xml(decomp):
                        return save_result(filepath, decomp, key, mode, offset, comp)

    print("[-] Could not decrypt")
    return False

def decrypt_conf(filepath, custom_key=None):
    """Decrypt .conf file"""
    print(f"\n{'='*60}")
    print(f"Decrypting: {filepath}")
    print("=" * 60)

    with open(filepath, 'rb') as f:
        raw = f.read()

    try:
        data = base64.b64decode(raw)
        print(f"Base64 decoded: {len(data)} bytes")
    except:
        data = raw

    keys = [custom_key] if custom_key else generate_keys()
    print(f"Testing {len(keys)} keys...")

    for key in keys:
        for mode in ['ECB', 'CBC']:
            ivs = [bytes(16), data[:16]] if mode == 'CBC' else [None]
            for iv in ivs:
                ct = data[16:] if (mode == 'CBC' and iv == data[:16]) else data
                dec = aes_decrypt(ct, key, mode, iv)
                if not dec:
                    continue

                if is_valid_xml(dec):
                    return save_result(filepath, dec, key, mode, 0, None)

                decomp, comp = try_decompress(dec)
                if decomp and is_valid_xml(decomp):
                    return save_result(filepath, decomp, key, mode, 0, comp)

    print("[-] Could not decrypt")
    return False

def save_result(filepath, data, key, mode, offset, compression):
    """Save decrypted result"""
    print(f"\n[+] SUCCESS!")
    print(f"[+] Key: {key.hex()}")
    print(f"[+] Mode: {mode}")
    print(f"[+] Offset: {offset}")
    if compression:
        print(f"[+] Compression: {compression}")

    out_path = filepath + ".decrypted.xml"
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"[+] Saved to: {out_path}")

    print(f"\n{'='*60}")
    print("DECRYPTED CONTENT")
    print("=" * 60)
    try:
        print(data[:3000].decode('utf-8', errors='replace'))
    except:
        print(data[:3000])
    print("=" * 60)

    return True

def main():
    parser = argparse.ArgumentParser(description='Huawei HG8145B7N Config Decryptor')
    parser.add_argument('files', nargs='*', help='Files to decrypt')
    parser.add_argument('--key', help='Custom key in hex format')
    args = parser.parse_args()

    custom_key = bytes.fromhex(args.key) if args.key else None

    files = args.files or [
        '/home/user/routerde/hw_ctree.xml',
        '/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf',
    ]

    print("=" * 60)
    print("Huawei HG8145B7N Config Decryption Tool")
    print("=" * 60)

    if custom_key:
        print(f"Using custom key: {custom_key.hex()}")

    for filepath in files:
        if not os.path.exists(filepath):
            print(f"[-] File not found: {filepath}")
            continue

        if 'hw_ctree' in filepath:
            decrypt_hwctree(filepath, custom_key)
        elif filepath.endswith('.conf'):
            decrypt_conf(filepath, custom_key)

if __name__ == "__main__":
    main()
