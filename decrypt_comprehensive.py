#!/usr/bin/env python3
"""
Comprehensive Huawei Router Config Decryption Tool
Tries multiple keys, modes, and compressions
"""

import base64
import gzip
import zlib
import struct
import os
import hashlib
import itertools
from Crypto.Cipher import AES
import binascii

# Device info for key generation
DEVICE = {
    "model": "HG8145B7N",
    "mac": "E0AEA2EFB1CD",
    "sn": "48575443286F3DB5",
    "sn_readable": "HWTC286F3DB5",
    "hw_ver": "39E7.A",
    "fw_ver": "V5R023C10S104",
}

# Known Huawei keys from various sources
KNOWN_KEYS = {
    # Standard Huawei key
    "huawei_std": bytes.fromhex("13395537D2730554A176799F6D56A239"),

    # HG659 keys
    "hg659_new": bytes.fromhex("6f479607f7a662b26bef918e242295b649e717ed84d80c944fa0aa9a26363f87"),
    "hg659_legacy": bytes.fromhex("1AAAB4A730B23E1FC8A1D59C79283A228B78410ECC46FA4F48EB1456E24C5B89"),

    # Zero key
    "zero_16": bytes(16),
    "zero_32": bytes(32),

    # Common patterns
    "ff_16": bytes([0xff] * 16),
}

# Known IVs
KNOWN_IVS = {
    "zero": bytes(16),
    "hg659_new": bytes.fromhex("c48368fe028ba92e83154e3ab15ccb78"),
    "hg659_legacy": bytes.fromhex("D1FE7512325C5713D362D332AFA3644C"),
}

def generate_device_keys():
    """Generate keys based on device information"""
    keys = []

    # Base strings
    bases = [
        DEVICE["model"],
        DEVICE["mac"],
        DEVICE["sn"],
        DEVICE["sn_readable"],
        DEVICE["hw_ver"],
        DEVICE["fw_ver"],
        "HG8145B7N",
        "AIS",
        "huawei",
        "admin",
        "telecomadmin",
        "root",
    ]

    suffixes = [
        "", "key", "KEY", "aes", "AES", "cfg", "CFG",
        "config", "CONFIG", "EncKey", "DecKey", "secret"
    ]

    for base in bases:
        for suffix in suffixes:
            pwd = f"{base}{suffix}" if suffix else base
            pwd_bytes = pwd.encode('utf-8')

            # MD5 (16 bytes)
            keys.append(hashlib.md5(pwd_bytes).digest())

            # SHA256 (32 bytes)
            keys.append(hashlib.sha256(pwd_bytes).digest())

            # SHA256 truncated (16 bytes)
            keys.append(hashlib.sha256(pwd_bytes).digest()[:16])

            # Direct padding to 16
            if len(pwd_bytes) <= 16:
                keys.append(pwd_bytes.ljust(16, b'\x00'))

            # Direct padding to 32
            if len(pwd_bytes) <= 32:
                keys.append(pwd_bytes.ljust(32, b'\x00'))

    # Combined patterns
    combos = [
        f"{DEVICE['model']}_{DEVICE['mac']}",
        f"{DEVICE['model']}_{DEVICE['sn']}",
        f"{DEVICE['mac']}_{DEVICE['model']}",
        f"{DEVICE['model']}_{DEVICE['fw_ver']}",
        f"HG8145B7N_AIS",
        f"AIS_HG8145B7N",
        f"HG8145B7N_V5R023C10S104_AES",
    ]

    for combo in combos:
        keys.append(hashlib.md5(combo.encode()).digest())
        keys.append(hashlib.sha256(combo.encode()).digest())
        keys.append(hashlib.sha256(combo.encode()).digest()[:16])

    return keys

def aes_decrypt(ciphertext, key, mode='ECB', iv=None):
    """AES decryption with automatic key sizing"""
    try:
        # Ensure key is valid length
        if len(key) == 16:
            pass  # AES-128
        elif len(key) == 24:
            pass  # AES-192
        elif len(key) == 32:
            pass  # AES-256
        elif len(key) < 16:
            key = key.ljust(16, b'\x00')
        elif len(key) < 24:
            key = key[:16]
        elif len(key) < 32:
            key = key[:24]
        else:
            key = key[:32]

        # Align ciphertext to block size
        if len(ciphertext) % 16 != 0:
            ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]

        if len(ciphertext) == 0:
            return None

        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        else:  # CBC
            if iv is None:
                iv = bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv[:16])

        return cipher.decrypt(ciphertext)
    except Exception as e:
        return None

def try_decompress(data):
    """Try various decompression methods"""
    if not data:
        return None, None

    # Check for GZIP header
    if len(data) >= 2 and data[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(data), 'gzip'
        except:
            pass

    # Try zlib with various window sizes
    for wbits in [15, -15, 31, 47, -zlib.MAX_WBITS]:
        try:
            return zlib.decompress(data, wbits), f'zlib({wbits})'
        except:
            pass

    # Try raw deflate
    try:
        decomp = zlib.decompressobj(-zlib.MAX_WBITS)
        return decomp.decompress(data), 'deflate'
    except:
        pass

    return None, None

def is_valid_xml(data):
    """Check if data is valid XML configuration"""
    if not data or len(data) < 10:
        return False

    try:
        text = data.decode('utf-8', errors='ignore')

        # Check for XML declaration
        if '<?xml' in text[:100]:
            return True

        # Check for Huawei config tags
        config_tags = [
            '<InternetGatewayDevice',
            '<DeviceInfo',
            '<X_HW_',
            '<LANDevice',
            '<WANDevice',
            '<WLANConfiguration',
            '<Services',
            '<ManagementServer',
            '<Layer2Bridging',
            '<IPPingDiagnostics',
            '<VoiceService',
        ]
        for tag in config_tags:
            if tag in text[:5000]:
                return True

    except:
        pass

    return False

def decrypt_file(filepath, encrypted_data, file_type):
    """Try all decryption combinations"""

    # Build key list
    all_keys = list(KNOWN_KEYS.values()) + generate_device_keys()

    # Remove duplicates
    unique_keys = []
    seen = set()
    for k in all_keys:
        if len(k) in [16, 24, 32]:
            kh = k.hex()
            if kh not in seen:
                seen.add(kh)
                unique_keys.append(k)

    print(f"[*] Testing {len(unique_keys)} unique keys")

    # Offsets to try (for hw_ctree.xml header)
    if file_type == 'hwctree':
        offsets = [8, 72, 100, 104, 108, 112, 96, 128]
    else:
        offsets = [0, 16]  # For conf file: start or after IV

    total = len(unique_keys) * len(offsets) * 2 * 3  # keys * offsets * modes * iv_variants
    attempt = 0

    for offset in offsets:
        if offset >= len(encrypted_data):
            continue

        ct = encrypted_data[offset:]

        for key in unique_keys:
            for mode in ['ECB', 'CBC']:
                if mode == 'CBC':
                    ivs = [
                        bytes(16),  # Zero IV
                        KNOWN_IVS.get('hg659_new', bytes(16)),
                        KNOWN_IVS.get('hg659_legacy', bytes(16)),
                        encrypted_data[:16] if len(encrypted_data) >= 16 else bytes(16),  # IV from data
                    ]
                else:
                    ivs = [None]

                for iv in ivs:
                    attempt += 1
                    if attempt % 5000 == 0:
                        print(f"  Progress: {attempt}/{total}")

                    decrypted = aes_decrypt(ct, key, mode, iv)
                    if not decrypted:
                        continue

                    # Check if decrypted data is directly valid
                    if is_valid_xml(decrypted):
                        return decrypted, key, mode, iv, offset, None

                    # Try decompress
                    decompressed, comp_method = try_decompress(decrypted)
                    if decompressed and is_valid_xml(decompressed):
                        return decompressed, key, mode, iv, offset, comp_method

    return None, None, None, None, None, None

def process_hwctree(filepath):
    """Process hw_ctree.xml file"""
    print(f"\n{'='*60}")
    print(f"Processing: {filepath}")
    print("=" * 60)

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)} bytes")
    print(f"Header magic: {binascii.hexlify(data[:4]).decode()}")

    result, key, mode, iv, offset, compression = decrypt_file(filepath, data, 'hwctree')

    if result:
        print(f"\n[+] SUCCESS!")
        print(f"[+] Key: {key.hex()}")
        print(f"[+] Mode: {mode}")
        if iv:
            print(f"[+] IV: {iv.hex()}")
        print(f"[+] Offset: {offset}")
        if compression:
            print(f"[+] Compression: {compression}")

        # Save result
        out_path = filepath + ".decrypted.xml"
        with open(out_path, 'wb') as f:
            f.write(result)
        print(f"[+] Saved to: {out_path}")

        # Show preview
        print(f"\n{'='*60}")
        print("DECRYPTED CONTENT")
        print("=" * 60)
        try:
            print(result[:5000].decode('utf-8', errors='replace'))
        except:
            print(result[:5000])
        print("=" * 60)

        return True

    print("\n[-] Could not decrypt")
    return False

def process_conf(filepath):
    """Process .conf file"""
    print(f"\n{'='*60}")
    print(f"Processing: {filepath}")
    print("=" * 60)

    with open(filepath, 'rb') as f:
        raw_data = f.read()

    print(f"Raw size: {len(raw_data)} bytes")

    # Try Base64 decode
    try:
        data = base64.b64decode(raw_data)
        print(f"Base64 decoded: {len(data)} bytes")
    except:
        data = raw_data
        print("Using raw data")

    result, key, mode, iv, offset, compression = decrypt_file(filepath, data, 'conf')

    if result:
        print(f"\n[+] SUCCESS!")
        print(f"[+] Key: {key.hex()}")
        print(f"[+] Mode: {mode}")
        if iv:
            print(f"[+] IV: {iv.hex()}")
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

        return True

    print("\n[-] Could not decrypt")
    return False

def main():
    print("=" * 60)
    print("Comprehensive Huawei Config Decryption")
    print("=" * 60)

    xml_file = "/home/user/routerde/hw_ctree.xml"
    conf_file = "/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf"

    success = False

    if os.path.exists(xml_file):
        if process_hwctree(xml_file):
            success = True

    if os.path.exists(conf_file):
        if process_conf(conf_file):
            success = True

    if not success:
        print("\n[!] Standard keys did not work.")
        print("[!] The router might use a custom ISP-specific key.")
        print("[!] The key might be in /etc/wap/aes_string on the router.")

if __name__ == "__main__":
    main()
