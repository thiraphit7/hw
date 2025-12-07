#!/usr/bin/env python3
"""
Extended Huawei Decryption - Try more methods
Including XOR, different key derivations, and pattern analysis
"""

import base64
import gzip
import zlib
import struct
import os
import hashlib
from Crypto.Cipher import AES, DES, DES3
import binascii

# Device info
DEVICE = {
    "model": "HG8145B7N",
    "mac": "E0AEA2EFB1CD",
    "sn": "48575443286F3DB5",
    "sn_readable": "HWTC286F3DB5",
    "hw_ver": "39E7.A",
    "fw_ver": "V5R023C10S104",
    "custom": "AIS",
}

def xor_decrypt(data, key):
    """XOR decryption with repeating key"""
    if isinstance(key, str):
        key = key.encode()
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return bytes(result)

def des_decrypt_ecb(data, key):
    """DES-ECB decryption"""
    try:
        if len(key) != 8:
            key = key[:8].ljust(8, b'\x00')
        if len(data) % 8 != 0:
            data = data[:len(data) - (len(data) % 8)]
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.decrypt(data)
    except:
        return None

def des3_decrypt(data, key):
    """3DES decryption"""
    try:
        if len(key) < 16:
            key = key.ljust(16, b'\x00')
        elif len(key) < 24:
            key = key[:16]
        if len(data) % 8 != 0:
            data = data[:len(data) - (len(data) % 8)]
        cipher = DES3.new(key[:16], DES3.MODE_ECB)
        return cipher.decrypt(data)
    except:
        return None

def aes_decrypt(data, key, mode='ECB', iv=None):
    """AES decryption"""
    try:
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

        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            if iv is None:
                iv = bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv[:16])
        return cipher.decrypt(data)
    except:
        return None

def try_decompress(data):
    """Try decompression"""
    if not data:
        return None, None

    # GZIP
    if data[:2] == b'\x1f\x8b':
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

def is_valid_output(data):
    """Check if output is valid"""
    if not data or len(data) < 20:
        return False

    try:
        text = data.decode('utf-8', errors='ignore')

        # XML patterns
        if '<?xml' in text[:200]:
            return True

        # Config patterns
        patterns = [
            '<InternetGatewayDevice',
            '<DeviceInfo',
            '<X_HW_',
            '<WLANConfiguration',
            '<WANDevice',
            '<LANDevice',
            '<Services',
            'DeviceSummary',
            'Manufacturer',
            '<config',
            '<Config',
            '<root',
        ]
        for p in patterns:
            if p in text[:5000]:
                return True

    except:
        pass

    return False

def generate_extended_keys():
    """Generate extended key list"""
    keys = []

    # Device-specific patterns following user's 6 pattern rules
    bases = [
        "HG8145B7N", "hg8145b7n", "HuaweiHG8145B7N", "AIS_HG8145B7N",
        "HG8145B7N-AIS", "OptiXstar", "OptiXstarHG8145B7N",
        DEVICE["mac"], DEVICE["sn"], DEVICE["sn_readable"],
    ]

    keyroles = [
        "key", "KEY", "aes", "AES", "cfg", "CFG",
        "cfgkey", "CFGKEY", "config", "CONFIG",
        "DecKey", "EncKey", "secret", "SECRET",
    ]

    versions = [DEVICE["fw_ver"], "V5R023C10", "V5"]
    years = ["2023", "2024", "2025"]

    # Pattern 1: base
    for b in bases:
        keys.append(b.encode())

    # Pattern 2: base_keyrole
    for b in bases:
        for k in keyroles:
            keys.append(f"{b}_{k}".encode())
            keys.append(f"{b}{k}".encode())

    # Pattern 3: keyrole_base
    for k in keyroles:
        for b in bases:
            keys.append(f"{k}_{b}".encode())
            keys.append(f"{k}{b}".encode())

    # Pattern 4: base + keyrole (no separator)
    for b in bases:
        for k in keyroles:
            keys.append(f"{b}{k}".encode())

    # Pattern 5: base_year
    for b in bases:
        for y in years:
            keys.append(f"{b}_{y}".encode())
            keys.append(f"{b}{y}".encode())

    # Pattern 6: base_firmware_keyrole
    for b in bases:
        for v in versions:
            for k in keyroles:
                keys.append(f"{b}_{v}_{k}".encode())
                keys.append(f"{b}{v}{k}".encode())

    # Common passwords
    common = [
        b"huawei", b"HUAWEI", b"admin", b"root",
        b"telecomadmin", b"admintelecom", b"password",
        b"hw_ctree_key", b"hw_ctree", b"ctree",
        b"AIS", b"ais", b"AISkey", b"ais_key",
        b"$1$YaKi9SFn$",
    ]
    keys.extend(common)

    # Known Huawei keys
    known_hex = [
        "13395537D2730554A176799F6D56A239",
        "6f479607f7a662b26bef918e242295b649e717ed84d80c944fa0aa9a26363f87",
        "1AAAB4A730B23E1FC8A1D59C79283A228B78410ECC46FA4F48EB1456E24C5B89",
        "0102030405060708",  # DES key
    ]
    for h in known_hex:
        try:
            keys.append(bytes.fromhex(h))
        except:
            pass

    # Derive hashes from all keys
    derived = []
    for k in keys:
        if isinstance(k, str):
            k = k.encode()
        derived.append(hashlib.md5(k).digest())
        derived.append(hashlib.sha256(k).digest())
        derived.append(hashlib.sha256(k).digest()[:16])
        derived.append(hashlib.sha1(k).digest()[:16])

    keys.extend(derived)

    # Remove duplicates, keep only valid lengths
    unique = []
    seen = set()
    for k in keys:
        if isinstance(k, str):
            k = k.encode()
        # For XOR, any length works; for AES we'll handle separately
        kh = k.hex() if isinstance(k, bytes) else k
        if kh not in seen:
            seen.add(kh)
            unique.append(k if isinstance(k, bytes) else k.encode())

    return unique

def analyze_patterns(data, offset=0):
    """Analyze data patterns"""
    analysis = []

    # Check entropy
    if len(data) > 100:
        byte_counts = [0] * 256
        for b in data[offset:offset+1000]:
            byte_counts[b] += 1
        non_zero = sum(1 for c in byte_counts if c > 0)
        analysis.append(f"Byte diversity: {non_zero}/256")

    # Look for repeating patterns
    if len(data) > 32:
        for block_size in [16, 32]:
            if data[offset:offset+block_size] == data[offset+block_size:offset+block_size*2]:
                analysis.append(f"Repeating {block_size}-byte blocks detected")

    return analysis

def main():
    print("=" * 60)
    print("Extended Huawei Decryption")
    print("=" * 60)

    files = [
        "/home/user/routerde/hw_ctree.xml",
        "/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf",
    ]

    keys = generate_extended_keys()
    print(f"Generated {len(keys)} unique keys")

    for filepath in files:
        if not os.path.exists(filepath):
            continue

        print(f"\n{'='*60}")
        print(f"Processing: {os.path.basename(filepath)}")
        print("=" * 60)

        with open(filepath, 'rb') as f:
            raw_data = f.read()

        # Prepare data variants
        variants = [("raw", raw_data)]

        # For conf file, try base64 decode
        if filepath.endswith('.conf'):
            try:
                decoded = base64.b64decode(raw_data)
                variants.append(("base64", decoded))
            except:
                pass

        # Determine offsets based on file type
        if 'hw_ctree' in filepath:
            offsets = [0, 8, 72, 100, 104, 108, 96, 128]
        else:
            offsets = [0, 16, 32]

        success = False

        for var_name, data in variants:
            if success:
                break

            print(f"\n[*] Variant: {var_name}, size: {len(data)}")

            # Pattern analysis
            patterns = analyze_patterns(data)
            for p in patterns:
                print(f"  {p}")

            for offset in offsets:
                if success or offset >= len(data):
                    continue

                ct = data[offset:]
                if len(ct) < 16:
                    continue

                # Try XOR with each key
                print(f"\n  Testing XOR at offset {offset}...")
                for key in keys[:100]:  # Limit XOR attempts
                    dec = xor_decrypt(ct, key)
                    if is_valid_output(dec):
                        print(f"\n  [+] SUCCESS! XOR")
                        print(f"  [+] Key: {key[:32]}...")
                        save_result(filepath, dec)
                        success = True
                        break

                    # Try decompress after XOR
                    decomp, comp = try_decompress(dec)
                    if decomp and is_valid_output(decomp):
                        print(f"\n  [+] SUCCESS! XOR + {comp}")
                        print(f"  [+] Key: {key[:32]}...")
                        save_result(filepath, decomp)
                        success = True
                        break

                if success:
                    break

                # Try DES
                print(f"  Testing DES at offset {offset}...")
                for key in keys[:50]:
                    dec = des_decrypt_ecb(ct, key)
                    if dec and is_valid_output(dec):
                        print(f"\n  [+] SUCCESS! DES-ECB")
                        save_result(filepath, dec)
                        success = True
                        break

                    if dec:
                        decomp, comp = try_decompress(dec)
                        if decomp and is_valid_output(decomp):
                            print(f"\n  [+] SUCCESS! DES + {comp}")
                            save_result(filepath, decomp)
                            success = True
                            break

                if success:
                    break

                # Try AES
                print(f"  Testing AES at offset {offset}...")
                attempt = 0
                for key in keys:
                    if len(key) < 16:
                        key_aes = key.ljust(16, b'\x00')
                    elif len(key) < 32:
                        key_aes = key[:16] if len(key) <= 16 else key[:24]
                    else:
                        key_aes = key[:32]

                    for mode in ['ECB', 'CBC']:
                        ivs = [bytes(16)]
                        if mode == 'CBC' and len(data) >= 16:
                            ivs.append(data[:16])
                            if offset >= 16:
                                ivs.append(data[offset-16:offset])

                        for iv in ivs:
                            attempt += 1
                            if attempt % 2000 == 0:
                                print(f"    Progress: {attempt} attempts...")

                            dec = aes_decrypt(ct, key_aes, mode, iv)
                            if not dec:
                                continue

                            if is_valid_output(dec):
                                print(f"\n  [+] SUCCESS! AES-{mode}")
                                print(f"  [+] Key: {key_aes.hex()}")
                                if mode == 'CBC':
                                    print(f"  [+] IV: {iv.hex()}")
                                save_result(filepath, dec)
                                success = True
                                break

                            decomp, comp = try_decompress(dec)
                            if decomp and is_valid_output(decomp):
                                print(f"\n  [+] SUCCESS! AES-{mode} + {comp}")
                                print(f"  [+] Key: {key_aes.hex()}")
                                save_result(filepath, decomp)
                                success = True
                                break

                        if success:
                            break
                    if success:
                        break

        if not success:
            print("\n[-] Could not decrypt this file")

def save_result(filepath, data):
    """Save decrypted data"""
    out_path = filepath + ".decrypted.xml"
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"  [+] Saved to: {out_path}")
    print(f"  [+] Size: {len(data)} bytes")
    print("\n  Preview:")
    print("  " + "-"*50)
    try:
        preview = data[:2000].decode('utf-8', errors='replace')
        for line in preview.split('\n')[:30]:
            print(f"  {line}")
    except:
        print(f"  {data[:500]}")
    print("  " + "-"*50)

if __name__ == "__main__":
    main()
