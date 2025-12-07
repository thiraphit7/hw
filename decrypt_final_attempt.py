#!/usr/bin/env python3
"""
Final comprehensive decryption attempt
Combining all approaches with extended brute force
"""

import os
import struct
import binascii
import hashlib
import base64
import gzip
import zlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
import itertools
import string

# Constants
PREVIEW_OFFSET = 0x40
DATA_OFFSET = 0x15C
KNOWN_PLAINTEXT = b'<?xml version="1.0" encoding="UT'

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def try_aes_ctr(data, key, nonce, init_ctr):
    try:
        if len(key) != 16:
            return None
        if len(nonce) < 8:
            nonce = nonce.ljust(8, b'\x00')
        ctr = Counter.new(64, prefix=nonce[:8], initial_value=init_ctr)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(data)
    except:
        return None

def try_aes_ecb(data, key):
    try:
        if len(key) < 16:
            key = key.ljust(16, b'\x00')
        key = key[:16]
        if len(data) % 16 != 0:
            data = data[:len(data) - len(data) % 16]
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(data)
    except:
        return None

def try_aes_cbc(data, key, iv=None):
    try:
        if len(key) < 16:
            key = key.ljust(16, b'\x00')
        key = key[:16]
        if iv is None:
            iv = bytes(16)
        if len(iv) < 16:
            iv = iv.ljust(16, b'\x00')
        iv = iv[:16]
        if len(data) % 16 != 0:
            data = data[:len(data) - len(data) % 16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(data)
    except:
        return None

def try_decompress(data):
    if not data:
        return None

    if data[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(data)
        except:
            pass

    for wbits in [15, -15, 31, 47, -zlib.MAX_WBITS]:
        try:
            return zlib.decompress(data, wbits)
        except:
            pass

    return None

def is_valid_xml(data):
    if not data or len(data) < 20:
        return False
    try:
        text = data[:1000].decode('utf-8', errors='ignore')
        patterns = ['<?xml', '<InternetGatewayDevice', '<DeviceInfo',
                   '<X_HW_', '<WANDevice', '<LANDevice', 'Manufacturer']
        return any(p in text for p in patterns)
    except:
        return False

def generate_massive_keylist():
    """Generate a massive list of potential keys"""
    keys = set()

    # Known Huawei keys from various firmware
    known_hex = [
        "13395537D2730554A176799F6D56A239",
        "4a578eea3a10e2c68b34cfadffbf3a5d",
        "472f7363e72846b2c02a6e687c4c20f9",
        "00000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffff",
    ]
    for h in known_hex:
        try:
            keys.add(bytes.fromhex(h))
        except:
            pass

    # Device-specific patterns
    device_info = {
        "model": ["HG8145B7N", "HG8145B7N-AIS", "hg8145b7n", "OptiXstar"],
        "mac": ["E0AEA2EFB1CD", "e0aea2efb1cd"],
        "sn": ["48575443286F3DB5", "HWTC286F3DB5"],
        "fw": ["V5R023C10S104", "V5R023C10", "V5R023"],
        "hw": ["39E7.A", "39E7A"],
        "isp": ["AIS", "ais", "AISFiber", "TrueOnline", "3BB", "TOT"],
    }

    # All single values
    for category, values in device_info.items():
        for v in values:
            keys.add(v.encode()[:16].ljust(16, b'\x00'))
            keys.add(hashlib.md5(v.encode()).digest())
            keys.add(hashlib.sha256(v.encode()).digest()[:16])
            keys.add(hashlib.sha1(v.encode()).digest()[:16])

    # Combinations
    for m in device_info["model"]:
        for isp in device_info["isp"]:
            patterns = [
                f"{m}_{isp}", f"{isp}_{m}", f"{m}{isp}", f"{isp}{m}",
                f"{m}_KEY", f"{m}_AES", f"{m}_cfg", f"{isp}_KEY",
            ]
            for p in patterns:
                keys.add(p.encode()[:16].ljust(16, b'\x00'))
                keys.add(hashlib.md5(p.encode()).digest())

    # MAC-based
    mac = "E0AEA2EFB1CD"
    for m in device_info["model"]:
        patterns = [
            f"{m}_{mac}", f"{mac}_{m}", f"{m}{mac}",
        ]
        for p in patterns:
            keys.add(hashlib.md5(p.encode()).digest())

    # Serial-based
    for sn in device_info["sn"]:
        for m in device_info["model"][:2]:
            p = f"{m}_{sn}"
            keys.add(hashlib.md5(p.encode()).digest())

    # Common router passwords
    common = [
        "huawei", "HUAWEI", "Huawei", "admin", "root", "password",
        "telecomadmin", "admintelecom", "hw_ctree", "ctree", "config",
        "HuaweiHG", "HuaweiKey", "HGkey", "HG8145", "HGpassword",
        "$1$YaKi9SFn$", "YaKi9SFn", "1234567890123456",
    ]
    for c in common:
        keys.add(c.encode()[:16].ljust(16, b'\x00'))
        keys.add(hashlib.md5(c.encode()).digest())

    # Numeric patterns (dates, versions)
    for y in range(2018, 2026):
        for m in range(1, 13):
            for d in [1, 7, 9, 15, 20]:
                date = f"{y}{m:02d}{d:02d}"
                keys.add(date.encode().ljust(16, b'\x00'))
                keys.add(hashlib.md5(date.encode()).digest())

    # Header-based (will add from file)
    # Random 4-byte patterns
    for a in range(256):
        for b in range(256):
            key = bytes([a, b, a^b, (a+b) & 0xFF]) * 4
            keys.add(key)

    # Thai-specific patterns
    thai_patterns = [
        "AIS_Thailand", "AIS_FIBER", "AISFibre", "AISBroadband",
        "TrueMove", "DTAC", "3BBFibre", "TOT_Fiber",
        "BangkokNet", "CAT_Telecom", "NT_Thailand",
    ]
    for p in thai_patterns:
        keys.add(p.encode()[:16].ljust(16, b'\x00'))
        keys.add(hashlib.md5(p.encode()).digest())

    return list(keys)

def analyze_keystream_relationship(preview_ct, known_pt):
    """Analyze the keystream to find patterns"""
    ks = xor_bytes(preview_ct, known_pt)
    print(f"\n[Keystream Analysis]")
    print(f"  Block 0: {ks[:16].hex()}")
    print(f"  Block 1: {ks[16:32].hex() if len(ks) >= 32 else 'N/A'}")

    # Check for patterns
    if ks[:8] == ks[8:16]:
        print("  Pattern: First half equals second half!")

    # Analyze byte distribution
    byte_counts = {}
    for b in ks[:16]:
        byte_counts[b] = byte_counts.get(b, 0) + 1
    repeats = sum(1 for c in byte_counts.values() if c > 1)
    print(f"  Repeated bytes: {repeats}/16")

    return ks

def decrypt_hwctree(filepath, keys):
    """Attempt decryption of hw_ctree.xml"""
    print(f"\n{'='*60}")
    print(f"Decrypting: {filepath}")
    print('='*60)

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"Size: {len(data)} bytes")
    print(f"Header: {data[:8].hex()}")

    # Extract keystream
    preview_ct = data[PREVIEW_OFFSET:PREVIEW_OFFSET + 32]
    keystream = analyze_keystream_relationship(preview_ct, KNOWN_PLAINTEXT)

    data_section = data[DATA_OFFSET:]
    print(f"Data section: {len(data_section)} bytes at 0x{DATA_OFFSET:x}")

    # Nonces
    nonces = [
        bytes(8),
        data[0:8],
        data[48:56],
        data[56:64],
        data[0x148:0x150],
        keystream[:8],
    ]

    print(f"\nTesting {len(keys)} keys...")
    test_count = 0

    for key in keys:
        if len(key) != 16:
            continue

        test_count += 1
        if test_count % 10000 == 0:
            print(f"  Progress: {test_count}...")

        # CTR mode
        for nonce in nonces:
            for init_ctr in [0, 1, 4, 21]:
                # Data section
                dec = try_aes_ctr(data_section, key, nonce, init_ctr)
                if dec and is_valid_xml(dec):
                    print(f"\n[+] SUCCESS CTR!")
                    print(f"[+] Key: {key.hex()}")
                    print(f"[+] Nonce: {nonce.hex()}")
                    return dec, key, "CTR"

                # With decompression
                if dec:
                    decomp = try_decompress(dec)
                    if decomp and is_valid_xml(decomp):
                        print(f"\n[+] SUCCESS CTR + decompress!")
                        print(f"[+] Key: {key.hex()}")
                        return decomp, key, "CTR+decomp"

        # ECB mode at various offsets
        for offset in [DATA_OFFSET, PREVIEW_OFFSET, 8, 72, 100, 104]:
            if offset >= len(data):
                continue
            ct = data[offset:]
            dec = try_aes_ecb(ct, key)
            if dec and is_valid_xml(dec):
                print(f"\n[+] SUCCESS ECB at offset {offset}!")
                print(f"[+] Key: {key.hex()}")
                return dec, key, "ECB"
            if dec:
                decomp = try_decompress(dec)
                if decomp and is_valid_xml(decomp):
                    print(f"\n[+] SUCCESS ECB + decompress!")
                    return decomp, key, "ECB+decomp"

        # CBC mode
        for offset in [DATA_OFFSET, 8]:
            if offset >= len(data):
                continue
            ct = data[offset:]
            for iv_src in [bytes(16), data[offset-16:offset] if offset >= 16 else bytes(16)]:
                dec = try_aes_cbc(ct, key, iv_src)
                if dec and is_valid_xml(dec):
                    print(f"\n[+] SUCCESS CBC!")
                    print(f"[+] Key: {key.hex()}")
                    return dec, key, "CBC"
                if dec:
                    decomp = try_decompress(dec)
                    if decomp and is_valid_xml(decomp):
                        print(f"\n[+] SUCCESS CBC + decompress!")
                        return decomp, key, "CBC+decomp"

    print(f"[-] Tested {test_count} keys without success")
    return None, None, None

def decrypt_conf(filepath, keys):
    """Attempt decryption of .conf file"""
    print(f"\n{'='*60}")
    print(f"Decrypting: {filepath}")
    print('='*60)

    with open(filepath, 'rb') as f:
        raw = f.read()

    # Try base64 decode
    try:
        data = base64.b64decode(raw)
        print(f"Base64 decoded: {len(data)} bytes")
    except:
        data = raw
        print(f"Raw data: {len(data)} bytes")

    print(f"First 32 bytes: {data[:32].hex()}")

    test_count = 0
    for key in keys:
        if len(key) != 16:
            continue

        test_count += 1
        if test_count % 10000 == 0:
            print(f"  Progress: {test_count}...")

        # ECB
        dec = try_aes_ecb(data, key)
        if dec and is_valid_xml(dec):
            print(f"\n[+] SUCCESS ECB!")
            print(f"[+] Key: {key.hex()}")
            return dec, key, "ECB"
        if dec:
            decomp = try_decompress(dec)
            if decomp and is_valid_xml(decomp):
                print(f"\n[+] SUCCESS ECB + decompress!")
                return decomp, key, "ECB+decomp"

        # CBC
        dec = try_aes_cbc(data, key, bytes(16))
        if dec and is_valid_xml(dec):
            print(f"\n[+] SUCCESS CBC!")
            print(f"[+] Key: {key.hex()}")
            return dec, key, "CBC"
        if dec:
            decomp = try_decompress(dec)
            if decomp and is_valid_xml(decomp):
                print(f"\n[+] SUCCESS CBC + decompress!")
                return decomp, key, "CBC+decomp"

        # CBC with IV from data
        if len(data) > 16:
            dec = try_aes_cbc(data[16:], key, data[:16])
            if dec and is_valid_xml(dec):
                print(f"\n[+] SUCCESS CBC with IV from data!")
                print(f"[+] Key: {key.hex()}")
                return dec, key, "CBC+IV"
            if dec:
                decomp = try_decompress(dec)
                if decomp and is_valid_xml(decomp):
                    print(f"\n[+] SUCCESS CBC+IV + decompress!")
                    return decomp, key, "CBC+IV+decomp"

        # CTR
        for nonce in [bytes(8), data[:8]]:
            dec = try_aes_ctr(data, key, nonce, 0)
            if dec and is_valid_xml(dec):
                print(f"\n[+] SUCCESS CTR!")
                print(f"[+] Key: {key.hex()}")
                return dec, key, "CTR"
            if dec:
                decomp = try_decompress(dec)
                if decomp and is_valid_xml(decomp):
                    print(f"\n[+] SUCCESS CTR + decompress!")
                    return decomp, key, "CTR+decomp"

    print(f"[-] Tested {test_count} keys without success")
    return None, None, None

def main():
    print("=" * 60)
    print("FINAL COMPREHENSIVE DECRYPTION ATTEMPT")
    print("Huawei HG8145B7N-AIS Router Configuration")
    print("=" * 60)

    keys = generate_massive_keylist()
    print(f"Generated {len(keys)} unique keys")

    # Add header-derived keys from hw_ctree.xml
    hw_path = "/home/user/routerde/hw_ctree.xml"
    if os.path.exists(hw_path):
        with open(hw_path, 'rb') as f:
            header = f.read(256)
        for i in range(0, 64, 4):
            keys.append(header[i:i+16])
            if i + 16 <= 64:
                keys.append(hashlib.md5(header[i:i+16]).digest())

    # Remove duplicates
    unique_keys = list(set(keys))
    print(f"Total unique keys after header analysis: {len(unique_keys)}")

    files = [
        "/home/user/routerde/hw_ctree.xml",
        "/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf",
    ]

    for filepath in files:
        if not os.path.exists(filepath):
            continue

        if "hw_ctree" in filepath:
            result, key, mode = decrypt_hwctree(filepath, unique_keys)
        else:
            result, key, mode = decrypt_conf(filepath, unique_keys)

        if result:
            out_path = filepath + ".decrypted.xml"
            with open(out_path, 'wb') as f:
                f.write(result)
            print(f"\n[+] Saved to: {out_path}")
            print(f"[+] Mode: {mode}")
            print(f"[+] Key: {key.hex() if key else 'N/A'}")
            print("\nDecrypted preview:")
            print("-" * 50)
            try:
                print(result[:2000].decode('utf-8', errors='replace'))
            except:
                print(result[:2000])
            print("-" * 50)

    print("\n" + "=" * 60)
    print("Decryption attempts completed")
    print("=" * 60)

if __name__ == "__main__":
    main()
