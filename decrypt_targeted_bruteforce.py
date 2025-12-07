#!/usr/bin/env python3
"""
Targeted brute force with common password patterns
Focus on 6-12 character passwords following ISP/router naming conventions
"""

import os
import hashlib
import itertools
import string
from Crypto.Cipher import AES
from Crypto.Util import Counter

PREVIEW_OFFSET = 0x40
DATA_OFFSET = 0x15C
KNOWN_PLAINTEXT = b'<?xml version="1.0" encoding="UT'

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def try_ctr(data, key, nonce, init_ctr):
    try:
        ctr = Counter.new(64, prefix=nonce[:8], initial_value=init_ctr)
        cipher = AES.new(key[:16], AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(data)
    except:
        return None

def validate_key_with_keystream(key, keystream_block_0, nonce, counter_val):
    """Check if key produces expected keystream"""
    try:
        # Build counter block
        counter_block = nonce[:8] + counter_val.to_bytes(8, 'big')
        cipher = AES.new(key[:16], AES.MODE_ECB)
        computed_ks = cipher.encrypt(counter_block)
        return computed_ks == keystream_block_0
    except:
        return False

def generate_targeted_passwords():
    """Generate passwords following common patterns"""
    passwords = set()

    # Pattern: Model + numbers
    models = ["HG8145B7N", "HG8145", "hg8145b7n", "hg8145"]
    for m in models:
        for n in range(1000):
            passwords.add(f"{m}{n:03d}")
            passwords.add(f"{m}{n:04d}")

    # Pattern: ISP + Model + numbers
    isps = ["AIS", "ais", "True", "3BB", "TOT"]
    for isp in isps:
        for m in ["HG8145", "HG8145B7N"]:
            passwords.add(f"{isp}{m}")
            passwords.add(f"{isp}_{m}")
            for n in range(100):
                passwords.add(f"{isp}{m}{n:02d}")

    # Pattern: Common prefixes + model
    prefixes = ["cfg_", "aes_", "key_", "enc_", "dec_", "hw_"]
    for p in prefixes:
        for m in models:
            passwords.add(f"{p}{m}")
            passwords.add(f"{p}{m}_AIS")

    # Pattern: MAC address variations
    mac_parts = ["E0AEA2", "EFB1CD", "A2EFB1"]
    for mp in mac_parts:
        passwords.add(mp)
        passwords.add(mp.lower())
        passwords.add(f"HG8145{mp}")
        passwords.add(f"AIS{mp}")

    # Pattern: Serial number variations
    sn_parts = ["HWTC28", "6F3DB5", "286F3D"]
    for sp in sn_parts:
        passwords.add(sp)
        passwords.add(f"HG8145{sp}")
        passwords.add(f"AIS{sp}")

    # Pattern: Firmware versions
    fw_parts = ["V5R023", "C10S104", "R023C10"]
    for fp in fw_parts:
        passwords.add(fp)
        passwords.add(f"HG8145{fp}")

    # Pattern: Year-based
    for y in range(2018, 2026):
        for m in range(1, 13):
            d = f"{y}{m:02d}"
            passwords.add(d)
            passwords.add(f"AIS{d}")
            passwords.add(f"HG8145{d}")

    # Pattern: Common 8-char passwords
    common_8 = [
        "12345678", "password", "admin123", "huawei12",
        "router12", "ais12345", "fiber123", "home1234",
        "internet", "broadband", "thailand",
    ]
    passwords.update(common_8)

    # Pattern: Alphanumeric combinations
    bases = ["AIS", "HG8", "HW", "CFG"]
    for b in bases:
        for n in range(10000):
            passwords.add(f"{b}{n:05d}")

    return list(passwords)

def main():
    print("=" * 60)
    print("TARGETED PASSWORD BRUTE FORCE")
    print("=" * 60)

    # Load data
    filepath = "/home/user/routerde/hw_ctree.xml"
    with open(filepath, 'rb') as f:
        data = f.read()

    # Extract keystream
    preview_ct = data[PREVIEW_OFFSET:PREVIEW_OFFSET + 32]
    keystream = xor_bytes(preview_ct, KNOWN_PLAINTEXT)
    ks_block_0 = keystream[:16]

    print(f"Keystream block 0: {ks_block_0.hex()}")

    # Generate passwords
    passwords = generate_targeted_passwords()
    print(f"Generated {len(passwords)} targeted passwords")

    # Nonces
    nonces = [
        bytes(8),
        data[0:8],
        data[48:56],
        data[56:64],
    ]

    # Test each password
    data_section = data[DATA_OFFSET:]
    total = len(passwords)
    found = False

    for idx, pwd in enumerate(passwords):
        if idx % 5000 == 0:
            print(f"Progress: {idx}/{total}")

        # Derive keys
        pwd_bytes = pwd.encode('utf-8')
        keys = [
            hashlib.md5(pwd_bytes).digest(),
            hashlib.sha256(pwd_bytes).digest()[:16],
            pwd_bytes[:16].ljust(16, b'\x00'),
        ]

        for key in keys:
            # Quick validation with keystream
            for nonce in nonces:
                for ctr in [0, 4]:
                    if validate_key_with_keystream(key, ks_block_0, nonce, ctr):
                        print(f"\n[+] KEYSTREAM MATCH!")
                        print(f"[+] Password: {pwd}")
                        print(f"[+] Key: {key.hex()}")
                        print(f"[+] Nonce: {nonce.hex()}")
                        print(f"[+] Counter: {ctr}")

                        # Full decrypt
                        dec = try_ctr(data_section, key, nonce, ctr + 17)
                        if dec:
                            out_path = filepath + ".decrypted.xml"
                            with open(out_path, 'wb') as f:
                                f.write(dec)
                            print(f"[+] Saved to: {out_path}")
                            print(f"\nDecrypted preview:")
                            print(dec[:500])

                        found = True
                        break

            if found:
                break

            # Direct decrypt test (slower)
            for nonce in nonces:
                dec = try_ctr(data_section, key, nonce, 0)
                if dec and dec[:5] == b'<?xml':
                    print(f"\n[+] SUCCESS!")
                    print(f"[+] Password: {pwd}")
                    print(f"[+] Key: {key.hex()}")
                    out_path = filepath + ".decrypted.xml"
                    with open(out_path, 'wb') as f:
                        f.write(dec)
                    print(f"[+] Saved to: {out_path}")
                    found = True
                    break

        if found:
            break

    if not found:
        print("\n[-] No matching password found")

    # Now try 6-char alphanumeric brute force
    print("\n" + "=" * 60)
    print("Attempting 6-char alphanumeric brute force...")
    print("=" * 60)

    # More targeted 6-char patterns
    prefixes = ["HG8145", "AIS123", "HUAWEI", "CONFIG"]
    for prefix in prefixes:
        print(f"Testing prefix: {prefix}")
        pwd_bytes = prefix.encode()
        key = hashlib.md5(pwd_bytes).digest()

        for nonce in nonces:
            for ctr in [0, 4, 21]:
                if validate_key_with_keystream(key, ks_block_0, nonce, ctr):
                    print(f"\n[+] MATCH: {prefix}")
                    dec = try_ctr(data_section, key, nonce, ctr)
                    if dec:
                        with open(filepath + ".decrypted.xml", 'wb') as f:
                            f.write(dec)
                        print(f"[+] Decrypted!")
                        return

    print("\n[-] 6-char brute force complete, no match found")

if __name__ == "__main__":
    main()
