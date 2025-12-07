#!/usr/bin/env python3
"""
Huawei-specific Key Derivation Functions
Based on analysis of Huawei firmware encryption patterns
"""

import os
import struct
import hashlib
import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter
import hmac

PREVIEW_OFFSET = 0x40
DATA_OFFSET = 0x15C
KNOWN_PLAINTEXT = b'<?xml version="1.0" encoding="UT'

# Device info
MAC = "E0AEA2EFB1CD"
SERIAL = "48575443286F3DB5"
SERIAL_READABLE = "HWTC286F3DB5"
FW_VERSION = "V5R023C10S104"
HW_VERSION = "39E7.A"
MODEL = "HG8145B7N"

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def try_ctr(data, key, nonce, init_ctr):
    try:
        ctr = Counter.new(64, prefix=nonce[:8], initial_value=init_ctr)
        cipher = AES.new(key[:16], AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(data)
    except:
        return None

def huawei_kdf_1(serial, salt):
    """Common Huawei key derivation: MD5(serial + salt)"""
    return hashlib.md5((serial + salt).encode()).digest()

def huawei_kdf_2(serial, mac):
    """Key derivation using serial and MAC"""
    combined = serial + mac
    return hashlib.md5(combined.encode()).digest()

def huawei_kdf_3(data, key_offset=0):
    """Key from specific firmware locations"""
    # This simulates reading key from firmware offset
    if len(data) > key_offset + 16:
        return data[key_offset:key_offset+16]
    return None

def huawei_kdf_4(model, version):
    """Key from model + version combination"""
    combined = f"{model}_{version}"
    return hashlib.sha256(combined.encode()).digest()[:16]

def huawei_kdf_5(serial_bytes):
    """Key from serial number bytes directly"""
    # Take first 16 bytes or pad
    if len(serial_bytes) >= 16:
        return serial_bytes[:16]
    return serial_bytes.ljust(16, b'\x00')

def huawei_kdf_6(magic, serial):
    """Key from file magic and serial"""
    combined = magic + serial.encode()
    return hashlib.md5(combined).digest()

def huawei_kdf_7(header_bytes, salt=b"HuaweiCfgKey"):
    """HMAC-based key derivation"""
    return hmac.new(salt, header_bytes, hashlib.md5).digest()

def huawei_kdf_8(model, mac, fw):
    """Combined device info key"""
    combined = f"{model}{mac}{fw}"
    return hashlib.sha256(combined.encode()).digest()[:16]

def huawei_kdf_9(date_stamp):
    """Key from configuration date"""
    return hashlib.md5(date_stamp.encode()).digest()

def generate_huawei_keys(data):
    """Generate keys using various Huawei KDF methods"""
    keys = []

    # Get header components
    magic = data[0:4]
    header = data[:64]
    date_from_header = data[0x150:0x158]  # 20220709 area

    # Common salts
    salts = [
        "", "AES", "KEY", "CFG", "ENC", "DEC",
        "HuaweiHG", "OptiXstar", "AIS", "Huawei",
        "$1$YaKi9SFn$", "hw_ctree", "config",
    ]

    # KDF 1: Serial + salt
    for salt in salts:
        keys.append(("KDF1_" + salt, huawei_kdf_1(SERIAL, salt)))
        keys.append(("KDF1_readable_" + salt, huawei_kdf_1(SERIAL_READABLE, salt)))

    # KDF 2: Serial + MAC
    keys.append(("KDF2_serial_mac", huawei_kdf_2(SERIAL, MAC)))
    keys.append(("KDF2_mac_serial", huawei_kdf_2(MAC, SERIAL)))

    # KDF 4: Model + version
    keys.append(("KDF4_model_fw", huawei_kdf_4(MODEL, FW_VERSION)))
    keys.append(("KDF4_model_hw", huawei_kdf_4(MODEL, HW_VERSION)))

    # KDF 5: Serial bytes directly
    keys.append(("KDF5_serial_hex", huawei_kdf_5(bytes.fromhex(SERIAL))))

    # KDF 6: Magic + serial
    keys.append(("KDF6_magic_serial", huawei_kdf_6(magic, SERIAL)))
    keys.append(("KDF6_magic_readable", huawei_kdf_6(magic, SERIAL_READABLE)))

    # KDF 7: HMAC on header
    hmac_salts = [b"HuaweiCfgKey", b"HG8145B7N", b"AES_KEY", b"ConfigKey"]
    for s in hmac_salts:
        keys.append((f"KDF7_{s.decode()}", huawei_kdf_7(header, s)))

    # KDF 8: Combined device info
    keys.append(("KDF8_combined", huawei_kdf_8(MODEL, MAC, FW_VERSION)))

    # KDF 9: Date from header (20220709)
    dates = ["20220709", "20211207", "20251118"]
    for d in dates:
        keys.append((f"KDF9_{d}", huawei_kdf_9(d)))

    # Additional Huawei-specific patterns
    # Some routers use XOR of model and serial
    model_bytes = MODEL.encode().ljust(16, b'\x00')
    serial_bytes = SERIAL.encode()[:16].ljust(16, b'\x00')
    keys.append(("XOR_model_serial", xor_bytes(model_bytes, serial_bytes)))

    # Some use reversed bytes
    keys.append(("reversed_serial", bytes.fromhex(SERIAL)[::-1].ljust(16, b'\x00')))

    # Huawei CFG specific patterns
    cfg_patterns = [
        f"cfg{MODEL}", f"CFG{MODEL}", f"aes{MODEL}", f"AES{MODEL}",
        f"hw_ctree_{MODEL}", f"config_{MODEL}", f"backup_{MODEL}",
    ]
    for p in cfg_patterns:
        keys.append((f"pattern_{p}", hashlib.md5(p.encode()).digest()))

    # ISP-specific patterns for AIS Thailand
    ais_patterns = [
        f"AIS_KEY_{MODEL}", f"AISFiber_{MODEL}", f"AIS_CONFIG_{MODEL}",
        f"TH_AIS_{MODEL}", f"THAILAND_AIS_{MODEL}", f"AIS2022_{MODEL}",
    ]
    for p in ais_patterns:
        keys.append((f"AIS_{p}", hashlib.md5(p.encode()).digest()))

    # Numeric key patterns (year-based)
    for year in [2020, 2021, 2022, 2023, 2024, 2025]:
        key_str = f"{MODEL}_{year}"
        keys.append((f"year_{year}", hashlib.md5(key_str.encode()).digest()))

    return keys

def main():
    print("=" * 60)
    print("HUAWEI KEY DERIVATION FUNCTION ATTACK")
    print("=" * 60)

    filepath = "/home/user/routerde/hw_ctree.xml"
    with open(filepath, 'rb') as f:
        data = f.read()

    # Extract keystream
    preview_ct = data[PREVIEW_OFFSET:PREVIEW_OFFSET + 32]
    keystream = xor_bytes(preview_ct, KNOWN_PLAINTEXT)
    ks_block_0 = keystream[:16]

    print(f"Keystream block 0: {ks_block_0.hex()}")
    print(f"\nDevice info:")
    print(f"  Model: {MODEL}")
    print(f"  MAC: {MAC}")
    print(f"  Serial: {SERIAL}")
    print(f"  Firmware: {FW_VERSION}")

    # Generate keys
    keys = generate_huawei_keys(data)
    print(f"\nGenerated {len(keys)} Huawei KDF keys")

    # Nonces
    nonces = [
        ("zero", bytes(8)),
        ("header_0", data[0:8]),
        ("header_48", data[48:56]),
        ("header_56", data[56:64]),
        ("data_header", data[0x148:0x150]),
    ]

    data_section = data[DATA_OFFSET:]

    print("\nTesting keys...")
    for key_name, key in keys:
        for nonce_name, nonce in nonces:
            for init_ctr in [0, 4, 21]:
                # Validate against keystream
                try:
                    counter_block = nonce[:8] + struct.pack(">Q", init_ctr)
                    cipher = AES.new(key, AES.MODE_ECB)
                    computed_ks = cipher.encrypt(counter_block)

                    if computed_ks == ks_block_0:
                        print(f"\n[+] KEYSTREAM MATCH!")
                        print(f"[+] Key name: {key_name}")
                        print(f"[+] Key: {key.hex()}")
                        print(f"[+] Nonce: {nonce_name} ({nonce.hex()})")
                        print(f"[+] Counter: {init_ctr}")

                        # Full decrypt
                        dec = try_ctr(data_section, key, nonce, 0)
                        if dec:
                            out_path = filepath + ".decrypted.xml"
                            with open(out_path, 'wb') as f:
                                f.write(dec)
                            print(f"[+] Saved to: {out_path}")
                            print(f"\nPreview:\n{dec[:500]}")
                            return

                except Exception as e:
                    continue

                # Direct decrypt test
                dec = try_ctr(data_section, key, nonce, init_ctr)
                if dec and dec[:5] == b'<?xml':
                    print(f"\n[+] SUCCESS!")
                    print(f"[+] Key name: {key_name}")
                    print(f"[+] Key: {key.hex()}")
                    out_path = filepath + ".decrypted.xml"
                    with open(out_path, 'wb') as f:
                        f.write(dec)
                    print(f"[+] Saved to: {out_path}")
                    print(f"\nPreview:\n{dec[:500]}")
                    return

    print("\n[-] No Huawei KDF key worked")
    print("\nThe key appears to be:")
    print("  - Randomly generated at factory")
    print("  - Stored in protected flash partition")
    print("  - Embedded in firmware binary (libconfigurationmgmt.so)")
    print("\nTo extract the key, physical access to the router is required.")

if __name__ == "__main__":
    main()
