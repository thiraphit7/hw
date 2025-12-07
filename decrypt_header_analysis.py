#!/usr/bin/env python3
"""
Deep header analysis for key extraction
Analyze every byte of the header for potential key material
"""

import os
import struct
import binascii
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter

KNOWN_PLAINTEXT = b'<?xml version="1.0" encoding="UT'
PREVIEW_OFFSET = 0x40
DATA_OFFSET = 0x15C

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def try_aes_ctr(data, key, nonce, init_ctr):
    try:
        if len(key) != 16:
            return None
        if len(nonce) != 8:
            nonce = nonce[:8].ljust(8, b'\x00')
        ctr = Counter.new(64, prefix=nonce, initial_value=init_ctr)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(data)
    except:
        return None

def analyze_header(data):
    """Deep analysis of file header"""
    print("=" * 70)
    print("DETAILED HEADER ANALYSIS")
    print("=" * 70)

    # Print header in various formats
    header = data[:0x160]

    print("\n[Hex dump of first 352 bytes]")
    for i in range(0, len(header), 16):
        hex_part = binascii.hexlify(header[i:i+16]).decode()
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in header[i:i+16])
        print(f"  0x{i:04x}: {hex_part}  |{ascii_part}|")

    # Parse header fields
    print("\n[Parsed header fields]")
    magic = struct.unpack("<I", data[0:4])[0]
    version = struct.unpack("<I", data[4:8])[0]
    print(f"  Magic: 0x{magic:08x}")
    print(f"  Version: {version}")

    # Look for 32-bit values that could be size/offset
    print("\n[32-bit values in header]")
    for i in range(0, 64, 4):
        val_le = struct.unpack("<I", data[i:i+4])[0]
        val_be = struct.unpack(">I", data[i:i+4])[0]
        if val_le > 0 and val_le < 1000000:
            print(f"  0x{i:02x}: LE={val_le}, BE={val_be}")

    # Extract data section header
    print("\n[Data section header at 0x148]")
    data_header = data[0x148:0x15C]
    print(f"  Raw: {binascii.hexlify(data_header).decode()}")

    for i in range(0, len(data_header), 4):
        val = struct.unpack("<I", data_header[i:i+4])[0]
        print(f"  +{i}: {val} (0x{val:08x})")

    return header

def extract_potential_keys(header):
    """Extract all potential key bytes from header"""
    keys = []

    # Direct 16-byte slices
    for offset in range(0, len(header) - 16, 4):
        keys.append(("header[{:02x}:{:02x}]".format(offset, offset+16),
                    header[offset:offset+16]))

    # XOR combinations
    for i in range(0, 32, 16):
        for j in range(32, 64, 16):
            xored = xor_bytes(header[i:i+16], header[j:j+16])
            keys.append((f"XOR header[{i:02x}] ^ header[{j:02x}]", xored))

    # Hash combinations
    for i in range(0, 64, 8):
        keys.append((f"MD5(header[{i:02x}:{i+8:02x}])",
                    hashlib.md5(header[i:i+8]).digest()))
        keys.append((f"MD5(header[{i:02x}:{i+16:02x}])",
                    hashlib.md5(header[i:i+16]).digest()))

    # Special positions based on format analysis
    special = [
        ("Magic+padding", header[0:4].ljust(16, b'\x00')),
        ("Magic reversed", header[0:4][::-1].ljust(16, b'\x00')),
        ("Pre-preview bytes", header[48:64]),
        ("Post-header", header[64:80]),
    ]
    keys.extend(special)

    return keys

def try_decrypt_with_header_keys(data):
    """Try decryption using header-derived keys"""
    print("\n" + "=" * 70)
    print("TRYING HEADER-DERIVED KEYS")
    print("=" * 70)

    header = data[:0x160]
    potential_keys = extract_potential_keys(header)

    preview_ct = data[PREVIEW_OFFSET:PREVIEW_OFFSET + 64]
    data_ct = data[DATA_OFFSET:]

    # Nonces to try
    nonces = [
        bytes(8),
        header[0:8],
        header[48:56],
        header[56:64],
        header[0x148:0x150],
    ]

    print(f"\nTesting {len(potential_keys)} potential keys with {len(nonces)} nonces...")

    for key_name, key in potential_keys:
        if len(key) != 16:
            continue

        for nonce in nonces:
            for init_ctr in [0, 1, 4, 21]:
                # Test preview
                dec = try_aes_ctr(preview_ct, key, nonce, init_ctr)
                if dec and dec[:5] == b'<?xml':
                    print(f"\n[+] SUCCESS! Key: {key_name}")
                    print(f"[+] Key hex: {key.hex()}")
                    print(f"[+] Nonce: {nonce.hex()}")
                    print(f"[+] Counter: {init_ctr}")
                    print(f"[+] Decrypted: {dec[:50]}")
                    return key, nonce, init_ctr

                # Test data section
                dec = try_aes_ctr(data_ct[:64], key, nonce, init_ctr)
                if dec and (b'<?xml' in dec or b'<Inter' in dec):
                    print(f"\n[+] SUCCESS on data! Key: {key_name}")
                    print(f"[+] Key hex: {key.hex()}")
                    print(f"[+] Decrypted: {dec[:50]}")
                    return key, nonce, init_ctr

    print("[-] No header-derived key worked")
    return None, None, None

def brute_force_with_known_keystream(data):
    """
    Use known keystream to validate keys more efficiently
    Keystream = AES(key, nonce || counter)
    So: key = AES_DECRYPT(keystream, nonce || counter) -- but AES doesn't work this way
    Instead: for each candidate key, encrypt counter and compare to keystream
    """
    print("\n" + "=" * 70)
    print("KEYSTREAM-BASED KEY VALIDATION")
    print("=" * 70)

    preview_ct = data[PREVIEW_OFFSET:PREVIEW_OFFSET + 32]
    keystream = xor_bytes(preview_ct, KNOWN_PLAINTEXT)
    ks_block_0 = keystream[:16]
    ks_block_1 = keystream[16:32] if len(keystream) >= 32 else None

    print(f"Keystream block 0: {ks_block_0.hex()}")
    if ks_block_1:
        print(f"Keystream block 1: {ks_block_1.hex()}")

    # For each potential key, check if AES(key, counter) == keystream
    # This is a validation approach

    # Common counter formats
    counter_formats = [
        # (nonce, counter_value) -> 16-byte block
        lambda n, c: n.ljust(8, b'\x00')[:8] + struct.pack(">Q", c),  # 64-bit nonce + 64-bit BE counter
        lambda n, c: n.ljust(8, b'\x00')[:8] + struct.pack("<Q", c),  # 64-bit nonce + 64-bit LE counter
        lambda n, c: struct.pack(">QQ", 0, c),  # Full 128-bit BE counter
        lambda n, c: struct.pack("<QQ", c, 0),  # Full 128-bit LE counter
        lambda n, c: n.ljust(12, b'\x00')[:12] + struct.pack(">I", c),  # 96-bit nonce + 32-bit counter
    ]

    # Try to find key using header bytes
    header = data[:0x160]

    # Generate more key candidates
    key_candidates = []

    # Header-derived
    for i in range(0, 64, 4):
        key_candidates.append(header[i:i+16])

    # Hash-derived
    patterns = [
        "HG8145B7N", "AIS", "Huawei", "OptiXstar",
        "HWTC286F3DB5", "E0AEA2EFB1CD", "V5R023C10S104",
    ]
    for p in patterns:
        key_candidates.append(hashlib.md5(p.encode()).digest())
        key_candidates.append(hashlib.sha256(p.encode()).digest()[:16])

    # Nonces
    nonces = [bytes(8), header[0:8], header[48:56]]

    print(f"\nValidating {len(key_candidates)} keys against keystream...")

    for key in key_candidates:
        if len(key) != 16:
            continue

        for nonce in nonces:
            for fmt_func in counter_formats:
                for ctr_val in [0, 1, 4]:
                    try:
                        counter_block = fmt_func(nonce, ctr_val)
                        if len(counter_block) != 16:
                            continue

                        cipher = AES.new(key, AES.MODE_ECB)
                        computed_ks = cipher.encrypt(counter_block)

                        if computed_ks == ks_block_0:
                            print(f"\n[+] FOUND MATCHING KEY!")
                            print(f"[+] Key: {key.hex()}")
                            print(f"[+] Nonce: {nonce.hex()}")
                            print(f"[+] Counter: {ctr_val}")
                            return key, nonce, ctr_val

                    except:
                        pass

    print("[-] No key matched the keystream")
    return None, None, None

def try_ecb_cbc_modes(data):
    """Also try ECB and CBC modes in case CTR analysis was wrong"""
    print("\n" + "=" * 70)
    print("TRYING ECB/CBC MODES (backup)")
    print("=" * 70)

    header = data[:0x100]
    data_section = data[DATA_OFFSET:]

    # Quick test with common keys
    test_keys = [
        hashlib.md5(b"HG8145B7N").digest(),
        hashlib.md5(b"AIS").digest(),
        hashlib.md5(b"Huawei").digest(),
        bytes.fromhex("13395537D2730554A176799F6D56A239"),
    ]

    for key in test_keys:
        # ECB
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            dec = cipher.decrypt(data_section[:64])
            if b'<?xml' in dec or b'<Inter' in dec:
                print(f"[+] ECB Success with key: {key.hex()}")
                return
        except:
            pass

        # CBC with zero IV
        try:
            cipher = AES.new(key, AES.MODE_CBC, bytes(16))
            dec = cipher.decrypt(data_section[:64])
            if b'<?xml' in dec or b'<Inter' in dec:
                print(f"[+] CBC Success with key: {key.hex()}")
                return
        except:
            pass

    print("[-] ECB/CBC modes also failed")

def main():
    filepath = "/home/user/routerde/hw_ctree.xml"
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"Analyzing: {filepath}")
    print(f"Size: {len(data)} bytes")

    # Deep header analysis
    analyze_header(data)

    # Try header-derived keys
    key, nonce, ctr = try_decrypt_with_header_keys(data)

    if not key:
        # Try keystream validation
        key, nonce, ctr = brute_force_with_known_keystream(data)

    if not key:
        # Fallback to ECB/CBC
        try_ecb_cbc_modes(data)

    if key:
        # Full decryption
        print("\n" + "=" * 70)
        print("FULL DECRYPTION")
        print("=" * 70)

        ctr_obj = Counter.new(64, prefix=nonce[:8], initial_value=ctr)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr_obj)
        decrypted = cipher.decrypt(data[DATA_OFFSET:])

        out_path = filepath + ".decrypted.xml"
        with open(out_path, 'wb') as f:
            f.write(decrypted)
        print(f"Saved to: {out_path}")

        print("\nDecrypted content:")
        print("-" * 50)
        print(decrypted[:2000].decode('utf-8', errors='replace'))

if __name__ == "__main__":
    main()
