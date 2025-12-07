#!/usr/bin/env python3
"""
Advanced AES-128-CTR Decryption for Huawei HG8145B7N
Using keystream analysis and counter prediction

Known:
- Preview at 0x40 decrypts to: <?xml version="1.0" encoding="UT
- Keystream Block 0: af1c7ee7fa6cb7c5bb83b81d055963ed
- Keystream Block 1: da21d600dbd67e583f208e14e385a625
- Data section starts at 0x15C with different counter
"""

import os
import struct
import binascii
import hashlib
import itertools
from Crypto.Cipher import AES
from Crypto.Util import Counter

# File offsets
PREVIEW_OFFSET = 0x40      # 64
DATA_HEADER_OFFSET = 0x148  # 328
DATA_OFFSET = 0x15C        # 348

# Known plaintext and derived keystream
KNOWN_PLAINTEXT = b'<?xml version="1.0" encoding="UT'
KEYSTREAM_BLOCK_0 = bytes.fromhex("af1c7ee7fa6cb7c5bb83b81d055963ed")
KEYSTREAM_BLOCK_1 = bytes.fromhex("da21d600dbd67e583f208e14e385a625")

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aes_ecb_encrypt(key, data):
    """Single block AES encryption"""
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(data)
    except:
        return None

def reverse_aes_key_from_keystream(keystream_block, counter_block):
    """
    Given keystream = AES(key, counter), try to find key
    This is the hard part - AES is designed to prevent this
    But we can check if a key produces the expected keystream
    """
    # Can't directly reverse - must brute force the key
    pass

def try_ctr_decrypt(ciphertext, key, nonce, initial_counter=0, counter_bytes=8):
    """Try AES-CTR with various counter configurations"""
    try:
        if len(key) != 16:
            return None

        if counter_bytes == 8:
            # 64-bit counter with 64-bit nonce prefix
            if len(nonce) != 8:
                nonce = nonce[:8].ljust(8, b'\x00')
            ctr = Counter.new(64, prefix=nonce, initial_value=initial_counter)
        elif counter_bytes == 16:
            # Full 128-bit counter, no prefix
            ctr = Counter.new(128, initial_value=initial_counter)
        else:
            # Custom: nonce as prefix, rest is counter
            prefix_len = 16 - counter_bytes
            if len(nonce) < prefix_len:
                nonce = nonce.ljust(prefix_len, b'\x00')
            ctr = Counter.new(counter_bytes * 8, prefix=nonce[:prefix_len], initial_value=initial_counter)

        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(ciphertext)
    except:
        return None

def validate_key_with_keystream(key, nonce, counter_value):
    """Check if key produces expected keystream"""
    try:
        # Build counter block
        if len(nonce) == 8:
            counter_block = nonce + struct.pack(">Q", counter_value)
        elif len(nonce) == 12:
            counter_block = nonce + struct.pack(">I", counter_value)
        else:
            counter_block = struct.pack(">QQ", 0, counter_value)

        # Encrypt counter to get keystream
        cipher = AES.new(key, AES.MODE_ECB)
        computed_ks = cipher.encrypt(counter_block)

        # Compare with known keystream
        if computed_ks == KEYSTREAM_BLOCK_0:
            return True
    except:
        pass
    return False

def generate_keys():
    """Generate comprehensive key list"""
    keys = []

    # Known Huawei firmware keys (various models)
    known_hex_keys = [
        "13395537D2730554A176799F6D56A239",  # HG8245H
        "1AAAB4A730B23E1FC8A1D59C79283A228B78410ECC46FA4F48EB1456E24C5B89",
        "472f7363e72846b2c02a6e687c4c20f9",  # Common Huawei
        "4a578eea3a10e2c68b34cfadffbf3a5d",  # HG8546M
        "e5c2f8e0d3c8c2e3a1b4c7d8e9f0a1b2",
        "0123456789abcdef0123456789abcdef",
        "48756177656948473831343542374e21",  # "HuaweiHG8145B7N!"
        "41495353656372657441455331323321",  # "AISSecretAES123!"
        "415f4b45595f464f525f414953000000",  # "A_KEY_FOR_AIS"
        "4147435f41455331323830303030303030",  # AGC pattern
    ]

    for h in known_hex_keys:
        try:
            k = bytes.fromhex(h)
            if len(k) >= 16:
                keys.append(k[:16])
            if len(k) >= 32:
                keys.append(k[:32])
        except:
            pass

    # Device-specific patterns
    device_patterns = [
        "HG8145B7N",
        "HG8145B7N-AIS",
        "HG8145B7NAIS",
        "AIS_HG8145B7N",
        "OptiXstar",
        "V5R023C10S104",
        "E0AEA2EFB1CD",  # MAC
        "48575443286F3DB5",  # Serial
        "HWTC286F3DB5",
    ]

    key_suffixes = ["_AES", "_KEY", "_CFG", "key", "aes", "cfg", "!@#"]

    for pattern in device_patterns:
        # Direct
        keys.append(pattern.encode()[:16].ljust(16, b'\x00'))

        # With suffixes
        for suffix in key_suffixes:
            combined = (pattern + suffix)[:16]
            keys.append(combined.encode().ljust(16, b'\x00'))

        # Hashed
        keys.append(hashlib.md5(pattern.encode()).digest())
        keys.append(hashlib.sha256(pattern.encode()).digest()[:16])

    # AIS Thailand specific
    ais_patterns = [
        "AIS", "AIS2023", "AIS2024", "AIS2025",
        "AISFIBER", "AISFibre", "AIS_Fibre",
        "AISHuawei", "HuaweiAIS", "AIS_HG8145",
        "AIS_CONFIG", "AIS_ROUTER", "TrueOnline",
        "3BB", "3BBFiber", "TOT", "TOTFIBER",
    ]

    for ais in ais_patterns:
        keys.append(ais.encode()[:16].ljust(16, b'\x00'))
        keys.append(hashlib.md5(ais.encode()).digest())

    # Numeric patterns (firmware dates, versions)
    for year in [2020, 2021, 2022, 2023, 2024, 2025]:
        for month in range(1, 13):
            date_str = f"{year}{month:02d}01"
            keys.append(date_str.encode().ljust(16, b'\x00'))
            keys.append(hashlib.md5(date_str.encode()).digest())

    # Firmware version patterns
    fw_patterns = [
        "V5R023C10S104", "V5R023C10", "V5R023",
        "C10S104", "S104", "R023C10S104",
    ]
    for fw in fw_patterns:
        keys.append(fw.encode()[:16].ljust(16, b'\x00'))
        keys.append(hashlib.md5(fw.encode()).digest())

    # Special patterns from header analysis
    keys.append(bytes.fromhex("07122120" + "00" * 12))  # Magic based
    keys.append(bytes.fromhex("20211207" + "00" * 12))  # Date reversed
    keys.append(bytes.fromhex("20220709" + "00" * 12))  # Timestamp from header

    # Remove duplicates
    unique = []
    seen = set()
    for k in keys:
        if len(k) == 16:
            kh = k.hex()
            if kh not in seen:
                seen.add(kh)
                unique.append(k)

    return unique

def analyze_counter_relationship(data):
    """Analyze potential counter relationship between preview and data sections"""
    print("\n" + "=" * 60)
    print("Counter Relationship Analysis")
    print("=" * 60)

    # Preview is at offset 0x40 (64 bytes = 4 blocks)
    # Data is at offset 0x15C (348 bytes = 21.75 blocks)

    preview_block_offset = PREVIEW_OFFSET // 16  # 4
    data_block_offset = DATA_OFFSET // 16        # 21 (348/16 = 21.75)

    print(f"Preview at offset 0x{PREVIEW_OFFSET:x} = block {preview_block_offset}")
    print(f"Data at offset 0x{DATA_OFFSET:x} = block {data_block_offset}")
    print(f"Block difference: {data_block_offset - preview_block_offset}")

    # If counter starts at 0 for preview, data would be at counter 17 or so
    # But they might use separate counter initialization

    return preview_block_offset, data_block_offset

def main():
    print("=" * 60)
    print("Advanced AES-128-CTR Decryption")
    print("Huawei HG8145B7N-AIS Configuration")
    print("=" * 60)

    filepath = "/home/user/routerde/hw_ctree.xml"
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)} bytes")
    print(f"Header: {binascii.hexlify(data[:16]).decode()}")

    # Verify known plaintext
    preview_ct = data[PREVIEW_OFFSET:PREVIEW_OFFSET + 32]
    recovered_ks = xor_bytes(preview_ct, KNOWN_PLAINTEXT)
    print(f"\nVerifying keystream extraction:")
    print(f"  Preview CT: {binascii.hexlify(preview_ct[:16]).decode()}")
    print(f"  Known PT:   {KNOWN_PLAINTEXT[:16]}")
    print(f"  Keystream:  {binascii.hexlify(recovered_ks[:16]).decode()}")

    # Analyze counter
    preview_block, data_block = analyze_counter_relationship(data)

    # Generate keys
    keys = generate_keys()
    print(f"\nGenerated {len(keys)} unique keys to test")

    # Generate nonces from various sources
    nonces = [
        bytes(8),                         # Zero
        data[0:8],                         # File start
        data[48:56],                       # Pre-preview
        data[56:64],                       # Pre-preview
        data[DATA_HEADER_OFFSET:DATA_HEADER_OFFSET+8],  # Data header
        bytes.fromhex("0712212002000000"),  # Magic + version
        bytes.fromhex("2022070900000000"),  # Date stamp
    ]

    # Try different counter configurations
    counter_configs = [
        (8, "64-bit counter"),
        (4, "32-bit counter"),
        (16, "128-bit counter"),
        (12, "96-bit counter"),
    ]

    data_section = data[DATA_OFFSET:]
    preview_section = data[PREVIEW_OFFSET:]

    print("\n" + "=" * 60)
    print("Testing keys with different CTR configurations")
    print("=" * 60)

    total_tests = len(keys) * len(nonces) * len(counter_configs) * 10  # Approx
    test_num = 0

    for key in keys:
        for nonce in nonces:
            for counter_bytes, counter_desc in counter_configs:
                # Try various initial counter values
                for init_ctr in [0, 1, 2, 4, preview_block, data_block,
                                 data_block - preview_block]:
                    test_num += 1
                    if test_num % 5000 == 0:
                        print(f"  Progress: {test_num} tests...")

                    # Test on preview section first (faster validation)
                    dec = try_ctr_decrypt(preview_section, key, nonce, init_ctr, counter_bytes)
                    if dec and dec[:5] == b'<?xml':
                        print(f"\n[+] SUCCESS on preview!")
                        print(f"[+] Key: {key.hex()}")
                        print(f"[+] Nonce: {nonce.hex()}")
                        print(f"[+] Counter: {init_ctr} ({counter_desc})")
                        print(f"[+] Decrypted preview: {dec[:100]}")

                        # Now try to decrypt data section with adjusted counter
                        data_counter = init_ctr + (DATA_OFFSET - PREVIEW_OFFSET) // 16
                        dec_data = try_ctr_decrypt(data_section, key, nonce, data_counter, counter_bytes)

                        if dec_data and (b'<?xml' in dec_data[:100] or b'<Inter' in dec_data[:100]):
                            print(f"[+] Data section also decrypted!")
                            save_result(filepath, dec_data, "data")
                        else:
                            # Try with fresh counter for data
                            for data_init in [0, 1, 2]:
                                dec_data = try_ctr_decrypt(data_section, key, nonce, data_init, counter_bytes)
                                if dec_data and (b'<?xml' in dec_data[:100] or b'<Inter' in dec_data[:100]):
                                    print(f"[+] Data decrypted with counter {data_init}")
                                    save_result(filepath, dec_data, "data")
                                    break

                        save_result(filepath, dec, "preview")
                        return

                    # Also test on data section directly
                    dec = try_ctr_decrypt(data_section, key, nonce, init_ctr, counter_bytes)
                    if dec and (b'<?xml' in dec[:100] or b'<InternetGatewayDevice' in dec[:200]):
                        print(f"\n[+] SUCCESS on data section!")
                        print(f"[+] Key: {key.hex()}")
                        print(f"[+] Nonce: {nonce.hex()}")
                        print(f"[+] Counter: {init_ctr} ({counter_desc})")
                        print(f"[+] Decrypted: {dec[:200]}")
                        save_result(filepath, dec, "data")
                        return

    print(f"\n[-] Tested {test_num} configurations without success")
    print("[-] The key may be firmware-embedded or randomly generated")

def save_result(filepath, data, section):
    """Save decrypted data"""
    out_path = f"{filepath}.{section}.decrypted.xml"
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"[+] Saved to: {out_path}")
    print(f"\n{'='*60}")
    print(f"DECRYPTED CONTENT ({section})")
    print("=" * 60)
    try:
        print(data[:3000].decode('utf-8', errors='replace'))
    except:
        print(data[:3000])

if __name__ == "__main__":
    main()
