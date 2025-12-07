#!/usr/bin/env python3
"""
Huawei HG8145B7N Decryption using AES-128-CTR
Based on analysis: Encryption is AES-128-CTR mode

File Structure:
- 0x000-0x040: Main header (signature 07122120)
- 0x040-0x060: Preview section (32 bytes encrypted XML header)
- 0x060-0x148: Padding (zeros)
- 0x148-0x15C: Data section header
- 0x15C-END: Encrypted XML config data

Known plaintext: "<?xml version="1.0" encoding="UT"
This allows keystream recovery via XOR
"""

import os
import struct
import binascii
from Crypto.Cipher import AES
from Crypto.Util import Counter

# File offsets
PREVIEW_OFFSET = 0x40      # 64
DATA_HEADER_OFFSET = 0x148  # 328
DATA_OFFSET = 0x15C        # 348

# Known plaintext for preview section
KNOWN_PLAINTEXT = b'<?xml version="1.0" encoding="UT'

def xor_bytes(a, b):
    """XOR two byte arrays"""
    return bytes(x ^ y for x, y in zip(a, b))

def extract_keystream_from_known_plaintext(encrypted, plaintext):
    """Extract keystream by XORing known plaintext with ciphertext"""
    return xor_bytes(encrypted, plaintext)

def try_ctr_decrypt(ciphertext, key, nonce=None, initial_counter=0):
    """Try AES-CTR decryption with various counter configurations"""
    try:
        if len(key) != 16:
            return None

        if nonce is None:
            nonce = bytes(8)

        # Create counter
        ctr = Counter.new(64, prefix=nonce, initial_value=initial_counter)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(ciphertext)
    except Exception as e:
        return None

def analyze_file(filepath):
    """Analyze hw_ctree.xml structure and attempt decryption"""
    print(f"\n{'='*60}")
    print("AES-128-CTR Decryption Analysis")
    print("=" * 60)

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)} bytes")
    print(f"Header: {binascii.hexlify(data[:8]).decode()}")

    # Extract preview section (encrypted XML header)
    preview_encrypted = data[PREVIEW_OFFSET:PREVIEW_OFFSET + len(KNOWN_PLAINTEXT)]
    print(f"\nPreview section (offset 0x{PREVIEW_OFFSET:02x}):")
    print(f"  Encrypted: {binascii.hexlify(preview_encrypted).decode()}")

    # Extract keystream using known plaintext
    keystream = extract_keystream_from_known_plaintext(preview_encrypted, KNOWN_PLAINTEXT)
    print(f"  Known PT:  {KNOWN_PLAINTEXT}")
    print(f"  Keystream: {binascii.hexlify(keystream).decode()}")

    # Verify by decrypting preview with keystream
    decrypted_preview = xor_bytes(preview_encrypted, keystream)
    print(f"  Decrypted: {decrypted_preview}")

    # Extract data section
    data_section = data[DATA_OFFSET:]
    print(f"\nData section (offset 0x{DATA_OFFSET:02x}):")
    print(f"  Size: {len(data_section)} bytes")
    print(f"  First 32 bytes: {binascii.hexlify(data_section[:32]).decode()}")

    # If we have the keystream for preview, we might be able to extend it
    # In CTR mode, each block uses: Key XOR Counter
    # The keystream is essentially encrypted counter values

    print("\n" + "=" * 60)
    print("Attempting keystream extension attack")
    print("=" * 60)

    # The keystream blocks for preview and data should be different
    # because they're at different counter positions
    # But if we can find the key, we can decrypt everything

    # Try using parts of the keystream as potential key bytes
    potential_keys = [
        keystream[:16],  # First 16 bytes of keystream
        keystream[16:32] if len(keystream) >= 32 else keystream[:16],
    ]

    # Also try header bytes that might be related to the key
    header_key_candidates = [
        data[64:80],   # Bytes 64-79
        data[64:96][:16] if len(data) >= 96 else data[64:80],
    ]
    potential_keys.extend(header_key_candidates)

    # Try known Huawei keys with CTR mode
    known_keys = [
        bytes.fromhex("13395537D2730554A176799F6D56A239"),
        bytes.fromhex("00600bc6c187005d125c4f1aabe9702a"),  # From keystream
    ]
    potential_keys.extend(known_keys)

    # Try different nonce configurations
    nonces = [
        bytes(8),                    # Zero nonce
        data[48:56],                 # From header
        data[56:64],                 # From header
        keystream[:8],               # From keystream
    ]

    for key in potential_keys:
        if len(key) < 16:
            key = key.ljust(16, b'\x00')
        key = key[:16]

        for nonce in nonces:
            if len(nonce) < 8:
                nonce = nonce.ljust(8, b'\x00')
            nonce = nonce[:8]

            for initial_counter in [0, 1, 2, 4]:
                # Try decrypting from preview offset
                dec = try_ctr_decrypt(data[PREVIEW_OFFSET:], key, nonce, initial_counter)
                if dec and dec[:5] == b'<?xml':
                    print(f"\n[+] SUCCESS at preview offset!")
                    print(f"[+] Key: {key.hex()}")
                    print(f"[+] Nonce: {nonce.hex()}")
                    print(f"[+] Initial counter: {initial_counter}")
                    print(f"[+] Decrypted: {dec[:100]}")
                    save_result(filepath, dec)
                    return True

                # Try decrypting from data offset
                dec = try_ctr_decrypt(data[DATA_OFFSET:], key, nonce, initial_counter)
                if dec and dec[:5] == b'<?xml':
                    print(f"\n[+] SUCCESS at data offset!")
                    print(f"[+] Key: {key.hex()}")
                    print(f"[+] Nonce: {nonce.hex()}")
                    print(f"[+] Initial counter: {initial_counter}")
                    print(f"[+] Decrypted: {dec[:100]}")
                    save_result(filepath, dec)
                    return True

    # Try XOR with repeated keystream (if CTR uses same counter range)
    print("\n" + "=" * 60)
    print("Attempting XOR with extended keystream")
    print("=" * 60)

    # Extend keystream by repeating (works if same counter is reused)
    extended_keystream = keystream * (len(data_section) // len(keystream) + 1)
    extended_keystream = extended_keystream[:len(data_section)]

    dec = xor_bytes(data_section, extended_keystream)
    if dec[:5] == b'<?xml':
        print("[+] SUCCESS with repeated keystream!")
        print(f"[+] Decrypted: {dec[:200]}")
        save_result(filepath, dec)
        return True
    else:
        print(f"  Result: {dec[:50]}")
        print("  Not valid XML")

    # Try different block alignments
    for offset_adjust in range(-16, 17):
        adjusted_data = data[DATA_OFFSET + offset_adjust:]
        for ks_offset in range(0, 16):
            adjusted_ks = keystream[ks_offset:] + keystream[:ks_offset]
            extended_ks = adjusted_ks * (len(adjusted_data) // len(adjusted_ks) + 1)
            extended_ks = extended_ks[:len(adjusted_data)]

            dec = xor_bytes(adjusted_data[:min(100, len(adjusted_data))],
                           extended_ks[:min(100, len(extended_ks))])
            if dec[:5] == b'<?xml':
                print(f"\n[+] SUCCESS with offset adjust {offset_adjust}, ks_offset {ks_offset}!")
                full_dec = xor_bytes(adjusted_data, extended_ks[:len(adjusted_data)])
                save_result(filepath, full_dec)
                return True

    print("\n[-] Could not decrypt with available keystream")
    return False

def save_result(filepath, data):
    """Save decrypted data"""
    out_path = filepath + ".decrypted.xml"
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"[+] Saved to: {out_path}")

    print(f"\n{'='*60}")
    print("DECRYPTED CONTENT")
    print("=" * 60)
    try:
        print(data[:5000].decode('utf-8', errors='replace'))
    except:
        print(data[:5000])
    print("=" * 60)

def main():
    filepath = "/home/user/routerde/hw_ctree.xml"
    if os.path.exists(filepath):
        analyze_file(filepath)
    else:
        print(f"File not found: {filepath}")

if __name__ == "__main__":
    main()
