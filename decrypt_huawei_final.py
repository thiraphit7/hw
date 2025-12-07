#!/usr/bin/env python3
"""
Huawei HG8145B7N Config Decryption - Final Version
Uses known Huawei AES key: 13395537D2730554A176799F6D56A239
"""

import base64
import gzip
import zlib
import struct
import os
from Crypto.Cipher import AES
import binascii

# Known Huawei AES key (from /etc/wap/aes_string)
HUAWEI_KEY = bytes.fromhex("13395537D2730554A176799F6D56A239")

# Additional keys to try
ADDITIONAL_KEYS = [
    bytes.fromhex("13395537D2730554A176799F6D56A239"),
    bytes.fromhex("243124594B61596939534E6624000000"),  # $1$YaKi9SNf$ padded
    bytes.fromhex("000102030405060708090A0B0C0D0E0F"),
    bytes.fromhex("00000000000000000000000000000000"),
]

def aes_decrypt_ecb(ciphertext, key):
    """Decrypt using AES-128-ECB"""
    try:
        # Ensure ciphertext is multiple of block size
        if len(ciphertext) % 16 != 0:
            ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]

        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(ciphertext)
    except Exception as e:
        print(f"AES ECB error: {e}")
        return None

def aes_decrypt_cbc(ciphertext, key, iv=None):
    """Decrypt using AES-128-CBC"""
    try:
        if iv is None:
            iv = b'\x00' * 16

        if len(ciphertext) % 16 != 0:
            ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.decrypt(ciphertext)
    except Exception as e:
        print(f"AES CBC error: {e}")
        return None

def try_decompress(data):
    """Try various decompression methods"""
    # Check for GZIP header
    if data[:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(data), 'gzip'
        except Exception as e:
            print(f"  GZIP failed: {e}")

    # Try zlib with different window sizes
    for wbits in [15, -15, 31, 47]:
        try:
            result = zlib.decompress(data, wbits)
            return result, f'zlib(wbits={wbits})'
        except:
            pass

    # Try raw deflate
    try:
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        result = decompressor.decompress(data)
        return result, 'deflate'
    except:
        pass

    return None, None

def is_valid_output(data):
    """Check if output looks valid"""
    if not data:
        return False

    # Check for XML
    try:
        text = data.decode('utf-8', errors='ignore')
        if '<?xml' in text[:500] or '<InternetGatewayDevice' in text[:1000]:
            return True
        if '<' in text[:100] and '>' in text[:200]:
            return True
    except:
        pass

    # Check for GZIP (might need decompression)
    if data[:2] == b'\x1f\x8b':
        return True

    return False

def decrypt_hwctree(filepath):
    """Decrypt hw_ctree.xml file"""
    print(f"\n{'='*60}")
    print(f"Decrypting: {filepath}")
    print("=" * 60)

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)} bytes")

    # Parse header
    print("\nHeader analysis:")
    print(f"  Magic: {binascii.hexlify(data[0:4]).decode()}")
    print(f"  Version: {struct.unpack('<I', data[4:8])[0]}")

    # Possible data start offsets to try
    # Standard is 8 bytes header skip, but this file has more complex header
    offsets = [8, 72, 100, 104, 96]

    for key in ADDITIONAL_KEYS:
        print(f"\n[*] Trying key: {key.hex()}")

        for offset in offsets:
            if offset >= len(data):
                continue

            encrypted = data[offset:]
            print(f"  [*] Offset {offset}: {len(encrypted)} bytes")

            # Try ECB mode
            decrypted = aes_decrypt_ecb(encrypted, key)
            if decrypted:
                # Try decompress
                final, comp_method = try_decompress(decrypted)
                if final and is_valid_output(final):
                    print(f"\n[+] SUCCESS! ECB mode at offset {offset}")
                    print(f"[+] Compression: {comp_method}")
                    save_and_show(filepath, final)
                    return True

                # Check if decrypted data itself is valid (no compression)
                if is_valid_output(decrypted):
                    print(f"\n[+] SUCCESS! ECB mode at offset {offset} (no compression)")
                    save_and_show(filepath, decrypted)
                    return True

            # Try CBC with zero IV
            decrypted = aes_decrypt_cbc(encrypted, key, b'\x00'*16)
            if decrypted:
                final, comp_method = try_decompress(decrypted)
                if final and is_valid_output(final):
                    print(f"\n[+] SUCCESS! CBC mode (zero IV) at offset {offset}")
                    print(f"[+] Compression: {comp_method}")
                    save_and_show(filepath, final)
                    return True

                if is_valid_output(decrypted):
                    print(f"\n[+] SUCCESS! CBC mode at offset {offset} (no compression)")
                    save_and_show(filepath, decrypted)
                    return True

            # Try CBC with IV from file header (bytes 48-64 might be IV)
            if len(data) >= 64:
                iv = data[48:64]
                decrypted = aes_decrypt_cbc(encrypted, key, iv)
                if decrypted:
                    final, comp_method = try_decompress(decrypted)
                    if final and is_valid_output(final):
                        print(f"\n[+] SUCCESS! CBC mode (header IV) at offset {offset}")
                        print(f"[+] Compression: {comp_method}")
                        save_and_show(filepath, final)
                        return True

    # If standard methods fail, try more offsets with byte-by-byte search for GZIP
    print("\n[*] Searching for embedded GZIP signature...")
    for i in range(0, min(len(data), 1000)):
        if data[i:i+2] == b'\x1f\x8b':
            print(f"  Found potential GZIP at offset {i}")
            try:
                decompressed = gzip.decompress(data[i:])
                if is_valid_output(decompressed):
                    print(f"\n[+] SUCCESS! Direct GZIP at offset {i}")
                    save_and_show(filepath, decompressed)
                    return True
            except:
                pass

    print("\n[-] Could not decrypt hw_ctree.xml")
    return False

def decrypt_conf(filepath):
    """Decrypt Base64 encoded .conf file"""
    print(f"\n{'='*60}")
    print(f"Decrypting: {filepath}")
    print("=" * 60)

    with open(filepath, 'rb') as f:
        raw_data = f.read()

    print(f"Raw file size: {len(raw_data)} bytes")

    # Decode Base64
    try:
        encrypted = base64.b64decode(raw_data)
        print(f"Base64 decoded: {len(encrypted)} bytes")
    except Exception as e:
        print(f"Base64 decode failed: {e}, using raw data")
        encrypted = raw_data

    for key in ADDITIONAL_KEYS:
        print(f"\n[*] Trying key: {key.hex()}")

        # Try ECB mode
        decrypted = aes_decrypt_ecb(encrypted, key)
        if decrypted:
            final, comp_method = try_decompress(decrypted)
            if final and is_valid_output(final):
                print(f"\n[+] SUCCESS! ECB mode")
                print(f"[+] Compression: {comp_method}")
                save_and_show(filepath, final)
                return True

            if is_valid_output(decrypted):
                print(f"\n[+] SUCCESS! ECB mode (no compression)")
                save_and_show(filepath, decrypted)
                return True

        # Try CBC zero IV
        decrypted = aes_decrypt_cbc(encrypted, key, b'\x00'*16)
        if decrypted:
            final, comp_method = try_decompress(decrypted)
            if final and is_valid_output(final):
                print(f"\n[+] SUCCESS! CBC mode")
                print(f"[+] Compression: {comp_method}")
                save_and_show(filepath, final)
                return True

        # Try with IV from first 16 bytes
        if len(encrypted) > 16:
            iv = encrypted[:16]
            ct = encrypted[16:]
            decrypted = aes_decrypt_cbc(ct, key, iv)
            if decrypted:
                final, comp_method = try_decompress(decrypted)
                if final and is_valid_output(final):
                    print(f"\n[+] SUCCESS! CBC mode (IV from data)")
                    print(f"[+] Compression: {comp_method}")
                    save_and_show(filepath, final)
                    return True

    print("\n[-] Could not decrypt .conf file")
    return False

def save_and_show(filepath, data):
    """Save result and show preview"""
    out_path = filepath + ".decrypted"
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"[+] Saved to: {out_path}")
    print(f"[+] Size: {len(data)} bytes")

    print(f"\n{'='*60}")
    print("DECRYPTED CONTENT PREVIEW")
    print("=" * 60)
    try:
        text = data[:3000].decode('utf-8', errors='replace')
        print(text)
    except:
        print(data[:3000])
    print("=" * 60)

def main():
    print("=" * 60)
    print("Huawei HG8145B7N Config Decryption Tool")
    print("Key: 13395537D2730554A176799F6D56A239")
    print("=" * 60)

    xml_file = "/home/user/routerde/hw_ctree.xml"
    conf_file = "/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf"

    success = False

    if os.path.exists(xml_file):
        if decrypt_hwctree(xml_file):
            success = True

    if os.path.exists(conf_file):
        if decrypt_conf(conf_file):
            success = True

    if success:
        print("\n[+] Decryption successful!")
    else:
        print("\n[-] Could not decrypt files with known keys")
        print("[*] Generating extended key list from patterns...")

if __name__ == "__main__":
    main()
