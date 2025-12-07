#!/usr/bin/env python3
"""
Try using header bytes directly as key
"""

import base64
import gzip
import zlib
import os
from Crypto.Cipher import AES
import binascii

def aes_decrypt(data, key, mode='ECB', iv=None):
    """AES decryption"""
    try:
        if len(key) not in [16, 24, 32]:
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
            cipher = AES.new(key, AES.MODE_CBC, iv[:16] if iv else bytes(16))
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
    """Check if output is valid XML"""
    if not data or len(data) < 20:
        return False
    try:
        text = data.decode('utf-8', errors='ignore')
        patterns = ['<?xml', '<InternetGatewayDevice', '<DeviceInfo', '<X_HW_',
                    '<WLANConfiguration', '<WANDevice', '<LANDevice', '<config']
        for p in patterns:
            if p in text[:5000]:
                return True
    except:
        pass
    return False

def main():
    print("=" * 60)
    print("Header-Based Key Decryption")
    print("=" * 60)

    # Read hw_ctree.xml
    with open('/home/user/routerde/hw_ctree.xml', 'rb') as f:
        data = f.read()

    # Extract potential keys from header
    header_keys = [
        ("Header[64:80]", data[64:80]),
        ("Header[64:96]", data[64:96]),
        ("Header[48:64]", data[48:64]),
        ("Header[0:16]", data[0:16]),
    ]

    # Generate derived keys
    derived_keys = []
    for name, key in header_keys:
        derived_keys.append((name, key))
        # XOR with common values
        derived_keys.append((f"{name} XOR 0xFF", bytes(b ^ 0xff for b in key)))
        # Reverse
        derived_keys.append((f"{name} reversed", key[::-1]))

    print(f"\nTesting {len(derived_keys)} header-derived keys")

    # Try different data start offsets
    offsets = [72, 100, 104, 108, 96, 128, 256]

    for offset in offsets:
        if offset >= len(data):
            continue

        ct = data[offset:]
        print(f"\n[*] Offset: {offset}")

        for key_name, key in derived_keys:
            if len(key) < 16:
                key = key.ljust(16, b'\x00')

            # Try as AES-128 key
            aes_key = key[:16]

            # ECB
            dec = aes_decrypt(ct, aes_key, 'ECB')
            if dec:
                decomp, comp = try_decompress(dec)
                if decomp and is_valid_output(decomp):
                    print(f"\n[+] SUCCESS! {key_name} - ECB + {comp}")
                    print(f"[+] Key: {aes_key.hex()}")
                    save_result('/home/user/routerde/hw_ctree.xml', decomp)
                    return

                if is_valid_output(dec):
                    print(f"\n[+] SUCCESS! {key_name} - ECB")
                    print(f"[+] Key: {aes_key.hex()}")
                    save_result('/home/user/routerde/hw_ctree.xml', dec)
                    return

            # CBC with zero IV
            dec = aes_decrypt(ct, aes_key, 'CBC', bytes(16))
            if dec:
                decomp, comp = try_decompress(dec)
                if decomp and is_valid_output(decomp):
                    print(f"\n[+] SUCCESS! {key_name} - CBC + {comp}")
                    print(f"[+] Key: {aes_key.hex()}")
                    save_result('/home/user/routerde/hw_ctree.xml', decomp)
                    return

                if is_valid_output(dec):
                    print(f"\n[+] SUCCESS! {key_name} - CBC")
                    print(f"[+] Key: {aes_key.hex()}")
                    save_result('/home/user/routerde/hw_ctree.xml', dec)
                    return

            # CBC with header IV
            iv = data[48:64]
            dec = aes_decrypt(ct, aes_key, 'CBC', iv)
            if dec:
                decomp, comp = try_decompress(dec)
                if decomp and is_valid_output(decomp):
                    print(f"\n[+] SUCCESS! {key_name} - CBC(IV from header) + {comp}")
                    print(f"[+] Key: {aes_key.hex()}")
                    print(f"[+] IV: {iv.hex()}")
                    save_result('/home/user/routerde/hw_ctree.xml', decomp)
                    return

            # Try as AES-256 key if long enough
            if len(key) >= 32:
                aes_key = key[:32]

                dec = aes_decrypt(ct, aes_key, 'ECB')
                if dec:
                    decomp, comp = try_decompress(dec)
                    if decomp and is_valid_output(decomp):
                        print(f"\n[+] SUCCESS! {key_name} - AES-256-ECB + {comp}")
                        print(f"[+] Key: {aes_key.hex()}")
                        save_result('/home/user/routerde/hw_ctree.xml', decomp)
                        return

                dec = aes_decrypt(ct, aes_key, 'CBC', bytes(16))
                if dec:
                    decomp, comp = try_decompress(dec)
                    if decomp and is_valid_output(decomp):
                        print(f"\n[+] SUCCESS! {key_name} - AES-256-CBC + {comp}")
                        print(f"[+] Key: {aes_key.hex()}")
                        save_result('/home/user/routerde/hw_ctree.xml', decomp)
                        return

    print("\n[-] Header-based keys did not work")

    # Now try with .conf file
    print("\n" + "=" * 60)
    print("Trying .conf file with header-derived keys")
    print("=" * 60)

    with open('/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf', 'rb') as f:
        raw = f.read()

    # Base64 decode
    try:
        conf_data = base64.b64decode(raw)
    except:
        conf_data = raw

    for key_name, key in derived_keys:
        if len(key) < 16:
            key = key.ljust(16, b'\x00')

        aes_key = key[:16]

        # ECB
        dec = aes_decrypt(conf_data, aes_key, 'ECB')
        if dec:
            decomp, comp = try_decompress(dec)
            if decomp and is_valid_output(decomp):
                print(f"\n[+] SUCCESS! {key_name} - ECB + {comp}")
                save_result('/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf', decomp)
                return

            if is_valid_output(dec):
                print(f"\n[+] SUCCESS! {key_name} - ECB")
                save_result('/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf', dec)
                return

        # CBC
        dec = aes_decrypt(conf_data, aes_key, 'CBC', bytes(16))
        if dec:
            decomp, comp = try_decompress(dec)
            if decomp and is_valid_output(decomp):
                print(f"\n[+] SUCCESS! {key_name} - CBC + {comp}")
                save_result('/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf', decomp)
                return

        # CBC with IV from data
        iv = conf_data[:16]
        dec = aes_decrypt(conf_data[16:], aes_key, 'CBC', iv)
        if dec:
            decomp, comp = try_decompress(dec)
            if decomp and is_valid_output(decomp):
                print(f"\n[+] SUCCESS! {key_name} - CBC(IV from data) + {comp}")
                save_result('/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf', decomp)
                return

    print("\n[-] Could not decrypt with header-derived keys")

def save_result(filepath, data):
    """Save decrypted data"""
    out_path = filepath + ".decrypted.xml"
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"[+] Saved to: {out_path}")
    print("\nPreview:")
    print("-" * 50)
    try:
        print(data[:2000].decode('utf-8', errors='replace'))
    except:
        print(data[:2000])
    print("-" * 50)

if __name__ == "__main__":
    main()
