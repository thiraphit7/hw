#!/usr/bin/env python3
"""
Huawei HG8145B7N Config Decryption Tool v3
Uses header bytes as potential keys
"""

import base64
import hashlib
import zlib
import gzip
import struct
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def try_decrypt_aes(ciphertext, key, mode='ECB', iv=None):
    """Try AES decryption"""
    try:
        key_len = len(key)
        if key_len not in [16, 24, 32]:
            if key_len < 16:
                key = key.ljust(16, b'\x00')
            elif key_len < 24:
                key = key[:16]
            elif key_len < 32:
                key = key[:24]
            else:
                key = key[:32]

        if len(ciphertext) % 16 != 0:
            ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]

        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            if iv is None:
                iv = b'\x00' * 16
            cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted = cipher.decrypt(ciphertext)
        return decrypted
    except:
        return None

def try_decompress(data):
    """Try various decompression methods"""
    # GZIP
    try:
        return gzip.decompress(data), 'gzip'
    except:
        pass

    # ZLIB with various window sizes
    for wbits in [15, -15, 31, 47, -zlib.MAX_WBITS]:
        try:
            return zlib.decompress(data, wbits), f'zlib_w{wbits}'
        except:
            pass

    # Raw deflate
    try:
        decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        return decompressor.decompress(data), 'deflate'
    except:
        pass

    return data, None

def is_valid_xml(data):
    """Check if data looks like valid XML config"""
    try:
        text = data.decode('utf-8', errors='ignore')
        # Must have XML declaration or config tags
        if '<?xml' in text[:200]:
            return True
        # Check for config-like XML tags
        config_patterns = [
            '<InternetGatewayDevice',
            '<X_HW_',
            '<DeviceInfo',
            '<LANDevice',
            '<WANDevice',
            '<WLANConfiguration',
            '<Services',
            '<Layer3Forwarding',
            '<ManagementServer',
        ]
        for pattern in config_patterns:
            if pattern in text[:2000]:
                return True
    except:
        pass
    return False

def analyze_header(data):
    """Analyze hw_ctree header and extract potential keys"""
    if len(data) < 100:
        return None

    header = {
        'magic': data[0:4],
        'version': struct.unpack('<I', data[4:8])[0],
        'flags': struct.unpack('<I', data[8:12])[0],
    }

    # Extract various potential key candidates from header
    keys = []

    # Bytes 64-79 (16 bytes) - could be AES-128 key
    if len(data) >= 80:
        keys.append(data[64:80])

    # Bytes 64-95 (32 bytes) - could be AES-256 key
    if len(data) >= 96:
        keys.append(data[64:96])

    # Bytes 64-87 (24 bytes) - could be AES-192 key
    if len(data) >= 88:
        keys.append(data[64:88])

    # Also try hash of header key bytes
    if len(data) >= 96:
        key_bytes = data[64:96]
        keys.append(hashlib.md5(key_bytes).digest())
        keys.append(hashlib.sha256(key_bytes).digest()[:16])
        keys.append(hashlib.sha256(key_bytes).digest())

    return header, keys

def decrypt_hwctree(filepath):
    """Decrypt hw_ctree.xml with header-based keys"""
    print(f"\n[*] Processing: {filepath}")

    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"[*] File size: {len(data)} bytes")

    # Analyze header
    header, header_keys = analyze_header(data)
    print(f"[*] Magic: {header['magic'].hex()}")
    print(f"[*] Version: {header['version']}")

    # Print potential keys from header
    print(f"[*] Extracted {len(header_keys)} potential keys from header")
    for i, k in enumerate(header_keys):
        print(f"    Key {i+1}: {k.hex()[:32]}...")

    # Build comprehensive key list
    all_keys = header_keys.copy()

    # Add known Huawei keys
    known_keys = [
        b'$1$YaKi9SFn$'.ljust(16, b'\x00'),
        b'HuaweiHomeGateway'[:16],
        b'huawei'.ljust(16, b'\x00'),
        b'admin'.ljust(16, b'\x00'),
        bytes.fromhex('00000000000000000000000000000000'),
        hashlib.md5(b'huawei').digest(),
        hashlib.md5(b'HG8145B7N').digest(),
        hashlib.md5(b'telecomadmin').digest(),
        hashlib.md5(b'admin').digest(),
        hashlib.md5(b'AIS').digest(),
        hashlib.md5(b'E0AEA2EFB1CD').digest(),
        hashlib.md5(b'48575443286F3DB5').digest(),
    ]
    all_keys.extend(known_keys)

    # Add device-specific derived keys
    device_strings = [
        "HG8145B7N", "E0AEA2EFB1CD", "48575443286F3DB5", "HWTC286F3DB5",
        "AIS", "39E7.A", "V5R023C10S104", "OptiXstar", "HuaweiHG8145B7N"
    ]
    for ds in device_strings:
        all_keys.append(hashlib.md5(ds.encode()).digest())
        all_keys.append(hashlib.sha256(ds.encode()).digest()[:16])
        all_keys.append(ds.encode()[:16].ljust(16, b'\x00'))

    # Combine patterns
    for base in ["HG8145B7N", "hg8145b7n"]:
        for suffix in ["key", "AES", "cfg", "config", "DecKey", "EncKey"]:
            combo = f"{base}_{suffix}"
            all_keys.append(hashlib.md5(combo.encode()).digest())
            all_keys.append(combo.encode()[:16].ljust(16, b'\x00'))

    # Remove duplicates
    unique_keys = []
    seen = set()
    for k in all_keys:
        if len(k) in [16, 24, 32]:
            khex = k.hex()
            if khex not in seen:
                seen.add(khex)
                unique_keys.append(k)

    print(f"[*] Total unique keys to try: {len(unique_keys)}")

    # Try different data offsets
    offsets = [72, 100, 104, 108, 112, 96, 128, 256]

    for offset in offsets:
        if offset >= len(data):
            continue

        enc_data = data[offset:]
        print(f"\n[*] Trying offset: {offset}, encrypted length: {len(enc_data)}")

        for key in unique_keys:
            # Try ECB
            dec = try_decrypt_aes(enc_data, key, 'ECB')
            if dec:
                final, comp = try_decompress(dec)
                if is_valid_xml(final):
                    print(f"\n[+] SUCCESS! ECB mode")
                    print(f"[+] Key: {key.hex()}")
                    print(f"[+] Offset: {offset}")
                    print(f"[+] Compression: {comp}")
                    save_result(filepath, final)
                    return True

            # Try CBC with zero IV
            dec = try_decrypt_aes(enc_data, key, 'CBC', b'\x00'*16)
            if dec:
                final, comp = try_decompress(dec)
                if is_valid_xml(final):
                    print(f"\n[+] SUCCESS! CBC mode (zero IV)")
                    print(f"[+] Key: {key.hex()}")
                    print(f"[+] Offset: {offset}")
                    print(f"[+] Compression: {comp}")
                    save_result(filepath, final)
                    return True

            # Try CBC with IV from header (bytes 48-64)
            if len(data) >= 64:
                iv = data[48:64]
                dec = try_decrypt_aes(enc_data, key, 'CBC', iv)
                if dec:
                    final, comp = try_decompress(dec)
                    if is_valid_xml(final):
                        print(f"\n[+] SUCCESS! CBC mode (header IV)")
                        print(f"[+] Key: {key.hex()}")
                        print(f"[+] IV: {iv.hex()}")
                        print(f"[+] Offset: {offset}")
                        print(f"[+] Compression: {comp}")
                        save_result(filepath, final)
                        return True

            # Try CBC with first 16 bytes of data as IV
            if len(enc_data) > 16:
                iv = enc_data[:16]
                ct = enc_data[16:]
                dec = try_decrypt_aes(ct, key, 'CBC', iv)
                if dec:
                    final, comp = try_decompress(dec)
                    if is_valid_xml(final):
                        print(f"\n[+] SUCCESS! CBC mode (data IV)")
                        print(f"[+] Key: {key.hex()}")
                        print(f"[+] Offset: {offset}")
                        print(f"[+] Compression: {comp}")
                        save_result(filepath, final)
                        return True

    print("[-] Could not decrypt with tested keys")
    return False

def decrypt_conf(filepath):
    """Decrypt Base64 .conf file"""
    print(f"\n[*] Processing: {filepath}")

    with open(filepath, 'rb') as f:
        raw_data = f.read()

    print(f"[*] File size: {len(raw_data)} bytes")

    # Decode Base64
    try:
        enc_data = base64.b64decode(raw_data)
        print(f"[*] Base64 decoded: {len(enc_data)} bytes")
    except:
        enc_data = raw_data
        print("[*] Not Base64, using raw data")

    # Build key list
    all_keys = []

    known_keys = [
        b'$1$YaKi9SFn$'.ljust(16, b'\x00'),
        b'HuaweiHomeGateway'[:16],
        b'huawei'.ljust(16, b'\x00'),
        b'admin'.ljust(16, b'\x00'),
        bytes.fromhex('00000000000000000000000000000000'),
        hashlib.md5(b'huawei').digest(),
        hashlib.md5(b'HG8145B7N').digest(),
        hashlib.md5(b'telecomadmin').digest(),
        hashlib.md5(b'admin').digest(),
        hashlib.md5(b'AIS').digest(),
        hashlib.md5(b'E0AEA2EFB1CD').digest(),
        hashlib.md5(b'48575443286F3DB5').digest(),
    ]
    all_keys.extend(known_keys)

    # Device patterns
    device_strings = [
        "HG8145B7N", "E0AEA2EFB1CD", "48575443286F3DB5", "HWTC286F3DB5",
        "AIS", "39E7.A", "V5R023C10S104", "OptiXstar"
    ]
    for ds in device_strings:
        all_keys.append(hashlib.md5(ds.encode()).digest())
        all_keys.append(hashlib.sha256(ds.encode()).digest()[:16])
        all_keys.append(ds.encode()[:16].ljust(16, b'\x00'))

    for base in ["HG8145B7N", "hg8145b7n", "AIS"]:
        for suffix in ["key", "AES", "cfg", "config", "DecKey", "EncKey", "_key", "_AES"]:
            combo = f"{base}{suffix}"
            all_keys.append(hashlib.md5(combo.encode()).digest())
            all_keys.append(combo.encode()[:16].ljust(16, b'\x00'))
            combo2 = f"{base}_{suffix}"
            all_keys.append(hashlib.md5(combo2.encode()).digest())

    # Remove duplicates
    unique_keys = list(set(k for k in all_keys if len(k) in [16, 24, 32]))
    print(f"[*] Keys to try: {len(unique_keys)}")

    for key in unique_keys:
        # ECB
        dec = try_decrypt_aes(enc_data, key, 'ECB')
        if dec:
            final, comp = try_decompress(dec)
            if is_valid_xml(final):
                print(f"\n[+] SUCCESS! ECB mode")
                print(f"[+] Key: {key.hex()}")
                save_result(filepath, final)
                return True

        # CBC zero IV
        dec = try_decrypt_aes(enc_data, key, 'CBC', b'\x00'*16)
        if dec:
            final, comp = try_decompress(dec)
            if is_valid_xml(final):
                print(f"\n[+] SUCCESS! CBC mode")
                print(f"[+] Key: {key.hex()}")
                save_result(filepath, final)
                return True

        # CBC with IV from data
        if len(enc_data) > 16:
            iv = enc_data[:16]
            ct = enc_data[16:]
            dec = try_decrypt_aes(ct, key, 'CBC', iv)
            if dec:
                final, comp = try_decompress(dec)
                if is_valid_xml(final):
                    print(f"\n[+] SUCCESS! CBC mode (IV from data)")
                    print(f"[+] Key: {key.hex()}")
                    save_result(filepath, final)
                    return True

    print("[-] Could not decrypt")
    return False

def save_result(filepath, data):
    """Save decrypted data"""
    out_path = filepath + ".decrypted"
    with open(out_path, 'wb') as f:
        f.write(data)
    print(f"[+] Saved to: {out_path}")
    print(f"\n[+] Preview:")
    print("-" * 60)
    try:
        preview = data[:2000].decode('utf-8', errors='replace')
        print(preview)
    except:
        print(data[:2000])
    print("-" * 60)

def main():
    print("=" * 60)
    print("Huawei HG8145B7N Decryption Tool v3")
    print("=" * 60)

    xml_file = "/home/user/routerde/hw_ctree.xml"
    conf_file = "/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf"

    if os.path.exists(xml_file):
        decrypt_hwctree(xml_file)

    if os.path.exists(conf_file):
        decrypt_conf(conf_file)

if __name__ == "__main__":
    main()
