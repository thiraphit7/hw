#!/usr/bin/env python3
"""
Huawei HG8145B7N Config Decryption Tool
Generates keys based on device information and attempts AES decryption
"""

import base64
import hashlib
import itertools
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii
import os

# Device Information
DEVICE_INFO = {
    "model": "HG8145B7N",
    "model_ais": "HG8145B7N-AIS",
    "mac": "E0:AE:A2:EF:B1:CD",
    "mac_no_colon": "E0AEA2EFB1CD",
    "mac_lower": "e0:ae:a2:ef:b1:cd",
    "mac_lower_no_colon": "e0aea2efb1cd",
    "hardware_version": "39E7.A",
    "firmware": "V5R023C10S104",
    "firmware_short": "V5R023C10",
    "firmware_ver": "V5",
    "sn": "48575443286F3DB5",
    "sn_readable": "HWTC286F3DB5",
    "ont_id": "1",
    "custom_info": "AIS",
}

# Base tokens (11 variants)
BASE_TOKENS = [
    "HG8145B7N",
    "hg8145b7n",
    "HuaweiHG8145B7N",
    "AIS_HG8145B7N",
    "HG8145B7N-AIS",
    "hg8145b7n-ais",
    "Huawei_HG8145B7N",
    "HUAWEI_HG8145B7N",
    "HG8145B7NAIS",
    "OptiXstar",
    "OptiXstarHG8145B7N",
]

# Key-role tokens (9 patterns)
KEYROLE_TOKENS = [
    "key", "KEY", "Key",
    "aes", "AES", "Aes",
    "cfg", "CFG",
    "cfgkey", "CFGKEY", "CfgKey",
    "config", "CONFIG", "Config",
    "DecKey", "deckey", "DECKEY",
    "EncKey", "enckey", "ENCKEY",
    "secret", "SECRET",
    "password", "PASSWORD",
    "encrypt", "ENCRYPT",
    "decrypt", "DECRYPT",
]

# Version tokens
VERSION_TOKENS = [
    "V5R023C10S104",
    "V5R023C10",
    "V5",
    "39E7.A",
    "39E7A",
]

# Year tokens
YEAR_TOKENS = ["2023", "2024", "2025"]

# Additional device-specific tokens
DEVICE_TOKENS = [
    DEVICE_INFO["mac_no_colon"],
    DEVICE_INFO["mac_lower_no_colon"],
    DEVICE_INFO["sn"],
    DEVICE_INFO["sn_readable"],
    DEVICE_INFO["custom_info"],
]

def generate_keys():
    """Generate all possible keys based on 6 patterns"""
    keys = set()

    # Pattern 1: <base> → HG8145B7N
    for base in BASE_TOKENS:
        keys.add(base)

    # Pattern 2: <base>_<keyrole> → HG8145B7N_AES
    for base in BASE_TOKENS:
        for keyrole in KEYROLE_TOKENS:
            keys.add(f"{base}_{keyrole}")
            keys.add(f"{base}{keyrole}")  # No separator variant

    # Pattern 3: <keyrole>_<base> → cfgkey_HG8145B7N
    for keyrole in KEYROLE_TOKENS:
        for base in BASE_TOKENS:
            keys.add(f"{keyrole}_{base}")
            keys.add(f"{keyrole}{base}")  # No separator variant

    # Pattern 4: <base><keyrole> → HG8145B7Nkey
    for base in BASE_TOKENS:
        for keyrole in KEYROLE_TOKENS:
            keys.add(f"{base}{keyrole}")

    # Pattern 5: <base>_<year> → HG8145B7N_2024
    for base in BASE_TOKENS:
        for year in YEAR_TOKENS:
            keys.add(f"{base}_{year}")
            keys.add(f"{base}{year}")

    # Pattern 6: <base>_<firmware>_<keyrole> → HG8145B7N_V5R023C10_AES
    for base in BASE_TOKENS:
        for version in VERSION_TOKENS:
            for keyrole in KEYROLE_TOKENS:
                keys.add(f"{base}_{version}_{keyrole}")
                keys.add(f"{base}{version}{keyrole}")

    # Additional patterns with device info
    # MAC-based keys
    for mac in [DEVICE_INFO["mac_no_colon"], DEVICE_INFO["mac_lower_no_colon"]]:
        keys.add(mac)
        keys.add(f"HG8145B7N_{mac}")
        keys.add(f"{mac}_HG8145B7N")
        for keyrole in KEYROLE_TOKENS:
            keys.add(f"{mac}_{keyrole}")
            keys.add(f"HG8145B7N_{mac}_{keyrole}")

    # SN-based keys
    for sn in [DEVICE_INFO["sn"], DEVICE_INFO["sn_readable"]]:
        keys.add(sn)
        keys.add(f"HG8145B7N_{sn}")
        keys.add(f"{sn}_HG8145B7N")
        for keyrole in KEYROLE_TOKENS:
            keys.add(f"{sn}_{keyrole}")

    # Common Huawei default keys
    huawei_defaults = [
        "huawei",
        "HUAWEI",
        "Huawei",
        "admin",
        "root",
        "telecomadmin",
        "admintelecom",
        "huawei@HG8145B7N",
        "HG8145B7N@huawei",
        "hw_ctree_key",
        "hw_config_key",
        "hwtree",
        "hwctree",
        "ctree",
        "Hw_ctree",
        "HWctree",
        "hwconfigtree",
        "configtree",
        "aescfgkey",
        "aes256cfgkey",
        "aes128cfgkey",
        "HuaweiConfigKey",
        "ConfigEncryptKey",
        "HGPONKey",
        "OLTKey",
        "ONTKey",
        "GPONKey",
        "WifiKey",
        "AISKey",
        "AIS_KEY",
        "ais_key",
        "huaweiais",
        "AISHuawei",
        "HuaweiAIS",
    ]
    keys.update(huawei_defaults)

    # Combine with custom info
    for default in huawei_defaults[:10]:
        keys.add(f"{default}_HG8145B7N")
        keys.add(f"HG8145B7N_{default}")

    return list(keys)

def derive_aes_key(password, key_length=16):
    """Derive AES key from password using different methods"""
    keys = []

    # Method 1: Direct bytes (if password is 16, 24, or 32 bytes)
    pwd_bytes = password.encode('utf-8')
    if len(pwd_bytes) in [16, 24, 32]:
        keys.append(pwd_bytes)

    # Method 2: MD5 hash (16 bytes for AES-128)
    keys.append(hashlib.md5(pwd_bytes).digest())

    # Method 3: SHA256 truncated (16 bytes for AES-128)
    keys.append(hashlib.sha256(pwd_bytes).digest()[:16])

    # Method 4: SHA256 full (32 bytes for AES-256)
    keys.append(hashlib.sha256(pwd_bytes).digest())

    # Method 5: Padded/truncated to 16 bytes
    padded = (pwd_bytes * ((16 // len(pwd_bytes)) + 1))[:16] if pwd_bytes else b'\x00' * 16
    keys.append(padded)

    # Method 6: Padded/truncated to 32 bytes
    padded32 = (pwd_bytes * ((32 // len(pwd_bytes)) + 1))[:32] if pwd_bytes else b'\x00' * 32
    keys.append(padded32)

    # Method 7: Zero-padded to 16 bytes
    keys.append(pwd_bytes[:16].ljust(16, b'\x00'))

    # Method 8: Zero-padded to 32 bytes
    keys.append(pwd_bytes[:32].ljust(32, b'\x00'))

    return keys

def try_decrypt_aes_ecb(ciphertext, key):
    """Try AES ECB decryption"""
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        # Try to unpad
        try:
            decrypted = unpad(decrypted, AES.block_size)
        except:
            pass
        return decrypted
    except Exception as e:
        return None

def try_decrypt_aes_cbc(ciphertext, key, iv=None):
    """Try AES CBC decryption"""
    try:
        if iv is None:
            # Try first 16 bytes as IV
            if len(ciphertext) > 16:
                iv = ciphertext[:16]
                ciphertext = ciphertext[16:]
            else:
                iv = b'\x00' * 16

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        try:
            decrypted = unpad(decrypted, AES.block_size)
        except:
            pass
        return decrypted
    except Exception as e:
        return None

def try_decrypt_aes_cbc_zero_iv(ciphertext, key):
    """Try AES CBC with zero IV"""
    try:
        iv = b'\x00' * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        try:
            decrypted = unpad(decrypted, AES.block_size)
        except:
            pass
        return decrypted
    except Exception as e:
        return None

def is_valid_xml(data):
    """Check if decrypted data looks like valid XML"""
    try:
        text = data.decode('utf-8', errors='ignore')
        # Check for XML markers
        if '<?xml' in text or '<' in text and '>' in text:
            # More specific checks
            if any(marker in text.lower() for marker in ['<config', '<device', '<setting', '<wan', '<lan', '<wifi', '<ssid', '<password', '<pppoe', '<username', '<!doctype', '<huawei', '<ctree', '<hw_ctree']):
                return True
            # Check for valid XML structure
            if text.strip().startswith('<') and '>' in text:
                return True
        return False
    except:
        return False

def is_valid_decrypted(data):
    """Check if data looks like valid decrypted content"""
    try:
        # Check for high proportion of printable ASCII
        printable_count = sum(1 for b in data if 32 <= b < 127 or b in [9, 10, 13])
        ratio = printable_count / len(data) if data else 0

        # Check for XML markers
        if is_valid_xml(data):
            return True, "XML"

        # Check for other text patterns
        text = data.decode('utf-8', errors='ignore')
        if ratio > 0.7:
            return True, "TEXT"

        return False, None
    except:
        return False, None

def load_encrypted_file(filepath):
    """Load and prepare encrypted file for decryption"""
    with open(filepath, 'rb') as f:
        content = f.read()

    results = []

    # Try as raw binary
    results.append(("raw", content))

    # Try as Base64
    try:
        decoded = base64.b64decode(content)
        results.append(("base64", decoded))
    except:
        pass

    # Try as Base64 with stripped whitespace
    try:
        stripped = content.replace(b'\n', b'').replace(b'\r', b'').replace(b' ', b'')
        decoded = base64.b64decode(stripped)
        results.append(("base64_stripped", decoded))
    except:
        pass

    return results

def main():
    print("=" * 60)
    print("Huawei HG8145B7N Config Decryption Tool")
    print("=" * 60)

    # Generate all possible keys
    print("\n[*] Generating keys...")
    passwords = generate_keys()
    print(f"[+] Generated {len(passwords)} password candidates")

    # Files to try
    files_to_try = [
        "/home/user/routerde/AIS_8806480495_HG8145B7N_20251118_121144.conf",
        "/home/user/routerde/hw_ctree.xml",
    ]

    for filepath in files_to_try:
        if not os.path.exists(filepath):
            print(f"[-] File not found: {filepath}")
            continue

        print(f"\n{'='*60}")
        print(f"[*] Processing: {os.path.basename(filepath)}")
        print("=" * 60)

        # Load encrypted content in different formats
        encrypted_variants = load_encrypted_file(filepath)
        print(f"[+] Loaded {len(encrypted_variants)} content variants")

        found = False

        for variant_name, encrypted_data in encrypted_variants:
            if found:
                break

            print(f"\n[*] Trying variant: {variant_name}")
            print(f"[*] Data length: {len(encrypted_data)} bytes")

            # Ensure data is multiple of 16 for AES
            if len(encrypted_data) % 16 != 0:
                # Pad to multiple of 16
                padded_len = ((len(encrypted_data) // 16) + 1) * 16
                encrypted_data_padded = encrypted_data.ljust(padded_len, b'\x00')
            else:
                encrypted_data_padded = encrypted_data

            total_attempts = len(passwords) * 8 * 3  # passwords * key_derivations * modes
            attempt = 0

            for password in passwords:
                if found:
                    break

                # Derive all possible keys from password
                aes_keys = derive_aes_key(password)

                for aes_key in aes_keys:
                    if found:
                        break

                    attempt += 1

                    # Progress indicator
                    if attempt % 10000 == 0:
                        print(f"[*] Progress: {attempt} attempts...")

                    # Try ECB mode
                    decrypted = try_decrypt_aes_ecb(encrypted_data_padded, aes_key)
                    if decrypted:
                        valid, dtype = is_valid_decrypted(decrypted)
                        if valid:
                            print(f"\n[+] SUCCESS! Key found!")
                            print(f"[+] Password: {password}")
                            print(f"[+] Key (hex): {aes_key.hex()}")
                            print(f"[+] Mode: ECB")
                            print(f"[+] Variant: {variant_name}")
                            print(f"[+] Data type: {dtype}")
                            print(f"\n[+] Decrypted preview (first 500 chars):")
                            print("-" * 40)
                            try:
                                print(decrypted[:500].decode('utf-8', errors='replace'))
                            except:
                                print(decrypted[:500])
                            print("-" * 40)

                            # Save decrypted file
                            out_path = filepath + ".decrypted"
                            with open(out_path, 'wb') as f:
                                f.write(decrypted)
                            print(f"[+] Saved to: {out_path}")
                            found = True
                            break

                    # Try CBC with zero IV
                    decrypted = try_decrypt_aes_cbc_zero_iv(encrypted_data_padded, aes_key)
                    if decrypted:
                        valid, dtype = is_valid_decrypted(decrypted)
                        if valid:
                            print(f"\n[+] SUCCESS! Key found!")
                            print(f"[+] Password: {password}")
                            print(f"[+] Key (hex): {aes_key.hex()}")
                            print(f"[+] Mode: CBC (zero IV)")
                            print(f"[+] Variant: {variant_name}")
                            print(f"[+] Data type: {dtype}")
                            print(f"\n[+] Decrypted preview (first 500 chars):")
                            print("-" * 40)
                            try:
                                print(decrypted[:500].decode('utf-8', errors='replace'))
                            except:
                                print(decrypted[:500])
                            print("-" * 40)

                            out_path = filepath + ".decrypted"
                            with open(out_path, 'wb') as f:
                                f.write(decrypted)
                            print(f"[+] Saved to: {out_path}")
                            found = True
                            break

                    # Try CBC with IV from data
                    decrypted = try_decrypt_aes_cbc(encrypted_data_padded, aes_key)
                    if decrypted:
                        valid, dtype = is_valid_decrypted(decrypted)
                        if valid:
                            print(f"\n[+] SUCCESS! Key found!")
                            print(f"[+] Password: {password}")
                            print(f"[+] Key (hex): {aes_key.hex()}")
                            print(f"[+] Mode: CBC (IV from data)")
                            print(f"[+] Variant: {variant_name}")
                            print(f"[+] Data type: {dtype}")
                            print(f"\n[+] Decrypted preview (first 500 chars):")
                            print("-" * 40)
                            try:
                                print(decrypted[:500].decode('utf-8', errors='replace'))
                            except:
                                print(decrypted[:500])
                            print("-" * 40)

                            out_path = filepath + ".decrypted"
                            with open(out_path, 'wb') as f:
                                f.write(decrypted)
                            print(f"[+] Saved to: {out_path}")
                            found = True
                            break

            if not found:
                print(f"[-] No valid key found for variant: {variant_name}")

        if not found:
            print(f"\n[-] Could not decrypt: {filepath}")

    print("\n" + "=" * 60)
    print("[*] Decryption attempts completed")
    print("=" * 60)

if __name__ == "__main__":
    main()
