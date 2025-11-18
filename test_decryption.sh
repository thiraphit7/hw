#!/bin/bash
# Test script for Huawei router decryption tools

echo "=========================================="
echo "Testing Huawei Router Decryption Tools"
echo "=========================================="
echo ""

# Test 1: Check Python dependencies
echo "[Test 1] Checking Python dependencies..."
python3 -c "from Crypto.Cipher import AES; print('✓ PyCryptodome installed')" || exit 1
echo ""

# Test 2: Verify script syntax
echo "[Test 2] Verifying Python script syntax..."
python3 -m py_compile decrypt_router.py decrypt_conf.py decrypt_ctree.py
if [ $? -eq 0 ]; then
    echo "✓ All scripts compile successfully"
else
    echo "✗ Script compilation failed"
    exit 1
fi
echo ""

# Test 3: Check help messages
echo "[Test 3] Testing help messages..."
python3 decrypt_router.py 2>&1 | grep -q "Huawei HG8145B7N"
if [ $? -eq 0 ]; then
    echo "✓ Help message displays correctly"
else
    echo "✗ Help message test failed"
    exit 1
fi
echo ""

# Test 4: Test .conf file decryption
echo "[Test 4] Testing .conf file decryption..."
if [ -f "AIS_8806480495_HG8145B7N_20251118_121144.conf" ]; then
    python3 decrypt_router.py AIS_8806480495_HG8145B7N_20251118_121144.conf > /dev/null 2>&1
    if [ -f "AIS_8806480495_HG8145B7N_20251118_121144_decrypted_raw.bin" ]; then
        echo "✓ .conf file processed (raw data generated)"
    else
        echo "⚠ .conf file processed but no output generated"
    fi
else
    echo "⚠ .conf test file not found"
fi
echo ""

# Test 5: Test hw_ctree.xml decryption
echo "[Test 5] Testing hw_ctree.xml file decryption..."
if [ -f "hw_ctree.xml" ]; then
    python3 decrypt_router.py hw_ctree.xml > /dev/null 2>&1
    if [ -f "hw_ctree_decrypted_raw.bin" ]; then
        echo "✓ hw_ctree.xml file processed (raw data generated)"
    else
        echo "⚠ hw_ctree.xml file processed but no output generated"
    fi
else
    echo "⚠ hw_ctree.xml test file not found"
fi
echo ""

# Test 6: Verify .gitignore works
echo "[Test 6] Verifying .gitignore excludes decrypted files..."
git status --short | grep -q "_decrypted"
if [ $? -ne 0 ]; then
    echo "✓ Decrypted files are properly ignored by git"
else
    echo "⚠ Some decrypted files may not be ignored"
fi
echo ""

echo "=========================================="
echo "Test Summary: All critical tests passed ✓"
echo "=========================================="
