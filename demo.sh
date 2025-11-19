#!/bin/bash
# Demo script showing usage of Huawei router configuration decryption tools

echo "=================================================="
echo "Huawei HG8145B7N Configuration Decryption Demo"
echo "=================================================="
echo ""

# Check if sample files exist
if [ ! -f "AIS_8806480495_HG8145B7N_20251118_121144.conf" ]; then
    echo "Error: Sample .conf file not found"
    exit 1
fi

if [ ! -f "hw_ctree.xml" ]; then
    echo "Error: Sample hw_ctree.xml file not found"
    exit 1
fi

echo "1. Analyzing .conf file structure..."
echo "-----------------------------------"
python3 analyze_config.py AIS_8806480495_HG8145B7N_20251118_121144.conf
echo ""
echo "Press Enter to continue..."
read

echo ""
echo "2. Analyzing hw_ctree.xml file structure..."
echo "-------------------------------------------"
python3 analyze_config.py hw_ctree.xml
echo ""
echo "Press Enter to continue..."
read

echo ""
echo "3. Attempting to decrypt .conf file with known keys..."
echo "------------------------------------------------------"
python3 huawei_decrypt.py AIS_8806480495_HG8145B7N_20251118_121144.conf
echo ""
echo "Press Enter to continue..."
read

echo ""
echo "4. Attempting to decrypt hw_ctree.xml with known keys..."
echo "--------------------------------------------------------"
python3 huawei_decrypt.py hw_ctree.xml
echo ""

echo "=================================================="
echo "Demo complete!"
echo ""
echo "NOTES:"
echo "- If decryption failed, you need the router-specific encryption key"
echo "- Extract the key from your router at /etc/wap/aes_string"
echo "- Then use: python3 huawei_decrypt.py file.conf -k YOUR_KEY_HERE"
echo ""
echo "See DECRYPTION_RESEARCH.md for detailed information"
echo "=================================================="
