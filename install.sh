#!/bin/bash
echo "[*] Installing JWTester dependencies..."
pip3 install -r requirements.txt --break-system-packages
echo "[+] Done! Run: python3 jwt_tester.py -t <token>"
