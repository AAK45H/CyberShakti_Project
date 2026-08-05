#!/bin/bash
# ============================================================
# Phase 1 setup for Person A ("The Attacker" / server builder)
# Generates the weak, no-forward-secrecy TLS key + self-signed cert
# ============================================================
set -e

echo "[*] Generating 2048-bit RSA key + self-signed cert (server.key / server.crt)..."
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
    -days 365 -nodes \
    -subj "/C=IN/ST=Lab/L=Lab/O=ForensicsClass/OU=VictimVM/CN=victim-vm"

mkdir -p uploads

echo "[*] Also writing a classic PKCS#1 copy (server_pkcs1.key)..."
echo "    Some older Wireshark builds are picky about key format -- if the"
echo "    modern PKCS#8 server.key doesn't decrypt in your Wireshark's RSA"
echo "    keys list, try server_pkcs1.key instead."
openssl rsa -in server.key -out server_pkcs1.key -traditional 2>/dev/null || \
    openssl rsa -in server.key -out server_pkcs1.key

echo "[+] Done."
echo "    server.key        -> the SECRET private key (PKCS#8, what the IDOR flaw leaks)"
echo "    server_pkcs1.key  -> same key, classic PKCS#1 format (Wireshark fallback)"
echo "    server.crt        -> the public certificate"
echo "    uploads/          -> put the image you want to serve as the 'confidential' file here"
echo ""
echo "Next: run 'python3 app.py' to start the vulnerable server."
