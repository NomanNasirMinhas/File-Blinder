#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Building file_blinder_dll.dll..."
(cd file_blinder_dll && cargo build --release)

echo "[*] Building file_blinder_injector.exe..."
(cd file_blinder_injector && cargo build --release)

echo "[*] Copying binaries..."
cp -f file_blinder_dll/target/release/file_blinder_dll.dll file_blinder_dll.dll
cp -f file_blinder_injector/target/release/file_blinder_injector.exe file_blinder_injector.exe

echo "[+] Build complete!"
ls -lh file_blinder_dll.dll file_blinder_injector.exe
