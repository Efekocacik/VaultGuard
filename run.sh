#!/bin/bash
# JARVIS Core HUD - Baslatici Scripti
# Kullanim: ./run.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

# Venv yoksa olustur
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Sanal ortam olusturuluyor..."
    python3 -m venv "$VENV_DIR"
fi

# En guncel Python'u venv icinde bul (3.14 > 3.12 > 3.11 > 3.9)
PYTHON=""
for v in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    candidate="$VENV_DIR/bin/$v"
    if [ -x "$candidate" ]; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "[!] Venv icinde Python bulunamadi."
    exit 1
fi

echo "[*] Kullanilan Python: $PYTHON"

# Gerekli paketleri kur (zaten kuruluysa hizlica atlar)
"$PYTHON" -m pip install --quiet flask flask-socketio flask-cors requests

echo ""
echo "============================================================"
echo "  JARVIS Core HUD baslatiliyor..."
echo "  Adres: http://localhost:5005"
echo "============================================================"
echo ""

# Uygulamayi calistir
"$PYTHON" "$SCRIPT_DIR/app.py"
