import os
import re
import time
import datetime
import threading
import requests
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# ─── Flask & SocketIO ──────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = 'jarvis-stark-core-protocol'
CORS(app)
# async_mode='threading' → eventlet/gevent gerekmez, stdlib thread kullanır
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ─── TTS Motoru (İsteğe Bağlı) ────────────────────────────────────────────────
try:
    import pyttsx3
    _tts_engine = pyttsx3.init()
    _tts_engine.setProperty('rate', 170)
    _tts_engine.setProperty('volume', 1.0)
    TTS_AVAILABLE = True
except Exception as _e:
    print("[TTS Bilgi]: pyttsx3 aktif degil - Sesli yanit pasif, metin modu aktif.")
    _tts_engine = None
    TTS_AVAILABLE = False

_tts_lock = threading.Lock()


def jarvis_speak(text: str) -> None:
    """Daemon thread'de TTS cagirir; ana thread'i bloke etmez."""
    if not TTS_AVAILABLE:
        return

    def _speak():
        with _tts_lock:
            try:
                _tts_engine.say(text[:300])   # uzun metinleri kisalt
                _tts_engine.runAndWait()
            except Exception as e:
                print(f"[TTS Hatasi]: {e}")

    threading.Thread(target=_speak, daemon=True).start()


# ─── Ollama LLM ───────────────────────────────────────────────────────────────
OLLAMA_API   = "http://localhost:11434/api/generate"
MODEL_NAME   = "llama3"
OLLAMA_TIMEOUT = 10  # saniye

SYSTEM_PROMPT = (
    "Sen Tony Stark'in gelistirdigi JARVIS yapay zekasisin. "
    "Kullaniciya her zaman 'efendim' diye hitap et. "
    "Cevaplarin kisa, net, teknik ve futuristik olsun. "
    "Turkce konus; cekirdek seviyesindeki guvenlik olaylarini dogrula."
)


def ask_ollama(prompt: str) -> str:
    """Ollama API'ye istek gonderir; hata durumunda fallback mesaj doner."""
    payload = {
        "model": MODEL_NAME,
        "prompt": f"{SYSTEM_PROMPT}\n\nKullanici: {prompt}\nJARVIS:",
        "stream": False,
    }
    try:
        res = requests.post(OLLAMA_API, json=payload, timeout=OLLAMA_TIMEOUT)
        res.raise_for_status()
        return res.json().get("response", "Islem tamamlandi efendim.").strip()
    except requests.exceptions.ConnectionError:
        return "Ollama servisi cevrimdisi efendim. Yerel LLM baglantisi saglanamadi."
    except requests.exceptions.Timeout:
        return "Istek zaman asimina ugradi efendim. Protokoller nominal modda devam ediyor."
    except Exception as e:
        print(f"[Ollama Hatasi]: {e}")
        return "Cekirdek protokolleri nominal modda calismaya devam ediyor efendim."


# ─── Sistem Eylemleri ─────────────────────────────────────────────────────────
_SYSFS_QUARANTINE = (
    "/sys/class/vaultguard_class/vaultguard_dev/quarantine_status"
)
_DEBUGFS_PURGE = "/sys/kernel/debug/vaultguard/force_purge"


def _sysfs_write(path: str, value: str) -> bool:
    """sysfs/debugfs dosyasina guvenli sekilde yazar; True = basari."""
    try:
        # sudo gerektiren operasyon — production'da sudoers kuralıyla kilitleyin
        ret = os.system(
            f"echo '{value}' | sudo tee {path} > /dev/null 2>&1"
        )
        return ret == 0
    except Exception as e:
        print(f"[SysFS Yazma Hatasi]: {e}")
        return False


def execute_system_action(cmd: str):
    """
    Tanimli sistem komutlarini eslestirir.
    Return: (handled: bool, reply: str)
    """
    c = cmd.lower().strip()

    # Karantina aç
    if "karantina" in c and any(w in c for w in ("aktif", "ac", "aç", "etkin", "baslat")):
        ok = _sysfs_write(_SYSFS_QUARANTINE, "1")
        if ok:
            return True, (
                "VaultGuard Zero-Trust karantina modu devreye sokuldu. "
                "Canary tuzaklari aktif efendim."
            )
        return True, (
            "Karantina komutu gonderildi efendim, ancak sysfs yazma dogrulanamadi. "
            "Modul yuklenmis mi kontrol edin."
        )

    # Karantina kapat
    if "karantina" in c and any(w in c for w in ("kapat", "guvenli", "güvenli", "devre")):
        ok = _sysfs_write(_SYSFS_QUARANTINE, "0")
        if ok:
            return True, (
                "Karantina kaldirildi. Sistem guvenli operasyonel moda gecti efendim."
            )
        return True, (
            "Karantina kapatma komutu gonderildi efendim, sysfs dogrulamasi basarisiz."
        )

    # Acil bellek imhasi — UI artik 'acil bellek imha' gonderiyor
    if any(kw in c for kw in ("bellek imha", "acil imha", "force purge", "purge", "kriptografik")):
        ok = _sysfs_write(_DEBUGFS_PURGE, "1")
        if ok:
            return True, (
                "Kriptografik acil durum imhasi tamamlandi. "
                "Cekirdek sirlari sifirlandi efendim."
            )
        return True, (
            "Acil imha komutu gonderildi efendim, ancak debugfs dogrulanamadi. "
            "Modul yuklenmis ve debugfs mount edilmis mi kontrol edin."
        )

    # Durum raporu
    if any(kw in c for kw in ("durum raporu", "sistem durumu", "telemetri", "status report")):
        data = parse_vaultguard_proc()
        return True, (
            f"Cekirdek durumu: {data['status']}. "
            f"Aktif sir: {data['active_secrets']}, "
            f"Toplam depolanan: {data['total_stored']}, "
            f"Canary alarmi: {data['canary_alerts']}, "
            f"Kripto hatasi: {data['crypto_errors']} efendim."
        )

    # Dosya oluştur
    if any(kw in c for kw in ("dosya olustur", "dosya oluştur", "dosyasi olustur")):
        words = c.split()
        filename = "protokol_notu.txt"
        for i, w in enumerate(words):
            if w in ("dosya", "dosyasi", "adinda", "adında") and i > 0:
                candidate = re.sub(r"[^\w\-]", "_", words[i - 1])
                if candidate:
                    filename = f"{candidate}.txt"
                break
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(
                    f"JARVIS Sistem Kaydi — {datetime.datetime.now().isoformat()}\n"
                )
            return True, f"'{filename}' basariyla olusturuldu ve diske muhurlendi efendim."
        except Exception as e:
            return True, f"Dosya olusturma basarisiz efendim: {e}"

    # Saat
    if any(kw in c for kw in ("saat kac", "saat kaç", "saat nedir", "zaman")):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        return True, f"Yerel zaman {now} efendim."

    return False, ""


# ─── /proc/vaultguard Telemetri Ayrıştırıcısı ────────────────────────────────
_PROC_PATH = "/proc/vaultguard"

# VaultGuard v2 /proc formatı için regex tablosu
_PATTERNS = {
    "status":         re.compile(r"Quarantine Status\s*:\s*(.+)"),
    "active_secrets": re.compile(r"Active Secrets\s*:\s*(\d+)"),
    "total_stored":   re.compile(r"Total Stored\s*:\s*(\d+)"),
    "total_purged":   re.compile(r"Total Purged\s*:\s*(\d+)"),
    "canary_alerts":  re.compile(r"Canary Alerts\s*:\s*(\d+)"),
    "crypto_errors":  re.compile(r"Crypto Errors\s*:\s*(\d+)"),
    "default_ttl":    re.compile(r"Default TTL(?:\s*\(sec\))?\s*:\s*(\d+)"),
}
# Slot satiri: [ label ]  PID=X  UID=Y  Remaining=Zs
_SLOT_RE = re.compile(
    r"\[\s*(.+?)\s*\]\s+PID=(\d+)\s+UID=(\d+)\s+Remaining=(\d+)s"
)


def parse_vaultguard_proc() -> dict:
    """
    /proc/vaultguard dosyasini okuyarak telemetri sozlugu doner.
    Modul yuklenmemisse veya okuma hatasi olursa guvenli varsayilanlari doner.
    """
    telemetry = {
        "status":         "MODUL CEVRIMDISI",
        "active_secrets":  0,
        "total_stored":    0,
        "total_purged":    0,
        "canary_alerts":   0,
        "crypto_errors":   0,
        "default_ttl":     None,
        "slots":           [],
        "raw":             "— /proc/vaultguard mevcut degil —",
    }

    if not os.path.exists(_PROC_PATH):
        return telemetry

    try:
        with open(_PROC_PATH, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(16384)   # max 16 KB okuyalim; overflow onlenir

        telemetry["raw"] = content

        for key, pat in _PATTERNS.items():
            m = pat.search(content)
            if m:
                val = m.group(1).strip()
                if key == "status":
                    telemetry[key] = val
                else:
                    try:
                        telemetry[key] = int(val)
                    except ValueError:
                        pass

        # Slot tablosu
        telemetry["slots"] = [
            {
                "label":     m.group(1),
                "pid":       int(m.group(2)),
                "uid":       int(m.group(3)),
                "remaining": int(m.group(4)),
            }
            for m in _SLOT_RE.finditer(content)
        ]

    except PermissionError:
        telemetry["raw"] = "ERISIM REDDEDILDI — sudo ile calistirin."
    except Exception as e:
        telemetry["raw"] = f"Okuma Hatasi: {e}"

    return telemetry


# ─── Telemetri Broadcaster (1 Hz, daemon thread) ─────────────────────────────
def telemetry_broadcaster() -> None:
    """
    1 saniyede bir /proc/vaultguard okuyarak tum WebSocket istemcilerine yayinlar.
    Hata durumunda thread olumez; hatayi loglar ve devam eder.
    """
    print("[Telemetri]: Broadcaster baslatildi.")
    while True:
        try:
            data = parse_vaultguard_proc()
            data["timestamp"] = datetime.datetime.now().strftime("%H:%M:%S")
            socketio.emit("telemetry_update", data, namespace="/")
        except Exception as e:
            # SocketIO henuz hazir degilse veya gecici hata varsa sessizce devam et
            print(f"[Telemetri Hatasi]: {e}")
        time.sleep(1.0)


# ─── Flask Rotalar ─────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    """REST endpoint — tarayici veya curl ile telemetri sorgulamak icin."""
    data = parse_vaultguard_proc()
    data["timestamp"] = datetime.datetime.now().isoformat()
    return jsonify(data)


@app.route("/api/health")
def api_health():
    """Basit uptime kontrol endpoint'i."""
    return jsonify({
        "status": "online",
        "tts": TTS_AVAILABLE,
        "time": datetime.datetime.now().isoformat(),
    })


# ─── WebSocket Olaylar ────────────────────────────────────────────────────────
_CMD_MAX_LEN = 512  # karakter limiti


@socketio.on("connect")
def on_connect():
    print(f"[WS]: Istemci baglandi.")
    # Yeni baglanan istemciye aninda guncel telemetri gonder
    try:
        data = parse_vaultguard_proc()
        data["timestamp"] = datetime.datetime.now().strftime("%H:%M:%S")
        emit("telemetry_update", data)
    except Exception as e:
        print(f"[WS Connect Emit Hatasi]: {e}")


@socketio.on("disconnect")
def on_disconnect():
    print(f"[WS]: Istemci ayrildi.")


@socketio.on("send_command")
def handle_command(json_data):
    """
    Kullanicidan gelen komut'u isler:
    1. Input dogrulamasi
    2. Sistem eylemi kontrolu
    3. Ollama LLM fallback
    4. TTS + WS yaniti
    """
    if not isinstance(json_data, dict):
        emit("jarvis_reply", {
            "command": "",
            "response": "Gecersiz istek formati efendim.",
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        })
        return

    user_msg = str(json_data.get("command", "")).strip()

    # Uzunluk dogrulamasi
    if not user_msg:
        return
    if len(user_msg) > _CMD_MAX_LEN:
        emit("jarvis_reply", {
            "command": user_msg[:80] + "...",
            "response": f"Komut cok uzun efendim. Maksimum {_CMD_MAX_LEN} karakter.",
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        })
        return

    reply = ""
    try:
        handled, reply = execute_system_action(user_msg)
        if not handled:
            reply = ask_ollama(user_msg)
    except Exception as e:
        print(f"[Komut Isleme Hatasi]: {e}")
        reply = "Islem sirasinda dahili bir hata olustu efendim."

    jarvis_speak(reply)

    emit("jarvis_reply", {
        "command":   user_msg,
        "response":  reply,
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
    })


# ─── Ana Giris Noktasi ────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Telemetri broadcaster'i sunucu basmadan once baslatmak guvenlidir;
    # socketio.emit bos istemci listesine yayin yapar ama hata vermez.
    broadcaster = threading.Thread(target=telemetry_broadcaster, daemon=True)
    broadcaster.start()

    jarvis_speak("Jarvis telemetri koprusu kuruldu efendim.")

    print("=" * 60)
    print("  JARVIS Core System Online")
    print(f"  Web HUD  : http://localhost:5005")
    print(f"  API      : http://localhost:5005/api/status")
    print(f"  TTS      : {'Aktif' if TTS_AVAILABLE else 'Devre disi'}")
    print("=" * 60)

    socketio.run(app, host="0.0.0.0", port=5005, debug=False)
