# VaultGuard v2.0

> **Zero-Trust Kernel Secret Vault Engine** — Linux çekirdeğinde çalışan, AES-256-GCM şifreli, çok katmanlı erişim kontrollü güvenlik modülü.

---

## 🔐 Nedir?

VaultGuard, hassas verileri (parola, API anahtarı, özel anahtar vb.) Linux çekirdek alanında güvenle saklayan bir **Loadable Kernel Module (LKM)**'dür.

Sırlar:
- **AES-256-GCM** ile şifreli tutulur (düz metin bellekte asla yer almaz)
- **PID + UID + PID Namespace** üçlü izolasyonuyla korunur
- **TTL** zamanlayıcısıyla otomatik olarak kriptografik imha edilir
- **DSE Koruması** (`memzero_explicit`) ile derleyici optimizasyonuna karşı korunur

---

## ✨ Özellikler

| Özellik | Açıklama |
|---|---|
| **AES-256-GCM** | Kernel Crypto API, donanım hızlandırmalı |
| **Multi-Slot Vault** | 64'e kadar bağımsız etiketli sır |
| **3 Katmanlı ACL** | PID + UID + Namespace + CAP_SYS_ADMIN override |
| **TTL Zamanlayıcı** | Her slot için bağımsız, saniye hassasiyetli |
| **DSE Koruması** | `memzero_explicit()` tüm kritik temizliklerde |
| **6 eBPF Tracepoint** | Her olay için ftrace + eBPF kancası |
| **Generic Netlink** | Çok dinleyicili SIEM olay akışı |
| **FASYNC Sinyal** | Geriye dönük uyumluluk (SIGIO) |
| **goto-chain Hata Yönetimi** | Kaynak sızıntısız init/exit |
| **procfs Telemetri** | `/proc/vaultguard` |
| **debugfs Arayüzü** | `force_purge`, `crypto_stats` |
| **sysfs Attribute** | `active_ttl`, `quarantine_status`, `canary_count` |

---

## 📁 Proje Yapısı

```
vaultguard_project/
├── vaultguard.c          # Ana kernel modülü (v2.0)
├── vaultguard.h          # Paylaşılan API tanımları (IOCTL, struct)
├── vaultguard_trace.h    # 6 eBPF/Ftrace tracepoint tanımı
├── vaultguard_netlink.h  # Generic Netlink protokol tanımları
├── vault_test.c          # Entegrasyon test programı
├── Makefile              # Derleme, kurulum, test otomasyonu
└── tools/
    ├── vaultctl.c        # Kullanıcı alanı yönetim CLI'ı
    └── vaultguard_monitor.bt  # bpftrace gerçek zamanlı izleyici
```

---

## 🚀 Hızlı Başlangıç

### 1. Derleme

```bash
make
```

### 2. Kurulum

```bash
sudo make install
```

Bu komut:
- Modülü yükler (`insmod`)
- Tracepoint'leri etkinleştirir
- Aygıt izinlerini ayarlar

### 3. Kullanım

```bash
# Sır depola (300 saniyelik TTL ile)
sudo vaultctl store --label db_pass --data 'Passw0rd!' --ttl 300

# Sır oku
sudo vaultctl get --label db_pass

# Tüm sırları listele
sudo vaultctl list

# Güvenlik durumu
sudo vaultctl status

# Gerçek zamanlı izleme (Ctrl+C ile çık)
sudo vaultctl monitor

# PID izolasyon testi
sudo vaultctl forktest --label test_key --data 'secret'

# Acil durum imhası
sudo vaultctl purge --force
```

### 4. Test

```bash
sudo make test
```

---

## 🔑 Güvenlik Mimarisi

```
┌─────────────────────────────────────────────────────────┐
│                     USER SPACE                           │
│  vaultctl CLI   │  SIEM Agent   │  bpftrace Monitor     │
└────────┬────────┴──────┬────────┴──────┬────────────────┘
         │ IOCTL         │ Netlink       │ Tracepoints
┌────────▼───────────────▼───────────────▼────────────────┐
│                   KERNEL SPACE                           │
│                                                          │
│  ┌─────────────────────────────────────────────────┐    │
│  │              ACL Katmanları                      │    │
│  │  Karantina → CAP_SYS_ADMIN → UID → NS → PID    │    │
│  └──────────────────────┬──────────────────────────┘    │
│                         │                                │
│  ┌──────────────────────▼──────────────────────────┐    │
│  │          AES-256-GCM Şifreleme                   │    │
│  │   [IV:12B][Ciphertext:256B][Auth Tag:16B]        │    │
│  └──────────────────────┬──────────────────────────┘    │
│                         │                                │
│  ┌──────────────────────▼──────────────────────────┐    │
│  │   Hashtable Vault (64 slot, TTL zamanlayıcılı)  │    │
│  └──────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

---

## 📡 IOCTL API Referansı

| Komut | Yön | Açıklama |
|---|---|---|
| `VAULT_IOC_STORE_SECRET` | Write | Miras: tek-slot depolama |
| `VAULT_IOC_GET_SECRET`   | Read  | Miras: tek-slot okuma |
| `VAULT_IOC_STORE_LABELED`  | Write | Etiketli sır depola |
| `VAULT_IOC_GET_LABELED`    | R/W   | Etiketli sır oku |
| `VAULT_IOC_DELETE_LABELED` | Write | Etiketli sır sil |
| `VAULT_IOC_LIST_LABELS`    | Read  | Tüm etiketleri listele |

---

## 📊 Kernel Arayüzleri

| Arayüz | Yol | Açıklama |
|---|---|---|
| Karakter Aygıtı | `/dev/vaultguard_dev` | IOCTL işlemleri |
| procfs | `/proc/vaultguard` | Güvenlik telemetrisi |
| sysfs | `/sys/.../active_ttl` | TTL yapılandırması |
| sysfs | `/sys/.../quarantine_status` | Karantina kontrolü |
| sysfs | `/sys/.../canary_count` | İhlal sayacı |
| debugfs | `/sys/kernel/debug/vaultguard/force_purge` | Acil imha |
| debugfs | `/sys/kernel/debug/vaultguard/crypto_stats` | Kripto istatistikleri |
| Tracing | `/sys/kernel/debug/tracing/events/vaultguard/` | 6 tracepoint |
| Netlink | `"vaultguard"` ailesi, `"vg_events"` grubu | Olay akışı |

---

## 🧪 Tracepoint'ler

```
vg_canary_trap       → Yetkisiz erişim denemesi (attacker_pid, owner_pid, deny_reason)
vg_secret_wiped      → Bellek imhası (reason_code, label)
vg_secret_stored     → Sır depolandı (owner_pid, owner_uid, label, ttl_sec)
vg_access_denied     → Erişim reddedildi (attacker_pid, attacker_uid, label, deny_reason)
vg_quarantine_toggle → Karantina durumu değişti (new_state, changed_by_pid)
vg_crypto_operation  → Kripto işlemi (op, success, label)
```

### bpftrace ile İzleme

```bash
# Tüm VaultGuard olaylarını izle
sudo bpftrace tools/vaultguard_monitor.bt

# Sadece ihlalleri izle
sudo bpftrace -e 'tracepoint:vaultguard:vg_canary_trap {
  printf("ALERT: PID %d sırrı çalmaya çalıştı!\n", args->attacker_pid);
}'
```

---

## 🔒 Güvenlik Modeli

### Zero-Trust İlkeleri
1. **Varsayılan Red** — Tüm erişimler varsayılan olarak reddedilir
2. **Çok Faktörlü Doğrulama** — PID, UID ve Namespace üçü birlikte doğrulanır
3. **Otomatik İmha** — TTL sonunda sıfır iz bırakmayan silme
4. **Şifreli Depolama** — Düz metin bellekte asla tutulmaz
5. **Denetim İzi** — Her olay tracepoint + Netlink ile loglanır

### Erişim Reddi Sebepleri

| Kod | Sebep |
|---|---|
| 1 | Karantina modu aktif |
| 2 | PID uyuşmazlığı |
| 3 | UID uyuşmazlığı |
| 4 | PID Namespace uyuşmazlığı |
| 5 | Sır bulunamadı |

### Yönetici Override
`CAP_SYS_ADMIN` yetkisine sahip süreçler (root dahil özel yetkili) tüm sırlara erişebilir. Bu durum da tracepoint + Netlink ile loglanır.

---

## 📝 Lisans

GPL v2 — Ayrıntılar için `SPDX-License-Identifier: GPL-2.0` başlıklarına bakın.
