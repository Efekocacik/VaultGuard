# VaultGuard v2.0

> **Zero-Trust Kernel Secret Vault Engine** — Linux cekirdeginde calisan, AES-256-GCM sifreli, cok katmanli erisim kontrollu guvenlik modulu.

---

## Nedir?

VaultGuard, hassas verileri (parola, API anahtari, ozel anahtar vb.) Linux cekirdek alaninda guvenle saklayan bir **Loadable Kernel Module (LKM)**'dur.

Sirlar:
- **AES-256-GCM** ile sifreli tutulur (duz metin bellekte asla yer almaz)
- **PID + UID + PID Namespace** uclu izolasyonuyla korunur
- **TTL** zamanlayicisiyla otomatik olarak kriptografik imha edilir
- **DSE Korumasi** (`memzero_explicit`) ile derleyici optimizasyonuna karsi korunur

---

## Ozellikler

| Ozellik | Aciklama |
|---|---|
| **AES-256-GCM** | Kernel Crypto API, donanim hizlandirmali |
| **Multi-Slot Vault** | 64'e kadar bagimsiz etiketli sir |
| **3 Katmanli ACL** | PID + UID + Namespace + CAP_SYS_ADMIN override |
| **TTL Zamanlayici** | Her slot icin bagimsiz, saniye hassasiyetli |
| **DSE Korumasi** | `memzero_explicit()` tum kritik temizliklerde |
| **6 eBPF Tracepoint** | Her olay icin ftrace + eBPF kancasi |
| **Generic Netlink** | Cok dinleyicili SIEM olay akisi |
| **FASYNC Sinyal** | Geriye donuk uyumluluk (SIGIO) |
| **goto-chain Hata Yonetimi** | Kaynak sizintisiz init/exit |
| **procfs Telemetri** | `/proc/vaultguard` |
| **debugfs Arayuzu** | `force_purge`, `crypto_stats` |
| **sysfs Attribute** | `active_ttl`, `quarantine_status`, `canary_count` |

---

## Proje Yapisi

```
vaultguard_project/
├── vaultguard.c          # Ana kernel modulu (v2.0)
├── vaultguard.h          # Paylasilan API tanimlari (IOCTL, struct)
├── vaultguard_trace.h    # 6 eBPF/Ftrace tracepoint tanimi
├── vaultguard_netlink.h  # Generic Netlink protokol tanimlari
├── vault_test.c          # Entegrasyon test programi
├── Makefile              # Derleme, kurulum, test otomasyonu
└── tools/
    ├── vaultctl.c        # Kullanici alani yonetim CLI'i
    └── vaultguard_monitor.bt  # bpftrace gercek zamanli izleyici
```

---

## Hizli Baslangic

### 1. Derleme

```bash
make
```

### 2. Kurulum

```bash
sudo make install
```

Bu komut:
- Modulu yukler (`insmod`)
- Tracepoint'leri etkinlestirir
- Aygit izinlerini ayarlar

### 3. Kullanim

```bash
# Sir depola (300 saniyelik TTL ile)
sudo vaultctl store --label db_pass --data 'Passw0rd!' --ttl 300

# Sir oku
sudo vaultctl get --label db_pass

# Tum sirlari listele
sudo vaultctl list

# Guvenlik durumu
sudo vaultctl status

# Gercek zamanli izleme (Ctrl+C ile cik)
sudo vaultctl monitor

# PID izolasyon testi
sudo vaultctl forktest --label test_key --data 'secret'

# Acil durum imhasi
sudo vaultctl purge --force
```

### 4. Test

```bash
sudo make test
```

---

## Guvenlik Mimarisi

```
+---------------------------------------------------------+
|                     USER SPACE                          |
|  vaultctl CLI   |  SIEM Agent   |  bpftrace Monitor     |
+--------+--------+------+--------+------+----------------+
         | IOCTL         | Netlink       | Tracepoints
+--------v---------------v---------------v----------------+
|                   KERNEL SPACE                          |
|                                                         |
|  +-------------------------------------------------+    |
|  │              ACL Katmanlari                     │    |
|  │  Karantina -> CAP_SYS_ADMIN -> UID -> NS -> PID │    |
|  +----------------------┬--------------------------+    |
|                         |                               |
|  +----------------------v--------------------------+    |
|  │          AES-256-GCM Sifreleme                  │    |
|  │   [IV:12B][Ciphertext:256B][Auth Tag:16B]       │    |
|  +----------------------┬--------------------------+    |
|                         |                               |
|  +----------------------v--------------------------+    |
|  │   Hashtable Vault (64 slot, TTL zamanlayicili)  │    |
|  +-------------------------------------------------+    |
+---------------------------------------------------------+
```

---

## IOCTL API Referansi

| Komut | Yon | Aciklama |
|---|---|---|
| `VAULT_IOC_STORE_SECRET` | Write | Miras: tek-slot depolama |
| `VAULT_IOC_GET_SECRET`   | Read  | Miras: tek-slot okuma |
| `VAULT_IOC_STORE_LABELED`  | Write | Etiketli sir depola |
| `VAULT_IOC_GET_LABELED`    | R/W   | Etiketli sir oku |
| `VAULT_IOC_DELETE_LABELED` | Write | Etiketli sir sil |
| `VAULT_IOC_LIST_LABELS`    | Read  | Tum etiketleri listele |

---

## Kernel Arayuzleri

| Arayuz | Yol | Aciklama |
|---|---|---|
| Karakter Aygiti | `/dev/vaultguard_dev` | IOCTL islemleri |
| procfs | `/proc/vaultguard` | Guvenlik telemetrisi |
| sysfs | `/sys/.../active_ttl` | TTL yapilandirmasi |
| sysfs | `/sys/.../quarantine_status` | Karantina kontrolu |
| sysfs | `/sys/.../canary_count` | Ihlal sayaci |
| debugfs | `/sys/kernel/debug/vaultguard/force_purge` | Acil imha |
| debugfs | `/sys/kernel/debug/vaultguard/crypto_stats` | Kripto istatistikleri |
| Tracing | `/sys/kernel/debug/tracing/events/vaultguard/` | 6 tracepoint |
| Netlink | `"vaultguard"` ailesi, `"vg_events"` grubu | Olay akisi |

---

## Tracepoint'ler

```
vg_canary_trap       -> Yetkisiz erisim denemesi (attacker_pid, owner_pid, deny_reason)
vg_secret_wiped      -> Bellek imhasi (reason_code, label)
vg_secret_stored     -> Sir depolandi (owner_pid, owner_uid, label, ttl_sec)
vg_access_denied     -> Erisim reddedildi (attacker_pid, attacker_uid, label, deny_reason)
vg_quarantine_toggle -> Karantina durumu degisti (new_state, changed_by_pid)
vg_crypto_operation  -> Kripto islemi (op, success, label)
```

### bpftrace ile Izleme

```bash
# Tum VaultGuard olaylarini izle
sudo bpftrace tools/vaultguard_monitor.bt

# Sadece ihlalleri izle
sudo bpftrace -e 'tracepoint:vaultguard:vg_canary_trap {
  printf("ALERT: PID %d sirri calmaya calisti!\n", args->attacker_pid);
}'
```

---

## Guvenlik Modeli

### Zero-Trust Ilkeleri
1. **Varsayilan Red** — Tum erisimler varsayilan olarak reddedilir
2. **Cok Faktorlu Dogrulama** — PID, UID ve Namespace ucu birlikte dogrulanir
3. **Otomatik Imha** — TTL sonunda sifir iz birakmayan silme
4. **Sifreli Depolama** — Duz metin bellekte asla tutulmaz
5. **Denetim Izi** — Her olay tracepoint + Netlink ile loglanir

### Erisim Reddi Sebepleri

| Kod | Sebep |
|---|---|
| 1 | Karantina modu aktif |
| 2 | PID uyusmazligi |
| 3 | UID uyusmazligi |
| 4 | PID Namespace uyusmazligi |
| 5 | Sir bulunamadi |

### Yonetici Override
`CAP_SYS_ADMIN` yetkisine sahip surecler (root dahil ozel yetkili) tum sirlara erisebilir. Bu durum da tracepoint + Netlink ile loglanir.

---

## Lisans

GPL v2 — Ayrintilar icin `SPDX-License-Identifier: GPL-2.0` basliklarina bakin.
