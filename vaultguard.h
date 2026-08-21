/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vaultguard.h — VaultGuard Kernel Module Public API
 *
 * Shared between kernel module and userspace tools.
 * Provides IOCTL definitions, data structures, and constants.
 *
 * Author: Efe
 * License: GPLv2
 */

#ifndef VAULTGUARD_H
#define VAULTGUARD_H

#include <linux/ioctl.h>
#include <linux/types.h>

/* ────────────────────────────────────────────────────────────────── */
/*  Constants                                                          */
/* ────────────────────────────────────────────────────────────────── */

#define VAULT_MAGIC          'V'
#define SECRET_MAX_LEN       256
#define VAULT_LABEL_MAX_LEN  64
#define VAULT_MAX_SLOTS      64  /* Maksimum eşzamanlı sır slotu */
#define VAULT_DEFAULT_TTL    30  /* Varsayılan TTL: 30 saniye     */

/*
 * Şifreli veri alanı boyutu (AES-256-GCM):
 *   IV  (12 byte) + Ciphertext (SECRET_MAX_LEN) + Auth Tag (16 byte)
 */
#define VAULT_IV_LEN          12
#define VAULT_TAG_LEN         16
#define VAULT_ENC_BUF_LEN     (VAULT_IV_LEN + SECRET_MAX_LEN + VAULT_TAG_LEN)

/* Erişim reddi sebep kodları */
#define VAULT_DENY_QUARANTINE   1  /* Karantina modu aktif         */
#define VAULT_DENY_PID          2  /* PID eşleşmedi                */
#define VAULT_DENY_UID          3  /* UID eşleşmedi                */
#define VAULT_DENY_NAMESPACE    4  /* PID namespace eşleşmedi      */
#define VAULT_DENY_NOT_FOUND    5  /* Etiket bulunamadı            */

/* ────────────────────────────────────────────────────────────────── */
/*  Userspace ↔ Kernel Veri Yapısı                                    */
/* ────────────────────────────────────────────────────────────────── */

/**
 * struct vault_user_request - IOCTL üzerinden geçirilen istek paketi
 *
 * @label:   Sırın benzersiz etiketi (null-terminate edilmiş string)
 * @data:    Saklanacak veya okunacak ham veri
 * @data_len: Verinin gerçek byte uzunluğu
 * @ttl_sec: Time-To-Live süresi (saniye). 0 → varsayılan kullan.
 */
struct vault_user_request {
    char          label[VAULT_LABEL_MAX_LEN];
    char          data[SECRET_MAX_LEN];
    __u32         data_len;
    __u64         ttl_sec;
};

/**
 * struct vault_list_entry - LIST_LABELS ioctl dönüş elemanı
 *
 * @label:       Sır etiketi
 * @remaining_ttl: Kalan TTL (saniye). -1 → sonsuz.
 */
struct vault_list_entry {
    char  label[VAULT_LABEL_MAX_LEN];
    __s64 remaining_ttl;
};

/* LIST_LABELS ioctl'inin doldurduğu buffer yapısı */
struct vault_list_response {
    __u32               count;
    struct vault_list_entry entries[VAULT_MAX_SLOTS];
};

/* ────────────────────────────────────────────────────────────────── */
/*  IOCTL Komutları                                                    */
/* ────────────────────────────────────────────────────────────────── */

/*
 * Eski (geriye dönük uyumluluk için korundu):
 *   VAULT_IOC_STORE_SECRET — tek slotlu miras depolama
 *   VAULT_IOC_GET_SECRET   — tek slotlu miras okuma
 */
#define VAULT_IOC_STORE_SECRET  _IOW(VAULT_MAGIC, 1, char *)
#define VAULT_IOC_GET_SECRET    _IOR(VAULT_MAGIC, 2, char *)

/*
 * Yeni çok-slotlu komutlar (vault_user_request yapısı kullanır):
 *   STORE_LABELED  — etiketli sır sakla (şifreli)
 *   GET_LABELED    — etikete göre sır getir (deşifreli)
 *   DELETE_LABELED — belirli sırrı güvenli sil
 *   LIST_LABELS    — mevcut etiketleri ve TTL'leri listele
 */
#define VAULT_IOC_STORE_LABELED  _IOW(VAULT_MAGIC, 3, struct vault_user_request)
#define VAULT_IOC_GET_LABELED    _IOWR(VAULT_MAGIC, 4, struct vault_user_request)
#define VAULT_IOC_DELETE_LABELED _IOW(VAULT_MAGIC, 5, struct vault_user_request)
#define VAULT_IOC_LIST_LABELS    _IOR(VAULT_MAGIC, 6, struct vault_list_response)

#endif /* VAULTGUARD_H */
