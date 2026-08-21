// SPDX-License-Identifier: GPL-2.0
/*
 * vaultguard.c — Zero-Trust Kernel Secret Vault Engine
 *
 * Özellikler:
 *   - AES-256-GCM şifreli bellek depolama (Kernel Crypto API)
 *   - Multi-slot vault (hashtable tabanlı, 64 eşzamanlı sır)
 *   - Çok katmanlı ACL: PID + UID + PID Namespace + CAP_SYS_ADMIN
 *   - Bağımsız slot TTL zamanlayıcıları (otomatik kriptografik imha)
 *   - DSE koruması (memzero_explicit, derleyici optimizasyonu engeli)
 *   - 6 adet eBPF/Ftrace tracepoint kancası
 *   - Generic Netlink olay akışı (SIEM/çoklu dinleyici desteği)
 *   - FASYNC sinyal bildirimi (geriye dönük uyumluluk)
 *   - Sysfs, procfs, debugfs arayüzleri
 *   - Kapsamlı hata yönetimi (goto-chain pattern)
 *
 * Arayüzler:
 *   /dev/vaultguard_dev         — IOCTL karakter aygıtı
 *   /proc/vaultguard            — Güvenlik telemetrisi
 *   /sys/kernel/debug/vaultguard/ — force_purge, crypto_stats
 *   sysfs attributes            — active_ttl, quarantine_status
 *
 * Author: Efe
 * License: GPLv2
 */

/* eBPF ve Ftrace tracepoint'leri EN ÜSTTE tanımlanmalı */
#define CREATE_TRACE_POINTS
#include "vaultguard_trace.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/workqueue.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/pid_namespace.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/completion.h>
#include <crypto/aead.h>
#include <net/genetlink.h>

#include "vaultguard.h"
#include "vaultguard_netlink.h"

#define DRIVER_NAME "vaultguard"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Efe");
MODULE_DESCRIPTION(
    "Zero-Trust Kernel Secret Vault: AES-GCM, Multi-Slot, "
    "Multi-Layer ACL, eBPF Tracepoints, Generic Netlink");
MODULE_VERSION("2.0");

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 1: Veri Yapıları
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * struct vault_entry - Hashtable'da saklanan bir sır slotu
 *
 * @label:         Sırın benzersiz etiketi
 * @enc_buf:       IV + Şifreli veri + Auth tag
 * @enc_len:       Şifreli verinin toplam uzunluğu (IV + CT + Tag)
 * @plain_len:     Orijinal düz metin uzunluğu (deşifre için gerekli)
 * @owner_pid:     Sırı yazan sürecin PID'i
 * @owner_uid:     Sırı yazan sürecin UID'i
 * @owner_ns_inum: Sırı yazan sürecin PID namespace inode numarası
 * @created_at:    Oluşturulma zamanı (ktime_t)
 * @ttl_sec:       Bu slotun TTL süresi (saniye)
 * @dwork:         Slot'a özel delayed_work (process context'te güvenli imha)
 * @node:          Hashtable bağlantı düğümü
 */
struct vault_entry {
    char                label[VAULT_LABEL_MAX_LEN];
    u8                  enc_buf[VAULT_ENC_BUF_LEN];
    int                 enc_len;
    int                 plain_len;
    pid_t               owner_pid;
    kuid_t              owner_uid;
    unsigned int        owner_ns_inum;
    ktime_t             created_at;
    unsigned long       ttl_sec;
    struct delayed_work dwork;
    struct hlist_node   node;
};

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 2: Global Durum
 * ═══════════════════════════════════════════════════════════════════ */

/* Hashtable: 2^8 = 256 bucket (birden fazla label → farklı bucket'a dağılır) */
static DEFINE_HASHTABLE(vault_ht, 8);

/* Tüm vault operasyonlarını koruyan okuma-yazma kilidi */
static DECLARE_RWSEM(vault_rwsem);

/* İstatistik sayaçları (lock-free) */
static atomic64_t canary_alerts   = ATOMIC64_INIT(0);
static atomic64_t active_secrets  = ATOMIC64_INIT(0);
static atomic64_t total_stored    = ATOMIC64_INIT(0);
static atomic64_t total_purged    = ATOMIC64_INIT(0);
static atomic64_t crypto_errors   = ATOMIC64_INIT(0);

/* Global konfigürasyon */
static unsigned long default_ttl_sec = VAULT_DEFAULT_TTL;
static int quarantine_mode           = 0;

/* Karakter aygıtı nesneleri */
static dev_t              dev_num;
static struct cdev        vault_cdev;
static struct class      *vault_class  = NULL;
static struct device     *vault_device = NULL;

/* Filesystem arayüz nesneleri */
static struct proc_dir_entry *proc_entry = NULL;
static struct dentry         *debug_dir  = NULL;

/* FASYNC kuyruğu (geriye dönük uyumluluk) */
static struct fasync_struct *async_queue;

/* AES-256-GCM şifreleme dönüştürücüsü */
static struct crypto_aead *vault_tfm = NULL;

/* AES-256 anahtarı: modül yüklenirken get_random_bytes() ile üretilir,
 * yalnızca çekirdek belleğinde tutulur, asla dışarıya çıkmaz. */
static u8 vault_aes_key[32];

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 3: Generic Netlink Tanımları
 * ═══════════════════════════════════════════════════════════════════ */

/* Politika: her attribute'un beklenen tipi */
static const struct nla_policy vg_genl_policy[VG_ATTR_MAX + 1] = {
    [VG_ATTR_EVENT_TYPE]    = { .type = NLA_U32  },
    [VG_ATTR_TIMESTAMP_NS]  = { .type = NLA_U64  },
    [VG_ATTR_PID]           = { .type = NLA_U32  },
    [VG_ATTR_UID]           = { .type = NLA_U32  },
    [VG_ATTR_LABEL]         = { .type = NLA_STRING, .len = VAULT_LABEL_MAX_LEN },
    [VG_ATTR_DENY_REASON]   = { .type = NLA_U32  },
    [VG_ATTR_TTL_REMAINING] = { .type = NLA_S64  },
};

/* VG_CMD_EVENT — userspace sadece dinler, çekirdek gönderir */
static const struct genl_ops vg_genl_ops[] = {
    /* Bu boş; tüm iletişim çekirdek → userspace yönündedir. */
};

static const struct genl_multicast_group vg_genl_mcgrps[] = {
    { .name = VG_GENL_MCAST_GROUP },
};

static struct genl_family vg_genl_family = {
    .name       = VG_GENL_NAME,
    .version    = VG_GENL_VERSION,
    .maxattr    = VG_ATTR_MAX,
    .policy     = vg_genl_policy,
    .ops        = vg_genl_ops,
    .n_ops      = ARRAY_SIZE(vg_genl_ops),
    .mcgrps     = vg_genl_mcgrps,
    .n_mcgrps   = ARRAY_SIZE(vg_genl_mcgrps),
    .module     = THIS_MODULE,
};

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 4: Generic Netlink Olay Yayıncısı
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * vg_netlink_send_event() - Tüm dinleyicilere güvenlik olayı gönder
 *
 * GFP_ATOMIC ile çağrılabilir (timer callback'lerden ve spinlock
 * bölgelerinden güvenli kullanım için).
 *
 * @event_type:  enum vg_event_type değeri
 * @pid:         İlgili sürecin PID'i (yoksa 0)
 * @uid_val:     İlgili sürecin UID'i (yoksa 0)
 * @label:       İlgili sır etiketi (yoksa NULL veya "")
 * @deny_reason: Erişim red sebebi kodu (geçerliyse)
 */
static void vg_netlink_send_event(enum vg_event_type event_type,
                                  pid_t pid, uid_t uid_val,
                                  const char *label, int deny_reason)
{
    struct sk_buff *skb;
    void *hdr;
    int ret;

    skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
    if (!skb)
        return;

    hdr = genlmsg_put(skb, 0, 0, &vg_genl_family, 0, VG_CMD_EVENT);
    if (!hdr)
        goto err_free;

    if (nla_put_u32(skb, VG_ATTR_EVENT_TYPE,   (u32)event_type)          ||
        nla_put_u64_64bit(skb, VG_ATTR_TIMESTAMP_NS,
                          (u64)ktime_get_real_ns(), VG_ATTR_UNSPEC)       ||
        nla_put_u32(skb, VG_ATTR_PID,           (u32)pid)                 ||
        nla_put_u32(skb, VG_ATTR_UID,           uid_val)                  ||
        nla_put_u32(skb, VG_ATTR_DENY_REASON,   (u32)deny_reason))
        goto err_cancel;

    if (label && label[0] != '\0')
        if (nla_put_string(skb, VG_ATTR_LABEL, label))
            goto err_cancel;

    genlmsg_end(skb, hdr);

    ret = genlmsg_multicast(&vg_genl_family, skb, 0, 0, GFP_ATOMIC);
    /* -ESRCH: Dinleyici yok — normal durum, hata sayma */
    if (ret && ret != -ESRCH)
        pr_debug("VaultGuard: netlink multicast hata: %d\n", ret);
    return;

err_cancel:
    genlmsg_cancel(skb, hdr);
err_free:
    nlmsg_free(skb);
}

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 5: AES-256-GCM Şifreleme / Çözme
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * vault_encrypt() - Düz metni AES-256-GCM ile şifrele
 *
 * Çıktı formatı (enc_buf içinde):
 *   [IV: 12 byte][Ciphertext: plain_len byte][Auth Tag: 16 byte]
 *
 * @plaintext:  Şifrelenecek veri
 * @plain_len:  Verinin byte uzunluğu
 * @enc_buf:    Çıktı tamponu (boyutu >= VAULT_IV_LEN + plain_len + VAULT_TAG_LEN)
 * @enc_len:    Çıktı: toplam yazılan byte sayısı
 *
 * Döndürür: 0 başarı, negatif hata kodu
 */
static int vault_encrypt(const u8 *plaintext, int plain_len,
                         u8 *enc_buf, int *enc_len)
{
    struct aead_request *req;
    struct scatterlist   sg[2];
    DECLARE_CRYPTO_WAIT(wait);
    u8  *iv        = enc_buf;                    /* enc_buf[0..11]   */
    u8  *ct_start  = enc_buf + VAULT_IV_LEN;     /* enc_buf[12..]    */
    u8  *work_buf;
    int  ret;

    /* Her şifreleme için rastgele IV üret (nonce reuse = ölümcül) */
    get_random_bytes(iv, VAULT_IV_LEN);

    /*
     * AES-GCM için çalışma tamponu: plaintext + tag alanı birlikte.
     * Kernel crypto API, şifreleme sonrası tag'i ciphertext'in ardına ekler.
     */
    work_buf = kmalloc(plain_len + VAULT_TAG_LEN, GFP_KERNEL);
    if (!work_buf)
        return -ENOMEM;

    memcpy(work_buf, plaintext, plain_len);
    memset(work_buf + plain_len, 0, VAULT_TAG_LEN);

    req = aead_request_alloc(vault_tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto out_free_buf;
    }

    sg_init_one(&sg[0], work_buf, plain_len + VAULT_TAG_LEN);

    aead_request_set_crypt(req, sg, sg, plain_len, iv);
    aead_request_set_ad(req, 0); /* Associated data kullanmıyoruz */
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP,
                              crypto_req_done, &wait);

    ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);
    if (ret == 0) {
        /* work_buf'a IV haricindeki kısmı (CT+Tag) kopyala */
        memcpy(ct_start, work_buf, plain_len + VAULT_TAG_LEN);
        *enc_len = VAULT_IV_LEN + plain_len + VAULT_TAG_LEN;
    }

    aead_request_free(req);

out_free_buf:
    memzero_explicit(work_buf, plain_len + VAULT_TAG_LEN);
    kfree(work_buf);
    return ret;
}

/**
 * vault_decrypt() - AES-256-GCM ile şifrelenmiş veriyi çöz
 *
 * @enc_buf:    IV + Ciphertext + Auth Tag içeren tampon
 * @plain_len:  Beklenen düz metin uzunluğu
 * @plaintext:  Çözülen verinin yazılacağı tampon (boyutu >= plain_len)
 *
 * Döndürür: 0 başarı, -EBADMSG auth tag doğrulaması başarısız,
 *           diğer negatifler: teknik hatalar
 */
static int vault_decrypt(const u8 *enc_buf, int plain_len, u8 *plaintext)
{
    struct aead_request *req;
    struct scatterlist   sg;
    DECLARE_CRYPTO_WAIT(wait);
    const u8 *iv       = enc_buf;
    const u8 *ct_start = enc_buf + VAULT_IV_LEN;
    u8  *work_buf;
    int  ct_len = plain_len + VAULT_TAG_LEN;
    int  ret;

    work_buf = kmalloc(ct_len, GFP_KERNEL);
    if (!work_buf)
        return -ENOMEM;

    memcpy(work_buf, ct_start, ct_len);

    req = aead_request_alloc(vault_tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto out_free_buf;
    }

    sg_init_one(&sg, work_buf, ct_len);

    aead_request_set_crypt(req, &sg, &sg, ct_len, (u8 *)iv);
    aead_request_set_ad(req, 0);
    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP,
                              crypto_req_done, &wait);

    ret = crypto_wait_req(crypto_aead_decrypt(req), &wait);
    if (ret == 0)
        memcpy(plaintext, work_buf, plain_len);
    else if (ret == -EBADMSG)
        pr_warn("VaultGuard: Auth tag doğrulaması BAŞARISIZ — veri bütünlüğü ihlali!\n");

    aead_request_free(req);

out_free_buf:
    memzero_explicit(work_buf, ct_len);
    kfree(work_buf);
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 6: Hashtable Yardımcıları
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * vault_find_entry() - Etiket ile slot bul
 *
 * vault_rwsem ile korunmalı (read veya write lock altında çağrılmalı).
 *
 * @label: Aranacak etiket
 * Döndürür: vault_entry işaretçisi veya NULL
 */
static struct vault_entry *vault_find_entry(const char *label)
{
    struct vault_entry *entry;
    u32 key = jhash(label, strnlen(label, VAULT_LABEL_MAX_LEN - 1), 0);

    hash_for_each_possible(vault_ht, entry, node, key) {
        if (strncmp(entry->label, label, VAULT_LABEL_MAX_LEN) == 0)
            return entry;
    }
    return NULL;
}

/**
 * vault_destroy_entry() - Slotu güvenle yok et ve bellekten temizle
 *
 * vault_rwsem write lock altında çağrılmalı.
 * Timer zaten iptal edilmiş olmalı (timer_delete_sync önceden çağrılmış).
 *
 * @entry: Silinecek slot
 * @reason_code: Tracepoint için silme sebebi (1=TTL, 2=Purge, 3=Manuel)
 */
static void vault_destroy_entry(struct vault_entry *entry, int reason_code)
{
    char label_copy[VAULT_LABEL_MAX_LEN];

    /* Label kopyası: bellek temizlenmeden önce tracepoint için */
    strlcpy(label_copy, entry->label, VAULT_LABEL_MAX_LEN);

    /* Şifreli belleği fiziksel olarak sıfırla (DSE koruması) */
    memzero_explicit(entry->enc_buf, VAULT_ENC_BUF_LEN);
    memzero_explicit(entry->label,   VAULT_LABEL_MAX_LEN);

    hash_del(&entry->node);
    kfree(entry);
    atomic64_dec(&active_secrets);
    atomic64_inc(&total_purged);

    trace_vg_secret_wiped(reason_code, label_copy);
    pr_info("VaultGuard: Sır imha edildi. Etiket='%s' Sebep=%d\n",
            label_copy, reason_code);
}

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 7: TTL Delayed Work Callback (Process Context - Panic Free)
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * vault_slot_work_cb() - TTL süresi dolan slot'u yok et
 *
 * kworker iş parçacığında (Process Context) çalışır.
 * down_write(&vault_rwsem) kilidini GÜVENLE (panic üretmeden) alabilir.
 */
static void vault_slot_work_cb(struct work_struct *work)
{
    struct delayed_work *dwork = to_delayed_work(work);
    struct vault_entry  *entry = container_of(dwork, struct vault_entry, dwork);
    char label_copy[VAULT_LABEL_MAX_LEN];

    down_write(&vault_rwsem);
    strlcpy(label_copy, entry->label, VAULT_LABEL_MAX_LEN);
    vault_destroy_entry(entry, 1 /* TTL doldu */);
    up_write(&vault_rwsem);

    /* Netlink olay bildirimi */
    vg_netlink_send_event(VG_EVENT_SECRET_EXPIRED, 0, 0, label_copy, 0);

    /* FASYNC bildirimi (geriye dönük uyumluluk) */
    if (async_queue)
        kill_fasync(&async_queue, SIGIO, POLL_IN);

    pr_info("VaultGuard: TTL doldu. Etiket='%s'\n", label_copy);
}

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 8: Çok Katmanlı ACL Doğrulaması
 * ═══════════════════════════════════════════════════════════════════ */

/**
 * vault_check_access() - Erişim kontrolü yap
 *
 * Doğrulama sırası:
 *   1. Karantina modu — herkese reddedilir (admin bile)
 *   2. CAP_SYS_ADMIN — bu yetkiye sahip süreçler her şeye erişir
 *   3. UID doğrulaması
 *   4. PID Namespace doğrulaması
 *   5. PID doğrulaması
 *
 * vault_rwsem read lock altında çağrılmalı.
 *
 * @entry: Erişilmek istenen slot
 * Döndürür: 0 erişim onaylandı, negatif hata kodu + VAULT_DENY_* reason
 */
static int vault_check_access(const struct vault_entry *entry, int *deny_reason)
{
    const struct cred *cred = current_cred();
    unsigned int cur_ns_inum;

    /* Katman 0: Karantina modu */
    if (quarantine_mode) {
        *deny_reason = VAULT_DENY_QUARANTINE;
        return -EACCES;
    }

    /* Katman 1: Admin override — CAP_SYS_ADMIN her şeyi geçer */
    if (capable(CAP_SYS_ADMIN))
        return 0;

    /* Katman 2: UID kontrolü */
    if (!uid_eq(cred->uid, entry->owner_uid)) {
        *deny_reason = VAULT_DENY_UID;
        return -EACCES;
    }

    /* Katman 3: PID Namespace kontrolü (konteyner izolasyonu) */
    cur_ns_inum = task_active_pid_ns(current)->ns.inum;
    if (cur_ns_inum != entry->owner_ns_inum) {
        *deny_reason = VAULT_DENY_NAMESPACE;
        return -EACCES;
    }

    /* Katman 4: PID kontrolü */
    if (current->pid != entry->owner_pid) {
        *deny_reason = VAULT_DENY_PID;
        return -EACCES;
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 9: IOCTL İşleyicileri (Yardımcılar)
 * ═══════════════════════════════════════════════════════════════════ */

/* --- store_labeled: yeni/güncelleme sır kaydet --- */
static long vault_ioctl_store_labeled(unsigned long arg)
{
    struct vault_user_request *ureq;
    struct vault_entry        *entry, *old_entry;
    u8   plain_buf[SECRET_MAX_LEN];
    int  enc_len = 0;
    int  ret = 0;
    u32  key;

    ureq = kmalloc(sizeof(*ureq), GFP_KERNEL);
    if (!ureq)
        return -ENOMEM;

    if (copy_from_user(ureq, (void __user *)arg, sizeof(*ureq))) {
        ret = -EFAULT;
        goto out_free_req;
    }

    /* Null-terminate güvencesi */
    ureq->label[VAULT_LABEL_MAX_LEN - 1] = '\0';
    ureq->data[SECRET_MAX_LEN - 1]       = '\0';
    if (ureq->data_len > SECRET_MAX_LEN - 1)
        ureq->data_len = SECRET_MAX_LEN - 1;

    /* Geçici düz metin tamponu */
    memcpy(plain_buf, ureq->data, ureq->data_len);
    plain_buf[ureq->data_len] = '\0';

    /* Şifrele */
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        ret = -ENOMEM;
        goto out_zero_plain;
    }

    ret = vault_encrypt(plain_buf, ureq->data_len,
                        entry->enc_buf, &enc_len);

    trace_vg_crypto_operation(0 /* encrypt */,
                              ret == 0 ? 1 : 0,
                              ureq->label);
    if (ret) {
        atomic64_inc(&crypto_errors);
        kfree(entry);
        goto out_zero_plain;
    }

    /* Slot meta verisi doldur */
    strlcpy(entry->label, ureq->label, VAULT_LABEL_MAX_LEN);
    entry->enc_len      = enc_len;
    entry->plain_len    = (int)ureq->data_len;
    entry->owner_pid    = current->pid;
    entry->owner_uid    = current_uid();
    entry->owner_ns_inum = task_active_pid_ns(current)->ns.inum;
    entry->created_at   = ktime_get_real();
    entry->ttl_sec      = (ureq->ttl_sec > 0) ? ureq->ttl_sec : default_ttl_sec;

    INIT_DELAYED_WORK(&entry->dwork, vault_slot_work_cb);

    down_write(&vault_rwsem);

    /* Aynı etikette eski slot varsa güvenle yok et */
    old_entry = vault_find_entry(ureq->label);
    if (old_entry) {
        cancel_delayed_work(&old_entry->dwork);
        vault_destroy_entry(old_entry, 3 /* Manuel/güncelleme */);
    }

    /* Hashtable'a ekle ve zamanlayıcıyı başlat */
    key = jhash(entry->label,
                strnlen(entry->label, VAULT_LABEL_MAX_LEN - 1), 0);
    hash_add(vault_ht, &entry->node, key);
    schedule_delayed_work(&entry->dwork,
                          msecs_to_jiffies(entry->ttl_sec * 1000));
    atomic64_inc(&active_secrets);
    atomic64_inc(&total_stored);

    up_write(&vault_rwsem);

    /* Tracepoint + Netlink bildirimleri */
    trace_vg_secret_stored(current->pid,
                           from_kuid_munged(current_user_ns(),
                                            current_uid()),
                           ureq->label, entry->ttl_sec);
    vg_netlink_send_event(VG_EVENT_SECRET_STORED, current->pid,
                          from_kuid_munged(current_user_ns(),
                                           current_uid()),
                          ureq->label, 0);

    pr_info("VaultGuard: Sır depolandı. Etiket='%s' PID=%d TTL=%lus\n",
            ureq->label, current->pid, entry->ttl_sec);

out_zero_plain:
    memzero_explicit(plain_buf, sizeof(plain_buf));
    memzero_explicit(ureq->data, SECRET_MAX_LEN);
out_free_req:
    kfree(ureq);
    return ret;
}

/* --- get_labeled: etikete göre sır oku --- */
static long vault_ioctl_get_labeled(unsigned long arg)
{
    struct vault_user_request *ureq;
    struct vault_entry        *entry;
    u8    plain_buf[SECRET_MAX_LEN];
    int   deny_reason = 0;
    int   ret = 0;

    ureq = kmalloc(sizeof(*ureq), GFP_KERNEL);
    if (!ureq)
        return -ENOMEM;

    if (copy_from_user(ureq, (void __user *)arg, sizeof(*ureq))) {
        ret = -EFAULT;
        goto out_free;
    }
    ureq->label[VAULT_LABEL_MAX_LEN - 1] = '\0';
    memset(ureq->data, 0, SECRET_MAX_LEN);

    down_read(&vault_rwsem);

    entry = vault_find_entry(ureq->label);
    if (!entry) {
        deny_reason = VAULT_DENY_NOT_FOUND;
        ret = -ENOENT;
        up_read(&vault_rwsem);
        goto out_free;
    }

    ret = vault_check_access(entry, &deny_reason);
    if (ret) {
        /* ACL başarısız — sayaçlar ve bildirimler */
        atomic64_inc(&canary_alerts);

        sysfs_notify(&vault_device->kobj, NULL, "quarantine_status");
        if (async_queue)
            kill_fasync(&async_queue, SIGIO, POLL_IN);

        trace_vg_canary_trap(current->pid, entry->owner_pid,
                             deny_reason);
        trace_vg_access_denied(current->pid,
                               from_kuid_munged(current_user_ns(),
                                                current_uid()),
                               ureq->label, deny_reason);

        pr_warn("VaultGuard: Erişim REDDEDİLDİ. PID=%d Etiket='%s' Sebep=%d\n",
                current->pid, ureq->label, deny_reason);

        up_read(&vault_rwsem);

        vg_netlink_send_event(VG_EVENT_ACCESS_DENIED, current->pid,
                              from_kuid_munged(current_user_ns(),
                                               current_uid()),
                              ureq->label, deny_reason);
        goto out_free;
    }

    /* Deşifre et */
    ret = vault_decrypt(entry->enc_buf, entry->plain_len, plain_buf);
    plain_buf[entry->plain_len] = '\0';

    up_read(&vault_rwsem);

    trace_vg_crypto_operation(1 /* decrypt */,
                              ret == 0 ? 1 : 0,
                              ureq->label);
    if (ret) {
        atomic64_inc(&crypto_errors);
        memzero_explicit(plain_buf, sizeof(plain_buf));
        goto out_free;
    }

    /* Kullanıcıya gönder */
    memcpy(ureq->data, plain_buf, entry->plain_len + 1);
    ureq->data_len = (u32)entry->plain_len;
    memzero_explicit(plain_buf, sizeof(plain_buf));

    if (copy_to_user((void __user *)arg, ureq, sizeof(*ureq)))
        ret = -EFAULT;

out_free:
    memzero_explicit(ureq, sizeof(*ureq));
    kfree(ureq);
    return ret;
}

/* --- delete_labeled: belirli sırrı güvenle sil --- */
static long vault_ioctl_delete_labeled(unsigned long arg)
{
    struct vault_user_request ureq;
    struct vault_entry       *entry;
    char   label_copy[VAULT_LABEL_MAX_LEN];
    int    deny_reason = 0;
    int    ret = 0;

    if (copy_from_user(&ureq, (void __user *)arg, sizeof(ureq)))
        return -EFAULT;
    ureq.label[VAULT_LABEL_MAX_LEN - 1] = '\0';
    strlcpy(label_copy, ureq.label, VAULT_LABEL_MAX_LEN);

    down_write(&vault_rwsem);
    entry = vault_find_entry(label_copy);
    if (!entry) {
        ret = -ENOENT;
        up_write(&vault_rwsem);
        return ret;
    }

    ret = vault_check_access(entry, &deny_reason);
    if (ret) {
        atomic64_inc(&canary_alerts);
        trace_vg_access_denied(current->pid,
                               from_kuid_munged(current_user_ns(),
                                                current_uid()),
                               label_copy, deny_reason);
        up_write(&vault_rwsem);
        vg_netlink_send_event(VG_EVENT_ACCESS_DENIED, current->pid,
                              from_kuid_munged(current_user_ns(),
                                               current_uid()),
                              label_copy, deny_reason);
        return ret;
    }

    cancel_delayed_work(&entry->dwork);
    vault_destroy_entry(entry, 3 /* Manuel silme */);
    up_write(&vault_rwsem);

    vg_netlink_send_event(VG_EVENT_SECRET_DELETED, current->pid,
                          from_kuid_munged(current_user_ns(),
                                           current_uid()),
                          label_copy, 0);
    return 0;
}

/* --- list_labels: mevcut tüm etiketleri listele --- */
static long vault_ioctl_list_labels(unsigned long arg)
{
    struct vault_list_response *resp;
    struct vault_entry         *entry;
    unsigned int bucket;
    int ret = 0;

    resp = kzalloc(sizeof(*resp), GFP_KERNEL);
    if (!resp)
        return -ENOMEM;

    down_read(&vault_rwsem);
    hash_for_each(vault_ht, bucket, entry, node) {
        if (resp->count >= VAULT_MAX_SLOTS)
            break;
        strlcpy(resp->entries[resp->count].label,
                entry->label, VAULT_LABEL_MAX_LEN);
        /* Kalan TTL = expires_at - now */
        {
            ktime_t expires = ktime_add(entry->created_at,
                                        ktime_set(entry->ttl_sec, 0));
            ktime_t now     = ktime_get_real();
            s64 rem         = ktime_to_ns(ktime_sub(expires, now));
            resp->entries[resp->count].remaining_ttl =
                (rem > 0) ? div_s64(rem, NSEC_PER_SEC) : 0;
        }
        resp->count++;
    }
    up_read(&vault_rwsem);

    if (copy_to_user((void __user *)arg, resp, sizeof(*resp)))
        ret = -EFAULT;

    kfree(resp);
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 10: IOCTL Ana İşleyicisi (Dispatcher)
 * ═══════════════════════════════════════════════════════════════════ */

static long vault_ioctl(struct file *filep, unsigned int cmd,
                        unsigned long arg)
{
    /* Miras IOCTL'ler (VAULT_IOC_STORE_SECRET / GET_SECRET):
     * Eski araçlarla geriye dönük uyumluluk için "legacy" etiketi
     * altında yeni altyapıya yönlendirilir.                         */
    if (cmd == VAULT_IOC_STORE_SECRET) {
        /* Miras: düz buffer → vault_user_request sarmalayıcı oluştur */
        struct vault_user_request legacy_req = {
            .label   = "_legacy_",
            .ttl_sec = 0,
        };
        if (copy_from_user(legacy_req.data, (char __user *)arg,
                           SECRET_MAX_LEN))
            return -EFAULT;
        legacy_req.data[SECRET_MAX_LEN - 1] = '\0';
        legacy_req.data_len = strnlen(legacy_req.data, SECRET_MAX_LEN - 1);
        {
            /* stack'te geçici req, arg olarak geçirmek için temp kullan */
            struct vault_user_request *tmp =
                kmemdup(&legacy_req, sizeof(legacy_req), GFP_KERNEL);
            long ret;
            if (!tmp) return -ENOMEM;
            memzero_explicit(&legacy_req, sizeof(legacy_req));
            /* Doğrudan kernel pointer ile çağır */
            {
                int enc_len = 0;
                struct vault_entry *entry, *old;
                u32 key;
                u8  plain_buf[SECRET_MAX_LEN];

                memcpy(plain_buf, tmp->data, tmp->data_len);
                entry = kzalloc(sizeof(*entry), GFP_KERNEL);
                if (!entry) {
                    kfree(tmp);
                    return -ENOMEM;
                }
                ret = vault_encrypt(plain_buf, tmp->data_len,
                                    entry->enc_buf, &enc_len);
                memzero_explicit(plain_buf, sizeof(plain_buf));

                if (ret) {
                    atomic64_inc(&crypto_errors);
                    kfree(entry);
                    kfree(tmp);
                    return ret;
                }
                strlcpy(entry->label, "_legacy_", VAULT_LABEL_MAX_LEN);
                entry->enc_len       = enc_len;
                entry->plain_len     = (int)tmp->data_len;
                entry->owner_pid     = current->pid;
                entry->owner_uid     = current_uid();
                entry->owner_ns_inum = task_active_pid_ns(current)->ns.inum;
                entry->created_at    = ktime_get_real();
                entry->ttl_sec       = default_ttl_sec;
                INIT_DELAYED_WORK(&entry->dwork, vault_slot_work_cb);

                down_write(&vault_rwsem);
                old = vault_find_entry("_legacy_");
                if (old) {
                    cancel_delayed_work(&old->dwork);
                    vault_destroy_entry(old, 3);
                }
                key = jhash("_legacy_", 8, 0);
                hash_add(vault_ht, &entry->node, key);
                schedule_delayed_work(&entry->dwork,
                                      msecs_to_jiffies(
                                          entry->ttl_sec * 1000));
                atomic64_inc(&active_secrets);
                atomic64_inc(&total_stored);
                up_write(&vault_rwsem);
                kfree(tmp);
                return 0;
            }
        }
    }

    if (cmd == VAULT_IOC_GET_SECRET) {
        /* Miras: _legacy_ etiketinden oku */
        struct vault_user_request ureq = {
            .label = "_legacy_",
        };
        struct vault_entry *entry;
        u8   plain_buf[SECRET_MAX_LEN];
        int  deny_reason = 0, ret;

        down_read(&vault_rwsem);
        entry = vault_find_entry("_legacy_");
        if (!entry) {
            up_read(&vault_rwsem);
            return -ENOENT;
        }
        ret = vault_check_access(entry, &deny_reason);
        if (ret) {
            atomic64_inc(&canary_alerts);
            trace_vg_canary_trap(current->pid, entry->owner_pid,
                                 deny_reason);
            if (async_queue)
                kill_fasync(&async_queue, SIGIO, POLL_IN);
            up_read(&vault_rwsem);
            vg_netlink_send_event(VG_EVENT_ACCESS_DENIED, current->pid,
                                  from_kuid_munged(current_user_ns(),
                                                   current_uid()),
                                  "_legacy_", deny_reason);
            return ret;
        }
        ret = vault_decrypt(entry->enc_buf, entry->plain_len, plain_buf);
        plain_buf[entry->plain_len] = '\0';
        up_read(&vault_rwsem);

        if (ret) {
            memzero_explicit(plain_buf, sizeof(plain_buf));
            return ret;
        }
        ret = copy_to_user((char __user *)arg, plain_buf,
                           strnlen(plain_buf, SECRET_MAX_LEN - 1) + 1)
              ? -EFAULT : 0;
        memzero_explicit(plain_buf, sizeof(plain_buf));
        return ret;
    }

    /* Yeni çok-slotlu IOCTL'ler */
    switch (cmd) {
    case VAULT_IOC_STORE_LABELED:
        return vault_ioctl_store_labeled(arg);
    case VAULT_IOC_GET_LABELED:
        return vault_ioctl_get_labeled(arg);
    case VAULT_IOC_DELETE_LABELED:
        return vault_ioctl_delete_labeled(arg);
    case VAULT_IOC_LIST_LABELS:
        return vault_ioctl_list_labels(arg);
    default:
        return -ENOTTY;
    }
}

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 11: Dosya Operasyonları
 * ═══════════════════════════════════════════════════════════════════ */

static int vault_fasync(int fd, struct file *filp, int mode)
{
    return fasync_helper(fd, filp, mode, &async_queue);
}

static int vault_release(struct inode *inode, struct file *filp)
{
    vault_fasync(-1, filp, 0);
    return 0;
}

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = vault_ioctl,
    .fasync         = vault_fasync,
    .release        = vault_release,
};

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 12: /proc/vaultguard Telemetri
 * ═══════════════════════════════════════════════════════════════════ */

static int vault_proc_show(struct seq_file *m, void *v)
{
    struct vault_entry *entry;
    unsigned int bucket;

    down_read(&vault_rwsem);
    seq_printf(m, "=== VaultGuard v2.0 Security Telemetry ===\n");
    seq_printf(m, "Quarantine Status  : %s\n",
               quarantine_mode ? "ACTIVE (LOCKDOWN)" : "SAFE");
    seq_printf(m, "Active Secrets     : %lld\n",
               atomic64_read(&active_secrets));
    seq_printf(m, "Total Stored       : %lld\n",
               atomic64_read(&total_stored));
    seq_printf(m, "Total Purged       : %lld\n",
               atomic64_read(&total_purged));
    seq_printf(m, "Canary Alerts      : %lld\n",
               atomic64_read(&canary_alerts));
    seq_printf(m, "Crypto Errors      : %lld\n",
               atomic64_read(&crypto_errors));
    seq_printf(m, "Default TTL (sec)  : %lu\n", default_ttl_sec);
    seq_printf(m, "\n--- Active Slots ---\n");

    hash_for_each(vault_ht, bucket, entry, node) {
        ktime_t expires = ktime_add(entry->created_at,
                                    ktime_set(entry->ttl_sec, 0));
        ktime_t now     = ktime_get_real();
        s64 rem         = ktime_to_ns(ktime_sub(expires, now));

        seq_printf(m, "  [%s]  PID=%-6d  UID=%-6u  Remaining=%llds\n",
                   entry->label,
                   entry->owner_pid,
                   from_kuid_munged(&init_user_ns, entry->owner_uid),
                   (rem > 0) ? div_s64(rem, NSEC_PER_SEC) : 0);
    }
    up_read(&vault_rwsem);
    return 0;
}

static int vault_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, vault_proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open    = vault_proc_open,
    .proc_read    = seq_read,
    .proc_release = single_release,
};

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 13: Sysfs Attribute'ları
 * ═══════════════════════════════════════════════════════════════════ */

static ssize_t active_ttl_show(struct device *dev,
                               struct device_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%lu\n", default_ttl_sec);
}

static ssize_t active_ttl_store(struct device *dev,
                                struct device_attribute *attr,
                                const char *buf, size_t count)
{
    unsigned long val;

    if (kstrtoul(buf, 10, &val) < 0 || val == 0)
        return -EINVAL;
    down_write(&vault_rwsem);
    default_ttl_sec = val;
    up_write(&vault_rwsem);
    return count;
}

static ssize_t quarantine_status_show(struct device *dev,
                                      struct device_attribute *attr,
                                      char *buf)
{
    return sysfs_emit(buf, "%d\n", quarantine_mode);
}

static ssize_t quarantine_status_store(struct device *dev,
                                       struct device_attribute *attr,
                                       const char *buf, size_t count)
{
    int val;

    if (kstrtoint(buf, 10, &val) < 0 || (val != 0 && val != 1))
        return -EINVAL;

    down_write(&vault_rwsem);
    quarantine_mode = val;
    up_write(&vault_rwsem);

    trace_vg_quarantine_toggle(val, current->pid);
    vg_netlink_send_event(val ? VG_EVENT_QUARANTINE_ON
                              : VG_EVENT_QUARANTINE_OFF,
                          current->pid,
                          from_kuid_munged(current_user_ns(),
                                           current_uid()),
                          NULL, 0);
    pr_warn("VaultGuard: Karantina modu %s (PID=%d)\n",
            val ? "ETKİNLEŞTİRİLDİ" : "DEVREdışı", current->pid);
    return count;
}

static ssize_t canary_count_show(struct device *dev,
                                  struct device_attribute *attr, char *buf)
{
    return sysfs_emit(buf, "%lld\n", atomic64_read(&canary_alerts));
}

static DEVICE_ATTR_RW(active_ttl);
static DEVICE_ATTR_RW(quarantine_status);
static DEVICE_ATTR_RO(canary_count);

static struct attribute *vault_attrs[] = {
    &dev_attr_active_ttl.attr,
    &dev_attr_quarantine_status.attr,
    &dev_attr_canary_count.attr,
    NULL
};
ATTRIBUTE_GROUPS(vault);

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 14: Debugfs İşleyicileri
 * ═══════════════════════════════════════════════════════════════════ */

/* force_purge: TÜM slotları acil durum imhası */
static ssize_t force_purge_write(struct file *file,
                                 const char __user *user_buf,
                                 size_t count, loff_t *ppos)
{
    struct vault_entry *entry;
    struct hlist_node  *tmp_node;
    unsigned int bucket;

    pr_emerg("VaultGuard: ACİL DURUM BELLEK İMHASI BAŞLATILDI!\n");

    down_write(&vault_rwsem);
    hash_for_each_safe(vault_ht, bucket, tmp_node, entry, node) {
        cancel_delayed_work(&entry->dwork);
        vault_destroy_entry(entry, 2 /* Acil imha */);
    }
    up_write(&vault_rwsem);

    vg_netlink_send_event(VG_EVENT_FORCE_PURGE, current->pid,
                          from_kuid_munged(current_user_ns(),
                                           current_uid()),
                          NULL, 0);
    if (async_queue)
        kill_fasync(&async_queue, SIGIO, POLL_IN);

    pr_emerg("VaultGuard: ACİL İMHA TAMAMLANDI. Tüm sırlar yok edildi.\n");
    return count;
}

static const struct file_operations purge_fops = {
    .owner = THIS_MODULE,
    .write = force_purge_write,
};

/* crypto_stats: Şifreleme istatistikleri */
static int crypto_stats_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Algorithm     : gcm(aes)\n");
    seq_printf(m, "Key size      : 256 bit\n");
    seq_printf(m, "IV size       : %d byte\n", VAULT_IV_LEN);
    seq_printf(m, "Tag size      : %d byte\n", VAULT_TAG_LEN);
    seq_printf(m, "Crypto Errors : %lld\n",
               atomic64_read(&crypto_errors));
    return 0;
}

static int crypto_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, crypto_stats_show, NULL);
}

static const struct file_operations crypto_stats_fops = {
    .owner   = THIS_MODULE,
    .open    = crypto_stats_open,
    .read    = seq_read,
    .release = single_release,
};

/* ═══════════════════════════════════════════════════════════════════
 *  BÖLÜM 15: Modül Init / Exit (goto-chain hata yönetimi)
 * ═══════════════════════════════════════════════════════════════════ */

static int __init vaultguard_init(void)
{
    int ret;

    pr_info("VaultGuard v2.0: Başlatılıyor...\n");

    /* 1. AES-256-GCM şifreleme altyapısını kur */
    vault_tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(vault_tfm)) {
        ret = PTR_ERR(vault_tfm);
        pr_err("VaultGuard: crypto_alloc_aead başarısız: %d\n", ret);
        vault_tfm = NULL;
        goto err_crypto_alloc;
    }

    /* AES anahtarını güvenli rastgele baytlarla doldur */
    get_random_bytes(vault_aes_key, sizeof(vault_aes_key));
    ret = crypto_aead_setkey(vault_tfm, vault_aes_key,
                             sizeof(vault_aes_key));
    if (ret) {
        pr_err("VaultGuard: AES anahtar ayarı başarısız: %d\n", ret);
        goto err_setkey;
    }

    ret = crypto_aead_setauthsize(vault_tfm, VAULT_TAG_LEN);
    if (ret) {
        pr_err("VaultGuard: Auth tag boyutu ayarı başarısız: %d\n", ret);
        goto err_setkey;
    }

    /* 2. Generic Netlink ailesini kaydet */
    ret = genl_register_family(&vg_genl_family);
    if (ret) {
        pr_err("VaultGuard: genl_register_family başarısız: %d\n", ret);
        goto err_setkey;
    }

    /* 3. Karakter aygıt numarasını tahsis et */
    ret = alloc_chrdev_region(&dev_num, 0, 1, DRIVER_NAME);
    if (ret < 0) {
        pr_err("VaultGuard: alloc_chrdev_region başarısız: %d\n", ret);
        goto err_chrdev;
    }

    /* 4. Karakter aygıtını başlat ve sisteme ekle */
    cdev_init(&vault_cdev, &fops);
    ret = cdev_add(&vault_cdev, dev_num, 1);
    if (ret < 0) {
        pr_err("VaultGuard: cdev_add başarısız: %d\n", ret);
        goto err_cdev;
    }

    /* 5. Aygıt sınıfı oluştur (Kernel sürüm uyumluluğu) */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    vault_class = class_create("vaultguard_class");
#else
    vault_class = class_create(THIS_MODULE, "vaultguard_class");
#endif
    if (IS_ERR(vault_class)) {
        ret = PTR_ERR(vault_class);
        pr_err("VaultGuard: class_create başarısız: %d\n", ret);
        goto err_class;
    }

    /* 6. Aygıt dosyasını oluştur (sysfs attribute gruplarıyla birlikte) */
    vault_device = device_create_with_groups(vault_class, NULL, dev_num,
                                             NULL, vault_groups,
                                             "vaultguard_dev");
    if (IS_ERR(vault_device)) {
        ret = PTR_ERR(vault_device);
        pr_err("VaultGuard: device_create başarısız: %d\n", ret);
        goto err_device;
    }

    /* 7. procfs girişi */
    proc_entry = proc_create(DRIVER_NAME, 0444, NULL, &proc_fops);
    if (!proc_entry) {
        ret = -ENOMEM;
        pr_err("VaultGuard: proc_create başarısız\n");
        goto err_proc;
    }

    /* 8. debugfs dizini ve dosyaları */
    debug_dir = debugfs_create_dir(DRIVER_NAME, NULL);
    if (IS_ERR_OR_NULL(debug_dir)) {
        ret = -ENOMEM;
        pr_err("VaultGuard: debugfs_create_dir başarısız\n");
        goto err_debugfs;
    }
    debugfs_create_file("force_purge", 0200, debug_dir, NULL, &purge_fops);
    debugfs_create_file("crypto_stats", 0444, debug_dir, NULL,
                        &crypto_stats_fops);

    /* 9. Hashtable'ı başlat */
    hash_init(vault_ht);

    pr_info("VaultGuard v2.0: Başarıyla yüklendi.\n");
    pr_info("  Algoritma   : AES-256-GCM\n");
    pr_info("  Max Slot    : %d\n", VAULT_MAX_SLOTS);
    pr_info("  Varsayılan TTL: %lu saniye\n", default_ttl_sec);
    pr_info("  Aygıt       : /dev/vaultguard_dev\n");
    pr_info("  Telemetri   : /proc/vaultguard\n");
    pr_info("  Netlink     : %s (grup: %s)\n",
            VG_GENL_NAME, VG_GENL_MCAST_GROUP);
    return 0;

    /* ─── Hata zinciri (her adım öncekinin tersini yapar) ─── */
err_debugfs:
    proc_remove(proc_entry);
err_proc:
    device_destroy(vault_class, dev_num);
err_device:
    class_destroy(vault_class);
err_class:
    cdev_del(&vault_cdev);
err_cdev:
    unregister_chrdev_region(dev_num, 1);
err_chrdev:
    genl_unregister_family(&vg_genl_family);
err_setkey:
    crypto_free_aead(vault_tfm);
    vault_tfm = NULL;
err_crypto_alloc:
    return ret;
}

static void __exit vaultguard_exit(void)
{
    struct vault_entry *entry;
    struct hlist_node  *tmp_node;
    unsigned int bucket;

    pr_info("VaultGuard v2.0: Kaldırılıyor...\n");

    /* 1. Tüm TTL zamanlayıcılarını durdur ve slotları temizle */
    down_write(&vault_rwsem);
    hash_for_each_safe(vault_ht, bucket, tmp_node, entry, node) {
        cancel_delayed_work(&entry->dwork);
        vault_destroy_entry(entry, 2 /* Modül kaldırma */);
    }
    up_write(&vault_rwsem);

    /* 2. AES anahtarını temizle */
    memzero_explicit(vault_aes_key, sizeof(vault_aes_key));

    /* 3. Alt sistemleri ters sırada kapat */
    debugfs_remove_recursive(debug_dir);
    proc_remove(proc_entry);
    device_destroy(vault_class, dev_num);
    class_destroy(vault_class);
    cdev_del(&vault_cdev);
    unregister_chrdev_region(dev_num, 1);
    genl_unregister_family(&vg_genl_family);

    if (vault_tfm)
        crypto_free_aead(vault_tfm);

    pr_info("VaultGuard v2.0: Başarıyla kaldırıldı.\n");
}

module_init(vaultguard_init);
module_exit(vaultguard_exit);
