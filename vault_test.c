/*
 * vault_test.c — VaultGuard Entegrasyon Test Programı
 *
 * Hem miras (legacy) hem de yeni çok-slotlu IOCTL'leri test eder.
 *
 * Kullanım:
 *   sudo ./vault_test store   <mesaj>        → Miras tek-slot depolama
 *   sudo ./vault_test get                    → Miras tek-slot okuma
 *   sudo ./vault_test forktest <mesaj>       → PID izolasyon testi
 *   sudo ./vault_test multitest              → Çok-slot kapsamlı test
 *   sudo ./vault_test ttltest <saniye>       → TTL otomatik imha testi
 *
 * Author: Efe
 * License: GPLv2
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdint.h>

/* Kernel'dan paylaşılan tanımlar (userspace uyumluluğu için typedef) */
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int64_t  __s64;

#include "vaultguard.h"

static int fd;

static void canary_signal_handler(int signum)
{
    (void)signum;
    printf("\n[!] SIEM ALARMI: Çekirdek Canary Tuzağı Tetiklendi! "
           "Zero-Trust ihlal girişimi loglandı.\n");
}

/* ── Miras: store ── */
static int test_store_legacy(const char *msg)
{
    char buffer[SECRET_MAX_LEN];
    snprintf(buffer, sizeof(buffer), "%s", msg);
    if (ioctl(fd, VAULT_IOC_STORE_SECRET, buffer) >= 0) {
        printf("[+] Miras depolama başarılı. PID: %d\n", getpid());
        return 0;
    }
    perror("[-] Miras depolama başarısız");
    return -1;
}

/* ── Miras: get ── */
static int test_get_legacy(void)
{
    char buffer[SECRET_MAX_LEN] = {0};
    if (ioctl(fd, VAULT_IOC_GET_SECRET, buffer) < 0) {
        printf("[-] ERİŞİM REDDEDİLDİ! (Farklı PID veya Karantina)\n");
        usleep(500000);
        return -1;
    }
    printf("[+] Çekirdekten okunan veri: %s\n", buffer);
    memset(buffer, 0, sizeof(buffer));
    return 0;
}

/* ── Çok-slot: store_labeled ── */
static int test_store_labeled(const char *label, const char *data,
                              unsigned long ttl)
{
    struct vault_user_request req = {0};
    snprintf(req.label, sizeof(req.label), "%s", label);
    snprintf(req.data,  sizeof(req.data),  "%s", data);
    req.data_len = (uint32_t)strlen(req.data);
    req.ttl_sec  = (uint64_t)ttl;

    if (ioctl(fd, VAULT_IOC_STORE_LABELED, &req) >= 0) {
        printf("[+] [%s] depolandı. (TTL=%lus)\n", label, ttl);
        memset(req.data, 0, SECRET_MAX_LEN);
        return 0;
    }
    perror("[-] store_labeled başarısız");
    return -1;
}

/* ── Çok-slot: get_labeled ── */
static int test_get_labeled(const char *label)
{
    struct vault_user_request req = {0};
    snprintf(req.label, sizeof(req.label), "%s", label);

    if (ioctl(fd, VAULT_IOC_GET_LABELED, &req) < 0) {
        printf("[-] [%s]: ERİŞİM REDDEDİLDİ (%s)\n",
               label, strerror_r(errno, req.data, 64) ? "?" : req.data);
        memset(&req, 0, sizeof(req));
        return -1;
    }
    printf("[+] [%s]: %s\n", label, req.data);
    memset(req.data, 0, SECRET_MAX_LEN);
    return 0;
}

/* ── Çok-slot: list ── */
static void test_list(void)
{
    struct vault_list_response resp = {0};
    uint32_t i;

    if (ioctl(fd, VAULT_IOC_LIST_LABELS, &resp) < 0) {
        perror("[-] list başarısız");
        return;
    }
    printf("[*] Aktif slot sayısı: %u\n", resp.count);
    for (i = 0; i < resp.count; i++) {
        printf("    %-30s  TTL: %llds\n",
               resp.entries[i].label,
               (long long)resp.entries[i].remaining_ttl);
    }
}

/* ── PID izolasyon testi (forktest) ── */
static void test_forktest(const char *msg)
{
    pid_t child;

    printf("[*] Ana süreç (PID: %d) veriyi yazıyor...\n", getpid());
    if (test_store_labeled("forktest_key", msg, 120) < 0)
        return;

    child = fork();
    if (child == 0) {
        printf("\n\t[X] Alt süreç (PID: %d) veriyi çalmaya çalışıyor!\n",
               getpid());
        if (test_get_labeled("forktest_key") < 0)
            printf("\t[-] Başarısız! Çekirdek alt süreci engelledi.\n");
        usleep(600000);
        exit(0);
    } else {
        wait(NULL);
        printf("\n[*] Ana süreç (PID: %d) kendi verisini okuyor...\n",
               getpid());
        test_get_labeled("forktest_key");
    }
}

/* ── Çok-slot kapsamlı test ── */
static void test_multitest(void)
{
    printf("\n=== ÇOK-SLOT TEST BAŞLIYOR ===\n\n");

    printf("[1] 3 farklı sır depolanıyor...\n");
    test_store_labeled("db_password",   "SuperSecure#1!", 300);
    test_store_labeled("api_key",       "sk-proj-abc123", 600);
    test_store_labeled("ssh_passphrase","id_ed25519_pw",  120);
    printf("\n");

    printf("[2] Tüm slotlar listeleniyor...\n");
    test_list();
    printf("\n");

    printf("[3] Her sırrı okuma...\n");
    test_get_labeled("db_password");
    test_get_labeled("api_key");
    test_get_labeled("ssh_passphrase");
    printf("\n");

    printf("[4] Var olmayan sırı okuma...\n");
    test_get_labeled("nonexistent_key");
    printf("\n");

    printf("[5] Aynı etikete güncelleme (overwrite)...\n");
    test_store_labeled("db_password", "NewPassword#2!", 300);
    test_get_labeled("db_password");
    printf("\n");

    printf("=== ÇOK-SLOT TEST TAMAMLANDI ===\n");
}

/* ── TTL dolum testi ── */
static void test_ttltest(int ttl_sec)
{
    printf("\n=== TTL DOLUM TESTİ (TTL=%d sn) ===\n\n", ttl_sec);

    test_store_labeled("ttl_test_key", "WillSelfDestruct", (unsigned long)ttl_sec);

    printf("[*] İlk okuma (veri mevcut olmalı):\n");
    test_get_labeled("ttl_test_key");

    printf("\n[*] TTL dolumu bekleniyor (%d + 2 saniye)...\n",
           ttl_sec);
    sleep(ttl_sec + 2);

    printf("[*] TTL sonrası okuma (veri yok olmuş olmalı):\n");
    test_get_labeled("ttl_test_key");

    printf("\n=== TTL TEST TAMAMLANDI ===\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Kullanım: %s <store <veri> | get | forktest <veri> | multitest | ttltest <sn>>\n",
               argv[0]);
        return 1;
    }

    fd = open("/dev/vaultguard_dev", O_RDWR);
    if (fd < 0) {
        perror("Aygıt açılamadı");
        return 1;
    }

    signal(SIGIO, canary_signal_handler);
    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | FASYNC);

    if (strcmp(argv[1], "store") == 0 && argc == 3) {
        test_store_legacy(argv[2]);
    }
    else if (strcmp(argv[1], "get") == 0) {
        test_get_legacy();
    }
    else if (strcmp(argv[1], "forktest") == 0 && argc == 3) {
        test_forktest(argv[2]);
    }
    else if (strcmp(argv[1], "multitest") == 0) {
        test_multitest();
    }
    else if (strcmp(argv[1], "ttltest") == 0 && argc == 3) {
        test_ttltest(atoi(argv[2]));
    }
    else {
        printf("Bilinmeyen komut: %s\n", argv[1]);
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
