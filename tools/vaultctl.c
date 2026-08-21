/*
 * vaultctl.c — VaultGuard Kullanıcı Alanı Yönetim Aracı
 *
 * IOCTL ve Generic Netlink üzerinden VaultGuard kernel modülüyle
 * iletişim kurar.
 *
 * Kullanım:
 *   vaultctl store  --label <etiket> --data <veri> [--ttl <saniye>]
 *   vaultctl get    --label <etiket>
 *   vaultctl delete --label <etiket>
 *   vaultctl list
 *   vaultctl purge  --force
 *   vaultctl status
 *   vaultctl monitor    (Netlink gerçek zamanlı olay akışı)
 *   vaultctl forktest   --label <etiket> --data <veri>  (PID izolasyon testi)
 *
 * Derleme:
 *   gcc -O2 -Wall -Wextra -o vaultctl vaultctl.c
 *
 * Author: Efe
 * License: GPLv2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>

/* Kernel header'larını taklit et (userspace için) */
#include <stdint.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int64_t  __s64;

#include "../vaultguard.h"
#include "../vaultguard_netlink.h"

/* ─────────────────────────────────────────────────────────── */
/*  Renkli Terminal Çıktısı                                     */
/* ─────────────────────────────────────────────────────────── */

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

#define OK(fmt, ...)   printf(COLOR_GREEN  "[+] " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...)  fprintf(stderr, COLOR_RED "[!] " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define INFO(fmt, ...) printf(COLOR_CYAN   "[*] " COLOR_RESET fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) printf(COLOR_YELLOW "[W] " COLOR_RESET fmt "\n", ##__VA_ARGS__)

/* ─────────────────────────────────────────────────────────── */
/*  Yardımcılar                                                 */
/* ─────────────────────────────────────────────────────────── */

static const char *DEVICE_PATH = "/dev/vaultguard_dev";
static const char *PROC_PATH   = "/proc/vaultguard";
static const char *PURGE_PATH  = "/sys/kernel/debug/vaultguard/force_purge";

static int open_device(void) {
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        ERR("Aygıt açılamadı: %s — %s", DEVICE_PATH, strerror(errno));
        ERR("Modül yüklü mü? 'sudo insmod vaultguard.ko'");
    }
    return fd;
}

static void deny_reason_str(int reason, char *buf, size_t len) {
    switch (reason) {
    case VAULT_DENY_QUARANTINE: snprintf(buf, len, "Karantina modu aktif"); break;
    case VAULT_DENY_PID:        snprintf(buf, len, "PID uyuşmazlığı");      break;
    case VAULT_DENY_UID:        snprintf(buf, len, "UID uyuşmazlığı");      break;
    case VAULT_DENY_NAMESPACE:  snprintf(buf, len, "Namespace uyuşmazlığı"); break;
    case VAULT_DENY_NOT_FOUND:  snprintf(buf, len, "Sır bulunamadı");       break;
    default:                    snprintf(buf, len, "Bilinmiyor (%d)", reason); break;
    }
}

/* ─────────────────────────────────────────────────────────── */
/*  Komut: store                                                */
/* ─────────────────────────────────────────────────────────── */

static int cmd_store(const char *label, const char *data,
                     unsigned long ttl)
{
    struct vault_user_request req = {0};
    int fd, ret;

    if (!label || !data) {
        ERR("store: --label ve --data zorunludur");
        return 1;
    }

    strncat(req.label, label, VAULT_LABEL_MAX_LEN - 1);
    strncat(req.data,  data,  SECRET_MAX_LEN - 1);
    req.data_len = (uint32_t)strlen(req.data);
    req.ttl_sec  = (uint64_t)ttl;

    fd = open_device();
    if (fd < 0) return 1;

    /* FASYNC kurulumu */
    signal(SIGIO, SIG_IGN);
    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | FASYNC);

    ret = ioctl(fd, VAULT_IOC_STORE_LABELED, &req);
    close(fd);

    /* req.data'yı belleğe iz bırakmadan temizle */
    memset(req.data, 0, SECRET_MAX_LEN);

    if (ret < 0) {
        ERR("Depolama başarısız: %s", strerror(errno));
        return 1;
    }

    OK("Sır güvenle depolandı.");
    INFO("Etiket  : '%s'", label);
    INFO("TTL     : %s", ttl ? "" : "varsayılan");
    INFO("PID     : %d", getpid());
    return 0;
}

/* ─────────────────────────────────────────────────────────── */
/*  Komut: get                                                  */
/* ─────────────────────────────────────────────────────────── */

static int cmd_get(const char *label)
{
    struct vault_user_request req = {0};
    int fd, ret;

    if (!label) {
        ERR("get: --label zorunludur");
        return 1;
    }

    strncat(req.label, label, VAULT_LABEL_MAX_LEN - 1);

    fd = open_device();
    if (fd < 0) return 1;

    ret = ioctl(fd, VAULT_IOC_GET_LABELED, &req);
    close(fd);

    if (ret < 0) {
        if (errno == EACCES) {
            ERR("Erişim REDDEDİLDİ! Zero-Trust ihlali algılandı.");
        } else if (errno == ENOENT) {
            ERR("Sır bulunamadı: '%s'", label);
        } else {
            ERR("Okuma hatası: %s", strerror(errno));
        }
        memset(&req, 0, sizeof(req));
        return 1;
    }

    OK("Çekirdekten alınan veri:");
    printf("    " COLOR_BOLD "%s" COLOR_RESET "\n", req.data);
    memset(req.data, 0, SECRET_MAX_LEN);
    return 0;
}

/* ─────────────────────────────────────────────────────────── */
/*  Komut: delete                                               */
/* ─────────────────────────────────────────────────────────── */

static int cmd_delete(const char *label)
{
    struct vault_user_request req = {0};
    int fd, ret;

    if (!label) {
        ERR("delete: --label zorunludur");
        return 1;
    }

    strncat(req.label, label, VAULT_LABEL_MAX_LEN - 1);

    fd = open_device();
    if (fd < 0) return 1;

    ret = ioctl(fd, VAULT_IOC_DELETE_LABELED, &req);
    close(fd);

    if (ret < 0) {
        ERR("Silme başarısız: %s", strerror(errno));
        return 1;
    }

    OK("Sır güvenle silindi: '%s'", label);
    return 0;
}

/* ─────────────────────────────────────────────────────────── */
/*  Komut: list                                                 */
/* ─────────────────────────────────────────────────────────── */

static int cmd_list(void)
{
    struct vault_list_response resp = {0};
    int fd, ret;
    uint32_t i;

    fd = open_device();
    if (fd < 0) return 1;

    ret = ioctl(fd, VAULT_IOC_LIST_LABELS, &resp);
    close(fd);

    if (ret < 0) {
        ERR("Liste alınamadı: %s", strerror(errno));
        return 1;
    }

    if (resp.count == 0) {
        INFO("Vault boş — aktif sır yok.");
        return 0;
    }

    printf(COLOR_BOLD "%-30s  %s\n" COLOR_RESET, "Etiket", "Kalan TTL");
    printf("%-30s  %s\n", "──────────────────────────────",
           "──────────");
    for (i = 0; i < resp.count; i++) {
        int64_t rem = resp.entries[i].remaining_ttl;
        printf("%-30s  ", resp.entries[i].label);
        if (rem > 60)
            printf(COLOR_GREEN "%llds (%lld dk)" COLOR_RESET "\n",
                   (long long)rem, (long long)(rem / 60));
        else if (rem > 0)
            printf(COLOR_YELLOW "%llds" COLOR_RESET "\n", (long long)rem);
        else
            printf(COLOR_RED "Süresi doldu" COLOR_RESET "\n");
    }
    printf("\nToplam: %u slot\n", resp.count);
    return 0;
}

/* ─────────────────────────────────────────────────────────── */
/*  Komut: purge                                                */
/* ─────────────────────────────────────────────────────────── */

static int cmd_purge(void)
{
    FILE *f;
    char confirm[8];

    printf(COLOR_RED COLOR_BOLD
           "\n[UYARI] Tum sirlar kriptografik olarak imha edilecek!\n"
           COLOR_RESET);
    printf("Onaylamak için 'PURGE' yazın: ");
    fflush(stdout);

    if (!fgets(confirm, sizeof(confirm), stdin))
        return 1;
    confirm[strcspn(confirm, "\n")] = '\0';

    if (strcmp(confirm, "PURGE") != 0) {
        INFO("İptal edildi.");
        return 0;
    }

    f = fopen(PURGE_PATH, "w");
    if (!f) {
        ERR("force_purge açılamadı: %s", strerror(errno));
        ERR("Root yetkisi gerekli ve debugfs bağlı olmalı.");
        return 1;
    }
    fprintf(f, "1");
    fclose(f);

    OK("Acil durum bellek imhası gerçekleştirildi!");
    return 0;
}

/* ─────────────────────────────────────────────────────────── */
/*  Komut: status                                               */
/* ─────────────────────────────────────────────────────────── */

static int cmd_status(void)
{
    FILE *f;
    char line[256];

    f = fopen(PROC_PATH, "r");
    if (!f) {
        ERR("/proc/vaultguard açılamadı: %s", strerror(errno));
        ERR("Modül yüklü mü?");
        return 1;
    }

    printf(COLOR_BOLD "\n=== VaultGuard v2.0 Güvenlik Durumu ===\n"
           COLOR_RESET);
    while (fgets(line, sizeof(line), f))
        printf("  %s", line);
    fclose(f);
    printf("\n");
    return 0;
}

/* ─────────────────────────────────────────────────────────── */
/*  Komut: forktest (PID izolasyon testi)                       */
/* ─────────────────────────────────────────────────────────── */

static volatile int siem_fired = 0;

static void canary_handler(int signum)
{
    (void)signum;
    siem_fired = 1;
}

static int cmd_forktest(const char *label, const char *data)
{
    struct vault_user_request req = {0};
    int fd;
    pid_t child;

    if (!label || !data) {
        ERR("forktest: --label ve --data zorunludur");
        return 1;
    }

    fd = open_device();
    if (fd < 0) return 1;

    signal(SIGIO, canary_handler);
    fcntl(fd, F_SETOWN, getpid());
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | FASYNC);

    /* Ana süreç: sır depola */
    strncat(req.label, label, VAULT_LABEL_MAX_LEN - 1);
    strncat(req.data,  data,  SECRET_MAX_LEN - 1);
    req.data_len = (uint32_t)strlen(req.data);

    INFO("Ana süreç (PID: %d) sır yazıyor: '%s'", getpid(), label);
    if (ioctl(fd, VAULT_IOC_STORE_LABELED, &req) < 0) {
        ERR("Store başarısız: %s", strerror(errno));
        close(fd);
        return 1;
    }
    memset(req.data, 0, SECRET_MAX_LEN);
    OK("Sır güvenle depolandı.");

    child = fork();
    if (child == 0) {
        /* Alt süreç: sırrı çalmaya çalış */
        struct vault_user_request steal = {0};
        printf("\n");
        WARN("Alt süreç (PID: %d) sırrı çalmaya çalışıyor!", getpid());
        strncat(steal.label, label, VAULT_LABEL_MAX_LEN - 1);

        if (ioctl(fd, VAULT_IOC_GET_LABELED, &steal) < 0) {
            ERR("Kernel engelledi! Erişim REDDEDİLDİ. (%s)",
                strerror(errno));
            usleep(600000); /* SIGIO sinyalini bekle */
        } else {
            WARN("Beklenmeyen başarı — güvenlik açığı!");
        }
        memset(&steal, 0, sizeof(steal));
        close(fd);
        exit(0);
    }

    /* Ana süreç: çocuğu bekle, sonra kendi verisini oku */
    wait(NULL);

    if (siem_fired)
        OK("SIEM Alarmı: Canary tuzağı tetiklendi ve sinyal alındı!");

    printf("\n");
    INFO("Ana süreç (PID: %d) kendi verisini okuyor...", getpid());
    memset(&req, 0, sizeof(req));
    strncat(req.label, label, VAULT_LABEL_MAX_LEN - 1);

    if (ioctl(fd, VAULT_IOC_GET_LABELED, &req) == 0) {
        OK("Başarılı! Veri: %s", req.data);
        memset(req.data, 0, SECRET_MAX_LEN);
    } else {
        ERR("Ana süreç de okuyamadı: %s", strerror(errno));
    }

    close(fd);
    return 0;
}

/* ─────────────────────────────────────────────────────────── */
/*  Komut: monitor (Generic Netlink dinleyicisi)                */
/* ─────────────────────────────────────────────────────────── */

/*
 * NOT: Tam Generic Netlink çözümü libmnl veya libnl-genl
 * kütüphanesi ile yapılır. Bu uygulama temel yapıyı gösterir;
 * tam olay ayrıştırması için libnl-genl-3.0 kullanılmalıdır.
 * Kurulum: apt install libnl-genl-3-dev
 */
static int cmd_monitor(void)
{
    printf(COLOR_BOLD
           "\n=== VaultGuard Gerçek Zamanlı Olay İzleyici ===\n"
           COLOR_RESET);
    printf("Olaylar için /sys/kernel/debug/tracing/trace_pipe dinleniyor...\n");
    printf(COLOR_YELLOW
           "(Çıkmak için Ctrl+C)\n"
           COLOR_RESET "\n");

    /* Basit yaklaşım: ftrace pipe'ı oku */
    {
        const char *trace_pipe = "/sys/kernel/debug/tracing/trace_pipe";
        FILE *f = fopen(trace_pipe, "r");
        char line[512];
        time_t t;
        char ts[32];

        if (!f) {
            ERR("trace_pipe açılamadı: %s", strerror(errno));
            ERR("Tracing etkin mi? 'echo 1 > /sys/kernel/debug/tracing/events/vaultguard/enable'");
            return 1;
        }

        /* VaultGuard tracepoint'lerini etkinleştir */
        system("echo 1 > /sys/kernel/debug/tracing/events/vaultguard/enable "
               "2>/dev/null");

        while (fgets(line, sizeof(line), f)) {
            /* Sadece vaultguard satırlarını filtrele */
            if (strstr(line, "vg_")) {
                t = time(NULL);
                strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));

                if (strstr(line, "CANARY TRAP") ||
                    strstr(line, "Access denied")) {
                    printf(COLOR_RED "[%s] %s" COLOR_RESET, ts, line);
                } else if (strstr(line, "Secret stored")) {
                    printf(COLOR_GREEN "[%s] %s" COLOR_RESET, ts, line);
                } else if (strstr(line, "wiped") ||
                           strstr(line, "Quarantine")) {
                    printf(COLOR_YELLOW "[%s] %s" COLOR_RESET, ts, line);
                } else {
                    printf("[%s] %s", ts, line);
                }
                fflush(stdout);
            }
        }
        fclose(f);
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────── */
/*  Yardım Mesajı                                               */
/* ─────────────────────────────────────────────────────────── */

static void print_usage(const char *prog)
{
    printf(COLOR_BOLD "\nVaultGuard v2.0 — Zero-Trust Kernel Secret Manager\n"
           COLOR_RESET);
    printf("Kullanım: %s <komut> [seçenekler]\n\n", prog);
    printf("Komutlar:\n");
    printf("  %-40s %s\n",
           "store --label <n> --data <v> [--ttl <s>]",
           "Sır sakla");
    printf("  %-40s %s\n",
           "get   --label <n>",
           "Sır oku");
    printf("  %-40s %s\n",
           "delete --label <n>",
           "Sır sil");
    printf("  %-40s %s\n",
           "list",
           "Tüm sırları listele");
    printf("  %-40s %s\n",
           "purge --force",
           "Acil durum imhası");
    printf("  %-40s %s\n",
           "status",
           "Güvenlik telemetrisi");
    printf("  %-40s %s\n",
           "monitor",
           "Gerçek zamanlı olay izleme");
    printf("  %-40s %s\n",
           "forktest --label <n> --data <v>",
           "PID izolasyon testi");
    printf("\nÖrnekler:\n");
    printf("  sudo %s store --label db_pass --data 'Passw0rd!' --ttl 300\n",
           prog);
    printf("  sudo %s get   --label db_pass\n", prog);
    printf("  sudo %s list\n", prog);
    printf("  sudo %s monitor\n", prog);
    printf("  sudo %s forktest --label test_key --data 'secret'\n\n", prog);
}

/* ─────────────────────────────────────────────────────────── */
/*  main                                                        */
/* ─────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    const char *cmd   = NULL;
    const char *label = NULL;
    const char *data  = NULL;
    unsigned long ttl = 0;
    int force = 0;
    int i;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    cmd = argv[1];

    /* Argüman ayrıştırma */
    for (i = 2; i < argc; i++) {
        if      (strcmp(argv[i], "--label") == 0 && i+1 < argc)
            label = argv[++i];
        else if (strcmp(argv[i], "--data")  == 0 && i+1 < argc)
            data  = argv[++i];
        else if (strcmp(argv[i], "--ttl")   == 0 && i+1 < argc)
            ttl   = (unsigned long)atol(argv[++i]);
        else if (strcmp(argv[i], "--force") == 0)
            force = 1;
    }

    /* Komut yönlendirme */
    if      (strcmp(cmd, "store")    == 0) return cmd_store(label, data, ttl);
    else if (strcmp(cmd, "get")      == 0) return cmd_get(label);
    else if (strcmp(cmd, "delete")   == 0) return cmd_delete(label);
    else if (strcmp(cmd, "list")     == 0) return cmd_list();
    else if (strcmp(cmd, "purge")    == 0) {
        (void)force; /* onay prompt'u içinde zaten soruluyor */
        return cmd_purge();
    }
    else if (strcmp(cmd, "status")   == 0) return cmd_status();
    else if (strcmp(cmd, "monitor")  == 0) return cmd_monitor();
    else if (strcmp(cmd, "forktest") == 0) return cmd_forktest(label, data);
    else {
        ERR("Bilinmeyen komut: '%s'", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
