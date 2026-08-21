# VaultGuard v2.0 — Makefile
#
# Hedefler:
#   make          → Kernel modülü + vaultctl + vault_test derle
#   make clean    → Tüm derleme artifaktlarını sil
#   make install  → Modülü sisteme yükle ve aygıt izinlerini ayarla
#   make uninstall→ Modülü sistemden kaldır
#   make test     → Hızlı otomatik smoke test çalıştır
#   make monitor  → bpftrace izleyiciyi başlat
#
# Kullanım:
#   make
#   sudo make install
#   sudo make test
#   sudo make monitor

# ─── Kernel modül ayarları ──────────────────────────────────────────
obj-m += vaultguard.o

# Tracepoint başlık dosyasının bulunabilmesi için kaynak dizini ekle
ccflags-y := -I$(src)

# Sıkı uyarı modu: profesyonel kernel kodu sıfır uyarıyla derlenmeli
ccflags-y += -Wall -Wextra -Wno-unused-parameter

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# ─── Userspace araç ayarları ────────────────────────────────────────
CFLAGS_USER := -O2 -Wall -Wextra -Wno-unused-parameter -I.
CC           := gcc

# ─── Varsayılan hedef ───────────────────────────────────────────────
.PHONY: all clean install uninstall test monitor

all: modules tools

# Kernel modülünü derle
modules:
	@echo "[ KM ] Kernel modülü derleniyor..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules W=1
	@echo "[ OK ] vaultguard.ko hazır."

# Kullanıcı alanı araçlarını derle
tools: tools/vaultctl vault_test

tools/vaultctl: tools/vaultctl.c vaultguard.h vaultguard_netlink.h
	@echo "[ CC ] vaultctl derleniyor..."
	$(CC) $(CFLAGS_USER) -o tools/vaultctl tools/vaultctl.c
	@echo "[ OK ] tools/vaultctl hazır."

vault_test: vault_test.c vaultguard.h
	@echo "[ CC ] vault_test derleniyor..."
	$(CC) $(CFLAGS_USER) -o vault_test vault_test.c
	@echo "[ OK ] vault_test hazır."

# ─── Temizlik ───────────────────────────────────────────────────────
clean:
	@echo "[ RM ] Derleme artifaktları siliniyor..."
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f vault_test tools/vaultctl
	@echo "[ OK ] Temizlendi."

# ─── Kurulum ────────────────────────────────────────────────────────
install: modules
	@echo "[ IN ] VaultGuard kurulum başlıyor..."
	@# Varsa önce kaldır
	-sudo rmmod vaultguard 2>/dev/null || true
	@# Modülü yükle
	sudo insmod vaultguard.ko
	@# Aygıt iznini kullanıcıya aç (geliştirme ortamı için)
	sudo chmod 666 /dev/vaultguard_dev 2>/dev/null || true
	@# procfs, debugfs tracing etkinleştir
	sudo sh -c 'echo 1 > /sys/kernel/debug/tracing/events/vaultguard/enable' 2>/dev/null || true
	@echo "[ OK ] VaultGuard yüklendi ve etkinleştirildi."
	@echo ""
	@echo "  Aygıt     : /dev/vaultguard_dev"
	@echo "  Telemetri : /proc/vaultguard"
	@echo "  Debug     : /sys/kernel/debug/vaultguard/"
	@echo "  Tracing   : /sys/kernel/debug/tracing/events/vaultguard/"
	@echo ""

# ─── Kaldırma ───────────────────────────────────────────────────────
uninstall:
	@echo "[ RM ] VaultGuard kaldırılıyor..."
	-sudo sh -c 'echo 0 > /sys/kernel/debug/tracing/events/vaultguard/enable' 2>/dev/null || true
	sudo rmmod vaultguard
	@echo "[ OK ] VaultGuard kaldırıldı."

# ─── Otomatik Smoke Test ────────────────────────────────────────────
test: tools/vaultctl vault_test
	@echo ""
	@echo "════════════════════════════════════════"
	@echo "  VaultGuard v2.0 — Otomatik Test"
	@echo "════════════════════════════════════════"
	@echo ""

	@echo "[ T1 ] Basit store/get testi..."
	sudo tools/vaultctl store --label test_smoke --data "HelloVault" --ttl 120
	sudo tools/vaultctl get   --label test_smoke
	@echo ""

	@echo "[ T2 ] List testi..."
	sudo tools/vaultctl list
	@echo ""

	@echo "[ T3 ] Delete testi..."
	sudo tools/vaultctl delete --label test_smoke
	sudo tools/vaultctl list
	@echo ""

	@echo "[ T4 ] PID izolasyon testi (forktest)..."
	sudo tools/vaultctl forktest --label fork_test --data "IsolatedData"
	@echo ""

	@echo "[ T5 ] Miras IOCTL uyumluluk testi..."
	sudo ./vault_test store "LegacySecret"
	sudo ./vault_test get
	@echo ""

	@echo "[ T6 ] Güvenlik durumu..."
	sudo tools/vaultctl status
	@echo ""

	@echo "[ OK ] Tüm testler tamamlandı."

# ─── eBPF İzleyici ──────────────────────────────────────────────────
monitor:
	@which bpftrace > /dev/null 2>&1 || \
	  (echo "bpftrace kurulu değil. Kurmak için: apt install bpftrace" && exit 1)
	sudo bpftrace tools/vaultguard_monitor.bt
