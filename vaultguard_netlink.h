/* SPDX-License-Identifier: GPL-2.0 */
/*
 * vaultguard_netlink.h — Generic Netlink Aile Tanımlamaları
 *
 * Kernel modül ve userspace araçları arasında gerçek zamanlı
 * olay akışı için Generic Netlink protokol tanımları.
 *
 * Dinlemek için:
 *   vaultctl monitor   (tools/vaultctl.c)
 *
 * Author: Efe
 * License: GPLv2
 */

#ifndef VAULTGUARD_NETLINK_H
#define VAULTGUARD_NETLINK_H

/* Generic Netlink aile adı (max 16 karakter) */
#define VG_GENL_NAME     "vaultguard"
#define VG_GENL_VERSION  1

/* Multicast grubu — tüm güvenlik olayları bu gruba yayınlanır */
#define VG_GENL_MCAST_GROUP  "vg_events"

/* ────────────────────────────────────────────────────────────────── */
/*  Komutlar (Netlink Commands)                                        */
/* ────────────────────────────────────────────────────────────────── */

enum vg_genl_cmd {
    VG_CMD_UNSPEC = 0,
    VG_CMD_EVENT,       /* Kernel → Userspace: Olay bildirimi */
    __VG_CMD_MAX,
};
#define VG_CMD_MAX (__VG_CMD_MAX - 1)

/* ────────────────────────────────────────────────────────────────── */
/*  Attribute'lar (Olay verisi TLV formatında taşınır)                */
/* ────────────────────────────────────────────────────────────────── */

enum vg_genl_attr {
    VG_ATTR_UNSPEC = 0,
    VG_ATTR_EVENT_TYPE,     /* u32: Olay tipi (aşağıdaki enum) */
    VG_ATTR_TIMESTAMP_NS,   /* u64: ktime nanosaniye cinsinden  */
    VG_ATTR_PID,            /* u32: İlgili süreç PID            */
    VG_ATTR_UID,            /* u32: İlgili süreç UID            */
    VG_ATTR_LABEL,          /* string: Sır etiketi              */
    VG_ATTR_DENY_REASON,    /* u32: Erişim red sebebi kodu      */
    VG_ATTR_TTL_REMAINING,  /* s64: Kalan TTL (saniye)          */
    __VG_ATTR_MAX,
};
#define VG_ATTR_MAX (__VG_ATTR_MAX - 1)

/* ────────────────────────────────────────────────────────────────── */
/*  Olay Tipleri (VG_ATTR_EVENT_TYPE değerleri)                       */
/* ────────────────────────────────────────────────────────────────── */

enum vg_event_type {
    VG_EVENT_ACCESS_DENIED     = 1, /* Yetkisiz erişim denemesi   */
    VG_EVENT_SECRET_STORED     = 2, /* Yeni sır depolandı         */
    VG_EVENT_SECRET_EXPIRED    = 3, /* TTL doldu, sır silindi     */
    VG_EVENT_FORCE_PURGE       = 4, /* Acil durum imhası          */
    VG_EVENT_QUARANTINE_ON     = 5, /* Karantina modu aktif edildi*/
    VG_EVENT_QUARANTINE_OFF    = 6, /* Karantina modu devre dışı  */
    VG_EVENT_SECRET_DELETED    = 7, /* Sır manuel silindi         */
};

#endif /* VAULTGUARD_NETLINK_H */
