/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM vaultguard

#if !defined(_VAULTGUARD_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _VAULTGUARD_TRACE_H

#include <linux/tracepoint.h>
#include <linux/version.h>

/* Linux 6.8+ ve Linux 7.0+ surumlerinde __assign_str artik tek arguman alir */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
#define __assign_str_compat(dst, src) __assign_str(dst)
#else
#define __assign_str_compat(dst, src) __assign_str(dst, src)
#endif

/* ---------------------------------------------------------------- */
/* Event 1: vg_canary_trap                                          */
/*   Yetkisiz bir PID sir okumayi denediginde tetiklenir.           */
/* ---------------------------------------------------------------- */
TRACE_EVENT(vg_canary_trap,
    TP_PROTO(pid_t attacker_pid, pid_t owner_pid, int deny_reason),
    TP_ARGS(attacker_pid, owner_pid, deny_reason),

    TP_STRUCT__entry(
        __field(pid_t, attacker_pid)
        __field(pid_t, owner_pid)
        __field(int,   deny_reason)
    ),

    TP_fast_assign(
        __entry->attacker_pid = attacker_pid;
        __entry->owner_pid    = owner_pid;
        __entry->deny_reason  = deny_reason;
    ),

    TP_printk("CANARY TRAP! Attacker PID=%d Owner PID=%d Reason=%d",
              __entry->attacker_pid,
              __entry->owner_pid,
              __entry->deny_reason)
);

/* ---------------------------------------------------------------- */
/* Event 2: vg_secret_wiped                                         */
/*   Bellek kriptografik olarak silindiginde tetiklenir.            */
/*   reason_code: 1=TTL Doldu, 2=Acil Imha, 3=Manuel Silme          */
/* ---------------------------------------------------------------- */
TRACE_EVENT(vg_secret_wiped,
    TP_PROTO(int reason_code, const char *label),
    TP_ARGS(reason_code, label),

    TP_STRUCT__entry(
        __field(int,        reason_code)
        __string(label,     label)
    ),

    TP_fast_assign(
        __entry->reason_code = reason_code;
        __assign_str_compat(label, label);
    ),

    TP_printk("Secure wipe. Reason=%d Label='%s'",
              __entry->reason_code,
              __get_str(label))
);

/* ---------------------------------------------------------------- */
/* Event 3: vg_secret_stored                                         */
/*   Yeni bir sir basariyla depolandiginda tetiklenir.              */
/* ---------------------------------------------------------------- */
TRACE_EVENT(vg_secret_stored,
    TP_PROTO(pid_t owner_pid, uid_t owner_uid, const char *label,
             unsigned long ttl_sec),
    TP_ARGS(owner_pid, owner_uid, label, ttl_sec),

    TP_STRUCT__entry(
        __field(pid_t,          owner_pid)
        __field(uid_t,          owner_uid)
        __string(label,         label)
        __field(unsigned long,  ttl_sec)
    ),

    TP_fast_assign(
        __entry->owner_pid = owner_pid;
        __entry->owner_uid = owner_uid;
        __assign_str_compat(label, label);
        __entry->ttl_sec   = ttl_sec;
    ),

    TP_printk("Secret stored. PID=%d UID=%u Label='%s' TTL=%lus",
              __entry->owner_pid,
              __entry->owner_uid,
              __get_str(label),
              __entry->ttl_sec)
);

/* ---------------------------------------------------------------- */
/* Event 4: vg_access_denied                                         */
/*   Erisim reddedildiginde tetiklenir.                             */
/* ---------------------------------------------------------------- */
TRACE_EVENT(vg_access_denied,
    TP_PROTO(pid_t attacker_pid, uid_t attacker_uid, const char *label,
             int deny_reason),
    TP_ARGS(attacker_pid, attacker_uid, label, deny_reason),

    TP_STRUCT__entry(
        __field(pid_t, attacker_pid)
        __field(uid_t, attacker_uid)
        __string(label, label)
        __field(int,   deny_reason)
    ),

    TP_fast_assign(
        __entry->attacker_pid = attacker_pid;
        __entry->attacker_uid = attacker_uid;
        __assign_str_compat(label, label);
        __entry->deny_reason  = deny_reason;
    ),

    TP_printk("Access denied. PID=%d UID=%u Label='%s' Reason=%d",
              __entry->attacker_pid,
              __entry->attacker_uid,
              __get_str(label),
              __entry->deny_reason)
);

/* ---------------------------------------------------------------- */
/* Event 5: vg_quarantine_toggle                                     */
/*   Karantina modu degistiginde tetiklenir.                        */
/* ---------------------------------------------------------------- */
TRACE_EVENT(vg_quarantine_toggle,
    TP_PROTO(int new_state, pid_t changed_by_pid),
    TP_ARGS(new_state, changed_by_pid),

    TP_STRUCT__entry(
        __field(int,   new_state)
        __field(pid_t, changed_by_pid)
    ),

    TP_fast_assign(
        __entry->new_state      = new_state;
        __entry->changed_by_pid = changed_by_pid;
    ),

    TP_printk("Quarantine %s by PID=%d",
              __entry->new_state ? "ACTIVATED" : "DEACTIVATED",
              __entry->changed_by_pid)
);

/* ---------------------------------------------------------------- */
/* Event 6: vg_crypto_operation                                      */
/*   Sifreleme/cozme islemlerinde tetiklenir.                       */
/*   op: 0=encrypt, 1=decrypt                                       */
/* ---------------------------------------------------------------- */
TRACE_EVENT(vg_crypto_operation,
    TP_PROTO(int op, int success, const char *label),
    TP_ARGS(op, success, label),

    TP_STRUCT__entry(
        __field(int,    op)
        __field(int,    success)
        __string(label, label)
    ),

    TP_fast_assign(
        __entry->op      = op;
        __entry->success = success;
        __assign_str_compat(label, label);
    ),

    TP_printk("%s on '%s': %s",
              __entry->op ? "Decrypt" : "Encrypt",
              __get_str(label),
              __entry->success ? "OK" : "FAILED")
);

#endif /* _VAULTGUARD_TRACE_H */

/* Cekirdek makrolarinin bu dosyayi dogru derlemesi icin zorunlu ayarlar */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE vaultguard_trace
#include <trace/define_trace.h>
