/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Basic Lustre library routines.
 *
 */

#ifndef _LUSTRE_LIB_H
#define _LUSTRE_LIB_H

#include <config.h>

#ifndef __KERNEL__
# include <string.h>
# include <sys/types.h>
#else
# include <asm/semaphore.h>
# include <linux/rwsem.h>
# include <linux/sched.h>
# include <linux/signal.h>
# include <linux/types.h>
#endif
#include <linux/portals_lib.h>
#include <linux/kp30.h> /* XXX just for LASSERT! */
#include <linux/lustre_idl.h>
#include <linux/lustre_cfg.h>

#ifndef LPU64
/* x86_64 has 64bit longs and defines u64 as long long */
#if BITS_PER_LONG > 32 && !defined(__x86_64__)
#define LPU64 "%lu"
#define LPD64 "%ld"
#define LPX64 "%#lx"
#else
#define LPU64 "%Lu"
#define LPD64 "%Ld"
#define LPX64 "%#Lx"
#endif
#endif

/* target.c */
struct ptlrpc_request;
struct recovd_data;
struct recovd_obd;
struct obd_export;
#include <linux/lustre_ha.h>
#include <linux/lustre_net.h>
#include <linux/lustre_compat25.h>
#include <linux/lvfs.h>

int target_handle_connect(struct ptlrpc_request *req, svc_handler_t handler);
int target_handle_disconnect(struct ptlrpc_request *req);
void target_destroy_export(struct obd_export *exp);
int target_handle_reconnect(struct lustre_handle *conn, struct obd_export *exp,
                            struct obd_uuid *cluuid);
int target_handle_ping(struct ptlrpc_request *req);
void target_cancel_recovery_timer(struct obd_device *obd);

#define OBD_RECOVERY_TIMEOUT (obd_timeout * 5 * HZ / 2) /* *waves hands* */
void target_start_recovery_timer(struct obd_device *obd, svc_handler_t handler);
void target_abort_recovery(void *data);
int target_queue_recovery_request(struct ptlrpc_request *req,
                                  struct obd_device *obd);
int target_queue_final_reply(struct ptlrpc_request *req, int rc);
void target_send_reply(struct ptlrpc_request *req, int rc, int fail_id);

/* client.c */

int client_sanobd_setup(struct obd_device *obddev, obd_count len, void *buf);
struct client_obd *client_conn2cli(struct lustre_handle *conn);

struct mdc_open_data;
struct obd_client_handle {
        struct lustre_handle och_fh;
        struct llog_cookie och_cookie;
        struct mdc_open_data *och_mod;
        __u32 och_magic;
};
#define OBD_CLIENT_HANDLE_MAGIC 0xd15ea5ed

/* statfs_pack.c */
void statfs_pack(struct obd_statfs *osfs, struct kstatfs *sfs);
void statfs_unpack(struct kstatfs *sfs, struct obd_statfs *osfs);

/* l_lock.c */
struct lustre_lock {
        int l_depth;
        struct task_struct *l_owner;
        struct semaphore l_sem;
        spinlock_t l_spin;
};

void l_lock_init(struct lustre_lock *);
void l_lock(struct lustre_lock *);
void l_unlock(struct lustre_lock *);
int l_has_lock(struct lustre_lock *);


#include <linux/portals_lib.h>

/*
 *   OBD IOCTLS
 */
#define OBD_IOCTL_VERSION 0x00010004

struct obd_ioctl_data {
        uint32_t ioc_len;
        uint32_t ioc_version;

        uint64_t ioc_cookie;
        uint32_t ioc_conn1;
        uint32_t ioc_conn2;

        struct obdo ioc_obdo1;
        struct obdo ioc_obdo2;

        obd_size         ioc_count;
        obd_off          ioc_offset;
        uint32_t         ioc_dev;
        uint32_t         ioc_command;

        uint64_t ioc_nid;
        uint32_t ioc_nal;
        uint32_t ioc_type;

        /* buffers the kernel will treat as user pointers */
        uint32_t ioc_plen1;
        char    *ioc_pbuf1;
        uint32_t ioc_plen2;
        char    *ioc_pbuf2;

        /* inline buffers for various arguments */
        uint32_t ioc_inllen1;
        char    *ioc_inlbuf1;
        uint32_t ioc_inllen2;
        char    *ioc_inlbuf2;
        uint32_t ioc_inllen3;
        char    *ioc_inlbuf3;
        uint32_t ioc_inllen4;
        char    *ioc_inlbuf4;

        char    ioc_bulk[0];
};

struct obd_ioctl_hdr {
        uint32_t ioc_len;
        uint32_t ioc_version;
};

static inline int obd_ioctl_packlen(struct obd_ioctl_data *data)
{
        int len = size_round(sizeof(struct obd_ioctl_data));
        len += size_round(data->ioc_inllen1);
        len += size_round(data->ioc_inllen2);
        len += size_round(data->ioc_inllen3);
        len += size_round(data->ioc_inllen4);
        return len;
}


static inline int obd_ioctl_is_invalid(struct obd_ioctl_data *data)
{
        if (data->ioc_len > (1<<30)) {
                printk("LustreError: OBD ioctl: ioc_len larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen1 > (1<<30)) {
                printk("LustreError: OBD ioctl: ioc_inllen1 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen2 > (1<<30)) {
                printk("LustreError: OBD ioctl: ioc_inllen2 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen3 > (1<<30)) {
                printk("LustreError: OBD ioctl: ioc_inllen3 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen4 > (1<<30)) {
                printk("LustreError: OBD ioctl: ioc_inllen4 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inlbuf1 && !data->ioc_inllen1) {
                printk("LustreError: OBD ioctl: inlbuf1 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_inlbuf2 && !data->ioc_inllen2) {
                printk("LustreError: OBD ioctl: inlbuf2 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_inlbuf3 && !data->ioc_inllen3) {
                printk("LustreError: OBD ioctl: inlbuf3 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_inlbuf4 && !data->ioc_inllen4) {
                printk("LustreError: OBD ioctl: inlbuf4 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_pbuf1 && !data->ioc_plen1) {
                printk("LustreError: OBD ioctl: pbuf1 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_pbuf2 && !data->ioc_plen2) {
                printk("LustreError: OBD ioctl: pbuf2 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_plen1 && !data->ioc_pbuf1) {
                printk("LustreError: OBD ioctl: plen1 set but NULL pointer\n");
                return 1;
        }
        if (data->ioc_plen2 && !data->ioc_pbuf2) {
                printk("LustreError: OBD ioctl: plen2 set but NULL pointer\n");
                return 1;
        }
        if (obd_ioctl_packlen(data) != data->ioc_len) {
                printk("LustreError: OBD ioctl: packlen exceeds ioc_len (%d != %d)\n",
                       obd_ioctl_packlen(data), data->ioc_len);
                return 1;
        }
        return 0;
}

#ifndef __KERNEL__
static inline int obd_ioctl_pack(struct obd_ioctl_data *data, char **pbuf,
                                 int max)
{
        char *ptr;
        struct obd_ioctl_data *overlay;
        data->ioc_len = obd_ioctl_packlen(data);
        data->ioc_version = OBD_IOCTL_VERSION;

        if (*pbuf && data->ioc_len > max)
                return 1;
        if (*pbuf == NULL) {
                *pbuf = malloc(data->ioc_len);
        }
        if (!*pbuf)
                return 1;
        overlay = (struct obd_ioctl_data *)*pbuf;
        memcpy(*pbuf, data, sizeof(*data));

        ptr = overlay->ioc_bulk;
        if (data->ioc_inlbuf1)
                LOGL(data->ioc_inlbuf1, data->ioc_inllen1, ptr);
        if (data->ioc_inlbuf2)
                LOGL(data->ioc_inlbuf2, data->ioc_inllen2, ptr);
        if (data->ioc_inlbuf3)
                LOGL(data->ioc_inlbuf3, data->ioc_inllen3, ptr);
        if (data->ioc_inlbuf4)
                LOGL(data->ioc_inlbuf4, data->ioc_inllen4, ptr);
        if (obd_ioctl_is_invalid(overlay))
                return 1;

        return 0;
}

static inline int obd_ioctl_unpack(struct obd_ioctl_data *data, char *pbuf,
                                   int max)
{
        char *ptr;
        struct obd_ioctl_data *overlay;

        if (!pbuf)
                return 1;
        overlay = (struct obd_ioctl_data *)pbuf;

        /* Preserve the caller's buffer pointers */
        overlay->ioc_inlbuf1 = data->ioc_inlbuf1;
        overlay->ioc_inlbuf2 = data->ioc_inlbuf2;
        overlay->ioc_inlbuf3 = data->ioc_inlbuf3;
        overlay->ioc_inlbuf4 = data->ioc_inlbuf4;

        memcpy(data, pbuf, sizeof(*data));

        ptr = overlay->ioc_bulk;
        if (data->ioc_inlbuf1)
                LOGU(data->ioc_inlbuf1, data->ioc_inllen1, ptr);
        if (data->ioc_inlbuf2)
                LOGU(data->ioc_inlbuf2, data->ioc_inllen2, ptr);
        if (data->ioc_inlbuf3)
                LOGU(data->ioc_inlbuf3, data->ioc_inllen3, ptr);
        if (data->ioc_inlbuf4)
                LOGU(data->ioc_inlbuf4, data->ioc_inllen4, ptr);

        return 0;
}
#endif

#include <linux/obd_support.h>

/* buffer MUST be at least the size of obd_ioctl_hdr */
static inline int obd_ioctl_getdata(char **buf, int *len, void *arg)
{
        struct obd_ioctl_hdr hdr;
        struct obd_ioctl_data *data;
        int err;
        int offset = 0;
        ENTRY;

        err = copy_from_user(&hdr, (void *)arg, sizeof(hdr));
        if ( err ) {
                EXIT;
                return err;
        }

        if (hdr.ioc_version != OBD_IOCTL_VERSION) {
                CERROR("Version mismatch kernel vs application\n");
                return -EINVAL;
        }

        if (hdr.ioc_len > OBD_MAX_IOCTL_BUFFER) {
                CERROR("User buffer len %d exceeds %d max buffer\n",
                       hdr.ioc_len, OBD_MAX_IOCTL_BUFFER);
                return -EINVAL;
        }

        if (hdr.ioc_len < sizeof(struct obd_ioctl_data)) {
                printk("LustreError: OBD: user buffer too small for ioctl\n");
                return -EINVAL;
        }

        /* XXX allocate this more intelligently, using kmalloc when
         * appropriate */
        OBD_VMALLOC(*buf, hdr.ioc_len);
        if (*buf == NULL) {
                CERROR("Cannot allocate control buffer of len %d\n",
                       hdr.ioc_len);
                RETURN(-EINVAL);
        }
        *len = hdr.ioc_len;
        data = (struct obd_ioctl_data *)*buf;

        err = copy_from_user(*buf, (void *)arg, hdr.ioc_len);
        if ( err ) {
                EXIT;
                return err;
        }

        if (obd_ioctl_is_invalid(data)) {
                CERROR("ioctl not correctly formatted\n");
                return -EINVAL;
        }

        if (data->ioc_inllen1) {
                data->ioc_inlbuf1 = &data->ioc_bulk[0];
                offset += size_round(data->ioc_inllen1);
        }

        if (data->ioc_inllen2) {
                data->ioc_inlbuf2 = &data->ioc_bulk[0] + offset;
                offset += size_round(data->ioc_inllen2);
        }

        if (data->ioc_inllen3) {
                data->ioc_inlbuf3 = &data->ioc_bulk[0] + offset;
                offset += size_round(data->ioc_inllen3);
        }

        if (data->ioc_inllen4) {
                data->ioc_inlbuf4 = &data->ioc_bulk[0] + offset;
        }

        EXIT;
        return 0;
}

static inline void obd_ioctl_freedata(char *buf, int len)
{
        ENTRY;

        OBD_VFREE(buf, len);
        EXIT;
        return;
}

#define OBD_IOC_CREATE                 _IOR ('f', 101, long)
#define OBD_IOC_DESTROY                _IOW ('f', 104, long)
#define OBD_IOC_PREALLOCATE            _IOWR('f', 105, long)

#define OBD_IOC_SETATTR                _IOW ('f', 107, long)
#define OBD_IOC_GETATTR                _IOR ('f', 108, long)
#define OBD_IOC_READ                   _IOWR('f', 109, long)
#define OBD_IOC_WRITE                  _IOWR('f', 110, long)


#define OBD_IOC_STATFS                 _IOWR('f', 113, long)
#define OBD_IOC_SYNC                   _IOR ('f', 114, long)
#define OBD_IOC_READ2                  _IOWR('f', 115, long)
#define OBD_IOC_FORMAT                 _IOWR('f', 116, long)
#define OBD_IOC_PARTITION              _IOWR('f', 117, long)
#define OBD_IOC_COPY                   _IOWR('f', 120, long)
#define OBD_IOC_MIGR                   _IOWR('f', 121, long)
#define OBD_IOC_PUNCH                  _IOWR('f', 122, long)

#define OBD_IOC_MODULE_DEBUG           _IOWR('f', 124, long)
#define OBD_IOC_BRW_READ               _IOWR('f', 125, long)
#define OBD_IOC_BRW_WRITE              _IOWR('f', 126, long)
#define OBD_IOC_NAME2DEV               _IOWR('f', 127, long)
#define OBD_IOC_UUID2DEV               _IOWR('f', 130, long)

#define OBD_IOC_LOV_GET_CONFIG         _IOWR('f', 132, long)
#define OBD_IOC_CLIENT_RECOVER         _IOW ('f', 133, long)

#define OBD_IOC_PING                   _IOWR('f', 135, long)

#define OBD_IOC_DEC_FS_USE_COUNT       _IO  ('f', 139      )
#define OBD_IOC_NO_TRANSNO             _IOW ('f', 140, long)
#define OBD_IOC_SET_READONLY           _IOW ('f', 141, long)
#define OBD_IOC_ABORT_RECOVERY         _IOR ('f', 142, long)

#define OBD_GET_VERSION                _IOWR ('f', 144, long)

#define OBD_IOC_CLOSE_UUID             _IOWR ('f', 147, long)

#define OBD_IOC_LOV_SETSTRIPE            _IOW ('f', 154, long)
#define OBD_IOC_LOV_GETSTRIPE            _IOW ('f', 155, long)

#define OBD_IOC_MOUNTOPT               _IOWR('f', 170, long)

#define OBD_IOC_RECORD                 _IOWR('f', 180, long)
#define OBD_IOC_ENDRECORD              _IOWR('f', 181, long)
#define OBD_IOC_PARSE                  _IOWR('f', 182, long)
#define OBD_IOC_DORECORD               _IOWR('f', 183, long)
#define OBD_IOC_PROCESS_CFG            _IOWR('f', 184, long)
#define OBD_IOC_DUMP_LOG               _IOWR('f', 185, long)

#define OBD_IOC_CATLOGLIST             _IOWR('f', 190, long)
#define OBD_IOC_LLOG_INFO              _IOWR('f', 191, long)
#define OBD_IOC_LLOG_PRINT             _IOWR('f', 192, long)
#define OBD_IOC_LLOG_CANCEL            _IOWR('f', 193, long)
#define OBD_IOC_LLOG_REMOVE            _IOWR('f', 194, long)
#define OBD_IOC_LLOG_CHECK             _IOWR('f', 195, long)
#define OBD_IOC_LLOG_CATINFO           _IOWR('f', 196, long)

#define ECHO_IOC_GET_STRIPE            _IOWR('f', 200, long)
#define ECHO_IOC_SET_STRIPE            _IOWR('f', 201, long)
#define ECHO_IOC_ENQUEUE               _IOWR('f', 202, long)
#define ECHO_IOC_CANCEL                _IOWR('f', 203, long)

/* XXX _IOWR('f', 250, long) has been defined in
 * portals/include/linux/kp30.h for debug, don't use it
 */

/* Until such time as we get_info the per-stripe maximum from the OST,
 * we define this to be 2T - 4k, which is the ext3 maxbytes. */
#define LUSTRE_STRIPE_MAXBYTES 0x1fffffff000ULL

#define CHECKSUM_BULK 0
#define POISON_BULK 0

#if CHECKSUM_BULK
static inline void ost_checksum(obd_count *cksum, void *addr, int len)
{
        unsigned char *ptr = (unsigned char *)addr;
        obd_count          sum = 0;

        /* very stupid, but means I don't have to think about byte order */
        while (len-- > 0)
                sum += *ptr++;

        *cksum = (*cksum << 2) + sum;
}
#endif

static inline int ll_insecure_random_int(void)
{
#ifdef __arch_um__
        struct timeval t;
        do_gettimeofday(&t);
        return (int)(t.tv_usec);
#else
        return (int)(get_cycles() >> 2);
#endif
}

/*
 * l_wait_event is a flexible sleeping function, permitting simple caller
 * configuration of interrupt and timeout sensitivity along with actions to
 * be performed in the event of either exception.
 *
 * Common usage looks like this:
 *
 * struct l_wait_info lwi = LWI_TIMEOUT_INTR(timeout, timeout_handler,
 *                                           intr_handler, callback_data);
 * rc = l_wait_event(waitq, condition, &lwi);
 *
 * (LWI_TIMEOUT and LWI_INTR macros are available for timeout- and
 * interrupt-only variants, respectively.)
 *
 * If a timeout is specified, the timeout_handler will be invoked in the event
 * that the timeout expires before the process is awakened.  (Note that any
 * waking of the process will restart the timeout, even if the condition is
 * not satisfied and the process immediately returns to sleep.  This might be
 * considered a bug.)  If the timeout_handler returns non-zero, l_wait_event
 * will return -ETIMEDOUT and the caller will continue.  If the handler returns
 * zero instead, the process will go back to sleep until it is awakened by the
 * waitq or some similar mechanism, or an interrupt occurs (if the caller has
 * asked for interrupts to be detected).  The timeout will only fire once, so
 * callers should take care that a timeout_handler which returns zero will take
 * future steps to awaken the process.  N.B. that these steps must include
 * making the provided condition become true.
 *
 * If the interrupt flag (lwi_signals) is non-zero, then the process will be
 * interruptible, and will be awakened by any "killable" signal (SIGTERM,
 * SIGKILL or SIGINT).  If a timeout is also specified, then the process will
 * only become interruptible _after_ the timeout has expired, though it can be
 * awakened by a signal that was delivered before the timeout and is still
 * pending when the timeout expires.  If a timeout is not specified, the process
 * will be interruptible at all times during l_wait_event.
 */

struct l_wait_info {
        long   lwi_timeout;
        int  (*lwi_on_timeout)(void *);
        long   lwi_signals;
        void (*lwi_on_signal)(void *);
        void  *lwi_cb_data;
};

#define LWI_TIMEOUT(time, cb, data)                                            \
((struct l_wait_info) {                                                        \
        lwi_timeout:    time,                                                  \
        lwi_on_timeout: cb,                                                    \
        lwi_cb_data:    data                                                   \
})

#define LWI_INTR(cb, data)                                                     \
((struct l_wait_info) {                                                        \
        lwi_signals:   1,                                                      \
        lwi_on_signal: cb,                                                     \
        lwi_cb_data:   data                                                    \
})

#define LWI_TIMEOUT_INTR(time, time_cb, sig_cb, data)                          \
((struct l_wait_info) {                                                        \
        lwi_timeout:    time,                                                  \
        lwi_on_timeout: time_cb,                                               \
        lwi_signals:    1,                                                     \
        lwi_on_signal:  sig_cb,                                                \
        lwi_cb_data:    data                                                   \
})

#define LUSTRE_FATAL_SIGS (sigmask(SIGKILL) | sigmask(SIGINT) |                \
                           sigmask(SIGTERM) | sigmask(SIGQUIT) |               \
                           sigmask(SIGALRM))

#ifdef __KERNEL__
static inline sigset_t l_w_e_set_sigs(int sigs)
{
        sigset_t old;
        unsigned long irqflags;

        SIGNAL_MASK_LOCK(current, irqflags);
        old = current->blocked;
        siginitsetinv(&current->blocked, sigs);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, irqflags);

        return old;
}

#define __l_wait_event(wq, condition, info, ret, excl)                         \
do {                                                                           \
        wait_queue_t __wait;                                                   \
        int __timed_out = 0;                                                   \
        unsigned long irqflags;                                                \
        sigset_t blocked;                                                      \
                                                                               \
        init_waitqueue_entry(&__wait, current);                                \
        if (excl)                                                              \
            add_wait_queue_exclusive(&wq, &__wait);                            \
        else                                                                   \
            add_wait_queue(&wq, &__wait);                                      \
                                                                               \
        /* Block all signals (just the non-fatal ones if no timeout). */       \
        if (info->lwi_signals && !info->lwi_timeout)                           \
            blocked = l_w_e_set_sigs(LUSTRE_FATAL_SIGS);                       \
        else                                                                   \
            blocked = l_w_e_set_sigs(0);                                       \
                                                                               \
        for (;;) {                                                             \
            set_current_state(TASK_INTERRUPTIBLE);                             \
            if (condition)                                                     \
                    break;                                                     \
            if (signal_pending(current)) {                                     \
                if (info->lwi_on_signal)                                       \
                        info->lwi_on_signal(info->lwi_cb_data);                \
                ret = -EINTR;                                                  \
                break;                                                         \
            }                                                                  \
            if (info->lwi_timeout && !__timed_out) {                           \
                if (schedule_timeout(info->lwi_timeout) == 0) {                \
                    __timed_out = 1;                                           \
                    if (!info->lwi_on_timeout ||                               \
                        info->lwi_on_timeout(info->lwi_cb_data)) {             \
                        ret = -ETIMEDOUT;                                      \
                        break;                                                 \
                    }                                                          \
                    /* We'll take signals after a timeout. */                  \
                    if (info->lwi_signals)                                     \
                        (void)l_w_e_set_sigs(LUSTRE_FATAL_SIGS);               \
                }                                                              \
            } else {                                                           \
                schedule();                                                    \
            }                                                                  \
        }                                                                      \
                                                                               \
        SIGNAL_MASK_LOCK(current, irqflags);                                   \
        current->blocked = blocked;                                            \
        RECALC_SIGPENDING;                                                     \
        SIGNAL_MASK_UNLOCK(current, irqflags);                                 \
                                                                               \
        current->state = TASK_RUNNING;                                         \
        remove_wait_queue(&wq, &__wait);                                       \
} while(0)

#else /* !__KERNEL__ */
#define __l_wait_event(wq, condition, info, ret, excl)                         \
do {                                                                           \
        int __timed_out = 0;                                                   \
                                                                               \
        for (;;) {                                                             \
            if (condition)                                                     \
                break;                                                         \
            if (liblustre_wait_event(info->lwi_timeout))                       \
                continue;                                                      \
            if (info->lwi_timeout && !__timed_out) {                           \
                __timed_out = 1;                                               \
                if (info->lwi_on_timeout == NULL ||                            \
                    info->lwi_on_timeout(info->lwi_cb_data)) {                 \
                    ret = -ETIMEDOUT;                                          \
                    break;                                                     \
                }                                                              \
            }                                                                  \
        }                                                                      \
} while (0)

#endif /* __KERNEL__ */

#define l_wait_event(wq, condition, info)                                      \
({                                                                             \
        int __ret = 0;                                                         \
        struct l_wait_info *__info = (info);                                   \
        if (!(condition))                                                      \
                __l_wait_event(wq, condition, __info, __ret, 0);               \
        __ret;                                                                 \
})

#define l_wait_event_exclusive(wq, condition, info)                            \
({                                                                             \
        int __ret = 0;                                                         \
        struct l_wait_info *__info = (info);                                   \
        if (!(condition))                                                      \
                __l_wait_event(wq, condition, __info, __ret, 1);               \
        __ret;                                                                 \
})

#endif /* _LUSTRE_LIB_H */
