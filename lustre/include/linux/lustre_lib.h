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

#ifndef __KERNEL__
# include <string.h>
#else
# include <asm/semaphore.h>
#endif
#include <linux/types.h>
#include <linux/portals_lib.h>
#include <linux/kp30.h> /* XXX just for LASSERT! */
#include <linux/lustre_idl.h>

#ifndef LPU64
#if BITS_PER_LONG > 32
#define LPU64 "%lu"
#define LPD64 "%ld"
#define LPX64 "%#lx"
#else
#define LPU64 "%Lu"
#define LPD64 "%Ld"
#define LPX64 "%#Lx"
#endif
#endif

#ifdef __KERNEL__
/* l_net.c */
struct ptlrpc_request;
struct obd_device;
struct recovd_data;
struct recovd_obd;
struct obd_export;
#include <linux/lustre_ha.h>

int target_handle_connect(struct ptlrpc_request *req);
int target_handle_disconnect(struct ptlrpc_request *req);
int target_handle_reconnect(struct lustre_handle *conn, struct obd_export *exp,
                            char *cluuid);
int client_obd_connect(struct lustre_handle *conn, struct obd_device *obd,
                       obd_uuid_t cluuid, struct recovd_obd *recovd,
                       ptlrpc_recovery_cb_t recover);
int client_obd_disconnect(struct lustre_handle *conn);
int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf);
int client_obd_cleanup(struct obd_device * obddev);
struct client_obd *client_conn2cli(struct lustre_handle *conn); 
struct obd_device *client_tgtuuid2obd(char *tgtuuid);

int target_revoke_connection(struct recovd_data *rd, int phase);

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

#define CB_PHASE_START   12
#define CB_PHASE_FINISH  13

/* This list head doesn't need to be locked, because it's only manipulated by
 * one thread at a time. */
struct obd_brw_set {
        struct list_head brw_desc_head; /* list of ptlrpc_bulk_desc */
        wait_queue_head_t brw_waitq;
        atomic_t brw_refcount;
        int brw_flags;

        int (*brw_callback)(struct obd_brw_set *, int phase);
};

/* simple.c */
struct obd_run_ctxt;
struct obd_ucred;
void push_ctxt(struct obd_run_ctxt *save, struct obd_run_ctxt *new_ctx,
               struct obd_ucred *cred);
void pop_ctxt(struct obd_run_ctxt *saved, struct obd_run_ctxt *new_ctx,
              struct obd_ucred *cred);
struct dentry *simple_mkdir(struct dentry *dir, char *name, int mode);
struct dentry *simple_mknod(struct dentry *dir, char *name, int mode);
int lustre_fread(struct file *file, char *str, int len, loff_t *off);
int lustre_fwrite(struct file *file, const char *str, int len, loff_t *off);
int lustre_fsync(struct file *file);

static inline void l_dput(struct dentry *de)
{
        if (!de || IS_ERR(de))
                return;
        shrink_dcache_parent(de);
        LASSERT(atomic_read(&de->d_count) > 0);
        dput(de);
}

static inline void ll_sleep(int t)
{
        set_current_state(TASK_INTERRUPTIBLE);
        schedule_timeout(t * HZ);
        set_current_state(TASK_RUNNING);
}
#endif

/* FIXME: This needs to validate pointers and cookies */
static inline void *lustre_handle2object(struct lustre_handle *handle)
{
        if (handle) 
                return (void *)(unsigned long)(handle->addr);
        return NULL; 
}

static inline void ldlm_object2handle(void *object, struct lustre_handle *handle)
{
        handle->addr = (__u64)(unsigned long)object;
}

#include <linux/portals_lib.h>

/*
 *   OBD IOCTLS
 */
#define OBD_IOCTL_VERSION 0x00010001

struct obd_ioctl_data {
        uint32_t ioc_len;
        uint32_t ioc_version;

        uint64_t ioc_addr;
        uint64_t ioc_cookie;
        uint32_t ioc_conn1;
        uint32_t ioc_conn2;

        struct obdo ioc_obdo1;
        struct obdo ioc_obdo2;

        obd_size         ioc_count;
        obd_off          ioc_offset;
        uint32_t         ioc_dev;
        uint32_t         ____padding;

        /* buffers the kernel will treat as user pointers */
        uint32_t ioc_plen1;
        char    *ioc_pbuf1;
        uint32_t ioc_plen2;
        char    *ioc_pbuf2;

        /* two inline buffers */
        uint32_t ioc_inllen1;
        char    *ioc_inlbuf1;
        uint32_t ioc_inllen2;
        char    *ioc_inlbuf2;
        uint32_t ioc_inllen3;
        char    *ioc_inlbuf3;

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
        return len;
}


static inline int obd_ioctl_is_invalid(struct obd_ioctl_data *data)
{
        if (data->ioc_len > (1<<30)) {
                printk("OBD ioctl: ioc_len larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen1 > (1<<30)) {
                printk("OBD ioctl: ioc_inllen1 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen2 > (1<<30)) {
                printk("OBD ioctl: ioc_inllen2 larger than 1<<30\n");
                return 1;
        }

        if (data->ioc_inllen3 > (1<<30)) {
                printk("OBD ioctl: ioc_inllen3 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inlbuf1 && !data->ioc_inllen1) {
                printk("OBD ioctl: inlbuf1 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_inlbuf2 && !data->ioc_inllen2) {
                printk("OBD ioctl: inlbuf2 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_inlbuf3 && !data->ioc_inllen3) {
                printk("OBD ioctl: inlbuf3 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_pbuf1 && !data->ioc_plen1) {
                printk("OBD ioctl: pbuf1 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_pbuf2 && !data->ioc_plen2) {
                printk("OBD ioctl: pbuf2 pointer but 0 length\n");
                return 1;
        }
        /*
        if (data->ioc_inllen1 && !data->ioc_inlbuf1) {
                printk("OBD ioctl: inllen1 set but NULL pointer\n");
                return 1;
        }
        if (data->ioc_inllen2 && !data->ioc_inlbuf2) {
                printk("OBD ioctl: inllen2 set but NULL pointer\n");
                return 1;
        }
        if (data->ioc_inllen3 && !data->ioc_inlbuf3) {
                printk("OBD ioctl: inllen3 set but NULL pointer\n");
                return 1;
        }
        */
        if (data->ioc_plen1 && !data->ioc_pbuf1) {
                printk("OBD ioctl: plen1 set but NULL pointer\n");
                return 1;
        }
        if (data->ioc_plen2 && !data->ioc_pbuf2) {
                printk("OBD ioctl: plen2 set but NULL pointer\n");
                return 1;
        }
        if (obd_ioctl_packlen(data) != data->ioc_len ) {
                printk("OBD ioctl: packlen exceeds ioc_len\n");
                return 1;
        }
#if 0
        if (data->ioc_inllen1 &&
            data->ioc_bulk[data->ioc_inllen1 - 1] != '\0') {
                printk("OBD ioctl: inlbuf1 not 0 terminated\n");
                return 1;
        }
        if (data->ioc_inllen2 &&
            data->ioc_bulk[size_round(data->ioc_inllen1) + data->ioc_inllen2 - 1] != '\0') {
                printk("OBD ioctl: inlbuf2 not 0 terminated\n");
                return 1;
        }
        if (data->ioc_inllen3 &&
            data->ioc_bulk[size_round(data->ioc_inllen1) + size_round(data->ioc_inllen2)
                           + data->ioc_inllen3 - 1] != '\0') {
                printk("OBD ioctl: inlbuf3 not 0 terminated\n");
                return 1;
        }
#endif 
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

        memcpy(data, pbuf, sizeof(*data));

        ptr = overlay->ioc_bulk;
        if (data->ioc_inlbuf1)
                LOGU(data->ioc_inlbuf1, data->ioc_inllen1, ptr);
        if (data->ioc_inlbuf2)
                LOGU(data->ioc_inlbuf2, data->ioc_inllen2, ptr);
        if (data->ioc_inlbuf3)
                LOGU(data->ioc_inlbuf3, data->ioc_inllen3, ptr);

        return 0;
}
#else

#include <linux/obd_support.h>

/* buffer MUST be at least the size of obd_ioctl_hdr */
static inline int obd_ioctl_getdata(char **buf, int *len, void *arg)
{
        struct obd_ioctl_hdr hdr;
        struct obd_ioctl_data *data;
        int err;
        ENTRY;

        err = copy_from_user(&hdr, (void *)arg, sizeof(hdr));
        if ( err ) {
                EXIT;
                return err;
        }

        if (hdr.ioc_version != OBD_IOCTL_VERSION) {
                printk("OBD: version mismatch kernel vs application\n");
                return -EINVAL;
        }

        if (hdr.ioc_len > 8192) {
                printk("OBD: user buffer exceeds 8192 max buffer\n");
                return -EINVAL;
        }

        if (hdr.ioc_len < sizeof(struct obd_ioctl_data)) {
                printk("OBD: user buffer too small for ioctl\n");
                return -EINVAL;
        }

        OBD_ALLOC(*buf, hdr.ioc_len);
        if (!*buf) {
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
                printk("OBD: ioctl not correctly formatted\n");
                return -EINVAL;
        }

        if (data->ioc_inllen1) {
                data->ioc_inlbuf1 = &data->ioc_bulk[0];
        }

        if (data->ioc_inllen2) {
                data->ioc_inlbuf2 = &data->ioc_bulk[0] +
                        size_round(data->ioc_inllen1);
        }

        if (data->ioc_inllen3) {
                data->ioc_inlbuf3 = &data->ioc_bulk[0] +
                        size_round(data->ioc_inllen1) +
                        size_round(data->ioc_inllen2);
        }

        EXIT;
        return 0;
}
#endif

#define OBD_IOC_CREATE                 _IOR ('f', 101, long)
#define OBD_IOC_SETUP                  _IOW ('f', 102, long)
#define OBD_IOC_CLEANUP                _IO  ('f', 103      )
#define OBD_IOC_DESTROY                _IOW ('f', 104, long)
#define OBD_IOC_PREALLOCATE            _IOWR('f', 105, long)

#define OBD_IOC_SETATTR                _IOW ('f', 107, long)
#define OBD_IOC_GETATTR                _IOR ('f', 108, long)
#define OBD_IOC_READ                   _IOWR('f', 109, long)
#define OBD_IOC_WRITE                  _IOWR('f', 110, long)
#define OBD_IOC_CONNECT                _IOR ('f', 111, long)
#define OBD_IOC_DISCONNECT             _IOW ('f', 112, long)
#define OBD_IOC_STATFS                 _IOWR('f', 113, long)
#define OBD_IOC_SYNC                   _IOR ('f', 114, long)
#define OBD_IOC_READ2                  _IOWR('f', 115, long)
#define OBD_IOC_FORMAT                 _IOWR('f', 116, long)
#define OBD_IOC_PARTITION              _IOWR('f', 117, long)
#define OBD_IOC_ATTACH                 _IOWR('f', 118, long)
#define OBD_IOC_DETACH                 _IOWR('f', 119, long)
#define OBD_IOC_COPY                   _IOWR('f', 120, long)
#define OBD_IOC_MIGR                   _IOWR('f', 121, long)
#define OBD_IOC_PUNCH                  _IOWR('f', 122, long)
#define OBD_IOC_DEVICE                 _IOWR('f', 123, long)
#define OBD_IOC_MODULE_DEBUG           _IOWR('f', 124, long)
#define OBD_IOC_BRW_READ               _IOWR('f', 125, long)
#define OBD_IOC_BRW_WRITE              _IOWR('f', 126, long)
#define OBD_IOC_NAME2DEV               _IOWR('f', 127, long)
#define OBD_IOC_NEWDEV                 _IOWR('f', 128, long)
#define OBD_IOC_LIST                   _IOWR('f', 129, long)
#define OBD_IOC_UUID2DEV               _IOWR('f', 130, long)

#define OBD_IOC_RECOVD_NEWCONN         _IOWR('f', 131, long)
#define OBD_IOC_LOV_SET_CONFIG         _IOWR('f', 132, long)
#define OBD_IOC_LOV_GET_CONFIG         _IOWR('f', 133, long)
#define OBD_IOC_LOV_CONFIG             OBD_IOC_LOV_SET_CONFIG

#define OBD_IOC_OPEN                   _IOWR('f', 134, long)
#define OBD_IOC_CLOSE                  _IOWR('f', 135, long)

#define OBD_IOC_RECOVD_FAILCONN        _IOWR('f', 136, long)

#define OBD_IOC_DEC_FS_USE_COUNT       _IO  ('f', 139      )

#define OBD_GET_VERSION                _IOWR ('f', 144, long)

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
        int  (*lwi_on_signal)(void *); /* XXX return is ignored for now */
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

/* XXX this should be one mask-check */
#define l_killable_pending(task)                                               \
(sigismember(&(task->pending.signal), SIGKILL) ||                              \
 sigismember(&(task->pending.signal), SIGINT) ||                               \
 sigismember(&(task->pending.signal), SIGTERM))

#define __l_wait_event(wq, condition, info, ret)                               \
do {                                                                           \
        wait_queue_t __wait;                                                   \
        long __state;                                                          \
        int __timed_out = 0;                                                   \
        init_waitqueue_entry(&__wait, current);                                \
                                                                               \
        add_wait_queue(&wq, &__wait);                                          \
        if (info->lwi_signals && !info->lwi_timeout)                           \
            __state = TASK_INTERRUPTIBLE;                                      \
        else                                                                   \
            __state = TASK_UNINTERRUPTIBLE;                                    \
        for (;;) {                                                             \
            set_current_state(__state);                                        \
            if (condition)                                                     \
                    break;                                                     \
            if (__state == TASK_INTERRUPTIBLE && l_killable_pending(current)) {\
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
                    if (info->lwi_signals) {                                   \
                        __state = TASK_INTERRUPTIBLE;                          \
                        /* Check for a pending interrupt. */                   \
                        if (info->lwi_signals && l_killable_pending(current)) {\
                            if (info->lwi_on_signal)                           \
                                info->lwi_on_signal(info->lwi_cb_data);        \
                            ret = -EINTR;                                      \
                            break;                                             \
                        }                                                      \
                    }                                                          \
                }                                                              \
            } else {                                                           \
                schedule();                                                    \
            }                                                                  \
        }                                                                      \
        current->state = TASK_RUNNING;                                         \
        remove_wait_queue(&wq, &__wait);                                       \
} while(0)

#define l_wait_event(wq, condition, info)                                      \
({                                                                             \
        int __ret = 0;                                                         \
        struct l_wait_info *__info = (info);                                   \
        if (!(condition))                                                      \
                __l_wait_event(wq, condition, __info, __ret);                  \
        __ret;                                                                 \
})

#endif /* _LUSTRE_LIB_H */
