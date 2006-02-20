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
# include <sys/types.h>
#else
# include <asm/semaphore.h>
# include <linux/rwsem.h>
# include <linux/sched.h>
# include <linux/signal.h>
# include <linux/types.h>
#endif
#include <libcfs/kp30.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_cfg.h>

#ifndef LP_POISON
#if BITS_PER_LONG > 32
# define LI_POISON ((int)0x5a5a5a5a5a5a5a5a)
# define LL_POISON ((long)0x5a5a5a5a5a5a5a5a)
# define LP_POISON ((void *)(long)0x5a5a5a5a5a5a5a5a)
#else
# define LI_POISON ((int)0x5a5a5a5a)
# define LL_POISON ((long)0x5a5a5a5a)
# define LP_POISON ((void *)(long)0x5a5a5a5a)
#endif
#endif

/* prng.c */
unsigned int ll_rand(void);        /* returns a random 32-bit integer */
void ll_srand(unsigned int, unsigned int);     /* seed the generator */

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
void target_committed_to_req(struct ptlrpc_request *req);

#ifdef HAVE_QUOTA_SUPPORT
/* quotacheck callback, dqacq/dqrel callback handler */
int target_handle_qc_callback(struct ptlrpc_request *req);
int target_handle_dqacq_callback(struct ptlrpc_request *req);
#else
#define target_handle_dqacq_callback(req) ldlm_callback_reply(req, -ENOTSUPP)
#define target_handle_qc_callback(req) (0)
#endif

void target_cancel_recovery_timer(struct obd_device *obd);

#define OBD_RECOVERY_TIMEOUT (obd_timeout * 5 * HZ / 2) /* *waves hands* */
void target_start_recovery_timer(struct obd_device *obd, svc_handler_t handler);
void target_abort_recovery(void *data);
void target_cleanup_recovery(struct obd_device *obd);
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
                CERROR("OBD ioctl: ioc_len larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen1 > (1<<30)) {
                CERROR("OBD ioctl: ioc_inllen1 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen2 > (1<<30)) {
                CERROR("OBD ioctl: ioc_inllen2 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen3 > (1<<30)) {
                CERROR("OBD ioctl: ioc_inllen3 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen4 > (1<<30)) {
                CERROR("OBD ioctl: ioc_inllen4 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inlbuf1 && !data->ioc_inllen1) {
                CERROR("OBD ioctl: inlbuf1 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_inlbuf2 && !data->ioc_inllen2) {
                CERROR("OBD ioctl: inlbuf2 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_inlbuf3 && !data->ioc_inllen3) {
                CERROR("OBD ioctl: inlbuf3 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_inlbuf4 && !data->ioc_inllen4) {
                CERROR("OBD ioctl: inlbuf4 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_pbuf1 && !data->ioc_plen1) {
                CERROR("OBD ioctl: pbuf1 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_pbuf2 && !data->ioc_plen2) {
                CERROR("OBD ioctl: pbuf2 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_plen1 && !data->ioc_pbuf1) {
                CERROR("OBD ioctl: plen1 set but NULL pointer\n");
                return 1;
        }
        if (data->ioc_plen2 && !data->ioc_pbuf2) {
                CERROR("OBD ioctl: plen2 set but NULL pointer\n");
                return 1;
        }
        if (obd_ioctl_packlen(data) > data->ioc_len) {
                CERROR("OBD ioctl: packlen exceeds ioc_len (%d > %d)\n",
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
        if (err)
                RETURN(err);

        if (hdr.ioc_version != OBD_IOCTL_VERSION) {
                CERROR("Version mismatch kernel vs application\n");
                RETURN(-EINVAL);
        }

        if (hdr.ioc_len > OBD_MAX_IOCTL_BUFFER) {
                CERROR("User buffer len %d exceeds %d max buffer\n",
                       hdr.ioc_len, OBD_MAX_IOCTL_BUFFER);
                RETURN(-EINVAL);
        }

        if (hdr.ioc_len < sizeof(struct obd_ioctl_data)) {
                CERROR("user buffer too small for ioctl (%d)\n", hdr.ioc_len);
                RETURN(-EINVAL);
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
        if (err) {
                OBD_VFREE(*buf, hdr.ioc_len);
                RETURN(err);
        }

        if (obd_ioctl_is_invalid(data)) {
                CERROR("ioctl not correctly formatted\n");
                OBD_VFREE(*buf, hdr.ioc_len);
                RETURN(-EINVAL);
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

        RETURN(0);
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
#define OBD_IOC_SYNC                   _IOW ('f', 114, long)
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
#define OBD_IOC_GETNAME                _IOR ('f', 131, long)

#define OBD_IOC_LOV_GET_CONFIG         _IOWR('f', 132, long)
#define OBD_IOC_CLIENT_RECOVER         _IOW ('f', 133, long)

#define OBD_IOC_DEC_FS_USE_COUNT       _IO  ('f', 139      )
#define OBD_IOC_NO_TRANSNO             _IOW ('f', 140, long)
#define OBD_IOC_SET_READONLY           _IOW ('f', 141, long)
#define OBD_IOC_ABORT_RECOVERY         _IOR ('f', 142, long)

#define OBD_GET_VERSION                _IOWR ('f', 144, long)

#define OBD_IOC_CLOSE_UUID             _IOWR ('f', 147, long)

#define OBD_IOC_LOV_SETSTRIPE          _IOW ('f', 154, long)
#define OBD_IOC_LOV_GETSTRIPE          _IOW ('f', 155, long)
#define OBD_IOC_LOV_SETEA              _IOW ('f', 156, long)

#define OBD_IOC_QUOTACHECK             _IOW ('f', 160, int)
#define OBD_IOC_POLL_QUOTACHECK        _IOR ('f', 161, struct if_quotacheck *)
#define OBD_IOC_QUOTACTL               _IOWR('f', 162, struct if_quotactl *)

#define OBD_IOC_MOUNTOPT               _IOWR('f', 170, long)

#define OBD_IOC_RECORD                 _IOWR('f', 180, long)
#define OBD_IOC_ENDRECORD              _IOWR('f', 181, long)
#define OBD_IOC_PARSE                  _IOWR('f', 182, long)
#define OBD_IOC_DORECORD               _IOWR('f', 183, long)
#define OBD_IOC_PROCESS_CFG            _IOWR('f', 184, long)
#define OBD_IOC_DUMP_LOG               _IOWR('f', 185, long)
#define OBD_IOC_CLEAR_LOG              _IOWR('f', 186, long)
#define OBD_IOC_PARAM                  _IOW ('f', 187, long)

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
 * lnet/include/libcfs/kp30.h for debug, don't use it
 */

/* Until such time as we get_info the per-stripe maximum from the OST,
 * we define this to be 2T - 4k, which is the ext3 maxbytes. */
#define LUSTRE_STRIPE_MAXBYTES 0x1fffffff000ULL

#define POISON_BULK 0

/*
 * l_wait_event is a flexible sleeping function, permitting simple caller
 * configuration of interrupt and timeout sensitivity along with actions to
 * be performed in the event of either exception.
 *
 * The first form of usage looks like this:
 *
 * struct l_wait_info lwi = LWI_TIMEOUT_INTR(timeout, timeout_handler,
 *                                           intr_handler, callback_data);
 * rc = l_wait_event(waitq, condition, &lwi);
 *
 * l_wait_event() makes the current process wait on 'waitq' until 'condition'
 * is TRUE or a "killable" signal (SIGTERM, SIKGILL, SIGINT) is pending.  It
 * returns 0 to signify 'condition' is TRUE, but if a signal wakes it before
 * 'condition' becomes true, it optionally calls the specified 'intr_handler'
 * if not NULL, and returns -EINTR.
 *
 * If a non-zero timeout is specified, signals are ignored until the timeout
 * has expired.  At this time, if 'timeout_handler' is not NULL it is called.
 * If it returns FALSE l_wait_event() continues to wait as described above with
 * signals enabled.  Otherwise it returns -ETIMEDOUT.
 *
 * LWI_INTR(intr_handler, callback_data) is shorthand for 
 * LWI_TIMEOUT_INTR(0, NULL, intr_handler, callback_data)
 *
 * The second form of usage looks like this:
 *
 * struct l_wait_info lwi = LWI_TIMEOUT(timeout, timeout_handler);
 * rc = l_wait_event(waitq, condition, &lwi);
 *
 * This form is the same as the first except that it COMPLETELY IGNORES
 * SIGNALS.  The caller must therefore beware that if 'timeout' is zero, or if
 * 'timeout_handler' is not NULL and returns FALSE, then the ONLY thing that
 * can unblock the current process is 'condition' becoming TRUE.
 *
 * Another form of usage is:
 * struct l_wait_info lwi = LWI_TIMEOUT_INTERVAL(timeout, interval,
 *                                               timeout_handler);
 * rc = l_wait_event(waitq, condition, &lwi);
 * This is the same as previous case, but condition is checked once every
 * 'interval' jiffies (if non-zero).
 *
 */

#define LWI_ON_SIGNAL_NOOP ((void (*)(void *))(-1))

struct l_wait_info {
        long   lwi_timeout;
        long   lwi_interval;
        int  (*lwi_on_timeout)(void *);
        void (*lwi_on_signal)(void *);
        void  *lwi_cb_data;
};

/* NB: LWI_TIMEOUT ignores signals completely */
#define LWI_TIMEOUT(time, cb, data)             \
((struct l_wait_info) {                         \
        .lwi_timeout    = time,                 \
        .lwi_on_timeout = cb,                   \
        .lwi_cb_data    = data,                 \
        .lwi_interval   = 0                     \
})

#define LWI_TIMEOUT_INTERVAL(time, interval, cb, data)  \
((struct l_wait_info) {                                 \
        .lwi_timeout    = time,                         \
        .lwi_on_timeout = cb,                           \
        .lwi_cb_data    = data,                         \
        .lwi_interval   = interval                      \
})


#define LWI_TIMEOUT_INTR(time, time_cb, sig_cb, data)                          \
((struct l_wait_info) {                                                        \
        .lwi_timeout    = time,                                                \
        .lwi_on_timeout = time_cb,                                             \
        .lwi_on_signal = (sig_cb == NULL) ? LWI_ON_SIGNAL_NOOP : sig_cb,       \
        .lwi_cb_data    = data,                                                \
        .lwi_interval    = 0                                                   \
})

#define LWI_INTR(cb, data)  LWI_TIMEOUT_INTR(0, NULL, cb, data)

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
        wait_queue_t  __wait;                                                  \
        unsigned long __timeout = info->lwi_timeout;                           \
        unsigned long __irqflags;                                              \
        sigset_t      __blocked;                                               \
                                                                               \
        ret = 0;                                                               \
        if (condition)                                                         \
                break;                                                         \
                                                                               \
        init_waitqueue_entry(&__wait, current);                                \
        if (excl)                                                              \
                add_wait_queue_exclusive(&wq, &__wait);                        \
        else                                                                   \
                add_wait_queue(&wq, &__wait);                                  \
                                                                               \
        /* Block all signals (just the non-fatal ones if no timeout). */       \
        if (info->lwi_on_signal != NULL && __timeout == 0)                     \
                __blocked = l_w_e_set_sigs(LUSTRE_FATAL_SIGS);                 \
        else                                                                   \
                __blocked = l_w_e_set_sigs(0);                                 \
                                                                               \
        for (;;) {                                                             \
                set_current_state(TASK_INTERRUPTIBLE);                         \
                                                                               \
                if (condition)                                                 \
                        break;                                                 \
                                                                               \
                if (__timeout == 0) {                                          \
                        schedule();                                            \
                } else {                                                       \
                        unsigned long interval = info->lwi_interval?           \
                                             min_t(unsigned long,              \
                                                 info->lwi_interval,__timeout):\
                                             __timeout;                        \
                        __timeout -= interval - schedule_timeout(interval);    \
                        if (__timeout == 0) {                                  \
                                if (info->lwi_on_timeout == NULL ||            \
                                    info->lwi_on_timeout(info->lwi_cb_data)) { \
                                        ret = -ETIMEDOUT;                      \
                                        break;                                 \
                                }                                              \
                                /* Take signals after the timeout expires. */  \
                                if (info->lwi_on_signal != NULL)               \
                                    (void)l_w_e_set_sigs(LUSTRE_FATAL_SIGS);   \
                        }                                                      \
                }                                                              \
                                                                               \
                if (condition)                                                 \
                        break;                                                 \
                                                                               \
                if (signal_pending(current)) {                                 \
                        if (info->lwi_on_signal != NULL && __timeout == 0) {   \
                                if (info->lwi_on_signal != LWI_ON_SIGNAL_NOOP) \
                                        info->lwi_on_signal(info->lwi_cb_data);\
                                ret = -EINTR;                                  \
                                break;                                         \
                        }                                                      \
                        /* We have to do this here because some signals */     \
                        /* are not blockable - ie from strace(1).       */     \
                        /* In these cases we want to schedule_timeout() */     \
                        /* again, because we don't want that to return  */     \
                        /* -EINTR when the RPC actually succeeded.      */     \
                        /* the RECALC_SIGPENDING below will deliver the */     \
                        /* signal properly.                             */     \
                        SIGNAL_MASK_LOCK(current, __irqflags);                 \
                        CLEAR_SIGPENDING;                                      \
                        SIGNAL_MASK_UNLOCK(current, __irqflags);               \
                }                                                              \
        }                                                                      \
                                                                               \
        SIGNAL_MASK_LOCK(current, __irqflags);                                 \
        current->blocked = __blocked;                                          \
        RECALC_SIGPENDING;                                                     \
        SIGNAL_MASK_UNLOCK(current, __irqflags);                               \
                                                                               \
        current->state = TASK_RUNNING;                                         \
        remove_wait_queue(&wq, &__wait);                                       \
} while(0)

#else /* !__KERNEL__ */
#define __l_wait_event(wq, condition, info, ret, excl)                  \
do {                                                                    \
        long __timeout = info->lwi_timeout;                             \
        long __now;                                                     \
        long __then = 0;                                                \
        int  __timed_out = 0;                                           \
                                                                        \
        ret = 0;                                                        \
        if (condition)                                                  \
                break;                                                  \
                                                                        \
        if (__timeout == 0)                                             \
                __timeout = 1000000000;                                 \
        else                                                            \
                __then = time(NULL);                                    \
                                                                        \
        while (!(condition)) {                                          \
                if (liblustre_wait_event(info->lwi_interval?:__timeout) || \
                    (info->lwi_interval && info->lwi_interval < __timeout)) {\
                        if (__timeout != 0 && info->lwi_timeout != 0) { \
                                __now = time(NULL);                     \
                                __timeout -= __now - __then;            \
                                if (__timeout < 0)                      \
                                        __timeout = 0;                  \
                                __then = __now;                         \
                        }                                               \
                        continue;                                       \
                }                                                       \
                                                                        \
                if (info->lwi_timeout != 0 && !__timed_out) {           \
                        __timed_out = 1;                                \
                        if (info->lwi_on_timeout == NULL ||             \
                            info->lwi_on_timeout(info->lwi_cb_data)) {  \
                                ret = -ETIMEDOUT;                       \
                                break;                                  \
                        }                                               \
                }                                                       \
        }                                                               \
} while (0)

#endif /* __KERNEL__ */

#define l_wait_event(wq, condition, info)                       \
({                                                              \
        int                 __ret;                              \
        struct l_wait_info *__info = (info);                    \
                                                                \
        __l_wait_event(wq, condition, __info, __ret, 0);        \
        __ret;                                                  \
})

#define l_wait_event_exclusive(wq, condition, info)             \
({                                                              \
        int                 __ret;                              \
        struct l_wait_info *__info = (info);                    \
                                                                \
        __l_wait_event(wq, condition, __info, __ret, 1);        \
        __ret;                                                  \
})

#ifdef __KERNEL__
#define LIBLUSTRE_CLIENT (0)
#else
#define LIBLUSTRE_CLIENT (1)
#endif

#endif /* _LUSTRE_LIB_H */

