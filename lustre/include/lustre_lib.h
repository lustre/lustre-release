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

#include <libcfs/kp30.h>
#include <lustre_idl.h>
#include <lustre_cfg.h>
#if defined(__linux__)
#include <linux/lustre_lib.h>
#elif defined(__APPLE__)
#include <darwin/lustre_lib.h>
#elif defined(__WINNT__)
#include <winnt/lustre_lib.h>
#else
#error Unsupported operating system.
#endif

/* target.c */
struct ptlrpc_request;
struct recovd_data;
struct recovd_obd;
struct obd_export;
#include <lustre_ha.h>
#include <lustre_net.h>
#include <lvfs.h>

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

#define OBD_RECOVERY_TIMEOUT (obd_timeout * 5 / 2) /* *waves hands* */
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
        cfs_task_t *l_owner;
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

#include <obd_support.h>

#ifdef __KERNEL__
/* function defined in lustre/obdclass/<platform>/<platform>-module.c */
int obd_ioctl_getdata(char **buf, int *len, void *arg);
#else
/* buffer MUST be at least the size of obd_ioctl_hdr */
static inline int obd_ioctl_getdata(char **buf, int *len, void *arg)
{
        struct obd_ioctl_hdr hdr;
        struct obd_ioctl_data *data;
        int err;
        int offset = 0;
        ENTRY;

        err = copy_from_user(&hdr, (void *)arg, sizeof(hdr));
        if ( err ) 
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
                CERROR("User buffer too small for ioctl (%d)\n", hdr.ioc_len);
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
        if ( err ) {
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

        EXIT;
        return 0;
}
#endif

static inline void obd_ioctl_freedata(char *buf, int len)
{
        ENTRY;

        OBD_VFREE(buf, len);
        EXIT;
        return;
}

#define OBD_IOC_CREATE                 _IOR ('f', 101, OBD_IOC_DATA_TYPE)
#define OBD_IOC_DESTROY                _IOW ('f', 104, OBD_IOC_DATA_TYPE)
#define OBD_IOC_PREALLOCATE            _IOWR('f', 105, OBD_IOC_DATA_TYPE)

#define OBD_IOC_SETATTR                _IOW ('f', 107, OBD_IOC_DATA_TYPE)
#define OBD_IOC_GETATTR                _IOR ('f', 108, OBD_IOC_DATA_TYPE)
#define OBD_IOC_READ                   _IOWR('f', 109, OBD_IOC_DATA_TYPE)
#define OBD_IOC_WRITE                  _IOWR('f', 110, OBD_IOC_DATA_TYPE)


#define OBD_IOC_STATFS                 _IOWR('f', 113, OBD_IOC_DATA_TYPE)
#define OBD_IOC_SYNC                   _IOW ('f', 114, OBD_IOC_DATA_TYPE)
#define OBD_IOC_READ2                  _IOWR('f', 115, OBD_IOC_DATA_TYPE)
#define OBD_IOC_FORMAT                 _IOWR('f', 116, OBD_IOC_DATA_TYPE)
#define OBD_IOC_PARTITION              _IOWR('f', 117, OBD_IOC_DATA_TYPE)
#define OBD_IOC_COPY                   _IOWR('f', 120, OBD_IOC_DATA_TYPE)
#define OBD_IOC_MIGR                   _IOWR('f', 121, OBD_IOC_DATA_TYPE)
#define OBD_IOC_PUNCH                  _IOWR('f', 122, OBD_IOC_DATA_TYPE)

#define OBD_IOC_MODULE_DEBUG           _IOWR('f', 124, OBD_IOC_DATA_TYPE)
#define OBD_IOC_BRW_READ               _IOWR('f', 125, OBD_IOC_DATA_TYPE)
#define OBD_IOC_BRW_WRITE              _IOWR('f', 126, OBD_IOC_DATA_TYPE)
#define OBD_IOC_NAME2DEV               _IOWR('f', 127, OBD_IOC_DATA_TYPE)
#define OBD_IOC_UUID2DEV               _IOWR('f', 130, OBD_IOC_DATA_TYPE)
#define OBD_IOC_GETNAME                _IOR ('f', 131, OBD_IOC_DATA_TYPE)

#define OBD_IOC_LOV_GET_CONFIG         _IOWR('f', 132, OBD_IOC_DATA_TYPE)
#define OBD_IOC_CLIENT_RECOVER         _IOW ('f', 133, OBD_IOC_DATA_TYPE)

#define OBD_IOC_DEC_FS_USE_COUNT       _IO  ('f', 139      )
#define OBD_IOC_NO_TRANSNO             _IOW ('f', 140, OBD_IOC_DATA_TYPE)
#define OBD_IOC_SET_READONLY           _IOW ('f', 141, OBD_IOC_DATA_TYPE)
#define OBD_IOC_ABORT_RECOVERY         _IOR ('f', 142, OBD_IOC_DATA_TYPE)

#define OBD_GET_VERSION                _IOWR ('f', 144, OBD_IOC_DATA_TYPE)

#define OBD_IOC_CLOSE_UUID             _IOWR ('f', 147, OBD_IOC_DATA_TYPE)

#define OBD_IOC_LOV_SETSTRIPE          _IOW ('f', 154, OBD_IOC_DATA_TYPE)
#define OBD_IOC_LOV_GETSTRIPE          _IOW ('f', 155, OBD_IOC_DATA_TYPE)
#define OBD_IOC_LOV_SETEA              _IOW ('f', 156, OBD_IOC_DATA_TYPE)

#define OBD_IOC_QUOTACHECK             _IOW ('f', 160, int)
#define OBD_IOC_POLL_QUOTACHECK        _IOR ('f', 161, struct if_quotacheck *)
#define OBD_IOC_QUOTACTL               _IOWR('f', 162, struct if_quotactl *)

#define OBD_IOC_MOUNTOPT               _IOWR('f', 170, OBD_IOC_DATA_TYPE)

#define OBD_IOC_RECORD                 _IOWR('f', 180, OBD_IOC_DATA_TYPE)
#define OBD_IOC_ENDRECORD              _IOWR('f', 181, OBD_IOC_DATA_TYPE)
#define OBD_IOC_PARSE                  _IOWR('f', 182, OBD_IOC_DATA_TYPE)
#define OBD_IOC_DORECORD               _IOWR('f', 183, OBD_IOC_DATA_TYPE)
#define OBD_IOC_PROCESS_CFG            _IOWR('f', 184, OBD_IOC_DATA_TYPE)
#define OBD_IOC_DUMP_LOG               _IOWR('f', 185, OBD_IOC_DATA_TYPE)
#define OBD_IOC_CLEAR_LOG              _IOWR('f', 186, OBD_IOC_DATA_TYPE)

#define OBD_IOC_CATLOGLIST             _IOWR('f', 190, OBD_IOC_DATA_TYPE)
#define OBD_IOC_LLOG_INFO              _IOWR('f', 191, OBD_IOC_DATA_TYPE)
#define OBD_IOC_LLOG_PRINT             _IOWR('f', 192, OBD_IOC_DATA_TYPE)
#define OBD_IOC_LLOG_CANCEL            _IOWR('f', 193, OBD_IOC_DATA_TYPE)
#define OBD_IOC_LLOG_REMOVE            _IOWR('f', 194, OBD_IOC_DATA_TYPE)
#define OBD_IOC_LLOG_CHECK             _IOWR('f', 195, OBD_IOC_DATA_TYPE)
#define OBD_IOC_LLOG_CATINFO           _IOWR('f', 196, OBD_IOC_DATA_TYPE)

#define ECHO_IOC_GET_STRIPE            _IOWR('f', 200, OBD_IOC_DATA_TYPE)
#define ECHO_IOC_SET_STRIPE            _IOWR('f', 201, OBD_IOC_DATA_TYPE)
#define ECHO_IOC_ENQUEUE               _IOWR('f', 202, OBD_IOC_DATA_TYPE)
#define ECHO_IOC_CANCEL                _IOWR('f', 203, OBD_IOC_DATA_TYPE)

/* XXX _IOWR('f', 250, long) has been defined in
 * lnet/include/libcfs/kp30.h for debug, don't use it
 */

/* Until such time as we get_info the per-stripe maximum from the OST,
 * we define this to be 2T - 4k, which is the ext3 maxbytes. */
#define LUSTRE_STRIPE_MAXBYTES 0x1fffffff000ULL

#define POISON_BULK 0

static inline int ll_insecure_random_int(void)
{
        struct timeval t;
        do_gettimeofday(&t);
        return (int)(t.tv_usec);
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
        cfs_duration_t lwi_timeout;
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

#ifdef __KERNEL__

#define __l_wait_event(wq, condition, info, ret, excl)                         \
do {                                                                           \
        cfs_waitlink_t __wait;                                                 \
        cfs_duration_t __timed_out = 0;                                        \
        unsigned long irqflags;                                                \
        cfs_sigset_t blocked;                                                  \
        cfs_time_t timeout_remaining;                                          \
                                                                               \
        cfs_waitlink_init(&__wait);                                            \
        if (excl)                                                              \
            cfs_waitq_add_exclusive(&wq, &__wait);                             \
        else                                                                   \
            cfs_waitq_add(&wq, &__wait);                                       \
                                                                               \
        /* Block all signals (just the non-fatal ones if no timeout). */       \
        if (info->lwi_signals && !info->lwi_timeout)                           \
            blocked = l_w_e_set_sigs(LUSTRE_FATAL_SIGS);                       \
        else                                                                   \
            blocked = l_w_e_set_sigs(0);                                       \
                                                                               \
        timeout_remaining = info->lwi_timeout;                                 \
                                                                               \
        for (;;) {                                                             \
            set_current_state(TASK_INTERRUPTIBLE);                             \
            if (condition)                                                     \
                    break;                                                     \
            if (info->lwi_timeout && !__timed_out) {                           \
                timeout_remaining = cfs_waitq_timedwait(&__wait,               \
                                                        CFS_TASK_INTERRUPTIBLE,\
                                                        timeout_remaining);    \
                if (timeout_remaining == 0) {                                  \
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
                cfs_waitq_wait(&__wait, CFS_TASK_INTERRUPTIBLE);;              \
            }                                                                  \
            if (condition)                                                     \
                    break;                                                     \
            if (cfs_signal_pending()) {                                        \
                    if (!info->lwi_timeout || __timed_out) {                   \
                            break;                                             \
                    } else {                                                   \
                            /* We have to do this here because some signals */ \
                            /* are not blockable - ie from strace(1).       */ \
                            /* In these cases we want to schedule_timeout() */ \
                            /* again, because we don't want that to return  */ \
                            /* -EINTR when the RPC actually succeeded.      */ \
                            /* the RECALC_SIGPENDING below will deliver the */ \
                            /* signal properly.                             */ \
                            cfs_sigmask_lock(irqflags);                        \
                            cfs_clear_sigpending();                            \
                            cfs_sigmask_unlock(irqflags);                      \
                    }                                                          \
            }                                                                  \
        }                                                                      \
                                                                               \
        cfs_block_sigs(blocked);                                               \
                                                                               \
        if ((!info->lwi_timeout || __timed_out) &&                             \
            cfs_signal_pending()) {                                            \
                if (info->lwi_on_signal)                                       \
                        info->lwi_on_signal(info->lwi_cb_data);                \
                ret = -EINTR;                                                  \
        }                                                                      \
                                                                               \
        set_current_state(TASK_RUNNING);                                       \
        cfs_waitq_del(&wq, &__wait);                                           \
} while(0)

#else /* !__KERNEL__ */
#define __l_wait_event(wq, condition, info, ret, excl)                         \
do {                                                                           \
        long timeout = info->lwi_timeout, elapse, last = 0;                    \
        int __timed_out = 0;                                                   \
                                                                               \
        if (info->lwi_timeout == 0)                                            \
            timeout = 1000000000;                                              \
        else                                                                   \
            last = time(NULL);                                                 \
                                                                               \
        for (;;) {                                                             \
            if (condition)                                                     \
                break;                                                         \
            if (liblustre_wait_event(timeout)) {                               \
                if (timeout == 0 || info->lwi_timeout == 0)                    \
                        continue;                                              \
                elapse = time(NULL) - last;                                    \
                if (elapse) {                                                  \
                        last += elapse;                                        \
                        timeout -= elapse;                                     \
                        if (timeout < 0)                                       \
                                timeout = 0;                                   \
                }                                                              \
                continue;                                                      \
            }                                                                  \
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

#define LMD_MAGIC_R1 0xbdacbdac
#define LMD_MAGIC    0xbdacbd02

#define lmd_bad_magic(LMDP)                                             \
({                                                                      \
        struct lustre_mount_data *_lmd__ = (LMDP);                      \
        int _ret__ = 0;                                                 \
        if (!_lmd__) {                                                  \
                LCONSOLE_ERROR("Missing mount data: "                   \
                       "check that /sbin/mount.lustre is installed.\n");\
                _ret__ = 1;                                             \
        } else if (_lmd__->lmd_magic == LMD_MAGIC_R1) {                 \
                LCONSOLE_ERROR("You're using an old version of "        \
                       "/sbin/mount.lustre.  Please install version "   \
                       "1.%d\n", LMD_MAGIC & 0xFF);                     \
                _ret__ = 1;                                             \
        } else if (_lmd__->lmd_magic != LMD_MAGIC) {                    \
                LCONSOLE_ERROR("Invalid mount data (%#x != %#x): "      \
                       "check that /sbin/mount.lustre is installed\n",  \
                       _lmd__->lmd_magic, LMD_MAGIC);                   \
                _ret__ = 1;                                             \
        }                                                               \
        _ret__;                                                         \
})

#ifdef __KERNEL__
#define LIBLUSTRE_CLIENT (0)
#else
#define LIBLUSTRE_CLIENT (1)
#endif

#endif /* _LUSTRE_LIB_H */

