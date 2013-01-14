/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef OSC_INTERNAL_H
#define OSC_INTERNAL_H

#define OAP_MAGIC 8675309

struct osc_async_page {
        int                     oap_magic;
        unsigned short          oap_cmd;
        unsigned short          oap_interrupted:1;

        struct list_head        oap_pending_item;
        struct list_head        oap_urgent_item;
        struct list_head        oap_rpc_item;

        obd_off                 oap_obj_off;
        unsigned                oap_page_off;
        enum async_flags        oap_async_flags;

        struct brw_page         oap_brw_page;

        struct oig_callback_context oap_occ;
        struct obd_io_group     *oap_oig;
        struct ptlrpc_request   *oap_request;
        struct client_obd       *oap_cli;
        struct lov_oinfo        *oap_loi;

        struct obd_async_page_ops *oap_caller_ops;
        void                    *oap_caller_data;
        struct list_head         oap_page_list;
        struct ldlm_lock        *oap_ldlm_lock;
        spinlock_t               oap_lock;
};

#define oap_page        oap_brw_page.pg
#define oap_count       oap_brw_page.count
#define oap_brw_flags   oap_brw_page.flag

#define OAP_FROM_COOKIE(c)                                                    \
        (LASSERT(((struct osc_async_page *)(c))->oap_magic == OAP_MAGIC),     \
         (struct osc_async_page *)(c))

struct osc_cache_waiter {
        struct list_head        ocw_entry;
        cfs_waitq_t             ocw_waitq;
        struct osc_async_page   *ocw_oap;
        int                     ocw_rc;
};

#define OSCC_FLAG_RECOVERING         0x01
#define OSCC_FLAG_CREATING           0x02
#define OSCC_FLAG_NOSPC              0x04 /* can't create more objects on OST */
#define OSCC_FLAG_SYNC_IN_PROGRESS   0x08 /* only allow one thread to sync */
#define OSCC_FLAG_LOW                0x10
#define OSCC_FLAG_EXITING            0x20
#define OSCC_FLAG_DEGRADED           0x40
#define OSCC_FLAG_RDONLY             0x80

int osc_precreate(struct obd_export *exp);
int osc_create(struct obd_export *exp, struct obdo *oa,
               struct lov_stripe_md **ea, struct obd_trans_info *oti);
int osc_create_async(struct obd_export *exp, struct obd_info *oinfo,
                     struct lov_stripe_md **ea, struct obd_trans_info *oti);
int osc_real_create(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md **ea, struct obd_trans_info *oti);
void oscc_init(struct obd_device *obd);
void osc_wake_cache_waiters(struct client_obd *cli);
int osc_shrink_grant_to_target(struct client_obd *cli, long target);

#ifdef LPROCFS
int lproc_osc_attach_seqstat(struct obd_device *dev);
void lprocfs_osc_init_vars(struct lprocfs_static_vars *lvars);
#else
static inline int lproc_osc_attach_seqstat(struct obd_device *dev) {return 0;}
static inline void lprocfs_osc_init_vars(struct lprocfs_static_vars *lvars)
{
        memset(lvars, 0, sizeof(*lvars));
}
#endif

#ifndef min_t
#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#endif

static inline int osc_recoverable_error(int rc)
{
        return (rc == -EIO || rc == -EROFS || rc == -ENOMEM ||
                rc == -EAGAIN || rc == -EINPROGRESS);
}

/* return 1 if osc should be resend request */
static inline int osc_should_resend(int resend, struct client_obd *cli)
{
        return atomic_read(&cli->cl_resends) ?
                atomic_read(&cli->cl_resends) > resend : 1;
}

static inline int osc_exp_is_2_0_server(struct obd_export *exp) {
       LASSERT(exp);
       return !!(exp->exp_connect_flags & OBD_CONNECT_FID);
}

#define OSC_FILE2MEM_OFF(fileoff,pshift) ((fileoff) + (pshift))
#endif /* OSC_INTERNAL_H */
