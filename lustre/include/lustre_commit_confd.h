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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lustre_commit_confd.h
 *
 * Structures relating to the log commit thread.
 */

#ifndef _LUSTRE_COMMIT_CONFD_H
#define _LUSTRE_COMMIT_CONFD_H

#include <lustre_log.h>

struct llog_canceld_ctxt {
        struct list_head           llcd_list;  /* free or pending struct list */
        struct llog_ctxt          *llcd_ctxt;
        struct llog_commit_master *llcd_lcm;
        int                        llcd_size;
        int                        llcd_cookiebytes;
        struct llog_cookie         llcd_cookies[0];
};

struct llog_commit_master {
        struct list_head        lcm_thread_busy;  /* list of busy daemons */
        struct list_head        lcm_thread_idle;  /* list of idle daemons */
        spinlock_t              lcm_thread_lock;  /* protects thread_list */
        atomic_t                lcm_thread_numidle;/* number of idle threads */
        atomic_t                lcm_thread_total; /* total number of threads */
        int                     lcm_thread_max;   /* <= num_osts normally */

        int                     lcm_flags;
        cfs_waitq_t             lcm_waitq;

        struct list_head        lcm_llcd_pending; /* llog_canceld_ctxt to send */
        struct list_head        lcm_llcd_resend;  /* try to resend this data */
        struct list_head        lcm_llcd_free;    /* free llog_canceld_ctxt */
        spinlock_t              lcm_llcd_lock;    /* protects llcd_free */
        atomic_t                lcm_llcd_numfree; /* items on llcd_free */
        int                     lcm_llcd_minfree; /* min free on llcd_free */
        int                     lcm_llcd_maxfree; /* max free on llcd_free */
};

#define LLOG_LCM_FL_EXIT        0x01
#define LLOG_LCM_FL_EXIT_FORCE  0x02

/* the thread data that collects local commits and makes rpc's */
struct llog_commit_daemon {
        struct list_head           lcd_lcm_list;  /* list of daemon threads */
        struct list_head           lcd_llcd_list; /* list of pending RPCs */
        struct llog_commit_master *lcd_lcm;       /* pointer back to parent */
        int                        lcd_index;     /* the index of the llog daemon */
};

/* ptlrpc/recov_thread.c */
int llog_start_commit_thread(struct llog_commit_master *);

int llog_init_commit_master(struct llog_commit_master *);
int llog_cleanup_commit_master(struct llog_commit_master *lcm, int force);
#endif /* _LUSTRE_COMMIT_CONFD_H */
