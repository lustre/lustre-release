/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <info@clusterfs.com>
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
 * Structures relating to the log commit thread.
 */

#ifndef _LUSTRE_COMMIT_CONFD_H
#define _LUSTRE_COMMIT_CONFD_H

#include <linux/lustre_log.h>

struct llog_commit_data {
        struct list_head           llcd_list;  /* free or pending struct list */
        struct lustre_handle      *llcd_conn;  /* which osc is cancel target */
        struct llog_commit_master *llcd_lcm;
        int                        llcd_tries; /* number of tries to send */
        int                        llcd_cookiebytes;
        struct llog_cookie         llcd_cookies[0];
};

struct llog_commit_master {
        struct list_head        lcm_thread_busy;  /* list of busy daemons */
        struct list_head        lcm_thread_idle;  /* list of idle daemons */
        spinlock_t              lcm_thread_lock;  /* protects thread_list */
        atomic_t                lcm_thread_numidle;/* number of idle threads */
        int                     lcm_thread_total; /* total number of threads */
        int                     lcm_thread_max;   /* <= num_osts normally */

        int                     lcm_flags;
        wait_queue_head_t       lcm_waitq;

        struct list_head        lcm_llcd_pending; /* llog_commit_data to send */
        struct list_head        lcm_llcd_resend;  /* try to resend this data */
        struct list_head        lcm_llcd_free;    /* free llog_commit_data */
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
};

int llog_start_commit_thread(struct llog_commit_master *lcm);
struct llog_commit_data *llcd_grab(struct llog_commit_master *lcm);
void llcd_send(struct llog_commit_data *llcd);

#endif /* _LUSTRE_COMMIT_CONFD_H */
