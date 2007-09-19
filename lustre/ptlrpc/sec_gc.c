/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2007 Cluster File Systems, Inc.
 *   Author: Eric Mei <ericm@clusterfs.com>
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
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC

#ifndef __KERNEL__
#include <liblustre.h>
#endif

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>
#include <lustre_sec.h>

#define SEC_GC_INTERVAL (30 * 60)

#ifdef __KERNEL__

static DECLARE_MUTEX(sec_gc_mutex);
static CFS_LIST_HEAD(sec_gc_list);
static spinlock_t sec_gc_list_lock = SPIN_LOCK_UNLOCKED;

static CFS_LIST_HEAD(sec_gc_ctx_list);
static spinlock_t sec_gc_ctx_list_lock = SPIN_LOCK_UNLOCKED;

static struct ptlrpc_thread sec_gc_thread;
static atomic_t sec_gc_wait_del = ATOMIC_INIT(0);


void sptlrpc_gc_add_sec(struct ptlrpc_sec *sec)
{
        if (!list_empty(&sec->ps_gc_list)) {
                CERROR("sec %p(%s) already in gc list\n",
                       sec, sec->ps_policy->sp_name);
                return;
        }

        spin_lock(&sec_gc_list_lock);
        list_add_tail(&sec_gc_list, &sec->ps_gc_list);
        spin_unlock(&sec_gc_list_lock);

        CDEBUG(D_SEC, "added sec %p(%s)\n", sec, sec->ps_policy->sp_name);
}
EXPORT_SYMBOL(sptlrpc_gc_add_sec);

void sptlrpc_gc_del_sec(struct ptlrpc_sec *sec)
{
        if (list_empty(&sec->ps_gc_list))
                return;

        might_sleep();

        spin_lock(&sec_gc_list_lock);
        list_del_init(&sec->ps_gc_list);
        spin_unlock(&sec_gc_list_lock);

        /* barrier */
        atomic_inc(&sec_gc_wait_del);
        mutex_down(&sec_gc_mutex);
        mutex_up(&sec_gc_mutex);
        atomic_dec(&sec_gc_wait_del);

        CDEBUG(D_SEC, "del sec %p(%s)\n", sec, sec->ps_policy->sp_name);
}
EXPORT_SYMBOL(sptlrpc_gc_del_sec);

void sptlrpc_gc_add_ctx(struct ptlrpc_cli_ctx *ctx)
{
        LASSERT(list_empty(&ctx->cc_gc_chain));

        CDEBUG(D_SEC, "hand over ctx %p(%u->%s)\n",
               ctx, ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec));
        spin_lock(&sec_gc_ctx_list_lock);
        list_add(&ctx->cc_gc_chain, &sec_gc_ctx_list);
        spin_unlock(&sec_gc_ctx_list_lock);

        sec_gc_thread.t_flags |= SVC_SIGNAL;
        cfs_waitq_signal(&sec_gc_thread.t_ctl_waitq);
}
EXPORT_SYMBOL(sptlrpc_gc_add_ctx);

static void sec_process_ctx_list(void)
{
        struct ptlrpc_cli_ctx *ctx;

again:
        spin_lock(&sec_gc_ctx_list_lock);
        if (!list_empty(&sec_gc_ctx_list)) {
                ctx = list_entry(sec_gc_ctx_list.next,
                                 struct ptlrpc_cli_ctx, cc_gc_chain);
                list_del_init(&ctx->cc_gc_chain);
                spin_unlock(&sec_gc_ctx_list_lock);

                LASSERT(ctx->cc_sec);
                LASSERT(atomic_read(&ctx->cc_refcount) == 1);
                CDEBUG(D_SEC, "gc pick up ctx %p(%u->%s)\n",
                       ctx, ctx->cc_vcred.vc_uid, sec2target_str(ctx->cc_sec));
                sptlrpc_cli_ctx_put(ctx, 1);

                goto again;
        }
        spin_unlock(&sec_gc_ctx_list_lock);
}

static void sec_do_gc(struct ptlrpc_sec *sec)
{
        cfs_time_t      now = cfs_time_current_sec();

        if (unlikely(sec->ps_gc_next == 0)) {
                CWARN("sec %p(%s) has 0 gc time\n",
                      sec, sec->ps_policy->sp_name);
                return;
        }

        if (unlikely(sec->ps_policy->sp_cops->gc_ctx == NULL)) {
                CWARN("sec %p(%s) is not prepared for gc\n",
                      sec, sec->ps_policy->sp_name);
                return;
        }

        CDEBUG(D_SEC, "check on sec %p(%s)\n", sec, sec->ps_policy->sp_name);

        if (time_after(sec->ps_gc_next, now))
                return;

        sec->ps_policy->sp_cops->gc_ctx(sec);
        sec->ps_gc_next = now + sec->ps_gc_interval;
}

static int sec_gc_main(void *arg)
{
        struct ptlrpc_thread *thread = (struct ptlrpc_thread *) arg;
        struct l_wait_info    lwi;

        cfs_daemonize("sptlrpc_ctx_gc");

        /* Record that the thread is running */
        thread->t_flags = SVC_RUNNING;
        cfs_waitq_signal(&thread->t_ctl_waitq);

        while (1) {
                struct ptlrpc_sec *sec, *next;

                thread->t_flags &= ~SVC_SIGNAL;
                sec_process_ctx_list();
again:
                mutex_down(&sec_gc_mutex);
                list_for_each_entry_safe(sec, next, &sec_gc_list, ps_gc_list) {
                        /*
                         * if someone is waiting to be deleted, let it
                         * proceed as soon as possible.
                         */
                        if (atomic_read(&sec_gc_wait_del)) {
                                CWARN("deletion pending, retry\n");
                                mutex_up(&sec_gc_mutex);
                                goto again;
                        }

                        sec_do_gc(sec);
                }
                mutex_up(&sec_gc_mutex);

                lwi = LWI_TIMEOUT(SEC_GC_INTERVAL * HZ, NULL, NULL);
                l_wait_event(thread->t_ctl_waitq,
                             thread->t_flags & (SVC_STOPPING | SVC_SIGNAL),
                             &lwi);

                if (thread->t_flags & SVC_STOPPING) {
                        thread->t_flags &= ~SVC_STOPPING;
                        break;
                }
        }

        thread->t_flags = SVC_STOPPED;
        cfs_waitq_signal(&thread->t_ctl_waitq);
        return 0;
}

int sptlrpc_gc_start_thread(void)
{
        struct l_wait_info lwi = { 0 };
        int                rc;

        /* initialize thread control */
        memset(&sec_gc_thread, 0, sizeof(sec_gc_thread));
        cfs_waitq_init(&sec_gc_thread.t_ctl_waitq);

        rc = cfs_kernel_thread(sec_gc_main, &sec_gc_thread,
                               CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("can't start gc thread: %d\n", rc);
                return rc;
        }

        l_wait_event(sec_gc_thread.t_ctl_waitq,
                     sec_gc_thread.t_flags & SVC_RUNNING, &lwi);
        return 0;
}

void sptlrpc_gc_stop_thread(void)
{
        struct l_wait_info lwi = { 0 };

        sec_gc_thread.t_flags = SVC_STOPPING;
        cfs_waitq_signal(&sec_gc_thread.t_ctl_waitq);

        l_wait_event(sec_gc_thread.t_ctl_waitq,
                     sec_gc_thread.t_flags & SVC_STOPPED, &lwi);
}

#else /* !__KERNEL__ */

void sptlrpc_gc_add_sec(struct ptlrpc_sec *sec)
{
}
void sptlrpc_gc_del_sec(struct ptlrpc_sec *sec)
{
}
int sptlrpc_gc_start_thread(void)
{
        return 0;
}
void sptlrpc_gc_stop_thread(void)
{
}

#endif /* __KERNEL__ */
