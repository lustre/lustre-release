/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (c) 2002 Cluster File Systems, Inc. <info@clusterfs.com>
 * Copyright (c) 2002 Lawrence Livermore National Laboratory
 *  Author: James Newsome <newsome2@llnl.gov>
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

#define DEBUG_SUBSYSTEM S_LDLM

#include <asm/atomic.h>
#include <linux/types.h>
#include <linux/random.h>

#include <linux/lustre_dlm.h>
#include <linux/obd.h>

struct ldlm_test_thread {
        struct obd_device *obddev;
        struct ldlm_namespace *t_ns;
        struct list_head t_link;
        __u32 t_flags;
        wait_queue_head_t t_ctl_waitq;
};

struct ldlm_test_lock {
        struct list_head l_link;
        struct lustre_handle l_lockh;
};

static unsigned int max_locks;
static unsigned int num_resources;
static unsigned int num_extents;

static spinlock_t ctl_lock = SPIN_LOCK_UNLOCKED;
/* protect these with the ctl_lock */
static LIST_HEAD(ctl_threads);
static int regression_running = 0;
static LIST_HEAD(lock_list);
static int num_locks = 0;

/* cumulative stats for regression test */
static atomic_t locks_requested = ATOMIC_INIT(0);
static atomic_t converts_requested = ATOMIC_INIT(0);
static atomic_t locks_granted = ATOMIC_INIT(0);
static atomic_t locks_matched = ATOMIC_INIT(0);

/* making this a global avoids the problem of having pointers
 * to garbage after the test exits.
 */
static struct lustre_handle regress_connh;

static int ldlm_do_decrement(void);
static int ldlm_do_enqueue(struct ldlm_test_thread *thread);
static int ldlm_do_convert(void);

/*
 * blocking ast for regression test.
 * Just cancels lock
 */
static int ldlm_test_blocking_ast(struct ldlm_lock *lock,
                                  struct ldlm_lock_desc *new,
                                  void *data, __u32 data_len)
{
        int rc;
        struct lustre_handle lockh;
        ENTRY;

        LDLM_DEBUG(lock, "We're blocking. Cancelling lock");
        ldlm_lock2handle(lock, &lockh);
        rc = ldlm_cli_cancel(&lockh);
        if (rc < 0) {
                CERROR("ldlm_cli_cancel: %d\n", rc);
                LBUG();
        }

        RETURN(0);
}

/* blocking ast for basic tests. noop */
static int ldlm_blocking_ast(struct ldlm_lock *lock,
                             struct ldlm_lock_desc *new,
                             void *data, __u32 data_len)
{
        ENTRY;
        CERROR("ldlm_blocking_ast: lock=%p, new=%p\n", lock, new);
        RETURN(0);
}

/* Completion ast for regression test.
 * Does not sleep when blocked.
 */
static int ldlm_test_completion_ast(struct ldlm_lock *lock, int flags)
{
        struct ldlm_test_lock *lock_info;
        ENTRY;

        if (flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                     LDLM_FL_BLOCK_CONV)) {
                LDLM_DEBUG(lock, "client-side enqueue returned a blocked lock");
                RETURN(0);
        }

        if (lock->l_granted_mode != lock->l_req_mode)
                CERROR("completion ast called with non-granted lock\n");

        /* add to list of granted locks */

        if (flags & LDLM_FL_WAIT_NOREPROC) {
                atomic_inc(&locks_matched);
                LDLM_DEBUG(lock, "lock matched");
        } else {
                atomic_inc(&locks_granted);
                LDLM_DEBUG(lock, "lock granted");
        }

        OBD_ALLOC(lock_info, sizeof(*lock_info));
        if (lock_info == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }

        ldlm_lock2handle(lock, &lock_info->l_lockh);

        spin_lock(&ctl_lock);
        list_add_tail(&lock_info->l_link, &lock_list);
        num_locks++;
        spin_unlock(&ctl_lock);

        RETURN(0);
}

int ldlm_test_basics(struct obd_device *obddev)
{
        struct ldlm_namespace *ns;
        struct ldlm_resource *res;
        __u64 res_id[RES_NAME_SIZE] = {1, 2, 3};
        ldlm_error_t err;
        struct ldlm_lock *lock1, *lock;
        int flags;
        ENTRY;

        ns = ldlm_namespace_new("test_server", LDLM_NAMESPACE_SERVER);
        if (ns == NULL)
                LBUG();

        lock1 = ldlm_lock_create(ns, NULL, res_id, LDLM_PLAIN, LCK_CR, NULL, 0);
        if (lock1 == NULL)
                LBUG();
        err = ldlm_lock_enqueue(lock1, NULL, 0, &flags,
                                ldlm_completion_ast, ldlm_blocking_ast);
        if (err != ELDLM_OK)
                LBUG();

        lock = ldlm_lock_create(ns, NULL, res_id, LDLM_PLAIN, LCK_EX, NULL, 0);
        if (lock == NULL)
                LBUG();
        err = ldlm_lock_enqueue(lock, NULL, 0, &flags,
                                ldlm_completion_ast, ldlm_blocking_ast);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_BLOCK_GRANTED))
                LBUG();

        res = ldlm_resource_get(ns, NULL, res_id, LDLM_PLAIN, 1);
        if (res == NULL)
                LBUG();
        ldlm_resource_dump(res);

        res = ldlm_lock_convert(lock1, LCK_NL, &flags);
        if (res != NULL)
                ldlm_reprocess_all(res);

        ldlm_resource_dump(res);
        ldlm_namespace_free(ns);

        RETURN(0);
}

int ldlm_test_extents(struct obd_device *obddev)
{
        struct ldlm_namespace *ns;
        struct ldlm_resource *res;
        struct ldlm_lock *lock, *lock1, *lock2;
        __u64 res_id[RES_NAME_SIZE] = {0, 0, 0};
        struct ldlm_extent ext1 = {4, 6}, ext2 = {6, 9}, ext3 = {10, 11};
        ldlm_error_t err;
        int flags;
        ENTRY;

        ns = ldlm_namespace_new("test_server", LDLM_NAMESPACE_SERVER);
        if (ns == NULL)
                LBUG();

        flags = 0;
        lock1 = ldlm_lock_create(ns, NULL, res_id, LDLM_EXTENT, LCK_PR, NULL,
                                 0);
        if (lock1 == NULL)
                LBUG();
        err = ldlm_lock_enqueue(lock1, &ext1, sizeof(ext1), &flags, NULL, NULL);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_LOCK_CHANGED))
                LBUG();

        flags = 0;
        lock2 = ldlm_lock_create(ns, NULL, res_id, LDLM_EXTENT, LCK_PR,
                                NULL, 0);
        err = ldlm_lock_enqueue(lock2, &ext2, sizeof(ext2), &flags, NULL, NULL);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_LOCK_CHANGED))
                LBUG();

        flags = 0;
        lock = ldlm_lock_create(ns, NULL, res_id, LDLM_EXTENT, LCK_EX, NULL, 0);
        if (lock == NULL)
                LBUG();
        err = ldlm_lock_enqueue(lock, &ext3, sizeof(ext3), &flags,
                                NULL, NULL);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_BLOCK_GRANTED))
                LBUG();
        if (flags & LDLM_FL_LOCK_CHANGED)
                LBUG();

        /* Convert/cancel blocking locks */
        flags = 0;
        res = ldlm_lock_convert(lock1, LCK_NL, &flags);
        if (res != NULL)
                ldlm_reprocess_all(res);

        ldlm_lock_cancel(lock2);
        if (res != NULL)
                ldlm_reprocess_all(res);

        /* Dump the results */
        res = ldlm_resource_get(ns, NULL, res_id, LDLM_EXTENT, 0);
        if (res == NULL)
                LBUG();
        ldlm_resource_dump(res);
        ldlm_namespace_free(ns);

        RETURN(0);
}

static int ldlm_test_network(struct obd_device *obddev,
                             struct lustre_handle *connh)
{

        __u64 res_id[RES_NAME_SIZE] = {1, 2, 3};
        struct ldlm_extent ext = {4, 6};
        struct lustre_handle lockh1;
        struct ldlm_lock *lock;
        int flags = 0;
        ldlm_error_t err;
        ENTRY;

        err = ldlm_cli_enqueue(connh, NULL, obddev->obd_namespace, NULL, res_id,
                               LDLM_EXTENT, &ext, sizeof(ext), LCK_PR, &flags,
                               ldlm_completion_ast, NULL, NULL, 0, &lockh1);

        CERROR("ldlm_cli_enqueue: %d\n", err);

        flags = 0;
        err = ldlm_cli_convert(&lockh1, LCK_EX, &flags);
        CERROR("ldlm_cli_convert: %d\n", err);

        lock = ldlm_handle2lock(&lockh1);
        ldlm_lock_dump(lock);
        ldlm_lock_put(lock);

        /* Need to decrement old mode. Don't bother incrementing new
         * mode since the test is done.
         */
        if (err == ELDLM_OK)
                ldlm_lock_decref(&lockh1, LCK_PR);

        RETURN(err);
}

static int ldlm_do_decrement(void)
{
        struct ldlm_test_lock *lock_info;
        struct ldlm_lock *lock;
        int rc = 0;
        ENTRY;

        spin_lock(&ctl_lock);
        if(list_empty(&lock_list)) {
                CERROR("lock_list is empty\n");
                spin_unlock(&ctl_lock);
                RETURN(0);
        }

        /* delete from list */
        lock_info = list_entry(lock_list.next,
                        struct ldlm_test_lock, l_link);
        list_del(lock_list.next);
        num_locks--;
        spin_unlock(&ctl_lock);

        /* decrement and free the info */
        lock = ldlm_handle2lock(&lock_info->l_lockh);
        ldlm_lock_decref(&lock_info->l_lockh, lock->l_granted_mode);
        ldlm_lock_put(lock);

        OBD_FREE(lock_info, sizeof(*lock_info));

        RETURN(rc);
}

static int ldlm_do_enqueue(struct ldlm_test_thread *thread)
{
        struct lustre_handle lockh;
        __u64 res_id[3] = {0};
        __u32 lock_mode;
        struct ldlm_extent ext;
        unsigned char random;
        int flags = 0, rc = 0;
        ENTRY;

        /* Pick a random resource from 1 to num_resources */
        get_random_bytes(&random, sizeof(random));
        res_id[0] = random % num_resources;

        /* Pick a random lock mode */
        get_random_bytes(&random, sizeof(random));
        lock_mode = random % LCK_NL + 1;

        /* Pick a random extent */
        get_random_bytes(&random, sizeof(random));
        ext.start = random % num_extents;
        get_random_bytes(&random, sizeof(random));
        ext.end = random %
                (num_extents - (int)ext.start) + ext.start;

        LDLM_DEBUG_NOLOCK("about to enqueue with resource "LPX64", mode %d,"
                          " extent "LPX64" -> "LPX64, res_id[0], lock_mode,
                          ext.start, ext.end);

        rc = ldlm_match_or_enqueue(&regress_connh, NULL,
                                   thread->obddev->obd_namespace,
                                   NULL, res_id, LDLM_EXTENT, &ext,
                                   sizeof(ext), lock_mode, &flags,
                                   ldlm_test_completion_ast,
                                   ldlm_test_blocking_ast,
                                   NULL, 0, &lockh);

        atomic_inc(&locks_requested);

        if (rc < 0) {
                CERROR("ldlm_cli_enqueue: %d\n", rc);
                LBUG();
        }

        RETURN(rc);
}

static int ldlm_do_convert(void)
{
        __u32 lock_mode;
        unsigned char random;
        int flags = 0, rc = 0;
        struct ldlm_test_lock *lock_info;
        struct ldlm_lock *lock;
        ENTRY;

        /* delete from list */
        spin_lock(&ctl_lock);
        lock_info = list_entry(lock_list.next, struct ldlm_test_lock, l_link);
        list_del(lock_list.next);
        num_locks--;
        spin_unlock(&ctl_lock);

        /* Pick a random lock mode */
        get_random_bytes(&random, sizeof(random));
        lock_mode = random % LCK_NL + 1;

        /* do the conversion */
        rc = ldlm_cli_convert(&lock_info->l_lockh , lock_mode, &flags);
        atomic_inc(&converts_requested);

        if (rc < 0) {
                CERROR("ldlm_cli_convert: %d\n", rc);
                LBUG();
        }

        /*
         *  Adjust reference counts.
         *  FIXME: This is technically a bit... wrong,
         *  since we don't know when/if the convert succeeded
         */
        ldlm_lock_addref(&lock_info->l_lockh, lock_mode);
        lock = ldlm_handle2lock(&lock_info->l_lockh);
        ldlm_lock_decref(&lock_info->l_lockh, lock->l_granted_mode);
        ldlm_lock_put(lock);

        OBD_FREE(lock_info, sizeof(*lock_info));

        RETURN(rc);
}



static int ldlm_test_main(void *data)
{
        struct ldlm_test_thread *thread = data;
        ENTRY;

        lock_kernel();
        daemonize();
        spin_lock_irq(&current->sigmask_lock);
        sigfillset(&current->blocked);
        recalc_sigpending(current);
        spin_unlock_irq(&current->sigmask_lock);

        sprintf(current->comm, "ldlm_test");
        unlock_kernel();

        /* Record that the thread is running */
        thread->t_flags |= SVC_RUNNING;
        wake_up(&thread->t_ctl_waitq);

        while (!(thread->t_flags & SVC_STOPPING)) {
                unsigned char random;
                unsigned char dec_chance, con_chance;
                unsigned char chance_left = 100;

                spin_lock(&ctl_lock);
                /* probability of decrementing increases linearly
                 * as more locks are held.
                 */
                dec_chance = chance_left * num_locks / max_locks;
                chance_left -= dec_chance;

                /* FIXME: conversions temporarily disabled
                 * until they are working correctly.
                 */
                /* con_chance = chance_left * num_locks / max_locks; */
                con_chance = 0;
                chance_left -= con_chance;
                spin_unlock(&ctl_lock);

                get_random_bytes(&random, sizeof(random));

                random = random % 100;
                if (random < dec_chance)
                        ldlm_do_decrement();
                else if (random < (dec_chance + con_chance))
                        ldlm_do_convert();
                else
                        ldlm_do_enqueue(thread);

                LDLM_DEBUG_NOLOCK("locks requested: %d, "
                                  "conversions requested %d",
                                  atomic_read(&locks_requested),
                                  atomic_read(&converts_requested));
                LDLM_DEBUG_NOLOCK("locks granted: %d, "
                                  "locks matched: %d",
                                  atomic_read(&locks_granted),
                                  atomic_read(&locks_matched));

                spin_lock(&ctl_lock);
                LDLM_DEBUG_NOLOCK("lock references currently held: %d, ",
                                  num_locks);
                spin_unlock(&ctl_lock);

                /*
                 * We don't sleep after a lock being blocked, so let's
                 * make sure other things can run.
                 */
                schedule();
        }

        thread->t_flags |= SVC_STOPPED;
        wake_up(&thread->t_ctl_waitq);

        RETURN(0);
}

static int ldlm_start_thread(struct obd_device *obddev,
                             struct lustre_handle *connh)
{
        struct ldlm_test_thread *test;
        int rc;
        ENTRY;

        OBD_ALLOC(test, sizeof(*test));
        if (test == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }
        init_waitqueue_head(&test->t_ctl_waitq);

        test->obddev = obddev;

        spin_lock(&ctl_lock);
        list_add(&test->t_link, &ctl_threads);
        spin_unlock(&ctl_lock);

        rc = kernel_thread(ldlm_test_main, (void *)test,
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread\n");
                RETURN(-EINVAL);
        }
        wait_event(test->t_ctl_waitq, test->t_flags & SVC_RUNNING);

        RETURN(0);
}

int ldlm_regression_start(struct obd_device *obddev,
                          struct lustre_handle *connh,
                          unsigned int threads, unsigned int max_locks_in,
                          unsigned int num_resources_in,
                          unsigned int num_extents_in)
{
        int i, rc = 0;
        ENTRY;

        spin_lock(&ctl_lock);
        if (regression_running) {
                CERROR("You can't start the ldlm regression twice.\n");
                spin_unlock(&ctl_lock);
                RETURN(-EINVAL);
        }
        regression_running = 1;
        spin_unlock(&ctl_lock);

        regress_connh = *connh;
        max_locks = max_locks_in;
        num_resources = num_resources_in;
        num_extents = num_extents_in;

        LDLM_DEBUG_NOLOCK("regression test started: threads: %d, max_locks: "
                          "%d, num_res: %d, num_ext: %d\n",
                          threads, max_locks_in, num_resources_in,
                          num_extents_in);

        for (i = 0; i < threads; i++) {
                rc = ldlm_start_thread(obddev, connh);
                if (rc < 0)
                        GOTO(cleanup, rc);
        }

 cleanup:
        if (rc < 0)
                ldlm_regression_stop();
        RETURN(rc);
}

int ldlm_regression_stop(void)
{
        ENTRY;

        spin_lock(&ctl_lock);
        if (!regression_running) {
                CERROR("The ldlm regression isn't started.\n");
                spin_unlock(&ctl_lock);
                RETURN(-EINVAL);
        }

        while (!list_empty(&ctl_threads)) {
                struct ldlm_test_thread *thread;
                thread = list_entry(ctl_threads.next, struct ldlm_test_thread,
                                    t_link);

                thread->t_flags |= SVC_STOPPING;

                spin_unlock(&ctl_lock);
                wake_up(&thread->t_ctl_waitq);
                wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_STOPPED);
                spin_lock(&ctl_lock);

                list_del(&thread->t_link);
                OBD_FREE(thread, sizeof(*thread));
        }

        /* decrement all held locks */
        while (!list_empty(&lock_list)) {
                struct ldlm_lock *lock;
                struct ldlm_test_lock *lock_info =
                       list_entry(lock_list.next, struct ldlm_test_lock,
                                   l_link);
                list_del(lock_list.next);
                num_locks--;

                lock = ldlm_handle2lock(&lock_info->l_lockh);
                ldlm_lock_decref(&lock_info->l_lockh, lock->l_granted_mode);
                ldlm_lock_put(lock);

                OBD_FREE(lock_info, sizeof(*lock_info));
        }

        regression_running = 0;
        spin_unlock(&ctl_lock);

        RETURN(0);
}

int ldlm_test(struct obd_device *obddev, struct lustre_handle *connh)
{
        int rc;
        rc = ldlm_test_basics(obddev);
        if (rc)
                RETURN(rc);

        rc = ldlm_test_extents(obddev);
        if (rc)
                RETURN(rc);

        rc = ldlm_test_network(obddev, connh);
        RETURN(rc);
}
