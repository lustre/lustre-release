/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Cluster File Systems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/types.h>
#include <linux/random.h>

#include <linux/lustre_dlm.h>

struct ldlm_test_thread {
        struct ldlm_namespace *t_ns;
        struct list_head t_link;
        __u32 t_flags; 
        wait_queue_head_t t_ctl_waitq;
};

static spinlock_t ctl_lock = SPIN_LOCK_UNLOCKED;
static struct list_head ctl_threads;
static int regression_running = 0;

static int ldlm_blocking_ast(struct ldlm_lock *lock,
                             struct ldlm_lock_desc *new,
                             void *data, __u32 data_len)
{
        ENTRY;
        CERROR("ldlm_blocking_ast: lock=%p, new=%p\n", lock, new);
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

        return 0;
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

        return 0;
}

static int ldlm_test_network(struct obd_device *obddev,
                             struct ptlrpc_connection *conn)
{

        __u64 res_id[RES_NAME_SIZE] = {1, 2, 3};
        struct ldlm_extent ext = {4, 6};
        struct lustre_handle lockh1;
        int flags = 0;
        ldlm_error_t err;

        /* FIXME: this needs a connh as 3rd paramter, before it will work */

        err = ldlm_cli_enqueue(NULL, NULL, obddev->obd_namespace, NULL, res_id,
                               LDLM_EXTENT, &ext, sizeof(ext), LCK_PR, &flags,
                               NULL, NULL, NULL, 0, &lockh1);
        CERROR("ldlm_cli_enqueue: %d\n", err);
        if (err == ELDLM_OK)
                ldlm_lock_decref(&lockh1, LCK_PR);

        RETURN(err);
}

static int ldlm_test_main(void *data)
{
        struct ldlm_test_thread *thread = data;
        struct ldlm_namespace *ns;
        ENTRY;

        lock_kernel();
        daemonize();
        spin_lock_irq(&current->sigmask_lock);
        sigfillset(&current->blocked);
        recalc_sigpending(current);
        spin_unlock_irq(&current->sigmask_lock);

        sprintf(current->comm, "ldlm_test");

        ns = ldlm_namespace_new("ldlm_test", LDLM_NAMESPACE_CLIENT);
        if (ns == NULL) {
                LBUG();
                GOTO(out, -ENOMEM);
        }

        /* Record that the thread is running */
        thread->t_flags |= SVC_RUNNING;
        wake_up(&thread->t_ctl_waitq);

        while (1) {
                struct lustre_handle lockh;
                __u64 res_id[3] = {0};
                __u32 lock_mode;
                char random;
                int flags = 0, rc;

                /* Pick a random resource from 1 to 10 */
                get_random_bytes(&random, sizeof(random));
                res_id[0] = random % 10 + 1;

                /* Pick a random lock mode */
                get_random_bytes(&random, sizeof(random));
                lock_mode = random % LCK_NL + 1;

                rc = ldlm_cli_enqueue(NULL, NULL, ns, NULL,
                                      res_id, LDLM_PLAIN, NULL, 0, lock_mode,
                                      &flags, ldlm_completion_ast,
                                      ldlm_blocking_ast, NULL, 0, &lockh);
                if (rc < 0) {
                        CERROR("ldlm_cli_enqueue: %d\n", rc);
                        LBUG();
                }
        }

 out:
        thread->t_flags |= SVC_STOPPED;
        wake_up(&thread->t_ctl_waitq);

        RETURN(0);
}

static int ldlm_start_thread(void)
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
                          struct ptlrpc_connection *conn, int count)
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

        for (i = 0; i < count; i++) {
                rc = ldlm_start_thread();
                if (rc < 0)
                        GOTO(cleanup, rc);
        }

 cleanup:
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

        regression_running = 0;
        spin_unlock(&ctl_lock);

        RETURN(0);
}

int ldlm_test(struct obd_device *obddev, struct ptlrpc_connection *conn)
{
        int rc;
        rc = ldlm_test_basics(obddev);
        if (rc)
                RETURN(rc);

        rc = ldlm_test_extents(obddev);
        if (rc)
                RETURN(rc);

        rc = ldlm_test_network(obddev, conn);
        RETURN(rc);
}
