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

#include <linux/lustre_dlm.h>

static int ldlm_test_callback(struct ldlm_lock *lock, struct ldlm_lock *new,
                               void *data, __u32 data_len)
{
        printk("ldlm_test_callback: lock=%p, new=%p\n", lock, new);
        return 0;
}

int ldlm_test_basics(struct obd_device *obddev)
{
        struct ldlm_namespace *ns;
        struct ldlm_resource *res;
        __u64 res_id[RES_NAME_SIZE] = {1, 2, 3};
        ldlm_error_t err;
        struct lustre_handle lockh_1, lockh_2;
        int flags;

        ns = ldlm_namespace_new(LDLM_NAMESPACE_SERVER);
        if (ns == NULL)
                LBUG();

        err = ldlm_local_lock_create(ns, NULL, res_id, LDLM_PLAIN, LCK_CR,
                                     NULL, 0, &lockh_1);
        err = ldlm_local_lock_enqueue(&lockh_1, NULL, 0, &flags,
                                      ldlm_test_callback, ldlm_test_callback);
        if (err != ELDLM_OK)
                LBUG();

        err = ldlm_local_lock_create(ns, NULL, res_id, LDLM_PLAIN, LCK_EX,
                                     NULL, 0, &lockh_2);
        err = ldlm_local_lock_enqueue(&lockh_2, NULL, 0, &flags,
                                      ldlm_test_callback, ldlm_test_callback);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_BLOCK_GRANTED))
                LBUG();

        res = ldlm_resource_get(ns, NULL, res_id, LDLM_PLAIN, 1);
        if (res == NULL)
                LBUG();
        ldlm_resource_dump(res);

        res = ldlm_local_lock_convert(&lockh_1, LCK_NL, &flags);
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
        struct ldlm_lock *lock;
        __u64 res_id[RES_NAME_SIZE] = {0, 0, 0};
        struct ldlm_extent ext1 = {4, 6}, ext2 = {6, 9}, ext3 = {10, 11};
        struct lustre_handle ext1_h, ext2_h, ext3_h;
        ldlm_error_t err;
        int flags;

        ns = ldlm_namespace_new(LDLM_NAMESPACE_SERVER);
        if (ns == NULL)
                LBUG();

        flags = 0;
        err = ldlm_local_lock_create(ns, NULL, res_id, LDLM_EXTENT, LCK_PR,
                                     NULL, 0, &ext1_h);
        err = ldlm_local_lock_enqueue(&ext1_h, &ext1, sizeof(ext1), &flags,
                                      NULL, NULL);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_LOCK_CHANGED))
                LBUG();

        flags = 0;
        err = ldlm_local_lock_create(ns, NULL, res_id, LDLM_EXTENT, LCK_PR,
                                     NULL, 0, &ext2_h);
        err = ldlm_local_lock_enqueue(&ext2_h, &ext2, sizeof(ext2), &flags,
                                      NULL, NULL);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_LOCK_CHANGED))
                LBUG();

        flags = 0;
        err = ldlm_local_lock_create(ns, NULL, res_id, LDLM_EXTENT, LCK_EX,
                                     NULL, 0, &ext3_h);
        err = ldlm_local_lock_enqueue(&ext3_h, &ext3, sizeof(ext3), &flags,
                                      NULL, NULL);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_BLOCK_GRANTED))
                LBUG();
        if (flags & LDLM_FL_LOCK_CHANGED)
                LBUG();

        /* Convert/cancel blocking locks */
        flags = 0;
        res = ldlm_local_lock_convert(&ext1_h, LCK_NL, &flags);
        if (res != NULL)
                ldlm_reprocess_all(res);

        flags = 0;
        lock = lustre_handle2object(&ext2_h);
        res = ldlm_local_lock_cancel(lock);
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
        struct ldlm_obd *ldlm = &obddev->u.ldlm;

        __u64 res_id[RES_NAME_SIZE] = {1, 2, 3};
        struct ldlm_extent ext = {4, 6};
        struct lustre_handle lockh1;
        int flags = 0;
        ldlm_error_t err;

        err = ldlm_cli_enqueue(ldlm->ldlm_client, conn, NULL,
                               obddev->obd_namespace, NULL, res_id, LDLM_EXTENT,
                               &ext, sizeof(ext), LCK_PR, &flags, NULL, NULL, 0,
                               &lockh1);
        CERROR("ldlm_cli_enqueue: %d\n", err);

        RETURN(err);
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
