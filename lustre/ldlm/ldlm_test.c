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

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/obd_support.h>
#include <linux/obd_class.h>

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
        struct ldlm_handle lockh_1, lockh_2;
        int flags;

        ldlm_lock(obddev);

        err = ldlm_namespace_new(obddev, 1, &ns);
        if (err != ELDLM_OK)
                LBUG();

        res = ldlm_resource_get(ns, NULL, res_id, LDLM_PLAIN, 1);
        if (res == NULL)
                LBUG();

        /* Get a couple of read locks */
        err = ldlm_local_lock_enqueue(obddev, 1, NULL, res_id, LDLM_PLAIN,
                                      NULL, LCK_CR, &flags, NULL,
                                      ldlm_test_callback, NULL, 0, &lockh_1);
        if (err != ELDLM_OK)
                LBUG();

        err = ldlm_local_lock_enqueue(obddev, 1, NULL, res_id, LDLM_PLAIN,
                                      NULL, LCK_EX, &flags, NULL,
                                      ldlm_test_callback, NULL, 0, &lockh_2);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_BLOCK_GRANTED))
                LBUG();

        ldlm_resource_dump(res);

        err = ldlm_local_lock_convert(obddev, &lockh_1, LCK_NL, &flags);
        if (err != ELDLM_OK)
                LBUG();

        ldlm_resource_dump(res);

        ldlm_unlock(obddev);

        return 0;
}

int ldlm_test_extents(struct obd_device *obddev)
{
        struct ldlm_namespace *ns;
        struct ldlm_resource *res;
        __u64 res_id[RES_NAME_SIZE] = {0, 0, 0};
        struct ldlm_extent ext1 = {4, 6}, ext2 = {6, 9}, ext3 = {10, 11};
        struct ldlm_handle ext1_h, ext2_h, ext3_h;
        ldlm_error_t err;
        int flags;

        ldlm_lock(obddev);

        err = ldlm_namespace_new(obddev, 2, &ns);
        if (err != ELDLM_OK)
                LBUG();

        flags = 0;
        err = ldlm_local_lock_enqueue(obddev, 2, NULL, res_id, LDLM_EXTENT,
                                      &ext1, LCK_PR, &flags, NULL, NULL, NULL,
                                      0, &ext1_h);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_LOCK_CHANGED))
                LBUG();

        flags = 0;
        err = ldlm_local_lock_enqueue(obddev, 2, NULL, res_id, LDLM_EXTENT,
                                      &ext2, LCK_PR, &flags, NULL, NULL, NULL,
                                      0, &ext2_h);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_LOCK_CHANGED))
                LBUG();

        flags = 0;
        err = ldlm_local_lock_enqueue(obddev, 2, NULL, res_id, LDLM_EXTENT,
                                      &ext3, LCK_EX, &flags, NULL, NULL, NULL,
                                      0, &ext3_h);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_BLOCK_GRANTED))
                LBUG();
        if (flags & LDLM_FL_LOCK_CHANGED)
                LBUG();

        /* Convert/cancel blocking locks */
        flags = 0;
        err = ldlm_local_lock_convert(obddev, &ext1_h, LCK_NL, &flags);
        if (err != ELDLM_OK)
                LBUG();

        flags = 0;
        err = ldlm_local_lock_cancel(obddev, &ext2_h);
        if (err != ELDLM_OK)
                LBUG();

        /* Dump the results */
        res = ldlm_resource_get(ns, NULL, res_id, LDLM_EXTENT, 0);
        if (res == NULL)
                LBUG();
        ldlm_resource_dump(res);

        ldlm_unlock(obddev);

        return 0;
}

static int ldlm_test_network(struct obd_device *obddev)
{
        struct ldlm_obd *ldlm = &obddev->u.ldlm;
        struct ptlrpc_request *request;

        __u64 res_id[RES_NAME_SIZE] = {1, 2, 3};
        struct ldlm_extent ext = {4, 6};
        struct ldlm_handle lockh1, lockh2;
        int flags = 0;
        ldlm_error_t err;

        err = ldlm_cli_namespace_new(ldlm->ldlm_client, &ldlm->ldlm_server_peer,
                                     3, &request);
        ptlrpc_free_req(request);
        CERROR("ldlm_cli_namespace_new: %d\n", err);
        if (err != ELDLM_OK)
                GOTO(out, err);

        err = ldlm_cli_enqueue(ldlm->ldlm_client, &ldlm->ldlm_server_peer, 3,
                               NULL, res_id, LDLM_EXTENT, &ext, LCK_PR, &flags,
                               NULL, 0, &lockh1, &request);
        ptlrpc_free_req(request);
        CERROR("ldlm_cli_enqueue: %d\n", err);

        flags = 0;
        err = ldlm_cli_enqueue(ldlm->ldlm_client, &ldlm->ldlm_server_peer, 3,
                               NULL, res_id, LDLM_EXTENT, &ext, LCK_EX, &flags,
                               NULL, 0, &lockh2, &request);
        ptlrpc_free_req(request);
        CERROR("ldlm_cli_enqueue: %d\n", err);

        EXIT;
 out:
        return err;
}

int ldlm_test(struct obd_device *obddev)
{
        int rc;
        rc = ldlm_test_basics(obddev);
        if (rc)
                RETURN(rc);

        rc = ldlm_test_extents(obddev);
        if (rc)
                RETURN(rc);

        rc = ldlm_test_network(obddev);
        RETURN(rc);
}
