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
        __u64 res_id[RES_NAME_SIZE] = {1, 4, 3};
        ldlm_error_t err;
        struct ldlm_handle h;
        int flags;

        ldlm_lock(obddev);

        ns = ldlm_namespace_new(obddev, 1);
        if (ns == NULL)
                LBUG();

        res = ldlm_resource_get(ns, NULL, res_id, LDLM_PLAIN, 1);
        if (res == NULL)
                LBUG();

        /* Get a couple of read locks */
        flags = LDLM_FL_BLOCKING_AST;
        err = ldlm_local_lock_enqueue(obddev, 1, NULL, res_id, LDLM_PLAIN,
                                      LCK_CR, &flags, NULL, ldlm_test_callback,
                                      NULL, 0, &h);
        if (err != ELDLM_OK)
                LBUG();

        err = ldlm_local_lock_enqueue(obddev, 1, NULL, res_id, LDLM_PLAIN,
                                      LCK_EX, &flags, NULL, ldlm_test_callback,
                                      NULL, 0, &h);
        if (err != -ELDLM_BLOCK_GRANTED)
                LBUG();

        ldlm_resource_dump(res);

        ldlm_unlock(obddev);

        return 0;
}

int ldlm_test_extents(struct obd_device *obddev)
{
        struct ldlm_namespace *ns;
        struct ldlm_resource *res;
        __u64 file_res_id[RES_NAME_SIZE] = {0, 0, 0};
        __u64 res_ext1[RES_NAME_SIZE] = {4, 6, 3};
        __u64 res_ext2[RES_NAME_SIZE] = {6, 9, 3};
        __u64 res_ext3[RES_NAME_SIZE] = {10, 11, 3};
        ldlm_error_t err;
        struct ldlm_handle file_h, ext1_h, ext2_h, ext3_h;
        int flags;

        ldlm_lock(obddev);

        ns = ldlm_namespace_new(obddev, 2);
        if (ns == NULL)
                LBUG();

        err = ldlm_local_lock_enqueue(obddev, 1, NULL, file_res_id, LDLM_EXTENT,
                                      LCK_NL, &flags, NULL, NULL, NULL, 0,
                                      &file_h);
        if (err != ELDLM_OK)
                LBUG();

        flags = 0;
        err = ldlm_local_lock_enqueue(obddev, 1, &file_h, res_ext1, LDLM_EXTENT,
                                      LCK_PR, &flags, NULL, NULL, NULL, 0,
                                      &ext1_h);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_RES_CHANGED))
                LBUG();

        flags = 0;
        err = ldlm_local_lock_enqueue(obddev, 1, &file_h, res_ext2, LDLM_EXTENT,
                                      LCK_PR, &flags, NULL, NULL, NULL, 0,
                                      &ext2_h);
        if (err != ELDLM_OK)
                LBUG();
        if (!(flags & LDLM_FL_RES_CHANGED))
                LBUG();

        flags = 0;
        err = ldlm_local_lock_enqueue(obddev, 1, &file_h, res_ext3, LDLM_EXTENT,
                                      LCK_EX, &flags, NULL, NULL, NULL, 0,
                                      &ext3_h);
        if (err != -ELDLM_BLOCK_GRANTED)
                LBUG();
        if (flags & LDLM_FL_RES_CHANGED)
                LBUG();

        /* Convert/cancel blocking locks */
        flags = 0;
        err = ldlm_local_lock_convert(obddev, &ext1_h, LCK_NL, &flags);
        if (err != ELDLM_OK)
                LBUG();

        flags = 0;
        err = ldlm_local_lock_cancel(obddev, &ext1_h);
        if (err != ELDLM_OK)
                LBUG();

        /* Dump the results */
        res = ldlm_resource_get(ns, NULL, file_res_id, LDLM_EXTENT, 0);
        if (res == NULL)
                LBUG();
        ldlm_resource_dump(res);
        res = ldlm_resource_get(ns, NULL, res_ext1, LDLM_EXTENT, 0);
        if (res == NULL)
                LBUG();
        ldlm_resource_dump(res);
        res = ldlm_resource_get(ns, NULL, res_ext2, LDLM_EXTENT, 0);
        if (res == NULL)
                LBUG();
        ldlm_resource_dump(res);

        ldlm_unlock(obddev);

        return 0;
}

int ldlm_test(struct obd_device *obddev)
{
        int rc; 
        rc = ldlm_test_basics(obddev);
        if (rc) 
                RETURN(rc);

        rc = ldlm_test_extents(obddev);
        RETURN(rc); 
}
