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

static void ldlm_test_callback(struct ldlm_lock *lock, struct ldlm_lock *new)
{
        printk("ldlm_test_callback: lock=%p, new=%p\n", lock, new);
}

int ldlm_test(struct obd_device *obddev)
{
        struct ldlm_namespace *ns;
        struct ldlm_resource *res;
        __u32 res_id[RES_NAME_SIZE] = {1, 2, 3, 4, 5, 6};
        ldlm_error_t err;
        struct ldlm_handle h;

        ns = ldlm_namespace_new(obddev, 1);
        if (ns == NULL)
                BUG();

        res = ldlm_resource_get(ns, NULL, res_id, 1);
        if (res == NULL)
                BUG();

        res->lr_blocking = ldlm_test_callback;

        /* Get a couple of read locks */
        err = ldlm_local_lock_enqueue(obddev, 1, NULL, NULL, res_id, 
                                      LCK_CR, &h);
        if (err != ELDLM_OK)
                BUG();

        err = ldlm_local_lock_enqueue(obddev, 1, NULL, NULL, res_id, 
                                      LCK_CR, &h);
        if (err != ELDLM_OK)
                BUG();

        ldlm_resource_dump(res);

        return 0;
}
