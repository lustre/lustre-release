/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001, 2002 Cluster File Systems, Inc.
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

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/quotaops.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/obd_support.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_dlm.h>

extern struct address_space_operations ll_aops;

void ll_release(struct dentry *de)
{
        ENTRY;

        OBD_FREE(de->d_fsdata, sizeof(struct ll_dentry_data));
        EXIT;
}

void ll_intent_release(struct dentry *de)
{
        struct lookup_intent *it;
        struct lustre_handle *handle;
        ENTRY;

        it = de->d_it;
        if (it == NULL) {
                EXIT;
                return;
        }

        LASSERT(ll_d2d(de) != NULL);

        if (it->it_lock_mode) {
                handle = (struct lustre_handle *)it->it_lock_handle;
                if (it->it_op == IT_SETATTR) {
                        int rc;
                        ldlm_lock_decref(handle, it->it_lock_mode);
                        rc = ldlm_cli_cancel(handle);
                        if (rc < 0)
                                CERROR("ldlm_cli_cancel: %d\n", rc);
                } else
                        ldlm_lock_decref(handle, it->it_lock_mode);
        }
        de->d_it = NULL;
        //up(&ll_d2d(de)->lld_it_sem);
        EXIT;
}

int ll_revalidate2(struct dentry *de, int flags, struct lookup_intent *it)
{
        struct ll_sb_info *sbi = ll_s2sbi(de->d_sb);
        struct lustre_handle lockh;
        __u64 res_id[RES_NAME_SIZE] = {0};
        struct obd_device *obddev;
        int rc = 0;
        ENTRY;

        if (it) {
                CDEBUG(D_INFO, "name: %*s, intent: %s\n", de->d_name.len,
                       de->d_name.name, ldlm_it2str(it->it_op));
                if (it->it_op == IT_RENAME)
                        it->it_data = de;
        }

        if (!de->d_inode)
                GOTO(out, rc = 0);

        obddev = class_conn2obd(&sbi->ll_mdc_conn);
        res_id[0] = de->d_inode->i_ino;

        CDEBUG(D_INFO, "trying to match res "LPU64"\n", res_id[0]);

        if (ldlm_lock_match(obddev->obd_namespace, res_id, LDLM_MDSINTENT,
                            NULL, 0, LCK_PR, &lockh)) {
                ldlm_lock_decref(&lockh, LCK_PR);
                GOTO(out, rc = 1);
        }

        if (ldlm_lock_match(obddev->obd_namespace, res_id, LDLM_MDSINTENT,
                            NULL, 0, LCK_PW, &lockh)) {
                ldlm_lock_decref(&lockh, LCK_PW);
                GOTO(out, rc = 1);
        }

        /* If the dentry is busy, we won't get called in lookup2 if we
         * return 0, so return 1.
         *
         * This is a temporary fix for bug 618962, but is one of the causes of
         * 619078. */
        CDEBUG(D_INFO, "d_count: %d\n", atomic_read(&de->d_count));
        if (it && atomic_read(&de->d_count) > 0) {
                CERROR("returning 1 for %*s during %s because d_count is %d\n",
                       de->d_name.len, de->d_name.name, ldlm_it2str(it->it_op),
                       atomic_read(&de->d_count));
                GOTO(out, rc = 1);
        }

 out:
        if (ll_d2d(de) == NULL) {
                CERROR("allocating fsdata\n");
                ll_set_dd(de);
        }
        //down(&ll_d2d(de)->lld_it_sem);
        // de->d_it = it;

        RETURN(rc);
}

int ll_set_dd(struct dentry *de)
{
        ENTRY;
        LASSERT(de != NULL);

        lock_kernel();

        if (de->d_fsdata != NULL) {
                CERROR("dentry %p already has d_fsdata set\n", de);
        } else {
                OBD_ALLOC(de->d_fsdata, sizeof(struct ll_dentry_data));
                sema_init(&ll_d2d(de)->lld_it_sem, 1);
        }

        unlock_kernel();

        RETURN(0);
}

struct dentry_operations ll_d_ops = {
        .d_revalidate2 = ll_revalidate2,
        .d_intent_release = ll_intent_release,
        .d_release = ll_release,
};
