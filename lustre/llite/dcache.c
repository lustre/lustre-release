/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 */

#include <linux/fs.h>
#include <linux/locks.h>
#include <linux/quotaops.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/obd_support.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_dlm.h>

extern struct address_space_operations ll_aops;

void ll_intent_release(struct dentry *de)
{
        struct lustre_handle *handle;
        ENTRY;

        if (de->d_it == NULL) {
                EXIT;
                return;
        }
        if (de->d_it->it_lock_mode) {
                handle = (struct lustre_handle *)de->d_it->it_lock_handle;
                if (de->d_it->it_op == IT_SETATTR) {
                        int rc;
                        ldlm_lock_decref(handle, de->d_it->it_lock_mode);
                        rc = ldlm_cli_cancel(handle);
                        if (rc < 0)
                                CERROR("ldlm_cli_cancel: %d\n", rc);
                } else
                        ldlm_lock_decref(handle, de->d_it->it_lock_mode);
        }
        de->d_it = NULL;
        EXIT;
}

int ll_revalidate2(struct dentry *de, int flags, struct lookup_intent *it)
{
        struct ll_sb_info *sbi = ll_s2sbi(de->d_sb);
        struct lustre_handle lockh;
        __u64 res_id[RES_NAME_SIZE] = {0};
        struct obd_device *obddev;
        ENTRY;

        if (it)
                RETURN(0); /* lookups will have NULL it */

        if (!de->d_inode)
                RETURN(0);

        obddev = class_conn2obd(&sbi->ll_mdc_conn);
        res_id[0] = de->d_inode->i_ino;

        CDEBUG(D_INFO, "trying to match res "LPU64"\n", res_id[0]);

        if (ldlm_lock_match(obddev->obd_namespace, res_id, LDLM_MDSINTENT,
                            NULL, 0, LCK_PR, &lockh)) {
                ldlm_lock_decref(&lockh, LCK_PR);
                RETURN(1);
        }

        if (ldlm_lock_match(obddev->obd_namespace, res_id, LDLM_MDSINTENT,
                            NULL, 0, LCK_PW, &lockh)) {
                ldlm_lock_decref(&lockh, LCK_PW);
                RETURN(1);
        }

        RETURN(0);
}

struct dentry_operations ll_d_ops = {
        d_revalidate2: ll_revalidate2,
        d_intent_release: ll_intent_release
};
