/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 *  Copyright (C) 2001, Cluster File Systems, Inc.
 * 
 */

#include <linux/fs.h>
#include <linux/locks.h>
#include <linux/quotaops.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/obd_support.h>
#include <linux/lustre_lite.h>

extern struct address_space_operations ll_aops;

void ll_intent_release(struct dentry *de)
{
        struct ldlm_lock *lock;
        struct lustre_handle *handle;
        ENTRY;

        if (de->d_it == NULL) {
                EXIT;
                return;
        }

        handle = (struct lustre_handle *)de->d_it->it_lock_handle;
        lock = lustre_handle2object(handle);
        CDEBUG(D_INFO, "calling ldlm_lock_decref(%p, %d)\n", lock,
               de->d_it->it_lock_mode);
        ldlm_lock_decref(lock, de->d_it->it_lock_mode);
        de->d_it = NULL;
        EXIT;
}

int ll_revalidate2(struct dentry *de, int flags, struct lookup_intent *it)
{
        ENTRY;
        
        RETURN(0);
}


struct dentry_operations ll_d_ops = { 
        d_revalidate2: ll_revalidate2,
        d_intent_release: ll_intent_release
};
