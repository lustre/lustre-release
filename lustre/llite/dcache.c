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

extern void d_delete_aliases(struct inode *);
void ll_intent_release(struct dentry *de, struct lookup_intent *it)
{
        struct lustre_handle *handle;
        ENTRY;

        /* XXX the check for RENAME2 is a workaround for old kernels 
           which call intent_release twice in rename 
        */
        if (it == NULL || it->it_op == IT_RENAME2) {
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

        if (it->it_op == IT_RELEASED_MAGIC) {
                EXIT; 
                return;
        }

        if (de->d_it && de->d_it == it) { 
                de->d_it = NULL;
                up(&ll_d2d(de)->lld_it_sem);
                it->it_op = IT_RELEASED_MAGIC;
        }

        EXIT;
}

extern struct dentry *ll_find_alias(struct inode *, struct dentry *);

static int revalidate2_finish(int flag, struct ptlrpc_request *request, 
                          struct dentry **de,
                          struct lookup_intent *it, 
                          int offset, obd_id ino)
{
        ldlm_lock_set_data((struct lustre_handle *)it->it_lock_handle,
                           (*de)->d_inode, sizeof(*((*de)->d_inode)));
        ptlrpc_req_finished(request);
        return 0;
}

int ll_revalidate2(struct dentry *de, int flags, struct lookup_intent *it)
{
        int rc;
        ENTRY;

        /* We don't want to cache negative dentries, so return 0 immediately.
         * We believe that this is safe, that negative dentries cannot be
         * pinned by someone else */
        if (de->d_inode == NULL) {
                CDEBUG(D_INODE, "negative dentry: ret 0 to force lookup2\n");
                RETURN(0);
        }

        rc = ll_intent_lock(de->d_parent->d_inode, &de, it, revalidate2_finish);
        if (rc < 0) {
                /* Something bad happened; overwrite it_status? */
                CERROR("ll_intent_lock: %d\n", rc);
        }
        /* unfortunately ll_intent_lock may cause a callback and revoke our 
           dentry */
        spin_lock(&dcache_lock);
        list_del_init(&de->d_hash);
        spin_unlock(&dcache_lock);
        d_rehash(de);

        if (!it)
                de->d_it = NULL;

        RETURN(1);
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
