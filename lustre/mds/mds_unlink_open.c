/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mds/mds_unlink_open.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

/* code for handling open unlinked files */

#define DEBUG_SUBSYSTEM S_MDS

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/version.h>

#include <libcfs/list.h>
#include <obd_class.h>
#include <lustre_fsfilt.h>
#include <lustre_mds.h>
#include <lvfs.h>

#include "mds_internal.h"

int mds_osc_destroy_orphan(struct obd_device *obd,
                           umode_t mode,
                           struct lov_mds_md *lmm,
                           int lmm_size,
                           struct llog_cookie *logcookies,
                           int log_unlink)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_stripe_md *lsm = NULL;
        struct obd_trans_info oti = { 0 };
        struct obdo *oa;
        int rc;
        ENTRY;

        if (lmm_size == 0)
                RETURN(0);

        rc = obd_unpackmd(mds->mds_osc_exp, &lsm, lmm, lmm_size);
        if (rc < 0) {
                CERROR("Error unpack md %p\n", lmm);
                RETURN(rc);
        } else {
                LASSERT(rc >= sizeof(*lsm));
                rc = 0;
        }

        rc = obd_checkmd(mds->mds_osc_exp, obd->obd_self_export, lsm);
        if (rc)
                GOTO(out_free_memmd, rc);

        OBDO_ALLOC(oa);
        if (oa == NULL)
                GOTO(out_free_memmd, rc = -ENOMEM);
        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE;

        if (log_unlink && logcookies) {
                oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies = logcookies;
        }
        rc = obd_destroy(mds->mds_osc_exp, oa, lsm, &oti, obd->obd_self_export);
        OBDO_FREE(oa);
        if (rc)
                CDEBUG(D_INODE, "destroy orphan objid 0x"LPX64" on ost error "
                       "%d\n", lsm->lsm_object_id, rc);
out_free_memmd:
        obd_free_memmd(mds->mds_osc_exp, &lsm);
        RETURN(rc);
}

static int mds_unlink_orphan(struct obd_device *obd, struct dentry *dchild,
                             struct inode *inode, struct inode *pending_dir)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lov_mds_md *lmm = NULL;
        struct llog_cookie *logcookies = NULL;
        int lmm_size, log_unlink = 0, cookie_size = 0;
        void *handle = NULL;
        umode_t mode;
        int rc, err;
        ENTRY;

        LASSERT(mds->mds_osc_obd != NULL);
        
        /* We don't need to do any of these other things for orhpan dirs,
         * especially not mds_get_md (may get a default LOV EA, bug 4554) */
        mode = inode->i_mode;
        if (S_ISDIR(mode)) {
                rc = ll_vfs_rmdir(pending_dir, dchild, mds->mds_vfsmnt);
                if (rc)
                        CERROR("error %d unlinking dir %*s from PENDING\n",
                               rc, dchild->d_name.len, dchild->d_name.name);
                RETURN(rc);
        }

        lmm_size = mds->mds_max_mdsize;
        OBD_ALLOC(lmm, lmm_size);
        if (lmm == NULL)
                RETURN(-ENOMEM);

        rc = mds_get_md(obd, inode, lmm, &lmm_size, 1, 0, 0);
        if (rc < 0)
                GOTO(out_free_lmm, rc);

        handle = fsfilt_start_log(obd, pending_dir, FSFILT_OP_UNLINK, NULL,
                                  le32_to_cpu(lmm->lmm_stripe_count));
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                CERROR("error fsfilt_start: %d\n", rc);
                handle = NULL;
                GOTO(out_free_lmm, rc);
        }

        rc = ll_vfs_unlink(pending_dir, dchild, mds->mds_vfsmnt);
        if (rc) {
                CERROR("error %d unlinking orphan %.*s from PENDING\n",
                       rc, dchild->d_name.len, dchild->d_name.name);
        } else if (lmm_size) {
                cookie_size = mds_get_cookie_size(obd, lmm); 
                OBD_ALLOC(logcookies, cookie_size);
                if (logcookies == NULL)
                        rc = -ENOMEM;
                else if (mds_log_op_unlink(obd, lmm,lmm_size,logcookies,
                                           cookie_size) > 0)
                        log_unlink = 1;
        }

        err = fsfilt_commit(obd, pending_dir, handle, 0);
        if (err) {
                CERROR("error committing orphan unlink: %d\n", err);
                if (!rc)
                        rc = err;
        } else if (!rc) {
                rc = mds_osc_destroy_orphan(obd, mode, lmm, lmm_size,
                                            logcookies, log_unlink);
        }

        if (logcookies != NULL)
                OBD_FREE(logcookies, cookie_size);
out_free_lmm:
        OBD_FREE(lmm, mds->mds_max_mdsize);
        RETURN(rc);
}

/* Delete inodes which were previously open-unlinked but were not reopened
 * during MDS recovery for whatever reason (e.g. client also failed, recovery
 * aborted, etc). */
int mds_cleanup_pending(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lvfs_run_ctxt saved;
        struct file *file;
        struct dentry *dchild, *dentry;
        struct vfsmount *mnt;
        struct inode *child_inode, *pending_dir = mds->mds_pending_dir->d_inode;
        struct l_linux_dirent *dirent, *n;
        struct list_head dentry_list;
        char d_name[LL_FID_NAMELEN];
        unsigned long inum;
        int i = 0, rc = 0, item = 0, namlen;
        ENTRY;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        /* dentry and mnt ref dropped in dentry_open() on error, or
         * in filp_close() if dentry_open() succeeds */
        dentry = dget(mds->mds_pending_dir);
        if (IS_ERR(dentry))
                GOTO(err_pop, rc = PTR_ERR(dentry));
        mnt = mntget(mds->mds_vfsmnt);
        if (IS_ERR(mnt))
                GOTO(err_mntget, rc = PTR_ERR(mnt));

        file = dentry_open(mds->mds_pending_dir, mds->mds_vfsmnt,
                           O_RDONLY | O_LARGEFILE);
        if (IS_ERR(file))
                GOTO(err_pop, rc = PTR_ERR(file));

        INIT_LIST_HEAD(&dentry_list);
        rc = l_readdir(file, &dentry_list);
        filp_close(file, 0);
        if (rc < 0)
                GOTO(err_out, rc);

        list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                i++;
                list_del(&dirent->lld_list);

                namlen = strlen(dirent->lld_name);
                LASSERT(sizeof(d_name) >= namlen + 1);
                strcpy(d_name, dirent->lld_name);
                inum = dirent->lld_ino;
                OBD_FREE(dirent, sizeof(*dirent));

                CDEBUG(D_INODE, "entry %d of PENDING DIR: %s\n", i, d_name);

                if (((namlen == 1) && !strcmp(d_name, ".")) ||
                    ((namlen == 2) && !strcmp(d_name, "..")) || inum == 0)
                        continue;

                LOCK_INODE_MUTEX(pending_dir);
                dchild = lookup_one_len(d_name, mds->mds_pending_dir, namlen);
                if (IS_ERR(dchild)) {
                        UNLOCK_INODE_MUTEX(pending_dir);
                        GOTO(err_out, rc = PTR_ERR(dchild));
                }
                if (!dchild->d_inode) {
                        CWARN("%s: orphan %s has already been removed\n",
                              obd->obd_name, d_name);
                        GOTO(next, rc = 0);
                }

                if (is_bad_inode(dchild->d_inode)) {
                        CERROR("%s: bad orphan inode found %lu/%u\n",
                               obd->obd_name, dchild->d_inode->i_ino,
                               dchild->d_inode->i_generation);
                        GOTO(next, rc = -ENOENT);
                }

                child_inode = dchild->d_inode;
                MDS_DOWN_READ_ORPHAN_SEM(child_inode);
                if (mds_inode_is_orphan(child_inode) &&
                    mds_orphan_open_count(child_inode)) {
                        MDS_UP_READ_ORPHAN_SEM(child_inode);
                        CWARN("%s: orphan %s re-opened during recovery\n",
                              obd->obd_name, d_name);
                        GOTO(next, rc = 0);
                }
                MDS_UP_READ_ORPHAN_SEM(child_inode);

                rc = mds_unlink_orphan(obd, dchild, child_inode, pending_dir);
                CDEBUG(D_INODE, "%s: removed orphan %s: rc %d\n",
                       obd->obd_name, d_name, rc);
                if (rc == 0)
                        item++;
                else
                        rc = 0;
next:
                l_dput(dchild);
                UNLOCK_INODE_MUTEX(pending_dir);
        }
        rc = 0;
err_out:
        list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                list_del(&dirent->lld_list);
                OBD_FREE(dirent, sizeof(*dirent));
        }
err_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (item > 0)
                CWARN("%s: removed %d pending open-unlinked files\n",
                      obd->obd_name, item);
        RETURN(rc);

err_mntget:
        l_dput(mds->mds_pending_dir);
        goto err_pop;
}
