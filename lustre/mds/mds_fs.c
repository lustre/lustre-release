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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mds/mds_fs.c
 *
 * Lustre Metadata Server (MDS) filesystem interface code
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <lustre_mds.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_lib.h>
#include <lustre_fsfilt.h>
#include <lustre_disk.h>
#include <libcfs/list.h>

#include "mds_internal.h"


/* Creates an object with the same name as its fid.  Because this is not at all
 * performance sensitive, it is accomplished by creating a file, checking the
 * fid, and renaming it. */
int mds_obd_create(struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct mds_obd *mds = &exp->exp_obd->u.mds;
        struct inode *parent_inode = mds->mds_objects_dir->d_inode;
        unsigned int tmpname = cfs_rand();
        struct file *filp;
        struct dentry *new_child;
        struct lvfs_run_ctxt saved;
        char fidname[LL_FID_NAMELEN];
        void *handle;
        struct lvfs_ucred ucred = { 0 };
        int rc = 0, err, namelen;
        ENTRY;

        /* the owner of object file should always be root */
        cap_raise(ucred.luc_cap, CAP_SYS_RESOURCE);

        if (strncmp(exp->exp_obd->obd_name, MDD_OBD_NAME,
                                   strlen(MDD_OBD_NAME))) {
                RETURN(0);
        }

        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, &ucred);

        sprintf(fidname, "OBJECTS/%u.%u", tmpname, current->pid);
        filp = filp_open(fidname, O_CREAT | O_EXCL, 0666);
        if (IS_ERR(filp)) {
                rc = PTR_ERR(filp);
                if (rc == -EEXIST) {
                        CERROR("impossible object name collision %u\n",
                               tmpname);
                        LBUG();
                }
                CERROR("error creating tmp object %u: rc %d\n", tmpname, rc);
                GOTO(out_pop, rc);
        }

        LASSERT(mds->mds_objects_dir == filp->f_dentry->d_parent);

        /* FIXME: need to see how this should change to properly store FID
         *        into obdo (o_id == OID, o_seq = SEQ) (maybe as IGIF?). */
#define o_generation o_parent_oid
        oa->o_id = filp->f_dentry->d_inode->i_ino;
        oa->o_generation = filp->f_dentry->d_inode->i_generation;
        namelen = ll_fid2str(fidname, oa->o_id, oa->o_generation);

        LOCK_INODE_MUTEX_PARENT(parent_inode);
        new_child = lookup_one_len(fidname, mds->mds_objects_dir, namelen);

        if (IS_ERR(new_child)) {
                CERROR("getting neg dentry for obj rename: %d\n", rc);
                GOTO(out_close, rc = PTR_ERR(new_child));
        }
        if (new_child->d_inode != NULL) {
                CERROR("impossible non-negative obj dentry " LPU64":%u!\n",
                       oa->o_id, oa->o_generation);
                LBUG();
        }

        handle = fsfilt_start(exp->exp_obd, mds->mds_objects_dir->d_inode,
                              FSFILT_OP_RENAME, NULL);
        if (IS_ERR(handle))
                GOTO(out_dput, rc = PTR_ERR(handle));

        rc = ll_vfs_rename(mds->mds_objects_dir->d_inode, filp->f_dentry,
                           filp->f_vfsmnt, mds->mds_objects_dir->d_inode,
                           new_child, filp->f_vfsmnt);

        if (rc)
                CERROR("error renaming new object "LPU64":%u: rc %d\n",
                       oa->o_id, oa->o_generation, rc);

        err = fsfilt_commit(exp->exp_obd, mds->mds_objects_dir->d_inode,
                            handle, 0);
        if (!err) {
                oa->o_seq = mdt_to_obd_objseq(mds->mds_id);
                oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGENER | OBD_MD_FLGROUP;
        } else if (!rc)
                rc = err;
out_dput:
        dput(new_child);
out_close:
        UNLOCK_INODE_MUTEX(parent_inode);
        err = filp_close(filp, 0);
        if (err) {
                CERROR("closing tmpfile %u: rc %d\n", tmpname, rc);
                if (!rc)
                        rc = err;
        }
out_pop:
        pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, &ucred);
        RETURN(rc);
}

int mds_obd_destroy(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *ea, struct obd_trans_info *oti,
                    struct obd_export *md_exp, void *capa)
{
        struct mds_obd *mds = &exp->exp_obd->u.mds;
        struct inode *parent_inode = mds->mds_objects_dir->d_inode;
        struct obd_device *obd = exp->exp_obd;
        struct lvfs_run_ctxt saved;
        struct lvfs_ucred ucred = { 0 };
        char fidname[LL_FID_NAMELEN];
        struct inode *inode = NULL;
        struct dentry *de;
        void *handle;
        int err, namelen, rc = 0;
        ENTRY;

        cap_raise(ucred.luc_cap, CAP_SYS_RESOURCE);
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &ucred);

        namelen = ll_fid2str(fidname, oa->o_id, oa->o_generation);

        LOCK_INODE_MUTEX_PARENT(parent_inode);
        de = lookup_one_len(fidname, mds->mds_objects_dir, namelen);
        if (IS_ERR(de)) {
                rc = IS_ERR(de);
                de = NULL;
                CERROR("error looking up object "LPU64" %s: rc %d\n",
                       oa->o_id, fidname, rc);
                GOTO(out_dput, rc);
        }
        if (de->d_inode == NULL) {
                CERROR("destroying non-existent object "LPU64" %s: rc %d\n",
                       oa->o_id, fidname, rc);
                GOTO(out_dput, rc = -ENOENT);
        }

        /* Stripe count is 1 here since this is some MDS specific stuff
           that is unlinked, not spanned across multiple OSTs */
        handle = fsfilt_start_log(obd, mds->mds_objects_dir->d_inode,
                                  FSFILT_OP_UNLINK, oti, 1);

        if (IS_ERR(handle))
                GOTO(out_dput, rc = PTR_ERR(handle));

        /* take a reference to protect inode from truncation within
           vfs_unlink() context. bug 10409 */
        inode = de->d_inode;
        atomic_inc(&inode->i_count);
        rc = ll_vfs_unlink(mds->mds_objects_dir->d_inode, de,
                           mds->mds_obt.obt_vfsmnt);
        if (rc)
                CERROR("error destroying object "LPU64":%u: rc %d\n",
                       oa->o_id, oa->o_generation, rc);
#undef o_generation

        err = fsfilt_commit(obd, mds->mds_objects_dir->d_inode, handle, 0);
        if (err && !rc)
                rc = err;
out_dput:
        if (de != NULL)
                l_dput(de);
        UNLOCK_INODE_MUTEX(parent_inode);

        if (inode)
                iput(inode);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &ucred);
        RETURN(rc);
}
