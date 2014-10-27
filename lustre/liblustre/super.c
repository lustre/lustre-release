/*
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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/liblustre/super.c
 *
 * Lustre Light Super operations
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>
#ifndef __CYGWIN__
# include <sys/statvfs.h>
#else
# include <sys/statfs.h>
#endif

#include "llite_lib.h"

#ifndef MAY_EXEC
#define MAY_EXEC        1
#define MAY_WRITE       2
#define MAY_READ        4
#endif

#define S_IXUGO (S_IXUSR|S_IXGRP|S_IXOTH)

static int ll_permission(struct inode *inode, int mask)
{
        struct intnl_stat *st = llu_i2stat(inode);
        mode_t mode = st->st_mode;

	if (current->fsuid == st->st_uid)
		mode >>= 6;
	else if (in_group_p(st->st_gid))
		mode >>= 3;

        if ((mode & mask & (MAY_READ|MAY_WRITE|MAY_EXEC)) == mask)
                return 0;

        if ((mask & (MAY_READ|MAY_WRITE)) ||
            (st->st_mode & S_IXUGO))
                if (cfs_capable(CFS_CAP_DAC_OVERRIDE))
                        return 0;

        if (mask == MAY_READ ||
            (S_ISDIR(st->st_mode) && !(mask & MAY_WRITE))) {
                if (cfs_capable(CFS_CAP_DAC_READ_SEARCH))
                        return 0;
        }

        return -EACCES;
}

static void llu_fsop_gone(struct filesys *fs)
{
        struct llu_sb_info *sbi = (struct llu_sb_info *) fs->fs_private;
        struct obd_device *obd = class_exp2obd(sbi->ll_md_exp);
        int next = 0;
        ENTRY;

        cfs_list_del(&sbi->ll_conn_chain);
        cl_sb_fini(sbi);
        obd_disconnect(sbi->ll_dt_exp);
        obd_disconnect(sbi->ll_md_exp);

        while ((obd = class_devices_in_group(&sbi->ll_sb_uuid, &next)) != NULL)
                class_manual_cleanup(obd);

        OBD_FREE(sbi, sizeof(*sbi));

        liblustre_wait_idle();
        EXIT;
}

static struct inode_ops llu_inode_ops;

static ldlm_mode_t llu_take_md_lock(struct inode *inode, __u64 bits,
                                    struct lustre_handle *lockh)
{
        ldlm_policy_data_t policy = { .l_inodebits = {bits}};
        struct lu_fid *fid;
        ldlm_mode_t rc;
	__u64 flags;
        ENTRY;

        fid = &llu_i2info(inode)->lli_fid;
        CDEBUG(D_INFO, "trying to match res "DFID"\n", PFID(fid));

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING;
        rc = md_lock_match(llu_i2mdexp(inode), flags, fid, LDLM_IBITS, &policy,
                           LCK_CR|LCK_CW|LCK_PR|LCK_PW, lockh);
        RETURN(rc);
}

void llu_update_inode(struct inode *inode, struct lustre_md *md)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct mdt_body *body = md->body;
        struct lov_stripe_md *lsm = md->lsm;
        struct intnl_stat *st = llu_i2stat(inode);

        LASSERT ((lsm != NULL) == ((body->valid & OBD_MD_FLEASIZE) != 0));

        if (body->valid & OBD_MD_FLMODE)
                st->st_mode = (st->st_mode & S_IFMT)|(body->mode & ~S_IFMT);
        if (body->valid & OBD_MD_FLTYPE)
                st->st_mode = (st->st_mode & ~S_IFMT)|(body->mode & S_IFMT);

        if (lsm != NULL) {
		if (!lli->lli_has_smd) {
			cl_file_inode_init(inode, md);
			lli->lli_has_smd = true;
			lli->lli_maxbytes = lsm->lsm_maxbytes;
			if (lli->lli_maxbytes > MAX_LFS_FILESIZE)
				lli->lli_maxbytes = MAX_LFS_FILESIZE;
		}
		if (md->lsm != NULL)
			obd_free_memmd(llu_i2obdexp(inode), &md->lsm);
        }

        if (body->valid & OBD_MD_FLATIME) {
                if (body->atime > LTIME_S(st->st_atime))
                        LTIME_S(st->st_atime) = body->atime;
                lli->lli_lvb.lvb_atime = body->atime;
        }
        if (body->valid & OBD_MD_FLMTIME) {
                if (body->mtime > LTIME_S(st->st_mtime))
                        LTIME_S(st->st_mtime) = body->mtime;
                lli->lli_lvb.lvb_mtime = body->mtime;
        }
        if (body->valid & OBD_MD_FLCTIME) {
                if (body->ctime > LTIME_S(st->st_ctime))
                        LTIME_S(st->st_ctime) = body->ctime;
                lli->lli_lvb.lvb_ctime = body->ctime;
        }
        if (S_ISREG(st->st_mode))
                st->st_blksize = min(2UL * PTLRPC_MAX_BRW_SIZE, LL_MAX_BLKSIZE);
        else
                st->st_blksize = 4096;
        if (body->valid & OBD_MD_FLUID)
                st->st_uid = body->uid;
        if (body->valid & OBD_MD_FLGID)
                st->st_gid = body->gid;
        if (body->valid & OBD_MD_FLNLINK)
                st->st_nlink = body->nlink;
        if (body->valid & OBD_MD_FLRDEV)
                st->st_rdev = body->rdev;
        if (body->valid & OBD_MD_FLFLAGS)
                lli->lli_st_flags = body->flags;
        if (body->valid & OBD_MD_FLSIZE) {
                if ((llu_i2sbi(inode)->ll_lco.lco_flags & OBD_CONNECT_SOM) &&
		    S_ISREG(st->st_mode) && lli->lli_has_smd) {
                        struct lustre_handle lockh;
                        ldlm_mode_t mode;

                        /* As it is possible a blocking ast has been processed
                         * by this time, we need to check there is an UPDATE
                         * lock on the client and set LLIF_MDS_SIZE_LOCK holding
                         * it. */
                        mode = llu_take_md_lock(inode, MDS_INODELOCK_UPDATE,
                                                &lockh);
                        if (mode) {
                                st->st_size = body->size;
                                lli->lli_flags |= LLIF_MDS_SIZE_LOCK;
                                ldlm_lock_decref(&lockh, mode);
                        }
                } else {
                    st->st_size = body->size;
                }

                if (body->valid & OBD_MD_FLBLOCKS)
                        st->st_blocks = body->blocks;
        }
}

void obdo_to_inode(struct inode *dst, struct obdo *src, obd_flag valid)
{
        struct llu_inode_info *lli = llu_i2info(dst);
        struct intnl_stat *st = llu_i2stat(dst);

        valid &= src->o_valid;

	LASSERTF(!(valid & (OBD_MD_FLTYPE | OBD_MD_FLGENER | OBD_MD_FLFID |
			    OBD_MD_FLID | OBD_MD_FLGROUP)),
		 "object "DOSTID", valid %x\n", POSTID(&src->o_oi), valid);

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE,"valid "LPX64", cur time "CFS_TIME_T"/"CFS_TIME_T
                       ", new %lu/%lu\n",
                       src->o_valid,
                       LTIME_S(st->st_mtime), LTIME_S(st->st_ctime),
                       (long)src->o_mtime, (long)src->o_ctime);

        if (valid & OBD_MD_FLATIME)
                LTIME_S(st->st_atime) = src->o_atime;
        if (valid & OBD_MD_FLMTIME)
                LTIME_S(st->st_mtime) = src->o_mtime;
        if (valid & OBD_MD_FLCTIME && src->o_ctime > LTIME_S(st->st_ctime))
                LTIME_S(st->st_ctime) = src->o_ctime;
        if (valid & OBD_MD_FLSIZE)
                st->st_size = src->o_size;
        if (valid & OBD_MD_FLBLOCKS) /* allocation of space */
                st->st_blocks = src->o_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                st->st_blksize = src->o_blksize;
        if (valid & OBD_MD_FLTYPE)
                st->st_mode = (st->st_mode & ~S_IFMT) | (src->o_mode & S_IFMT);
        if (valid & OBD_MD_FLMODE)
                st->st_mode = (st->st_mode & S_IFMT) | (src->o_mode & ~S_IFMT);
        if (valid & OBD_MD_FLUID)
                st->st_uid = src->o_uid;
        if (valid & OBD_MD_FLGID)
                st->st_gid = src->o_gid;
        if (valid & OBD_MD_FLFLAGS)
                lli->lli_st_flags = src->o_flags;
}

/**
 * Performs the getattr on the inode and updates its fields.
 * If @sync != 0, perform the getattr under the server-side lock.
 */
int llu_inode_getattr(struct inode *inode, struct obdo *obdo,
                      __u64 ioepoch, int sync)
{
	struct ptlrpc_request_set *set;
	struct lov_stripe_md *lsm = NULL;
	struct obd_info oinfo = { { { 0 } } };
	int rc;
	ENTRY;

	lsm = ccc_inode_lsm_get(inode);
        LASSERT(lsm);

        oinfo.oi_md = lsm;
        oinfo.oi_oa = obdo;
	oinfo.oi_oa->o_oi = lsm->lsm_oi;
        oinfo.oi_oa->o_mode = S_IFREG;
        oinfo.oi_oa->o_ioepoch = ioepoch;
        oinfo.oi_oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE |
                               OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                               OBD_MD_FLBLKSZ | OBD_MD_FLMTIME |
                               OBD_MD_FLCTIME | OBD_MD_FLGROUP |
                               OBD_MD_FLATIME | OBD_MD_FLEPOCH;
        obdo_set_parent_fid(oinfo.oi_oa, &llu_i2info(inode)->lli_fid);
        if (sync) {
                oinfo.oi_oa->o_valid |= OBD_MD_FLFLAGS;
                oinfo.oi_oa->o_flags |= OBD_FL_SRVLOCK;
        }

        set = ptlrpc_prep_set();
        if (set == NULL) {
                CERROR ("ENOMEM allocing request set\n");
                rc = -ENOMEM;
        } else {
                rc = obd_getattr_async(llu_i2obdexp(inode), &oinfo, set);
                if (rc == 0)
                        rc = ptlrpc_set_wait(set);
                ptlrpc_set_destroy(set);
        }
	ccc_inode_lsm_put(inode, lsm);
        if (rc)
                RETURN(rc);

        oinfo.oi_oa->o_valid = OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ |
                               OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                               OBD_MD_FLSIZE;

	obdo_refresh_inode(inode, oinfo.oi_oa, oinfo.oi_oa->o_valid);
	CDEBUG(D_INODE, "objid "DOSTID" size %llu, blocks %llu, "
	       "blksize %llu\n", POSTID(&oinfo.oi_oa->o_oi),
	       (long long unsigned)llu_i2stat(inode)->st_size,
	       (long long unsigned)llu_i2stat(inode)->st_blocks,
	       (long long unsigned)llu_i2stat(inode)->st_blksize);
	RETURN(0);
}

static struct inode* llu_new_inode(struct filesys *fs,
                                   struct lu_fid *fid)
{
        struct inode *inode;
        struct llu_inode_info *lli;
        struct intnl_stat st = {
                .st_dev  = 0,
#if 0
#ifndef AUTOMOUNT_FILE_NAME
                .st_mode = fid->f_type & S_IFMT,
#else
                .st_mode = fid->f_type /* all of the bits! */
#endif
#endif
                /* FIXME: fix this later */
                .st_mode = 0,

                .st_uid  = geteuid(),
                .st_gid  = getegid(),
        };

        OBD_ALLOC(lli, sizeof(*lli));
        if (!lli)
                return NULL;

        /* initialize lli here */
        lli->lli_sbi = llu_fs2sbi(fs);
	lli->lli_has_smd = false;
        lli->lli_symlink_name = NULL;
        lli->lli_flags = 0;
        lli->lli_maxbytes = (__u64)(~0UL);
        lli->lli_file_data = NULL;

        lli->lli_sysio_fid.fid_data = &lli->lli_fid;
        lli->lli_sysio_fid.fid_len = sizeof(lli->lli_fid);
        lli->lli_fid = *fid;

        /* file identifier is needed by functions like _sysio_i_find() */
        inode = _sysio_i_new(fs, &lli->lli_sysio_fid,
                             &st, 0, &llu_inode_ops, lli);

        if (!inode)
                OBD_FREE(lli, sizeof(*lli));

        return inode;
}

static int llu_have_md_lock(struct inode *inode, __u64 lockpart)
{
        struct lustre_handle lockh;
        ldlm_policy_data_t policy = { .l_inodebits = { lockpart } };
        struct lu_fid *fid;
	__u64 flags;
        ENTRY;

        LASSERT(inode);

        fid = &llu_i2info(inode)->lli_fid;
        CDEBUG(D_INFO, "trying to match res "DFID"\n", PFID(fid));

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING | LDLM_FL_TEST_LOCK;
        if (md_lock_match(llu_i2mdexp(inode), flags, fid, LDLM_IBITS, &policy,
                          LCK_CR|LCK_CW|LCK_PR|LCK_PW, &lockh)) {
                RETURN(1);
        }
        RETURN(0);
}

static int llu_inode_revalidate(struct inode *inode)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat *st = llu_i2stat(inode);
        ENTRY;

        if (!inode) {
                CERROR("REPORT THIS LINE TO PETER\n");
                RETURN(0);
        }

        if (!llu_have_md_lock(inode, MDS_INODELOCK_UPDATE)) {
                struct lustre_md md;
                struct ptlrpc_request *req = NULL;
                struct llu_sb_info *sbi = llu_i2sbi(inode);
                struct md_op_data op_data = { { 0 } };
                unsigned long valid = OBD_MD_FLGETATTR;
                int rc, ealen = 0;

                /* Why don't we update all valid MDS fields here, if we're
                 * doing an RPC anyways?  -phil */
                if (S_ISREG(st->st_mode)) {
                        ealen = obd_size_diskmd(sbi->ll_dt_exp, NULL);
                        valid |= OBD_MD_FLEASIZE;
                }

                llu_prep_md_op_data(&op_data, inode, NULL, NULL, 0, ealen,
                                    LUSTRE_OPC_ANY);
                op_data.op_valid = valid;

                rc = md_getattr(sbi->ll_md_exp, &op_data, &req);
                if (rc) {
                        CERROR("failure %d inode %llu\n", rc,
                               (long long)st->st_ino);
                        RETURN(-abs(rc));
                }
                rc = md_get_lustre_md(sbi->ll_md_exp, req,
                                      sbi->ll_dt_exp, sbi->ll_md_exp, &md);

                /* XXX Too paranoid? */
                if (((md.body->valid ^ valid) & OBD_MD_FLEASIZE) &&
                    !((md.body->valid & OBD_MD_FLNLINK) &&
                      (md.body->nlink == 0))) {
                        CERROR("Asked for %s eadata but got %s (%d)\n",
                               (valid & OBD_MD_FLEASIZE) ? "some" : "no",
                               (md.body->valid & OBD_MD_FLEASIZE) ? "some":"none",
                                md.body->eadatasize);
                }
                if (rc) {
                        ptlrpc_req_finished(req);
                        RETURN(rc);
                }


                llu_update_inode(inode, &md);
		if (md.lsm != NULL)
			obd_free_memmd(sbi->ll_dt_exp, &md.lsm);
		ptlrpc_req_finished(req);
	}

	if (!lli->lli_has_smd) {
                /* object not yet allocated, don't validate size */
                st->st_atime = lli->lli_lvb.lvb_atime;
                st->st_mtime = lli->lli_lvb.lvb_mtime;
                st->st_ctime = lli->lli_lvb.lvb_ctime;
                RETURN(0);
        }

        /* ll_glimpse_size will prefer locally cached writes if they extend
         * the file */
        RETURN(cl_glimpse_size(inode));
}

static void copy_stat_buf(struct inode *ino, struct intnl_stat *b)
{
        *b = *llu_i2stat(ino);
}

static int llu_iop_getattr(struct pnode *pno,
                           struct inode *ino,
                           struct intnl_stat *b)
{
        int rc;
        ENTRY;

        liblustre_wait_event(0);

        if (!ino) {
                LASSERT(pno);
                LASSERT(pno->p_base->pb_ino);
                ino = pno->p_base->pb_ino;
        } else {
                LASSERT(!pno || pno->p_base->pb_ino == ino);
        }

        /* libsysio might call us directly without intent lock,
         * we must re-fetch the attrs here
         */
        rc = llu_inode_revalidate(ino);
        if (!rc) {
                copy_stat_buf(ino, b);
                LASSERT(!llu_i2info(ino)->lli_it);
        }

        liblustre_wait_event(0);
        RETURN(rc);
}

static int null_if_equal(struct ldlm_lock *lock, void *data)
{
        if (data == lock->l_ast_data) {
                lock->l_ast_data = NULL;

                if (lock->l_req_mode != lock->l_granted_mode)
                        LDLM_ERROR(lock,"clearing inode with ungranted lock\n");
        }

        return LDLM_ITER_CONTINUE;
}

void llu_clear_inode(struct inode *inode)
{
	struct llu_inode_info *lli = llu_i2info(inode);
	struct llu_sb_info *sbi = llu_i2sbi(inode);
	struct lov_stripe_md *lsm;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%llu/%lu(%p)\n",
               (long long)llu_i2stat(inode)->st_ino, lli->lli_st_generation,
               inode);

        lli->lli_flags &= ~LLIF_MDS_SIZE_LOCK;
	md_null_inode(sbi->ll_md_exp, ll_inode2fid(inode));

	lsm = ccc_inode_lsm_get(inode);
	if (lsm != NULL)
		obd_change_cbdata(sbi->ll_dt_exp, lsm, null_if_equal, inode);
	ccc_inode_lsm_put(inode, lsm);

	cl_inode_fini(inode);
	lli->lli_has_smd = false;

        if (lli->lli_symlink_name) {
                OBD_FREE(lli->lli_symlink_name,
                         strlen(lli->lli_symlink_name) + 1);
                lli->lli_symlink_name = NULL;
        }

        EXIT;
}

void llu_iop_gone(struct inode *inode)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        ENTRY;

        liblustre_wait_event(0);
        llu_clear_inode(inode);

        OBD_FREE(lli, sizeof(*lli));
        EXIT;
}

static int inode_setattr(struct inode * inode, struct iattr * attr)
{
        unsigned int ia_valid = attr->ia_valid;
        struct intnl_stat *st = llu_i2stat(inode);
        int error = 0;

        /*
         * inode_setattr() is only ever invoked with ATTR_SIZE (by
         * llu_setattr_raw()) when file has no bodies. Check this.
         */
	LASSERT(ergo(ia_valid & ATTR_SIZE, !llu_i2info(inode)->lli_has_smd));

        if (ia_valid & ATTR_SIZE)
                st->st_size = attr->ia_size;
        if (ia_valid & ATTR_UID)
                st->st_uid = attr->ia_uid;
        if (ia_valid & ATTR_GID)
                st->st_gid = attr->ia_gid;
        if (ia_valid & ATTR_ATIME)
                st->st_atime = attr->ia_atime;
        if (ia_valid & ATTR_MTIME)
                st->st_mtime = attr->ia_mtime;
        if (ia_valid & ATTR_CTIME)
                st->st_ctime = attr->ia_ctime;
	if (ia_valid & ATTR_MODE) {
		st->st_mode = attr->ia_mode;
		if (!in_group_p(st->st_gid) &&
		    !cfs_capable(CFS_CAP_FSETID))
			st->st_mode &= ~S_ISGID;
	}
        /* mark_inode_dirty(inode); */
        return error;
}

int llu_md_setattr(struct inode *inode, struct md_op_data *op_data,
                   struct md_open_data **mod)
{
        struct lustre_md md;
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct ptlrpc_request *request = NULL;
        int rc;
        ENTRY;

        llu_prep_md_op_data(op_data, inode, NULL, NULL, 0, 0, LUSTRE_OPC_ANY);
        rc = md_setattr(sbi->ll_md_exp, op_data, NULL, 0, NULL,
                        0, &request, mod);

        if (rc) {
                ptlrpc_req_finished(request);
                if (rc != -EPERM && rc != -EACCES)
                        CERROR("md_setattr fails: rc = %d\n", rc);
                RETURN(rc);
        }

        rc = md_get_lustre_md(sbi->ll_md_exp, request,
                              sbi->ll_dt_exp, sbi->ll_md_exp, &md);
        if (rc) {
                ptlrpc_req_finished(request);
                RETURN(rc);
        }

        /* We call inode_setattr to adjust timestamps.
         * If there is at least some data in file, we cleared ATTR_SIZE
         * above to avoid invoking vmtruncate, otherwise it is important
         * to call vmtruncate in inode_setattr to update inode->i_size
         * (bug 6196) */
        inode_setattr(inode, &op_data->op_attr);
        llu_update_inode(inode, &md);
        ptlrpc_req_finished(request);

        RETURN(rc);
}

/* Close IO epoch and send Size-on-MDS attribute update. */
static int llu_setattr_done_writing(struct inode *inode,
                                    struct md_op_data *op_data,
                                    struct md_open_data *mod)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat *st = llu_i2stat(inode);
        int rc = 0;
        ENTRY;

        LASSERT(op_data != NULL);
        if (!S_ISREG(st->st_mode))
                RETURN(0);

        /* XXX: pass och here for the recovery purpose. */
        CDEBUG(D_INODE, "Epoch "LPU64" closed on "DFID" for truncate\n",
               op_data->op_ioepoch, PFID(&lli->lli_fid));

        op_data->op_flags = MF_EPOCH_CLOSE;
        llu_done_writing_attr(inode, op_data);
        llu_pack_inode2opdata(inode, op_data, NULL);

        rc = md_done_writing(llu_i2sbi(inode)->ll_md_exp, op_data, mod);
        if (rc == -EAGAIN) {
                /* MDS has instructed us to obtain Size-on-MDS attribute
                 * from OSTs and send setattr to back to MDS. */
                rc = llu_som_update(inode, op_data);
        } else if (rc) {
                CERROR("inode %llu mdc truncate failed: rc = %d\n",
                       (unsigned long long)st->st_ino, rc);
        }
        RETURN(rc);
}

/* If this inode has objects allocated to it (lsm != NULL), then the OST
 * object(s) determine the file size and mtime.  Otherwise, the MDS will
 * keep these values until such a time that objects are allocated for it.
 * We do the MDS operations first, as it is checking permissions for us.
 * We don't to the MDS RPC if there is nothing that we want to store there,
 * otherwise there is no harm in updating mtime/atime on the MDS if we are
 * going to do an RPC anyways.
 *
 * If we are doing a truncate, we will send the mtime and ctime updates
 * to the OST with the punch RPC, otherwise we do an explicit setattr RPC.
 * I don't believe it is possible to get e.g. ATTR_MTIME_SET and ATTR_SIZE
 * at the same time.
 */
int llu_setattr_raw(struct inode *inode, struct iattr *attr)
{
	int has_lsm = llu_i2info(inode)->lli_has_smd;
        struct intnl_stat *st = llu_i2stat(inode);
        int ia_valid = attr->ia_valid;
        struct md_op_data op_data = { { 0 } };
        struct md_open_data *mod = NULL;
        int rc = 0, rc1 = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%llu\n", (long long)st->st_ino);

        if (ia_valid & ATTR_SIZE) {
                if (attr->ia_size > ll_file_maxbytes(inode)) {
                        CDEBUG(D_INODE, "file too large %llu > "LPU64"\n",
                               (long long)attr->ia_size,
                               ll_file_maxbytes(inode));
                        RETURN(-EFBIG);
                }

                attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
        }

        /* We mark all of the fields "set" so MDS/OST does not re-set them */
        if (attr->ia_valid & ATTR_CTIME) {
                attr->ia_ctime = CFS_CURRENT_TIME;
                attr->ia_valid |= ATTR_CTIME_SET;
        }
        if (!(ia_valid & ATTR_ATIME_SET) && (attr->ia_valid & ATTR_ATIME)) {
                attr->ia_atime = CFS_CURRENT_TIME;
                attr->ia_valid |= ATTR_ATIME_SET;
        }
        if (!(ia_valid & ATTR_MTIME_SET) && (attr->ia_valid & ATTR_MTIME)) {
                attr->ia_mtime = CFS_CURRENT_TIME;
                attr->ia_valid |= ATTR_MTIME_SET;
        }

        if (attr->ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime "CFS_TIME_T", ctime "CFS_TIME_T
		       ", now = "CFS_TIME_T"\n",
		       LTIME_S(attr->ia_mtime), LTIME_S(attr->ia_ctime),
		       LTIME_S(CFS_CURRENT_TIME));

	/* NB: ATTR_SIZE will only be set after this point if the size
	 * resides on the MDS, ie, this file has no objects. */
	if (has_lsm)
		attr->ia_valid &= ~ATTR_SIZE;

	/* If only OST attributes being set on objects, don't do MDS RPC.
	 * In that case, we need to check permissions and update the local
	 * inode ourselves so we can call obdo_from_inode() always. */
	if (ia_valid & (has_lsm ? ~(ATTR_FROM_OPEN | ATTR_RAW) : ~0)) {
                memcpy(&op_data.op_attr, attr, sizeof(*attr));

                /* Open epoch for truncate. */
                if (exp_connect_som(llu_i2mdexp(inode)) &&
                    (ia_valid & ATTR_SIZE))
                        op_data.op_flags = MF_EPOCH_OPEN;
                rc = llu_md_setattr(inode, &op_data, &mod);
                if (rc)
                        RETURN(rc);

                llu_ioepoch_open(llu_i2info(inode), op_data.op_ioepoch);
		if (!has_lsm || !S_ISREG(st->st_mode)) {
                        CDEBUG(D_INODE, "no lsm: not setting attrs on OST\n");
                        GOTO(out, rc);
                }
        } else {
                /* The OST doesn't check permissions, but the alternative is
                 * a gratuitous RPC to the MDS.  We already rely on the client
                 * to do read/write/truncate permission checks, so is mtime OK?
                 */
                if (ia_valid & (ATTR_MTIME | ATTR_ATIME)) {
                        /* from sys_utime() */
                        if (!(ia_valid & (ATTR_MTIME_SET | ATTR_ATIME_SET))) {
                                if (current->fsuid != st->st_uid &&
                                    (rc = ll_permission(inode, MAY_WRITE)) != 0)
                                        RETURN(rc);
                        } else {
                                /* from inode_change_ok() */
                                if (current->fsuid != st->st_uid &&
                                    !cfs_capable(CFS_CAP_FOWNER))
                                        RETURN(-EPERM);
                        }
                }


                /* Won't invoke llu_vmtruncate(), as we already cleared
                 * ATTR_SIZE */
                inode_setattr(inode, attr);
        }

        if (ia_valid & ATTR_SIZE)
                attr->ia_valid |= ATTR_SIZE;
        if (ia_valid & (ATTR_SIZE |
                        ATTR_ATIME | ATTR_ATIME_SET |
                        ATTR_MTIME | ATTR_MTIME_SET))
                /* on truncate and utimes send attributes to osts, setting
                 * mtime/atime to past will be performed under PW 0:EOF extent
                 * lock (new_size:EOF for truncate)
                 * it may seem excessive to send mtime/atime updates to osts
                 * when not setting times to past, but it is necessary due to
                 * possible time de-synchronization */
                rc = cl_setattr_ost(inode, attr, NULL);
        EXIT;
out:
        if (op_data.op_ioepoch)
                rc1 = llu_setattr_done_writing(inode, &op_data, mod);
        return rc ? rc : rc1;
}

/* here we simply act as a thin layer to glue it with
 * llu_setattr_raw(), which is copy from kernel
 */
static int llu_iop_setattr(struct pnode *pno,
                           struct inode *ino,
                           unsigned mask,
                           struct intnl_stat *stbuf)
{
        struct iattr iattr;
        int rc;
        ENTRY;

        liblustre_wait_event(0);

        LASSERT(!(mask & ~(SETATTR_MTIME | SETATTR_ATIME |
                           SETATTR_UID | SETATTR_GID |
                           SETATTR_LEN | SETATTR_MODE)));
        memset(&iattr, 0, sizeof(iattr));

        if (mask & SETATTR_MODE) {
                iattr.ia_mode = stbuf->st_mode;
                iattr.ia_valid |= ATTR_MODE;
        }
        if (mask & SETATTR_MTIME) {
                iattr.ia_mtime = stbuf->st_mtime;
                iattr.ia_valid |= ATTR_MTIME | ATTR_MTIME_SET;
        }
        if (mask & SETATTR_ATIME) {
                iattr.ia_atime = stbuf->st_atime;
                iattr.ia_valid |= ATTR_ATIME | ATTR_ATIME_SET;
        }
        if (mask & SETATTR_UID) {
                iattr.ia_uid = stbuf->st_uid;
                iattr.ia_valid |= ATTR_UID;
        }
        if (mask & SETATTR_GID) {
                iattr.ia_gid = stbuf->st_gid;
                iattr.ia_valid |= ATTR_GID;
        }
        if (mask & SETATTR_LEN) {
                iattr.ia_size = stbuf->st_size; /* XXX signed expansion problem */
                iattr.ia_valid |= ATTR_SIZE;
        }

        iattr.ia_valid |= ATTR_RAW | ATTR_CTIME;
        iattr.ia_ctime = CFS_CURRENT_TIME;

        rc = llu_setattr_raw(ino, &iattr);
        liblustre_wait_idle();
        RETURN(rc);
}

#define EXT2_LINK_MAX           32000

static int llu_iop_symlink_raw(struct pnode *pno, const char *tgt)
{
        struct inode *dir = pno->p_base->pb_parent->pb_ino;
        struct qstr *qstr = &pno->p_base->pb_name;
        const char *name = qstr->name;
        int len = qstr->len;
        struct ptlrpc_request *request = NULL;
        struct llu_sb_info *sbi = llu_i2sbi(dir);
        struct md_op_data op_data = {{ 0 }};
        int err = -EMLINK;
        ENTRY;

        liblustre_wait_event(0);
        if (llu_i2stat(dir)->st_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        llu_prep_md_op_data(&op_data, dir, NULL, name, len, 0,
                            LUSTRE_OPC_SYMLINK);

        err = md_create(sbi->ll_md_exp, &op_data, tgt, strlen(tgt) + 1,
                        S_IFLNK | S_IRWXUGO, current->fsuid, current->fsgid,
                        cfs_curproc_cap_pack(), 0, &request);
        ptlrpc_req_finished(request);
        liblustre_wait_event(0);
        RETURN(err);
}

static int llu_readlink_internal(struct inode *inode,
                                 struct ptlrpc_request **request,
                                 char **symname)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct mdt_body *body;
        struct intnl_stat *st = llu_i2stat(inode);
        struct md_op_data op_data = {{ 0 }};
        int rc, symlen = st->st_size + 1;
        ENTRY;

        *request = NULL;
        *symname = NULL;

        if (lli->lli_symlink_name) {
                *symname = lli->lli_symlink_name;
                CDEBUG(D_INODE, "using cached symlink %s\n", *symname);
                RETURN(0);
        }

        llu_prep_md_op_data(&op_data, inode, NULL, NULL, 0, symlen,
                            LUSTRE_OPC_ANY);
        op_data.op_valid = OBD_MD_LINKNAME;

        rc = md_getattr(sbi->ll_md_exp, &op_data, request);
        if (rc) {
                CERROR("inode %llu: rc = %d\n", (long long)st->st_ino, rc);
                RETURN(rc);
        }

        body = req_capsule_server_get(&(*request)->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        if ((body->valid & OBD_MD_LINKNAME) == 0) {
                CERROR ("OBD_MD_LINKNAME not set on reply\n");
                GOTO (failed, rc = -EPROTO);
        }

        LASSERT(symlen != 0);
        if (body->eadatasize != symlen) {
                CERROR("inode %llu: symlink length %d not expected %d\n",
                       (long long)st->st_ino, body->eadatasize - 1, symlen - 1);
                GOTO(failed, rc = -EPROTO);
        }

        *symname = req_capsule_server_get(&(*request)->rq_pill, &RMF_MDT_MD);
        if (*symname == NULL ||
            strnlen(*symname, symlen) != symlen - 1) {
                /* not full/NULL terminated */
                CERROR("inode %llu: symlink not NULL terminated string"
                       "of length %d\n", (long long)st->st_ino, symlen - 1);
                GOTO(failed, rc = -EPROTO);
        }

        OBD_ALLOC(lli->lli_symlink_name, symlen);
        /* do not return an error if we cannot cache the symlink locally */
        if (lli->lli_symlink_name)
                memcpy(lli->lli_symlink_name, *symname, symlen);

        RETURN(0);

 failed:
        ptlrpc_req_finished (*request);
        RETURN (-EPROTO);
}

static int llu_iop_readlink(struct pnode *pno, char *data, size_t bufsize)
{
        struct inode *inode = pno->p_base->pb_ino;
        struct ptlrpc_request *request;
        char *symname;
        int rc;
        ENTRY;

        liblustre_wait_event(0);
        rc = llu_readlink_internal(inode, &request, &symname);
        if (rc)
                GOTO(out, rc);

        LASSERT(symname);
        strncpy(data, symname, bufsize);
        rc = strlen(symname);

        ptlrpc_req_finished(request);
 out:
        liblustre_wait_event(0);
        RETURN(rc);
}

static int llu_iop_mknod_raw(struct pnode *pno,
                             mode_t mode,
                             dev_t dev)
{
        struct ptlrpc_request *request = NULL;
        struct inode *dir = pno->p_parent->p_base->pb_ino;
        struct llu_sb_info *sbi = llu_i2sbi(dir);
        struct md_op_data op_data = {{ 0 }};
        int err = -EMLINK;
        ENTRY;

        liblustre_wait_event(0);
        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%llu\n",
               (int)pno->p_base->pb_name.len, pno->p_base->pb_name.name,
               (long long)llu_i2stat(dir)->st_ino);

        if (llu_i2stat(dir)->st_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        switch (mode & S_IFMT) {
        case 0:
        case S_IFREG:
                mode |= S_IFREG; /* for mode = 0 case, fallthrough */
        case S_IFCHR:
        case S_IFBLK:
        case S_IFIFO:
        case S_IFSOCK:
                llu_prep_md_op_data(&op_data, dir, NULL,
                                    pno->p_base->pb_name.name,
                                    pno->p_base->pb_name.len, 0,
                                    LUSTRE_OPC_MKNOD);

                err = md_create(sbi->ll_md_exp, &op_data, NULL, 0, mode,
                                current->fsuid, current->fsgid,
                                cfs_curproc_cap_pack(), dev, &request);
                ptlrpc_req_finished(request);
                break;
        case S_IFDIR:
                err = -EPERM;
                break;
        default:
                err = -EINVAL;
        }
        liblustre_wait_event(0);
        RETURN(err);
}

static int llu_iop_link_raw(struct pnode *old, struct pnode *new)
{
        struct inode *src = old->p_base->pb_ino;
        struct inode *dir = new->p_parent->p_base->pb_ino;
        const char *name = new->p_base->pb_name.name;
        int namelen = new->p_base->pb_name.len;
        struct ptlrpc_request *request = NULL;
        struct md_op_data op_data = {{ 0 }};
        int rc;
        ENTRY;

        LASSERT(src);
        LASSERT(dir);

        liblustre_wait_event(0);
        llu_prep_md_op_data(&op_data, src, dir, name, namelen, 0,
                            LUSTRE_OPC_ANY);
        rc = md_link(llu_i2sbi(src)->ll_md_exp, &op_data, &request);
        ptlrpc_req_finished(request);
        liblustre_wait_event(0);

        RETURN(rc);
}

/*
 * libsysio will clear the inode immediately after return
 */
static int llu_iop_unlink_raw(struct pnode *pno)
{
        struct inode *dir = pno->p_base->pb_parent->pb_ino;
        struct qstr *qstr = &pno->p_base->pb_name;
        const char *name = qstr->name;
        int len = qstr->len;
        struct inode *target = pno->p_base->pb_ino;
        struct ptlrpc_request *request = NULL;
        struct md_op_data op_data = { { 0 } };
        int rc;
        ENTRY;

        LASSERT(target);

        liblustre_wait_event(0);
        llu_prep_md_op_data(&op_data, dir, NULL, name, len, 0,
                            LUSTRE_OPC_ANY);
        rc = md_unlink(llu_i2sbi(dir)->ll_md_exp, &op_data, &request);
        if (!rc)
                rc = llu_objects_destroy(request, dir);
        ptlrpc_req_finished(request);
        liblustre_wait_idle();

        RETURN(rc);
}

static int llu_iop_rename_raw(struct pnode *old, struct pnode *new)
{
        struct inode *src = old->p_parent->p_base->pb_ino;
        struct inode *tgt = new->p_parent->p_base->pb_ino;
        const char *oldname = old->p_base->pb_name.name;
        int oldnamelen = old->p_base->pb_name.len;
        const char *newname = new->p_base->pb_name.name;
        int newnamelen = new->p_base->pb_name.len;
        struct ptlrpc_request *request = NULL;
        struct md_op_data op_data = { { 0 } };
        int rc;
        ENTRY;

        LASSERT(src);
        LASSERT(tgt);

        liblustre_wait_event(0);
        llu_prep_md_op_data(&op_data, src, tgt, NULL, 0, 0,
                            LUSTRE_OPC_ANY);
        rc = md_rename(llu_i2sbi(src)->ll_md_exp, &op_data,
                       oldname, oldnamelen, newname, newnamelen,
                       &request);
        if (!rc) {
                rc = llu_objects_destroy(request, src);
        }

        ptlrpc_req_finished(request);
        liblustre_wait_idle();

        RETURN(rc);
}

#ifdef _HAVE_STATVFS
static int llu_statfs_internal(struct llu_sb_info *sbi,
                               struct obd_statfs *osfs, __u64 max_age)
{
        struct obd_statfs obd_osfs;
        int rc;
        ENTRY;

        rc = obd_statfs(NULL, sbi->ll_md_exp, osfs, max_age, 0);
        if (rc) {
                CERROR("md_statfs fails: rc = %d\n", rc);
                RETURN(rc);
        }

        CDEBUG(D_SUPER, "MDC blocks "LPU64"/"LPU64" objects "LPU64"/"LPU64"\n",
               osfs->os_bavail, osfs->os_blocks, osfs->os_ffree,osfs->os_files);

        rc = obd_statfs_rqset(class_exp2obd(sbi->ll_dt_exp),
                              &obd_statfs, max_age, 0);
        if (rc) {
                CERROR("obd_statfs fails: rc = %d\n", rc);
                RETURN(rc);
        }

        CDEBUG(D_SUPER, "OSC blocks "LPU64"/"LPU64" objects "LPU64"/"LPU64"\n",
               obd_osfs.os_bavail, obd_osfs.os_blocks, obd_osfs.os_ffree,
               obd_osfs.os_files);

        osfs->os_blocks = obd_osfs.os_blocks;
        osfs->os_bfree = obd_osfs.os_bfree;
        osfs->os_bavail = obd_osfs.os_bavail;

        /* If we don't have as many objects free on the OST as inodes
         * on the MDS, we reduce the total number of inodes to
         * compensate, so that the "inodes in use" number is correct.
         */
        if (obd_osfs.os_ffree < osfs->os_ffree) {
                osfs->os_files = (osfs->os_files - osfs->os_ffree) +
                        obd_osfs.os_ffree;
                osfs->os_ffree = obd_osfs.os_ffree;
        }

        RETURN(rc);
}

static int llu_statfs(struct llu_sb_info *sbi, struct statfs *sfs)
{
        struct obd_statfs osfs;
        int rc;

        CDEBUG(D_VFSTRACE, "VFS Op:\n");

        /* For now we will always get up-to-date statfs values, but in the
         * future we may allow some amount of caching on the client (e.g.
         * from QOS or lprocfs updates). */
        rc = llu_statfs_internal(sbi, &osfs,
                                 cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS));
        if (rc)
                return rc;

        statfs_unpack(sfs, &osfs);

        if (sizeof(sfs->f_blocks) == 4) {
                while (osfs.os_blocks > ~0UL) {
                        sfs->f_bsize <<= 1;

                        osfs.os_blocks >>= 1;
                        osfs.os_bfree >>= 1;
                        osfs.os_bavail >>= 1;
                }
        }

        sfs->f_blocks = osfs.os_blocks;
        sfs->f_bfree = osfs.os_bfree;
        sfs->f_bavail = osfs.os_bavail;

        return 0;
}

static int llu_iop_statvfs(struct pnode *pno,
                           struct inode *ino,
                           struct intnl_statvfs *buf)
{
        struct statfs fs;
        int rc;
        ENTRY;

        liblustre_wait_event(0);

#ifndef __CYGWIN__
        LASSERT(pno->p_base->pb_ino);
        rc = llu_statfs(llu_i2sbi(pno->p_base->pb_ino), &fs);
        if (rc)
                RETURN(rc);

        /* from native driver */
        buf->f_bsize = fs.f_bsize;  /* file system block size */
        buf->f_frsize = fs.f_bsize; /* file system fundamental block size */
        buf->f_blocks = fs.f_blocks;
        buf->f_bfree = fs.f_bfree;
        buf->f_bavail = fs.f_bavail;
        buf->f_files = fs.f_files;  /* Total number serial numbers */
        buf->f_ffree = fs.f_ffree;  /* Number free serial numbers */
        buf->f_favail = fs.f_ffree; /* Number free ser num for non-privileged*/
        buf->f_fsid = fs.f_fsid.__val[1];
        buf->f_flag = 0;            /* No equiv in statfs; maybe use type? */
        buf->f_namemax = fs.f_namelen;
#endif

        liblustre_wait_event(0);
        RETURN(0);
}
#endif /* _HAVE_STATVFS */

static int llu_iop_mkdir_raw(struct pnode *pno, mode_t mode)
{
        struct inode *dir = pno->p_base->pb_parent->pb_ino;
        struct qstr *qstr = &pno->p_base->pb_name;
        const char *name = qstr->name;
        int len = qstr->len;
        struct ptlrpc_request *request = NULL;
        struct intnl_stat *st = llu_i2stat(dir);
        struct md_op_data op_data = {{ 0 }};
        int err = -EMLINK;
        ENTRY;

        liblustre_wait_event(0);
        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%llu/%lu(%p)\n", len, name,
               (long long)st->st_ino, llu_i2info(dir)->lli_st_generation, dir);

        if (st->st_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        llu_prep_md_op_data(&op_data, dir, NULL, name, len, 0,
                            LUSTRE_OPC_MKDIR);

        err = md_create(llu_i2sbi(dir)->ll_md_exp, &op_data, NULL, 0,
                        mode | S_IFDIR, current->fsuid, current->fsgid,
                        cfs_curproc_cap_pack(), 0, &request);
        ptlrpc_req_finished(request);
        liblustre_wait_event(0);
        RETURN(err);
}

static int llu_iop_rmdir_raw(struct pnode *pno)
{
        struct inode *dir = pno->p_base->pb_parent->pb_ino;
        struct qstr *qstr = &pno->p_base->pb_name;
        const char *name = qstr->name;
        int len = qstr->len;
        struct ptlrpc_request *request = NULL;
        struct md_op_data op_data = {{ 0 }};
        int rc;
        ENTRY;

        liblustre_wait_event(0);
        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%llu/%lu(%p)\n", len, name,
               (long long)llu_i2stat(dir)->st_ino,
               llu_i2info(dir)->lli_st_generation, dir);

        llu_prep_md_op_data(&op_data, dir, NULL, name, len, S_IFDIR,
                            LUSTRE_OPC_ANY);
        rc = md_unlink(llu_i2sbi(dir)->ll_md_exp, &op_data, &request);
        ptlrpc_req_finished(request);

        liblustre_wait_event(0);
        RETURN(rc);
}

#ifdef O_DIRECT
#define FCNTL_FLMASK (O_APPEND|O_NONBLOCK|O_ASYNC|O_DIRECT)
#else
#define FCNTL_FLMASK (O_APPEND|O_NONBLOCK|O_ASYNC)
#endif
#define FCNTL_FLMASK_INVALID (O_NONBLOCK|O_ASYNC)

/* refer to ll_file_flock() for details */
static int llu_file_flock(struct inode *ino,
                          int cmd,
                          struct file_lock *file_lock)
{
	struct llu_inode_info *lli = llu_i2info(ino);
	struct ldlm_res_id res_id =
		{ .name = {fid_seq(&lli->lli_fid),
			   fid_oid(&lli->lli_fid),
			   fid_ver(&lli->lli_fid),
			   LDLM_FLOCK} };
	struct ldlm_enqueue_info einfo = {
		.ei_type	= LDLM_FLOCK,
		.ei_mode	= 0,
		.ei_cb_cp	= ldlm_flock_completion_ast,
		.ei_cbdata	= file_lock,
	};
	struct intnl_stat     *st  = llu_i2stat(ino);
	struct lustre_handle lockh = {0};
	ldlm_policy_data_t flock;
	__u64 flags = 0;
	int rc;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%llu file_lock=%p\n",
               (unsigned long long)st->st_ino, file_lock);

        flock.l_flock.pid = file_lock->fl_pid;
        flock.l_flock.start = file_lock->fl_start;
        flock.l_flock.end = file_lock->fl_end;

        switch (file_lock->fl_type) {
        case F_RDLCK:
                einfo.ei_mode = LCK_PR;
                break;
        case F_UNLCK:
                einfo.ei_mode = LCK_NL;
                break;
        case F_WRLCK:
                einfo.ei_mode = LCK_PW;
                break;
        default:
                CERROR("unknown fcntl lock type: %d\n", file_lock->fl_type);
                LBUG();
        }

        switch (cmd) {
        case F_SETLKW:
#ifdef F_SETLKW64
#if F_SETLKW64 != F_SETLKW
        case F_SETLKW64:
#endif
#endif
                flags = 0;
                break;
        case F_SETLK:
#ifdef F_SETLK64
#if F_SETLK64 != F_SETLK
        case F_SETLK64:
#endif
#endif
                flags = LDLM_FL_BLOCK_NOWAIT;
                break;
        case F_GETLK:
#ifdef F_GETLK64
#if F_GETLK64 != F_GETLK
        case F_GETLK64:
#endif
#endif
                flags = LDLM_FL_TEST_LOCK;
                file_lock->fl_type = einfo.ei_mode;
                break;
        default:
                CERROR("unknown fcntl cmd: %d\n", cmd);
                LBUG();
        }

	CDEBUG(D_DLMTRACE, "inode=%llu, pid=%u, cmd=%d, flags="LPX64", "
	       "mode=%u, start="LPX64", end="LPX64"\n",
	       (unsigned long long)st->st_ino,
	       flock.l_flock.pid, cmd, flags, einfo.ei_mode,
	       flock.l_flock.start, flock.l_flock.end);
        {
                struct lmv_obd *lmv;
                struct obd_device *lmv_obd;
                lmv_obd = class_exp2obd(llu_i2mdexp(ino));
                lmv = &lmv_obd->u.lmv;

                if (lmv->desc.ld_tgt_count < 1)
                        RETURN(rc = -ENODEV);

		if (lmv->tgts[0] != NULL && lmv->tgts[0]->ltd_exp != NULL)
			rc = ldlm_cli_enqueue(lmv->tgts[0]->ltd_exp, NULL,
					      &einfo, &res_id, &flock, &flags,
					      NULL, 0, LVB_T_NONE, &lockh, 0);
		else
			rc = -ENODEV;
        }
        RETURN(rc);
}

static int assign_type(struct file_lock *fl, int type)
{
        switch (type) {
        case F_RDLCK:
        case F_WRLCK:
        case F_UNLCK:
                fl->fl_type = type;
                return 0;
        default:
                return -EINVAL;
        }
}

static int flock_to_posix_lock(struct inode *ino,
                               struct file_lock *fl,
                               struct flock *l)
{
        switch (l->l_whence) {
        /* XXX: only SEEK_SET is supported in lustre */
        case SEEK_SET:
                fl->fl_start = 0;
                break;
        default:
                return -EINVAL;
        }

        fl->fl_end = l->l_len - 1;
        if (l->l_len < 0)
                return -EINVAL;
        if (l->l_len == 0)
                fl->fl_end = OFFSET_MAX;

        fl->fl_pid = getpid();
        fl->fl_flags = FL_POSIX;
        fl->fl_notify = NULL;
        fl->fl_insert = NULL;
        fl->fl_remove = NULL;
        /* XXX: these fields can't be filled with suitable values,
                but I think lustre doesn't use them.
         */
        fl->fl_owner = NULL;
        fl->fl_file = NULL;

        return assign_type(fl, l->l_type);
}

static int llu_fcntl_getlk(struct inode *ino, struct flock *flock)
{
        struct file_lock fl;
        int error;

        error = EINVAL;
        if ((flock->l_type != F_RDLCK) && (flock->l_type != F_WRLCK))
                goto out;

        error = flock_to_posix_lock(ino, &fl, flock);
        if (error)
                goto out;

        error = llu_file_flock(ino, F_GETLK, &fl);
        if (error)
                goto out;

        flock->l_type = F_UNLCK;
        if (fl.fl_type != F_UNLCK) {
                flock->l_pid = fl.fl_pid;
                flock->l_start = fl.fl_start;
                flock->l_len = fl.fl_end == OFFSET_MAX ? 0:
                        fl.fl_end - fl.fl_start + 1;
                flock->l_whence = SEEK_SET;
                flock->l_type = fl.fl_type;
        }

out:
        return error;
}

static int llu_fcntl_setlk(struct inode *ino, int cmd, struct flock *flock)
{
        struct file_lock fl;
        int flags = llu_i2info(ino)->lli_open_flags + 1;
        int error;

        error = flock_to_posix_lock(ino, &fl, flock);
        if (error)
                goto out;
        if (cmd == F_SETLKW)
                fl.fl_flags |= FL_SLEEP;

        error = -EBADF;
        switch (flock->l_type) {
        case F_RDLCK:
                if (!(flags & FMODE_READ))
                        goto out;
                break;
        case F_WRLCK:
                if (!(flags & FMODE_WRITE))
                        goto out;
                break;
        case F_UNLCK:
                break;
        default:
                error = -EINVAL;
                goto out;
        }

        error = llu_file_flock(ino, cmd, &fl);
        if (error)
                goto out;

out:
        return error;
}

static int llu_iop_fcntl(struct inode *ino, int cmd, va_list ap, int *rtn)
{
        struct llu_inode_info *lli = llu_i2info(ino);
        long flags;
        struct flock *flock;
        long err = 0;

        liblustre_wait_event(0);
        switch (cmd) {
        case F_GETFL:
                *rtn = lli->lli_open_flags;
                break;
        case F_SETFL:
                flags = va_arg(ap, long);
                flags &= FCNTL_FLMASK;
                if (flags & FCNTL_FLMASK_INVALID) {
                        LCONSOLE_ERROR_MSG(0x010, "liblustre does not support "
                                           "the O_NONBLOCK or O_ASYNC flags. "
                                           "Please fix your application.\n");
                        *rtn = -EINVAL;
                        err = EINVAL;
                        break;
                }
                lli->lli_open_flags = (int)(flags & FCNTL_FLMASK) |
                                      (lli->lli_open_flags & ~FCNTL_FLMASK);
                *rtn = 0;
                break;
        case F_GETLK:
#ifdef F_GETLK64
#if F_GETLK64 != F_GETLK
        case F_GETLK64:
#endif
#endif
                flock = va_arg(ap, struct flock *);
                err = llu_fcntl_getlk(ino, flock);
                *rtn = err? -1: 0;
                break;
        case F_SETLK:
#ifdef F_SETLKW64
#if F_SETLKW64 != F_SETLKW
        case F_SETLKW64:
#endif
#endif
        case F_SETLKW:
#ifdef F_SETLK64
#if F_SETLK64 != F_SETLK
        case F_SETLK64:
#endif
#endif
                flock = va_arg(ap, struct flock *);
                err = llu_fcntl_setlk(ino, cmd, flock);
                *rtn = err? -1: 0;
                break;
        default:
                CERROR("unsupported fcntl cmd %x\n", cmd);
                *rtn = -ENOSYS;
                err = ENOSYS;
                break;
        }

        liblustre_wait_event(0);
        return err;
}

static int llu_get_grouplock(struct inode *inode, unsigned long arg)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        int rc;
        struct ccc_grouplock grouplock;
        ENTRY;

        if (fd->fd_flags & LL_FILE_IGNORE_LOCK) {
                RETURN(-ENOTSUPP);
        }
        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                RETURN(-EINVAL);
        }
        LASSERT(fd->fd_grouplock.cg_lock == NULL);

        rc = cl_get_grouplock(cl_i2info(inode)->lli_clob,
                              arg, (lli->lli_open_flags & O_NONBLOCK),
                              &grouplock);

        if (rc)
                RETURN(rc);

        fd->fd_flags |= LL_FILE_GROUP_LOCKED;
        fd->fd_grouplock = grouplock;

        RETURN(0);
}

int llu_put_grouplock(struct inode *inode, unsigned long arg)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct ccc_grouplock grouplock;
        ENTRY;

        if (!(fd->fd_flags & LL_FILE_GROUP_LOCKED))
                RETURN(-EINVAL);

        LASSERT(fd->fd_grouplock.cg_lock != NULL);

        if (fd->fd_grouplock.cg_gid != arg)
                RETURN(-EINVAL);

        grouplock = fd->fd_grouplock;
        memset(&fd->fd_grouplock, 0, sizeof(fd->fd_grouplock));
        fd->fd_flags &= ~LL_FILE_GROUP_LOCKED;

        cl_put_grouplock(&grouplock);

        RETURN(0);
}

static int llu_lov_dir_setstripe(struct inode *ino, unsigned long arg)
{
        struct llu_sb_info *sbi = llu_i2sbi(ino);
        struct ptlrpc_request *request = NULL;
        struct md_op_data op_data = {{ 0 }};
        struct lov_user_md lum, *lump = (struct lov_user_md *)arg;
        int rc = 0;

        llu_prep_md_op_data(&op_data, ino, NULL, NULL, 0, 0,
                            LUSTRE_OPC_ANY);

        LASSERT(sizeof(lum) == sizeof(*lump));
        LASSERT(sizeof(lum.lmm_objects[0]) ==
                sizeof(lump->lmm_objects[0]));
	if (copy_from_user(&lum, lump, sizeof(lum)))
                return(-EFAULT);

        switch (lum.lmm_magic) {
        case LOV_USER_MAGIC_V1: {
                if (lum.lmm_magic != cpu_to_le32(LOV_USER_MAGIC_V1))
                        lustre_swab_lov_user_md_v1(&lum);
                break;
                }
        case LOV_USER_MAGIC_V3: {
                if (lum.lmm_magic != cpu_to_le32(LOV_USER_MAGIC_V3))
                        lustre_swab_lov_user_md_v3((struct lov_user_md_v3 *)&lum);
                break;
                }
        default: {
                CDEBUG(D_IOCTL, "bad userland LOV MAGIC:"
                                " %#08x != %#08x nor %#08x\n",
                                lum.lmm_magic, LOV_USER_MAGIC_V1,
                                LOV_USER_MAGIC_V3);
                RETURN(-EINVAL);
        }
        }

        /* swabbing is done in lov_setstripe() on server side */
        rc = md_setattr(sbi->ll_md_exp, &op_data, &lum,
                        sizeof(lum), NULL, 0, &request, NULL);
        if (rc) {
                ptlrpc_req_finished(request);
                if (rc != -EPERM && rc != -EACCES)
                        CERROR("md_setattr fails: rc = %d\n", rc);
                return rc;
        }
        ptlrpc_req_finished(request);

        return rc;
}

static int llu_lov_setstripe_ea_info(struct inode *ino, int flags,
				     struct lov_user_md *lum, int lum_size)
{
	struct llu_sb_info *sbi = llu_i2sbi(ino);
	struct llu_inode_info *lli = llu_i2info(ino);
	struct lookup_intent oit = {.it_op = IT_OPEN, .it_flags = flags};
	struct ldlm_enqueue_info einfo = {
		.ei_type	= LDLM_IBITS,
		.ei_mode	= LCK_CR,
		.ei_cb_bl	= llu_md_blocking_ast,
		.ei_cb_cp	= ldlm_completion_ast,
	};
	struct ptlrpc_request *req = NULL;
	struct lustre_md md;
	struct md_op_data data = {{ 0 }};
	struct lustre_handle lockh;
	int rc = 0;
	ENTRY;

	if (lli->lli_has_smd) {
		CDEBUG(D_IOCTL, "stripe already exists for ino "DFID"\n",
		       PFID(&lli->lli_fid));
		return -EEXIST;
	}

        llu_prep_md_op_data(&data, NULL, ino, NULL, 0, O_RDWR,
                            LUSTRE_OPC_ANY);
        rc = md_enqueue(sbi->ll_md_exp, &einfo, &oit, &data,
                        &lockh, lum, lum_size, NULL, LDLM_FL_INTENT_ONLY);
        if (rc)
                GOTO(out, rc);

        req = oit.d.lustre.it_data;
        rc = it_open_error(DISP_IT_EXECD, &oit);
        if (rc) {
                req->rq_replay = 0;
                GOTO(out, rc);
        }

        rc = it_open_error(DISP_OPEN_OPEN, &oit);
        if (rc) {
                req->rq_replay = 0;
                GOTO(out, rc);
        }

        rc = md_get_lustre_md(sbi->ll_md_exp, req,
                              sbi->ll_dt_exp, sbi->ll_md_exp, &md);
        if (rc)
                GOTO(out, rc);

        llu_update_inode(ino, &md);
        llu_local_open(lli, &oit);
        /* release intent */
        if (lustre_handle_is_used(&lockh))
                ldlm_lock_decref(&lockh, LCK_CR);
        ptlrpc_req_finished(req);
        req = NULL;
        rc = llu_file_release(ino);
        EXIT;

out:
        if (req != NULL)
                ptlrpc_req_finished(req);
        return rc;
}

static int llu_lov_file_setstripe(struct inode *ino, unsigned long arg)
{
        struct lov_user_md lum, *lump = (struct lov_user_md *)arg;
        int rc;
        int flags = FMODE_WRITE;
        ENTRY;

        LASSERT(sizeof(lum) == sizeof(*lump));
        LASSERT(sizeof(lum.lmm_objects[0]) == sizeof(lump->lmm_objects[0]));
	if (copy_from_user(&lum, lump, sizeof(lum)))
                RETURN(-EFAULT);

        rc = llu_lov_setstripe_ea_info(ino, flags, &lum, sizeof(lum));
        RETURN(rc);
}

static int llu_lov_setstripe(struct inode *ino, unsigned long arg)
{
        struct intnl_stat *st = llu_i2stat(ino);
        if (S_ISREG(st->st_mode))
                return llu_lov_file_setstripe(ino, arg);
        if (S_ISDIR(st->st_mode))
                return llu_lov_dir_setstripe(ino, arg);

        return -EINVAL;
}

static int llu_lov_getstripe(struct inode *ino, unsigned long arg)
{
	struct lov_stripe_md *lsm = NULL;
	int rc = -ENODATA;

	lsm = ccc_inode_lsm_get(ino);
	if (lsm != NULL)
		rc = obd_iocontrol(LL_IOC_LOV_GETSTRIPE, llu_i2obdexp(ino), 0, lsm,
				   (void *)arg);
	ccc_inode_lsm_put(ino, lsm);
	return rc;
}

static int llu_iop_ioctl(struct inode *ino, unsigned long int request,
                         va_list ap)
{
        unsigned long arg;
        int rc;

        liblustre_wait_event(0);

        switch (request) {
        case LL_IOC_GROUP_LOCK:
                arg = va_arg(ap, unsigned long);
                rc = llu_get_grouplock(ino, arg);
                break;
        case LL_IOC_GROUP_UNLOCK:
                arg = va_arg(ap, unsigned long);
                rc = llu_put_grouplock(ino, arg);
                break;
        case LL_IOC_LOV_SETSTRIPE:
                arg = va_arg(ap, unsigned long);
                rc = llu_lov_setstripe(ino, arg);
                break;
        case LL_IOC_LOV_GETSTRIPE:
                arg = va_arg(ap, unsigned long);
                rc = llu_lov_getstripe(ino, arg);
                break;
        default:
                CERROR("did not support ioctl cmd %lx\n", request);
                rc = -ENOSYS;
                break;
        }

        liblustre_wait_event(0);
        return rc;
}

/*
 * we already do syncronous read/write
 */
static int llu_iop_sync(struct inode *inode)
{
        liblustre_wait_event(0);
        return 0;
}

static int llu_iop_datasync(struct inode *inode)
{
        liblustre_wait_event(0);
        return 0;
}

struct filesys_ops llu_filesys_ops =
{
        fsop_gone: llu_fsop_gone,
};

struct inode *llu_iget(struct filesys *fs, struct lustre_md *md)
{
        struct inode *inode;
        struct lu_fid fid;
        struct file_identifier fileid = {&fid, sizeof(fid)};

        if ((md->body->valid & (OBD_MD_FLID | OBD_MD_FLTYPE)) !=
            (OBD_MD_FLID | OBD_MD_FLTYPE)) {
                CERROR("bad md body valid mask "LPX64"\n", md->body->valid);
                LBUG();
                return ERR_PTR(-EPERM);
        }

        /* try to find existing inode */
        fid = md->body->fid1;

        inode = _sysio_i_find(fs, &fileid);
        if (inode) {
                if (inode->i_zombie/* ||
                    lli->lli_st_generation != md->body->generation*/) {
                        I_RELE(inode);
                }
                else {
                        llu_update_inode(inode, md);
                        return inode;
                }
        }

        inode = llu_new_inode(fs, &fid);
        if (inode)
                llu_update_inode(inode, md);

        return inode;
}

static int
llu_fsswop_mount(const char *source,
                 unsigned flags,
                 const void *data __IS_UNUSED,
                 struct pnode *tocover,
                 struct mount **mntp)
{
        struct filesys *fs;
        struct inode *root;
        struct pnode_base *rootpb;
        struct obd_device *obd;
        struct llu_sb_info *sbi;
        struct obd_statfs osfs;
        static struct qstr noname = { NULL, 0, 0 };
        struct ptlrpc_request *request = NULL;
        struct lustre_md md;
        class_uuid_t uuid;
        struct config_llog_instance cfg = {0, };
        struct lustre_profile *lprof;
        char *zconf_mgsnid, *zconf_profile;
        char *osc = NULL, *mdc = NULL;
        int async = 1, err = -EINVAL;
        struct obd_connect_data ocd = {0,};
        struct md_op_data op_data = {{0}};
        /* %p for void* in printf needs 16+2 characters: 0xffffffffffffffff */
        const int instlen = sizeof(cfg.cfg_instance) * 2 + 2;

        ENTRY;

        if (ll_parse_mount_target(source,
                                  &zconf_mgsnid,
                                  &zconf_profile)) {
                CERROR("mal-formed target %s\n", source);
                RETURN(err);
        }
        if (!zconf_mgsnid || !zconf_profile) {
                printf("Liblustre: invalid target %s\n", source);
                RETURN(err);
        }
        /* allocate & initialize sbi */
        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi)
                RETURN(-ENOMEM);

        CFS_INIT_LIST_HEAD(&sbi->ll_conn_chain);
        ll_generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &sbi->ll_sb_uuid);

        /* generate a string unique to this super, let's try
         the address of the super itself.*/
        cfg.cfg_instance = sbi;

        /* retrive & parse config log */
        cfg.cfg_uuid = sbi->ll_sb_uuid;
        err = liblustre_process_log(&cfg, zconf_mgsnid, zconf_profile, 1);
        if (err < 0) {
                CERROR("Unable to process log: %s\n", zconf_profile);
                GOTO(out_free, err);
        }

        lprof = class_get_profile(zconf_profile);
        if (lprof == NULL) {
                CERROR("No profile found: %s\n", zconf_profile);
                GOTO(out_free, err = -EINVAL);
        }
        OBD_ALLOC(osc, strlen(lprof->lp_dt) + instlen + 2);
        sprintf(osc, "%s-%p", lprof->lp_dt, cfg.cfg_instance);

        OBD_ALLOC(mdc, strlen(lprof->lp_md) + instlen + 2);
        sprintf(mdc, "%s-%p", lprof->lp_md, cfg.cfg_instance);

        if (!osc) {
                CERROR("no osc\n");
                GOTO(out_free, err = -EINVAL);
        }
        if (!mdc) {
                CERROR("no mdc\n");
                GOTO(out_free, err = -EINVAL);
        }

        fs = _sysio_fs_new(&llu_filesys_ops, flags, sbi);
        if (!fs) {
                err = -ENOMEM;
                goto out_free;
        }

        obd = class_name2obd(mdc);
        if (!obd) {
                CERROR("MDC %s: not setup or attached\n", mdc);
                GOTO(out_free, err = -EINVAL);
        }
        obd_set_info_async(NULL, obd->obd_self_export, sizeof(KEY_ASYNC),
                           KEY_ASYNC, sizeof(async), &async, NULL);

        ocd.ocd_connect_flags = OBD_CONNECT_IBITS | OBD_CONNECT_VERSION |
                                OBD_CONNECT_FID | OBD_CONNECT_AT |
				OBD_CONNECT_VBR | OBD_CONNECT_FULL20 |
				OBD_CONNECT_LVB_TYPE;

#ifdef LIBLUSTRE_POSIX_ACL
        ocd.ocd_connect_flags |= OBD_CONNECT_ACL;
#endif
        ocd.ocd_ibits_known = MDS_INODELOCK_FULL;
        ocd.ocd_version = LUSTRE_VERSION_CODE;

        /* setup mdc */
        err = obd_connect(NULL, &sbi->ll_md_exp, obd, &sbi->ll_sb_uuid, &ocd, NULL);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                GOTO(out_free, err);
        }

        err = obd_statfs(NULL, sbi->ll_md_exp, &osfs, 100000000, 0);
        if (err)
                GOTO(out_md, err);

        /*
         * FIXME fill fs stat data into sbi here!!! FIXME
         */

        /* setup osc */
        obd = class_name2obd(osc);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                GOTO(out_md, err = -EINVAL);
        }
        obd_set_info_async(NULL, obd->obd_self_export, sizeof(KEY_ASYNC),
                           KEY_ASYNC, sizeof(async), &async, NULL);

        obd->obd_upcall.onu_owner = &sbi->ll_lco;
        obd->obd_upcall.onu_upcall = cl_ocd_update;

        ocd.ocd_connect_flags = OBD_CONNECT_SRVLOCK | OBD_CONNECT_REQPORTAL |
                                OBD_CONNECT_VERSION | OBD_CONNECT_TRUNCLOCK |
                                OBD_CONNECT_FID | OBD_CONNECT_AT |
				OBD_CONNECT_FULL20 | OBD_CONNECT_EINPROGRESS |
				OBD_CONNECT_LVB_TYPE;

        ocd.ocd_version = LUSTRE_VERSION_CODE;
        err = obd_connect(NULL, &sbi->ll_dt_exp, obd, &sbi->ll_sb_uuid, &ocd, NULL);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", osc, err);
                GOTO(out_md, err);
        }
        sbi->ll_lco.lco_flags = ocd.ocd_connect_flags;
        sbi->ll_lco.lco_md_exp = sbi->ll_md_exp;
        sbi->ll_lco.lco_dt_exp = sbi->ll_dt_exp;

        fid_zero(&sbi->ll_root_fid);
        err = md_getstatus(sbi->ll_md_exp, &sbi->ll_root_fid, NULL);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_lock_cn_cb, err);
        }
        if (!fid_is_sane(&sbi->ll_root_fid)) {
                CERROR("Invalid root fid during mount\n");
                GOTO(out_lock_cn_cb, err = -EINVAL);
        }
        CDEBUG(D_SUPER, "rootfid "DFID"\n", PFID(&sbi->ll_root_fid));

        op_data.op_fid1 = sbi->ll_root_fid;
        op_data.op_valid = OBD_MD_FLGETATTR | OBD_MD_FLBLOCKS;
        /* fetch attr of root inode */
        err = md_getattr(sbi->ll_md_exp, &op_data, &request);
        if (err) {
                CERROR("md_getattr failed for root: rc = %d\n", err);
                GOTO(out_lock_cn_cb, err);
        }

        err = md_get_lustre_md(sbi->ll_md_exp, request,
                               sbi->ll_dt_exp, sbi->ll_md_exp, &md);
        if (err) {
                CERROR("failed to understand root inode md: rc = %d\n",err);
                GOTO(out_request, err);
        }

        LASSERT(fid_is_sane(&sbi->ll_root_fid));

        root = llu_iget(fs, &md);
        if (!root || IS_ERR(root)) {
                CERROR("fail to generate root inode\n");
                GOTO(out_request, err = -EBADF);
        }

        /*
         * Generate base path-node for root.
         */
        rootpb = _sysio_pb_new(&noname, NULL, root);
        if (!rootpb) {
                err = -ENOMEM;
                goto out_inode;
        }

        err = _sysio_do_mount(fs, rootpb, flags, tocover, mntp);
        if (err) {
                _sysio_pb_gone(rootpb);
                goto out_inode;
        }

        cl_sb_init(sbi);

        ptlrpc_req_finished(request);

        CDEBUG(D_SUPER, "LibLustre: %s mounted successfully!\n", source);
        err = 0;
        goto out_free;

out_inode:
        _sysio_i_gone(root);
out_request:
        ptlrpc_req_finished(request);
out_lock_cn_cb:
        obd_disconnect(sbi->ll_dt_exp);
out_md:
        obd_disconnect(sbi->ll_md_exp);
out_free:
        if (osc)
                OBD_FREE(osc, strlen(lprof->lp_dt) + instlen + 2);
        if (mdc)
                OBD_FREE(mdc, strlen(lprof->lp_md) + instlen + 2);
        OBD_FREE(sbi, sizeof(*sbi));
        liblustre_wait_idle();
        return err;
}

struct fssw_ops llu_fssw_ops = {
        llu_fsswop_mount
};

static struct inode_ops llu_inode_ops = {
        inop_lookup:    llu_iop_lookup,
        inop_getattr:   llu_iop_getattr,
        inop_setattr:   llu_iop_setattr,
        inop_filldirentries:     llu_iop_filldirentries,
        inop_mkdir:     llu_iop_mkdir_raw,
        inop_rmdir:     llu_iop_rmdir_raw,
        inop_symlink:   llu_iop_symlink_raw,
        inop_readlink:  llu_iop_readlink,
        inop_open:      llu_iop_open,
        inop_close:     llu_iop_close,
        inop_link:      llu_iop_link_raw,
        inop_unlink:    llu_iop_unlink_raw,
        inop_rename:    llu_iop_rename_raw,
        inop_pos:       llu_iop_pos,
        inop_read:      llu_iop_read,
        inop_write:     llu_iop_write,
        inop_iodone:    llu_iop_iodone,
        inop_fcntl:     llu_iop_fcntl,
        inop_sync:      llu_iop_sync,
        inop_datasync:  llu_iop_datasync,
        inop_ioctl:     llu_iop_ioctl,
        inop_mknod:     llu_iop_mknod_raw,
#ifdef _HAVE_STATVFS
        inop_statvfs:   llu_iop_statvfs,
#endif
        inop_gone:      llu_iop_gone,
};
