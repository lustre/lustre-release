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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
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

#include <sysio.h>
#ifdef HAVE_XTIO_H
#include <xtio.h>
#endif
#include <fs.h>
#include <mount.h>
#include <inode.h>
#ifdef HAVE_FILE_H
#include <file.h>
#endif

#undef LIST_HEAD

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
        struct obd_device *obd = class_exp2obd(sbi->ll_mdc_exp);
        struct obd_device *lov_obd = class_exp2obd(sbi->ll_osc_exp);
        int next = 0;
        ENTRY;

        list_del(&sbi->ll_conn_chain);

        obd_disconnect(sbi->ll_osc_exp);
        obd_unregister_lock_cancel_cb(lov_obd, llu_extent_lock_cancel_cb);

        obd_disconnect(sbi->ll_mdc_exp);

        while ((obd = class_devices_in_group(&sbi->ll_sb_uuid, &next)) != NULL)
                class_manual_cleanup(obd);

        OBD_FREE(sbi, sizeof(*sbi));

        liblustre_wait_idle();
        EXIT;
}

static struct inode_ops llu_inode_ops;

void llu_update_inode(struct inode *inode, struct mds_body *body,
                      struct lov_stripe_md *lsm)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat *st = llu_i2stat(inode);

        LASSERT ((lsm != NULL) == ((body->valid & OBD_MD_FLEASIZE) != 0));
        if (lsm != NULL) {
                if (lli->lli_smd == NULL) {
                        lli->lli_smd = lsm;
                        lli->lli_maxbytes = lsm->lsm_maxbytes;
                        if (lli->lli_maxbytes > PAGE_CACHE_MAXBYTES)
                                lli->lli_maxbytes = PAGE_CACHE_MAXBYTES;
                } else {
                        if (lov_stripe_md_cmp(lli->lli_smd, lsm)) {
                                CERROR("lsm mismatch for inode %lld\n",
                                       (long long)st->st_ino);
                                LBUG();
                        }
                }
        }

        if (body->valid & OBD_MD_FLID)
                st->st_ino = body->ino;
        if (body->valid & OBD_MD_FLGENER)
                lli->lli_st_generation = body->generation;
        if (body->valid & OBD_MD_FLMTIME) {
                if (body->mtime > LTIME_S(st->st_mtime))
                        LTIME_S(st->st_mtime) = body->mtime;
                lli->lli_lvb.lvb_mtime = body->mtime;
        }
        if (body->valid & OBD_MD_FLATIME) {
                if (body->atime > LTIME_S(st->st_atime))
                        LTIME_S(st->st_atime) = body->atime;
                lli->lli_lvb.lvb_atime = body->atime;
        }
        if (body->valid & OBD_MD_FLCTIME) {
                if (body->ctime > LTIME_S(st->st_ctime))
                        LTIME_S(st->st_ctime) = body->ctime;
                lli->lli_lvb.lvb_ctime = body->ctime;
        }
        if (body->valid & OBD_MD_FLMODE)
                st->st_mode = (st->st_mode & S_IFMT)|(body->mode & ~S_IFMT);
        if (body->valid & OBD_MD_FLTYPE)
                st->st_mode = (st->st_mode & ~S_IFMT)|(body->mode & S_IFMT);
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
        if (body->valid & OBD_MD_FLSIZE)
                st->st_size = body->size;
        if (body->valid & OBD_MD_FLBLOCKS)
                st->st_blocks = body->blocks;
        if (body->valid & OBD_MD_FLFLAGS)
                lli->lli_st_flags = body->flags;

        lli->lli_fid = body->fid1;
}

void obdo_to_inode(struct inode *dst, struct obdo *src, obd_flag valid)
{
        struct llu_inode_info *lli = llu_i2info(dst);
        struct intnl_stat *st = llu_i2stat(dst);

        valid &= src->o_valid;

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE,"valid "LPX64", cur time %lu/%lu, new %lu/%lu\n",
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
        if (valid & OBD_MD_FLGENER)
                lli->lli_st_generation = src->o_generation;
}

#define S_IRWXUGO       (S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO       (S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)

void obdo_from_inode(struct obdo *dst, struct inode *src, obd_flag valid)
{
        struct llu_inode_info *lli = llu_i2info(src);
        struct intnl_stat *st = llu_i2stat(src);
        obd_flag newvalid = 0;

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE, "valid %x, new time %lu/%lu\n",
                       valid, LTIME_S(st->st_mtime),
                       LTIME_S(st->st_ctime));

        if (valid & OBD_MD_FLATIME) {
                dst->o_atime = LTIME_S(st->st_atime);
                newvalid |= OBD_MD_FLATIME;
        }
        if (valid & OBD_MD_FLMTIME) {
                dst->o_mtime = LTIME_S(st->st_mtime);
                newvalid |= OBD_MD_FLMTIME;
        }
        if (valid & OBD_MD_FLCTIME) {
                dst->o_ctime = LTIME_S(st->st_ctime);
                newvalid |= OBD_MD_FLCTIME;
        }
        if (valid & OBD_MD_FLSIZE) {
                dst->o_size = st->st_size;
                newvalid |= OBD_MD_FLSIZE;
        }
        if (valid & OBD_MD_FLBLOCKS) {  /* allocation of space (x512 bytes) */
                dst->o_blocks = st->st_blocks;
                newvalid |= OBD_MD_FLBLOCKS;
        }
        if (valid & OBD_MD_FLBLKSZ) {   /* optimal block size */
                dst->o_blksize = st->st_blksize;
                newvalid |= OBD_MD_FLBLKSZ;
        }
        if (valid & OBD_MD_FLTYPE) {
                dst->o_mode = (dst->o_mode & S_IALLUGO)|(st->st_mode & S_IFMT);
                newvalid |= OBD_MD_FLTYPE;
        }
        if (valid & OBD_MD_FLMODE) {
                dst->o_mode = (dst->o_mode & S_IFMT)|(st->st_mode & S_IALLUGO);
                newvalid |= OBD_MD_FLMODE;
        }
        if (valid & OBD_MD_FLUID) {
                dst->o_uid = st->st_uid;
                newvalid |= OBD_MD_FLUID;
        }
        if (valid & OBD_MD_FLGID) {
                dst->o_gid = st->st_gid;
                newvalid |= OBD_MD_FLGID;
        }
        if (valid & OBD_MD_FLFLAGS) {
                dst->o_flags = lli->lli_st_flags;
                newvalid |= OBD_MD_FLFLAGS;
        }
        if (valid & OBD_MD_FLGENER) {
                dst->o_generation = lli->lli_st_generation;
                newvalid |= OBD_MD_FLGENER;
        }
        if (valid & OBD_MD_FLFID) {
                dst->o_fid = st->st_ino;
                newvalid |= OBD_MD_FLFID;
        }

        dst->o_valid |= newvalid;
}

/*
 * really does the getattr on the inode and updates its fields
 */
int llu_inode_getattr(struct inode *inode, struct lov_stripe_md *lsm)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct obd_export *exp = llu_i2obdexp(inode);
        struct ptlrpc_request_set *set;
        struct obd_info oinfo = { { { 0 } } };
        struct obdo oa = { 0 };
        obd_flag refresh_valid;
        int rc;
        ENTRY;

        LASSERT(lsm);
        LASSERT(lli);

        oinfo.oi_md = lsm;
        oinfo.oi_oa = &oa;
        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = S_IFREG;
        oa.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ | OBD_MD_FLMTIME |
                OBD_MD_FLCTIME;

        set = ptlrpc_prep_set();
        if (set == NULL) {
                CERROR ("ENOMEM allocing request set\n");
                rc = -ENOMEM;
        } else {
                rc = obd_getattr_async(exp, &oinfo, set);
                if (rc == 0)
                        rc = ptlrpc_set_wait(set);
                ptlrpc_set_destroy(set);
        }
        if (rc)
                RETURN(rc);

        refresh_valid = OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ | OBD_MD_FLMTIME |
                        OBD_MD_FLCTIME | OBD_MD_FLSIZE;

        obdo_refresh_inode(inode, &oa, refresh_valid);

        RETURN(0);
}

static struct inode* llu_new_inode(struct filesys *fs,
                                   struct ll_fid *fid)
{
        struct inode *inode;
        struct llu_inode_info *lli;
        struct intnl_stat st = {
                .st_dev  = 0,
#ifndef AUTOMOUNT_FILE_NAME
                .st_mode = fid->f_type & S_IFMT,
#else
                .st_mode = fid->f_type /* all of the bits! */
#endif
                .st_uid  = geteuid(),
                .st_gid  = getegid(),
        };

        OBD_ALLOC(lli, sizeof(*lli));
        if (!lli)
                return NULL;

        /* initialize lli here */
        lli->lli_sbi = llu_fs2sbi(fs);
        lli->lli_smd = NULL;
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
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct llu_inode_info *lli = llu_i2info(inode);
        struct lustre_handle lockh;
        struct ldlm_res_id res_id = { .name = {0} };
        struct obd_device *obddev;
        ldlm_policy_data_t policy = { .l_inodebits = { lockpart } };
        int flags;
        ENTRY;

        LASSERT(inode);

        obddev = sbi->ll_mdc_exp->exp_obd;
        res_id.name[0] = llu_i2stat(inode)->st_ino;
        res_id.name[1] = lli->lli_st_generation;

        CDEBUG(D_INFO, "trying to match res "LPU64"\n", res_id.name[0]);

        flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING | LDLM_FL_TEST_LOCK;
        if (ldlm_lock_match(obddev->obd_namespace, flags, &res_id, LDLM_IBITS,
                            &policy, LCK_CR|LCK_CW|LCK_PR|LCK_PW, &lockh)) {
                RETURN(1);
        }
        RETURN(0);
}

static int llu_inode_revalidate(struct inode *inode)
{
        struct lov_stripe_md *lsm = NULL;
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
                struct ll_fid fid;
                unsigned long valid = OBD_MD_FLGETATTR;
                int rc, ealen = 0;

                /* Why don't we update all valid MDS fields here, if we're
                 * doing an RPC anyways?  -phil */
                if (S_ISREG(st->st_mode)) {
                        ealen = obd_size_diskmd(sbi->ll_osc_exp, NULL);
                        valid |= OBD_MD_FLEASIZE;
                }
                llu_inode2fid(&fid, inode);
                rc = mdc_getattr(sbi->ll_mdc_exp, &fid, valid, ealen, &req);
                if (rc) {
                        CERROR("failure %d inode %llu\n", rc,
                               (long long)st->st_ino);
                        RETURN(-abs(rc));
                }
                rc = mdc_req2lustre_md(req, REPLY_REC_OFF, sbi->ll_osc_exp,&md);

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


                llu_update_inode(inode, md.body, md.lsm);
                if (md.lsm != NULL && lli->lli_smd != md.lsm)
                        obd_free_memmd(sbi->ll_osc_exp, &md.lsm);

                if (md.body->valid & OBD_MD_FLSIZE)
                        set_bit(LLI_F_HAVE_MDS_SIZE_LOCK,
                                &lli->lli_flags);
                ptlrpc_req_finished(req);
        }

        lsm = lli->lli_smd;
        if (!lsm) {
                /* object not yet allocated, don't validate size */
                st->st_atime = lli->lli_lvb.lvb_atime;
                st->st_mtime = lli->lli_lvb.lvb_mtime;
                st->st_ctime = lli->lli_lvb.lvb_ctime;
                RETURN(0);
        }

        /* ll_glimpse_size will prefer locally cached writes if they extend
         * the file */
        RETURN(llu_glimpse_size(inode));
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
        struct ll_fid fid;
        struct llu_inode_info *lli = llu_i2info(inode);
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%llu/%lu(%p)\n",
               (long long)llu_i2stat(inode)->st_ino, lli->lli_st_generation,
               inode);

        llu_inode2fid(&fid, inode);
        clear_bit(LLI_F_HAVE_MDS_SIZE_LOCK, &(lli->lli_flags));
        mdc_change_cbdata(sbi->ll_mdc_exp, &fid, null_if_equal, inode);

        if (lli->lli_smd)
                obd_change_cbdata(sbi->ll_osc_exp, lli->lli_smd,
                                  null_if_equal, inode);

        if (lli->lli_smd) {
                obd_free_memmd(sbi->ll_osc_exp, &lli->lli_smd);
                lli->lli_smd = NULL;
        }

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
        LASSERT(ergo(ia_valid & ATTR_SIZE, llu_i2info(inode)->lli_smd == NULL));

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
                if (!in_group_p(st->st_gid) && !cfs_capable(CFS_CAP_FSETID))
                        st->st_mode &= ~S_ISGID;
        }
        /* mark_inode_dirty(inode); */
        return error;
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
        struct lov_stripe_md *lsm = llu_i2info(inode)->lli_smd;
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct intnl_stat *st = llu_i2stat(inode);
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data op_data;
        int ia_valid = attr->ia_valid;
        int rc = 0;
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
                attr->ia_ctime = CURRENT_TIME;
                attr->ia_valid |= ATTR_CTIME_SET;
        }
        if (!(ia_valid & ATTR_ATIME_SET) && (attr->ia_valid & ATTR_ATIME)) {
                attr->ia_atime = CURRENT_TIME;
                attr->ia_valid |= ATTR_ATIME_SET;
        }
        if (!(ia_valid & ATTR_MTIME_SET) && (attr->ia_valid & ATTR_MTIME)) {
                attr->ia_mtime = CURRENT_TIME;
                attr->ia_valid |= ATTR_MTIME_SET;
        }

        if (attr->ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu, now = %lu\n",
                       LTIME_S(attr->ia_mtime), LTIME_S(attr->ia_ctime),
                       LTIME_S(CURRENT_TIME));
        if (lsm)
                attr->ia_valid &= ~ATTR_SIZE;

        /* If only OST attributes being set on objects, don't do MDS RPC.
         * In that case, we need to check permissions and update the local
         * inode ourselves so we can call obdo_from_inode() always. */
        if (ia_valid & (lsm ? ~(ATTR_SIZE | ATTR_FROM_OPEN | ATTR_RAW) : ~0)) {
                struct lustre_md md;
                llu_prepare_mdc_op_data(&op_data, inode, NULL, NULL, 0, 0);

                rc = mdc_setattr(sbi->ll_mdc_exp, &op_data,
                                  attr, NULL, 0, NULL, 0, &request);

                if (rc) {
                        ptlrpc_req_finished(request);
                        if (rc != -EPERM && rc != -EACCES)
                                CERROR("mdc_setattr fails: rc = %d\n", rc);
                        RETURN(rc);
                }

                rc = mdc_req2lustre_md(request, REPLY_REC_OFF, sbi->ll_osc_exp,
                                       &md);
                if (rc) {
                        ptlrpc_req_finished(request);
                        RETURN(rc);
                }

                /* We call inode_setattr to adjust timestamps.
                 * If there is at least some data in file, we cleared ATTR_SIZE
                 * above to avoid invoking vmtruncate, otherwise it is important
                 * to call vmtruncate in inode_setattr to update inode->i_size
                 * (bug 6196) */
                inode_setattr(inode, attr);
                llu_update_inode(inode, md.body, md.lsm);
                ptlrpc_req_finished(request);

                if (!lsm || !S_ISREG(st->st_mode)) {
                        CDEBUG(D_INODE, "no lsm: not setting attrs on OST\n");
                        RETURN(0);
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

        if (ia_valid & ATTR_SIZE) {
                ldlm_policy_data_t policy = { .l_extent = {attr->ia_size,
                                                           OBD_OBJECT_EOF} };
                struct lustre_handle lockh = { 0, };
                struct lustre_handle match_lockh = { 0, };

                int err;
                int flags = LDLM_FL_TEST_LOCK; /* for assertion check below */
                int lock_mode;
                obd_flag obd_flags;

                /* check that there are no matching locks */
                LASSERT(obd_match(sbi->ll_osc_exp, lsm, LDLM_EXTENT, &policy,
                                  LCK_PW, &flags, inode, &match_lockh, NULL)
                                  <= 0);

                /* XXX when we fix the AST intents to pass the discard-range
                 * XXX extent, make ast_flags always LDLM_AST_DISCARD_DATA
                 * XXX here. */
                flags = (attr->ia_size == 0) ? LDLM_AST_DISCARD_DATA : 0;

                if (sbi->ll_lco.lco_flags & OBD_CONNECT_TRUNCLOCK) {
                        lock_mode = LCK_NL;
                        obd_flags = OBD_FL_TRUNCLOCK;
                        CDEBUG(D_INODE, "delegating locking to the OST");
                } else {
                        lock_mode = LCK_PW;
                        obd_flags = 0;
                }

                /* with lock_mode == LK_NL no lock is taken. */
                rc = llu_extent_lock(NULL, inode, lsm, lock_mode, &policy,
                                     &lockh, flags);
                if (rc != ELDLM_OK) {
                        if (rc > 0)
                                RETURN(-ENOLCK);
                        RETURN(rc);
                }

                rc = llu_vmtruncate(inode, attr->ia_size, obd_flags);

                /* unlock now as we don't mind others file lockers racing with
                 * the mds updates below? */
                err = llu_extent_unlock(NULL, inode, lsm, lock_mode, &lockh);
                if (err) {
                        CERROR("llu_extent_unlock failed: %d\n", err);
                        if (!rc)
                                rc = err;
                }
        } else if (ia_valid & (ATTR_MTIME | ATTR_MTIME_SET)) {
                struct obd_info oinfo = { { { 0 } } };
                struct obdo oa = { 0 };
                struct lustre_handle lockh = { 0 };
                obd_valid valid;

                CDEBUG(D_INODE, "set mtime on OST inode %llu to %lu\n",
                       (long long)st->st_ino, LTIME_S(attr->ia_mtime));

                oa.o_id = lsm->lsm_object_id;
                oa.o_valid = OBD_MD_FLID;

                valid = OBD_MD_FLTYPE;

                if (LTIME_S(attr->ia_mtime) < LTIME_S(attr->ia_ctime)){
                        struct ost_lvb xtimes;

                        /* setting mtime to past is performed under PW
                         * EOF extent lock */
                        oinfo.oi_policy.l_extent.start = 0;
                        oinfo.oi_policy.l_extent.end = OBD_OBJECT_EOF;
                        rc = llu_extent_lock(NULL, inode, lsm, LCK_PW,
                                             &oinfo.oi_policy,
                                             &lockh, 0);
                        if (rc)
                                RETURN(rc);

                        /* setattr under locks
                         *
                         * 1. restore inode's timestamps which are
                         * about to be set as long as concurrent stat
                         * (via llu_glimpse_size) might bring
                         * out-of-date ones
                         *
                         * 2. update lsm so that next stat (via
                         * llu_glimpse_size) could get correct values
                         * in lsm */
                        lov_stripe_lock(lsm);
                        if (ia_valid & ATTR_ATIME) {
                                st->st_atime = xtimes.lvb_atime =
                                        attr->ia_atime;
                                valid |= OBD_MD_FLATIME;
                        }
                        if (ia_valid & ATTR_MTIME) {
                                st->st_mtime = xtimes.lvb_mtime =
                                        attr->ia_mtime;
                                valid |= OBD_MD_FLMTIME;
                        }
                        if (ia_valid & ATTR_CTIME) {
                                st->st_ctime = xtimes.lvb_ctime =
                                        attr->ia_mtime;
                                valid |= OBD_MD_FLCTIME;
                        }

                        obd_update_lvb(sbi->ll_osc_exp, lsm,
                                       &xtimes, valid);
                        lov_stripe_unlock(lsm);
                } else {
                        /* lockless setattr
                         *
                         * 1. do not use inode's timestamps because
                         * concurrent stat might fill the inode with
                         * out-of-date times, send values from attr
                         * instead
                         *
                         * 2.do no update lsm, as long as stat (via
                         * ll_glimpse_size) will bring attributes from
                         * osts anyway */
                        if (ia_valid & ATTR_ATIME) {
                                oa.o_atime = attr->ia_atime;
                                oa.o_valid |= OBD_MD_FLATIME;
                        }
                        if (ia_valid & ATTR_MTIME) {
                                oa.o_mtime = attr->ia_mtime;
                                oa.o_valid |= OBD_MD_FLMTIME;
                        }
                        if (ia_valid & ATTR_CTIME) {
                                oa.o_ctime = attr->ia_ctime;
                                oa.o_valid |= OBD_MD_FLCTIME;
                        }
                }

                obdo_from_inode(&oa, inode, valid);

                oinfo.oi_oa = &oa;
                oinfo.oi_md = lsm;

                rc = obd_setattr_rqset(sbi->ll_osc_exp, &oinfo, NULL);
                if (rc)
                        CERROR("obd_setattr_async fails: rc=%d\n", rc);

                if (LTIME_S(attr->ia_mtime) < LTIME_S(attr->ia_ctime)){
                        int err;

                        err = llu_extent_unlock(NULL, inode, lsm,
                                               LCK_PW, &lockh);
                        if (unlikely(err != 0)) {
                                CERROR("extent unlock failed: "
                                       "err=%d\n", err);
                                if (rc == 0)
                                        rc = err;
                        }
                }
        }
        RETURN(rc);
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
        iattr.ia_ctime = CURRENT_TIME;

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
        struct mdc_op_data op_data;
        int err = -EMLINK;
        ENTRY;

        liblustre_wait_event(0);
        if (llu_i2stat(dir)->st_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        llu_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
        err = mdc_create(sbi->ll_mdc_exp, &op_data, tgt, strlen(tgt) + 1,
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
        struct ll_fid fid;
        struct mds_body *body;
        struct intnl_stat *st = llu_i2stat(inode);
        int rc, symlen = st->st_size + 1;
        ENTRY;

        *request = NULL;
        *symname = NULL;

        if (lli->lli_symlink_name) {
                *symname = lli->lli_symlink_name;
                CDEBUG(D_INODE, "using cached symlink %s\n", *symname);
                RETURN(0);
        }

        llu_inode2fid(&fid, inode);
        rc = mdc_getattr(sbi->ll_mdc_exp, &fid,
                         OBD_MD_LINKNAME, symlen, request);
        if (rc) {
                CERROR("inode %llu: rc = %d\n", (long long)st->st_ino, rc);
                RETURN(rc);
        }

        body = lustre_msg_buf((*request)->rq_repmsg, REPLY_REC_OFF,
                              sizeof(*body));
        LASSERT(body != NULL);
        LASSERT(lustre_rep_swabbed(*request, REPLY_REC_OFF));

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

        *symname = lustre_msg_buf((*request)->rq_repmsg, REPLY_REC_OFF + 1,
                                   symlen);
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
        struct mdc_op_data op_data;
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
                llu_prepare_mdc_op_data(&op_data, dir, NULL,
                                        pno->p_base->pb_name.name,
                                        pno->p_base->pb_name.len,
                                        0);
                err = mdc_create(sbi->ll_mdc_exp, &op_data, NULL, 0, mode,
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
        struct mdc_op_data op_data;
        int rc;
        ENTRY;

        LASSERT(src);
        LASSERT(dir);

        liblustre_wait_event(0);
        llu_prepare_mdc_op_data(&op_data, src, dir, name, namelen, 0);
        rc = mdc_link(llu_i2sbi(src)->ll_mdc_exp, &op_data, &request);
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
        struct mdc_op_data op_data;
        int rc;
        ENTRY;

        LASSERT(target);

        liblustre_wait_event(0);
        llu_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
        rc = mdc_unlink(llu_i2sbi(dir)->ll_mdc_exp, &op_data, &request);
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
        struct mdc_op_data op_data;
        int rc;
        ENTRY;

        LASSERT(src);
        LASSERT(tgt);

        liblustre_wait_event(0);
        llu_prepare_mdc_op_data(&op_data, src, tgt, NULL, 0, 0);
        rc = mdc_rename(llu_i2sbi(src)->ll_mdc_exp, &op_data,
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

        rc = obd_statfs(class_exp2obd(sbi->ll_mdc_exp), osfs, max_age, 0);
        if (rc) {
                CERROR("mdc_statfs fails: rc = %d\n", rc);
                RETURN(rc);
        }

        CDEBUG(D_SUPER, "MDC blocks "LPU64"/"LPU64" objects "LPU64"/"LPU64"\n",
               osfs->os_bavail, osfs->os_blocks, osfs->os_ffree,osfs->os_files);

        rc = obd_statfs_rqset(class_exp2obd(sbi->ll_osc_exp),
                              &obd_osfs, max_age, 0);
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
        struct mdc_op_data op_data;
        int err = -EMLINK;
        ENTRY;

        liblustre_wait_event(0);
        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%llu/%lu(%p)\n", len, name,
               (long long)st->st_ino, llu_i2info(dir)->lli_st_generation, dir);

        if (st->st_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        llu_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
        err = mdc_create(llu_i2sbi(dir)->ll_mdc_exp, &op_data, NULL, 0,
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
        struct mdc_op_data op_data;
        int rc;
        ENTRY;

        liblustre_wait_event(0);
        CDEBUG(D_VFSTRACE, "VFS Op:name=%.*s,dir=%llu/%lu(%p)\n", len, name,
               (long long)llu_i2stat(dir)->st_ino,
               llu_i2info(dir)->lli_st_generation, dir);

        llu_prepare_mdc_op_data(&op_data, dir, NULL, name, len, S_IFDIR);
        rc = mdc_unlink(llu_i2sbi(dir)->ll_mdc_exp, &op_data, &request);
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
int llu_file_flock(struct inode *ino, int cmd, struct file_lock *file_lock)
{
        struct llu_inode_info *lli = llu_i2info(ino);
        struct intnl_stat *st = llu_i2stat(ino);
        struct ldlm_res_id res_id =
                { .name = {st->st_ino, lli->lli_st_generation, LDLM_FLOCK} };
        struct ldlm_enqueue_info einfo = { LDLM_FLOCK, 0, NULL,
                ldlm_flock_completion_ast, NULL, file_lock };
        struct lustre_handle lockh = {0};
        ldlm_policy_data_t flock;
        int flags = 0;
        int rc;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%llu file_lock=%p\n",
               (unsigned long long) st->st_ino, file_lock);

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

        CDEBUG(D_DLMTRACE, "inode=%llu, pid=%u, flags=%#x, mode=%u, "
               "start="LPU64", end="LPU64"\n",
               (unsigned long long) st->st_ino, flock.l_flock.pid,
               flags, einfo.ei_mode, flock.l_flock.start, flock.l_flock.end);

        rc = ldlm_cli_enqueue(llu_i2mdcexp(ino), NULL, &einfo, res_id, 
                              &flock, &flags, NULL, 0, NULL, &lockh, 0);

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

        error = -EINVAL;
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
                        *rtn = -1;
                        err = -EINVAL;
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
                *rtn = -1;
                err = -ENOSYS;
                break;
        }

        liblustre_wait_event(0);
        return err;
}

static int llu_get_grouplock(struct inode *inode, unsigned long arg)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        ldlm_policy_data_t policy = { .l_extent = { .start = 0,
                                                    .end = OBD_OBJECT_EOF}};
        struct lustre_handle lockh = { 0 };
        struct lov_stripe_md *lsm = lli->lli_smd;
        ldlm_error_t err;
        int flags = 0;
        ENTRY;

        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                RETURN(-EINVAL);
        }

        policy.l_extent.gid = arg;
        if (lli->lli_open_flags & O_NONBLOCK)
                flags = LDLM_FL_BLOCK_NOWAIT;

        err = llu_extent_lock(fd, inode, lsm, LCK_GROUP, &policy, &lockh,
                              flags);
        if (err)
                RETURN(err);

        fd->fd_flags |= LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK;
        fd->fd_gid = arg;
        memcpy(&fd->fd_cwlockh, &lockh, sizeof(lockh));

        RETURN(0);
}

static int llu_put_grouplock(struct inode *inode, unsigned long arg)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct lov_stripe_md *lsm = lli->lli_smd;
        ldlm_error_t err;
        ENTRY;

        if (!(fd->fd_flags & LL_FILE_GROUP_LOCKED))
                RETURN(-EINVAL);

        if (fd->fd_gid != arg)
                RETURN(-EINVAL);

        fd->fd_flags &= ~(LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK);

        err = llu_extent_unlock(fd, inode, lsm, LCK_GROUP, &fd->fd_cwlockh);
        if (err)
                RETURN(err);

        fd->fd_gid = 0;
        memset(&fd->fd_cwlockh, 0, sizeof(fd->fd_cwlockh));

        RETURN(0);
}

static int llu_lov_dir_setstripe(struct inode *ino, unsigned long arg)
{
        struct llu_sb_info *sbi = llu_i2sbi(ino); 
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data op_data;
        struct iattr attr = { 0 };
        struct lov_user_md_v3 lum;
        struct lov_user_md *lump = (struct lov_user_md *)arg;
        int rc = 0, lum_size = 0;

        llu_prepare_mdc_op_data(&op_data, ino, NULL, NULL, 0, 0);

        LASSERT(sizeof(lum.lmm_objects[0]) ==
                sizeof(lump->lmm_objects[0]));
        rc = copy_from_user(&lum, lump, sizeof(*lump));
        if (rc)
                return(-EFAULT);
        lum_size = sizeof(struct lov_user_md_v1);
        if (lum.lmm_magic == LOV_USER_MAGIC_V3) {
                rc = copy_from_user(&lum, lump, sizeof(lum));
                if (rc)
                        return(-EFAULT);
                lum_size = sizeof(struct lov_user_md_v3);
        }

        if ((lum.lmm_magic != cpu_to_le32(LOV_USER_MAGIC_V1)) &&
            (lum.lmm_magic != cpu_to_le32(LOV_USER_MAGIC_V3))) {
                rc = lustre_swab_lov_user_md((struct lov_user_md_v1 *)&lum);
                if (rc) 
                        RETURN(rc);
        }

        /* swabbing is done in lov_setstripe() on server side */
        rc = mdc_setattr(sbi->ll_mdc_exp, &op_data,
                         &attr, &lum, lum_size, NULL, 0, &request);
        if (rc) {
                ptlrpc_req_finished(request);
                if (rc != -EPERM && rc != -EACCES)
                        CERROR("mdc_setattr fails: rc = %d\n", rc);
                return rc;
        }
        ptlrpc_req_finished(request);

        return rc;
}

static int llu_lov_setstripe_ea_info(struct inode *ino, int flags,
                                     struct lov_user_md *lum, int lum_size)
{
        struct llu_sb_info *sbi = llu_i2sbi(ino); 
        struct obd_export *exp = llu_i2obdexp(ino);
        struct llu_inode_info *lli = llu_i2info(ino);
        struct llu_inode_info *lli2 = NULL;
        struct lov_stripe_md *lsm;
        struct lookup_intent oit = {.it_op = IT_OPEN, .it_flags = flags};
        struct ldlm_enqueue_info einfo = { LDLM_IBITS, LCK_CR,
                llu_mdc_blocking_ast, ldlm_completion_ast, NULL, NULL };

        struct ptlrpc_request *req = NULL;
        struct lustre_md md;
        struct mdc_op_data data;
        struct lustre_handle lockh;
        int rc = 0;
        ENTRY;

        lsm = lli->lli_smd;
        if (lsm) {
                CDEBUG(D_IOCTL, "stripe already exists for ino "LPU64"\n",
                       lli->lli_fid.id);
                return -EEXIST;
        }

        OBD_ALLOC(lli2, sizeof(struct llu_inode_info));
        if (!lli2)
                return -ENOMEM;
        
        memcpy(lli2, lli, sizeof(struct llu_inode_info));
        lli2->lli_open_count = 0;
        lli2->lli_it = NULL;
        lli2->lli_file_data = NULL;
        lli2->lli_smd = NULL;
        lli2->lli_symlink_name = NULL;
        ino->i_private = lli2;

        llu_prepare_mdc_op_data(&data, NULL, ino, NULL, 0, O_RDWR);

        rc = mdc_enqueue(sbi->ll_mdc_exp, &einfo, &oit, &data,
                         &lockh, lum, lum_size, LDLM_FL_INTENT_ONLY);
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
        
        rc = mdc_req2lustre_md(req, DLM_REPLY_REC_OFF, exp, &md);
        if (rc)
                GOTO(out, rc);
        
        llu_update_inode(ino, md.body, md.lsm);
        lli->lli_smd = lli2->lli_smd;
        lli2->lli_smd = NULL;

        llu_local_open(lli2, &oit);
       
        /* release intent */
        if (lustre_handle_is_used(&lockh))
                ldlm_lock_decref(&lockh, LCK_CR);

        ptlrpc_req_finished(req);
        req = NULL;
        
        rc = llu_file_release(ino);
 out:
        ino->i_private = lli;
        if (lli2)
                OBD_FREE(lli2, sizeof(struct llu_inode_info));
        if (req != NULL)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

static int llu_lov_file_setstripe(struct inode *ino, unsigned long arg)
{
        struct lov_user_md lum, *lump = (struct lov_user_md *)arg;
        int rc;
        int flags = FMODE_WRITE;
        ENTRY;

        LASSERT(sizeof(lum) == sizeof(*lump));
        LASSERT(sizeof(lum.lmm_objects[0]) == sizeof(lump->lmm_objects[0]));
        rc = copy_from_user(&lum, lump, sizeof(lum));
        if (rc)
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
        struct lov_stripe_md *lsm = llu_i2info(ino)->lli_smd;

        if (!lsm)
                RETURN(-ENODATA);

        return obd_iocontrol(LL_IOC_LOV_GETSTRIPE, llu_i2obdexp(ino), 0, lsm,
                            (void *)arg);
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
        struct ll_fid fid;
        struct file_identifier fileid = {&fid, sizeof(fid)};

        if ((md->body->valid &
             (OBD_MD_FLGENER | OBD_MD_FLID | OBD_MD_FLTYPE)) !=
            (OBD_MD_FLGENER | OBD_MD_FLID | OBD_MD_FLTYPE)) {
                CERROR("bad md body valid mask "LPX64"\n", md->body->valid);
                LBUG();
                return ERR_PTR(-EPERM);
        }

        /* try to find existing inode */
        fid = md->body->fid1;

        inode = _sysio_i_find(fs, &fileid);
        if (inode) {
                struct llu_inode_info *lli = llu_i2info(inode);

                if (inode->i_zombie ||
                    lli->lli_st_generation != md->body->generation) {
                        I_RELE(inode);
                }
                else {
                        llu_update_inode(inode, md->body, md->lsm);
                        return inode;
                }
        }

        inode = llu_new_inode(fs, &fid);
        if (inode)
                llu_update_inode(inode, md->body, md->lsm);

        return inode;
}

extern struct list_head lustre_profile_list;

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
        struct ll_fid rootfid;
        struct llu_sb_info *sbi;
        struct obd_statfs osfs;
        static struct qstr noname = { NULL, 0, 0 };
        struct ptlrpc_request *request = NULL;
        struct lustre_handle mdc_conn = {0, };
        struct lustre_handle osc_conn = {0, };
        struct lustre_md md;
        class_uuid_t uuid;
        struct config_llog_instance cfg = {0, };
        char ll_instance[sizeof(sbi) * 2 + 3];
        struct lustre_profile *lprof;
        char *zconf_mgsnid, *zconf_profile;
        char *osc = NULL, *mdc = NULL;
        int async = 1, err = -EINVAL;
        struct obd_connect_data ocd = {0,};

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
        snprintf(ll_instance, sizeof(ll_instance), "%p", sbi);

        /* retrive & parse config log */
        cfg.cfg_instance = ll_instance;
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
        OBD_ALLOC(osc, strlen(lprof->lp_osc) + strlen(ll_instance) + 2);
        sprintf(osc, "%s-%s", lprof->lp_osc, ll_instance);

        OBD_ALLOC(mdc, strlen(lprof->lp_mdc) + strlen(ll_instance) + 2);
        sprintf(mdc, "%s-%s", lprof->lp_mdc, ll_instance);

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
        obd_set_info_async(obd->obd_self_export, sizeof(KEY_ASYNC), KEY_ASYNC,
                           sizeof(async), &async, NULL);

        ocd.ocd_connect_flags = OBD_CONNECT_IBITS | OBD_CONNECT_VERSION |
                                OBD_CONNECT_AT | OBD_CONNECT_VBR;
#ifdef LIBLUSTRE_POSIX_ACL
        ocd.ocd_connect_flags |= OBD_CONNECT_ACL;
#endif
        ocd.ocd_ibits_known = MDS_INODELOCK_FULL;
        ocd.ocd_version = LUSTRE_VERSION_CODE;

        /* setup mdc */
        err = obd_connect(&mdc_conn, obd, &sbi->ll_sb_uuid, &ocd, &sbi->ll_mdc_exp);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                GOTO(out_free, err);
        }

        err = obd_statfs(obd, &osfs, 100000000, 0);
        if (err)
                GOTO(out_mdc, err);

        /*
         * FIXME fill fs stat data into sbi here!!! FIXME
         */

        /* setup osc */
        obd = class_name2obd(osc);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                GOTO(out_mdc, err = -EINVAL);
        }
        obd_set_info_async(obd->obd_self_export, sizeof(KEY_ASYNC), KEY_ASYNC,
                           sizeof(async), &async, NULL);

        obd->obd_upcall.onu_owner = &sbi->ll_lco;
        obd->obd_upcall.onu_upcall = ll_ocd_update;

        obd_register_lock_cancel_cb(obd, llu_extent_lock_cancel_cb);

        ocd.ocd_connect_flags = OBD_CONNECT_SRVLOCK | OBD_CONNECT_REQPORTAL |
                                OBD_CONNECT_VERSION | OBD_CONNECT_TRUNCLOCK |
                                OBD_CONNECT_AT | OBD_CONNECT_EINPROGRESS;
        ocd.ocd_version = LUSTRE_VERSION_CODE;
        err = obd_connect(&osc_conn, obd, &sbi->ll_sb_uuid, &ocd, &sbi->ll_osc_exp);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", osc, err);
                GOTO(out_lock_cb, err);
        }
        sbi->ll_lco.lco_flags = ocd.ocd_connect_flags;
        sbi->ll_lco.lco_mdc_exp = sbi->ll_mdc_exp;
        sbi->ll_lco.lco_osc_exp = sbi->ll_osc_exp;

        mdc_init_ea_size(sbi->ll_mdc_exp, sbi->ll_osc_exp);

        err = mdc_getstatus(sbi->ll_mdc_exp, &rootfid);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_lock_cb, err);
        }
        CDEBUG(D_SUPER, "rootfid "LPU64"\n", rootfid.id);
        sbi->ll_rootino = rootfid.id;

        /* fetch attr of root inode */
        err = mdc_getattr(sbi->ll_mdc_exp, &rootfid,
                          OBD_MD_FLGETATTR | OBD_MD_FLBLOCKS, 0, 
                          &request);
        if (err) {
                CERROR("mdc_getattr failed for root: rc = %d\n", err);
                GOTO(out_osc, err);
        }

        err = mdc_req2lustre_md(request, REPLY_REC_OFF, sbi->ll_osc_exp, &md);
        if (err) {
                CERROR("failed to understand root inode md: rc = %d\n",err);
                GOTO(out_request, err);
        }

        LASSERT(sbi->ll_rootino != 0);

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

        ptlrpc_req_finished(request);

        CDEBUG(D_SUPER, "LibLustre: %s mounted successfully!\n", source);
        liblustre_wait_idle();

        return 0;

out_inode:
        _sysio_i_gone(root);
out_request:
        ptlrpc_req_finished(request);
out_osc:
        obd_disconnect(sbi->ll_osc_exp);
out_lock_cb:
        obd = class_name2obd(osc);
        obd_unregister_lock_cancel_cb(obd, llu_extent_lock_cancel_cb);
out_mdc:
        obd_disconnect(sbi->ll_mdc_exp);
out_free:
        if (osc)
                OBD_FREE(osc, strlen(osc) + 1);
        if (mdc)
                OBD_FREE(mdc, strlen(mdc) + 1);
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
