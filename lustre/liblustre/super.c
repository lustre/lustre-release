/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_LLITE

#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <sysio.h>
#include <fs.h>
#include <mount.h>
#include <inode.h>
#include <file.h>

#include "llite_lib.h"

static void llu_fsop_gone(struct filesys *fs)
{
        /* FIXME */
}

static struct inode_ops llu_inode_ops;

void llu_update_inode(struct inode *inode, struct mds_body *body,
                      struct lov_stripe_md *lsm)
{
        struct llu_inode_info *lli = llu_i2info(inode);

        LASSERT ((lsm != NULL) == ((body->valid & OBD_MD_FLEASIZE) != 0));
        if (lsm != NULL) {
                if (lli->lli_smd == NULL)                        
                        lli->lli_smd = lsm;
                else
                        LASSERT (!memcmp (lli->lli_smd, lsm,
                                          sizeof (*lsm)));
        }

        if (body->valid & OBD_MD_FLID)
                lli->lli_st_ino = body->ino;
        if (body->valid & OBD_MD_FLATIME)
                LTIME_S(lli->lli_st_atime) = body->atime;
        if (body->valid & OBD_MD_FLMTIME)
                LTIME_S(lli->lli_st_mtime) = body->mtime;
        if (body->valid & OBD_MD_FLCTIME)
                LTIME_S(lli->lli_st_ctime) = body->ctime;
        if (body->valid & OBD_MD_FLMODE)
                lli->lli_st_mode = (lli->lli_st_mode & S_IFMT)|(body->mode & ~S_IFMT);
        if (body->valid & OBD_MD_FLTYPE)
                lli->lli_st_mode = (lli->lli_st_mode & ~S_IFMT)|(body->mode & S_IFMT);
        if (body->valid & OBD_MD_FLUID)
                lli->lli_st_uid = body->uid;
        if (body->valid & OBD_MD_FLGID)
                lli->lli_st_gid = body->gid;
        if (body->valid & OBD_MD_FLFLAGS)
                lli->lli_st_flags = body->flags;
        if (body->valid & OBD_MD_FLNLINK)
                lli->lli_st_nlink = body->nlink;
        if (body->valid & OBD_MD_FLGENER)
                lli->lli_st_generation = body->generation;
        if (body->valid & OBD_MD_FLRDEV)
                lli->lli_st_rdev = body->rdev;
        if (body->valid & OBD_MD_FLSIZE)
                lli->lli_st_size = body->size;
        if (body->valid & OBD_MD_FLBLOCKS)
                lli->lli_st_blocks = body->blocks;

        /* fillin fid */
        if (body->valid & OBD_MD_FLID)
                lli->lli_fid.id = body->ino;
        if (body->valid & OBD_MD_FLGENER)
                lli->lli_fid.generation = body->generation;
        if (body->valid & OBD_MD_FLTYPE)
                lli->lli_fid.f_type = body->mode & S_IFMT;
}

void obdo_to_inode(struct inode *dst, struct obdo *src, obd_flag valid)
{
        struct llu_inode_info *lli = llu_i2info(dst);

        valid &= src->o_valid;

        if (valid & OBD_MD_FLATIME)
                LTIME_S(lli->lli_st_atime) = src->o_atime;
        if (valid & OBD_MD_FLMTIME)
                LTIME_S(lli->lli_st_mtime) = src->o_mtime;
        if (valid & OBD_MD_FLCTIME && src->o_ctime > LTIME_S(lli->lli_st_ctime))
                LTIME_S(lli->lli_st_ctime) = src->o_ctime;
        if (valid & OBD_MD_FLSIZE)
                lli->lli_st_size = src->o_size;
        if (valid & OBD_MD_FLBLOCKS) /* allocation of space */
                lli->lli_st_blocks = src->o_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                lli->lli_st_blksize = src->o_blksize;
        if (valid & OBD_MD_FLTYPE)
                lli->lli_st_mode = (lli->lli_st_mode & ~S_IFMT) | (src->o_mode & S_IFMT);
        if (valid & OBD_MD_FLMODE)
                lli->lli_st_mode = (lli->lli_st_mode & S_IFMT) | (src->o_mode & ~S_IFMT);
        if (valid & OBD_MD_FLUID)
                lli->lli_st_uid = src->o_uid;
        if (valid & OBD_MD_FLGID)
                lli->lli_st_gid = src->o_gid;
        if (valid & OBD_MD_FLFLAGS)
                lli->lli_st_flags = src->o_flags;
        if (valid & OBD_MD_FLNLINK)
                lli->lli_st_nlink = src->o_nlink;
        if (valid & OBD_MD_FLGENER)
                lli->lli_st_generation = src->o_generation;
        if (valid & OBD_MD_FLRDEV)
                lli->lli_st_rdev = src->o_rdev;
}

void obdo_from_inode(struct obdo *dst, struct inode *src, obd_flag valid)
{
        struct llu_inode_info *lli = llu_i2info(src);

        if (valid & OBD_MD_FLATIME)
                dst->o_atime = LTIME_S(lli->lli_st_atime);
        if (valid & OBD_MD_FLMTIME)
                dst->o_mtime = LTIME_S(lli->lli_st_mtime);
        if (valid & OBD_MD_FLCTIME)
                dst->o_ctime = LTIME_S(lli->lli_st_ctime);
        if (valid & OBD_MD_FLSIZE)
                dst->o_size = lli->lli_st_size;
        if (valid & OBD_MD_FLBLOCKS)   /* allocation of space */
                dst->o_blocks = lli->lli_st_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                dst->o_blksize = lli->lli_st_blksize;
        if (valid & OBD_MD_FLTYPE)
                dst->o_mode = (dst->o_mode & ~S_IFMT) | (lli->lli_st_mode & S_IFMT);
        if (valid & OBD_MD_FLMODE)
                dst->o_mode = (dst->o_mode & S_IFMT) | (lli->lli_st_mode & ~S_IFMT);
        if (valid & OBD_MD_FLUID)
                dst->o_uid = lli->lli_st_uid;
        if (valid & OBD_MD_FLGID)
                dst->o_gid = lli->lli_st_gid;
        if (valid & OBD_MD_FLFLAGS)
                dst->o_flags = lli->lli_st_flags;
        if (valid & OBD_MD_FLNLINK)
                dst->o_nlink = lli->lli_st_nlink;
        if (valid & OBD_MD_FLGENER)
                dst->o_generation = lli->lli_st_generation;
        if (valid & OBD_MD_FLRDEV)
                dst->o_rdev = (__u32)(lli->lli_st_rdev);

        dst->o_valid |= (valid & ~OBD_MD_FLID);
}

int llu_inode_getattr(struct inode *inode, struct lov_stripe_md *lsm,
                      char *ostdata)
{
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct obdo oa;
        int rc;
        ENTRY;

        LASSERT(lsm);
        LASSERT(sbi);

        memset(&oa, 0, sizeof oa);
        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = S_IFREG;
        oa.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                OBD_MD_FLBLOCKS | OBD_MD_FLMTIME | OBD_MD_FLCTIME;

        if (ostdata != NULL) {
                memcpy(&oa.o_inline, ostdata, FD_OSTDATA_SIZE);
                oa.o_valid |= OBD_MD_FLHANDLE;
        }

        rc = obd_getattr(&sbi->ll_osc_conn, &oa, lsm);
        if (rc)
                RETURN(rc);

        obdo_to_inode(inode, &oa, OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                           OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        RETURN(0);
}

struct inode* llu_new_inode(struct filesys *fs, ino_t ino, mode_t mode)
{
	struct inode *inode;
        struct llu_inode_info *lli;

        OBD_ALLOC(lli, sizeof(*lli));
        if (!lli)
                return NULL;

        /* initialize lli here */
        lli->lli_sbi = llu_fs2sbi(fs);
        lli->lli_smd = NULL;
        lli->lli_symlink_name = NULL;
        lli->lli_flags = 0;
        INIT_LIST_HEAD(&lli->lli_read_extents);
        lli->lli_file_data = NULL;

        /* could file_identifier be 0 ? FIXME */
	inode = _sysio_i_new(fs, ino, NULL,
#ifndef AUTOMOUNT_FILE_NAME
	 	       	     mode & S_IFMT,
#else
			     mode,	/* all of the bits! */
#endif
                             0,
			     &llu_inode_ops, lli);

	if (!inode)
		OBD_FREE(lli, sizeof(*lli));

        return inode;
}

static int llu_iop_lookup(struct pnode *pnode,
                          struct inode **inop,
                          struct intent *intnt __IS_UNUSED,
                          const char *path __IS_UNUSED)
{
        struct pnode_base *pb_dir = pnode->p_parent->p_base;
        struct ptlrpc_request *request = NULL;
        struct llu_sb_info *sbi = llu_i2sbi(pb_dir->pb_ino);
        struct ll_fid *fid = &llu_i2info(pb_dir->pb_ino)->lli_fid;
        struct qstr *name = &pnode->p_base->pb_name;
        struct mds_body *body;
        unsigned long valid;
        char *pname;
        int rc, easize;
        struct ll_read_inode2_cookie lic = {.lic_body = NULL, .lic_lsm = NULL};

        /* the mount root inode have no name, so don't call
         * remote in this case. but probably we need revalidate
         * it here? FIXME */
        if (pnode->p_mount->mnt_root == pnode) {
                struct inode *i = pnode->p_base->pb_ino;
                I_REF(i);
                *inop = i;
                return 0;
        }

        if (!name->len)
                return -EINVAL;

        /* mdc_getattr_name require NULL-terminated name */
        OBD_ALLOC(pname, name->len + 1);
        if (!pname)
                return -ENOMEM;
        memcpy(pname, name->name, name->len);
        pname[name->len] = 0;

        valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE;

        /* FIXME before getattr_name, we don't know whether
         * the inode we are finding is regular or not, so here
         * we blindly require server feed in EA data */
        easize = obd_size_diskmd(&sbi->ll_osc_conn, NULL);
        valid |= OBD_MD_FLEASIZE;

        rc = mdc_getattr_name(&sbi->ll_mdc_conn, fid,
                              pname, name->len + 1,
                              valid, easize, &request);
        if (rc < 0) {
                CERROR("mdc_getattr_name: %d\n", rc);
                rc = -ENOENT;
                goto out;
        }
        body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*body));

        *inop = llu_new_inode(pnode->p_mount->mnt_fs, body->ino, body->mode);
        if (!inop)
                goto out;

        lic.lic_body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*lic.lic_body));
        LASSERT (lic.lic_body != NULL);
        LASSERT_REPSWABBED (request, 0);

        if (S_ISREG(lic.lic_body->mode) &&
            lic.lic_body->valid & OBD_MD_FLEASIZE) {
                struct lov_mds_md    *lmm;
                int                   lmm_size;
                int                   rc;
                
                lmm_size = lic.lic_body->eadatasize;
                if (lmm_size == 0) {
                        CERROR ("OBD_MD_FLEASIZE set but eadatasize 0\n");
                        RETURN (-EPROTO);
                }
                lmm = lustre_msg_buf(request->rq_repmsg, 0 + 1, lmm_size);
                LASSERT(lmm != NULL);
                LASSERT_REPSWABBED (request, 0 + 1);

                rc = obd_unpackmd (&sbi->ll_osc_conn, 
                                   &lic.lic_lsm, lmm, lmm_size);
                if (rc < 0) {
                        CERROR ("Error %d unpacking eadata\n", rc);
                        RETURN (rc);
                }
                LASSERT (rc >= sizeof (*lic.lic_lsm));

        } else {
                lic.lic_lsm = NULL;
        }

        llu_update_inode(*inop, body, lic.lic_lsm);

        if (llu_i2info(*inop)->lli_smd) {
                rc = llu_inode_getattr(*inop, llu_i2info(*inop)->lli_smd, NULL);
                if (rc)
                        _sysio_i_gone(*inop);
        }

out:
        ptlrpc_req_finished(request);
        OBD_FREE(pname, name->len + 1);

        return rc;
}

static int llu_iop_getattr(struct pnode *pno,
                           struct inode *ino,
                           struct intnl_stat *b)
{
        struct llu_inode_info *lli = llu_i2info(ino);

        b->st_dev = lli->lli_st_dev;
        b->st_ino = lli->lli_st_ino;
        b->st_mode = lli->lli_st_mode;
        b->st_nlink = lli->lli_st_nlink;
        b->st_uid = lli->lli_st_uid;
        b->st_gid = lli->lli_st_gid;
        b->st_rdev = lli->lli_st_rdev;
        b->st_size = lli->lli_st_size;
        b->st_blksize = lli->lli_st_blksize;
        b->st_blocks = lli->lli_st_blocks;
        b->st_atime = lli->lli_st_atime;
        b->st_mtime = lli->lli_st_mtime;
        b->st_ctime = lli->lli_st_ctime;

        return 0;
}

int llu_mdc_cancel_unused(struct lustre_handle *conn,
                          struct llu_inode_info *lli,
                          int flags)
{
        struct ldlm_res_id res_id =
                { .name = {lli->lli_st_ino, lli->lli_st_generation} };
        struct obd_device *obddev = class_conn2obd(conn);
        ENTRY;
        RETURN(ldlm_cli_cancel_unused(obddev->obd_namespace, &res_id, flags));
}

static void llu_clear_inode(struct inode *inode)
{
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct llu_inode_info *lli = llu_i2info(inode);
        int rc;
        ENTRY;

        CDEBUG(D_INODE, "clear inode: %lu\n", lli->lli_st_ino);
        rc = llu_mdc_cancel_unused(&sbi->ll_mdc_conn, lli,
                                   LDLM_FL_NO_CALLBACK);
        if (rc < 0) {
                CERROR("ll_mdc_cancel_unused: %d\n", rc);
                /* XXX FIXME do something dramatic */
        }

        if (lli->lli_smd) {
                rc = obd_cancel_unused(&sbi->ll_osc_conn, lli->lli_smd, 0);
                if (rc < 0) {
                        CERROR("obd_cancel_unused: %d\n", rc);
                        /* XXX FIXME do something dramatic */
                }
        }

        if (lli->lli_smd)
                obd_free_memmd(&sbi->ll_osc_conn, &lli->lli_smd);

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

        llu_clear_inode(inode);

        OBD_FREE(lli, sizeof(*lli));
}

static int llu_setattr_raw(struct inode *inode, struct iattr *attr)
{
        struct ptlrpc_request *request = NULL;
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct llu_inode_info *lli = llu_i2info(inode);
        struct mdc_op_data op_data;
        int err = 0;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu\n", lli->lli_st_ino);

        /* if need truncate, do it at first */
        if (attr->ia_valid & ATTR_SIZE) {
                printf("************* don't support truncate now !!!!!!!!\n");
                LBUG();
        }

        /* Don't send size changes to MDS to avoid "fast EA" problems, and
         * also avoid a pointless RPC (we get file size from OST anyways).
         */
        attr->ia_valid &= ~ATTR_SIZE;
        if (!attr->ia_valid)
                RETURN(0);

        llu_prepare_mdc_op_data(&op_data, inode, NULL, NULL, 0, 0);

        err = mdc_setattr(&sbi->ll_mdc_conn, &op_data,
                          attr, NULL, 0, &request);
        if (err)
                CERROR("mdc_setattr fails: err = %d\n", err);

        ptlrpc_req_finished(request);

        if (S_ISREG(inode->i_mode) && attr->ia_valid & ATTR_MTIME_SET) {
                struct lov_stripe_md *lsm = lli->lli_smd;
                struct obdo oa;
                int err2;

                CDEBUG(D_INODE, "set mtime on OST inode %lu to %lu\n",
                       lli->lli_st_ino, attr->ia_mtime);
                oa.o_id = lsm->lsm_object_id;
                oa.o_mode = S_IFREG;
                oa.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMTIME;
                oa.o_mtime = attr->ia_mtime;
                err2 = obd_setattr(&sbi->ll_osc_conn, &oa, lsm, NULL);
                if (err2) {
                        CERROR("obd_setattr fails: rc=%d\n", err);
                        if (!err)
                                err = err2;
                }
        }
        RETURN(err);
}

/* FIXME here we simply act as a thin layer to glue it with
 * llu_setattr_raw(), which is copy from kernel
 */
static int llu_iop_setattr(struct pnode *pno,
                           struct inode *ino,
                           unsigned mask,
                           struct intnl_stat *stbuf)
{
        struct iattr iattr;

        memset(&iattr, 0, sizeof(iattr));

        if (mask & SETATTR_MODE) {
                iattr.ia_mode = stbuf->st_mode;
                iattr.ia_valid |= ATTR_MODE;
        }
        if (mask & SETATTR_MTIME) {
                iattr.ia_mtime = stbuf->st_mtime;
                iattr.ia_valid |= ATTR_MTIME;
        }
        if (mask & SETATTR_ATIME) {
                iattr.ia_atime = stbuf->st_atime;
                iattr.ia_valid |= ATTR_ATIME;
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
                iattr.ia_size = stbuf->st_size; /* FIXME signed expansion problem */
                iattr.ia_valid |= ATTR_SIZE;
        }

        iattr.ia_valid |= ATTR_RAW;
        /* FIXME FIXME FIXME FIXME FIXME FIXME FIXME
         * without ATTR_FROM_OPEN, mds_reint_setattr will call
         * mds_fid2locked_dentry() and deadlocked at completion_ast call.
         * Here we workaround it and avoid any locking.
         * FIXME FIXME FIXME FIXME FIXME FIXME FIXME
         */
        iattr.ia_valid |= ATTR_FROM_OPEN;

        return llu_setattr_raw(ino, &iattr);
}


static int llu_mkdir2(struct inode *dir, const char *name, int len, int mode)
{
        struct ptlrpc_request *request = NULL;
        time_t curtime = CURRENT_TIME;
        struct llu_sb_info *sbi = llu_i2sbi(dir);
        struct llu_inode_info *lli = llu_i2info(dir);
        struct mdc_op_data op_data;
        int err = -EMLINK;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu\n",
               name, lli->lli_st_ino);

        /* FIXME check this later */
#if 0 
        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);
        mode = (mode & (S_IRWXUGO|S_ISVTX) & ~current->fs->umask) | S_IFDIR;
#endif
        mode |= S_IFDIR;
        llu_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
        err = mdc_create(&sbi->ll_mdc_conn, &op_data, NULL, 0, mode,
                         current->fsuid, current->fsgid,
                         curtime, 0, &request);
        ptlrpc_req_finished(request);
        RETURN(err);
}

static llu_iop_mkdir(struct pnode *pno, mode_t mode)
{
        struct inode *dir = pno->p_base->pb_parent->pb_ino;
        struct qstr *qstr = &pno->p_base->pb_name;
        int rc;

        LASSERT(dir);

        rc = llu_mkdir2(dir, qstr->name, qstr->len, mode);

        return rc;
}

struct filesys_ops llu_filesys_ops =
{
        fsop_gone: llu_fsop_gone,
};


static struct inode_ops llu_inode_ops = {
        inop_lookup:    llu_iop_lookup,
        inop_getattr:   llu_iop_getattr,
        inop_setattr:   llu_iop_setattr,
        inop_getdirentries:     NULL,
        inop_mkdir:     llu_iop_mkdir,
        inop_rmdir:     NULL,
        inop_symlink:   NULL,
        inop_readlink:  NULL,
        inop_open:      llu_iop_open,
        inop_close:     llu_iop_close,
        inop_unlink:    NULL,
        inop_ipreadv:   llu_iop_ipreadv,
        inop_ipwritev:  llu_iop_ipwritev,
        inop_iodone:    llu_iop_iodone,
        inop_fcntl:     NULL,
        inop_sync:      NULL,
        inop_datasync:  NULL,
        inop_ioctl:     NULL,
        inop_mknod:     NULL,
        inop_statvfs:   NULL,
        inop_gone:      llu_iop_gone,
};


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
        static struct qstr noname = { NULL, 0, 0 };
        struct ll_fid rootfid;

        struct llu_sb_info *sbi;
        struct ptlrpc_connection *mdc_conn;
        struct ptlrpc_request *request = NULL;
        struct mds_body *root_body;
        struct obd_uuid param_uuid;
        class_uuid_t uuid;
        struct obd_device *obd;
        char *osc=mount_option.osc_uuid;
        char *mdc=mount_option.mdc_uuid;
        int err = -EINVAL;

        ENTRY;

        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi)
                RETURN(-ENOMEM);

        INIT_LIST_HEAD(&sbi->ll_conn_chain);
        generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &sbi->ll_sb_uuid);

        fs = _sysio_fs_new(&llu_filesys_ops, flags, sbi);
        if (!fs) {
                err = -ENOMEM;
                goto out_free;
        }

        strncpy(param_uuid.uuid, mdc, sizeof(param_uuid.uuid));
        obd = class_uuid2obd(&param_uuid);
        if (!obd) {
                CERROR("MDC %s: not setup or attached\n", mdc);
                err = -EINVAL;
                goto out_free;
        }

        /* setup mdc */
        /* FIXME need recover stuff */
        err = obd_connect(&sbi->ll_mdc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                goto out_free;
        }

        mdc_conn = sbi2mdc(sbi)->cl_import->imp_connection;

        /* setup osc */
        strncpy(param_uuid.uuid, osc, sizeof(param_uuid.uuid));
        obd = class_uuid2obd(&param_uuid);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                err = -EINVAL;
                goto out_mdc;
        }

        err = obd_connect(&sbi->ll_osc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", osc, err);
                goto out_mdc;
        }

        err = mdc_getstatus(&sbi->ll_mdc_conn, &rootfid);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                goto out_osc;
        }
        CDEBUG(D_SUPER, "rootfid "LPU64"\n", rootfid.id);
        sbi->ll_rootino = rootfid.id;

/* XXX do we need this??
        memset(&osfs, 0, sizeof(osfs));
        rc = obd_statfs(&sbi->ll_mdc_conn, &osfs);
*/
        /* fetch attr of root inode */
        err = mdc_getattr(&sbi->ll_mdc_conn, &rootfid,
                          OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 0, &request);
        if (err) {
                CERROR("mdc_getattr failed for root: rc = %d\n", err);
                goto out_request;
        }

        root_body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*root_body));
        LASSERT(sbi->ll_rootino != 0);

        root = llu_new_inode(fs, root_body->ino, root_body->mode);
        if (!root) {
		err = -ENOMEM;
                goto out_request;
        }

        llu_update_inode(root, root_body, NULL);

	/*
	 * Generate base path-node for root.
	 */
	rootpb = _sysio_pb_new(&noname, NULL, root);
	if (!rootpb) {
		err = -ENOMEM;
		goto out_inode;
	}

	err = _sysio_do_mount(fs, rootpb, flags, NULL, mntp);
	if (err) {
                _sysio_pb_gone(rootpb);
		goto out_inode;
        }

        ptlrpc_req_finished(request);
        request = NULL;

        printf("************************************************\n");
        printf("*          Mount successfully!!!!!!!           *\n");
        printf("************************************************\n");

        return 0;

out_inode:
        _sysio_i_gone(root);
out_request:
        ptlrpc_req_finished(request);
out_osc:
        obd_disconnect(&sbi->ll_osc_conn);
out_mdc:
        obd_disconnect(&sbi->ll_mdc_conn);
out_free:
        OBD_FREE(sbi, sizeof(*sbi));
        return err;
}

struct fssw_ops llu_fssw_ops = {
        llu_fsswop_mount
};

