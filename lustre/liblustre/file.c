/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light file operations
 *
 *  Copyright (c) 2002-2004 Cluster File Systems, Inc.
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
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>

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

/* Pack the required supplementary groups into the supplied groups array.
 * If we don't need to use the groups from the target inode(s) then we
 * instead pack one or more groups from the user's supplementary group
 * array in case it might be useful.  Not needed if doing an MDS-side upcall. */
void ll_i2gids(__u32 *suppgids, struct inode *i1, struct inode *i2)
{
        LASSERT(i1 != NULL);
        LASSERT(suppgids != NULL);

        if (in_group_p(i1->i_stbuf.st_gid))
                suppgids[0] = i1->i_stbuf.st_gid;
        else
                suppgids[0] = -1;

        if (i2) {
                if (in_group_p(i2->i_stbuf.st_gid))
                        suppgids[1] = i2->i_stbuf.st_gid;
                else
                        suppgids[1] = -1;
        } else {
                suppgids[1] = -1;
        }
}

void llu_prep_md_op_data(struct md_op_data *op_data, struct inode *i1,
                         struct inode *i2, const char *name, int namelen,
                         int mode, __u32 opc)
{
        LASSERT(i1 != NULL || i2 != NULL);
        LASSERT(op_data);

        if (i1) {
                ll_i2gids(op_data->op_suppgids, i1, i2);
                op_data->op_fid1 = *ll_inode2fid(i1);
        }else {
                ll_i2gids(op_data->op_suppgids, i2, i1);
                op_data->op_fid1 = *ll_inode2fid(i2);
        }

        if (i2)
                op_data->op_fid2 = *ll_inode2fid(i2);
        else
                fid_zero(&op_data->op_fid2);

        op_data->op_opc = opc;
        op_data->op_name = name;
        op_data->op_mode = mode;
        op_data->op_namelen = namelen;
        op_data->op_mod_time = CURRENT_TIME;
        op_data->op_data = NULL;
}

void llu_finish_md_op_data(struct md_op_data *op_data)
{
        OBD_FREE_PTR(op_data);
}

void obdo_refresh_inode(struct inode *dst,
                        struct obdo *src,
                        obd_flag valid)
{
        struct intnl_stat *st = llu_i2stat(dst);
        valid &= src->o_valid;

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE,"valid "LPX64", cur time "CFS_TIME_T"/"CFS_TIME_T
		       ", new %lu/%lu\n",
                       src->o_valid, LTIME_S(st->st_mtime),
                       LTIME_S(st->st_ctime),
                       (long)src->o_mtime, (long)src->o_ctime);

        if (valid & OBD_MD_FLATIME && src->o_atime > LTIME_S(st->st_atime))
                LTIME_S(st->st_atime) = src->o_atime;
        
        /* mtime is always updated with ctime, but can be set in past.
           As write and utime(2) may happen within 1 second, and utime's
           mtime has a priority over write's one, leave mtime from mds 
           for the same ctimes. */
        if (valid & OBD_MD_FLCTIME && src->o_ctime > LTIME_S(st->st_ctime)) {
                LTIME_S(st->st_ctime) = src->o_ctime;
                if (valid & OBD_MD_FLMTIME)
                        LTIME_S(st->st_mtime) = src->o_mtime;
        }
        if (valid & OBD_MD_FLSIZE && src->o_size > st->st_size)
                st->st_size = src->o_size;
        /* optimum IO size */
        if (valid & OBD_MD_FLBLKSZ)
                st->st_blksize = src->o_blksize;
        /* allocation of space */
        if (valid & OBD_MD_FLBLOCKS && src->o_blocks > st->st_blocks)
                st->st_blocks = src->o_blocks;
}

int llu_local_open(struct llu_inode_info *lli, struct lookup_intent *it)
{
        struct ptlrpc_request *req = it->d.lustre.it_data;
        struct ll_file_data *fd;
        struct mdt_body *body;
        ENTRY;

        body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        /* already opened? */
        if (lli->lli_open_count++)
                RETURN(0);

        LASSERT(!lli->lli_file_data);

        OBD_ALLOC(fd, sizeof(*fd));
        /* We can't handle this well without reorganizing ll_file_open and
         * ll_md_close, so don't even try right now. */
        LASSERT(fd != NULL);

        memcpy(&fd->fd_mds_och.och_fh, &body->handle, sizeof(body->handle));
        fd->fd_mds_och.och_magic = OBD_CLIENT_HANDLE_MAGIC;
        fd->fd_mds_och.och_fid   = lli->lli_fid;
        lli->lli_file_data = fd;

        md_set_open_replay_data(lli->lli_sbi->ll_md_exp,
                                &fd->fd_mds_och, it->d.lustre.it_data);

        RETURN(0);
}

int llu_iop_open(struct pnode *pnode, int flags, mode_t mode)
{
        struct inode *inode = pnode->p_base->pb_ino;
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat *st = llu_i2stat(inode);
        struct ll_file_data *fd;
        struct ptlrpc_request *request;
        struct lookup_intent *it;
        struct lov_stripe_md *lsm;
        int rc = 0;
        ENTRY;

        liblustre_wait_event(0);

        /* don't do anything for '/' */
        if (llu_is_root_inode(inode))
                RETURN(0);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%llu\n", (long long)st->st_ino);
        LL_GET_INTENT(inode, it);

        if (!it->d.lustre.it_disposition) {
                LBUG();
        }

        rc = it_open_error(DISP_OPEN_OPEN, it);
        if (rc)
                GOTO(out_release, rc);

        rc = llu_local_open(lli, it);
        if (rc)
                LBUG();

        if (!S_ISREG(st->st_mode))
                GOTO(out_release, rc = 0);

        fd = lli->lli_file_data;

        lsm = lli->lli_smd;
        if (lsm == NULL) {
                if (fd->fd_flags & O_LOV_DELAY_CREATE) {
                        CDEBUG(D_INODE, "object creation was delayed\n");
                        GOTO(out_release, rc);
                }
        }
        fd->fd_flags &= ~O_LOV_DELAY_CREATE;

        lli->lli_open_flags = flags & ~(O_CREAT | O_EXCL | O_TRUNC);

 out_release:
        request = it->d.lustre.it_data;
        ptlrpc_req_finished(request);

        it->it_op_release(it);
        OBD_FREE(it, sizeof(*it));

        /* libsysio hasn't done anything for O_TRUNC. here we
         * simply simulate it as open(...); truncate(...); */
        if (rc == 0 && (flags & O_TRUNC) && S_ISREG(st->st_mode)) {
                struct iattr attr;

                memset(&attr, 0, sizeof(attr));
                attr.ia_size = 0;
                attr.ia_valid |= ATTR_SIZE | ATTR_RAW;
                rc = llu_setattr_raw(inode, &attr);
                if (rc)
                        CERROR("error %d truncate in open()\n", rc);
        }

        liblustre_wait_event(0);
        RETURN(rc);
}

int llu_objects_destroy(struct ptlrpc_request *req, struct inode *dir)
{
        struct mdt_body *body;
        struct lov_mds_md *eadata;
        struct lov_stripe_md *lsm = NULL;
        struct obd_trans_info oti = { 0 };
        struct obdo *oa;
        int rc;
        ENTRY;

        body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);

        if (!(body->valid & OBD_MD_FLEASIZE))
                RETURN(0);

        if (body->eadatasize == 0) {
                CERROR("OBD_MD_FLEASIZE set but eadatasize zero\n");
                GOTO(out, rc = -EPROTO);
        }

        /* The MDS sent back the EA because we unlinked the last reference
         * to this file. Use this EA to unlink the objects on the OST.
         * It's opaque so we don't swab here; we leave it to obd_unpackmd() to
         * check it is complete and sensible. */
        eadata = req_capsule_server_sized_get(&req->rq_pill, &RMF_MDT_MD,
                                              body->eadatasize);

        LASSERT(eadata != NULL);

        rc = obd_unpackmd(llu_i2obdexp(dir), &lsm, eadata,body->eadatasize);
        if (rc < 0) {
                CERROR("obd_unpackmd: %d\n", rc);
                GOTO(out, rc);
        }
        LASSERT(rc >= sizeof(*lsm));

        OBDO_ALLOC(oa);
        if (oa == NULL)
                GOTO(out_free_memmd, rc = -ENOMEM);

        oa->o_id = lsm->lsm_object_id;
        oa->o_gr = lsm->lsm_object_gr;
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLGROUP;

        if (body->valid & OBD_MD_FLCOOKIE) {
                oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies =
                        req_capsule_server_sized_get(&req->rq_pill,
                                                   &RMF_LOGCOOKIES,
                                                   sizeof(struct llog_cookie) *
                                                   lsm->lsm_stripe_count);
                if (oti.oti_logcookies == NULL) {
                        oa->o_valid &= ~OBD_MD_FLCOOKIE;
                        body->valid &= ~OBD_MD_FLCOOKIE;
                }
        }

        rc = obd_destroy(llu_i2obdexp(dir), oa, lsm, &oti, NULL);
        OBDO_FREE(oa);
        if (rc)
                CERROR("obd destroy objid 0x"LPX64" error %d\n",
                       lsm->lsm_object_id, rc);
 out_free_memmd:
        obd_free_memmd(llu_i2obdexp(dir), &lsm);
 out:
        return rc;
}

int llu_sizeonmds_update(struct inode *inode, struct md_open_data *mod,
                         struct lustre_handle *fh, __u64 ioepoch)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct md_op_data op_data = {{ 0 }};
        struct obdo oa;
        int rc;
        ENTRY;
        
        LASSERT(!(lli->lli_flags & LLIF_MDS_SIZE_LOCK));
        LASSERT(sbi->ll_lco.lco_flags & OBD_CONNECT_SOM);
        
        rc = llu_inode_getattr(inode, &oa);
        if (rc == -ENOENT) {
                oa.o_valid = 0;
                CDEBUG(D_INODE, "objid "LPX64" is already destroyed\n",
                       lli->lli_smd->lsm_object_id);
        } else if (rc) {
                CERROR("inode_getattr failed (%d): unable to send a "
                       "Size-on-MDS attribute update for inode %llu/%lu\n",
                       rc, (long long)llu_i2stat(inode)->st_ino,
                       lli->lli_st_generation);
                RETURN(rc);
        }
        
        md_from_obdo(&op_data, &oa, oa.o_valid);
        memcpy(&op_data.op_handle, fh, sizeof(*fh));
        op_data.op_ioepoch = ioepoch;
        op_data.op_flags |= MF_SOM_CHANGE;

        rc = llu_md_setattr(inode, &op_data, &mod);
        RETURN(rc);
}

int llu_md_close(struct obd_export *md_exp, struct inode *inode)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct ptlrpc_request *req = NULL;
        struct obd_client_handle *och = &fd->fd_mds_och;
        struct intnl_stat *st = llu_i2stat(inode);
        struct md_op_data op_data = { { 0 } };
        int seq_end = 0, rc;
        ENTRY;

        /* clear group lock, if present */
        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                struct lov_stripe_md *lsm = llu_i2info(inode)->lli_smd;
                fd->fd_flags &= ~(LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK);
                rc = llu_extent_unlock(fd, inode, lsm, LCK_GROUP,
                                       &fd->fd_cwlockh);
        }

        op_data.op_attr.ia_valid = ATTR_MODE | ATTR_ATIME_SET |
                                ATTR_MTIME_SET | ATTR_CTIME_SET;
        
        if (fd->fd_flags & FMODE_WRITE) {
                struct llu_sb_info *sbi = llu_i2sbi(inode);
                if (!(sbi->ll_lco.lco_flags & OBD_CONNECT_SOM) ||
                    !S_ISREG(llu_i2stat(inode)->st_mode)) {
                        op_data.op_attr.ia_valid |= ATTR_SIZE | ATTR_BLOCKS;
                } else {
                        /* Inode cannot be dirty. Close the epoch. */
                        op_data.op_flags |= MF_EPOCH_CLOSE;
                        /* XXX: Send CHANGE flag only if Size-on-MDS inode attributes
                         * are really changed.  */
                        op_data.op_flags |= MF_SOM_CHANGE;

                        /* Pack Size-on-MDS attributes if we are in IO epoch and 
                         * attributes are valid. */
                        LASSERT(!(lli->lli_flags & LLIF_MDS_SIZE_LOCK));
                        if (!llu_local_size(inode))
                                op_data.op_attr.ia_valid |= 
                                        OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
                }
        }
        op_data.op_fid1 = lli->lli_fid;
        op_data.op_attr.ia_atime = st->st_atime;
        op_data.op_attr.ia_mtime = st->st_mtime;
        op_data.op_attr.ia_ctime = st->st_ctime;
        op_data.op_attr.ia_size = st->st_size;
        op_data.op_attr_blocks = st->st_blocks;
        op_data.op_attr.ia_attr_flags = lli->lli_st_flags;
        op_data.op_ioepoch = lli->lli_ioepoch;
        memcpy(&op_data.op_handle, &och->och_fh, sizeof(op_data.op_handle));

        rc = md_close(md_exp, &op_data, och->och_mod, &req);
        if (rc != -EAGAIN)
                seq_end = 1;

        if (rc == -EAGAIN) {
                /* We are the last writer, so the MDS has instructed us to get
                 * the file size and any write cookies, then close again. */
                LASSERT(fd->fd_flags & FMODE_WRITE);
                rc = llu_sizeonmds_update(inode, och->och_mod, &och->och_fh,
                                          op_data.op_ioepoch);
                if (rc) {
                        CERROR("inode %llu mdc Size-on-MDS update failed: "
                               "rc = %d\n", (long long)st->st_ino, rc);
                        rc = 0;
                }
        } else if (rc) {
                CERROR("inode %llu close failed: rc %d\n",
                       (long long)st->st_ino, rc);
        } else {
                rc = llu_objects_destroy(req, inode);
                if (rc)
                        CERROR("inode %llu ll_objects destroy: rc = %d\n",
                               (long long)st->st_ino, rc);
        }

        if (seq_end)
                ptlrpc_close_replay_seq(req);
        md_clear_open_replay_data(md_exp, och);
        ptlrpc_req_finished(req);
        och->och_fh.cookie = DEAD_HANDLE_MAGIC;
        lli->lli_file_data = NULL;
        OBD_FREE(fd, sizeof(*fd));

        RETURN(rc);
}

int llu_file_release(struct inode *inode)
{
        struct ll_file_data *fd;
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct llu_inode_info *lli = llu_i2info(inode);
        int rc = 0, rc2;

        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%llu/%lu\n",
               (long long)llu_i2stat(inode)->st_ino, lli->lli_st_generation);

        if (llu_is_root_inode(inode))
                RETURN(0);

        /* still opened by others? */
        if (--lli->lli_open_count)
                RETURN(0);

        fd = lli->lli_file_data;
        if (!fd) /* no process opened the file after an mcreate */
                RETURN(0);

        rc2 = llu_md_close(sbi->ll_md_exp, inode);
        if (rc2 && !rc)
                rc = rc2;

        RETURN(rc);
}

/*
 * libsysio require us return 0
 */
int llu_iop_close(struct inode *inode)
{
        int rc;

        liblustre_wait_event(0);

        rc = llu_file_release(inode);
        if (rc) {
                CERROR("file close error %d\n", rc);
        }
        /* if open count == 0 && stale_flag is set, should we
         * remove the inode immediately? */
        liblustre_wait_idle();
        return 0;
}

_SYSIO_OFF_T llu_iop_pos(struct inode *ino, _SYSIO_OFF_T off)
{
        ENTRY;

        liblustre_wait_event(0);

        if (off < 0 || off > ll_file_maxbytes(ino))
                RETURN(-EINVAL);

        RETURN(off);
}

/* this isn't where truncate starts.  roughly:
 * llu_iop_{open,setattr}->llu_setattr_raw->llu_vmtruncate->llu_truncate
 * we grab the lock back in setattr_raw to avoid races. */
static void llu_truncate(struct inode *inode, obd_flag flags)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat *st = llu_i2stat(inode);
        struct obd_info oinfo = { { { 0 } } };
        struct obdo oa = { 0 };
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%llu/%lu(%p) to %llu\n",
               (long long)st->st_ino, lli->lli_st_generation, inode,
               (long long)st->st_size);

        if (!lli->lli_smd) {
                CDEBUG(D_INODE, "truncate on inode %llu with no objects\n",
                       (long long)st->st_ino);
                EXIT;
                return;
        }

        oinfo.oi_md = lli->lli_smd;
        oinfo.oi_policy.l_extent.start = st->st_size;
        oinfo.oi_policy.l_extent.end = OBD_OBJECT_EOF;
        oinfo.oi_oa = &oa;
        oa.o_id = lli->lli_smd->lsm_object_id;
        oa.o_valid = OBD_MD_FLID | OBD_MD_FLFLAGS;
        oa.o_flags = flags; /* We don't actually want to copy inode flags */
 
        obdo_from_inode(&oa, inode,
                        OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLATIME |
                        OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        obd_adjust_kms(llu_i2obdexp(inode), lli->lli_smd, st->st_size, 1);

        CDEBUG(D_INFO, "calling punch for "LPX64" (all bytes after %Lu)\n",
               oa.o_id, (long long)st->st_size);

        /* truncate == punch from new size to absolute end of file */
        rc = obd_punch_rqset(llu_i2obdexp(inode), &oinfo, NULL);
        if (rc)
                CERROR("obd_truncate fails (%d) ino %llu\n",
                       rc, (long long)st->st_ino);
        else
                obdo_to_inode(inode, &oa, OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                          OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                          OBD_MD_FLCTIME);

        EXIT;
        return;
} /* llu_truncate */

int llu_vmtruncate(struct inode * inode, loff_t offset, obd_flag flags)
{
        llu_i2stat(inode)->st_size = offset;

        /*
         * llu_truncate() is only called from this
         * point. llu_vmtruncate/llu_truncate split exists to mimic the
         * structure of Linux VFS truncate code path.
         */

        llu_truncate(inode, flags);

        return 0;
}
