/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light file operations
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
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <sysio.h>
#include <fs.h>
#include <mount.h>
#include <inode.h>
#include <file.h>

#undef LIST_HEAD

#include "llite_lib.h"

void llu_prepare_mdc_op_data(struct mdc_op_data *data,
                             struct inode *i1,
                             struct inode *i2,
                             const char *name,
                             int namelen,
                             int mode)
{
        LASSERT(i1);
        
        ll_i2uctxt(&data->ctxt, i1, i2);
        ll_inode2fid(&data->fid1, i1);

        if (i2) {
                ll_inode2fid(&data->fid2, i2);
        }

        data->name = name;
        data->namelen = namelen;
        data->create_mode = mode;
        data->mod_time = CURRENT_TIME;
}

void obdo_refresh_inode(struct inode *dst,
                        struct obdo *src,
                        obd_flag valid)
{
        struct llu_inode_info *lli = llu_i2info(dst);
        valid &= src->o_valid;

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE, "valid %x, cur time %lu/%lu, new %lu/%lu\n",
                       src->o_valid, LTIME_S(lli->lli_st_mtime), 
                       LTIME_S(lli->lli_st_ctime),
                       (long)src->o_mtime, (long)src->o_ctime);

        if (valid & OBD_MD_FLATIME && src->o_atime > LTIME_S(lli->lli_st_atime))
                LTIME_S(lli->lli_st_atime) = src->o_atime;
        if (valid & OBD_MD_FLMTIME && src->o_mtime > LTIME_S(lli->lli_st_mtime))
                LTIME_S(lli->lli_st_mtime) = src->o_mtime;
        if (valid & OBD_MD_FLCTIME && src->o_ctime > LTIME_S(lli->lli_st_ctime))
                LTIME_S(lli->lli_st_ctime) = src->o_ctime;
        if (valid & OBD_MD_FLSIZE && src->o_size > lli->lli_st_size)
                lli->lli_st_size = src->o_size;
        /* optimum IO size */
        if (valid & OBD_MD_FLBLKSZ)
                lli->lli_st_blksize = src->o_blksize;
        /* allocation of space */
        if (valid & OBD_MD_FLBLOCKS && src->o_blocks > lli->lli_st_blocks)
                lli->lli_st_blocks = src->o_blocks;
}

static int llu_local_open(struct llu_inode_info *lli, struct lookup_intent *it)
{
        struct ptlrpc_request *req = it->d.lustre.it_data;
        struct ll_file_data *fd;
        struct mds_body *body;
        ENTRY;

        body = lustre_msg_buf (req->rq_repmsg, 1, sizeof (*body));
        LASSERT (body != NULL);                 /* reply already checked out */
        LASSERT_REPSWABBED (req, 1);            /* and swabbed down */

        /* already opened? */
        if (lli->lli_open_count++)
                RETURN(0);
                
        LASSERT(!lli->lli_file_data);

        OBD_ALLOC(fd, sizeof(*fd));
        /* We can't handle this well without reorganizing ll_file_open and
         * ll_mdc_close, so don't even try right now. */
        LASSERT(fd != NULL);

        memcpy(&fd->fd_mds_och.och_fh, &body->handle, sizeof(body->handle));
        fd->fd_mds_och.och_magic = OBD_CLIENT_HANDLE_MAGIC;
        lli->lli_file_data = fd;

        mdc_set_open_replay_data(&fd->fd_mds_och, it->d.lustre.it_data);

        RETURN(0);
}

int llu_iop_open(struct pnode *pnode, int flags, mode_t mode)
{
        struct inode *inode = pnode->p_base->pb_ino;
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd;
        struct ptlrpc_request *request;
        struct lookup_intent *it;
        struct lov_stripe_md *lsm;
        int rc = 0;
        ENTRY;

        /* don't do anything for '/' */
        if (llu_is_root_inode(inode))
                RETURN(0);

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu\n", lli->lli_st_ino);
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

        if (!S_ISREG(lli->lli_st_mode))
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

        lli->lli_open_flags = flags;

 out_release:
        request = it->d.lustre.it_data;
        ptlrpc_req_finished(request);

        it->it_op_release(it);
        OBD_FREE(it, sizeof(*it));

        RETURN(rc);
}

int llu_objects_destroy(struct ptlrpc_request *request, struct inode *dir)
{
        struct mds_body *body;
        struct lov_mds_md *eadata;
        struct lov_stripe_md *lsm = NULL;
        struct obd_trans_info oti = { 0 };
        struct obdo *oa;
        int rc;
        ENTRY;

        /* req is swabbed so this is safe */
        body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*body));

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
        eadata = lustre_swab_repbuf(request, 1, body->eadatasize, NULL);
        LASSERT(eadata != NULL);
        if (eadata == NULL) {
                CERROR("Can't unpack MDS EA data\n");
                GOTO(out, rc = -EPROTO);
        }

        rc = obd_unpackmd(llu_i2obdexp(dir), &lsm, eadata, body->eadatasize);
        if (rc < 0) {
                CERROR("obd_unpackmd: %d\n", rc);
                GOTO(out, rc);
        }
        LASSERT(rc >= sizeof(*lsm));

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out_free_memmd, rc = -ENOMEM);

        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE;

        if (body->valid & OBD_MD_FLCOOKIE) {
                oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies =
                        lustre_msg_buf(request->rq_repmsg, 2,
                                       sizeof(struct llog_cookie) *
                                       lsm->lsm_stripe_count);
                if (oti.oti_logcookies == NULL) {
                        oa->o_valid &= ~OBD_MD_FLCOOKIE;
                        body->valid &= ~OBD_MD_FLCOOKIE;
                }
        }

        rc = obd_destroy(llu_i2obdexp(dir), oa, lsm, &oti);
        obdo_free(oa);
        if (rc)
                CERROR("obd destroy objid 0x"LPX64" error %d\n",
                       lsm->lsm_object_id, rc);
 out_free_memmd:
        obd_free_memmd(llu_i2obdexp(dir), &lsm);
 out:
        return rc;
}

int llu_mdc_close(struct obd_export *mdc_exp, struct inode *inode)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct ptlrpc_request *req = NULL;
        struct obd_client_handle *och = &fd->fd_mds_och;
        struct obdo obdo;
        int rc, valid;
        ENTRY;

        /* clear group lock, if present */
        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                struct lov_stripe_md *lsm = llu_i2info(inode)->lli_smd;
                fd->fd_flags &= ~(LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK);
                rc = llu_extent_unlock(fd, inode, lsm, LCK_GROUP,
                                       &fd->fd_cwlockh);
        }

        valid = OBD_MD_FLID;
        if (test_bit(LLI_F_HAVE_OST_SIZE_LOCK, &lli->lli_flags))
                valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;

        memset(&obdo, 0, sizeof(obdo));
        obdo.o_id = lli->lli_st_ino;
        obdo.o_mode = lli->lli_st_mode;
        obdo.o_size = lli->lli_st_size;
        obdo.o_blocks = lli->lli_st_blocks;
        if (0 /* ll_is_inode_dirty(inode) */) {
                obdo.o_flags = MDS_BFLAG_UNCOMMITTED_WRITES;
                valid |= OBD_MD_FLFLAGS;
        }
        obdo.o_valid = valid;
        rc = mdc_close(mdc_exp, &obdo, och, &req);
        if (rc == EAGAIN) {
                /* We are the last writer, so the MDS has instructed us to get
                 * the file size and any write cookies, then close again. */
                //ll_queue_done_writing(inode);
                rc = 0;
        } else if (rc) {
                CERROR("inode %lu close failed: rc = %d\n", lli->lli_st_ino, rc);
        } else {
                rc = llu_objects_destroy(req, inode);
                if (rc)
                        CERROR("inode %lu ll_objects destroy: rc = %d\n",
                                lli->lli_st_ino, rc);
        }

        mdc_clear_open_replay_data(och);
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
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%lu\n", lli->lli_st_ino,
               lli->lli_st_generation);

        if (llu_is_root_inode(inode))
                RETURN(0);

        /* still opened by others? */
        if (--lli->lli_open_count)
                RETURN(0);

        fd = lli->lli_file_data;
        if (!fd) /* no process opened the file after an mcreate */
                RETURN(0);

        rc2 = llu_mdc_close(sbi->ll_mdc_exp, inode);
        if (rc2 && !rc)
                rc = rc2;

        RETURN(rc);
}

int llu_iop_close(struct inode *inode)
{
        int rc;

        rc = llu_file_release(inode);
        /* if open count == 0 && stale_flag is set, should we
         * remove the inode immediately? */
        return rc;
}

int llu_iop_ipreadv(struct inode *ino,
                    struct ioctx *ioctx)
{
        ENTRY;

        if (!ioctx->ioctx_iovlen)
                RETURN(0);
        if (ioctx->ioctx_iovlen < 0)
                RETURN(-EINVAL);

        ioctx->ioctx_private = llu_file_read(ino,
                                        ioctx->ioctx_iovec,
                                        ioctx->ioctx_iovlen,
                                        ioctx->ioctx_offset);
        if (IS_ERR(ioctx->ioctx_private))
                return (PTR_ERR(ioctx->ioctx_private));

        RETURN(0);
}

int llu_iop_ipwritev(struct inode *ino,
                     struct ioctx *ioctx)
{
        ENTRY;

        if (!ioctx->ioctx_iovlen)
                RETURN(0);
        if (ioctx->ioctx_iovlen < 0)
                RETURN(-EINVAL);

        ioctx->ioctx_private = llu_file_write(ino,
                                         ioctx->ioctx_iovec,
                                         ioctx->ioctx_iovlen,
                                         ioctx->ioctx_offset);
        if (IS_ERR(ioctx->ioctx_private))
                return (PTR_ERR(ioctx->ioctx_private));

        RETURN(0);
}

/* this isn't where truncate starts.   roughly:
 * sys_truncate->ll_setattr_raw->vmtruncate->ll_truncate
 * we grab the lock back in setattr_raw to avoid races. */
static void llu_truncate(struct inode *inode)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obdo oa = {0};
        int err;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%lu\n", lli->lli_st_ino,
               lli->lli_st_generation);

        if (!lsm) {
                CERROR("truncate on inode %lu with no objects\n", lli->lli_st_ino);
                EXIT;
                return;
        }

        oa.o_id = lsm->lsm_object_id;
        oa.o_valid = OBD_MD_FLID;
        obdo_from_inode(&oa, inode, OBD_MD_FLTYPE|OBD_MD_FLMODE|OBD_MD_FLATIME|
                                    OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        CDEBUG(D_INFO, "calling punch for "LPX64" (all bytes after %Lu)\n",
               oa.o_id, lli->lli_st_size);

        /* truncate == punch from new size to absolute end of file */
        err = obd_punch(llu_i2obdexp(inode), &oa, lsm, lli->lli_st_size,
                        OBD_OBJECT_EOF, NULL);
        if (err)
                CERROR("obd_truncate fails (%d) ino %lu\n", err, lli->lli_st_ino);
        else
                obdo_to_inode(inode, &oa, OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                          OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                          OBD_MD_FLCTIME);

        EXIT;
        return;
}

int llu_vmtruncate(struct inode * inode, loff_t offset)
{
        struct llu_inode_info *lli = llu_i2info(inode);

        lli->lli_st_size = offset;

        llu_truncate(inode);

        return 0;
}
