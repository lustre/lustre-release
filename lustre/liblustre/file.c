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

void llu_prepare_mdc_op_data(struct mdc_op_data *data,
                             struct inode *i1,
                             struct inode *i2,
                             const char *name,
                             int namelen,
                             int mode)
{
        struct llu_inode_info *lli1, *lli2;

        LASSERT(i1);

        lli1 = llu_i2info(i1);
        data->ino1 = lli1->lli_st_ino;
        data->gen1 = lli1->lli_st_generation;
        data->typ1 = lli1->lli_st_mode & S_IFMT;
        data->gid1 = lli1->lli_st_gid;

        if (i2) {
                lli2 = llu_i2info(i2);
                data->ino2 = lli2->lli_st_ino;
                data->gen2 = lli2->lli_st_generation;
                data->typ2 = lli2->lli_st_mode & S_IFMT;
                data->gid2 = lli2->lli_st_gid;
        } else
                data->ino2 = 0;

        data->name = name;
        data->namelen = namelen;
        data->mode = mode;
}

static struct inode *llu_create_node(struct inode *dir, const char *name,
                                     int namelen, const void *data, int datalen,
                                     int mode, __u64 extra,
                                     struct lookup_intent *it)
{
        struct inode *inode;
        struct ptlrpc_request *request = NULL;
        struct mds_body *body;
        time_t time = 123456;//time(NULL);
        struct llu_sb_info *sbi = llu_i2sbi(dir);

        if (it && it->it_disposition) {
                LBUG();
#if 0
                ll_invalidate_inode_pages(dir);
#endif
                request = it->it_data;
                body = lustre_msg_buf(request->rq_repmsg, 1, sizeof(*body));
        } else {
                struct mdc_op_data op_data;
                struct llu_inode_info *lli_dir = llu_i2info(dir);
                int gid = current->fsgid;
                int rc;

                if (lli_dir->lli_st_mode & S_ISGID) {
                        gid = lli_dir->lli_st_gid;
                        if (S_ISDIR(mode))
                                mode |= S_ISGID;
                }

                llu_prepare_mdc_op_data(&op_data, dir, NULL, name, namelen, 0);
                rc = mdc_create(&sbi->ll_mdc_conn, &op_data,
                                data, datalen, mode, current->fsuid, gid,
                                time, extra, &request);
                if (rc) {
                        inode = (struct inode*)rc;
                        goto out;
                }
                body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*body));
        }

        inode = llu_new_inode(dir->i_fs, body->ino, body->mode);
        if (!inode) {
                /* FIXME more cleanup needed? */
                goto out;
        }

        llu_update_inode(inode, body, NULL);

        if (it && it->it_disposition) {
                /* We asked for a lock on the directory, but were
                 * granted a lock on the inode.  Since we finally have
                 * an inode pointer, stuff it in the lock. */
#if 0
                ll_mdc_lock_set_inode((struct lustre_handle *)it->it_lock_handle,
                                      inode);
#endif
        }

 out:
        ptlrpc_req_finished(request);
        return inode;
}

int llu_create(struct inode *dir, struct pnode_base *pnode, int mode)
{
        struct inode *inode;
#if 0
        int rc = 0;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu,intent=%s\n",
               dentry->d_name.name, dir->i_ino, LL_IT2STR(dentry->d_it));

        it = dentry->d_it;

        rc = ll_it_open_error(IT_OPEN_CREATE, it);
        if (rc) {
                LL_GET_INTENT(dentry, it);
                ptlrpc_req_finished(it->it_data);
                RETURN(rc);
        }
#endif
        inode = llu_create_node(dir, pnode->pb_name.name, pnode->pb_name.len,
                                NULL, 0, mode, 0, NULL);

        if (IS_ERR(inode))
                RETURN(PTR_ERR(inode));

        pnode->pb_ino = inode;

        return 0;
}

static int llu_create_obj(struct lustre_handle *conn, struct inode *inode,
                          struct lov_stripe_md *lsm)
{
        struct ptlrpc_request *req = NULL;
        struct llu_inode_info *lli = llu_i2info(inode);
        struct lov_mds_md *lmm = NULL;
        struct obdo *oa;
        struct iattr iattr;
        struct mdc_op_data op_data;
        int rc, err, lmm_size = 0;;
        ENTRY;

        oa = obdo_alloc();
        if (!oa)
                RETURN(-ENOMEM);

        oa->o_mode = S_IFREG | 0600;
        oa->o_id = lli->lli_st_ino;
        /* Keep these 0 for now, because chown/chgrp does not change the
         * ownership on the OST, and we don't want to allow BA OST NFS
         * users to access these objects by mistake.
         */
        oa->o_uid = 0;
        oa->o_gid = 0;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMODE |
                OBD_MD_FLUID | OBD_MD_FLGID;

        rc = obd_create(conn, oa, &lsm, NULL);
        if (rc) {
                CERROR("error creating objects for inode %lu: rc = %d\n",
                       lli->lli_st_ino, rc);
                if (rc > 0) {
                        CERROR("obd_create returned invalid rc %d\n", rc);
                        rc = -EIO;
                }
                GOTO(out_oa, rc);
        }

        LASSERT(lsm && lsm->lsm_object_id);
        rc = obd_packmd(conn, &lmm, lsm);
        if (rc < 0)
                GOTO(out_destroy, rc);

        lmm_size = rc;

        /* Save the stripe MD with this file on the MDS */
        memset(&iattr, 0, sizeof(iattr));
        iattr.ia_valid = ATTR_FROM_OPEN;

        llu_prepare_mdc_op_data(&op_data, inode, NULL, NULL, 0, 0);

        rc = mdc_setattr(&llu_i2sbi(inode)->ll_mdc_conn, &op_data,
                         &iattr, lmm, lmm_size, &req);
        ptlrpc_req_finished(req);

        obd_free_diskmd(conn, &lmm);

        /* If we couldn't complete mdc_open() and store the stripe MD on the
         * MDS, we need to destroy the objects now or they will be leaked.
         */
        if (rc) {
                CERROR("error: storing stripe MD for %lu: rc %d\n",
                       lli->lli_st_ino, rc);
                GOTO(out_destroy, rc);
        }
        lli->lli_smd = lsm;

        EXIT;
out_oa:
        obdo_free(oa);
        return rc;

out_destroy:
        obdo_from_inode(oa, inode, OBD_MD_FLTYPE);
        oa->o_id = lsm->lsm_object_id;
        oa->o_valid |= OBD_MD_FLID;
        err = obd_destroy(conn, oa, lsm, NULL);
        obd_free_memmd(conn, &lsm);
        if (err) {
                CERROR("error uncreating inode %lu objects: rc %d\n",
                       lli->lli_st_ino, err);
        }
        goto out_oa;
}

/* FIXME currently no "it" passed in */
static int llu_local_open(struct llu_inode_info *lli, struct lookup_intent *it)
{
        struct ll_file_data *fd;
#if 0
        struct ptlrpc_request *req = it->it_data;
        struct mds_body *body = lustre_msg_buf(req->rq_repmsg, 1);
        ENTRY;
#endif
        LASSERT(!lli->lli_file_data);

        fd = malloc(sizeof(struct ll_file_data));
        /* We can't handle this well without reorganizing ll_file_open and
         * ll_mdc_close, so don't even try right now. */
        LASSERT(fd != NULL);

        memset(fd, 0, sizeof(*fd));
#if 0
        memcpy(&fd->fd_mds_och.och_fh, &body->handle, sizeof(body->handle));
        fd->fd_mds_och.och_req = it->it_data;
#endif
        lli->lli_file_data = fd;

        RETURN(0);
}

static int llu_osc_open(struct lustre_handle *conn, struct inode *inode,
                        struct lov_stripe_md *lsm)
{
        struct ll_file_data *fd = llu_i2info(inode)->lli_file_data;
        struct obdo *oa;
        int rc;
        ENTRY;

        oa = obdo_alloc();
        if (!oa)
                RETURN(-ENOMEM);
        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = S_IFREG;
        oa->o_valid = (OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLBLOCKS |
                       OBD_MD_FLMTIME | OBD_MD_FLCTIME);
        rc = obd_open(conn, oa, lsm, NULL, &fd->fd_ost_och);
        if (rc)
                GOTO(out, rc);

//        file->f_flags &= ~O_LOV_DELAY_CREATE;
        obdo_to_inode(inode, oa, OBD_MD_FLBLOCKS | OBD_MD_FLMTIME |
                      OBD_MD_FLCTIME);

        EXIT;
out:
        obdo_free(oa);
        return rc;
}

static int llu_file_open(struct inode *inode)
{
#if 0
        struct llu_sb_info *sbi = llu_i2sbi(inode);
#endif
        struct llu_inode_info *lli = llu_i2info(inode);
        struct lustre_handle *conn = llu_i2obdconn(inode);
        struct lookup_intent *it;
        struct lov_stripe_md *lsm;
        int rc = 0;

#if 0
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu\n", inode->i_ino);
        LL_GET_INTENT(file->f_dentry, it);
        rc = ll_it_open_error(IT_OPEN_OPEN, it);
        if (rc)
                RETURN(rc);
#endif
        rc = llu_local_open(lli, it);
        if (rc)
                LBUG();
#if 0
        mdc_set_open_replay_data(&((struct ll_file_data *)
				  file->private_data)->fd_mds_och);
#endif
        lsm = lli->lli_smd;
        if (lsm == NULL) {
#if 0
                if (file->f_flags & O_LOV_DELAY_CREATE) {
                        CDEBUG(D_INODE, "delaying object creation\n");
                        RETURN(0);
                }
#endif
                if (!lli->lli_smd) {
                        rc = llu_create_obj(conn, inode, NULL);
                        if (rc)
                                GOTO(out_close, rc);
                } else {
                        CERROR("warning: stripe already set on ino %lu\n",
                               lli->lli_st_ino);
                }
                lsm = lli->lli_smd;
        }

        rc = llu_osc_open(conn, inode, lsm);
        if (rc)
                GOTO(out_close, rc);
        RETURN(0);

 out_close:
//        ll_mdc_close(&sbi->ll_mdc_conn, inode, file);
        return rc;
}

int llu_iop_open(struct pnode *pnode, int flags, mode_t mode)
{
        struct inode *dir = pnode->p_parent->p_base->pb_ino;
        int rc;
        /* FIXME later we must add the ldlm here */

        LASSERT(dir);

        /* libsysio forgot to guarentee mode is valid XXX */
        mode |= S_IFREG;

        if (!pnode->p_base->pb_ino) {
                rc = llu_create(dir, pnode->p_base, mode);
                if (rc)
                        return rc;
        }

        LASSERT(pnode->p_base->pb_ino);
        return llu_file_open(pnode->p_base->pb_ino);
}


static int llu_mdc_close(struct lustre_handle *mdc_conn, struct inode *inode)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct ptlrpc_request *req = NULL;
        unsigned long flags;
        struct obd_import *imp;
        int rc;

        /* FIXME add following code later FIXME */
#if 0
        /* Complete the open request and remove it from replay list */
        rc = mdc_close(&ll_i2sbi(inode)->ll_mdc_conn, lli->lli_st_ino,
                       inode->i_mode, &fd->fd_mds_och.och_fh, &req);
        if (rc)
                CERROR("inode %lu close failed: rc = %d\n",
                                lli->lli_st_ino, rc);

        imp = fd->fd_mds_och.och_req->rq_import;
        LASSERT(imp != NULL);
        spin_lock_irqsave(&imp->imp_lock, flags);

        DEBUG_REQ(D_HA, fd->fd_mds_och.och_req, "matched open req %p", 
		  fd->fd_mds_och.och_req);

        /* We held on to the request for replay until we saw a close for that
         * file.  Now that we've closed it, it gets replayed on the basis of
         * its transno only. */
        spin_lock (&fd->fd_mds_och.och_req->rq_lock);
        fd->fd_mds_och.och_req->rq_replay = 0;
        spin_unlock (&fd->fd_mds_och.och_req->rq_lock);

        if (fd->fd_mds_och.och_req->rq_transno) {
                /* This open created a file, so it needs replay as a
                 * normal transaction now.  Our reference to it now
                 * effectively owned by the imp_replay_list, and it'll
                 * be committed just like other transno-having
                 * requests from here on out. */

                /* We now retain this close request, so that it is
                 * replayed if the open is replayed.  We duplicate the
                 * transno, so that we get freed at the right time,
                 * and rely on the difference in xid to keep
                 * everything ordered correctly.
                 *
                 * But! If this close was already given a transno
                 * (because it caused real unlinking of an
                 * open-unlinked file, f.e.), then we'll be ordered on
                 * the basis of that and we don't need to do anything
                 * magical here. */
                if (!req->rq_transno) {
                        req->rq_transno = fd->fd_mds_och.och_req->rq_transno;
                        ptlrpc_retain_replayable_request(req, imp);
                }
                spin_unlock_irqrestore(&imp->imp_lock, flags);

                /* Should we free_committed now? we always free before
                 * replay, so it's probably a wash.  We could check to
                 * see if the fd_req should already be committed, in
                 * which case we can avoid the whole retain_replayable
                 * dance. */
        } else {
                /* No transno means that we can just drop our ref. */
                spin_unlock_irqrestore(&imp->imp_lock, flags);
        }
        ptlrpc_req_finished(fd->fd_mds_och.och_req);

        /* Do this after the fd_req->rq_transno check, because we don't want
         * to bounce off zero references. */
        ptlrpc_req_finished(req);
        fd->fd_mds_och.och_fh.cookie = DEAD_HANDLE_MAGIC;
#endif
        lli->lli_file_data = NULL;
        free(fd);

        RETURN(-abs(rc));
}

static int llu_file_release(struct inode *inode)
{
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct llu_inode_info *lli = llu_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ll_file_data *fd;
        struct obdo oa;
        int rc = 0, rc2;

        fd = lli->lli_file_data;
        if (!fd) /* no process opened the file after an mcreate */
                RETURN(rc = 0);

        /* we might not be able to get a valid handle on this file
         * again so we really want to flush our write cache.. */
        if (S_ISREG(inode->i_mode) && lsm) {
                memset(&oa, 0, sizeof(oa));
                oa.o_id = lsm->lsm_object_id;
                oa.o_mode = S_IFREG;
                oa.o_valid = OBD_MD_FLTYPE | OBD_MD_FLID;
                
                memcpy(&oa.o_inline, &fd->fd_ost_och, FD_OSTDATA_SIZE);
                oa.o_valid |= OBD_MD_FLHANDLE;

                rc = obd_close(&sbi->ll_osc_conn, &oa, lsm, NULL);
                if (rc)
                        CERROR("inode %lu object close failed: rc = "
                               "%d\n", lli->lli_st_ino, rc);
	}

        rc2 = llu_mdc_close(&sbi->ll_mdc_conn, inode);
        if (rc2 && !rc)
                rc = rc2;

        RETURN(rc);
}

int llu_iop_close(struct inode *inode)
{
        return llu_file_release(inode);
}

int llu_iop_ipreadv(struct inode *ino,
                    struct io_arguments *ioargs,
                    struct ioctx **ioctxp)
{
        struct ioctx *ioctx;

        if (!ioargs->ioarg_iovlen)
                return 0;
        if (ioargs->ioarg_iovlen < 0)
                return -EINVAL;

        ioctx = _sysio_ioctx_new(ino, ioargs);
        if (!ioctx)
                return -ENOMEM;

        ioctx->ioctx_cc = llu_file_read(ino,
                                        ioctx->ioctx_iovec,
                                        ioctx->ioctx_iovlen,
                                        ioctx->ioctx_offset);
        if (ioctx->ioctx_cc < 0)
                ioctx->ioctx_errno = ioctx->ioctx_cc;

        *ioctxp = ioctx;
        return 0;
}

int llu_iop_ipwritev(struct inode *ino,
                     struct io_arguments *ioargs,
                     struct ioctx **ioctxp)
{
        struct ioctx *ioctx;

        if (!ioargs->ioarg_iovlen)
                return 0;
        if (ioargs->ioarg_iovlen < 0)
                return -EINVAL;

        ioctx = _sysio_ioctx_new(ino, ioargs);
        if (!ioctx)
                return -ENOMEM;

        ioctx->ioctx_cc = llu_file_write(ino,
                                         ioctx->ioctx_iovec,
                                         ioctx->ioctx_iovlen,
                                         ioctx->ioctx_offset);
        if (ioctx->ioctx_cc < 0)
                ioctx->ioctx_errno = ioctx->ioctx_cc;

        *ioctxp = ioctx;
        return 0;
}

