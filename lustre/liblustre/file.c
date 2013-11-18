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
 * lustre/liblustre/file.c
 *
 * Lustre Light file operations
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
        op_data->op_mod_time = CFS_CURRENT_TIME;
        op_data->op_data = NULL;
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
        if (valid & OBD_MD_FLMTIME && src->o_mtime > LTIME_S(st->st_mtime))
                LTIME_S(st->st_mtime) = src->o_mtime;
        if (valid & OBD_MD_FLCTIME && src->o_ctime > LTIME_S(st->st_ctime))
                LTIME_S(st->st_ctime) = src->o_ctime;
        if (valid & OBD_MD_FLSIZE && src->o_size > st->st_size)
                st->st_size = src->o_size;
        /* optimum IO size */
        if (valid & OBD_MD_FLBLKSZ)
                st->st_blksize = src->o_blksize;
        /* allocation of space */
        if (valid & OBD_MD_FLBLOCKS && src->o_blocks > st->st_blocks)
                st->st_blocks = src->o_blocks;
}

/**
 * Assign an obtained @ioepoch to client's inode. No lock is needed, MDS does
 * not believe attributes if a few ioepoch holders exist. Attributes for
 * previous ioepoch if new one is opened are also skipped by MDS.
 */
void llu_ioepoch_open(struct llu_inode_info *lli, __u64 ioepoch)
{
        if (ioepoch && lli->lli_ioepoch != ioepoch) {
                lli->lli_ioepoch = ioepoch;
                CDEBUG(D_INODE, "Epoch "LPU64" opened on "DFID" for truncate\n",
                       ioepoch, PFID(&lli->lli_fid));
        }
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
        llu_ioepoch_open(lli, body->ioepoch);
	md_set_open_replay_data(lli->lli_sbi->ll_md_exp, &fd->fd_mds_och, it);

        RETURN(0);
}

int llu_iop_open(struct pnode *pnode, int flags, mode_t mode)
{
        struct inode *inode = pnode->p_base->pb_ino;
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat *st = llu_i2stat(inode);
        struct ptlrpc_request *request;
        struct lookup_intent *it;
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

	if (lli->lli_has_smd && cl_is_lov_delay_create(flags)) {
		/* a bit ugly, but better than changing the open() API */
		unsigned int tmp_flags = flags;

		cl_lov_delay_create_clear(&tmp_flags);
		flags = tmp_flags;
	}
	/*XXX: open_flags are overwritten and the previous ones are lost */
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

	oa->o_oi = lsm->lsm_oi;
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLGROUP;
        obdo_set_parent_fid(oa, &llu_i2info(dir)->lli_fid);
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

	rc = obd_destroy(NULL, llu_i2obdexp(dir), oa, lsm, &oti, NULL, NULL);
	OBDO_FREE(oa);
	if (rc)
		CERROR("obd destroy objid "DOSTID" error %d\n",
		       POSTID(&lsm->lsm_oi), rc);
out_free_memmd:
	obd_free_memmd(llu_i2obdexp(dir), &lsm);
out:
	return rc;
}

/** Cliens updates SOM attributes on MDS: obd_getattr and md_setattr. */
int llu_som_update(struct inode *inode, struct md_op_data *op_data)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct obdo oa = { 0 };
        __u32 old_flags;
        int rc;
        ENTRY;

        LASSERT(!(lli->lli_flags & LLIF_MDS_SIZE_LOCK));
        LASSERT(sbi->ll_lco.lco_flags & OBD_CONNECT_SOM);

        old_flags = op_data->op_flags;
        op_data->op_flags = MF_SOM_CHANGE;

        /* If inode is already in another epoch, skip getattr from OSTs. */
        if (lli->lli_ioepoch == op_data->op_ioepoch) {
                rc = llu_inode_getattr(inode, &oa, op_data->op_ioepoch,
                                       old_flags & MF_GETATTR_LOCK);
                if (rc) {
                        oa.o_valid = 0;
			if (rc != -ENOENT)
                                CERROR("inode_getattr failed (%d): unable to "
                                       "send a Size-on-MDS attribute update "
                                       "for inode %llu/%lu\n", rc,
                                       (long long)llu_i2stat(inode)->st_ino,
                                       lli->lli_st_generation);
                }  else {
                        CDEBUG(D_INODE, "Size-on-MDS update on "DFID"\n",
                               PFID(&lli->lli_fid));
                }

                /* Install attributes into op_data. */
                md_from_obdo(op_data, &oa, oa.o_valid);
        }

        rc = llu_md_setattr(inode, op_data, NULL);
        RETURN(rc);
}

void llu_pack_inode2opdata(struct inode *inode, struct md_op_data *op_data,
                           struct lustre_handle *fh)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat *st = llu_i2stat(inode);
        ENTRY;

        op_data->op_fid1 = lli->lli_fid;
        op_data->op_attr.ia_atime = st->st_atime;
        op_data->op_attr.ia_mtime = st->st_mtime;
        op_data->op_attr.ia_ctime = st->st_ctime;
        op_data->op_attr.ia_size = st->st_size;
        op_data->op_attr_blocks = st->st_blocks;
        op_data->op_attr.ia_attr_flags = lli->lli_st_flags;
        op_data->op_ioepoch = lli->lli_ioepoch;
        if (fh)
                op_data->op_handle = *fh;
        EXIT;
}

/** Pack SOM attributes info @opdata for CLOSE, DONE_WRITING rpc. */
void llu_done_writing_attr(struct inode *inode, struct md_op_data *op_data)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        ENTRY;

        op_data->op_flags |= MF_SOM_CHANGE;

        /* Pack Size-on-MDS attributes if we are in IO
         * epoch and attributes are valid. */
        LASSERT(!(lli->lli_flags & LLIF_MDS_SIZE_LOCK));
        if (!cl_local_size(inode))
                op_data->op_attr.ia_valid |= ATTR_MTIME_SET | ATTR_CTIME_SET |
                        ATTR_ATIME_SET | ATTR_SIZE | ATTR_BLOCKS;

        EXIT;
}

static void llu_prepare_close(struct inode *inode, struct md_op_data *op_data,
                              struct ll_file_data *fd)
{
        struct obd_client_handle *och = &fd->fd_mds_och;

        op_data->op_attr.ia_valid = ATTR_MODE      | ATTR_ATIME_SET |
                                    ATTR_MTIME_SET | ATTR_CTIME_SET;

        if (fd->fd_flags & FMODE_WRITE) {
                struct llu_sb_info *sbi = llu_i2sbi(inode);
                if (!(sbi->ll_lco.lco_flags & OBD_CONNECT_SOM) ||
                    !S_ISREG(llu_i2stat(inode)->st_mode)) {
                        op_data->op_attr.ia_valid |= ATTR_SIZE | ATTR_BLOCKS;
                } else {
                        /* Inode cannot be dirty. Close the epoch. */
                        op_data->op_flags |= MF_EPOCH_CLOSE;
                        /* XXX: Send SOM attributes only if they are really
                         * changed.  */
                        llu_done_writing_attr(inode, op_data);
                }
        }
        llu_pack_inode2opdata(inode, op_data, &och->och_fh);
        llu_prep_md_op_data(op_data, inode, NULL, NULL,
                            0, 0, LUSTRE_OPC_ANY);
}

int llu_md_close(struct obd_export *md_exp, struct inode *inode)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct ptlrpc_request *req = NULL;
        struct obd_client_handle *och = &fd->fd_mds_och;
        struct intnl_stat *st = llu_i2stat(inode);
        struct md_op_data op_data = { { 0 } };
        int rc;
        ENTRY;

        /* clear group lock, if present */
        if (fd->fd_flags & LL_FILE_GROUP_LOCKED)
                llu_put_grouplock(inode, fd->fd_grouplock.cg_gid);

        llu_prepare_close(inode, &op_data, fd);
        rc = md_close(md_exp, &op_data, och->och_mod, &req);
        if (rc == -EAGAIN) {
                /* We are the last writer, so the MDS has instructed us to get
                 * the file size and any write cookies, then close again. */
                LASSERT(lli->lli_open_flags & FMODE_WRITE);
                rc = llu_som_update(inode, &op_data);
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
