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

void llu_prepare_mdc_op_data(struct mdc_op_data *data,
                             struct inode *i1,
                             struct inode *i2,
                             const char *name,
                             int namelen,
                             int mode)
{
        LASSERT(i1 != NULL || i2 != NULL);

        if (i1) {
                ll_i2gids(data->suppgids, i1, i2);
                llu_inode2fid(&data->fid1, i1);
        }else {
                ll_i2gids(data->suppgids, i2, i1);
                llu_inode2fid(&data->fid1, i2);
        }

        if (i2)
                llu_inode2fid(&data->fid2, i2);
        else
                memset(&data->fid2, 0, sizeof(data->fid2));

        data->name = name;
        data->namelen = namelen;
        data->create_mode = mode;
        data->mod_time = CURRENT_TIME;
        data->data = NULL;
}

void obdo_refresh_inode(struct inode *dst,
                        struct obdo *src,
                        obd_flag valid)
{
        struct intnl_stat *st = llu_i2stat(dst);
        valid &= src->o_valid;

        if (valid & (OBD_MD_FLCTIME | OBD_MD_FLMTIME))
                CDEBUG(D_INODE,"valid "LPX64", cur time %lu/%lu, new %lu/%lu\n",
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

int llu_local_open(struct llu_inode_info *lli, struct lookup_intent *it)
{
        struct ptlrpc_request *req = it->d.lustre.it_data;
        struct ll_file_data *fd;
        struct mds_body *body;
        ENTRY;

        body = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF, sizeof(*body));
        LASSERT(body != NULL);                 /* reply already checked out */
        /* and swabbed down */
        LASSERT(lustre_rep_swabbed(req, DLM_REPLY_REC_OFF));

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
        body = lustre_msg_buf(request->rq_repmsg, REPLY_REC_OFF, sizeof(*body));

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
        eadata = lustre_swab_repbuf(request, REPLY_REC_OFF+1, body->eadatasize,
                                    NULL);
        LASSERT(eadata != NULL);
        if (eadata == NULL) {
                CERROR("Can't unpack MDS EA data\n");
                GOTO(out, rc = -EPROTO);
        }

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
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE;

        if (body->valid & OBD_MD_FLCOOKIE) {
                oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies =
                        lustre_msg_buf(request->rq_repmsg, REPLY_REC_OFF + 2,
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

int llu_mdc_close(struct obd_export *mdc_exp, struct inode *inode)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat *st = llu_i2stat(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct ptlrpc_request *req = NULL;
        struct obd_client_handle *och = &fd->fd_mds_och;
        struct obdo obdo;
        struct mdc_op_data data = { { 0 } };
        int rc, valid;
        ENTRY;

        /* clear group lock, if present */
        if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
                struct lov_stripe_md *lsm = llu_i2info(inode)->lli_smd;
                fd->fd_flags &= ~(LL_FILE_GROUP_LOCKED|LL_FILE_IGNORE_LOCK);
                rc = llu_extent_unlock(fd, inode, lsm, LCK_GROUP,
                                       &fd->fd_cwlockh);
        }

        obdo.o_id = st->st_ino;
        obdo.o_valid = OBD_MD_FLID;
        valid = OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLSIZE |OBD_MD_FLBLOCKS |
                OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME;
        if (test_bit(LLI_F_HAVE_OST_SIZE_LOCK, &lli->lli_flags))
                valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;

        obdo_from_inode(&obdo, inode, valid);

        if (0 /* ll_is_inode_dirty(inode) */) {
                obdo.o_flags = MDS_BFLAG_UNCOMMITTED_WRITES;
                obdo.o_valid |= OBD_MD_FLFLAGS;
        }
        data.fid1 = lli->lli_fid;
        rc = mdc_close(mdc_exp, &data, &obdo, och, &req);
        if (rc == EAGAIN) {
                /* We are the last writer, so the MDS has instructed us to get
                 * the file size and any write cookies, then close again. */
                //ll_queue_done_writing(inode);
                rc = 0;
        } else if (rc) {
                CERROR("inode %llu close failed: rc %d\n",
                       (long long)st->st_ino, rc);
        } else {
                rc = llu_objects_destroy(req, inode);
                if (rc)
                        CERROR("inode %llu ll_objects destroy: rc = %d\n",
                               (long long)st->st_ino, rc);
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

        rc2 = llu_mdc_close(sbi->ll_mdc_exp, inode);
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
        struct ldlm_res_id res_id =
                { .name = {llu_i2stat(inode)->st_ino,
                 (__u64)llu_i2info(inode)->lli_st_generation, LDLM_FLOCK} };
        struct lustre_handle lockh = {0};

        liblustre_wait_event(0);

        /* If we have posix locks on this file - clear all of those */
        if (ldlm_lock_match(
                      class_exp2obd(llu_i2mdcexp(inode))->obd_namespace,
                      LDLM_FL_BLOCK_GRANTED|LDLM_FL_TEST_LOCK|LDLM_FL_CBPENDING,
                      &res_id, LDLM_FLOCK, NULL, LCK_PR|LCK_PW, &lockh)) {
                struct file_lock lock;
                lock.fl_type = F_UNLCK;
                lock.fl_flags = FL_POSIX;
                lock.fl_start = 0;
                lock.fl_end = OFFSET_MAX;
                lock.fl_pid = getpid();
                lock.fl_notify = NULL;
                lock.fl_insert = NULL;
                lock.fl_remove = NULL;
                lock.fl_owner = NULL;
                lock.fl_file = NULL;

                llu_file_flock(inode, F_SETLK, &lock);
        }

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
        obd_valid valid;
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
 
        valid = OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLATIME;
        if (flags & OBD_FL_TRUNCLOCK) {
                /* lockless truncate
                 *
                 * 1. do not use inode's timestamps because concurrent
                 * stat might fill the inode with out-of-date times,
                 * send current instead
                 *
                 * 2.do no update lsm, as long as stat (via
                 * llu_glimpse_size) will bring attributes from osts
                 * anyway */
                oa.o_mtime = oa.o_ctime = CURRENT_TIME;
                oa.o_valid |= OBD_MD_FLMTIME | OBD_MD_FLCTIME;
        } else {
                /* truncate under locks
                 *
                 * 1. update inode's mtime and ctime as long as
                 * concurrent stat (via llu_glimpse_size) might bring
                 * out-of-date ones
                 *
                 * 2. update lsm so that next stat (via
                 * llu_glimpse_size) could get correct values in lsm */
                struct ost_lvb xtimes;

                lov_stripe_lock(lli->lli_smd);
                st->st_mtime = st->st_ctime = CURRENT_TIME;
                xtimes.lvb_mtime = st->st_mtime;
                xtimes.lvb_ctime = st->st_ctime;
                obd_update_lvb(llu_i2obdexp(inode), lli->lli_smd, &xtimes,
                               OBD_MD_FLMTIME | OBD_MD_FLCTIME);
                lov_stripe_unlock(lli->lli_smd);

                valid |= OBD_MD_FLMTIME | OBD_MD_FLCTIME;
        }
        obdo_from_inode(&oa, inode, valid);

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
