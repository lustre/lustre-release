/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#define DEBUG_SUBSYSTEM S_MDC
#ifndef __KERNEL__
# include <fcntl.h>
# include <liblustre.h>
#endif
#include <lustre/lustre_idl.h>
#include <lustre_net.h>
#include "mdc_internal.h"

#ifndef __KERNEL__
/* some liblustre hackings here */
#ifndef O_DIRECTORY
#define O_DIRECTORY     0
#endif
#endif

static void __mdc_pack_body(struct mdt_body *b, __u32 suppgid)
{
        LASSERT (b != NULL);

        b->suppgid = suppgid;
        b->uid = current->uid;
        b->gid = current->gid;
        b->fsuid = current->fsuid;
        b->fsgid = current->fsgid;
        b->capability = current->cap_effective;
}

void mdc_pack_capa(struct ptlrpc_request *req, const struct req_msg_field *field,
                   struct obd_capa *oc)
{
        struct req_capsule *pill = &req->rq_pill;
        struct lustre_capa *c;

        if (oc == NULL) {
                LASSERT(req_capsule_get_size(pill, field, RCL_CLIENT) == 0);
                return;
        }

        c = req_capsule_client_get(pill, field);
        LASSERT(c != NULL);
        capa_cpy(c, oc);
        DEBUG_CAPA(D_SEC, c, "pack");
}

void mdc_is_subdir_pack(struct ptlrpc_request *req, const struct lu_fid *pfid,
                        const struct lu_fid *cfid, int flags)
{
        struct mdt_body *b = req_capsule_client_get(&req->rq_pill,
                                                    &RMF_MDT_BODY);

        if (pfid) {
                b->fid1 = *pfid;
                b->valid = OBD_MD_FLID;
        }
        if (cfid)
                b->fid2 = *cfid;
        b->flags = flags;
}

void mdc_pack_body(struct ptlrpc_request *req,
                   const struct lu_fid *fid, struct obd_capa *oc,
                   __u64 valid, int ea_size, __u32 suppgid, int flags)
{
        struct mdt_body *b = req_capsule_client_get(&req->rq_pill,
                                                    &RMF_MDT_BODY);
        LASSERT(b != NULL);
        b->valid = valid;
        b->eadatasize = ea_size;
        b->flags = flags;
        __mdc_pack_body(b, suppgid);
        if (fid) {
                b->fid1 = *fid;
                b->valid |= OBD_MD_FLID;
                mdc_pack_capa(req, &RMF_CAPA1, oc);
        }
}

void mdc_readdir_pack(struct ptlrpc_request *req, __u64 pgoff,
                      __u32 size, const struct lu_fid *fid, struct obd_capa *oc)
{
        struct mdt_body *b = req_capsule_client_get(&req->rq_pill,
                                                    &RMF_MDT_BODY);
        b->fid1 = *fid;
        b->valid |= OBD_MD_FLID;
        b->size = pgoff;                       /* !! */
        b->nlink = size;                        /* !! */
        __mdc_pack_body(b, -1);
        mdc_pack_capa(req, &RMF_CAPA1, oc);
}

/* packing of MDS records */
void mdc_create_pack(struct ptlrpc_request *req, struct md_op_data *op_data,
                     const void *data, int datalen, __u32 mode,
                     __u32 uid, __u32 gid, __u32 cap_effective, __u64 rdev)
{
        struct mdt_rec_create *rec;
        char                  *tmp;

        CLASSERT(sizeof(struct mdt_rec_reint) == sizeof(struct mdt_rec_create));
        rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);


        rec->cr_opcode   = REINT_CREATE;
        rec->cr_fsuid    = uid;
        rec->cr_fsgid    = gid;
        rec->cr_cap      = cap_effective;
        rec->cr_fid1     = op_data->op_fid1;
        rec->cr_fid2     = op_data->op_fid2;
        rec->cr_mode     = mode;
        rec->cr_rdev     = rdev;
        rec->cr_time     = op_data->op_mod_time;
        rec->cr_suppgid1 = op_data->op_suppgids[0];
        rec->cr_suppgid2 = op_data->op_suppgids[1];
        rec->cr_flags    = op_data->op_flags & ~MF_SOM_LOCAL_FLAGS;
        rec->cr_bias     = op_data->op_bias;

        mdc_pack_capa(req, &RMF_CAPA1, op_data->op_capa1);

        tmp = req_capsule_client_get(&req->rq_pill, &RMF_NAME);
        LOGL0(op_data->op_name, op_data->op_namelen, tmp);

        if (data) {
                tmp = req_capsule_client_get(&req->rq_pill, &RMF_EADATA);
                memcpy(tmp, data, datalen);
        }
}

static __u32 mds_pack_open_flags(__u32 flags)
{
        __u32 cr_flags = (flags & (FMODE_READ | FMODE_WRITE |
                                   MDS_OPEN_HAS_EA | MDS_OPEN_HAS_OBJS | 
                                   MDS_OPEN_OWNEROVERRIDE | MDS_OPEN_LOCK));
        if (flags & O_CREAT)
                cr_flags |= MDS_OPEN_CREAT;
        if (flags & O_EXCL)
                cr_flags |= MDS_OPEN_EXCL;
        if (flags & O_TRUNC)
                cr_flags |= MDS_OPEN_TRUNC;
        if (flags & O_APPEND)
                cr_flags |= MDS_OPEN_APPEND;
        if (flags & O_SYNC)
                cr_flags |= MDS_OPEN_SYNC;
        if (flags & O_DIRECTORY)
                cr_flags |= MDS_OPEN_DIRECTORY;
        if (flags & O_JOIN_FILE)
                cr_flags |= MDS_OPEN_JOIN_FILE;
#ifdef FMODE_EXEC
        if (flags & FMODE_EXEC)
                cr_flags |= MDS_FMODE_EXEC;
#endif
        if (flags & O_LOV_DELAY_CREATE)
                cr_flags |= MDS_OPEN_DELAY_CREATE;

        return cr_flags;
}

/* packing of MDS records */
void mdc_join_pack(struct ptlrpc_request *req,
                   struct md_op_data *op_data,
                   __u64 head_size)
{
        struct mdt_rec_join *rec;

        rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_JOINFILE);
        LASSERT(rec != NULL);
        rec->jr_fid = op_data->op_fid2;
        rec->jr_headsize = head_size;
}

void mdc_open_pack(struct ptlrpc_request *req, struct md_op_data *op_data,
                   __u32 mode, __u64 rdev, __u32 flags, const void *lmm,
                   int lmmlen)
{
        struct mdt_rec_create *rec;
        char *tmp;

        CLASSERT(sizeof(struct mdt_rec_reint) == sizeof(struct mdt_rec_create));
        rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);

        /* XXX do something about time, uid, gid */
        rec->cr_opcode   = REINT_OPEN;
        rec->cr_fsuid    = current->fsuid;
        rec->cr_fsgid    = current->fsgid;
        rec->cr_cap      = current->cap_effective;
        if (op_data != NULL) {
                rec->cr_fid1 = op_data->op_fid1;
                rec->cr_fid2 = op_data->op_fid2;
        }
        rec->cr_mode     = mode;
        rec->cr_flags    = mds_pack_open_flags(flags);
        rec->cr_rdev     = rdev;
        rec->cr_time     = op_data->op_mod_time;
        rec->cr_suppgid1 = op_data->op_suppgids[0];
        rec->cr_suppgid2 = op_data->op_suppgids[1];
        rec->cr_bias     = op_data->op_bias;

        mdc_pack_capa(req, &RMF_CAPA1, op_data->op_capa1);
        /* the next buffer is child capa, which is used for replay,
         * will be packed from the data in reply message. */

        if (op_data->op_name) {
                tmp = req_capsule_client_get(&req->rq_pill, &RMF_NAME);
                LOGL0(op_data->op_name, op_data->op_namelen, tmp);
        }

        if (lmm) {
                rec->cr_flags |= MDS_OPEN_HAS_EA;
#ifndef __KERNEL__
                /*XXX a hack for liblustre to set EA (LL_IOC_LOV_SETSTRIPE) */
                rec->cr_fid2 = op_data->op_fid2;
#endif
                tmp = req_capsule_client_get(&req->rq_pill, &RMF_EADATA);
                memcpy (tmp, lmm, lmmlen);
        }
}

static inline __u64 attr_pack(unsigned int ia_valid) {
        __u64 sa_valid = 0;

        if (ia_valid & ATTR_MODE)
                sa_valid |= MDS_ATTR_MODE;
        if (ia_valid & ATTR_UID)
                sa_valid |= MDS_ATTR_UID;
        if (ia_valid & ATTR_GID)
                sa_valid |= MDS_ATTR_GID;
        if (ia_valid & ATTR_SIZE)
                sa_valid |= MDS_ATTR_SIZE;
        if (ia_valid & ATTR_ATIME)
                sa_valid |= MDS_ATTR_ATIME;
        if (ia_valid & ATTR_MTIME)
                sa_valid |= MDS_ATTR_MTIME;
        if (ia_valid & ATTR_CTIME)
                sa_valid |= MDS_ATTR_CTIME;
        if (ia_valid & ATTR_ATIME_SET)
                sa_valid |= MDS_ATTR_ATIME_SET;
        if (ia_valid & ATTR_MTIME_SET)
                sa_valid |= MDS_ATTR_MTIME_SET;
        if (ia_valid & ATTR_FORCE)
                sa_valid |= MDS_ATTR_FORCE;
        if (ia_valid & ATTR_ATTR_FLAG)
                sa_valid |= MDS_ATTR_ATTR_FLAG;
        if (ia_valid & ATTR_KILL_SUID)
                sa_valid |=  MDS_ATTR_KILL_SUID;
        if (ia_valid & ATTR_KILL_SGID)
                sa_valid |= MDS_ATTR_KILL_SGID;
        if (ia_valid & ATTR_CTIME_SET)
                sa_valid |= MDS_ATTR_CTIME_SET;
        if (ia_valid & ATTR_FROM_OPEN)
                sa_valid |= MDS_ATTR_FROM_OPEN;
        if (ia_valid & ATTR_BLOCKS)
                sa_valid |= MDS_ATTR_BLOCKS;
        if (ia_valid & ATTR_TRUNC)
                sa_valid |= MDS_ATTR_TRUNC;
        if (ia_valid & MDS_OPEN_OWNEROVERRIDE)
                /* NFSD hack (see bug 5781) */
                sa_valid |= MDS_OPEN_OWNEROVERRIDE;
        return sa_valid;
}

static void mdc_setattr_pack_rec(struct mdt_rec_setattr *rec,
                                 struct md_op_data *op_data)
{
        rec->sa_opcode  = REINT_SETATTR;
        rec->sa_fsuid   = current->fsuid;
        rec->sa_fsgid   = current->fsgid;
        rec->sa_cap     = current->cap_effective;
        rec->sa_suppgid = -1;

        rec->sa_fid    = op_data->op_fid1;
        rec->sa_valid  = attr_pack(op_data->op_attr.ia_valid);
        rec->sa_mode   = op_data->op_attr.ia_mode;
        rec->sa_uid    = op_data->op_attr.ia_uid;
        rec->sa_gid    = op_data->op_attr.ia_gid;
        rec->sa_size   = op_data->op_attr.ia_size;
        rec->sa_blocks = op_data->op_attr_blocks;
        rec->sa_atime  = LTIME_S(op_data->op_attr.ia_atime);
        rec->sa_mtime  = LTIME_S(op_data->op_attr.ia_mtime);
        rec->sa_ctime  = LTIME_S(op_data->op_attr.ia_ctime);
        rec->sa_attr_flags = ((struct ll_iattr *)&op_data->op_attr)->ia_attr_flags;
        if ((op_data->op_attr.ia_valid & ATTR_GID) &&
            in_group_p(op_data->op_attr.ia_gid))
                rec->sa_suppgid = op_data->op_attr.ia_gid;
        else
                rec->sa_suppgid = op_data->op_suppgids[0];
}

static void mdc_epoch_pack(struct mdt_epoch *epoch, struct md_op_data *op_data)
{
        memcpy(&epoch->handle, &op_data->op_handle, sizeof(epoch->handle));
        epoch->ioepoch = op_data->op_ioepoch;
        epoch->flags = op_data->op_flags & ~MF_SOM_LOCAL_FLAGS;
}

void mdc_setattr_pack(struct ptlrpc_request *req, struct md_op_data *op_data,
                      void *ea, int ealen, void *ea2, int ea2len)
{
        struct mdt_rec_setattr *rec;
        struct mdt_epoch *epoch;
        
        CLASSERT(sizeof(struct mdt_rec_reint) ==sizeof(struct mdt_rec_setattr));
        rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);
        mdc_setattr_pack_rec(rec, op_data);

        mdc_pack_capa(req, &RMF_CAPA1, op_data->op_capa1);

        if (op_data->op_flags & (MF_SOM_CHANGE | MF_EPOCH_OPEN)) {
                epoch = req_capsule_client_get(&req->rq_pill, &RMF_MDT_EPOCH);
                mdc_epoch_pack(epoch, op_data);
        }

        if (ealen == 0)
                return;

        memcpy(req_capsule_client_get(&req->rq_pill, &RMF_EADATA), ea, ealen);

        if (ea2len == 0)
                return;

        memcpy(req_capsule_client_get(&req->rq_pill, &RMF_LOGCOOKIES), ea2,
               ea2len);
}

void mdc_unlink_pack(struct ptlrpc_request *req, struct md_op_data *op_data)
{
        struct mdt_rec_unlink *rec;
        char *tmp;
 
        CLASSERT(sizeof(struct mdt_rec_reint) == sizeof(struct mdt_rec_unlink));
        rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);
        LASSERT (rec != NULL);

        rec->ul_opcode  = REINT_UNLINK;
        rec->ul_fsuid   = op_data->op_fsuid;
        rec->ul_fsgid   = op_data->op_fsgid;
        rec->ul_cap     = op_data->op_cap;
        rec->ul_mode    = op_data->op_mode;
        rec->ul_suppgid1= op_data->op_suppgids[0];
        rec->ul_suppgid2= -1;
        rec->ul_fid1    = op_data->op_fid1;
        rec->ul_fid2    = op_data->op_fid2;
        rec->ul_time    = op_data->op_mod_time;
        rec->ul_bias    = op_data->op_bias;

        mdc_pack_capa(req, &RMF_CAPA1, op_data->op_capa1);

        tmp = req_capsule_client_get(&req->rq_pill, &RMF_NAME);
        LASSERT(tmp != NULL);
        LOGL0(op_data->op_name, op_data->op_namelen, tmp);
}

void mdc_link_pack(struct ptlrpc_request *req, struct md_op_data *op_data)
{
        struct mdt_rec_link *rec;
        char *tmp;

        CLASSERT(sizeof(struct mdt_rec_reint) == sizeof(struct mdt_rec_link));
        rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);
        LASSERT (rec != NULL);

        rec->lk_opcode   = REINT_LINK;
        rec->lk_fsuid    = op_data->op_fsuid;//current->fsuid;
        rec->lk_fsgid    = op_data->op_fsgid;//current->fsgid;
        rec->lk_cap      = op_data->op_cap;//current->cap_effective;
        rec->lk_suppgid1 = op_data->op_suppgids[0];
        rec->lk_suppgid2 = op_data->op_suppgids[1];
        rec->lk_fid1     = op_data->op_fid1;
        rec->lk_fid2     = op_data->op_fid2;
        rec->lk_time     = op_data->op_mod_time;
        rec->lk_bias     = op_data->op_bias;

        mdc_pack_capa(req, &RMF_CAPA1, op_data->op_capa1);
        mdc_pack_capa(req, &RMF_CAPA2, op_data->op_capa2);

        tmp = req_capsule_client_get(&req->rq_pill, &RMF_NAME);
        LOGL0(op_data->op_name, op_data->op_namelen, tmp);
}

void mdc_rename_pack(struct ptlrpc_request *req, struct md_op_data *op_data,
                     const char *old, int oldlen, const char *new, int newlen)
{
        struct mdt_rec_rename *rec;
        char *tmp;

        CLASSERT(sizeof(struct mdt_rec_reint) == sizeof(struct mdt_rec_rename));
        rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);

        /* XXX do something about time, uid, gid */
        rec->rn_opcode   = REINT_RENAME;
        rec->rn_fsuid    = op_data->op_fsuid;
        rec->rn_fsgid    = op_data->op_fsgid;
        rec->rn_cap      = op_data->op_cap;
        rec->rn_suppgid1 = op_data->op_suppgids[0];
        rec->rn_suppgid2 = op_data->op_suppgids[1];
        rec->rn_fid1     = op_data->op_fid1;
        rec->rn_fid2     = op_data->op_fid2;
        rec->rn_time     = op_data->op_mod_time;
        rec->rn_mode     = op_data->op_mode;
        rec->rn_bias     = op_data->op_bias;

        mdc_pack_capa(req, &RMF_CAPA1, op_data->op_capa1);
        mdc_pack_capa(req, &RMF_CAPA2, op_data->op_capa2);

        tmp = req_capsule_client_get(&req->rq_pill, &RMF_NAME);
        LOGL0(old, oldlen, tmp);

        if (new) {
                tmp = req_capsule_client_get(&req->rq_pill, &RMF_SYMTGT);
                LOGL0(new, newlen, tmp);
        }
}

void mdc_getattr_pack(struct ptlrpc_request *req, __u64 valid, int flags,
                      struct md_op_data *op_data)
{
        struct mdt_body *b = req_capsule_client_get(&req->rq_pill,
                                                    &RMF_MDT_BODY);

        b->fsuid = current->fsuid;
        b->fsgid = current->fsgid;
        b->capability = current->cap_effective;
        b->valid = valid;
        if (op_data->op_bias & MDS_CHECK_SPLIT)
                b->valid |= OBD_MD_FLCKSPLIT;
        if (op_data->op_bias & MDS_CROSS_REF)
                b->valid |= OBD_MD_FLCROSSREF;
        b->flags = flags | MDS_BFLAG_EXT_FLAGS;
        b->suppgid = op_data->op_suppgids[0];

        b->fid1 = op_data->op_fid1;
        b->fid2 = op_data->op_fid2;
        b->valid |= OBD_MD_FLID;

        mdc_pack_capa(req, &RMF_CAPA1, op_data->op_capa1);

        if (op_data->op_name) {
                char *tmp = req_capsule_client_get(&req->rq_pill, &RMF_NAME);
                LOGL0(op_data->op_name, op_data->op_namelen, tmp);

        }
}

void mdc_close_pack(struct ptlrpc_request *req, struct md_op_data *op_data)
{
        struct mdt_epoch *epoch;
        struct mdt_rec_setattr *rec;

        epoch = req_capsule_client_get(&req->rq_pill, &RMF_MDT_EPOCH);
        rec = req_capsule_client_get(&req->rq_pill, &RMF_REC_REINT);

        mdc_setattr_pack_rec(rec, op_data);
        mdc_pack_capa(req, &RMF_CAPA1, op_data->op_capa1);
        mdc_epoch_pack(epoch, op_data);
}

static int mdc_req_avail(struct client_obd *cli, struct mdc_cache_waiter *mcw)
{
        int rc;
        ENTRY;
        spin_lock(&cli->cl_loi_list_lock);
        rc = list_empty(&mcw->mcw_entry);
        spin_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
};

/* We record requests in flight in cli->cl_r_in_flight here.
 * There is only one write rpc possible in mdc anyway. If this to change
 * in the future - the code may need to be revisited. */
void mdc_enter_request(struct client_obd *cli)
{
        struct mdc_cache_waiter mcw;
        struct l_wait_info lwi = { 0 };

        spin_lock(&cli->cl_loi_list_lock);
        if (cli->cl_r_in_flight >= cli->cl_max_rpcs_in_flight) {
                list_add_tail(&mcw.mcw_entry, &cli->cl_cache_waiters);
                cfs_waitq_init(&mcw.mcw_waitq);
                spin_unlock(&cli->cl_loi_list_lock);
                l_wait_event(mcw.mcw_waitq, mdc_req_avail(cli, &mcw), &lwi);
        } else {
                cli->cl_r_in_flight++;
                spin_unlock(&cli->cl_loi_list_lock);
        }
}

void mdc_exit_request(struct client_obd *cli)
{
        struct list_head *l, *tmp;
        struct mdc_cache_waiter *mcw;

        spin_lock(&cli->cl_loi_list_lock);
        cli->cl_r_in_flight--;
        list_for_each_safe(l, tmp, &cli->cl_cache_waiters) {
                
                if (cli->cl_r_in_flight >= cli->cl_max_rpcs_in_flight) {
                        /* No free request slots anymore */
                        break;
                }

                mcw = list_entry(l, struct mdc_cache_waiter, mcw_entry);
                list_del_init(&mcw->mcw_entry);
                cli->cl_r_in_flight++;
                cfs_waitq_signal(&mcw->mcw_waitq);
        }
        /* Empty waiting list? Decrease reqs in-flight number */
        
        spin_unlock(&cli->cl_loi_list_lock);
}
