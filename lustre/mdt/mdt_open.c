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
 * lustre/mdt/mdt_open.c
 *
 * Lustre Metadata Target (mdt) open/close file handling
 *
 * Author: Huang Hua <huanghua@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <lustre_acl.h>
#include <lustre_mds.h>
#include "mdt_internal.h"

/* we do nothing because we do not have refcount now */
static void mdt_mfd_get(void *mfdp)
{
}

/* Create a new mdt_file_data struct, initialize it,
 * and insert it to global hash table */
struct mdt_file_data *mdt_mfd_new(void)
{
        struct mdt_file_data *mfd;
        ENTRY;

        OBD_ALLOC_PTR(mfd);
        if (mfd != NULL) {
                CFS_INIT_LIST_HEAD(&mfd->mfd_handle.h_link);
                CFS_INIT_LIST_HEAD(&mfd->mfd_list);
                class_handle_hash(&mfd->mfd_handle, mdt_mfd_get);
        }
        RETURN(mfd);
}

/*
 * Find the mfd pointed to by handle in global hash table.
 * In case of replay the handle is obsoleted
 * but mfd can be found in mfd list by that handle
 */
struct mdt_file_data *mdt_handle2mfd(struct mdt_thread_info *info,
                                     const struct lustre_handle *handle)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_file_data  *mfd;
        ENTRY;

        LASSERT(handle != NULL);
        mfd = class_handle2object(handle->cookie);
        /* during dw/setattr replay the mfd can be found by old handle */
        if (mfd == NULL &&
            lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                struct mdt_export_data *med = &req->rq_export->exp_mdt_data;
                list_for_each_entry(mfd, &med->med_open_head, mfd_list) {
                        if (mfd->mfd_old_handle.cookie == handle->cookie)
                                RETURN (mfd);
                }
                mfd = NULL;
        }
        RETURN (mfd);
}

/* free mfd */
void mdt_mfd_free(struct mdt_file_data *mfd)
{
        LASSERT(list_empty(&mfd->mfd_list));
        OBD_FREE_RCU(mfd, sizeof *mfd, &mfd->mfd_handle);
}

static int mdt_create_data(struct mdt_thread_info *info,
                           struct mdt_object *p, struct mdt_object *o)
{
        struct md_op_spec     *spec = &info->mti_spec;
        struct md_attr        *ma = &info->mti_attr;
        int rc;
        ENTRY;

        if (!md_should_create(spec->sp_cr_flags))
                RETURN(0);

        ma->ma_need = MA_INODE | MA_LOV;
        ma->ma_valid = 0;
        rc = mdo_create_data(info->mti_env,
                             p ? mdt_object_child(p) : NULL,
                             mdt_object_child(o), spec, ma);
        RETURN(rc);
}

static int mdt_epoch_opened(struct mdt_object *mo)
{
        return mo->mot_epochcount;
}

int mdt_sizeonmds_enabled(struct mdt_object *mo)
{
        return !mo->mot_ioepoch;
}

/* Re-enable Size-on-MDS. */
void mdt_sizeonmds_enable(struct mdt_thread_info *info,
                          struct mdt_object *mo)
{
       spin_lock(&info->mti_mdt->mdt_ioepoch_lock);
       if (info->mti_epoch->ioepoch == mo->mot_ioepoch) {
                LASSERT(!mdt_epoch_opened(mo));
                mo->mot_ioepoch = 0;
                mo->mot_flags = 0;
       }
       spin_unlock(&info->mti_mdt->mdt_ioepoch_lock);
}

/* Open the epoch. Epoch open is allowed if @writecount is not negative.
 * The epoch and writecount handling is performed under the mdt_ioepoch_lock. */
int mdt_epoch_open(struct mdt_thread_info *info, struct mdt_object *o)
{
        struct mdt_device *mdt = info->mti_mdt;
        int cancel = 0;
        int rc = 0;
        ENTRY;

        if (!(mdt_conn_flags(info) & OBD_CONNECT_SOM) ||
            !S_ISREG(lu_object_attr(&o->mot_obj.mo_lu)))
                RETURN(0);

        spin_lock(&mdt->mdt_ioepoch_lock);
        if (mdt_epoch_opened(o)) {
                /* Epoch continues even if there is no writers yet. */
                CDEBUG(D_INODE, "continue epoch "LPU64" for "DFID"\n",
                       o->mot_ioepoch, PFID(mdt_object_fid(o)));
        } else {
                if (info->mti_replayepoch > mdt->mdt_ioepoch)
                        mdt->mdt_ioepoch = info->mti_replayepoch;
                else
                        mdt->mdt_ioepoch++;
                o->mot_ioepoch = info->mti_replayepoch ?
                        info->mti_replayepoch : mdt->mdt_ioepoch;
                CDEBUG(D_INODE, "starting epoch "LPU64" for "DFID"\n",
                       mdt->mdt_ioepoch, PFID(mdt_object_fid(o)));
                cancel = 1;
        }
        o->mot_epochcount++;
        spin_unlock(&mdt->mdt_ioepoch_lock);

        /* Cancel Size-on-MDS attributes on clients if not truncate.
         * In the later case, mdt_reint_setattr will do it. */
        if (cancel && (info->mti_rr.rr_fid1 != NULL)) {
                struct mdt_lock_handle  *lh = &info->mti_lh[MDT_LH_CHILD];
                mdt_lock_reg_init(lh, LCK_EX);
                rc = mdt_object_lock(info, o, lh, MDS_INODELOCK_UPDATE,
                                     MDT_LOCAL_LOCK);
                if (rc == 0)
                        mdt_object_unlock(info, o, lh, 1);
        }
        RETURN(rc);
}

/* Update the on-disk attributes if needed and re-enable Size-on-MDS caching. */
static int mdt_sizeonmds_update(struct mdt_thread_info *info,
                                struct mdt_object *o)
{
        ENTRY;

        CDEBUG(D_INODE, "Closing epoch "LPU64" on "DFID". Count %d\n",
               o->mot_ioepoch, PFID(mdt_object_fid(o)), o->mot_epochcount);

        if (info->mti_attr.ma_attr.la_valid & LA_SIZE) {
                /* Do Size-on-MDS attribute update.
                 * Size-on-MDS is re-enabled inside. */
                /* XXX: since we have opened the file, it is unnecessary
                 * to check permission when close it. Between the "open"
                 * and "close", maybe someone has changed the file mode
                 * or flags, or the file created mode do not permit wirte,
                 * and so on. Just set MDS_PERM_BYPASS for all the cases. */
                info->mti_attr.ma_attr_flags |= MDS_PERM_BYPASS | MDS_SOM;
                info->mti_attr.ma_attr.la_valid &= LA_SIZE | LA_BLOCKS |
                                                LA_ATIME | LA_MTIME | LA_CTIME;
                RETURN(mdt_attr_set(info, o, 0));
        } else
                mdt_sizeonmds_enable(info, o);
        RETURN(0);
}

/* Epoch closes.
 * Returns 1 if epoch does not close.
 * Returns 0 if epoch closes.
 * Returns -EAGAIN if epoch closes but an Size-on-MDS Update is still needed
 * from the client. */
static int mdt_epoch_close(struct mdt_thread_info *info, struct mdt_object *o)
{
        int eviction = (mdt_info_req(info) == NULL ? 1 : 0);
        struct lu_attr *la = &info->mti_attr.ma_attr;
        int achange = 0;
        int opened;
        int rc = 1;
        ENTRY;

        if (!(mdt_conn_flags(info) & OBD_CONNECT_SOM) ||
            !S_ISREG(lu_object_attr(&o->mot_obj.mo_lu)))
                RETURN(0);

        spin_lock(&info->mti_mdt->mdt_ioepoch_lock);

        /* Epoch closes only if client tells about it or eviction occures. */
        if (eviction || (info->mti_epoch->flags & MF_EPOCH_CLOSE)) {
                LASSERT(o->mot_epochcount);
                o->mot_epochcount--;

                CDEBUG(D_INODE, "Closing epoch "LPU64" on "DFID". Count %d\n",
                       o->mot_ioepoch, PFID(mdt_object_fid(o)),
                       o->mot_epochcount);

                if (!eviction)
                        achange = (info->mti_epoch->flags & MF_SOM_CHANGE);

                rc = 0;
                if (!eviction && !mdt_epoch_opened(o)) {
                        /* Epoch ends. Is an Size-on-MDS update needed? */
                        if (o->mot_flags & MF_SOM_CHANGE) {
                                /* Some previous writer changed the attribute.
                                 * Do not believe to the current Size-on-MDS
                                 * update, re-ask client. */
                                rc = -EAGAIN;
                        } else if (!(la->la_valid & LA_SIZE) && achange) {
                                /* Attributes were changed by the last writer
                                 * only but no Size-on-MDS update is received.*/
                                rc = -EAGAIN;
                        }
                }

                if (achange || eviction)
                        o->mot_flags |= MF_SOM_CHANGE;
        }

        opened = mdt_epoch_opened(o);
        spin_unlock(&info->mti_mdt->mdt_ioepoch_lock);

        /* If eviction occurred, do nothing. */
        if ((rc == 0) && !opened && !eviction) {
                /* Epoch ends and wanted Size-on-MDS update is obtained. */
                rc = mdt_sizeonmds_update(info, o);
                /* Avoid the following setattrs of these attributes, e.g.
                 * for atime update. */
                info->mti_attr.ma_valid = 0;
        }
        RETURN(rc);
}

int mdt_write_read(struct mdt_device *mdt, struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
        spin_lock(&mdt->mdt_ioepoch_lock);
        rc = o->mot_writecount;
        spin_unlock(&mdt->mdt_ioepoch_lock);
        RETURN(rc);
}

int mdt_write_get(struct mdt_device *mdt, struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
        spin_lock(&mdt->mdt_ioepoch_lock);
        if (o->mot_writecount < 0)
                rc = -ETXTBSY;
        else
                o->mot_writecount++;
        spin_unlock(&mdt->mdt_ioepoch_lock);
        RETURN(rc);
}

static void mdt_write_put(struct mdt_device *mdt, struct mdt_object *o)
{
        ENTRY;
        spin_lock(&mdt->mdt_ioepoch_lock);
        o->mot_writecount--;
        spin_unlock(&mdt->mdt_ioepoch_lock);
        EXIT;
}

static int mdt_write_deny(struct mdt_device *mdt, struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
        spin_lock(&mdt->mdt_ioepoch_lock);
        if (o->mot_writecount > 0)
                rc = -ETXTBSY;
        else
                o->mot_writecount--;
        spin_unlock(&mdt->mdt_ioepoch_lock);
        RETURN(rc);
}

static void mdt_write_allow(struct mdt_device *mdt, struct mdt_object *o)
{
        ENTRY;
        spin_lock(&mdt->mdt_ioepoch_lock);
        o->mot_writecount++;
        spin_unlock(&mdt->mdt_ioepoch_lock);
        EXIT;
}

/* there can be no real transaction so prepare the fake one */
static void mdt_empty_transno(struct mdt_thread_info* info)
{
        struct mdt_device *mdt = info->mti_mdt;
        struct ptlrpc_request *req = mdt_info_req(info);

        ENTRY;
        /* transaction is occured already */
        if (lustre_msg_get_transno(req->rq_repmsg) != 0) {
                EXIT;
                return;
        }

        spin_lock(&mdt->mdt_transno_lock);
        if (info->mti_transno == 0) {
                info->mti_transno = ++ mdt->mdt_last_transno;
        } else {
                /* should be replay */
                if (info->mti_transno > mdt->mdt_last_transno)
                        mdt->mdt_last_transno = info->mti_transno;
        }
        spin_unlock(&mdt->mdt_transno_lock);

        CDEBUG(D_INODE, "transno = %llu, last_committed = %llu\n",
                        info->mti_transno,
                        req->rq_export->exp_obd->obd_last_committed);

        req->rq_transno = info->mti_transno;
        lustre_msg_set_transno(req->rq_repmsg, info->mti_transno);
        lustre_msg_set_last_xid(req->rq_repmsg, req->rq_xid);
        EXIT;
}

void mdt_mfd_set_mode(struct mdt_file_data *mfd, int mode)
{
        LASSERT(mfd != NULL);

        CDEBUG(D_HA, "Change mfd %p mode 0x%x->0x%x\n",
               mfd, (unsigned int)mfd->mfd_mode, (unsigned int)mode);

        mfd->mfd_mode = mode;
}

static int mdt_mfd_open(struct mdt_thread_info *info, struct mdt_object *p,
                        struct mdt_object *o, int flags, int created)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_export_data  *med = &req->rq_export->exp_mdt_data;
        struct mdt_file_data    *mfd;
        struct md_attr          *ma  = &info->mti_attr;
        struct lu_attr          *la  = &ma->ma_attr;
        struct mdt_body         *repbody;
        int                      rc = 0, isdir, isreg;
        ENTRY;

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        isreg = S_ISREG(la->la_mode);
        isdir = S_ISDIR(la->la_mode);
        if ((isreg && !(ma->ma_valid & MA_LOV))) {
                /*
                 * No EA, check whether it is will set regEA and dirEA since in
                 * above attr get, these size might be zero, so reset it, to
                 * retrieve the MD after create obj.
                 */
                ma->ma_lmm_size = req_capsule_get_size(info->mti_pill,
                                                       &RMF_MDT_MD,
                                                       RCL_SERVER);
                /* in replay case, p == NULL */
                rc = mdt_create_data(info, p, o);
                if (rc)
                        RETURN(rc);
        }

        CDEBUG(D_INODE, "after open, ma_valid bit = "LPX64" lmm_size = %d\n",
               ma->ma_valid, ma->ma_lmm_size);

        if (ma->ma_valid & MA_LOV) {
                LASSERT(ma->ma_lmm_size != 0);
                repbody->eadatasize = ma->ma_lmm_size;
                if (isdir)
                        repbody->valid |= OBD_MD_FLDIREA;
                else
                        repbody->valid |= OBD_MD_FLEASIZE;
        }

        if (flags & FMODE_WRITE) {
                rc = mdt_write_get(info->mti_mdt, o);
                if (rc == 0) {
                        mdt_epoch_open(info, o);
                        repbody->ioepoch = o->mot_ioepoch;
                }
        } else if (flags & MDS_FMODE_EXEC) {
                rc = mdt_write_deny(info->mti_mdt, o);
        }
        if (rc)
                RETURN(rc);

        rc = mo_open(info->mti_env, mdt_object_child(o),
                     created ? flags | MDS_OPEN_CREATED : flags);
        if (rc)
                RETURN(rc);

        mfd = mdt_mfd_new();
        if (mfd != NULL) {
                /*
                 * Keep a reference on this object for this open, and is
                 * released by mdt_mfd_close().
                 */
                mdt_object_get(info->mti_env, o);

                /*
                 * @flags is always not zero. At least it should be FMODE_READ,
                 * FMODE_WRITE or FMODE_EXEC.
                 */
                LASSERT(flags != 0);

                /* Open handling. */
                mdt_mfd_set_mode(mfd, flags);

                mfd->mfd_object = o;
                mfd->mfd_xid = req->rq_xid;

                /* replay handle */
                if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                        struct mdt_file_data *old_mfd;
                        /* Check wheather old cookie already exist in
                         * the list, becasue when do recovery, client
                         * might be disconnected from server, and
                         * restart replay, so there maybe some orphan
                         * mfd here, we should remove them */
                        LASSERT(info->mti_rr.rr_handle != NULL);
                        old_mfd = mdt_handle2mfd(info, info->mti_rr.rr_handle);
                        if (old_mfd) {
                                CDEBUG(D_HA, "del orph mfd %p cookie" LPX64"\n",
                                       mfd, info->mti_rr.rr_handle->cookie);
                                spin_lock(&med->med_open_lock);
                                class_handle_unhash(&old_mfd->mfd_handle);
                                list_del_init(&old_mfd->mfd_list);
                                spin_unlock(&med->med_open_lock);
                                mdt_mfd_free(old_mfd);
                        }
                        CDEBUG(D_HA, "Store old cookie "LPX64" in new mfd\n",
                               info->mti_rr.rr_handle->cookie);
                        mfd->mfd_old_handle.cookie =
                                                info->mti_rr.rr_handle->cookie;
                }
                spin_lock(&med->med_open_lock);
                list_add(&mfd->mfd_list, &med->med_open_head);
                spin_unlock(&med->med_open_lock);

                repbody->handle.cookie = mfd->mfd_handle.h_cookie;
                mdt_empty_transno(info);
        } else
                rc = -ENOMEM;

        RETURN(rc);
}


static int mdt_finish_open(struct mdt_thread_info *info,
                           struct mdt_object *p, struct mdt_object *o,
                           int flags, int created, struct ldlm_reply *rep)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_export_data  *med = &req->rq_export->exp_mdt_data;
        struct mdt_device       *mdt = info->mti_mdt;
        struct md_attr          *ma  = &info->mti_attr;
        struct lu_attr          *la  = &ma->ma_attr;
        struct mdt_file_data    *mfd;
        struct mdt_body         *repbody;
        int                      rc = 0;
        int                      isreg, isdir, islnk;
        struct list_head        *t;
        ENTRY;

        LASSERT(ma->ma_valid & MA_INODE);

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        isreg = S_ISREG(la->la_mode);
        isdir = S_ISDIR(la->la_mode);
        islnk = S_ISLNK(la->la_mode);
        mdt_pack_attr2body(info, repbody, la, mdt_object_fid(o));

        if (med->med_rmtclient) {
                void *buf = req_capsule_server_get(info->mti_pill, &RMF_ACL);

                rc = mdt_pack_remote_perm(info, o, buf);
                if (rc) {
                        repbody->valid &= ~OBD_MD_FLRMTPERM;
                        repbody->aclsize = 0;
                } else {
                        repbody->valid |= OBD_MD_FLRMTPERM;
                        repbody->aclsize = sizeof(struct mdt_remote_perm);
                }
        }
#ifdef CONFIG_FS_POSIX_ACL
        else if (req->rq_export->exp_connect_flags & OBD_CONNECT_ACL) {
                const struct lu_env *env = info->mti_env;
                struct md_object *next = mdt_object_child(o);
                struct lu_buf *buf = &info->mti_buf;

                buf->lb_buf = req_capsule_server_get(info->mti_pill, &RMF_ACL);
                buf->lb_len = req_capsule_get_size(info->mti_pill, &RMF_ACL,
                                                   RCL_SERVER);
                if (buf->lb_len > 0) {
                        rc = mo_xattr_get(env, next, buf,
                                          XATTR_NAME_ACL_ACCESS);
                        if (rc < 0) {
                                if (rc == -ENODATA) {
                                        repbody->aclsize = 0;
                                        repbody->valid |= OBD_MD_FLACL;
                                        rc = 0;
                                } else if (rc == -EOPNOTSUPP) {
                                        rc = 0;
                                } else {
                                        CERROR("got acl size: %d\n", rc);
                                }
                        } else {
                                repbody->aclsize = rc;
                                repbody->valid |= OBD_MD_FLACL;
                                rc = 0;
                        }
                }
        }
#endif

        if (mdt->mdt_opts.mo_mds_capa) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA1);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_MDS_DEFAULT;
                capa->lc_uid = 0;
                rc = mo_capa_get(info->mti_env, mdt_object_child(o), capa, 0);
                if (rc)
                        RETURN(rc);
                repbody->valid |= OBD_MD_FLMDSCAPA;
        }
        if (mdt->mdt_opts.mo_oss_capa &&
            S_ISREG(lu_object_attr(&o->mot_obj.mo_lu))) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA2);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_OSS_DEFAULT | capa_open_opc(flags);
                capa->lc_uid = 0;
                rc = mo_capa_get(info->mti_env, mdt_object_child(o), capa, 0);
                if (rc)
                        RETURN(rc);
                repbody->valid |= OBD_MD_FLOSSCAPA;
        }

        /*
         * If we are following a symlink, don't open; and do not return open
         * handle for special nodes as client required.
         */
        if (islnk || (!isreg && !isdir &&
            (req->rq_export->exp_connect_flags & OBD_CONNECT_NODEVOH))) {
                lustre_msg_set_transno(req->rq_repmsg, 0);
                RETURN(0);
        }

        mdt_set_disposition(info, rep, DISP_OPEN_OPEN);

        /*
         * We need to return the existing object's fid back, so it is done here,
         * after preparing the reply.
         */
        if (!created && (flags & MDS_OPEN_EXCL) && (flags & MDS_OPEN_CREAT))
                RETURN(-EEXIST);

        /* This can't be done earlier, we need to return reply body */
        if (isdir) {
                if (flags & (MDS_OPEN_CREAT | FMODE_WRITE)) {
                        /* We are trying to create or write an existing dir. */
                        RETURN(-EISDIR);
                }
        } else if (flags & MDS_OPEN_DIRECTORY)
                RETURN(-ENOTDIR);

        if (OBD_FAIL_CHECK_RESET(OBD_FAIL_MDS_OPEN_CREATE,
                                 OBD_FAIL_LDLM_REPLY | OBD_FAIL_ONCE)) {
                RETURN(-EAGAIN);
        }

        mfd = NULL;
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
                spin_lock(&med->med_open_lock);
                list_for_each(t, &med->med_open_head) {
                        mfd = list_entry(t, struct mdt_file_data, mfd_list);
                        if (mfd->mfd_xid == req->rq_xid) {
                                break;
                        }
                        mfd = NULL;
                }
                spin_unlock(&med->med_open_lock);

                if (mfd != NULL) {
                        repbody->handle.cookie = mfd->mfd_handle.h_cookie;
                        /*set repbody->ea_size for resent case*/
                        if (ma->ma_valid & MA_LOV) {
                                LASSERT(ma->ma_lmm_size != 0);
                                repbody->eadatasize = ma->ma_lmm_size;
                                if (isdir)
                                        repbody->valid |= OBD_MD_FLDIREA;
                                else
                                        repbody->valid |= OBD_MD_FLEASIZE;
                        }
                        RETURN(0);
                }
        }

        rc = mdt_mfd_open(info, p, o, flags, created);
        RETURN(rc);
}

extern void mdt_req_from_lcd(struct ptlrpc_request *req,
                             struct lsd_client_data *lcd);

void mdt_reconstruct_open(struct mdt_thread_info *info,
                          struct mdt_lock_handle *lhc)
{
        const struct lu_env *env = info->mti_env;
        struct mdt_device       *mdt  = info->mti_mdt;
        struct req_capsule      *pill = info->mti_pill;
        struct ptlrpc_request   *req  = mdt_info_req(info);
        struct mdt_export_data  *med  = &req->rq_export->exp_mdt_data;
        struct lsd_client_data  *lcd  = med->med_lcd;
        struct md_attr          *ma   = &info->mti_attr;
        struct mdt_reint_record *rr   = &info->mti_rr;
        __u32                   flags = info->mti_spec.sp_cr_flags;
        struct ldlm_reply       *ldlm_rep;
        struct mdt_object       *parent;
        struct mdt_object       *child;
        struct mdt_body         *repbody;
        int                      rc;
        ENTRY;

        LASSERT(pill->rc_fmt == &RQF_LDLM_INTENT_OPEN);
        ldlm_rep = req_capsule_server_get(pill, &RMF_DLM_REP);
        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);

        ma->ma_lmm = req_capsule_server_get(pill, &RMF_MDT_MD);
        ma->ma_lmm_size = req_capsule_get_size(pill, &RMF_MDT_MD,
                                               RCL_SERVER);
        ma->ma_need = MA_INODE | MA_LOV;
        ma->ma_valid = 0;

        mdt_req_from_lcd(req, med->med_lcd);
        mdt_set_disposition(info, ldlm_rep, lcd->lcd_last_data);

        CERROR("This is reconstruct open: disp="LPX64", result=%d\n",
                ldlm_rep->lock_policy_res1, req->rq_status);

        if (mdt_get_disposition(ldlm_rep, DISP_OPEN_CREATE) &&
            req->rq_status != 0)
                /* We did not create successfully, return error to client. */
                GOTO(out, rc = req->rq_status);

        if (mdt_get_disposition(ldlm_rep, DISP_OPEN_CREATE)) {
                struct obd_export *exp = req->rq_export;
                /*
                 * We failed after creation, but we do not know in which step
                 * we failed. So try to check the child object.
                 */
                parent = mdt_object_find(env, mdt, rr->rr_fid1);
                if (IS_ERR(parent)) {
                        rc = PTR_ERR(parent);
                        LCONSOLE_WARN("Parent "DFID" lookup error %d."
                                      " Evicting client %s with export %s.\n",
                                      PFID(mdt_object_fid(parent)), rc,
                                      obd_uuid2str(&exp->exp_client_uuid),
                                      obd_export_nid2str(exp));
                        mdt_export_evict(exp);
                        EXIT;
                        return;
                }
                child = mdt_object_find(env, mdt, rr->rr_fid2);
                if (IS_ERR(child)) {
                        rc = PTR_ERR(parent);
                        LCONSOLE_WARN("Child "DFID" lookup error %d."
                                      " Evicting client %s with export %s.\n",
                                      PFID(mdt_object_fid(child)), rc,
                                      obd_uuid2str(&exp->exp_client_uuid),
                                      obd_export_nid2str(exp));
                        mdt_export_evict(exp);
                        EXIT;
                        return;
                }
                rc = mdt_object_exists(child);
                if (rc > 0) {
                        struct md_object *next;

                        mdt_set_capainfo(info, 1, rr->rr_fid2, BYPASS_CAPA);
                        next = mdt_object_child(child);
                        rc = mo_attr_get(env, next, ma);
                        if (rc == 0)
                              rc = mdt_finish_open(info, parent, child,
                                                   flags, 1, ldlm_rep);
                } else if (rc < 0) {
                        /* the child object was created on remote server */
                        repbody->fid1 = *rr->rr_fid2;
                        repbody->valid |= (OBD_MD_FLID | OBD_MD_MDS);
                        rc = 0;
                } else if (rc == 0) {
                        /* the child does not exist, we should do regular open */
                        mdt_object_put(env, parent);
                        mdt_object_put(env, child);
                        GOTO(regular_open, 0);
                }
                mdt_object_put(env, parent);
                mdt_object_put(env, child);
                GOTO(out, rc);
        } else {
regular_open:
                /* We did not try to create, so we are a pure open */
                rc = mdt_reint_open(info, lhc);
        }

        EXIT;
out:
        req->rq_status = rc;
        lustre_msg_set_status(req->rq_repmsg, req->rq_status);
        LASSERT(ergo(rc < 0, lustre_msg_get_transno(req->rq_repmsg) == 0));
}

static int mdt_open_by_fid(struct mdt_thread_info* info,
                           struct ldlm_reply *rep)
{
        const struct lu_env     *env = info->mti_env;
        __u32                    flags = info->mti_spec.sp_cr_flags;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_object       *o;
        int                      rc;
        ENTRY;

        o = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid2);
        if (IS_ERR(o))
                RETURN(rc = PTR_ERR(o));

        rc = mdt_object_exists(o);
        if (rc > 0) {
                mdt_set_disposition(info, rep, (DISP_IT_EXECD |
                                                DISP_LOOKUP_EXECD |
                                                DISP_LOOKUP_POS));

                rc = mo_attr_get(env, mdt_object_child(o), ma);
                if (rc == 0)
                        rc = mdt_finish_open(info, NULL, o, flags, 0, rep);
        } else if (rc == 0) {
                rc = -ENOENT;
        } else  {
                /* the child object was created on remote server */
                struct mdt_body *repbody;
                repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
                repbody->fid1 = *rr->rr_fid2;
                repbody->valid |= (OBD_MD_FLID | OBD_MD_MDS);
                rc = 0;
        }

        mdt_object_put(info->mti_env, o);
        RETURN(rc);
}

int mdt_pin(struct mdt_thread_info* info)
{
        ENTRY;
        RETURN(err_serious(-EOPNOTSUPP));
}

/* Cross-ref request. Currently it can only be a pure open (w/o create) */
static int mdt_cross_open(struct mdt_thread_info* info,
                          const struct lu_fid *fid,
                          struct ldlm_reply *rep, __u32 flags)
{
        struct md_attr    *ma = &info->mti_attr;
        struct mdt_object *o;
        int                rc;
        ENTRY;

        o = mdt_object_find(info->mti_env, info->mti_mdt, fid);
        if (IS_ERR(o))
                RETURN(rc = PTR_ERR(o));

        rc = mdt_object_exists(o);
        if (rc > 0) {
                /* Do permission check for cross-open. */
                rc = mo_permission(info->mti_env, NULL, mdt_object_child(o),
                                   NULL, flags | MDS_OPEN_CROSS);
                if (rc)
                        goto out;

                mdt_set_capainfo(info, 0, fid, BYPASS_CAPA);
                rc = mo_attr_get(info->mti_env, mdt_object_child(o), ma);
                if (rc == 0)
                        rc = mdt_finish_open(info, NULL, o, flags, 0, rep);
        } else if (rc == 0) {
                /*
                 * Something is wrong here. lookup was positive but there is
                 * no object!
                 */
                CERROR("Cross-ref object doesn't exist!\n");
                rc = -EFAULT;
        } else  {
                /* Something is wrong here, the object is on another MDS! */
                CERROR("The object isn't on this server! FLD error?\n");
                LU_OBJECT_DEBUG(D_WARNING, info->mti_env,
                                &o->mot_obj.mo_lu,
                                "Object isn't on this server! FLD error?\n");

                rc = -EFAULT;
        }

out:
        mdt_object_put(info->mti_env, o);
        RETURN(rc);
}

int mdt_reint_open(struct mdt_thread_info *info, struct mdt_lock_handle *lhc)
{
        struct mdt_device       *mdt = info->mti_mdt;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_object       *parent;
        struct mdt_object       *child;
        struct mdt_lock_handle  *lh;
        struct ldlm_reply       *ldlm_rep;
        struct mdt_body         *repbody;
        struct lu_fid           *child_fid = &info->mti_tmp_fid1;
        struct md_attr          *ma = &info->mti_attr;
        __u32                    create_flags = info->mti_spec.sp_cr_flags;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct lu_name          *lname;
        int                      result, rc;
        int                      created = 0;
        __u32                    msg_flags;
        ENTRY;

        OBD_FAIL_TIMEOUT_ORSET(OBD_FAIL_MDS_PAUSE_OPEN, OBD_FAIL_ONCE,
                               (obd_timeout + 1) / 4);

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        ma->ma_lmm = req_capsule_server_get(info->mti_pill, &RMF_MDT_MD);
        ma->ma_lmm_size = req_capsule_get_size(info->mti_pill, &RMF_MDT_MD,
                                               RCL_SERVER);
        ma->ma_need = MA_INODE | MA_LOV;
        ma->ma_valid = 0;

        LASSERT(info->mti_pill->rc_fmt == &RQF_LDLM_INTENT_OPEN);
        ldlm_rep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);

        /* TODO: JOIN file */
        if (create_flags & MDS_OPEN_JOIN_FILE) {
                CERROR("JOIN file will be supported soon\n");
                GOTO(out, result = err_serious(-EOPNOTSUPP));
        }
        msg_flags = lustre_msg_get_flags(req->rq_reqmsg);

        CDEBUG(D_INODE, "I am going to open "DFID"/(%s->"DFID") "
               "cr_flag=0%o mode=0%06o msg_flag=0x%x\n",
               PFID(rr->rr_fid1), rr->rr_name,
               PFID(rr->rr_fid2), create_flags,
               ma->ma_attr.la_mode, msg_flags);

        if (msg_flags & MSG_REPLAY ||
            (req->rq_export->exp_libclient && create_flags&MDS_OPEN_HAS_EA)) {
                /* This is a replay request or from liblustre with ea. */
                result = mdt_open_by_fid(info, ldlm_rep);

                if (result != -ENOENT) {
                        if (req->rq_export->exp_libclient &&
                            create_flags&MDS_OPEN_HAS_EA)
                                GOTO(out, result = 0);
                        GOTO(out, result);
                }
                /*
                 * We didn't find the correct object, so we need to re-create it
                 * via a regular replay.
                 */
                if (!(create_flags & MDS_OPEN_CREAT)) {
                        DEBUG_REQ(D_ERROR, req,"OPEN & CREAT not in open replay.");
                        GOTO(out, result = -EFAULT);
                }
                CDEBUG(D_INFO, "Open replay did find object, continue as "
                       "regular open\n");
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK))
                GOTO(out, result = err_serious(-ENOMEM));

        mdt_set_disposition(info, ldlm_rep,
                            (DISP_IT_EXECD | DISP_LOOKUP_EXECD));

        if (info->mti_cross_ref) {
                /* This is cross-ref open */
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
                result = mdt_cross_open(info, rr->rr_fid1, ldlm_rep,
                                        create_flags);
                GOTO(out, result);
        }

        lh = &info->mti_lh[MDT_LH_PARENT];
        mdt_lock_pdo_init(lh, (create_flags & MDS_OPEN_CREAT) ?
                          LCK_PW : LCK_PR, rr->rr_name, rr->rr_namelen);

        parent = mdt_object_find_lock(info, rr->rr_fid1, lh,
                                      MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                GOTO(out, result = PTR_ERR(parent));

        fid_zero(child_fid);

        lname = mdt_name(info->mti_env, (char *)rr->rr_name, rr->rr_namelen);

        result = mdo_lookup(info->mti_env, mdt_object_child(parent),
                            lname, child_fid, &info->mti_spec);
        LASSERTF(ergo(result == 0, fid_is_sane(child_fid)),
                 "looking for "DFID"/%s, result fid="DFID"\n",
                 PFID(mdt_object_fid(parent)), rr->rr_name, PFID(child_fid));

        if (result != 0 && result != -ENOENT && result != -ESTALE)
                GOTO(out_parent, result);

        if (result == -ENOENT || result == -ESTALE) {
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_NEG);
                if (result == -ESTALE) {
                        /*
                         * -ESTALE means the parent is a dead(unlinked) dir, so
                         * it should return -ENOENT to in accordance with the
                         * original mds implementaion.
                         */
                        GOTO(out_parent, result = -ENOENT);
                }
                if (!(create_flags & MDS_OPEN_CREAT))
                        GOTO(out_parent, result);
                *child_fid = *info->mti_rr.rr_fid2;
                LASSERTF(fid_is_sane(child_fid), "fid="DFID"\n",
                         PFID(child_fid));
        } else {
                /*
                 * Check for O_EXCL is moved to the mdt_finish_open(), we need to
                 * return FID back in that case.
                 */
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
        }

        child = mdt_object_find(info->mti_env, mdt, child_fid);
        if (IS_ERR(child))
                GOTO(out_parent, result = PTR_ERR(child));

        mdt_set_capainfo(info, 1, child_fid, BYPASS_CAPA);
        if (result == -ENOENT) {
                /* Not found and with MDS_OPEN_CREAT: let's create it. */
                mdt_set_disposition(info, ldlm_rep, DISP_OPEN_CREATE);

                /* Let lower layers know what is lock mode on directory. */
                info->mti_spec.sp_cr_mode =
                        mdt_dlm_mode2mdl_mode(lh->mlh_pdo_mode);

                /*
                 * Do not perform lookup sanity check. We know that name does
                 * not exist.
                 */
                info->mti_spec.sp_cr_lookup = 0;

                result = mdo_create(info->mti_env,
                                    mdt_object_child(parent),
                                    lname,
                                    mdt_object_child(child),
                                    &info->mti_spec,
                                    &info->mti_attr);
                if (result == -ERESTART) {
                        mdt_clear_disposition(info, ldlm_rep, DISP_OPEN_CREATE);
                        GOTO(out_child, result);
                } else {
                        if (result != 0)
                                GOTO(out_child, result);
                }
                created = 1;
        } else {
                /* We have to get attr & lov ea for this object */
                result = mo_attr_get(info->mti_env, mdt_object_child(child),
                                     ma);
                /*
                 * The object is on remote node, return its FID for remote open.
                 */
                if (result == -EREMOTE) {
                        /*
                         * Check if this lock already was sent to client and
                         * this is resent case. For resent case do not take lock
                         * again, use what is already granted.
                         */
                        LASSERT(lhc != NULL);

                        if (lustre_handle_is_used(&lhc->mlh_reg_lh)) {
                                struct ldlm_lock *lock;

                                LASSERT(msg_flags & MSG_RESENT);

                                lock = ldlm_handle2lock(&lhc->mlh_reg_lh);
                                if (!lock) {
                                        CERROR("Invalid lock handle "LPX64"\n",
                                               lhc->mlh_reg_lh.cookie);
                                        LBUG();
                                }
                                LASSERT(fid_res_name_eq(mdt_object_fid(child),
                                                        &lock->l_resource->lr_name));
                                LDLM_LOCK_PUT(lock);
                                rc = 0;
                        } else {
                                mdt_lock_handle_init(lhc);
                                mdt_lock_reg_init(lhc, LCK_PR);

                                rc = mdt_object_lock(info, child, lhc,
                                                     MDS_INODELOCK_LOOKUP,
                                                     MDT_CROSS_LOCK);
                        }
                        repbody->fid1 = *mdt_object_fid(child);
                        repbody->valid |= (OBD_MD_FLID | OBD_MD_MDS);
                        if (rc != 0)
                                result = rc;
                        GOTO(out_child, result);
                }
        }

        LASSERT(!lustre_handle_is_used(&lhc->mlh_reg_lh));

        /* get openlock if this is not replay and if a client requested it */
        if (!(msg_flags & MSG_REPLAY) && create_flags & MDS_OPEN_LOCK) {
                ldlm_mode_t lm;

                LASSERT(!created);
                if (create_flags & FMODE_WRITE)
                        lm = LCK_CW;
                else if (create_flags & MDS_FMODE_EXEC)
                        lm = LCK_PR;
                else
                        lm = LCK_CR;
                mdt_lock_handle_init(lhc);
                mdt_lock_reg_init(lhc, lm);
                rc = mdt_object_lock(info, child, lhc,
                                     MDS_INODELOCK_LOOKUP | MDS_INODELOCK_OPEN,
                                     MDT_CROSS_LOCK);
                if (rc) {
                        result = rc;
                        GOTO(out_child, result);
                } else {
                        result = -EREMOTE;
                        mdt_set_disposition(info, ldlm_rep, DISP_OPEN_LOCK);
                }
        }

        /* Try to open it now. */
        rc = mdt_finish_open(info, parent, child, create_flags,
                             created, ldlm_rep);
        if (rc) {
                result = rc;
                if (lustre_handle_is_used(&lhc->mlh_reg_lh))
                        /* openlock was acquired and mdt_finish_open failed -
                           drop the openlock */
                        mdt_object_unlock(info, child, lhc, 1);
                if (created) {
                        ma->ma_need = 0;
                        ma->ma_valid = 0;
                        ma->ma_cookie_size = 0;
                        info->mti_no_need_trans = 1;
                        rc = mdo_unlink(info->mti_env,
                                        mdt_object_child(parent),
                                        mdt_object_child(child),
                                        lname,
                                        &info->mti_attr);
                        if (rc != 0)
                                CERROR("Error in cleanup of open\n");
                }
        }
        EXIT;
out_child:
        mdt_object_put(info->mti_env, child);
out_parent:
        mdt_object_unlock_put(info, parent, lh, result);
out:
        if (result && result != -EREMOTE)
                lustre_msg_set_transno(req->rq_repmsg, 0);
        return result;
}

#define MFD_CLOSED(mode) (((mode) & ~(FMODE_EPOCH | FMODE_SOM | \
                                      FMODE_EPOCHLCK)) == FMODE_CLOSED)

static int mdt_mfd_closed(struct mdt_file_data *mfd)
{
        return ((mfd == NULL) || MFD_CLOSED(mfd->mfd_mode));
}

int mdt_mfd_close(struct mdt_thread_info *info, struct mdt_file_data *mfd)
{
        struct mdt_object *o = mfd->mfd_object;
        struct md_object *next = mdt_object_child(o);
        struct md_attr *ma = &info->mti_attr;
        int rc = 0, ret = 0;
        int mode;
        ENTRY;

        mode = mfd->mfd_mode;

        if ((mode & FMODE_WRITE) || (mode & FMODE_EPOCHLCK)) {
                mdt_write_put(info->mti_mdt, o);
                ret = mdt_epoch_close(info, o);
        } else if (mode & MDS_FMODE_EXEC) {
                mdt_write_allow(info->mti_mdt, o);
        } else if (mode & FMODE_EPOCH) {
                ret = mdt_epoch_close(info, o);
        }

        /* Update atime on close only. */
        if ((mode & MDS_FMODE_EXEC || mode & FMODE_READ || mode & FMODE_WRITE)
            && (ma->ma_valid & MA_INODE) && (ma->ma_attr.la_valid & LA_ATIME)) {
                /* Set the atime only. */
                ma->ma_attr.la_valid = LA_ATIME;
                rc = mo_attr_set(info->mti_env, next, ma);
        }

        ma->ma_need |= MA_INODE;
        ma->ma_valid = 0;

        if (!MFD_CLOSED(mode))
                rc = mo_close(info->mti_env, next, ma);
        else if (ret == -EAGAIN)
                rc = mo_attr_get(info->mti_env, next, ma);

        /* If the object is unlinked, do not try to re-enable SIZEONMDS */
        if ((ret == -EAGAIN) && (ma->ma_valid & MA_INODE) &&
            (ma->ma_attr.la_nlink == 0)) {
                ret = 0;
        }

        if ((ret == -EAGAIN) || (ret == 1)) {
                struct mdt_export_data *med;

                /* The epoch has not closed or Size-on-MDS update is needed.
                 * Put mfd back into the list. */
                LASSERT(mdt_conn_flags(info) & OBD_CONNECT_SOM);
                mdt_mfd_set_mode(mfd, (ret == 1 ? FMODE_EPOCH : FMODE_SOM));

                LASSERT(mdt_info_req(info));
                med = &mdt_info_req(info)->rq_export->exp_mdt_data;
                spin_lock(&med->med_open_lock);
                list_add(&mfd->mfd_list, &med->med_open_head);
                class_handle_hash_back(&mfd->mfd_handle);
                spin_unlock(&med->med_open_lock);

                if (ret == 1) {
                        ret = 0;
                } else {
                        CDEBUG(D_INODE, "Size-on-MDS attribute update is "
                               "needed on "DFID"\n", PFID(mdt_object_fid(o)));
                }
        } else {
                mdt_mfd_free(mfd);
                mdt_object_put(info->mti_env, o);
        }

        RETURN(rc ? rc : ret);
}

int mdt_close(struct mdt_thread_info *info)
{
        struct mdt_export_data *med;
        struct mdt_file_data   *mfd;
        struct mdt_object      *o;
        struct md_attr         *ma = &info->mti_attr;
        struct mdt_body        *repbody = NULL;
        struct ptlrpc_request  *req = mdt_info_req(info);
        int rc, ret = 0;
        ENTRY;

        /* Close may come with the Size-on-MDS update. Unpack it. */
        rc = mdt_close_unpack(info);
        if (rc)
                RETURN(err_serious(rc));

        LASSERT(info->mti_epoch);

        req_capsule_set_size(info->mti_pill, &RMF_MDT_MD, RCL_SERVER,
                             info->mti_mdt->mdt_max_mdsize);
        req_capsule_set_size(info->mti_pill, &RMF_LOGCOOKIES, RCL_SERVER,
                             info->mti_mdt->mdt_max_cookiesize);
        rc = req_capsule_server_pack(info->mti_pill);
        if (mdt_check_resent(info, mdt_reconstruct_generic, NULL))
                RETURN(lustre_msg_get_status(req->rq_repmsg));

        /* Continue to close handle even if we can not pack reply */
        if (rc == 0) {
                repbody = req_capsule_server_get(info->mti_pill,
                                                 &RMF_MDT_BODY);
                ma->ma_lmm = req_capsule_server_get(info->mti_pill,
                                                    &RMF_MDT_MD);
                ma->ma_lmm_size = req_capsule_get_size(info->mti_pill,
                                                       &RMF_MDT_MD,
                                                       RCL_SERVER);
                ma->ma_cookie = req_capsule_server_get(info->mti_pill,
                                                       &RMF_LOGCOOKIES);
                ma->ma_cookie_size = req_capsule_get_size(info->mti_pill,
                                                          &RMF_LOGCOOKIES,
                                                          RCL_SERVER);
                ma->ma_need = MA_INODE | MA_LOV | MA_COOKIE;
                repbody->eadatasize = 0;
                repbody->aclsize = 0;
        } else
                rc = err_serious(rc);

        med = &req->rq_export->exp_mdt_data;
        spin_lock(&med->med_open_lock);
        mfd = mdt_handle2mfd(info, &info->mti_epoch->handle);
        if (mdt_mfd_closed(mfd)) {
                spin_unlock(&med->med_open_lock);
                CDEBUG(D_INODE, "no handle for file close: fid = "DFID
                       ": cookie = "LPX64"\n", PFID(info->mti_rr.rr_fid1),
                       info->mti_epoch->handle.cookie);
                rc = err_serious(-ESTALE);
        } else {
                class_handle_unhash(&mfd->mfd_handle);
                list_del_init(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);

                /* Do not lose object before last unlink. */
                o = mfd->mfd_object;
                mdt_object_get(info->mti_env, o);
                ret = mdt_mfd_close(info, mfd);
                if (repbody != NULL)
                        rc = mdt_handle_last_unlink(info, o, ma);
                mdt_empty_transno(info);
                mdt_object_put(info->mti_env, o);
        }
        if (repbody != NULL)
                mdt_shrink_reply(info);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK))
                RETURN(err_serious(-ENOMEM));

        if (OBD_FAIL_CHECK_RESET(OBD_FAIL_MDS_CLOSE_NET_REP,
                                 OBD_FAIL_MDS_CLOSE_NET_REP))
                info->mti_fail_id = OBD_FAIL_MDS_CLOSE_NET_REP;
        RETURN(rc ? rc : ret);
}

int mdt_done_writing(struct mdt_thread_info *info)
{
        struct mdt_body         *repbody = NULL;
        struct mdt_export_data  *med;
        struct mdt_file_data    *mfd;
        int rc;
        ENTRY;

        rc = req_capsule_server_pack(info->mti_pill);
        if (rc)
                RETURN(err_serious(rc));

        repbody = req_capsule_server_get(info->mti_pill,
                                         &RMF_MDT_BODY);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        /* Done Writing may come with the Size-on-MDS update. Unpack it. */
        rc = mdt_close_unpack(info);
        if (rc)
                RETURN(err_serious(rc));

        if (mdt_check_resent(info, mdt_reconstruct_generic, NULL))
                RETURN(lustre_msg_get_status(mdt_info_req(info)->rq_repmsg));

        med = &info->mti_exp->exp_mdt_data;
        spin_lock(&med->med_open_lock);
        mfd = mdt_handle2mfd(info, &info->mti_epoch->handle);
        if (mfd == NULL) {
                spin_unlock(&med->med_open_lock);
                CDEBUG(D_INODE, "no handle for done write: fid = "DFID
                       ": cookie = "LPX64"\n", PFID(info->mti_rr.rr_fid1),
                       info->mti_epoch->handle.cookie);
                RETURN(-ESTALE);
        }

        LASSERT(mfd->mfd_mode == FMODE_EPOCH ||
                mfd->mfd_mode == FMODE_EPOCHLCK);
        class_handle_unhash(&mfd->mfd_handle);
        list_del_init(&mfd->mfd_list);
        spin_unlock(&med->med_open_lock);

        /* Set EPOCH CLOSE flag if not set by client. */
        info->mti_epoch->flags |= MF_EPOCH_CLOSE;
        info->mti_attr.ma_valid = 0;
        rc = mdt_mfd_close(info, mfd);
        mdt_empty_transno(info);
        RETURN(rc);
}
