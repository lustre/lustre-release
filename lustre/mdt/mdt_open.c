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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
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

#define DEBUG_SUBSYSTEM S_MDS

#include <lustre_acl.h>
#include <lustre_mds.h>
#include "mdt_internal.h"

/* we do nothing because we do not have refcount now */
static void mdt_mfd_get(void *mfdp)
{
}

static struct portals_handle_ops mfd_handle_ops = {
	.hop_addref = mdt_mfd_get,
	.hop_free   = NULL,
};

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
		class_handle_hash(&mfd->mfd_handle, &mfd_handle_ops);
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
        if (mfd == NULL && req_is_replay(req)) {
                struct mdt_export_data *med = &req->rq_export->exp_mdt_data;
                cfs_list_for_each_entry(mfd, &med->med_open_head, mfd_list) {
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
        LASSERT(cfs_list_empty(&mfd->mfd_list));
        OBD_FREE_RCU(mfd, sizeof *mfd, &mfd->mfd_handle);
}

static int mdt_create_data(struct mdt_thread_info *info,
                           struct mdt_object *p, struct mdt_object *o)
{
        struct md_op_spec     *spec = &info->mti_spec;
        struct md_attr        *ma   = &info->mti_attr;
        int                    rc   = 0;
        ENTRY;

        if (!md_should_create(spec->sp_cr_flags))
                RETURN(0);

        ma->ma_need = MA_INODE | MA_LOV;
        ma->ma_valid = 0;
        cfs_mutex_lock(&o->mot_lov_mutex);
        if (!(o->mot_flags & MOF_LOV_CREATED)) {
                rc = mdo_create_data(info->mti_env,
                                     p ? mdt_object_child(p) : NULL,
                                     mdt_object_child(o), spec, ma);
                if (rc == 0 && ma->ma_valid & MA_LOV)
                        o->mot_flags |= MOF_LOV_CREATED;
        }
        cfs_mutex_unlock(&o->mot_lov_mutex);
        RETURN(rc);
}

static int mdt_ioepoch_opened(struct mdt_object *mo)
{
        return mo->mot_ioepoch_count;
}

int mdt_object_is_som_enabled(struct mdt_object *mo)
{
        return !mo->mot_ioepoch;
}

/**
 * Re-enable Size-on-MDS.
 * Call under ->mot_ioepoch_mutex.
 */
static void mdt_object_som_enable(struct mdt_object *mo, __u64 ioepoch)
{
        if (ioepoch == mo->mot_ioepoch) {
                LASSERT(!mdt_ioepoch_opened(mo));
                mo->mot_ioepoch = 0;
                mo->mot_flags = 0;
        }
}

/**
 * Open the IOEpoch. It is allowed if @writecount is not negative.
 * The epoch and writecount handling is performed under the mot_ioepoch_mutex.
 */
int mdt_ioepoch_open(struct mdt_thread_info *info, struct mdt_object *o,
                     int created)
{
        struct mdt_device *mdt = info->mti_mdt;
        int cancel = 0;
        int rc = 0;
        ENTRY;

        if (!(mdt_conn_flags(info) & OBD_CONNECT_SOM) ||
            !S_ISREG(lu_object_attr(&o->mot_obj.mo_lu)))
                RETURN(0);

        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        if (mdt_ioepoch_opened(o)) {
                /* Epoch continues even if there is no writers yet. */
                CDEBUG(D_INODE, "continue epoch "LPU64" for "DFID"\n",
                       o->mot_ioepoch, PFID(mdt_object_fid(o)));
        } else {
                /* XXX: ->mdt_ioepoch is not initialized at the mount */
                cfs_spin_lock(&mdt->mdt_ioepoch_lock);
                if (mdt->mdt_ioepoch < info->mti_replayepoch)
                        mdt->mdt_ioepoch = info->mti_replayepoch;

                if (info->mti_replayepoch)
                        o->mot_ioepoch = info->mti_replayepoch;
                else if (++mdt->mdt_ioepoch == IOEPOCH_INVAL)
                        o->mot_ioepoch = ++mdt->mdt_ioepoch;
                else
                        o->mot_ioepoch = mdt->mdt_ioepoch;

                cfs_spin_unlock(&mdt->mdt_ioepoch_lock);

                CDEBUG(D_INODE, "starting epoch "LPU64" for "DFID"\n",
                       o->mot_ioepoch, PFID(mdt_object_fid(o)));
                if (created)
                        o->mot_flags |= MOF_SOM_CREATED;
                cancel = 1;
        }
        o->mot_ioepoch_count++;
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);

        /* Cancel Size-on-MDS attributes cached on clients for the open case.
         * In the truncate case, see mdt_reint_setattr(). */
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

/**
 * Update SOM on-disk attributes.
 * If enabling, write update inodes and lustre-ea with the proper IOEpoch,
 * mountid and attributes. If disabling, zero IOEpoch id in lustre-ea.
 * Call under ->mot_ioepoch_mutex.
 */
static int mdt_som_attr_set(struct mdt_thread_info *info,
                            struct mdt_object *obj, __u64 ioepoch, int enable)
{
        struct md_attr *ma = &info->mti_attr;
        int rc;
        ENTRY;

        CDEBUG(D_INODE, "Size-on-MDS attribute %s for epoch "LPU64
               " on "DFID".\n", enable ? "update" : "disabling",
               ioepoch, PFID(mdt_object_fid(obj)));

        ma->ma_valid |= MA_SOM;
        ma->ma_som = &info->mti_u.som.data;
        if (enable) {
                struct mdt_device *mdt = info->mti_mdt;
                struct lu_attr *la = &ma->ma_attr;

                ma->ma_som->msd_ioepoch = ioepoch;
                ma->ma_som->msd_size = la->la_valid & LA_SIZE ? la->la_size : 0;
                ma->ma_som->msd_blocks = la->la_valid & LA_BLOCKS ?
                                         la->la_blocks : 0;
                ma->ma_som->msd_mountid = mdt->mdt_lut.lut_obd->u.obt.obt_mount_count;
                ma->ma_attr.la_valid &= LA_ATIME | LA_MTIME | LA_CTIME;
        } else {
                ma->ma_som->msd_ioepoch = IOEPOCH_INVAL;
                ma->ma_attr.la_valid &= LA_ATIME;
        }

        /* Since we have opened the file, it is unnecessary
         * to check permission when close it. Between the "open"
         * and "close", maybe someone has changed the file mode
         * or flags, or the file created mode do not permit wirte,
         * and so on. Just set MDS_PERM_BYPASS for all the cases. */
        ma->ma_attr_flags |= MDS_PERM_BYPASS | MDS_SOM;

        rc = mdt_attr_set(info, obj, ma, 0);
        RETURN(rc);
}

/** Perform the eviction specific actions on ioepoch close. */
static inline int mdt_ioepoch_close_on_eviction(struct mdt_thread_info *info,
                                                struct mdt_object *o)
{
        int rc = 0;

        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        CDEBUG(D_INODE, "Eviction. Closing IOepoch "LPU64" on "DFID". "
               "Count %d\n", o->mot_ioepoch, PFID(mdt_object_fid(o)),
               o->mot_ioepoch_count);
        o->mot_ioepoch_count--;

        /* If eviction occured set MOF_SOM_RECOV,
         * if no other epoch holders, disable SOM on disk. */
        o->mot_flags |= MOF_SOM_CHANGE | MOF_SOM_RECOV;
        if (!mdt_ioepoch_opened(o)) {
                rc = mdt_som_attr_set(info, o, o->mot_ioepoch, MDT_SOM_DISABLE);
                mdt_object_som_enable(o, o->mot_ioepoch);
        }
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);
        RETURN(rc);
}

/**
 * Perform the replay specific actions on ioepoch close.
 * Skip SOM attribute update if obtained and just forget about the inode state
 * for the last ioepoch holder. The SOM cache is invalidated on MDS failure.
 */
static inline int mdt_ioepoch_close_on_replay(struct mdt_thread_info *info,
                                              struct mdt_object *o)
{
        int rc = MDT_IOEPOCH_CLOSED;
        ENTRY;

        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        CDEBUG(D_INODE, "Replay. Closing epoch "LPU64" on "DFID". Count %d\n",
               o->mot_ioepoch, PFID(mdt_object_fid(o)), o->mot_ioepoch_count);
        o->mot_ioepoch_count--;

        /* Get an info from the replayed request if client is supposed
         * to send an Attibute Update, reconstruct @rc if so */
        if (info->mti_ioepoch->flags & MF_SOM_AU)
                rc = MDT_IOEPOCH_GETATTR;

        if (!mdt_ioepoch_opened(o))
                mdt_object_som_enable(o, info->mti_ioepoch->ioepoch);
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);

        RETURN(rc);
}

/**
 * Regular file IOepoch close.
 * Closes the ioepoch, checks the object state, apply obtained attributes and
 * re-enable SOM on the object, if possible. Also checks if the recovery is
 * needed and packs OBD_MD_FLGETATTRLOCK flag into the reply to force the client
 * to obtain SOM attributes under the server-side OST locks.
 *
 * Return value:
 * MDT_IOEPOCH_CLOSED if ioepoch is closed.
 * MDT_IOEPOCH_GETATTR if ioepoch is closed but another SOM update is needed.
 */
static inline int mdt_ioepoch_close_reg(struct mdt_thread_info *info,
                                        struct mdt_object *o)
{
        struct md_attr *tmp_ma;
        struct lu_attr *la;
        int achange, opened;
        int recovery = 0;
        int rc = 0, ret = MDT_IOEPOCH_CLOSED;
        ENTRY;

        la = &info->mti_attr.ma_attr;
        achange = (info->mti_ioepoch->flags & MF_SOM_CHANGE);

        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        o->mot_ioepoch_count--;

        tmp_ma = &info->mti_u.som.attr;
        tmp_ma->ma_lmm = info->mti_attr.ma_lmm;
        tmp_ma->ma_lmm_size = info->mti_attr.ma_lmm_size;
        tmp_ma->ma_som = &info->mti_u.som.data;
        tmp_ma->ma_need = MA_INODE | MA_LOV | MA_SOM;
        tmp_ma->ma_valid = 0;
        rc = mo_attr_get(info->mti_env, mdt_object_child(o), tmp_ma);
        if (rc)
                GOTO(error_up, rc);

        /* Check the on-disk SOM state. */
        if (o->mot_flags & MOF_SOM_RECOV)
                recovery = 1;
        else if (!(o->mot_flags & MOF_SOM_CREATED) &&
                 !(tmp_ma->ma_valid & MA_SOM))
                recovery = 1;

        CDEBUG(D_INODE, "Closing epoch "LPU64" on "DFID". Count %d\n",
               o->mot_ioepoch, PFID(mdt_object_fid(o)), o->mot_ioepoch_count);

        opened = mdt_ioepoch_opened(o);
        /**
         * If IOEpoch is not opened, check if a Size-on-MDS update is needed.
         * Skip the check for file with no LOV  or for unlink files.
         */
        if (!opened && tmp_ma->ma_valid & MA_LOV &&
            !(tmp_ma->ma_valid & MA_INODE && tmp_ma->ma_attr.la_nlink == 0)) {
                if (recovery)
                        /* If some previous writer was evicted, re-ask the
                         * client for attributes. Even if attributes are
                         * provided, we cannot believe in them.
                         * Another use case is that there is no SOM cache on
                         * disk -- first access with SOM or there was an MDS
                         * failure. */
                        ret = MDT_IOEPOCH_GETATTR;
                else if (o->mot_flags & MOF_SOM_CHANGE)
                        /* Some previous writer changed the attribute.
                         * Do not believe to the current Size-on-MDS
                         * update, re-ask client. */
                        ret = MDT_IOEPOCH_GETATTR;
                else if (!(la->la_valid & LA_SIZE) && achange)
                        /* Attributes were changed by the last writer
                         * only but no Size-on-MDS update is received.*/
                        ret = MDT_IOEPOCH_GETATTR;
        }

        if (achange || ret == MDT_IOEPOCH_GETATTR)
                o->mot_flags |= MOF_SOM_CHANGE;

        /* If epoch ends and relable SOM attributes are obtained, update them.
         * Create SOM ea for new files even if there is no attributes obtained
         * (0-length file). */
        if (ret == MDT_IOEPOCH_CLOSED && !opened) {
                if (achange || o->mot_flags & MOF_SOM_CREATED) {
                        LASSERT(achange || !(la->la_valid & LA_SIZE));
                        rc = mdt_som_attr_set(info, o, o->mot_ioepoch,
                                              MDT_SOM_ENABLE);
                        /* Avoid the following setattrs of these attributes,
                         * e.g. for atime update. */
                        info->mti_attr.ma_valid = 0;
                }
                mdt_object_som_enable(o, o->mot_ioepoch);
        }

        cfs_mutex_unlock(&o->mot_ioepoch_mutex);
        /* If recovery is needed, tell the client to perform GETATTR under
         * the lock. */
        if (ret == MDT_IOEPOCH_GETATTR && recovery) {
                struct mdt_body *rep;
                rep = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
                rep->valid |= OBD_MD_FLGETATTRLOCK;
        }

        RETURN(rc ? : ret);

error_up:
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);
        return rc;
}

/**
 * Close IOEpoch (opened file or MDS_FMODE_EPOCH state). It happens if:
 * - a client closes the IOEpoch;
 * - a client eviction occured.
 * Return values:
 * MDT_IOEPOCH_OPENED if the client does not close IOEpoch.
 * MDT_IOEPOCH_CLOSED if the client closes IOEpoch.
 * MDT_IOEPOCH_GETATTR if the client closes IOEpoch but another SOM attribute
 * update is needed.
 */
static int mdt_ioepoch_close(struct mdt_thread_info *info, struct mdt_object *o)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        ENTRY;

        if (!(mdt_conn_flags(info) & OBD_CONNECT_SOM) ||
            !S_ISREG(lu_object_attr(&o->mot_obj.mo_lu)))
                RETURN(0);

        LASSERT(o->mot_ioepoch_count);
        LASSERT(info->mti_ioepoch == NULL ||
                info->mti_ioepoch->ioepoch == o->mot_ioepoch);

        /* IOEpoch is closed only if client tells about it or eviction occures.
         * In the replay case, always close the epoch. */
        if (req == NULL)
                RETURN(mdt_ioepoch_close_on_eviction(info, o));
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY)
                RETURN(mdt_ioepoch_close_on_replay(info, o));
        if (info->mti_ioepoch->flags & MF_EPOCH_CLOSE)
                RETURN(mdt_ioepoch_close_reg(info, o));
        /* IO epoch is not closed. */
        RETURN(MDT_IOEPOCH_OPENED);
}

/**
 * Close MDS_FMODE_SOM state, when IOEpoch is already closed and we are waiting
 * for attribute update. It happens if:
 * - SOM Attribute Update is obtained;
 * - the client failed to obtain it and informs MDS about it;
 * - a client eviction occured.
 * Apply obtained attributes for the 1st case, wipe out the on-disk SOM
 * cache otherwise.
 */
int mdt_som_au_close(struct mdt_thread_info *info, struct mdt_object *o)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        __u64 ioepoch = 0;
        int act = MDT_SOM_ENABLE;
        int rc = 0;
        ENTRY;

        LASSERT(!req || info->mti_ioepoch);
        if (!(mdt_conn_flags(info) & OBD_CONNECT_SOM) ||
            !S_ISREG(lu_object_attr(&o->mot_obj.mo_lu)))
                RETURN(0);

        /* No size whereas MF_SOM_CHANGE is set means client failed to
         * obtain ost attributes, drop the SOM cache on disk if so. */
        if (!req ||
            (info->mti_ioepoch &&
             info->mti_ioepoch->flags & MF_SOM_CHANGE &&
             !(info->mti_attr.ma_attr.la_valid & LA_SIZE)))
                act = MDT_SOM_DISABLE;

        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        /* Mark the object it is the recovery state if we failed to obtain
         * SOM attributes. */
        if (act == MDT_SOM_DISABLE)
                o->mot_flags |= MOF_SOM_RECOV;

        if (!mdt_ioepoch_opened(o)) {
                ioepoch =  info->mti_ioepoch ?
                        info->mti_ioepoch->ioepoch : o->mot_ioepoch;

                if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY))
                        rc = mdt_som_attr_set(info, o, ioepoch, act);
                mdt_object_som_enable(o, ioepoch);
        }
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);
        RETURN(rc);
}

int mdt_write_read(struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        rc = o->mot_writecount;
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);
        RETURN(rc);
}

int mdt_write_get(struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        if (o->mot_writecount < 0)
                rc = -ETXTBSY;
        else
                o->mot_writecount++;
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);
        RETURN(rc);
}

void mdt_write_put(struct mdt_object *o)
{
        ENTRY;
        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        o->mot_writecount--;
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);
        EXIT;
}

static int mdt_write_deny(struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        if (o->mot_writecount > 0)
                rc = -ETXTBSY;
        else
                o->mot_writecount--;
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);
        RETURN(rc);
}

static void mdt_write_allow(struct mdt_object *o)
{
        ENTRY;
        cfs_mutex_lock(&o->mot_ioepoch_mutex);
        o->mot_writecount++;
        cfs_mutex_unlock(&o->mot_ioepoch_mutex);
        EXIT;
}

/* there can be no real transaction so prepare the fake one */
static void mdt_empty_transno(struct mdt_thread_info *info, int rc)
{
        struct mdt_device      *mdt = info->mti_mdt;
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct tg_export_data  *ted;
        struct lsd_client_data *lcd;

        ENTRY;
        /* transaction has occurred already */
        if (lustre_msg_get_transno(req->rq_repmsg) != 0)
                RETURN_EXIT;

        cfs_spin_lock(&mdt->mdt_lut.lut_translock);
        if (info->mti_transno == 0) {
                info->mti_transno = ++ mdt->mdt_lut.lut_last_transno;
        } else {
                /* should be replay */
                if (info->mti_transno > mdt->mdt_lut.lut_last_transno)
                        mdt->mdt_lut.lut_last_transno = info->mti_transno;
        }
        cfs_spin_unlock(&mdt->mdt_lut.lut_translock);

        CDEBUG(D_INODE, "transno = "LPU64", last_committed = "LPU64"\n",
                        info->mti_transno,
                        req->rq_export->exp_obd->obd_last_committed);

        req->rq_transno = info->mti_transno;
        lustre_msg_set_transno(req->rq_repmsg, info->mti_transno);

        /* update lcd in memory only for resent cases */
        ted = &req->rq_export->exp_target_data;
        LASSERT(ted);
        cfs_mutex_lock(&ted->ted_lcd_lock);
        lcd = ted->ted_lcd;
        if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE ||
            lustre_msg_get_opc(req->rq_reqmsg) == MDS_DONE_WRITING) {
                if (info->mti_transno != 0)
                        lcd->lcd_last_close_transno = info->mti_transno;
                lcd->lcd_last_close_xid = req->rq_xid;
                lcd->lcd_last_close_result = rc;
        } else {
                /* VBR: save versions in last_rcvd for reconstruct. */
                __u64 *pre_versions = lustre_msg_get_versions(req->rq_repmsg);
                if (pre_versions) {
                        lcd->lcd_pre_versions[0] = pre_versions[0];
                        lcd->lcd_pre_versions[1] = pre_versions[1];
                        lcd->lcd_pre_versions[2] = pre_versions[2];
                        lcd->lcd_pre_versions[3] = pre_versions[3];
                }
                if (info->mti_transno != 0)
                        lcd->lcd_last_transno = info->mti_transno;
                lcd->lcd_last_xid = req->rq_xid;
                lcd->lcd_last_result = rc;
                lcd->lcd_last_data = info->mti_opdata;
        }
        cfs_mutex_unlock(&ted->ted_lcd_lock);

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
                        struct mdt_object *o, __u64 flags, int created)
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
        if (isreg && !(ma->ma_valid & MA_LOV)) {
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
                rc = mdt_write_get(o);
                if (rc == 0) {
                        mdt_ioepoch_open(info, o, created);
                        repbody->ioepoch = o->mot_ioepoch;
                }
        } else if (flags & MDS_FMODE_EXEC) {
                rc = mdt_write_deny(o);
        }
        if (rc)
                RETURN(rc);

        rc = mo_open(info->mti_env, mdt_object_child(o),
                     created ? flags | MDS_OPEN_CREATED : flags);
        if (rc)
                GOTO(err_out, rc);

        mfd = mdt_mfd_new();
        if (mfd != NULL) {
                /*
                 * Keep a reference on this object for this open, and is
                 * released by mdt_mfd_close().
                 */
                mdt_object_get(info->mti_env, o);

                /*
                 * @flags is always not zero. At least it should be FMODE_READ,
                 * FMODE_WRITE or MDS_FMODE_EXEC.
                 */
                LASSERT(flags != 0);

                /* Open handling. */
                mdt_mfd_set_mode(mfd, flags);

                mfd->mfd_object = o;
                mfd->mfd_xid = req->rq_xid;

                /* replay handle */
                if (req_is_replay(req)) {
                        struct mdt_file_data *old_mfd;
                        /* Check wheather old cookie already exist in
                         * the list, becasue when do recovery, client
                         * might be disconnected from server, and
                         * restart replay, so there maybe some orphan
                         * mfd here, we should remove them */
                        LASSERT(info->mti_rr.rr_handle != NULL);
                        old_mfd = mdt_handle2mfd(info, info->mti_rr.rr_handle);
                        if (old_mfd) {
                                CDEBUG(D_HA, "del orph mfd %p fid=("DFID") "
                                       "cookie=" LPX64"\n", mfd,
                                       PFID(mdt_object_fid(mfd->mfd_object)),
                                       info->mti_rr.rr_handle->cookie);
                                cfs_spin_lock(&med->med_open_lock);
                                class_handle_unhash(&old_mfd->mfd_handle);
                                cfs_list_del_init(&old_mfd->mfd_list);
                                cfs_spin_unlock(&med->med_open_lock);
                                /* no attr update for that close */
                                la->la_valid = 0;
                                ma->ma_valid |= MA_FLAGS;
                                ma->ma_attr_flags |= MDS_RECOV_OPEN;
                                mdt_mfd_close(info, old_mfd);
                                ma->ma_attr_flags &= ~MDS_RECOV_OPEN;
                                ma->ma_valid &= ~MA_FLAGS;
                        }
                        CDEBUG(D_HA, "Store old cookie "LPX64" in new mfd\n",
                               info->mti_rr.rr_handle->cookie);
                        mfd->mfd_old_handle.cookie =
                                                info->mti_rr.rr_handle->cookie;
                }
                repbody->handle.cookie = mfd->mfd_handle.h_cookie;

                if (req->rq_export->exp_disconnected) {
                        cfs_spin_lock(&med->med_open_lock);
                        class_handle_unhash(&mfd->mfd_handle);
                        cfs_list_del_init(&mfd->mfd_list);
                        cfs_spin_unlock(&med->med_open_lock);
                        mdt_mfd_close(info, mfd);
                } else {
                        cfs_spin_lock(&med->med_open_lock);
                        cfs_list_add(&mfd->mfd_list, &med->med_open_head);
                        cfs_spin_unlock(&med->med_open_lock);
                }

                mdt_empty_transno(info, rc);
        } else {
                GOTO(err_out, rc = -ENOMEM);
        }

        RETURN(rc);

err_out:
        if (flags & FMODE_WRITE)
                        /* XXX We also need to close io epoch here.
                         * See LU-1220 - green */
                mdt_write_put(o);
        else if (flags & FMODE_EXEC)
                mdt_write_allow(o);
        return rc;
}

int mdt_finish_open(struct mdt_thread_info *info,
                    struct mdt_object *p, struct mdt_object *o,
                    __u64 flags, int created, struct ldlm_reply *rep)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct obd_export       *exp = req->rq_export;
        struct mdt_export_data  *med = &req->rq_export->exp_mdt_data;
        struct md_attr          *ma  = &info->mti_attr;
        struct lu_attr          *la  = &ma->ma_attr;
        struct mdt_file_data    *mfd;
        struct mdt_body         *repbody;
        int                      rc = 0;
        int                      isreg, isdir, islnk;
        cfs_list_t              *t;
        ENTRY;

        LASSERT(ma->ma_valid & MA_INODE);

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        isreg = S_ISREG(la->la_mode);
        isdir = S_ISDIR(la->la_mode);
        islnk = S_ISLNK(la->la_mode);
        mdt_pack_attr2body(info, repbody, la, mdt_object_fid(o));

        if (exp_connect_rmtclient(exp)) {
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
        else if (exp->exp_connect_flags & OBD_CONNECT_ACL) {
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

        if (info->mti_mdt->mdt_opts.mo_mds_capa &&
            exp->exp_connect_flags & OBD_CONNECT_MDS_CAPA) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA1);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_MDS_DEFAULT;
                rc = mo_capa_get(info->mti_env, mdt_object_child(o), capa, 0);
                if (rc)
                        RETURN(rc);
                repbody->valid |= OBD_MD_FLMDSCAPA;
        }
        if (info->mti_mdt->mdt_opts.mo_oss_capa &&
            exp->exp_connect_flags & OBD_CONNECT_OSS_CAPA &&
            S_ISREG(lu_object_attr(&o->mot_obj.mo_lu))) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA2);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_OSS_DEFAULT | capa_open_opc(flags);
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
                cfs_spin_lock(&med->med_open_lock);
                cfs_list_for_each(t, &med->med_open_head) {
                        mfd = cfs_list_entry(t, struct mdt_file_data, mfd_list);
                        if (mfd->mfd_xid == req->rq_xid) {
                                break;
                        }
                        mfd = NULL;
                }
                cfs_spin_unlock(&med->med_open_lock);

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
        struct tg_export_data   *ted  = &req->rq_export->exp_target_data;
        struct lsd_client_data  *lcd  = ted->ted_lcd;
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
        ma->ma_need = MA_INODE;
        if (ma->ma_lmm_size > 0)
                ma->ma_need |= MA_LOV;

        ma->ma_valid = 0;

        mdt_req_from_lcd(req, lcd);
        mdt_set_disposition(info, ldlm_rep, lcd->lcd_last_data);

        CDEBUG(D_INODE, "This is reconstruct open: disp="LPX64", result=%d\n",
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
                                      PFID(rr->rr_fid1), rc,
                                      obd_uuid2str(&exp->exp_client_uuid),
                                      obd_export_nid2str(exp));
                        mdt_export_evict(exp);
                        RETURN_EXIT;
                }
                child = mdt_object_find(env, mdt, rr->rr_fid2);
                if (IS_ERR(child)) {
                        rc = PTR_ERR(child);
                        LCONSOLE_WARN("Child "DFID" lookup error %d."
                                      " Evicting client %s with export %s.\n",
                                      PFID(mdt_object_fid(child)), rc,
                                      obd_uuid2str(&exp->exp_client_uuid),
                                      obd_export_nid2str(exp));
                        mdt_object_put(env, parent);
                        mdt_export_evict(exp);
                        RETURN_EXIT;
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

int mdt_open_by_fid(struct mdt_thread_info* info,
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

int mdt_open_by_fid_lock(struct mdt_thread_info *info, struct ldlm_reply *rep,
			 struct mdt_lock_handle *lhc)
{
        const struct lu_env     *env   = info->mti_env;
        struct mdt_device       *mdt   = info->mti_mdt;
        __u32                    flags = info->mti_spec.sp_cr_flags;
        struct mdt_reint_record *rr    = &info->mti_rr;
        struct md_attr          *ma    = &info->mti_attr;
        struct mdt_object       *parent= NULL;
        struct mdt_object       *o;
        int                      rc;
        ldlm_mode_t              lm;
        ENTRY;

	if (md_should_create(flags) && !(flags & MDS_OPEN_HAS_EA)) {
                if (!lu_fid_eq(rr->rr_fid1, rr->rr_fid2)) {
                        parent = mdt_object_find(env, mdt, rr->rr_fid1);
                        if (IS_ERR(parent)) {
                                CDEBUG(D_INODE, "Fail to find parent "DFID
                                       " for anonymous created %ld, try to"
                                       " use server-side parent.\n",
                                       PFID(rr->rr_fid1), PTR_ERR(parent));
                                parent = NULL;
                        }
                }
                if (parent == NULL)
                        ma->ma_need |= MA_PFID;
        }

        o = mdt_object_find(env, mdt, rr->rr_fid2);
        if (IS_ERR(o))
                RETURN(rc = PTR_ERR(o));

        rc = mdt_object_exists(o);
        if (rc == 0) {
                mdt_set_disposition(info, rep, (DISP_LOOKUP_EXECD |
                                    DISP_LOOKUP_NEG));
                GOTO(out, rc = -ENOENT);
        } else if (rc < 0) {
                CERROR("NFS remote open shouldn't happen.\n");
                GOTO(out, rc);
        }
        mdt_set_disposition(info, rep, (DISP_IT_EXECD |
                                        DISP_LOOKUP_EXECD |
                                        DISP_LOOKUP_POS));

        if (flags & FMODE_WRITE)
                lm = LCK_CW;
        else if (flags & MDS_FMODE_EXEC)
                lm = LCK_PR;
        else
                lm = LCK_CR;

        mdt_lock_handle_init(lhc);
        mdt_lock_reg_init(lhc, lm);
        rc = mdt_object_lock(info, o, lhc,
                             MDS_INODELOCK_LOOKUP | MDS_INODELOCK_OPEN,
                             MDT_CROSS_LOCK);
        if (rc)
                GOTO(out, rc);

        rc = mo_attr_get(env, mdt_object_child(o), ma);
        if (rc)
                GOTO(out, rc);

        if (ma->ma_valid & MA_PFID) {
                parent = mdt_object_find(env, mdt, &ma->ma_pfid);
                if (IS_ERR(parent)) {
                        CDEBUG(D_INODE, "Fail to find parent "DFID
                               " for anonymous created %ld, try to"
                               " use system default.\n",
                               PFID(&ma->ma_pfid), PTR_ERR(parent));
                        parent = NULL;
                }
        }

        if (flags & MDS_OPEN_LOCK)
                mdt_set_disposition(info, rep, DISP_OPEN_LOCK);
        rc = mdt_finish_open(info, parent, o, flags, 0, rep);

        if (!(flags & MDS_OPEN_LOCK) || rc)
                mdt_object_unlock(info, o, lhc, 1);

        GOTO(out, rc);
out:
        mdt_object_put(env, o);
        if (parent != NULL)
                mdt_object_put(env, parent);
        return rc;
}

int mdt_pin(struct mdt_thread_info* info)
{
        ENTRY;
        RETURN(err_serious(-EOPNOTSUPP));
}

/* Cross-ref request. Currently it can only be a pure open (w/o create) */
int mdt_cross_open(struct mdt_thread_info* info,
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
        __u64                    create_flags = info->mti_spec.sp_cr_flags;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct lu_name          *lname;
        int                      result, rc;
        int                      created = 0;
        __u32                    msg_flags;
        ENTRY;

        OBD_FAIL_TIMEOUT_ORSET(OBD_FAIL_MDS_PAUSE_OPEN, OBD_FAIL_ONCE,
                               (obd_timeout + 1) / 4);

	mdt_counter_incr(req, LPROC_MDT_OPEN);
        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        ma->ma_lmm = req_capsule_server_get(info->mti_pill, &RMF_MDT_MD);
        ma->ma_lmm_size = req_capsule_get_size(info->mti_pill, &RMF_MDT_MD,
                                               RCL_SERVER);
        ma->ma_need = MA_INODE;
        if (ma->ma_lmm_size > 0)
                ma->ma_need |= MA_LOV;

        ma->ma_valid = 0;

        LASSERT(info->mti_pill->rc_fmt == &RQF_LDLM_INTENT_OPEN);
        ldlm_rep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);

        if (unlikely(create_flags & MDS_OPEN_JOIN_FILE)) {
                CERROR("file join is not supported anymore.\n");
                GOTO(out, result = err_serious(-EOPNOTSUPP));
        }
        msg_flags = lustre_msg_get_flags(req->rq_reqmsg);

        if ((create_flags & (MDS_OPEN_HAS_EA | MDS_OPEN_HAS_OBJS)) &&
            info->mti_spec.u.sp_ea.eadata == NULL)
                GOTO(out, result = err_serious(-EINVAL));

        CDEBUG(D_INODE, "I am going to open "DFID"/(%s->"DFID") "
               "cr_flag="LPO64" mode=0%06o msg_flag=0x%x\n",
               PFID(rr->rr_fid1), rr->rr_name,
               PFID(rr->rr_fid2), create_flags,
               ma->ma_attr.la_mode, msg_flags);

	if (req_is_replay(req) ||
	    (req->rq_export->exp_libclient && create_flags & MDS_OPEN_HAS_EA)) {
		/* This is a replay request or from liblustre with ea. */
		result = mdt_open_by_fid(info, ldlm_rep);

		if (result != -ENOENT) {
			if (req->rq_export->exp_libclient &&
			    create_flags & MDS_OPEN_HAS_EA)
				GOTO(out, result = 0);
			GOTO(out, result);
		}
		/* We didn't find the correct object, so we need to re-create it
		 * via a regular replay. */
		if (!(create_flags & MDS_OPEN_CREAT)) {
			DEBUG_REQ(D_ERROR, req,
				  "OPEN & CREAT not in open replay/by_fid.");
			GOTO(out, result = -EFAULT);
		}
		CDEBUG(D_INFO, "No object(1), continue as regular open.\n");
	} else if ((rr->rr_namelen == 0 && !info->mti_cross_ref &&
		    create_flags & MDS_OPEN_LOCK) ||
		   (create_flags & MDS_OPEN_BY_FID)) {
		result = mdt_open_by_fid_lock(info, ldlm_rep, lhc);
		if (result != -ENOENT && !(create_flags & MDS_OPEN_CREAT))
			GOTO(out, result);
		if (unlikely(rr->rr_namelen == 0))
			GOTO(out, result = -EINVAL);
		CDEBUG(D_INFO, "No object(2), continue as regular open.\n");
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

        /* get and check version of parent */
        result = mdt_version_get_check(info, parent, 0);
        if (result)
                GOTO(out_parent, result);

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
		child = mdt_object_new(info->mti_env, mdt, child_fid);
	} else {
		/*
		 * Check for O_EXCL is moved to the mdt_finish_open(), we need to
		 * return FID back in that case.
		 */
		mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
		child = mdt_object_find(info->mti_env, mdt, child_fid);
	}
        if (IS_ERR(child))
                GOTO(out_parent, result = PTR_ERR(child));

        /** check version of child  */
        rc = mdt_version_get_check(info, child, 1);
        if (rc)
                GOTO(out_child, result = rc);

        mdt_set_capainfo(info, 1, child_fid, BYPASS_CAPA);
        if (result == -ENOENT) {
                if (mdt_object_obf(parent))
                        GOTO(out_child, result = -EPERM);

                /* save versions in reply */
                mdt_version_get_save(info, parent, 0);
                mdt_version_get_save(info, child, 1);

                /* version of child will be changed */
                info->mti_mos = child;

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
                info->mti_spec.sp_feat = &dt_directory_features;

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
        if (!req_is_replay(req) && create_flags & MDS_OPEN_LOCK) {
                ldlm_mode_t lm;

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
        mdt_object_unlock_put(info, parent, lh, result || !created);
out:
        if (result && result != -EREMOTE)
                lustre_msg_set_transno(req->rq_repmsg, 0);
        return result;
}

#define MFD_CLOSED(mode) (((mode) & ~(MDS_FMODE_EPOCH | MDS_FMODE_SOM | \
                                      MDS_FMODE_TRUNC)) == MDS_FMODE_CLOSED)

static int mdt_mfd_closed(struct mdt_file_data *mfd)
{
        return ((mfd == NULL) || MFD_CLOSED(mfd->mfd_mode));
}

int mdt_mfd_close(struct mdt_thread_info *info, struct mdt_file_data *mfd)
{
        struct mdt_object *o = mfd->mfd_object;
        struct md_object *next = mdt_object_child(o);
        struct md_attr *ma = &info->mti_attr;
        int ret = MDT_IOEPOCH_CLOSED;
        int rc = 0;
        int mode;
        ENTRY;

        mode = mfd->mfd_mode;

        if ((mode & FMODE_WRITE) || (mode & MDS_FMODE_TRUNC)) {
                mdt_write_put(o);
                ret = mdt_ioepoch_close(info, o);
        } else if (mode & MDS_FMODE_EXEC) {
                mdt_write_allow(o);
        } else if (mode & MDS_FMODE_EPOCH) {
                ret = mdt_ioepoch_close(info, o);
        } else if (mode & MDS_FMODE_SOM) {
                ret = mdt_som_au_close(info, o);
        }

        /* Update atime on close only. */
        if ((mode & MDS_FMODE_EXEC || mode & FMODE_READ || mode & FMODE_WRITE)
            && (ma->ma_valid & MA_INODE) && (ma->ma_attr.la_valid & LA_ATIME)) {
                /* Set the atime only. */
                ma->ma_valid = MA_INODE;
                ma->ma_attr.la_valid = LA_ATIME;
                rc = mo_attr_set(info->mti_env, next, ma);
        }

        ma->ma_need |= MA_INODE;
        ma->ma_valid &= ~MA_INODE;

        if (!MFD_CLOSED(mode))
                rc = mo_close(info->mti_env, next, ma, mode);

        if (ret == MDT_IOEPOCH_GETATTR || ret == MDT_IOEPOCH_OPENED) {
                struct mdt_export_data *med;

                /* The IOepoch is still opened or SOM update is needed.
                 * Put mfd back into the list. */
                LASSERT(mdt_conn_flags(info) & OBD_CONNECT_SOM);
                mdt_mfd_set_mode(mfd, ret == MDT_IOEPOCH_OPENED ?
                                      MDS_FMODE_EPOCH : MDS_FMODE_SOM);

                LASSERT(mdt_info_req(info));
                med = &mdt_info_req(info)->rq_export->exp_mdt_data;
                cfs_spin_lock(&med->med_open_lock);
                cfs_list_add(&mfd->mfd_list, &med->med_open_head);
                class_handle_hash_back(&mfd->mfd_handle);
                cfs_spin_unlock(&med->med_open_lock);

                if (ret == MDT_IOEPOCH_OPENED) {
                        ret = 0;
                } else {
                        ret = -EAGAIN;
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

	mdt_counter_incr(req, LPROC_MDT_CLOSE);
        /* Close may come with the Size-on-MDS update. Unpack it. */
        rc = mdt_close_unpack(info);
        if (rc)
                RETURN(err_serious(rc));

        LASSERT(info->mti_ioepoch);

        req_capsule_set_size(info->mti_pill, &RMF_MDT_MD, RCL_SERVER,
                             info->mti_mdt->mdt_max_mdsize);
        req_capsule_set_size(info->mti_pill, &RMF_LOGCOOKIES, RCL_SERVER,
                             info->mti_mdt->mdt_max_cookiesize);
        rc = req_capsule_server_pack(info->mti_pill);
        if (mdt_check_resent(info, mdt_reconstruct_generic, NULL)) {
                mdt_client_compatibility(info);
                if (rc == 0)
                        mdt_fix_reply(info);
                RETURN(lustre_msg_get_status(req->rq_repmsg));
        }

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
        } else {
                rc = err_serious(rc);
        }

        med = &req->rq_export->exp_mdt_data;
        cfs_spin_lock(&med->med_open_lock);
        mfd = mdt_handle2mfd(info, &info->mti_ioepoch->handle);
        if (mdt_mfd_closed(mfd)) {
                cfs_spin_unlock(&med->med_open_lock);
                CDEBUG(D_INODE, "no handle for file close: fid = "DFID
                       ": cookie = "LPX64"\n", PFID(info->mti_rr.rr_fid1),
                       info->mti_ioepoch->handle.cookie);
                /** not serious error since bug 3633 */
                rc = -ESTALE;
        } else {
                class_handle_unhash(&mfd->mfd_handle);
                cfs_list_del_init(&mfd->mfd_list);
                cfs_spin_unlock(&med->med_open_lock);

                /* Do not lose object before last unlink. */
                o = mfd->mfd_object;
                mdt_object_get(info->mti_env, o);
                ret = mdt_mfd_close(info, mfd);
                if (repbody != NULL)
                        rc = mdt_handle_last_unlink(info, o, ma);
                mdt_empty_transno(info, rc);
                mdt_object_put(info->mti_env, o);
        }
        if (repbody != NULL) {
                mdt_client_compatibility(info);
                rc = mdt_fix_reply(info);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK))
                RETURN(err_serious(-ENOMEM));

        if (OBD_FAIL_CHECK_RESET(OBD_FAIL_MDS_CLOSE_NET_REP,
                                 OBD_FAIL_MDS_CLOSE_NET_REP))
                info->mti_fail_id = OBD_FAIL_MDS_CLOSE_NET_REP;
        RETURN(rc ? rc : ret);
}

/**
 * DONE_WRITING rpc handler.
 *
 * As mfd is not kept after replayed CLOSE (see mdt_ioepoch_close_on_replay()),
 * only those DONE_WRITING rpc will be replayed which really wrote smth on disk,
 * and got a trasid. Waiting for such DONE_WRITING is not reliable, so just
 * skip attributes and reconstruct the reply here.
 */
int mdt_done_writing(struct mdt_thread_info *info)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
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
                RETURN(lustre_msg_get_status(req->rq_repmsg));

        med = &info->mti_exp->exp_mdt_data;
        cfs_spin_lock(&med->med_open_lock);
        mfd = mdt_handle2mfd(info, &info->mti_ioepoch->handle);
        if (mfd == NULL) {
                cfs_spin_unlock(&med->med_open_lock);
                CDEBUG(D_INODE, "no handle for done write: fid = "DFID
                       ": cookie = "LPX64" ioepoch = "LPU64"\n",
                       PFID(info->mti_rr.rr_fid1),
                       info->mti_ioepoch->handle.cookie,
                       info->mti_ioepoch->ioepoch);
                /* If this is a replay, reconstruct the transno. */
                if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                        rc = info->mti_ioepoch->flags & MF_SOM_AU ?
                             -EAGAIN : 0;
                        mdt_empty_transno(info, rc);
                        RETURN(rc);
                }
                RETURN(-ESTALE);
        }

        LASSERT(mfd->mfd_mode == MDS_FMODE_EPOCH ||
                mfd->mfd_mode == MDS_FMODE_TRUNC);
        class_handle_unhash(&mfd->mfd_handle);
        cfs_list_del_init(&mfd->mfd_list);
        cfs_spin_unlock(&med->med_open_lock);

        /* Set EPOCH CLOSE flag if not set by client. */
        info->mti_ioepoch->flags |= MF_EPOCH_CLOSE;
        info->mti_attr.ma_valid = 0;

        info->mti_attr.ma_lmm_size = info->mti_mdt->mdt_max_mdsize;
        OBD_ALLOC_LARGE(info->mti_attr.ma_lmm, info->mti_mdt->mdt_max_mdsize);
        if (info->mti_attr.ma_lmm == NULL)
                RETURN(-ENOMEM);

        rc = mdt_mfd_close(info, mfd);

        OBD_FREE_LARGE(info->mti_attr.ma_lmm, info->mti_mdt->mdt_max_mdsize);
        mdt_empty_transno(info, rc);
        RETURN(rc);
}
