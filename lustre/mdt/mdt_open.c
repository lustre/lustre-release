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
 * Copyright (c) 2011, 2013, Intel Corporation.
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
#include <lustre_nodemap.h>

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
struct mdt_file_data *mdt_mfd_new(const struct mdt_export_data *med)
{
	struct mdt_file_data *mfd;
	ENTRY;

	OBD_ALLOC_PTR(mfd);
	if (mfd != NULL) {
		INIT_LIST_HEAD(&mfd->mfd_handle.h_link);
		mfd->mfd_handle.h_owner = med;
		INIT_LIST_HEAD(&mfd->mfd_list);
		class_handle_hash(&mfd->mfd_handle, &mfd_handle_ops);
	}

	RETURN(mfd);
}

/*
 * Find the mfd pointed to by handle in global hash table.
 * In case of replay the handle is obsoleted
 * but mfd can be found in mfd list by that handle.
 * Callers need to be holding med_open_lock.
 */
struct mdt_file_data *mdt_handle2mfd(struct mdt_export_data *med,
				     const struct lustre_handle *handle,
				     bool is_replay_or_resent)
{
	struct mdt_file_data   *mfd;
	ENTRY;

	LASSERT(handle != NULL);
	mfd = class_handle2object(handle->cookie, med);
	/* during dw/setattr replay the mfd can be found by old handle */
	if (mfd == NULL && is_replay_or_resent) {
		list_for_each_entry(mfd, &med->med_open_head, mfd_list) {
			if (mfd->mfd_old_handle.cookie == handle->cookie)
				RETURN(mfd);
		}
		mfd = NULL;
	}

	RETURN(mfd);
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
	struct md_attr        *ma   = &info->mti_attr;
	int                    rc   = 0;
	ENTRY;

	if (!md_should_create(spec->sp_cr_flags))
		RETURN(0);

	ma->ma_need = MA_INODE | MA_LOV;
	ma->ma_valid = 0;
	mutex_lock(&o->mot_lov_mutex);
	if (!(o->mot_flags & MOF_LOV_CREATED)) {
		rc = mdo_create_data(info->mti_env,
				     p ? mdt_object_child(p) : NULL,
				     mdt_object_child(o), spec, ma);
		if (rc == 0)
			rc = mdt_attr_get_complex(info, o, ma);

		if (rc == 0 && ma->ma_valid & MA_LOV)
			o->mot_flags |= MOF_LOV_CREATED;
	}

	mutex_unlock(&o->mot_lov_mutex);
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
	    !S_ISREG(lu_object_attr(&o->mot_obj)))
		RETURN(0);

	mutex_lock(&o->mot_ioepoch_mutex);
	if (mdt_ioepoch_opened(o)) {
		/* Epoch continues even if there is no writers yet. */
		CDEBUG(D_INODE, "continue epoch "LPU64" for "DFID"\n",
		       o->mot_ioepoch, PFID(mdt_object_fid(o)));
	} else {
		/* XXX: ->mdt_ioepoch is not initialized at the mount */
		spin_lock(&mdt->mdt_ioepoch_lock);
                if (mdt->mdt_ioepoch < info->mti_replayepoch)
                        mdt->mdt_ioepoch = info->mti_replayepoch;

                if (info->mti_replayepoch)
                        o->mot_ioepoch = info->mti_replayepoch;
                else if (++mdt->mdt_ioepoch == IOEPOCH_INVAL)
                        o->mot_ioepoch = ++mdt->mdt_ioepoch;
                else
                        o->mot_ioepoch = mdt->mdt_ioepoch;

		spin_unlock(&mdt->mdt_ioepoch_lock);

		CDEBUG(D_INODE, "starting epoch "LPU64" for "DFID"\n",
		       o->mot_ioepoch, PFID(mdt_object_fid(o)));
		if (created)
			o->mot_flags |= MOF_SOM_CREATED;
		cancel = 1;
	}
	o->mot_ioepoch_count++;
	mutex_unlock(&o->mot_ioepoch_mutex);

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
 * mountid and attributes. If disabling, clean SOM xattr.
 * Call under ->mot_ioepoch_mutex.
 */
static int mdt_som_attr_set(struct mdt_thread_info *info,
			    struct mdt_object *obj, __u64 ioepoch, bool enable)
{
	struct md_object	*next = mdt_object_child(obj);
	int			 rc;
        ENTRY;

        CDEBUG(D_INODE, "Size-on-MDS attribute %s for epoch "LPU64
               " on "DFID".\n", enable ? "update" : "disabling",
               ioepoch, PFID(mdt_object_fid(obj)));

	if (enable) {
		struct lu_buf		*buf = &info->mti_buf;
		struct som_attrs	*attrs;
		struct md_attr		*ma = &info->mti_attr;
		struct lu_attr		*la = &ma->ma_attr;
		struct obd_device	*obd = info->mti_mdt->mdt_lut.lut_obd;

		attrs = (struct som_attrs *)info->mti_xattr_buf;
		CLASSERT(sizeof(info->mti_xattr_buf) >= sizeof(*attrs));

		/* pack SOM attributes */
		memset(attrs, 0, sizeof(*attrs));
		attrs->som_ioepoch = ioepoch;
		attrs->som_mountid = obd->u.obt.obt_mount_count;
		if ((la->la_valid & LA_SIZE) != 0)
			attrs->som_size = la->la_size;
		if ((la->la_valid & LA_BLOCKS) != 0)
			attrs->som_blocks = la->la_blocks;
		lustre_som_swab(attrs);

		/* update SOM attributes */
		buf->lb_buf = attrs;
		buf->lb_len = sizeof(*attrs);
		rc = mo_xattr_set(info->mti_env, next, buf, XATTR_NAME_SOM, 0);
	} else {
		/* delete SOM attributes */
		rc = mo_xattr_del(info->mti_env, next, XATTR_NAME_SOM);
	}

        RETURN(rc);
}

/** Perform the eviction specific actions on ioepoch close. */
static inline int mdt_ioepoch_close_on_eviction(struct mdt_thread_info *info,
                                                struct mdt_object *o)
{
        int rc = 0;

	mutex_lock(&o->mot_ioepoch_mutex);
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
	mutex_unlock(&o->mot_ioepoch_mutex);
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

	mutex_lock(&o->mot_ioepoch_mutex);
        CDEBUG(D_INODE, "Replay. Closing epoch "LPU64" on "DFID". Count %d\n",
               o->mot_ioepoch, PFID(mdt_object_fid(o)), o->mot_ioepoch_count);
        o->mot_ioepoch_count--;

        /* Get an info from the replayed request if client is supposed
         * to send an Attibute Update, reconstruct @rc if so */
        if (info->mti_ioepoch->flags & MF_SOM_AU)
                rc = MDT_IOEPOCH_GETATTR;

        if (!mdt_ioepoch_opened(o))
                mdt_object_som_enable(o, info->mti_ioepoch->ioepoch);
	mutex_unlock(&o->mot_ioepoch_mutex);

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

	mutex_lock(&o->mot_ioepoch_mutex);
        o->mot_ioepoch_count--;

        tmp_ma = &info->mti_u.som.attr;
        tmp_ma->ma_lmm = info->mti_attr.ma_lmm;
        tmp_ma->ma_lmm_size = info->mti_attr.ma_lmm_size;
        tmp_ma->ma_som = &info->mti_u.som.data;
        tmp_ma->ma_need = MA_INODE | MA_LOV | MA_SOM;
        tmp_ma->ma_valid = 0;
	rc = mdt_attr_get_complex(info, o, tmp_ma);
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

	mutex_unlock(&o->mot_ioepoch_mutex);
        /* If recovery is needed, tell the client to perform GETATTR under
         * the lock. */
        if (ret == MDT_IOEPOCH_GETATTR && recovery) {
                struct mdt_body *rep;
                rep = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		rep->mbo_valid |= OBD_MD_FLGETATTRLOCK;
        }

        RETURN(rc ? : ret);

error_up:
	mutex_unlock(&o->mot_ioepoch_mutex);
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
	    !S_ISREG(lu_object_attr(&o->mot_obj)))
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
	if (info->mti_ioepoch && (info->mti_ioepoch->flags & MF_EPOCH_CLOSE))
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
	struct ptlrpc_request	*req = mdt_info_req(info);
	__u64			 ioepoch = 0;
	int			 act = MDT_SOM_ENABLE;
	int			 rc = 0;
	ENTRY;

	LASSERT(!req || info->mti_ioepoch);
	if (!(mdt_conn_flags(info) & OBD_CONNECT_SOM) ||
	    !S_ISREG(lu_object_attr(&o->mot_obj)))
		RETURN(0);

        /* No size whereas MF_SOM_CHANGE is set means client failed to
         * obtain ost attributes, drop the SOM cache on disk if so. */
        if (!req ||
            (info->mti_ioepoch &&
             info->mti_ioepoch->flags & MF_SOM_CHANGE &&
             !(info->mti_attr.ma_attr.la_valid & LA_SIZE)))
                act = MDT_SOM_DISABLE;

	mutex_lock(&o->mot_ioepoch_mutex);
        /* Mark the object it is the recovery state if we failed to obtain
         * SOM attributes. */
        if (act == MDT_SOM_DISABLE)
                o->mot_flags |= MOF_SOM_RECOV;

        if (!mdt_ioepoch_opened(o)) {
                ioepoch =  info->mti_ioepoch ?
                        info->mti_ioepoch->ioepoch : o->mot_ioepoch;

		if (req != NULL
		    && !(lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY))
                        rc = mdt_som_attr_set(info, o, ioepoch, act);
                mdt_object_som_enable(o, ioepoch);
        }
	mutex_unlock(&o->mot_ioepoch_mutex);
        RETURN(rc);
}

int mdt_write_read(struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
	mutex_lock(&o->mot_ioepoch_mutex);
        rc = o->mot_writecount;
	mutex_unlock(&o->mot_ioepoch_mutex);
        RETURN(rc);
}

int mdt_write_get(struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
	mutex_lock(&o->mot_ioepoch_mutex);
        if (o->mot_writecount < 0)
                rc = -ETXTBSY;
        else
                o->mot_writecount++;
	mutex_unlock(&o->mot_ioepoch_mutex);
        RETURN(rc);
}

void mdt_write_put(struct mdt_object *o)
{
        ENTRY;
	mutex_lock(&o->mot_ioepoch_mutex);
        o->mot_writecount--;
	mutex_unlock(&o->mot_ioepoch_mutex);
        EXIT;
}

static int mdt_write_deny(struct mdt_object *o)
{
        int rc = 0;
        ENTRY;
	mutex_lock(&o->mot_ioepoch_mutex);
        if (o->mot_writecount > 0)
                rc = -ETXTBSY;
        else
                o->mot_writecount--;
	mutex_unlock(&o->mot_ioepoch_mutex);
        RETURN(rc);
}

static void mdt_write_allow(struct mdt_object *o)
{
        ENTRY;
	mutex_lock(&o->mot_ioepoch_mutex);
        o->mot_writecount++;
	mutex_unlock(&o->mot_ioepoch_mutex);
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

	spin_lock(&mdt->mdt_lut.lut_translock);
	if (rc != 0) {
		if (info->mti_transno != 0) {
			struct obd_export *exp = req->rq_export;

			CERROR("%s: replay trans "LPU64" NID %s: rc = %d\n",
			       mdt_obd_name(mdt), info->mti_transno,
			       libcfs_nid2str(exp->exp_connection->c_peer.nid),
			       rc);
			spin_unlock(&mdt->mdt_lut.lut_translock);
			RETURN_EXIT;
		}
	} else if (info->mti_transno == 0) {
		info->mti_transno = ++mdt->mdt_lut.lut_last_transno;
	} else {
		/* should be replay */
		if (info->mti_transno > mdt->mdt_lut.lut_last_transno)
			mdt->mdt_lut.lut_last_transno = info->mti_transno;
	}
	spin_unlock(&mdt->mdt_lut.lut_translock);

	CDEBUG(D_INODE, "transno = "LPU64", last_committed = "LPU64"\n",
	       info->mti_transno,
	       req->rq_export->exp_obd->obd_last_committed);

	req->rq_transno = info->mti_transno;
	lustre_msg_set_transno(req->rq_repmsg, info->mti_transno);

	/* update lcd in memory only for resent cases */
	ted = &req->rq_export->exp_target_data;
	LASSERT(ted);
	mutex_lock(&ted->ted_lcd_lock);
	lcd = ted->ted_lcd;
	if (info->mti_transno < lcd->lcd_last_transno &&
	    info->mti_transno != 0) {
		/* This should happen during replay. Do not update
		 * last rcvd info if replay req transno < last transno,
		 * otherwise the following resend(after replay) can not
		 * be checked correctly by xid */
		mutex_unlock(&ted->ted_lcd_lock);
		CDEBUG(D_HA, "%s: transno = "LPU64" < last_transno = "LPU64"\n",
		       mdt_obd_name(mdt), info->mti_transno,
		       lcd->lcd_last_transno);
		RETURN_EXIT;
	}

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
	mutex_unlock(&ted->ted_lcd_lock);

        EXIT;
}

void mdt_mfd_set_mode(struct mdt_file_data *mfd, __u64 mode)
{
	LASSERT(mfd != NULL);

	CDEBUG(D_HA, DFID " Change mfd mode "LPO64" -> "LPO64".\n",
	       PFID(mdt_object_fid(mfd->mfd_object)), mfd->mfd_mode, mode);

	mfd->mfd_mode = mode;
}

/**
 * prep ma_lmm/ma_lmv for md_attr from reply
 */
void mdt_prep_ma_buf_from_rep(struct mdt_thread_info *info,
			      struct mdt_object *obj,
			      struct md_attr *ma)
{
	LASSERT(ma->ma_lmv == NULL && ma->ma_lmm == NULL);
	if (S_ISDIR(obj->mot_header.loh_attr)) {
		ma->ma_lmv = req_capsule_server_get(info->mti_pill,
						    &RMF_MDT_MD);
		ma->ma_lmv_size = req_capsule_get_size(info->mti_pill,
						       &RMF_MDT_MD,
						       RCL_SERVER);
		if (ma->ma_lmv_size > 0)
			ma->ma_need |= MA_LMV;
	} else {
		ma->ma_lmm = req_capsule_server_get(info->mti_pill,
						    &RMF_MDT_MD);
		ma->ma_lmm_size = req_capsule_get_size(info->mti_pill,
						       &RMF_MDT_MD,
						       RCL_SERVER);
		if (ma->ma_lmm_size > 0)
			ma->ma_need |= MA_LOV;
	}
}

static int mdt_mfd_open(struct mdt_thread_info *info, struct mdt_object *p,
			struct mdt_object *o, __u64 flags, int created,
			struct ldlm_reply *rep)
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
	if (isreg && !(ma->ma_valid & MA_LOV) && !(flags & MDS_OPEN_RELEASE)) {
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

		if (exp_connect_flags(req->rq_export) & OBD_CONNECT_DISP_STRIPE)
			mdt_set_disposition(info, rep, DISP_OPEN_STRIPE);
        }

        CDEBUG(D_INODE, "after open, ma_valid bit = "LPX64" lmm_size = %d\n",
               ma->ma_valid, ma->ma_lmm_size);

        if (ma->ma_valid & MA_LOV) {
                LASSERT(ma->ma_lmm_size != 0);
		repbody->mbo_eadatasize = ma->ma_lmm_size;
		if (isdir)
			repbody->mbo_valid |= OBD_MD_FLDIREA;
		else
			repbody->mbo_valid |= OBD_MD_FLEASIZE;
	}

	if (ma->ma_valid & MA_LMV) {
		LASSERT(ma->ma_lmv_size != 0);
		repbody->mbo_eadatasize = ma->ma_lmv_size;
		LASSERT(isdir);
		repbody->mbo_valid |= OBD_MD_FLDIREA | OBD_MD_MEA;
	}

	if (flags & FMODE_WRITE) {
		rc = mdt_write_get(o);
		if (rc == 0) {
			mdt_ioepoch_open(info, o, created);
			repbody->mbo_ioepoch = o->mot_ioepoch;
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

	mfd = mdt_mfd_new(med);
	if (mfd == NULL)
		GOTO(err_out, rc = -ENOMEM);

	/*
	 * Keep a reference on this object for this open, and is
	 * released by mdt_mfd_close().
	 */
	mdt_object_get(info->mti_env, o);
	mfd->mfd_object = o;
	mfd->mfd_xid = req->rq_xid;

	/*
	 * @flags is always not zero. At least it should be FMODE_READ,
	 * FMODE_WRITE or MDS_FMODE_EXEC.
	 */
	LASSERT(flags != 0);

	/* Open handling. */
	mdt_mfd_set_mode(mfd, flags);

	atomic_inc(&o->mot_open_count);
	if (flags & MDS_OPEN_LEASE)
		atomic_inc(&o->mot_lease_count);

	/* replay handle */
	if (req_is_replay(req)) {
		struct mdt_file_data *old_mfd;
		/* Check wheather old cookie already exist in
		 * the list, becasue when do recovery, client
		 * might be disconnected from server, and
		 * restart replay, so there maybe some orphan
		 * mfd here, we should remove them */
		LASSERT(info->mti_rr.rr_handle != NULL);
		spin_lock(&med->med_open_lock);
		old_mfd = mdt_handle2mfd(med, info->mti_rr.rr_handle, true);
		if (old_mfd != NULL) {
			CDEBUG(D_HA, "delete orphan mfd = %p, fid = "DFID", "
			       "cookie = "LPX64"\n", mfd,
			       PFID(mdt_object_fid(mfd->mfd_object)),
			       info->mti_rr.rr_handle->cookie);
			class_handle_unhash(&old_mfd->mfd_handle);
			list_del_init(&old_mfd->mfd_list);
			spin_unlock(&med->med_open_lock);
			/* no attr update for that close */
			la->la_valid = 0;
			ma->ma_valid |= MA_FLAGS;
			ma->ma_attr_flags |= MDS_RECOV_OPEN;
			mdt_mfd_close(info, old_mfd);
			ma->ma_attr_flags &= ~MDS_RECOV_OPEN;
			ma->ma_valid &= ~MA_FLAGS;
		} else {
			spin_unlock(&med->med_open_lock);
			CDEBUG(D_HA, "orphan mfd not found, fid = "DFID", "
			       "cookie = "LPX64"\n",
			       PFID(mdt_object_fid(mfd->mfd_object)),
			       info->mti_rr.rr_handle->cookie);
		}

		CDEBUG(D_HA, "Store old cookie "LPX64" in new mfd\n",
		       info->mti_rr.rr_handle->cookie);

		mfd->mfd_old_handle.cookie = info->mti_rr.rr_handle->cookie;
	}

	repbody->mbo_handle.cookie = mfd->mfd_handle.h_cookie;

	if (req->rq_export->exp_disconnected) {
		spin_lock(&med->med_open_lock);
		class_handle_unhash(&mfd->mfd_handle);
		list_del_init(&mfd->mfd_list);
		spin_unlock(&med->med_open_lock);
		mdt_mfd_close(info, mfd);
	} else {
		spin_lock(&med->med_open_lock);
		list_add(&mfd->mfd_list, &med->med_open_head);
		spin_unlock(&med->med_open_lock);
	}

	mdt_empty_transno(info, rc);

        RETURN(rc);

err_out:
	if (flags & FMODE_WRITE)
		/* XXX We also need to close io epoch here.
		 * See LU-1220 - green */
		mdt_write_put(o);
	else if (flags & MDS_FMODE_EXEC)
		mdt_write_allow(o);

	return rc;
}

int mdt_finish_open(struct mdt_thread_info *info,
                    struct mdt_object *p, struct mdt_object *o,
                    __u64 flags, int created, struct ldlm_reply *rep)
{
	struct ptlrpc_request	*req = mdt_info_req(info);
	struct obd_export	*exp = req->rq_export;
	struct mdt_export_data	*med = &req->rq_export->exp_mdt_data;
	struct md_attr		*ma  = &info->mti_attr;
	struct lu_attr		*la  = &ma->ma_attr;
	struct mdt_file_data	*mfd;
	struct mdt_body		*repbody;
	int			 rc = 0;
	int			 isreg, isdir, islnk;
	struct list_head	*t;
	ENTRY;

        LASSERT(ma->ma_valid & MA_INODE);

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        isreg = S_ISREG(la->la_mode);
        isdir = S_ISDIR(la->la_mode);
        islnk = S_ISLNK(la->la_mode);
        mdt_pack_attr2body(info, repbody, la, mdt_object_fid(o));

	/* LU-2275, simulate broken behaviour (esp. prevalent in
	 * pre-2.4 servers where a very strange reply is sent on error
	 * that looks like it was actually almost succesful and a failure at the
	 * same time */
	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_NEGATIVE_POSITIVE)) {
		mdt_set_disposition(info, rep, DISP_OPEN_OPEN |
					       DISP_LOOKUP_NEG |
					       DISP_LOOKUP_POS);

		if (flags & MDS_OPEN_LOCK)
			mdt_set_disposition(info, rep, DISP_OPEN_LOCK);

		RETURN(-ENOENT);
	}

        if (exp_connect_rmtclient(exp)) {
                void *buf = req_capsule_server_get(info->mti_pill, &RMF_ACL);

                rc = mdt_pack_remote_perm(info, o, buf);
                if (rc) {
			repbody->mbo_valid &= ~OBD_MD_FLRMTPERM;
			repbody->mbo_aclsize = 0;
		} else {
			repbody->mbo_valid |= OBD_MD_FLRMTPERM;
			repbody->mbo_aclsize = sizeof(struct mdt_remote_perm);
                }
        }
#ifdef CONFIG_FS_POSIX_ACL
	else if (exp_connect_flags(exp) & OBD_CONNECT_ACL)
		rc = mdt_pack_acl2body(info, repbody, o,
				       exp->exp_target_data.ted_nodemap);
#endif

	if (info->mti_mdt->mdt_lut.lut_mds_capa &&
	    exp_connect_flags(exp) & OBD_CONNECT_MDS_CAPA) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA1);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_MDS_DEFAULT;
                rc = mo_capa_get(info->mti_env, mdt_object_child(o), capa, 0);
                if (rc)
                        RETURN(rc);
		repbody->mbo_valid |= OBD_MD_FLMDSCAPA;
        }
	if (info->mti_mdt->mdt_lut.lut_oss_capa &&
	    exp_connect_flags(exp) & OBD_CONNECT_OSS_CAPA &&
	    S_ISREG(lu_object_attr(&o->mot_obj))) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA2);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_OSS_DEFAULT | capa_open_opc(flags);
                rc = mo_capa_get(info->mti_env, mdt_object_child(o), capa, 0);
                if (rc)
                        RETURN(rc);
		repbody->mbo_valid |= OBD_MD_FLOSSCAPA;
        }

        /*
         * If we are following a symlink, don't open; and do not return open
         * handle for special nodes as client required.
         */
	if (islnk || (!isreg && !isdir &&
	    (exp_connect_flags(req->rq_export) & OBD_CONNECT_NODEVOH))) {
		lustre_msg_set_transno(req->rq_repmsg, 0);
		RETURN(0);
	}

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
			if (mfd->mfd_xid == req->rq_xid)
				break;
			mfd = NULL;
		}
		spin_unlock(&med->med_open_lock);

                if (mfd != NULL) {
			repbody->mbo_handle.cookie = mfd->mfd_handle.h_cookie;
			/* set repbody->ea_size for resent case */
			if (ma->ma_valid & MA_LOV) {
				LASSERT(ma->ma_lmm_size != 0);
				repbody->mbo_eadatasize = ma->ma_lmm_size;
				if (isdir)
					repbody->mbo_valid |= OBD_MD_FLDIREA;
				else
					repbody->mbo_valid |= OBD_MD_FLEASIZE;
                        }
			mdt_set_disposition(info, rep, DISP_OPEN_OPEN);
			RETURN(0);
		}
	}

	rc = mdt_mfd_open(info, p, o, flags, created, rep);
	if (!rc)
		mdt_set_disposition(info, rep, DISP_OPEN_OPEN);

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
	__u64                   flags = info->mti_spec.sp_cr_flags;
        struct ldlm_reply       *ldlm_rep;
        struct mdt_object       *parent;
        struct mdt_object       *child;
        struct mdt_body         *repbody;
        int                      rc;
        ENTRY;

        LASSERT(pill->rc_fmt == &RQF_LDLM_INTENT_OPEN);
        ldlm_rep = req_capsule_server_get(pill, &RMF_DLM_REP);
        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);

	ma->ma_need = MA_INODE | MA_HSM;
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
			LCONSOLE_WARN("cannot lookup child "DFID": rc = %d; "
				      "evicting client %s with export %s\n",
				      PFID(rr->rr_fid2), rc,
				      obd_uuid2str(&exp->exp_client_uuid),
				      obd_export_nid2str(exp));
			mdt_object_put(env, parent);
			mdt_export_evict(exp);
			RETURN_EXIT;
		}

		if (unlikely(mdt_object_remote(child))) {
			/* the child object was created on remote server */
			if (!mdt_is_dne_client(exp)) {
				/* Return -EIO for old client */
				mdt_object_put(env, parent);
				mdt_object_put(env, child);
				GOTO(out, rc = -EIO);
			}
			repbody->mbo_fid1 = *rr->rr_fid2;
			repbody->mbo_valid |= (OBD_MD_FLID | OBD_MD_MDS);
			rc = 0;
		} else {
			if (mdt_object_exists(child)) {
				mdt_set_capainfo(info, 1, rr->rr_fid2,
						 BYPASS_CAPA);
				mdt_prep_ma_buf_from_rep(info, child, ma);
				rc = mdt_attr_get_complex(info, child, ma);
				if (rc == 0)
					rc = mdt_finish_open(info, parent,
							     child, flags,
							     1, ldlm_rep);
			} else {
				/* the child does not exist, we should do
				 * regular open */
				mdt_object_put(env, parent);
				mdt_object_put(env, child);
				GOTO(regular_open, 0);
			}
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

int mdt_open_by_fid(struct mdt_thread_info *info, struct ldlm_reply *rep)
{
	__u64			 flags = info->mti_spec.sp_cr_flags;
        struct mdt_reint_record *rr = &info->mti_rr;
        struct md_attr          *ma = &info->mti_attr;
        struct mdt_object       *o;
        int                      rc;
        ENTRY;

        o = mdt_object_find(info->mti_env, info->mti_mdt, rr->rr_fid2);
        if (IS_ERR(o))
                RETURN(rc = PTR_ERR(o));

	if (unlikely(mdt_object_remote(o))) {
                /* the child object was created on remote server */
                struct mdt_body *repbody;

		mdt_set_disposition(info, rep, (DISP_IT_EXECD |
						DISP_LOOKUP_EXECD |
						DISP_LOOKUP_POS));
                repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		repbody->mbo_fid1 = *rr->rr_fid2;
		repbody->mbo_valid |= (OBD_MD_FLID | OBD_MD_MDS);
                rc = 0;
	} else {
		if (mdt_object_exists(o)) {
			mdt_set_disposition(info, rep, (DISP_IT_EXECD |
							DISP_LOOKUP_EXECD |
							DISP_LOOKUP_POS));
			mdt_prep_ma_buf_from_rep(info, o, ma);
			rc = mdt_attr_get_complex(info, o, ma);
			if (rc == 0)
				rc = mdt_finish_open(info, NULL, o, flags, 0,
						     rep);
		} else {
			rc = -ENOENT;
		}
	}

        mdt_object_put(info->mti_env, o);
        RETURN(rc);
}

/* lock object for open */
static int mdt_object_open_lock(struct mdt_thread_info *info,
				struct mdt_object *obj,
				struct mdt_lock_handle *lhc,
				__u64 *ibits)
{
	struct md_attr	*ma = &info->mti_attr;
	__u64		 open_flags = info->mti_spec.sp_cr_flags;
	ldlm_mode_t	 lm = LCK_CR;
	bool		 acq_lease = !!(open_flags & MDS_OPEN_LEASE);
	bool		 try_layout = false;
	bool		 create_layout = false;
	int		 rc = 0;
	ENTRY;

	*ibits = 0;
	mdt_lock_handle_init(lhc);

	if (req_is_replay(mdt_info_req(info)))
		RETURN(0);

	if (S_ISREG(lu_object_attr(&obj->mot_obj))) {
		if (ma->ma_need & MA_LOV && !(ma->ma_valid & MA_LOV) &&
		    md_should_create(open_flags))
			create_layout = true;
		if (exp_connect_layout(info->mti_exp) && !create_layout &&
		    ma->ma_need & MA_LOV)
			try_layout = true;
	}

	if (acq_lease) {
		/* lease open, acquire write mode of open sem */
		down_write(&obj->mot_open_sem);

		/* Lease exists and ask for new lease */
		if (atomic_read(&obj->mot_lease_count) > 0) {
			/* only exclusive open is supported, so lease
			 * are conflicted to each other */
			GOTO(out, rc = -EBUSY);
		}

		/* Lease must be with open lock */
		if (!(open_flags & MDS_OPEN_LOCK)) {
			CERROR("Request lease for file:"DFID ", but open lock "
				"is missed, open_flags = "LPO64".\n",
				PFID(mdt_object_fid(obj)), open_flags);
			GOTO(out, rc = -EPROTO);
		}

		/* XXX: only exclusive open is supported. */
		lm = LCK_EX;
		*ibits = MDS_INODELOCK_OPEN;

		/* never grant LCK_EX layout lock to client */
		try_layout = false;
	} else { /* normal open */
		/* normal open holds read mode of open sem */
		down_read(&obj->mot_open_sem);

		if (open_flags & MDS_OPEN_LOCK) {
			if (open_flags & FMODE_WRITE)
				lm = LCK_CW;
			else if (open_flags & MDS_FMODE_EXEC)
				lm = LCK_PR;
			else
				lm = LCK_CR;

			*ibits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_OPEN;
		} else if (atomic_read(&obj->mot_lease_count) > 0) {
			if (open_flags & FMODE_WRITE)
				lm = LCK_CW;
			else
				lm = LCK_CR;

			/* revoke lease */
			*ibits = MDS_INODELOCK_OPEN;
			try_layout = false;

			lhc = &info->mti_lh[MDT_LH_LOCAL];
		}
		CDEBUG(D_INODE, "normal open:"DFID" lease count: %d, lm: %d\n",
			PFID(mdt_object_fid(obj)),
			atomic_read(&obj->mot_open_count), lm);
	}

	mdt_lock_reg_init(lhc, lm);

	/* one problem to return layout lock on open is that it may result
	 * in too many layout locks cached on the client side. */
	if (!OBD_FAIL_CHECK(OBD_FAIL_MDS_NO_LL_OPEN) && try_layout) {
		/* return lookup lock to validate inode at the client side,
		 * this is pretty important otherwise mdt will return layout
		 * lock for each open.
		 * However this is a double-edged sword because changing
		 * permission will revoke huge # of LOOKUP locks. */
		*ibits |= MDS_INODELOCK_LAYOUT | MDS_INODELOCK_LOOKUP;
		if (!mdt_object_lock_try(info, obj, lhc, *ibits,
					 MDT_CROSS_LOCK)) {
			*ibits &= ~(MDS_INODELOCK_LAYOUT|MDS_INODELOCK_LOOKUP);
			if (*ibits != 0)
				rc = mdt_object_lock(info, obj, lhc, *ibits,
						MDT_CROSS_LOCK);
		}
	} else if (*ibits != 0) {
		rc = mdt_object_lock(info, obj, lhc, *ibits, MDT_CROSS_LOCK);
	}

	CDEBUG(D_INODE, "Requested bits lock:"DFID ", ibits = "LPX64
		", open_flags = "LPO64", try_layout = %d, rc = %d\n",
		PFID(mdt_object_fid(obj)), *ibits, open_flags, try_layout, rc);

	/* will change layout, revoke layout locks by enqueuing EX lock. */
	if (rc == 0 && create_layout) {
		struct mdt_lock_handle *ll = &info->mti_lh[MDT_LH_LAYOUT];

		CDEBUG(D_INODE, "Will create layout, get EX layout lock:"DFID
			", open_flags = "LPO64"\n",
			PFID(mdt_object_fid(obj)), open_flags);

		/* We cannot enqueue another lock for the same resource we
		 * already have a lock for, due to mechanics of waiting list
		 * iterating in ldlm, see LU-3601.
		 * As such we'll drop the open lock we just got above here,
		 * it's ok not to have this open lock as it's main purpose is to
		 * flush unused cached client open handles. */
		if (lustre_handle_is_used(&lhc->mlh_reg_lh))
			mdt_object_unlock(info, obj, lhc, 1);

		LASSERT(!try_layout);
		mdt_lock_handle_init(ll);
		mdt_lock_reg_init(ll, LCK_EX);
		rc = mdt_object_lock(info, obj, ll, MDS_INODELOCK_LAYOUT,
					MDT_LOCAL_LOCK);

		OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_LL_BLOCK, 2);
	}

	/* Check if there is any other open handles after acquiring
	 * open lock. At this point, caching open handles have been revoked
	 * by open lock.
	 * XXX: Now only exclusive open is supported. Need to check the
	 * type of open for generic lease support. */
	if (rc == 0 && acq_lease) {
		struct ptlrpc_request *req = mdt_info_req(info);
		struct mdt_export_data *med = &req->rq_export->exp_mdt_data;
		struct mdt_file_data *mfd;
		bool is_replay_or_resent;
		int open_count = 0;

		/* For lease: application can open a file and then apply lease,
		 * @handle contains original open handle in that case.
		 * In recovery, open REQ will be replayed and the lease REQ may
		 * be resent that means the open handle is already stale, so we
		 * need to fix it up here by finding new handle. */
		is_replay_or_resent = req_is_replay(req) ||
			lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT;

		/* if the request is _not_ a replay request, rr_handle
		 * may be used to hold an openhandle which is issuing the
		 * lease request, so that this openhandle doesn't count. */
		mfd = mdt_handle2mfd(med, info->mti_rr.rr_handle,
				     is_replay_or_resent);
		if (mfd != NULL)
			++open_count;

		CDEBUG(D_INODE, "acq_lease "DFID": openers: %d, want: %d\n",
			PFID(mdt_object_fid(obj)),
			atomic_read(&obj->mot_open_count), open_count);

		if (atomic_read(&obj->mot_open_count) > open_count)
			GOTO(out, rc = -EBUSY);
	}
	GOTO(out, rc);

out:
	RETURN(rc);
}

static void mdt_object_open_unlock(struct mdt_thread_info *info,
				   struct mdt_object *obj,
				   struct mdt_lock_handle *lhc,
				   __u64 ibits, int rc)
{
	__u64 open_flags = info->mti_spec.sp_cr_flags;
	struct mdt_lock_handle *ll = &info->mti_lh[MDT_LH_LOCAL];
	ENTRY;

	if (req_is_replay(mdt_info_req(info)))
		RETURN_EXIT;

	/* Release local lock - the lock put in MDT_LH_LOCAL will never
	 * return to client side. */
	if (lustre_handle_is_used(&ll->mlh_reg_lh))
		mdt_object_unlock(info, obj, ll, 1);

	ll = &info->mti_lh[MDT_LH_LAYOUT];
	/* Release local layout lock, layout was created */
	if (lustre_handle_is_used(&ll->mlh_reg_lh)) {
		LASSERT(!(ibits & MDS_INODELOCK_LAYOUT));
		mdt_object_unlock(info, obj, ll, 1);
	}

	if (open_flags & MDS_OPEN_LEASE)
		up_write(&obj->mot_open_sem);
	else
		up_read(&obj->mot_open_sem);

	/* Cross-ref case, the lock should be returned to the client */
	if (ibits == 0 || rc == -MDT_EREMOTE_OPEN)
		RETURN_EXIT;

	if (!(open_flags & MDS_OPEN_LOCK) && !(ibits & MDS_INODELOCK_LAYOUT)) {
		/* for the open request, the lock will only return to client
		 * if open or layout lock is granted. */
		rc = 1;
	}

	if (rc != 0 || !lustre_handle_is_used(&lhc->mlh_reg_lh)) {
		struct ldlm_reply       *ldlm_rep;

		ldlm_rep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
		mdt_clear_disposition(info, ldlm_rep, DISP_OPEN_LOCK);
		if (lustre_handle_is_used(&lhc->mlh_reg_lh))
			mdt_object_unlock(info, obj, lhc, 1);
	}
	RETURN_EXIT;
}

/**
 * Check release is permitted for the current HSM flags.
 */
static bool mdt_hsm_release_allow(const struct md_attr *ma)
{
	if (!(ma->ma_valid & MA_HSM))
		return false;

	if (ma->ma_hsm.mh_flags & (HS_DIRTY|HS_NORELEASE|HS_LOST))
		return false;

	if (!(ma->ma_hsm.mh_flags & HS_ARCHIVED))
		return false;

	return true;
}

int mdt_open_by_fid_lock(struct mdt_thread_info *info, struct ldlm_reply *rep,
			 struct mdt_lock_handle *lhc)
{
        const struct lu_env     *env   = info->mti_env;
        struct mdt_device       *mdt   = info->mti_mdt;
        __u64                    flags = info->mti_spec.sp_cr_flags;
        struct mdt_reint_record *rr    = &info->mti_rr;
        struct md_attr          *ma    = &info->mti_attr;
        struct mdt_object       *parent= NULL;
        struct mdt_object       *o;
        int                      rc;
	int			 object_locked = 0;
	__u64			 ibits = 0;
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
		GOTO(out_parent_put, rc = PTR_ERR(o));

	if (mdt_object_remote(o)) {
		CDEBUG(D_INFO, "%s: "DFID" is on remote MDT.\n",
		       mdt_obd_name(info->mti_mdt),
		       PFID(rr->rr_fid2));
		GOTO(out, rc = -EREMOTE);
	} else if (!mdt_object_exists(o)) {
		mdt_set_disposition(info, rep,
				    DISP_IT_EXECD |
				    DISP_LOOKUP_EXECD |
				    DISP_LOOKUP_NEG);
		GOTO(out, rc = -ENOENT);
	}

	mdt_set_disposition(info, rep, (DISP_IT_EXECD | DISP_LOOKUP_EXECD));

	mdt_prep_ma_buf_from_rep(info, o, ma);
	if (flags & MDS_OPEN_RELEASE)
		ma->ma_need |= MA_HSM;
	rc = mdt_attr_get_complex(info, o, ma);
	if (rc)
		GOTO(out, rc);

	/* If a release request, check file flags are fine and ask for an
	 * exclusive open access. */
	if (flags & MDS_OPEN_RELEASE && !mdt_hsm_release_allow(ma))
		GOTO(out, rc = -EPERM);

	rc = mdt_check_resent_lock(info, o, lhc);
	if (rc < 0) {
		GOTO(out, rc);
	} else if (rc > 0) {
		rc = mdt_object_open_lock(info, o, lhc, &ibits);
		object_locked = 1;
		if (rc)
			GOTO(out_unlock, rc);
	}

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

        rc = mdt_finish_open(info, parent, o, flags, 0, rep);
	if (!rc) {
		mdt_set_disposition(info, rep, DISP_LOOKUP_POS);
		if (flags & MDS_OPEN_LOCK)
			mdt_set_disposition(info, rep, DISP_OPEN_LOCK);
		if (flags & MDS_OPEN_LEASE)
			mdt_set_disposition(info, rep, DISP_OPEN_LEASE);
	}
	GOTO(out_unlock, rc);

out_unlock:
	if (object_locked)
		mdt_object_open_unlock(info, o, lhc, ibits, rc);
out:
	mdt_object_put(env, o);
out_parent_put:
	if (parent != NULL)
		mdt_object_put(env, parent);
	return rc;
}

/* Cross-ref request. Currently it can only be a pure open (w/o create) */
static int mdt_cross_open(struct mdt_thread_info *info,
			  const struct lu_fid *parent_fid,
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

	if (mdt_object_remote(o)) {
		/* Something is wrong here, the object is on another MDS! */
		CERROR("%s: "DFID" isn't on this server!: rc = %d\n",
		       mdt_obd_name(info->mti_mdt), PFID(fid), -EFAULT);
		LU_OBJECT_DEBUG(D_WARNING, info->mti_env,
				&o->mot_obj,
				"Object isn't on this server! FLD error?\n");
                rc = -EFAULT;
	} else {
		if (mdt_object_exists(o)) {
			/* Do permission check for cross-open. */
			rc = mo_permission(info->mti_env, NULL,
					   mdt_object_child(o),
					   NULL, flags | MDS_OPEN_CROSS);
			if (rc)
				goto out;

			mdt_prep_ma_buf_from_rep(info, o, ma);
			mdt_set_capainfo(info, 0, fid, BYPASS_CAPA);
			rc = mdt_attr_get_complex(info, o, ma);
			if (rc != 0)
				GOTO(out, rc);

			rc = mdt_finish_open(info, NULL, o, flags, 0, rep);
		} else {
			/*
			 * Something is wrong here. lookup was positive but
			 * there is no object!
			 */
			CERROR("%s: "DFID" doesn't exist!: rc = %d\n",
			      mdt_obd_name(info->mti_mdt), PFID(fid), -EFAULT);
			rc = -EFAULT;
		}
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
	__u64			 ibits = 0;
        struct mdt_reint_record *rr = &info->mti_rr;
        int                      result, rc;
        int                      created = 0;
	int			 object_locked = 0;
        __u32                    msg_flags;
        ENTRY;

        OBD_FAIL_TIMEOUT_ORSET(OBD_FAIL_MDS_PAUSE_OPEN, OBD_FAIL_ONCE,
                               (obd_timeout + 1) / 4);

	mdt_counter_incr(req, LPROC_MDT_OPEN);
        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        ma->ma_need = MA_INODE;
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

	CDEBUG(D_INODE, "I am going to open "DFID"/("DNAME"->"DFID") "
	       "cr_flag="LPO64" mode=0%06o msg_flag=0x%x\n",
	       PFID(rr->rr_fid1), PNAME(&rr->rr_name),
	       PFID(rr->rr_fid2), create_flags,
	       ma->ma_attr.la_mode, msg_flags);

	if (info->mti_cross_ref) {
		/* This is cross-ref open */
		mdt_set_disposition(info, ldlm_rep,
			    (DISP_IT_EXECD | DISP_LOOKUP_EXECD |
			     DISP_LOOKUP_POS));
		result = mdt_cross_open(info, rr->rr_fid2, rr->rr_fid1,
					ldlm_rep, create_flags);
		GOTO(out, result);
	} else if (req_is_replay(req) ||
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
	} else if (create_flags & (MDS_OPEN_BY_FID | MDS_OPEN_LOCK)) {
		/*
		 * MDS_OPEN_LOCK is checked for backward compatibility with 2.1
		 * client.
		 */
		result = mdt_open_by_fid_lock(info, ldlm_rep, lhc);
		if (result < 0)
			CDEBUG(D_INFO, "no object for "DFID": %d\n",
			       PFID(rr->rr_fid2), result);
		GOTO(out, result);
	}

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_OPEN_PACK))
                GOTO(out, result = err_serious(-ENOMEM));

        mdt_set_disposition(info, ldlm_rep,
                            (DISP_IT_EXECD | DISP_LOOKUP_EXECD));

	if (!lu_name_is_valid(&rr->rr_name))
		GOTO(out, result = -EPROTO);

        lh = &info->mti_lh[MDT_LH_PARENT];
	mdt_lock_pdo_init(lh,
			  (create_flags & MDS_OPEN_CREAT) ? LCK_PW : LCK_PR,
			  &rr->rr_name);

        parent = mdt_object_find_lock(info, rr->rr_fid1, lh,
                                      MDS_INODELOCK_UPDATE);
        if (IS_ERR(parent))
                GOTO(out, result = PTR_ERR(parent));

        /* get and check version of parent */
        result = mdt_version_get_check(info, parent, 0);
        if (result)
                GOTO(out_parent, result);

        fid_zero(child_fid);

	result = mdo_lookup(info->mti_env, mdt_object_child(parent),
			    &rr->rr_name, child_fid, &info->mti_spec);

	LASSERTF(ergo(result == 0, fid_is_sane(child_fid)),
		 "looking for "DFID"/"DNAME", found FID = "DFID"\n",
		 PFID(mdt_object_fid(parent)), PNAME(&rr->rr_name),
		 PFID(child_fid));

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
		if (exp_connect_flags(req->rq_export) & OBD_CONNECT_RDONLY)
			GOTO(out_parent, result = -EROFS);
                *child_fid = *info->mti_rr.rr_fid2;
                LASSERTF(fid_is_sane(child_fid), "fid="DFID"\n",
                         PFID(child_fid));
		/* In the function below, .hs_keycmp resolves to
		 * lu_obj_hop_keycmp() */
		/* coverity[overrun-buffer-val] */
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
		/* Create under OBF and .lustre is not permitted */
		if (!fid_is_md_operative(rr->rr_fid1))
			GOTO(out_child, result = -EPERM);

		/* save versions in reply */
		mdt_version_get_save(info, parent, 0);
		mdt_version_get_save(info, child, 1);

		/* version of child will be changed */
		tgt_vbr_obj_set(info->mti_env, mdt_obj2dt(child));

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
				    &rr->rr_name,
				    mdt_object_child(child),
				    &info->mti_spec,
				    &info->mti_attr);
                if (result == -ERESTART) {
                        mdt_clear_disposition(info, ldlm_rep, DISP_OPEN_CREATE);
                        GOTO(out_child, result);
                } else {
			mdt_prep_ma_buf_from_rep(info, child, ma);
			/* XXX: we should call this once, see few lines below */
			if (result == 0)
				result = mdt_attr_get_complex(info, child, ma);

                        if (result != 0)
                                GOTO(out_child, result);
                }
                created = 1;
        } else {
                /*
                 * The object is on remote node, return its FID for remote open.
                 */
		if (mdt_object_remote(child)) {
                        /*
                         * Check if this lock already was sent to client and
                         * this is resent case. For resent case do not take lock
                         * again, use what is already granted.
                         */
                        LASSERT(lhc != NULL);

			rc = mdt_check_resent_lock(info, child, lhc);
			if (rc < 0) {
				GOTO(out_child, result = rc);
			} else if (rc > 0) {
                                mdt_lock_handle_init(lhc);
                                mdt_lock_reg_init(lhc, LCK_PR);

                                rc = mdt_object_lock(info, child, lhc,
                                                     MDS_INODELOCK_LOOKUP,
                                                     MDT_CROSS_LOCK);
                        }
			repbody->mbo_fid1 = *mdt_object_fid(child);
			repbody->mbo_valid |= (OBD_MD_FLID | OBD_MD_MDS);
                        if (rc != 0)
                                result = rc;
			else
				result = -MDT_EREMOTE_OPEN;
                        GOTO(out_child, result);
		} else if (mdt_object_exists(child)) {
			/* We have to get attr & LOV EA & HSM for this
			 * object. */
			mdt_prep_ma_buf_from_rep(info, child, ma);
			ma->ma_need |= MA_HSM;
			result = mdt_attr_get_complex(info, child, ma);
			if (result != 0)
				GOTO(out_child, result);
		} else {
			/* Object does not exist. Likely FS corruption. */
			CERROR("%s: name '"DNAME"' present, but FID "
			       DFID" is invalid\n", mdt_obd_name(info->mti_mdt),
			       PNAME(&rr->rr_name), PFID(child_fid));
			GOTO(out_child, result = -EIO);
		}
        }

	rc = mdt_check_resent_lock(info, child, lhc);
	if (rc < 0) {
		GOTO(out_child, result = rc);
	} else if (rc == 0) {
		/* the open lock might already be gotten in
		 * ldlm_handle_enqueue() */
		LASSERT(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT);
		if (create_flags & MDS_OPEN_LOCK)
			mdt_set_disposition(info, ldlm_rep, DISP_OPEN_LOCK);
	} else {
		/* get openlock if this isn't replay and client requested it */
		if (!req_is_replay(req)) {
			rc = mdt_object_open_lock(info, child, lhc, &ibits);
			object_locked = 1;
			if (rc != 0)
				GOTO(out_child_unlock, result = rc);
			else if (create_flags & MDS_OPEN_LOCK)
				mdt_set_disposition(info, ldlm_rep,
						    DISP_OPEN_LOCK);
		}
	}
	/* Try to open it now. */
	rc = mdt_finish_open(info, parent, child, create_flags,
			     created, ldlm_rep);
	if (rc) {
		result = rc;
		/* openlock will be released if mdt_finish_open failed */
		mdt_clear_disposition(info, ldlm_rep, DISP_OPEN_LOCK);

		if (created && create_flags & MDS_OPEN_VOLATILE) {
			CERROR("%s: cannot open volatile file "DFID", orphan "
			       "file will be left in PENDING directory until "
			       "next reboot, rc = %d\n", mdt_obd_name(mdt),
			       PFID(mdt_object_fid(child)), rc);
			GOTO(out_child_unlock, result);
		}

		if (created) {
			ma->ma_need = 0;
			ma->ma_valid = 0;
			rc = mdo_unlink(info->mti_env,
					mdt_object_child(parent),
					mdt_object_child(child),
					&rr->rr_name,
					&info->mti_attr, 0);
			if (rc != 0)
				CERROR("%s: "DFID" cleanup of open: rc = %d\n",
				       mdt_obd_name(info->mti_mdt),
				       PFID(mdt_object_fid(child)), rc);
			mdt_clear_disposition(info, ldlm_rep, DISP_OPEN_CREATE);
		}
	}
	EXIT;
out_child_unlock:
	if (object_locked)
		mdt_object_open_unlock(info, child, lhc, ibits, result);
out_child:
	mdt_object_put(info->mti_env, child);
out_parent:
	mdt_object_unlock_put(info, parent, lh, result || !created);
out:
	if (result)
		lustre_msg_set_transno(req->rq_repmsg, 0);
	return result;
}

/**
 * Create an orphan object use local root.
 */
static struct mdt_object *mdt_orphan_open(struct mdt_thread_info *info,
					  struct mdt_device *mdt,
					  const struct lu_fid *fid,
					  struct md_attr *attr, fmode_t fmode)
{
	const struct lu_env *env = info->mti_env;
	struct md_op_spec *spec = &info->mti_spec;
	struct lu_fid *local_root_fid = &info->mti_tmp_fid1;
	struct mdt_object *obj = NULL;
	struct mdt_object *local_root;
	static const struct lu_name lname = {
		.ln_name = "i_am_nobody",
		.ln_namelen = sizeof("i_am_nobody") - 1,
	};
	struct lu_ucred *uc;
	cfs_cap_t uc_cap_save;
	int rc;
	ENTRY;

	rc = dt_root_get(env, mdt->mdt_bottom, local_root_fid);
	if (rc != 0)
		RETURN(ERR_PTR(rc));

	local_root = mdt_object_find(env, mdt, local_root_fid);
	if (IS_ERR(local_root))
		RETURN(local_root);

	obj = mdt_object_new(env, mdt, fid);
	if (IS_ERR(obj))
		GOTO(out, rc = PTR_ERR(obj));

	spec->sp_cr_lookup = 0;
	spec->sp_feat = &dt_directory_features;
	spec->sp_cr_mode = MDL_MINMODE; /* no lock */
	spec->sp_cr_flags = MDS_OPEN_VOLATILE | fmode;
	if (attr->ma_valid & MA_LOV) {
		spec->u.sp_ea.eadata = attr->ma_lmm;
		spec->u.sp_ea.eadatalen = attr->ma_lmm_size;
		spec->sp_cr_flags |= MDS_OPEN_HAS_EA;
	} else {
		spec->sp_cr_flags |= MDS_OPEN_DELAY_CREATE;
	}

	uc = lu_ucred(env);
	uc_cap_save = uc->uc_cap;
	uc->uc_cap |= 1 << CFS_CAP_DAC_OVERRIDE;
	rc = mdo_create(env, mdt_object_child(local_root), &lname,
			mdt_object_child(obj), spec, attr);
	uc->uc_cap = uc_cap_save;
	if (rc < 0) {
		CERROR("%s: cannot create volatile file "DFID": rc = %d\n",
		       mdt_obd_name(mdt), PFID(fid), rc);
		GOTO(out, rc);
	}

	rc = mo_open(env, mdt_object_child(obj), MDS_OPEN_CREATED);
	if (rc < 0)
		CERROR("%s: cannot open volatile file "DFID", orphan "
		       "file will be left in PENDING directory until "
		       "next reboot, rc = %d\n", mdt_obd_name(mdt),
		       PFID(fid), rc);
	GOTO(out, rc);

out:
	if (rc < 0) {
		if (!IS_ERR(obj))
			mdt_object_put(env, obj);
		obj = ERR_PTR(rc);
	}
	mdt_object_put(env, local_root);
	return obj;
}

static int mdt_hsm_release(struct mdt_thread_info *info, struct mdt_object *o,
			   struct md_attr *ma)
{
	struct mdt_lock_handle *lh = &info->mti_lh[MDT_LH_LAYOUT];
	struct close_data      *data;
	struct ldlm_lock       *lease;
	struct mdt_object      *orphan;
	struct md_attr         *orp_ma;
	struct lu_buf          *buf;
	bool			lease_broken;
	int                     rc;
	int                     rc2;
	ENTRY;

	if (exp_connect_flags(info->mti_exp) & OBD_CONNECT_RDONLY)
		RETURN(-EROFS);

	data = req_capsule_client_get(info->mti_pill, &RMF_CLOSE_DATA);
	if (data == NULL)
		RETURN(-EPROTO);

	lease = ldlm_handle2lock(&data->cd_handle);
	if (lease == NULL)
		RETURN(-ESTALE);

	/* try to hold open_sem so that nobody else can open the file */
	if (!down_write_trylock(&o->mot_open_sem)) {
		ldlm_lock_cancel(lease);
		GOTO(out_reprocess, rc = -EBUSY);
	}

	/* Check if the lease open lease has already canceled */
	lock_res_and_lock(lease);
	lease_broken = ldlm_is_cancel(lease);
	unlock_res_and_lock(lease);

	LDLM_DEBUG(lease, DFID " lease broken? %d\n",
		   PFID(mdt_object_fid(o)), lease_broken);

	/* Cancel server side lease. Client side counterpart should
	 * have been cancelled. It's okay to cancel it now as we've
	 * held mot_open_sem. */
	ldlm_lock_cancel(lease);

	if (lease_broken) /* don't perform release task */
		GOTO(out_unlock, rc = -ESTALE);

	if (fid_is_zero(&data->cd_fid) || !fid_is_sane(&data->cd_fid))
		GOTO(out_unlock, rc = -EINVAL);

	/* ma_need was set before but it seems fine to change it in order to
	 * avoid modifying the one from RPC */
	ma->ma_need = MA_HSM;
	rc = mdt_attr_get_complex(info, o, ma);
	if (rc != 0)
		GOTO(out_unlock, rc);

	if (!mdt_hsm_release_allow(ma))
		GOTO(out_unlock, rc = -EPERM);

	/* already released? */
	if (ma->ma_hsm.mh_flags & HS_RELEASED)
		GOTO(out_unlock, rc = 0);

	/* Compare on-disk and packed data_version */
	if (data->cd_data_version != ma->ma_hsm.mh_arch_ver) {
		CDEBUG(D_HSM, DFID" data_version mismatches: packed="LPU64
		       " and on-disk="LPU64"\n", PFID(mdt_object_fid(o)),
		       data->cd_data_version, ma->ma_hsm.mh_arch_ver);
		GOTO(out_unlock, rc = -EPERM);
	}

	ma->ma_valid = MA_INODE;
	ma->ma_attr.la_valid &= LA_ATIME | LA_MTIME | LA_CTIME | LA_SIZE;
	rc = mo_attr_set(info->mti_env, mdt_object_child(o), ma);
	if (rc < 0)
		GOTO(out_unlock, rc);

	ma->ma_need = MA_INODE | MA_LOV;
	rc = mdt_attr_get_complex(info, o, ma);
	if (rc < 0)
		GOTO(out_unlock, rc);

	if (!(ma->ma_valid & MA_LOV)) {
		/* Even empty file are released */
		memset(ma->ma_lmm, 0, sizeof(*ma->ma_lmm));
		ma->ma_lmm->lmm_magic = cpu_to_le32(LOV_MAGIC_V1_DEF);
		ma->ma_lmm->lmm_pattern = cpu_to_le32(LOV_PATTERN_RAID0);
		ma->ma_lmm->lmm_stripe_size = cpu_to_le32(LOV_MIN_STRIPE_SIZE);
		ma->ma_lmm_size = sizeof(*ma->ma_lmm);
	} else {
		/* Magic must be LOV_MAGIC_Vx_DEF otherwise LOD will interpret
		 * ma_lmm as lov_user_md, then it will be confused by union of
		 * layout_gen and stripe_offset. */
		if (le32_to_cpu(ma->ma_lmm->lmm_magic) == LOV_MAGIC_V1)
			ma->ma_lmm->lmm_magic = cpu_to_le32(LOV_MAGIC_V1_DEF);
		else if (le32_to_cpu(ma->ma_lmm->lmm_magic) == LOV_MAGIC_V3)
			ma->ma_lmm->lmm_magic = cpu_to_le32(LOV_MAGIC_V3_DEF);
		else
			GOTO(out_unlock, rc = -EINVAL);
	}

	/* Set file as released */
	ma->ma_lmm->lmm_pattern |= cpu_to_le32(LOV_PATTERN_F_RELEASED);

	/* Hopefully it's not used in this call path */
	orp_ma = &info->mti_u.som.attr;
	orp_ma->ma_attr.la_mode = S_IFREG | S_IWUSR;
	orp_ma->ma_attr.la_uid = ma->ma_attr.la_uid;
	orp_ma->ma_attr.la_gid = ma->ma_attr.la_gid;
	orp_ma->ma_attr.la_valid = LA_MODE | LA_UID | LA_GID;
	orp_ma->ma_lmm = ma->ma_lmm;
	orp_ma->ma_lmm_size = ma->ma_lmm_size;
	orp_ma->ma_valid = MA_INODE | MA_LOV;
	orphan = mdt_orphan_open(info, info->mti_mdt, &data->cd_fid, orp_ma,
				 FMODE_WRITE);
	if (IS_ERR(orphan)) {
		CERROR("%s: cannot open orphan file "DFID": rc = %ld\n",
		       mdt_obd_name(info->mti_mdt), PFID(&data->cd_fid),
		       PTR_ERR(orphan));
		GOTO(out_unlock, rc = PTR_ERR(orphan));
	}

	/* Set up HSM attribute for orphan object */
	CLASSERT(sizeof(struct hsm_attrs) <= sizeof(info->mti_xattr_buf));
	buf = &info->mti_buf;
	buf->lb_buf = info->mti_xattr_buf;
	buf->lb_len = sizeof(struct hsm_attrs);
	ma->ma_hsm.mh_flags |= HS_RELEASED;
	lustre_hsm2buf(buf->lb_buf, &ma->ma_hsm);
	ma->ma_hsm.mh_flags &= ~HS_RELEASED;

	mdt_lock_reg_init(lh, LCK_EX);
	rc = mdt_object_lock(info, o, lh, MDS_INODELOCK_LAYOUT |
			     MDS_INODELOCK_XATTR, MDT_LOCAL_LOCK);
	if (rc != 0)
		GOTO(out_close, rc);

	rc = mo_xattr_set(info->mti_env, mdt_object_child(orphan), buf,
			  XATTR_NAME_HSM, 0);

	if (rc == 0)
		/* Swap layout with orphan object */
		rc = mo_swap_layouts(info->mti_env, mdt_object_child(o),
				     mdt_object_child(orphan),
				     SWAP_LAYOUTS_MDS_HSM);

	/* Release exclusive LL */
	mdt_object_unlock(info, o, lh, 1);

	EXIT;

out_close:
	/* Close orphan object anyway */
	rc2 = mo_close(info->mti_env, mdt_object_child(orphan), orp_ma,
		       FMODE_WRITE);
	if (rc2 < 0)
		CERROR("%s: error closing volatile file "DFID": rc = %d\n",
		       mdt_obd_name(info->mti_mdt), PFID(&data->cd_fid), rc2);
	LU_OBJECT_DEBUG(D_HSM, info->mti_env, &orphan->mot_obj,
			"object closed\n");
	mdt_object_put(info->mti_env, orphan);

out_unlock:
	up_write(&o->mot_open_sem);

	if (rc == 0) { /* already released */
		struct mdt_body *repbody;
		repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
		LASSERT(repbody != NULL);
		repbody->mbo_valid |= OBD_MD_FLRELEASED;
	}

out_reprocess:
	ldlm_reprocess_all(lease->l_resource);
	LDLM_LOCK_PUT(lease);

	ma->ma_valid = 0;
	ma->ma_need = 0;

	return rc;
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
	__u64 mode;
        ENTRY;

        mode = mfd->mfd_mode;

	if (ma->ma_attr_flags & MDS_HSM_RELEASE) {
		rc = mdt_hsm_release(info, o, ma);
		if (rc < 0) {
			CDEBUG(D_HSM, "%s: File " DFID " release failed: %d\n",
				mdt_obd_name(info->mti_mdt),
				PFID(mdt_object_fid(o)), rc);
			/* continue to close even error occurred. */
		}
	}

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

	/* If file data is modified, add the dirty flag. */
	if (ma->ma_attr_flags & MDS_DATA_MODIFIED)
		rc = mdt_add_dirty_flag(info, o, ma);

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
		spin_lock(&med->med_open_lock);
		list_add(&mfd->mfd_list, &med->med_open_head);
		class_handle_hash_back(&mfd->mfd_handle);
		spin_unlock(&med->med_open_lock);

                if (ret == MDT_IOEPOCH_OPENED) {
                        ret = 0;
                } else {
                        ret = -EAGAIN;
                        CDEBUG(D_INODE, "Size-on-MDS attribute update is "
                               "needed on "DFID"\n", PFID(mdt_object_fid(o)));
                }
        } else {
		/* adjust open and lease count */
		if (mode & MDS_OPEN_LEASE) {
			LASSERT(atomic_read(&o->mot_lease_count) > 0);
			atomic_dec(&o->mot_lease_count);
		}
		LASSERT(atomic_read(&o->mot_open_count) > 0);
		atomic_dec(&o->mot_open_count);

		mdt_mfd_free(mfd);
		mdt_object_put(info->mti_env, o);
	}

	RETURN(rc ? rc : ret);
}

int mdt_close(struct tgt_session_info *tsi)
{
	struct mdt_thread_info	*info = tsi2mdt_info(tsi);
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
        struct mdt_export_data *med;
        struct mdt_file_data   *mfd;
        struct mdt_object      *o;
        struct md_attr         *ma = &info->mti_attr;
        struct mdt_body        *repbody = NULL;
        int rc, ret = 0;
        ENTRY;

	mdt_counter_incr(req, LPROC_MDT_CLOSE);
	/* Close may come with the Size-on-MDS update. Unpack it. */
	rc = mdt_close_unpack(info);
	if (rc)
		GOTO(out, rc = err_serious(rc));

        LASSERT(info->mti_ioepoch);

	/* These fields are no longer used and are left for compatibility.
	 * size is always zero */
        req_capsule_set_size(info->mti_pill, &RMF_MDT_MD, RCL_SERVER,
			     0);
        req_capsule_set_size(info->mti_pill, &RMF_LOGCOOKIES, RCL_SERVER,
			     0);
        rc = req_capsule_server_pack(info->mti_pill);
        if (mdt_check_resent(info, mdt_reconstruct_generic, NULL)) {
                mdt_client_compatibility(info);
                if (rc == 0)
                        mdt_fix_reply(info);
		mdt_exit_ucred(info);
		GOTO(out, rc = lustre_msg_get_status(req->rq_repmsg));
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
                ma->ma_need = MA_INODE | MA_LOV | MA_COOKIE;
		repbody->mbo_eadatasize = 0;
		repbody->mbo_aclsize = 0;
        } else {
                rc = err_serious(rc);
        }

        med = &req->rq_export->exp_mdt_data;
	spin_lock(&med->med_open_lock);
	mfd = mdt_handle2mfd(med, &info->mti_ioepoch->handle,
			     req_is_replay(req));
	if (mdt_mfd_closed(mfd)) {
		spin_unlock(&med->med_open_lock);
		CDEBUG(D_INODE, "no handle for file close: fid = "DFID
		       ": cookie = "LPX64"\n", PFID(info->mti_rr.rr_fid1),
		       info->mti_ioepoch->handle.cookie);
		/** not serious error since bug 3633 */
		rc = -ESTALE;
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
                mdt_empty_transno(info, rc);
                mdt_object_put(info->mti_env, o);
        }
        if (repbody != NULL) {
                mdt_client_compatibility(info);
                rc = mdt_fix_reply(info);
        }

	mdt_exit_ucred(info);
	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_CLOSE_PACK))
		GOTO(out, rc = err_serious(-ENOMEM));

	if (OBD_FAIL_CHECK_RESET(OBD_FAIL_MDS_CLOSE_NET_REP,
				 OBD_FAIL_MDS_CLOSE_NET_REP))
		tsi->tsi_reply_fail_id = OBD_FAIL_MDS_CLOSE_NET_REP;
out:
	mdt_thread_info_fini(info);
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
int mdt_done_writing(struct tgt_session_info *tsi)
{
	struct ptlrpc_request	*req = tgt_ses_req(tsi);
	struct mdt_thread_info	*info = tsi2mdt_info(tsi);
        struct mdt_body         *repbody = NULL;
        struct mdt_export_data  *med;
        struct mdt_file_data    *mfd;
        int rc;
        ENTRY;

	rc = req_capsule_server_pack(tsi->tsi_pill);
	if (rc)
		GOTO(out, rc = err_serious(rc));

	repbody = req_capsule_server_get(tsi->tsi_pill, &RMF_MDT_BODY);
	repbody->mbo_eadatasize = 0;
	repbody->mbo_aclsize = 0;

	/* Done Writing may come with the Size-on-MDS update. Unpack it. */
	rc = mdt_close_unpack(info);
	if (rc)
		GOTO(out, rc = err_serious(rc));

	if (mdt_check_resent(info, mdt_reconstruct_generic, NULL)) {
		mdt_exit_ucred(info);
		GOTO(out, rc = lustre_msg_get_status(req->rq_repmsg));
	}

	med = &info->mti_exp->exp_mdt_data;
	spin_lock(&med->med_open_lock);
	mfd = mdt_handle2mfd(med, &info->mti_ioepoch->handle,
			     req_is_replay(req));
	if (mfd == NULL) {
		spin_unlock(&med->med_open_lock);
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
		} else
			rc = -ESTALE;
		GOTO(error_ucred, rc);
	}

	LASSERT(mfd->mfd_mode == MDS_FMODE_EPOCH ||
		mfd->mfd_mode == MDS_FMODE_TRUNC);
	class_handle_unhash(&mfd->mfd_handle);
	list_del_init(&mfd->mfd_list);
	spin_unlock(&med->med_open_lock);

        /* Set EPOCH CLOSE flag if not set by client. */
        info->mti_ioepoch->flags |= MF_EPOCH_CLOSE;
        info->mti_attr.ma_valid = 0;

        info->mti_attr.ma_lmm_size = info->mti_mdt->mdt_max_mdsize;
        OBD_ALLOC_LARGE(info->mti_attr.ma_lmm, info->mti_mdt->mdt_max_mdsize);
	if (info->mti_attr.ma_lmm == NULL)
		GOTO(error_ucred, rc = -ENOMEM);

        rc = mdt_mfd_close(info, mfd);

        OBD_FREE_LARGE(info->mti_attr.ma_lmm, info->mti_mdt->mdt_max_mdsize);
        mdt_empty_transno(info, rc);
error_ucred:
	mdt_exit_ucred(info);
out:
	mdt_thread_info_fini(info);
	RETURN(rc);
}
