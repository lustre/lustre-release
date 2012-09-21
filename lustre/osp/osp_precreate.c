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
 * Copyright (c) 2011, 2012, Intel, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osp/osp_sync.c
 *
 * Lustre OST Proxy Device
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include "osp_internal.h"

/*
 * there are two specific states to take care about:
 *
 * = import is disconnected =
 *
 * = import is inactive =
 *   in this case osp_declare_object_create() returns an error
 *
 */

/*
 * statfs
 */
static inline int osp_statfs_need_update(struct osp_device *d)
{
	return !cfs_time_before(cfs_time_current(),
				d->opd_statfs_fresh_till);
}

static void osp_statfs_timer_cb(unsigned long _d)
{
	struct osp_device *d = (struct osp_device *) _d;

	LASSERT(d);
	cfs_waitq_signal(&d->opd_pre_waitq);
}

static int osp_statfs_interpret(const struct lu_env *env,
				struct ptlrpc_request *req,
				union ptlrpc_async_args *aa, int rc)
{
	struct obd_import	*imp = req->rq_import;
	struct obd_statfs	*msfs;
	struct osp_device	*d;

	ENTRY;

	aa = ptlrpc_req_async_args(req);
	d = aa->pointer_arg[0];
	LASSERT(d);

	if (rc != 0)
		GOTO(out, rc);

	msfs = req_capsule_server_get(&req->rq_pill, &RMF_OBD_STATFS);
	if (msfs == NULL)
		GOTO(out, rc = -EPROTO);

	d->opd_statfs = *msfs;

	osp_pre_update_status(d, rc);

	/* schedule next update */
	d->opd_statfs_fresh_till = cfs_time_shift(d->opd_statfs_maxage);
	cfs_timer_arm(&d->opd_statfs_timer, d->opd_statfs_fresh_till);
	d->opd_statfs_update_in_progress = 0;

	CDEBUG(D_CACHE, "updated statfs %p\n", d);

	RETURN(0);
out:
	/* couldn't update statfs, try again as soon as possible */
	cfs_waitq_signal(&d->opd_pre_waitq);
	if (req->rq_import_generation == imp->imp_generation)
		CERROR("%s: couldn't update statfs: rc = %d\n",
		       d->opd_obd->obd_name, rc);
	RETURN(rc);
}

static int osp_statfs_update(struct osp_device *d)
{
	struct ptlrpc_request	*req;
	struct obd_import	*imp;
	union ptlrpc_async_args	*aa;
	int			 rc;

	ENTRY;

	CDEBUG(D_CACHE, "going to update statfs\n");

	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_STATFS);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_STATFS);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}
	ptlrpc_request_set_replen(req);
	req->rq_request_portal = OST_CREATE_PORTAL;
	ptlrpc_at_set_req_timeout(req);

	req->rq_interpret_reply = (ptlrpc_interpterer_t)osp_statfs_interpret;
	aa = ptlrpc_req_async_args(req);
	aa->pointer_arg[0] = d;

	ptlrpcd_add_req(req, PDL_POLICY_ROUND, -1);

	cfs_timer_disarm(&d->opd_statfs_timer);

	/*
	 * no updates till reply
	 */
	d->opd_statfs_fresh_till = cfs_time_shift(obd_timeout * 1000);
	d->opd_statfs_update_in_progress = 1;

	RETURN(0);
}

/*
 * XXX: there might be a case where removed object(s) do not add free
 * space (empty object). if the number of such deletions is high, then
 * we can start to update statfs too often - a rpc storm
 * TODO: some throttling is needed
 */
void osp_statfs_need_now(struct osp_device *d)
{
	if (!d->opd_statfs_update_in_progress) {
		/*
		 * if current status is -ENOSPC (lack of free space on OST)
		 * then we should poll OST immediately once object destroy
		 * is replied
		 */
		d->opd_statfs_fresh_till = cfs_time_shift(-1);
		cfs_timer_disarm(&d->opd_statfs_timer);
		cfs_waitq_signal(&d->opd_pre_waitq);
	}
}


/*
 * OSP tries to maintain pool of available objects so that calls to create
 * objects don't block most of time
 *
 * each time OSP gets connected to OST, we should start from precreation cleanup
 */
static inline int osp_precreate_running(struct osp_device *d)
{
	return !!(d->opd_pre_thread.t_flags & SVC_RUNNING);
}

static inline int osp_precreate_stopped(struct osp_device *d)
{
	return !!(d->opd_pre_thread.t_flags & SVC_STOPPED);
}

static inline int osp_precreate_near_empty_nolock(struct osp_device *d)
{
	int window = d->opd_pre_last_created - d->opd_pre_next;

	/* don't consider new precreation till OST is healty and
	 * has free space */
	return ((window - d->opd_pre_reserved < d->opd_pre_grow_count / 2) &&
		(d->opd_pre_status == 0));
}

static inline int osp_precreate_near_empty(struct osp_device *d)
{
	int rc;

	/* XXX: do we really need locking here? */
	cfs_spin_lock(&d->opd_pre_lock);
	rc = osp_precreate_near_empty_nolock(d);
	cfs_spin_unlock(&d->opd_pre_lock);
	return rc;
}

static int osp_precreate_send(struct osp_device *d)
{
	struct ptlrpc_request	*req;
	struct obd_import	*imp;
	struct ost_body		*body;
	int			 rc, grow, diff;

	ENTRY;

	/* don't precreate new objects till OST healthy and has free space */
	if (unlikely(d->opd_pre_status)) {
		CDEBUG(D_INFO, "%s: don't send new precreate: rc = %d\n",
		       d->opd_obd->obd_name, d->opd_pre_status);
		RETURN(0);
	}

	/*
	 * if not connection/initialization is compeleted, ignore
	 */
	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_CREATE);
	if (req == NULL)
		RETURN(-ENOMEM);
	req->rq_request_portal = OST_CREATE_PORTAL;
	/* we should not resend create request - anyway we will have delorphan
	 * and kill these objects */
	req->rq_no_delay = req->rq_no_resend = 1;

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_CREATE);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	cfs_spin_lock(&d->opd_pre_lock);
	if (d->opd_pre_grow_count > d->opd_pre_max_grow_count / 2)
		d->opd_pre_grow_count = d->opd_pre_max_grow_count / 2;
	grow = d->opd_pre_grow_count;
	cfs_spin_unlock(&d->opd_pre_lock);

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);
	body->oa.o_id = d->opd_pre_last_created + grow;
	body->oa.o_seq = FID_SEQ_OST_MDT0; /* XXX: support for CMD? */
	body->oa.o_valid = OBD_MD_FLGROUP;

	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc) {
		CERROR("%s: can't precreate: rc = %d\n",
		       d->opd_obd->obd_name, rc);
		GOTO(out_req, rc);
	}
	LASSERT(req->rq_transno == 0);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out_req, rc = -EPROTO);

	CDEBUG(D_HA, "new last_created %lu\n", (unsigned long) body->oa.o_id);
	LASSERT(body->oa.o_id > d->opd_pre_next);

	diff = body->oa.o_id - d->opd_pre_last_created;

	cfs_spin_lock(&d->opd_pre_lock);
	if (diff < grow) {
		/* the OST has not managed to create all the
		 * objects we asked for */
		d->opd_pre_grow_count = max(diff, OST_MIN_PRECREATE);
		d->opd_pre_grow_slow = 1;
	} else {
		/* the OST is able to keep up with the work,
		 * we could consider increasing grow_count
		 * next time if needed */
		d->opd_pre_grow_slow = 0;
	}
	d->opd_pre_last_created = body->oa.o_id;
	cfs_spin_unlock(&d->opd_pre_lock);
	CDEBUG(D_OTHER, "current precreated pool: %llu-%llu\n",
	       d->opd_pre_next, d->opd_pre_last_created);

out_req:
	/* now we can wakeup all users awaiting for objects */
	osp_pre_update_status(d, rc);
	cfs_waitq_signal(&d->opd_pre_user_waitq);

	ptlrpc_req_finished(req);
	RETURN(rc);
}


static int osp_get_lastid_from_ost(struct osp_device *d)
{
	struct ptlrpc_request	*req;
	struct obd_import	*imp;
	obd_id			*reply;
	char			*tmp;
	int			 rc;

	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_GET_INFO_LAST_ID);
	if (req == NULL)
		RETURN(-ENOMEM);

	req_capsule_set_size(&req->rq_pill, &RMF_SETINFO_KEY,
			     RCL_CLIENT, sizeof(KEY_LAST_ID));
	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GET_INFO);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	tmp = req_capsule_client_get(&req->rq_pill, &RMF_SETINFO_KEY);
	memcpy(tmp, KEY_LAST_ID, sizeof(KEY_LAST_ID));

	req->rq_no_delay = req->rq_no_resend = 1;
	ptlrpc_request_set_replen(req);
	rc = ptlrpc_queue_wait(req);
	if (rc) {
		/* bad-bad OST.. let sysadm sort this out */
		ptlrpc_set_import_active(imp, 0);
		GOTO(out, rc);
	}

	reply = req_capsule_server_get(&req->rq_pill, &RMF_OBD_ID);
	if (reply == NULL)
		GOTO(out, rc = -EPROTO);

	d->opd_last_used_id = *reply;
	CDEBUG(D_HA, "%s: got last_id "LPU64" from OST\n",
	       d->opd_obd->obd_name, d->opd_last_used_id);

out:
	ptlrpc_req_finished(req);
	RETURN(rc);

}

/**
 * asks OST to clean precreate orphans
 * and gets next id for new objects
 */
static int osp_precreate_cleanup_orphans(struct osp_device *d)
{
	struct ptlrpc_request	*req = NULL;
	struct obd_import	*imp;
	struct ost_body		*body;
	int			 rc;

	ENTRY;

	LASSERT(d->opd_recovery_completed);
	LASSERT(d->opd_pre_reserved == 0);

	CDEBUG(D_HA, "%s: going to cleanup orphans since "LPU64"\n",
		d->opd_obd->obd_name, d->opd_last_used_id);

	if (d->opd_last_used_id < 2) {
		/* lastid looks strange... ask OST */
		rc = osp_get_lastid_from_ost(d);
		if (rc)
			GOTO(out, rc);
	}

	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_CREATE);
	if (req == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_CREATE);
	if (rc) {
		ptlrpc_request_free(req);
		GOTO(out, rc);
	}

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	body->oa.o_flags = OBD_FL_DELORPHAN;
	body->oa.o_valid = OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
	body->oa.o_seq = FID_SEQ_OST_MDT0;

	/* remove from NEXT after used one */
	body->oa.o_id = d->opd_last_used_id + 1;

	ptlrpc_request_set_replen(req);

	/* Don't resend the delorphan req */
	req->rq_no_resend = req->rq_no_delay = 1;

	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(out, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	/*
	 * OST provides us with id new pool starts from in body->oa.o_id
	 */
	cfs_spin_lock(&d->opd_pre_lock);
	if (le64_to_cpu(d->opd_last_used_id) > body->oa.o_id) {
		d->opd_pre_grow_count = OST_MIN_PRECREATE +
					le64_to_cpu(d->opd_last_used_id) -
					body->oa.o_id;
		d->opd_pre_last_created = le64_to_cpu(d->opd_last_used_id) + 1;
	} else {
		d->opd_pre_grow_count = OST_MIN_PRECREATE;
		d->opd_pre_last_created = body->oa.o_id + 1;
	}
	d->opd_pre_next = d->opd_pre_last_created;
	d->opd_pre_grow_slow = 0;
	cfs_spin_unlock(&d->opd_pre_lock);

	CDEBUG(D_HA, "Got last_id "LPU64" from OST, last_used is "LPU64
	       ", next "LPU64"\n", body->oa.o_id,
	       le64_to_cpu(d->opd_last_used_id), d->opd_pre_next);

out:
	if (req)
		ptlrpc_req_finished(req);

	RETURN(rc);
}

/*
 * the function updates current precreation status used: functional or not
 *
 * rc is a last code from the transport, rc == 0 meaning transport works
 * well and users of lod can use objects from this OSP
 *
 * the status depends on current usage of OST
 */
void osp_pre_update_status(struct osp_device *d, int rc)
{
	struct obd_statfs	*msfs = &d->opd_statfs;
	int			 old = d->opd_pre_status;
	__u64			 used;

	d->opd_pre_status = rc;
	if (rc)
		goto out;

	if (likely(msfs->os_type)) {
		used = min_t(__u64, (msfs->os_blocks - msfs->os_bfree) >> 10,
				    1 << 30);
		if ((msfs->os_ffree < 32) || (msfs->os_bavail < used)) {
			d->opd_pre_status = -ENOSPC;
			if (old != -ENOSPC)
				CDEBUG(D_INFO, "%s: status: "LPU64" blocks, "
				       LPU64" free, "LPU64" used, "LPU64" "
				       "avail -> %d: rc = %d\n",
				       d->opd_obd->obd_name, msfs->os_blocks,
				       msfs->os_bfree, used, msfs->os_bavail,
				       d->opd_pre_status, rc);
			CDEBUG(D_INFO,
			       "non-commited changes: %lu, in progress: %u\n",
			       d->opd_syn_changes, d->opd_syn_rpc_in_progress);
		} else if (old == -ENOSPC) {
			d->opd_pre_status = 0;
			d->opd_pre_grow_slow = 0;
			d->opd_pre_grow_count = OST_MIN_PRECREATE;
			cfs_waitq_signal(&d->opd_pre_waitq);
			CDEBUG(D_INFO, "%s: no space: "LPU64" blocks, "LPU64
			       " free, "LPU64" used, "LPU64" avail -> %d: "
			       "rc = %d\n", d->opd_obd->obd_name,
			       msfs->os_blocks, msfs->os_bfree, used,
			       msfs->os_bavail, d->opd_pre_status, rc);
		}
	}

out:
	cfs_waitq_signal(&d->opd_pre_user_waitq);
}

static int osp_precreate_thread(void *_arg)
{
	struct osp_device	*d = _arg;
	struct ptlrpc_thread	*thread = &d->opd_pre_thread;
	struct l_wait_info	 lwi = { 0 };
	char			 pname[16];
	int			 rc;

	ENTRY;

	sprintf(pname, "osp-pre-%u\n", d->opd_index);
	cfs_daemonize(pname);

	cfs_spin_lock(&d->opd_pre_lock);
	thread->t_flags = SVC_RUNNING;
	cfs_spin_unlock(&d->opd_pre_lock);
	cfs_waitq_signal(&thread->t_ctl_waitq);

	while (osp_precreate_running(d)) {
		/*
		 * need to be connected to OST
		 */
		while (osp_precreate_running(d)) {
			l_wait_event(d->opd_pre_waitq,
				     !osp_precreate_running(d) ||
				     d->opd_new_connection, &lwi);

			if (!osp_precreate_running(d))
				break;

			if (!d->opd_new_connection)
				continue;

			/* got connected */
			d->opd_new_connection = 0;
			d->opd_got_disconnected = 0;
			break;
		}

		osp_statfs_update(d);

		/*
		 * wait for local recovery to finish, so we can cleanup orphans
		 * orphans are all objects since "last used" (assigned), but
		 * there might be objects reserved and in some cases they won't
		 * be used. we can't cleanup them till we're sure they won't be
		 * used. so we block new reservations and wait till all reserved
		 * objects either user or released.
		 */
		l_wait_event(d->opd_pre_waitq, (!d->opd_pre_reserved &&
						d->opd_recovery_completed) ||
			     !osp_precreate_running(d) ||
			     d->opd_got_disconnected, &lwi);

		if (osp_precreate_running(d) && !d->opd_got_disconnected) {
			rc = osp_precreate_cleanup_orphans(d);
			if (rc) {
				CERROR("%s: cannot cleanup orphans: rc = %d\n",
				       d->opd_obd->obd_name,  rc);
				/* we can't proceed from here, OST seem to
				 * be in a bad shape, better to wait for
				 * a new instance of the server and repeat
				 * from the beginning. notify possible waiters
				 * this OSP isn't quite functional yet */
				osp_pre_update_status(d, rc);
				cfs_waitq_signal(&d->opd_pre_user_waitq);
				l_wait_event(d->opd_pre_waitq,
					     !osp_precreate_running(d) ||
					     d->opd_new_connection, &lwi);
				continue;

			}
		}

		/*
		 * connected, can handle precreates now
		 */
		while (osp_precreate_running(d)) {
			l_wait_event(d->opd_pre_waitq,
				     !osp_precreate_running(d) ||
				     osp_precreate_near_empty(d) ||
				     osp_statfs_need_update(d) ||
				     d->opd_got_disconnected, &lwi);

			if (!osp_precreate_running(d))
				break;

			/* something happened to the connection
			 * have to start from the beginning */
			if (d->opd_got_disconnected)
				break;

			if (osp_statfs_need_update(d))
				osp_statfs_update(d);

			if (osp_precreate_near_empty(d)) {
				rc = osp_precreate_send(d);
				/* osp_precreate_send() sets opd_pre_status
				 * in case of error, that prevent the using of
				 * failed device. */
				if (rc != 0 && rc != -ENOSPC &&
				    rc != -ETIMEDOUT && rc != -ENOTCONN)
					CERROR("%s: cannot precreate objects:"
					       " rc = %d\n",
					       d->opd_obd->obd_name, rc);
			}
		}
	}

	thread->t_flags = SVC_STOPPED;
	cfs_waitq_signal(&thread->t_ctl_waitq);

	RETURN(0);
}

static int osp_precreate_ready_condition(struct osp_device *d)
{
	/* ready if got enough precreated objects */
	if (d->opd_pre_next + d->opd_pre_reserved < d->opd_pre_last_created)
		return 1;

	/* ready if OST reported no space and no destoys in progress */
	if (d->opd_syn_changes + d->opd_syn_rpc_in_progress == 0 &&
	    d->opd_pre_status != 0)
		return 1;

	return 0;
}

static int osp_precreate_timeout_condition(void *data)
{
	struct osp_device *d = data;

	LCONSOLE_WARN("%s: slow creates, last="LPU64", next="LPU64", "
		      "reserved="LPU64", syn_changes=%lu, "
		      "syn_rpc_in_progress=%d, status=%d\n",
		      d->opd_obd->obd_name, d->opd_pre_last_created,
		      d->opd_pre_next, d->opd_pre_reserved,
		      d->opd_syn_changes, d->opd_syn_rpc_in_progress,
		      d->opd_pre_status);

	return 0;
}

/*
 * called to reserve object in the pool
 * return codes:
 *  ENOSPC - no space on corresponded OST
 *  EAGAIN - precreation is in progress, try later
 *  EIO    - no access to OST
 */
int osp_precreate_reserve(const struct lu_env *env, struct osp_device *d)
{
	struct l_wait_info	 lwi;
	cfs_time_t		 expire = cfs_time_shift(obd_timeout);
	int			 precreated, rc;
	int			 count = 0;

	ENTRY;

	LASSERT(d->opd_pre_last_created >= d->opd_pre_next);

	lwi = LWI_TIMEOUT(cfs_time_seconds(obd_timeout),
			  osp_precreate_timeout_condition, d);

	/*
	 * wait till:
	 *  - preallocation is done
	 *  - no free space expected soon
	 *  - can't connect to OST for too long (obd_timeout)
	 */
	while ((rc = d->opd_pre_status) == 0 || rc == -ENOSPC ||
		rc == -ENODEV) {
		if (unlikely(rc == -ENODEV)) {
			if (cfs_time_aftereq(cfs_time_current(), expire))
				break;
		}

#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 3, 90, 0)
#error "remove this before the release"
#endif
		/*
		 * to address Andreas's concern on possible busy-loop
		 * between this thread and osp_precreate_send()
		 */
		LASSERT(count++ < 1000);

		/*
		 * increase number of precreations
		 */
		if (d->opd_pre_grow_count < d->opd_pre_max_grow_count &&
		    d->opd_pre_grow_slow == 0 &&
		    (d->opd_pre_last_created - d->opd_pre_next <=
		     d->opd_pre_grow_count / 4 + 1)) {
			cfs_spin_lock(&d->opd_pre_lock);
			d->opd_pre_grow_slow = 1;
			d->opd_pre_grow_count *= 2;
			cfs_spin_unlock(&d->opd_pre_lock);
		}

		/*
		 * we never use the last object in the window
		 */
		cfs_spin_lock(&d->opd_pre_lock);
		precreated = d->opd_pre_last_created - d->opd_pre_next;
		if (precreated > d->opd_pre_reserved) {
			d->opd_pre_reserved++;
			cfs_spin_unlock(&d->opd_pre_lock);
			rc = 0;

			/* XXX: don't wake up if precreation is in progress */
			if (osp_precreate_near_empty_nolock(d))
				cfs_waitq_signal(&d->opd_pre_waitq);

			break;
		}
		cfs_spin_unlock(&d->opd_pre_lock);

		/*
		 * all precreated objects have been used and no-space
		 * status leave us no chance to succeed very soon
		 * but if there is destroy in progress, then we should
		 * wait till that is done - some space might be released
		 */
		if (unlikely(rc == -ENOSPC)) {
			if (d->opd_syn_changes) {
				/* force local commit to release space */
				dt_commit_async(env, d->opd_storage);
			}
			if (d->opd_syn_rpc_in_progress) {
				/* just wait till destroys are done */
				/* see l_wait_even() few lines below */
			}
			if (d->opd_syn_changes +
			    d->opd_syn_rpc_in_progress == 0) {
				/* no hope for free space */
				break;
			}
		}

		/* XXX: don't wake up if precreation is in progress */
		cfs_waitq_signal(&d->opd_pre_waitq);

		l_wait_event(d->opd_pre_user_waitq,
			     osp_precreate_ready_condition(d), &lwi);
	}

	RETURN(rc);
}

/*
 * this function relies on reservation made before
 */
__u64 osp_precreate_get_id(struct osp_device *d)
{
	obd_id objid;

	/* grab next id from the pool */
	cfs_spin_lock(&d->opd_pre_lock);
	LASSERT(d->opd_pre_next <= d->opd_pre_last_created);
	objid = d->opd_pre_next++;
	d->opd_pre_reserved--;
	/*
	 * last_used_id must be changed along with getting new id otherwise
	 * we might miscalculate gap causing object loss or leak
	 */
	osp_update_last_id(d, objid);
	cfs_spin_unlock(&d->opd_pre_lock);

	/*
	 * probably main thread suspended orphan cleanup till
	 * all reservations are released, see comment in
	 * osp_precreate_thread() just before orphan cleanup
	 */
	if (unlikely(d->opd_pre_reserved == 0 && d->opd_pre_status))
		cfs_waitq_signal(&d->opd_pre_waitq);

	return objid;
}

/*
 *
 */
int osp_object_truncate(const struct lu_env *env, struct dt_object *dt,
			__u64 size)
{
	struct osp_device	*d = lu2osp_dev(dt->do_lu.lo_dev);
	struct ptlrpc_request	*req = NULL;
	struct obd_import	*imp;
	struct ost_body		*body;
	struct obdo		*oa = NULL;
	int			 rc;

	ENTRY;

	imp = d->opd_obd->u.cli.cl_import;
	LASSERT(imp);

	req = ptlrpc_request_alloc(imp, &RQF_OST_PUNCH);
	if (req == NULL)
		RETURN(-ENOMEM);

	/* XXX: capa support? */
	/* osc_set_capa_size(req, &RMF_CAPA1, capa); */
	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_PUNCH);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	/*
	 * XXX: decide how do we do here with resend
	 * if we don't resend, then client may see wrong file size
	 * if we do resend, then MDS thread can get stuck for quite long
	 */
	req->rq_no_resend = req->rq_no_delay = 1;

	req->rq_request_portal = OST_IO_PORTAL; /* bug 7198 */
	ptlrpc_at_set_req_timeout(req);

	OBD_ALLOC_PTR(oa);
	if (oa == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = fid_ostid_pack(lu_object_fid(&dt->do_lu), &oa->o_oi);
	LASSERT(rc == 0);
	oa->o_size = size;
	oa->o_blocks = OBD_OBJECT_EOF;
	oa->o_valid = OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
		      OBD_MD_FLID | OBD_MD_FLGROUP;

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	LASSERT(body);
	lustre_set_wire_obdo(&body->oa, oa);

	/* XXX: capa support? */
	/* osc_pack_capa(req, body, capa); */

	ptlrpc_request_set_replen(req);

	rc = ptlrpc_queue_wait(req);
	if (rc)
		CERROR("can't punch object: %d\n", rc);
out:
	ptlrpc_req_finished(req);
	if (oa)
		OBD_FREE_PTR(oa);
	RETURN(rc);
}

int osp_init_precreate(struct osp_device *d)
{
	struct l_wait_info	 lwi = { 0 };
	int			 rc;

	ENTRY;

	/* initially precreation isn't ready */
	d->opd_pre_status = -EAGAIN;
	d->opd_pre_next = 1;
	d->opd_pre_last_created = 1;
	d->opd_pre_reserved = 0;
	d->opd_got_disconnected = 1;
	d->opd_pre_grow_slow = 0;
	d->opd_pre_grow_count = OST_MIN_PRECREATE;
	d->opd_pre_min_grow_count = OST_MIN_PRECREATE;
	d->opd_pre_max_grow_count = OST_MAX_PRECREATE;

	cfs_spin_lock_init(&d->opd_pre_lock);
	cfs_waitq_init(&d->opd_pre_waitq);
	cfs_waitq_init(&d->opd_pre_user_waitq);
	cfs_waitq_init(&d->opd_pre_thread.t_ctl_waitq);

	/*
	 * Initialize statfs-related things
	 */
	d->opd_statfs_maxage = 5; /* default update interval */
	d->opd_statfs_fresh_till = cfs_time_shift(-1000);
	CDEBUG(D_OTHER, "current %llu, fresh till %llu\n",
	       (unsigned long long)cfs_time_current(),
	       (unsigned long long)d->opd_statfs_fresh_till);
	cfs_timer_init(&d->opd_statfs_timer, osp_statfs_timer_cb, d);

	/*
	 * start thread handling precreation and statfs updates
	 */
	rc = cfs_create_thread(osp_precreate_thread, d, 0);
	if (rc < 0) {
		CERROR("can't start precreate thread %d\n", rc);
		RETURN(rc);
	}

	l_wait_event(d->opd_pre_thread.t_ctl_waitq,
		     osp_precreate_running(d) || osp_precreate_stopped(d),
		     &lwi);

	RETURN(0);
}

void osp_precreate_fini(struct osp_device *d)
{
	struct ptlrpc_thread *thread = &d->opd_pre_thread;

	ENTRY;

	cfs_timer_disarm(&d->opd_statfs_timer);

	thread->t_flags = SVC_STOPPING;
	cfs_waitq_signal(&d->opd_pre_waitq);

	cfs_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_STOPPED);

	EXIT;
}

