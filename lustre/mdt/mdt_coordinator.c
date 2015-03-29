/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2011, 2012 Commissariat a l'energie atomique et aux energies
 *                          alternatives
 *
 * Copyright (c) 2013, 2014, Intel Corporation.
 * Use is subject to license terms.
 */
/*
 * lustre/mdt/mdt_coordinator.c
 *
 * Lustre HSM Coordinator
 *
 * Author: Jacques-Charles Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 * Author: Thomas Leibovici <thomas.leibovici@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_export.h>
#include <obd.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include "mdt_internal.h"

static struct lprocfs_vars lprocfs_mdt_hsm_vars[];

/**
 * get obj and HSM attributes on a fid
 * \param mti [IN] context
 * \param fid [IN] object fid
 * \param hsm [OUT] HSM meta data
 * \retval obj or error (-ENOENT if not found)
 */
struct mdt_object *mdt_hsm_get_md_hsm(struct mdt_thread_info *mti,
				      const struct lu_fid *fid,
				      struct md_hsm *hsm)
{
	struct md_attr		*ma;
	struct mdt_object	*obj;
	int			 rc;
	ENTRY;

	ma = &mti->mti_attr;
	ma->ma_need = MA_HSM;
	ma->ma_valid = 0;

	/* find object by FID */
	obj = mdt_object_find(mti->mti_env, mti->mti_mdt, fid);
	if (IS_ERR(obj))
		RETURN(obj);

	if (!mdt_object_exists(obj)) {
		/* no more object */
		mdt_object_put(mti->mti_env, obj);
		RETURN(ERR_PTR(-ENOENT));
	}

	rc = mdt_attr_get_complex(mti, obj, ma);
	if (rc) {
		mdt_object_put(mti->mti_env, obj);
		RETURN(ERR_PTR(rc));
	}

	if (ma->ma_valid & MA_HSM)
		*hsm = ma->ma_hsm;
	else
		memset(hsm, 0, sizeof(*hsm));
	ma->ma_valid = 0;
	RETURN(obj);
}

void mdt_hsm_dump_hal(int level, const char *prefix,
		      struct hsm_action_list *hal)
{
	int			 i, sz;
	struct hsm_action_item	*hai;
	char			 buf[12];

	CDEBUG(level, "%s: HAL header: version %X count %d compound "LPX64
		      " archive_id %d flags "LPX64"\n",
	       prefix, hal->hal_version, hal->hal_count,
	       hal->hal_compound_id, hal->hal_archive_id, hal->hal_flags);

	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++) {
		sz = hai->hai_len - sizeof(*hai);
		CDEBUG(level, "%s %d: fid="DFID" dfid="DFID
		       " compound/cookie="LPX64"/"LPX64
		       " action=%s extent="LPX64"-"LPX64" gid="LPX64
		       " datalen=%d data=[%s]\n",
		       prefix, i,
		       PFID(&hai->hai_fid), PFID(&hai->hai_dfid),
		       hal->hal_compound_id, hai->hai_cookie,
		       hsm_copytool_action2name(hai->hai_action),
		       hai->hai_extent.offset,
		       hai->hai_extent.length,
		       hai->hai_gid, sz,
		       hai_dump_data_field(hai, buf, sizeof(buf)));
		hai = hai_next(hai);
	}
}

/**
 * data passed to llog_cat_process() callback
 * to scan requests and take actions
 */
struct hsm_scan_data {
	struct mdt_thread_info		*mti;
	char				 fs_name[MTI_NAME_MAXLEN+1];
	/* request to be send to agents */
	int				 request_sz;	/** allocated size */
	int				 max_requests;	/** vector size */
	int				 request_cnt;	/** used count */
	struct {
		int			 hal_sz;
		int			 hal_used_sz;
		struct hsm_action_list	*hal;
	} *request;
	/* records to be canceled */
	int				 max_cookie;	/** vector size */
	int				 cookie_cnt;	/** used count */
	__u64				*cookies;
};

/**
 *  llog_cat_process() callback, used to:
 *  - find waiting request and start action
 *  - purge canceled and done requests
 * \param env [IN] environment
 * \param llh [IN] llog handle
 * \param hdr [IN] llog record
 * \param data [IN/OUT] cb data = struct hsm_scan_data
 * \retval 0 success
 * \retval -ve failure
 */
static int mdt_coordinator_cb(const struct lu_env *env,
			      struct llog_handle *llh,
			      struct llog_rec_hdr *hdr,
			      void *data)
{
	const struct llog_agent_req_rec	*larr;
	struct hsm_scan_data		*hsd;
	struct hsm_action_item		*hai;
	struct mdt_device		*mdt;
	struct coordinator		*cdt;
	int				 rc;
	ENTRY;

	hsd = data;
	mdt = hsd->mti->mti_mdt;
	cdt = &mdt->mdt_coordinator;

	larr = (struct llog_agent_req_rec *)hdr;
	dump_llog_agent_req_rec("mdt_coordinator_cb(): ", larr);
	switch (larr->arr_status) {
	case ARS_WAITING: {
		int i, empty_slot, found;

		/* Are agents full? */
		if (atomic_read(&cdt->cdt_request_count) ==
		    cdt->cdt_max_requests)
			break;

		/* first search if the request if known in the list we have
		 * build and if there is room in the request vector */
		empty_slot = -1;
		found = -1;
		for (i = 0; i < hsd->max_requests &&
			    (empty_slot == -1 || found == -1); i++) {
			if (hsd->request[i].hal == NULL) {
				empty_slot = i;
				continue;
			}
			if (hsd->request[i].hal->hal_compound_id ==
				larr->arr_compound_id) {
				found = i;
				continue;
			}
		}
		if (found == -1 && empty_slot == -1)
			/* unknown request and no more room for new request,
			 * continue scan for to find other entries for
			 * already found request
			 */
			RETURN(0);

		if (found == -1) {
			struct hsm_action_list *hal;

			/* request is not already known */
			/* allocates hai vector size just needs to be large
			 * enough */
			hsd->request[empty_slot].hal_sz =
				     sizeof(*hsd->request[empty_slot].hal) +
				     cfs_size_round(MTI_NAME_MAXLEN+1) +
				     2 * cfs_size_round(larr->arr_hai.hai_len);
			OBD_ALLOC(hal, hsd->request[empty_slot].hal_sz);
			if (!hal) {
				CERROR("%s: Cannot allocate memory (%d o)"
				       "for compound "LPX64"\n",
				       mdt_obd_name(mdt),
				       hsd->request[i].hal_sz,
				       larr->arr_compound_id);
				RETURN(-ENOMEM);
			}
			hal->hal_version = HAL_VERSION;
			strlcpy(hal->hal_fsname, hsd->fs_name,
				MTI_NAME_MAXLEN + 1);
			hal->hal_compound_id = larr->arr_compound_id;
			hal->hal_archive_id = larr->arr_archive_id;
			hal->hal_flags = larr->arr_flags;
			hal->hal_count = 0;
			hsd->request[empty_slot].hal_used_sz = hal_size(hal);
			hsd->request[empty_slot].hal = hal;
			hsd->request_cnt++;
			found = empty_slot;
			hai = hai_first(hal);
		} else {
			/* request is known */
			/* we check if record archive num is the same as the
			 * known request, if not we will serve it in multiple
			 * time because we do not know if the agent can serve
			 * multiple backend
			 * a use case is a compound made of multiple restore
			 * where the files are not archived in the same backend
			 */
			if (larr->arr_archive_id !=
			    hsd->request[found].hal->hal_archive_id)
				RETURN(0);

			if (hsd->request[found].hal_sz <
			    hsd->request[found].hal_used_sz +
			     cfs_size_round(larr->arr_hai.hai_len)) {
				/* Not enough room, need an extension */
				void *hal_buffer;
				int sz;

				sz = 2 * hsd->request[found].hal_sz;
				OBD_ALLOC(hal_buffer, sz);
				if (!hal_buffer) {
					CERROR("%s: Cannot allocate memory "
					       "(%d o) for compound "LPX64"\n",
					       mdt_obd_name(mdt), sz,
					       larr->arr_compound_id);
					RETURN(-ENOMEM);
				}
				memcpy(hal_buffer, hsd->request[found].hal,
				       hsd->request[found].hal_used_sz);
				OBD_FREE(hsd->request[found].hal,
					 hsd->request[found].hal_sz);
				hsd->request[found].hal = hal_buffer;
				hsd->request[found].hal_sz = sz;
			}
			hai = hai_first(hsd->request[found].hal);
			for (i = 0; i < hsd->request[found].hal->hal_count;
			     i++)
				hai = hai_next(hai);
		}
		memcpy(hai, &larr->arr_hai, larr->arr_hai.hai_len);
		hai->hai_cookie = larr->arr_hai.hai_cookie;
		hai->hai_gid = larr->arr_hai.hai_gid;

		hsd->request[found].hal_used_sz +=
						   cfs_size_round(hai->hai_len);
		hsd->request[found].hal->hal_count++;
		break;
	}
	case ARS_STARTED: {
		struct cdt_agent_req *car;
		cfs_time_t last;

		/* we search for a running request
		 * error may happen if coordinator crashes or stopped
		 * with running request
		 */
		car = mdt_cdt_find_request(cdt, larr->arr_hai.hai_cookie, NULL);
		if (car == NULL) {
			last = larr->arr_req_create;
		} else {
			last = car->car_req_update;
			mdt_cdt_put_request(car);
		}

		/* test if request too long, if yes cancel it
		 * the same way the copy tool acknowledge a cancel request */
		if ((last + cdt->cdt_active_req_timeout)
		     < cfs_time_current_sec()) {
			struct hsm_progress_kernel pgs;

			dump_llog_agent_req_rec("mdt_coordinator_cb(): "
						"request timed out, start "
						"cleaning", larr);
			/* a too old cancel request just needs to be removed
			 * this can happen, if copy tool does not support cancel
			 * for other requests, we have to remove the running
			 * request and notify the copytool
			 */
			pgs.hpk_fid = larr->arr_hai.hai_fid;
			pgs.hpk_cookie = larr->arr_hai.hai_cookie;
			pgs.hpk_extent = larr->arr_hai.hai_extent;
			pgs.hpk_flags = HP_FLAG_COMPLETED;
			pgs.hpk_errval = ENOSYS;
			pgs.hpk_data_version = 0;
			/* update request state, but do not record in llog, to
			 * avoid deadlock on cdt_llog_lock
			 */
			rc = mdt_hsm_update_request_state(hsd->mti, &pgs, 0);
			if (rc)
				CERROR("%s: Cannot cleanup timed out request: "
				       DFID" for cookie "LPX64" action=%s\n",
				       mdt_obd_name(mdt),
				       PFID(&pgs.hpk_fid), pgs.hpk_cookie,
				       hsm_copytool_action2name(
						     larr->arr_hai.hai_action));

			if (rc == -ENOENT) {
				/* The request no longer exists, forget
				 * about it, and do not send a cancel request
				 * to the client, for which an error will be
				 * sent back, leading to an endless cycle of
				 * cancellation. */
				RETURN(LLOG_DEL_RECORD);
			}

			/* add the cookie to the list of record to be
			 * canceled by caller */
			if (hsd->max_cookie == (hsd->cookie_cnt - 1)) {
				__u64 *ptr, *old_ptr;
				int old_sz, new_sz, new_cnt;

				/* need to increase vector size */
				old_sz = sizeof(__u64) * hsd->max_cookie;
				old_ptr = hsd->cookies;

				new_cnt = 2 * hsd->max_cookie;
				new_sz = sizeof(__u64) * new_cnt;

				OBD_ALLOC(ptr, new_sz);
				if (!ptr) {
					CERROR("%s: Cannot allocate memory "
					       "(%d o) for cookie vector\n",
					       mdt_obd_name(mdt), new_sz);
					RETURN(-ENOMEM);
				}
				memcpy(ptr, hsd->cookies, old_sz);
				hsd->cookies = ptr;
				hsd->max_cookie = new_cnt;
				OBD_FREE(old_ptr, old_sz);
			}
			hsd->cookies[hsd->cookie_cnt] =
						       larr->arr_hai.hai_cookie;
			hsd->cookie_cnt++;
		}
		break;
	}
	case ARS_FAILED:
	case ARS_CANCELED:
	case ARS_SUCCEED:
		if ((larr->arr_req_change + cdt->cdt_grace_delay) <
		    cfs_time_current_sec())
			RETURN(LLOG_DEL_RECORD);
		break;
	}
	RETURN(0);
}

/**
 * create /proc entries for coordinator
 * \param mdt [IN]
 * \retval 0 success
 * \retval -ve failure
 */
int hsm_cdt_procfs_init(struct mdt_device *mdt)
{
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	int			 rc = 0;
	ENTRY;

	/* init /proc entries, failure is not critical */
	cdt->cdt_proc_dir = lprocfs_register("hsm",
					     mdt2obd_dev(mdt)->obd_proc_entry,
					     lprocfs_mdt_hsm_vars, mdt);
	if (IS_ERR(cdt->cdt_proc_dir)) {
		rc = PTR_ERR(cdt->cdt_proc_dir);
		CERROR("%s: Cannot create 'hsm' directory in mdt proc dir,"
		       " rc=%d\n", mdt_obd_name(mdt), rc);
		cdt->cdt_proc_dir = NULL;
		RETURN(rc);
	}

	RETURN(0);
}

/**
 * remove /proc entries for coordinator
 * \param mdt [IN]
 */
void  hsm_cdt_procfs_fini(struct mdt_device *mdt)
{
	struct coordinator	*cdt = &mdt->mdt_coordinator;

	LASSERT(cdt->cdt_state == CDT_STOPPED);
	if (cdt->cdt_proc_dir != NULL)
		lprocfs_remove(&cdt->cdt_proc_dir);
}

/**
 * get vector of hsm cdt /proc vars
 * \param none
 * \retval var vector
 */
struct lprocfs_vars *hsm_cdt_get_proc_vars(void)
{
	return lprocfs_mdt_hsm_vars;
}

/**
 * coordinator thread
 * \param data [IN] obd device
 * \retval 0 success
 * \retval -ve failure
 */
static int mdt_coordinator(void *data)
{
	struct mdt_thread_info	*mti = data;
	struct mdt_device	*mdt = mti->mti_mdt;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct hsm_scan_data	 hsd = { NULL };
	int			 rc = 0;
	ENTRY;

	cdt->cdt_thread.t_flags = SVC_RUNNING;
	wake_up(&cdt->cdt_thread.t_ctl_waitq);

	CDEBUG(D_HSM, "%s: coordinator thread starting, pid=%d\n",
	       mdt_obd_name(mdt), current_pid());

	/* timeouted cookie vector initialization */
	hsd.max_cookie = 0;
	hsd.cookie_cnt = 0;
	hsd.cookies = NULL;
	/* we use a copy of cdt_max_requests in the cb, so if cdt_max_requests
	 * increases due to a change from /proc we do not overflow the
	 * hsd.request[] vector
	 */
	hsd.max_requests = cdt->cdt_max_requests;
	hsd.request_sz = hsd.max_requests * sizeof(*hsd.request);
	OBD_ALLOC(hsd.request, hsd.request_sz);
	if (!hsd.request)
		GOTO(out, rc = -ENOMEM);

	hsd.mti = mti;
	obd_uuid2fsname(hsd.fs_name, mdt_obd_name(mdt), MTI_NAME_MAXLEN);

	while (1) {
		struct l_wait_info lwi;
		int i;

		lwi = LWI_TIMEOUT(cfs_time_seconds(cdt->cdt_loop_period),
				  NULL, NULL);
		l_wait_event(cdt->cdt_thread.t_ctl_waitq,
			     (cdt->cdt_thread.t_flags &
			      (SVC_STOPPING|SVC_EVENT)),
			     &lwi);

		CDEBUG(D_HSM, "coordinator resumes\n");

		if (cdt->cdt_thread.t_flags & SVC_STOPPING ||
		    cdt->cdt_state == CDT_STOPPING) {
			cdt->cdt_thread.t_flags &= ~SVC_STOPPING;
			rc = 0;
			break;
		}

		/* wake up before timeout, new work arrives */
		if (cdt->cdt_thread.t_flags & SVC_EVENT)
			cdt->cdt_thread.t_flags &= ~SVC_EVENT;

		/* if coordinator is suspended continue to wait */
		if (cdt->cdt_state == CDT_DISABLE) {
			CDEBUG(D_HSM, "disable state, coordinator sleeps\n");
			continue;
		}

		CDEBUG(D_HSM, "coordinator starts reading llog\n");

		if (hsd.max_requests != cdt->cdt_max_requests) {
			/* cdt_max_requests has changed,
			 * we need to allocate a new buffer
			 */
			OBD_FREE(hsd.request, hsd.request_sz);
			hsd.max_requests = cdt->cdt_max_requests;
			hsd.request_sz =
				   hsd.max_requests * sizeof(*hsd.request);
			OBD_ALLOC(hsd.request, hsd.request_sz);
			if (!hsd.request) {
				rc = -ENOMEM;
				break;
			}
		}

		/* create canceled cookie vector for an arbitrary size
		 * if needed, vector will grow during llog scan
		 */
		hsd.max_cookie = 10;
		hsd.cookie_cnt = 0;
		OBD_ALLOC(hsd.cookies, hsd.max_cookie * sizeof(__u64));
		if (!hsd.cookies) {
			rc = -ENOMEM;
			goto clean_cb_alloc;
		}
		hsd.request_cnt = 0;

		rc = cdt_llog_process(mti->mti_env, mdt,
				      mdt_coordinator_cb, &hsd);
		if (rc < 0)
			goto clean_cb_alloc;

		CDEBUG(D_HSM, "Found %d requests to send and %d"
			      " requests to cancel\n",
		       hsd.request_cnt, hsd.cookie_cnt);
		/* first we cancel llog records of the timed out requests */
		if (hsd.cookie_cnt > 0) {
			rc = mdt_agent_record_update(mti->mti_env, mdt,
						     hsd.cookies,
						     hsd.cookie_cnt,
						     ARS_CANCELED);
			if (rc)
				CERROR("%s: mdt_agent_record_update() failed, "
				       "rc=%d, cannot update status to %s "
				       "for %d cookies\n",
				       mdt_obd_name(mdt), rc,
				       agent_req_status2name(ARS_CANCELED),
				       hsd.cookie_cnt);
		}

		if (list_empty(&cdt->cdt_agents)) {
			CDEBUG(D_HSM, "no agent available, "
				      "coordinator sleeps\n");
			goto clean_cb_alloc;
		}

		/* here hsd contains a list of requests to be started */
		for (i = 0; i < hsd.max_requests; i++) {
			struct hsm_action_list	*hal;
			struct hsm_action_item	*hai;
			__u64			*cookies;
			int			 sz, j;
			enum agent_req_status	 status;

			/* still room for work ? */
			if (atomic_read(&cdt->cdt_request_count) ==
			    cdt->cdt_max_requests)
				break;

			if (hsd.request[i].hal == NULL)
				continue;

			/* found a request, we start it */
			/* kuc payload allocation so we avoid an additionnal
			 * allocation in mdt_hsm_agent_send()
			 */
			hal = kuc_alloc(hsd.request[i].hal_used_sz,
					KUC_TRANSPORT_HSM, HMT_ACTION_LIST);
			if (IS_ERR(hal)) {
				CERROR("%s: Cannot allocate memory (%d o) "
				       "for compound "LPX64"\n",
				       mdt_obd_name(mdt),
				       hsd.request[i].hal_used_sz,
				       hsd.request[i].hal->hal_compound_id);
				continue;
			}
			memcpy(hal, hsd.request[i].hal,
			       hsd.request[i].hal_used_sz);

			rc = mdt_hsm_agent_send(mti, hal, 0);
			/* if failure, we suppose it is temporary
			 * if the copy tool failed to do the request
			 * it has to use hsm_progress
			 */
			status = (rc ? ARS_WAITING : ARS_STARTED);

			/* set up cookie vector to set records status
			 * after copy tools start or failed
			 */
			sz = hsd.request[i].hal->hal_count * sizeof(__u64);
			OBD_ALLOC(cookies, sz);
			if (cookies == NULL) {
				CERROR("%s: Cannot allocate memory (%d o) "
				       "for cookies vector "LPX64"\n",
				       mdt_obd_name(mdt), sz,
				       hsd.request[i].hal->hal_compound_id);
				kuc_free(hal, hsd.request[i].hal_used_sz);
				continue;
			}
			hai = hai_first(hal);
			for (j = 0; j < hsd.request[i].hal->hal_count; j++) {
				cookies[j] = hai->hai_cookie;
				hai = hai_next(hai);
			}

			rc = mdt_agent_record_update(mti->mti_env, mdt, cookies,
						hsd.request[i].hal->hal_count,
						status);
			if (rc)
				CERROR("%s: mdt_agent_record_update() failed, "
				       "rc=%d, cannot update status to %s "
				       "for %d cookies\n",
				       mdt_obd_name(mdt), rc,
				       agent_req_status2name(status),
				       hsd.request[i].hal->hal_count);

			OBD_FREE(cookies, sz);
			kuc_free(hal, hsd.request[i].hal_used_sz);
		}
clean_cb_alloc:
		/* free cookie vector allocated for/by callback */
		if (hsd.cookies) {
			OBD_FREE(hsd.cookies, hsd.max_cookie * sizeof(__u64));
			hsd.max_cookie = 0;
			hsd.cookie_cnt = 0;
			hsd.cookies = NULL;
		}

		/* free hal allocated by callback */
		for (i = 0; i < hsd.max_requests; i++) {
			if (hsd.request[i].hal) {
				OBD_FREE(hsd.request[i].hal,
					 hsd.request[i].hal_sz);
				hsd.request[i].hal_sz = 0;
				hsd.request[i].hal = NULL;
				hsd.request_cnt--;
			}
		}
		LASSERT(hsd.request_cnt == 0);

		/* reset callback data */
		memset(hsd.request, 0, hsd.request_sz);
	}
	EXIT;
out:
	if (hsd.request)
		OBD_FREE(hsd.request, hsd.request_sz);

	if (hsd.cookies)
		OBD_FREE(hsd.cookies, hsd.max_cookie * sizeof(__u64));

	if (cdt->cdt_state == CDT_STOPPING) {
		/* request comes from /proc path, so we need to clean cdt
		 * struct */
		 mdt_hsm_cdt_stop(mdt);
		 mdt->mdt_opts.mo_coordinator = 0;
	} else {
		/* request comes from a thread event, generated
		 * by mdt_stop_coordinator(), we have to ack
		 * and cdt cleaning will be done by event sender
		 */
		cdt->cdt_thread.t_flags = SVC_STOPPED;
		wake_up(&cdt->cdt_thread.t_ctl_waitq);
	}

	if (rc != 0)
		CERROR("%s: coordinator thread exiting, process=%d, rc=%d\n",
		       mdt_obd_name(mdt), current_pid(), rc);
	else
		CDEBUG(D_HSM, "%s: coordinator thread exiting, process=%d,"
			      " no error\n",
		       mdt_obd_name(mdt), current_pid());

	return rc;
}

/**
 * lookup a restore handle by FID
 * caller needs to hold cdt_restore_lock
 * \param cdt [IN] coordinator
 * \param fid [IN] FID
 * \retval cdt_restore_handle found
 * \retval NULL not found
 */
static struct cdt_restore_handle *hsm_restore_hdl_find(struct coordinator *cdt,
						       const struct lu_fid *fid)
{
	struct cdt_restore_handle	*crh;
	ENTRY;

	list_for_each_entry(crh, &cdt->cdt_restore_hdl, crh_list) {
		if (lu_fid_eq(&crh->crh_fid, fid))
			RETURN(crh);
	}
	RETURN(NULL);
}

/**
 * data passed to llog_cat_process() callback
 * to scan requests and take actions
 */
struct hsm_restore_data {
	struct mdt_thread_info	*hrd_mti;
};

/**
 *  llog_cat_process() callback, used to:
 *  - find restore request and allocate the restore handle
 * \param env [IN] environment
 * \param llh [IN] llog handle
 * \param hdr [IN] llog record
 * \param data [IN/OUT] cb data = struct hsm_restore_data
 * \retval 0 success
 * \retval -ve failure
 */
static int hsm_restore_cb(const struct lu_env *env,
			  struct llog_handle *llh,
			  struct llog_rec_hdr *hdr, void *data)
{
	struct llog_agent_req_rec	*larr;
	struct hsm_restore_data		*hrd;
	struct cdt_restore_handle	*crh;
	struct hsm_action_item		*hai;
	struct mdt_thread_info		*mti;
	struct coordinator		*cdt;
	struct mdt_object		*child;
	int rc;
	ENTRY;

	hrd = data;
	mti = hrd->hrd_mti;
	cdt = &mti->mti_mdt->mdt_coordinator;

	larr = (struct llog_agent_req_rec *)hdr;
	hai = &larr->arr_hai;
	if (hai->hai_cookie > cdt->cdt_last_cookie)
		/* update the cookie to avoid collision */
		cdt->cdt_last_cookie = hai->hai_cookie + 1;

	if (hai->hai_action != HSMA_RESTORE ||
	    agent_req_in_final_state(larr->arr_status))
		RETURN(0);

	/* restore request not in a final state */

	OBD_SLAB_ALLOC_PTR(crh, mdt_hsm_cdt_kmem);
	if (crh == NULL)
		RETURN(-ENOMEM);

	crh->crh_fid = hai->hai_fid;
	/* in V1 all file is restored
	crh->extent.start = hai->hai_extent.offset;
	crh->extent.end = hai->hai_extent.offset + hai->hai_extent.length;
	*/
	crh->crh_extent.start = 0;
	crh->crh_extent.end = hai->hai_extent.length;
	/* get the layout lock */
	mdt_lock_reg_init(&crh->crh_lh, LCK_EX);
	child = mdt_object_find_lock(mti, &crh->crh_fid, &crh->crh_lh,
				     MDS_INODELOCK_LAYOUT);
	if (IS_ERR(child))
		GOTO(out, rc = PTR_ERR(child));

	rc = 0;
	/* we choose to not keep a reference
	 * on the object during the restore time which can be very long */
	mdt_object_put(mti->mti_env, child);

	mutex_lock(&cdt->cdt_restore_lock);
	list_add_tail(&crh->crh_list, &cdt->cdt_restore_hdl);
	mutex_unlock(&cdt->cdt_restore_lock);

out:
	RETURN(rc);
}

/**
 * restore coordinator state at startup
 * the goal is to take a layout lock for each registered restore request
 * \param mti [IN] context
 */
static int mdt_hsm_pending_restore(struct mdt_thread_info *mti)
{
	struct hsm_restore_data	 hrd;
	int			 rc;
	ENTRY;

	hrd.hrd_mti = mti;

	rc = cdt_llog_process(mti->mti_env, mti->mti_mdt,
			      hsm_restore_cb, &hrd);

	RETURN(rc);
}

static int hsm_init_ucred(struct lu_ucred *uc)
{
	ENTRY;

	uc->uc_valid = UCRED_OLD;
	uc->uc_o_uid = 0;
	uc->uc_o_gid = 0;
	uc->uc_o_fsuid = 0;
	uc->uc_o_fsgid = 0;
	uc->uc_uid = 0;
	uc->uc_gid = 0;
	uc->uc_fsuid = 0;
	uc->uc_fsgid = 0;
	uc->uc_suppgids[0] = -1;
	uc->uc_suppgids[1] = -1;
	uc->uc_cap = CFS_CAP_FS_MASK;
	uc->uc_umask = 0777;
	uc->uc_ginfo = NULL;
	uc->uc_identity = NULL;

	RETURN(0);
}

/**
 * wake up coordinator thread
 * \param mdt [IN] device
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_cdt_wakeup(struct mdt_device *mdt)
{
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	ENTRY;

	if (cdt->cdt_state == CDT_STOPPED)
		RETURN(-ESRCH);

	/* wake up coordinator */
	cdt->cdt_thread.t_flags = SVC_EVENT;
	wake_up(&cdt->cdt_thread.t_ctl_waitq);

	RETURN(0);
}

/**
 * initialize coordinator struct
 * \param mdt [IN] device
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_cdt_init(struct mdt_device *mdt)
{
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct mdt_thread_info	*cdt_mti = NULL;
	int			 rc;
	ENTRY;

	cdt->cdt_state = CDT_STOPPED;

	init_waitqueue_head(&cdt->cdt_thread.t_ctl_waitq);
	mutex_init(&cdt->cdt_llog_lock);
	init_rwsem(&cdt->cdt_agent_lock);
	init_rwsem(&cdt->cdt_request_lock);
	mutex_init(&cdt->cdt_restore_lock);

	INIT_LIST_HEAD(&cdt->cdt_requests);
	INIT_LIST_HEAD(&cdt->cdt_agents);
	INIT_LIST_HEAD(&cdt->cdt_restore_hdl);

	rc = lu_env_init(&cdt->cdt_env, LCT_MD_THREAD);
	if (rc < 0)
		RETURN(rc);

	/* for mdt_ucred(), lu_ucred stored in lu_ucred_key */
	rc = lu_context_init(&cdt->cdt_session, LCT_SERVER_SESSION);
	if (rc == 0) {
		lu_context_enter(&cdt->cdt_session);
		cdt->cdt_env.le_ses = &cdt->cdt_session;
	} else {
		lu_env_fini(&cdt->cdt_env);
		RETURN(rc);
	}

	cdt_mti = lu_context_key_get(&cdt->cdt_env.le_ctx, &mdt_thread_key);
	LASSERT(cdt_mti != NULL);

	cdt_mti->mti_env = &cdt->cdt_env;
	cdt_mti->mti_mdt = mdt;

	hsm_init_ucred(mdt_ucred(cdt_mti));

	/* default values for /proc tunnables
	 * can be override by MGS conf */
	cdt->cdt_default_archive_id = 1;
	cdt->cdt_grace_delay = 60;
	cdt->cdt_loop_period = 10;
	cdt->cdt_max_requests = 3;
	cdt->cdt_policy = CDT_DEFAULT_POLICY;
	cdt->cdt_active_req_timeout = 3600;

	RETURN(0);
}

/**
 * free a coordinator thread
 * \param mdt [IN] device
 */
int  mdt_hsm_cdt_fini(struct mdt_device *mdt)
{
	struct coordinator *cdt = &mdt->mdt_coordinator;
	ENTRY;

	lu_context_exit(cdt->cdt_env.le_ses);
	lu_context_fini(cdt->cdt_env.le_ses);

	lu_env_fini(&cdt->cdt_env);

	RETURN(0);
}

/**
 * start a coordinator thread
 * \param mdt [IN] device
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_cdt_start(struct mdt_device *mdt)
{
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	int			 rc;
	void			*ptr;
	struct mdt_thread_info	*cdt_mti;
	struct task_struct	*task;
	ENTRY;

	/* functions defined but not yet used
	 * this avoid compilation warning
	 */
	ptr = dump_requests;

	if (cdt->cdt_state != CDT_STOPPED) {
		CERROR("%s: Coordinator already started\n",
		       mdt_obd_name(mdt));
		RETURN(-EALREADY);
	}

	CLASSERT(1 << (CDT_POLICY_SHIFT_COUNT - 1) == CDT_POLICY_LAST);
	cdt->cdt_policy = CDT_DEFAULT_POLICY;

	cdt->cdt_state = CDT_INIT;

	atomic_set(&cdt->cdt_compound_id, cfs_time_current_sec());
	/* just need to be larger than previous one */
	/* cdt_last_cookie is protected by cdt_llog_lock */
	cdt->cdt_last_cookie = cfs_time_current_sec();
	atomic_set(&cdt->cdt_request_count, 0);
	cdt->cdt_user_request_mask = (1UL << HSMA_RESTORE);
	cdt->cdt_group_request_mask = (1UL << HSMA_RESTORE);
	cdt->cdt_other_request_mask = (1UL << HSMA_RESTORE);

	/* to avoid deadlock when start is made through /proc
	 * /proc entries are created by the coordinator thread */

	/* set up list of started restore requests */
	cdt_mti = lu_context_key_get(&cdt->cdt_env.le_ctx, &mdt_thread_key);
	rc = mdt_hsm_pending_restore(cdt_mti);
	if (rc)
		CERROR("%s: cannot take the layout locks needed"
		       " for registered restore: %d\n",
		       mdt_obd_name(mdt), rc);

	task = kthread_run(mdt_coordinator, cdt_mti, "hsm_cdtr");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		cdt->cdt_state = CDT_STOPPED;
		CERROR("%s: error starting coordinator thread: %d\n",
		       mdt_obd_name(mdt), rc);
		RETURN(rc);
	} else {
		CDEBUG(D_HSM, "%s: coordinator thread started\n",
		       mdt_obd_name(mdt));
		rc = 0;
	}

	wait_event(cdt->cdt_thread.t_ctl_waitq,
		       (cdt->cdt_thread.t_flags & SVC_RUNNING));

	cdt->cdt_state = CDT_RUNNING;
	mdt->mdt_opts.mo_coordinator = 1;
	RETURN(0);
}

/**
 * stop a coordinator thread
 * \param mdt [IN] device
 */
int mdt_hsm_cdt_stop(struct mdt_device *mdt)
{
	struct coordinator		*cdt = &mdt->mdt_coordinator;
	struct cdt_agent_req		*car, *tmp1;
	struct hsm_agent		*ha, *tmp2;
	struct cdt_restore_handle	*crh, *tmp3;
	struct mdt_thread_info		*cdt_mti;
	ENTRY;

	if (cdt->cdt_state == CDT_STOPPED) {
		CERROR("%s: Coordinator already stopped\n",
		       mdt_obd_name(mdt));
		RETURN(-EALREADY);
	}

	if (cdt->cdt_state != CDT_STOPPING) {
		/* stop coordinator thread before cleaning */
		cdt->cdt_thread.t_flags = SVC_STOPPING;
		wake_up(&cdt->cdt_thread.t_ctl_waitq);
		wait_event(cdt->cdt_thread.t_ctl_waitq,
			   cdt->cdt_thread.t_flags & SVC_STOPPED);
	}
	cdt->cdt_state = CDT_STOPPED;

	/* start cleaning */
	down_write(&cdt->cdt_request_lock);
	list_for_each_entry_safe(car, tmp1, &cdt->cdt_requests,
				 car_request_list) {
		list_del(&car->car_request_list);
		mdt_cdt_free_request(car);
	}
	up_write(&cdt->cdt_request_lock);

	down_write(&cdt->cdt_agent_lock);
	list_for_each_entry_safe(ha, tmp2, &cdt->cdt_agents, ha_list) {
		list_del(&ha->ha_list);
		OBD_FREE_PTR(ha);
	}
	up_write(&cdt->cdt_agent_lock);

	cdt_mti = lu_context_key_get(&cdt->cdt_env.le_ctx, &mdt_thread_key);
	mutex_lock(&cdt->cdt_restore_lock);
	list_for_each_entry_safe(crh, tmp3, &cdt->cdt_restore_hdl, crh_list) {
		struct mdt_object	*child;

		/* give back layout lock */
		child = mdt_object_find(&cdt->cdt_env, mdt, &crh->crh_fid);
		if (!IS_ERR(child))
			mdt_object_unlock_put(cdt_mti, child, &crh->crh_lh, 1);

		list_del(&crh->crh_list);

		OBD_SLAB_FREE_PTR(crh, mdt_hsm_cdt_kmem);
	}
	mutex_unlock(&cdt->cdt_restore_lock);

	mdt->mdt_opts.mo_coordinator = 0;

	RETURN(0);
}

/**
 * register all requests from an hal in the memory list
 * \param mti [IN] context
 * \param hal [IN] request
 * \param uuid [OUT] in case of CANCEL, the uuid of the agent
 *  which is running the CT
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_add_hal(struct mdt_thread_info *mti,
		    struct hsm_action_list *hal, struct obd_uuid *uuid)
{
	struct mdt_device	*mdt = mti->mti_mdt;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct hsm_action_item	*hai;
	int			 rc = 0, i;
	ENTRY;

	/* register request in memory list */
	hai = hai_first(hal);
	for (i = 0; i < hal->hal_count; i++, hai = hai_next(hai)) {
		struct cdt_agent_req *car;

		/* in case of a cancel request, we first mark the ondisk
		 * record of the request we want to stop as canceled
		 * this does not change the cancel record
		 * it will be done when updating the request status
		 */
		if (hai->hai_action == HSMA_CANCEL) {
			rc = mdt_agent_record_update(mti->mti_env, mti->mti_mdt,
						     &hai->hai_cookie,
						     1, ARS_CANCELED);
			if (rc) {
				CERROR("%s: mdt_agent_record_update() failed, "
				       "rc=%d, cannot update status to %s "
				       "for cookie "LPX64"\n",
				       mdt_obd_name(mdt), rc,
				       agent_req_status2name(ARS_CANCELED),
				       hai->hai_cookie);
				GOTO(out, rc);
			}

			/* find the running request to set it canceled */
			car = mdt_cdt_find_request(cdt, hai->hai_cookie, NULL);
			if (car != NULL) {
				car->car_canceled = 1;
				/* uuid has to be changed to the one running the
				* request to cancel */
				*uuid = car->car_uuid;
				mdt_cdt_put_request(car);
			}
			/* no need to memorize cancel request
			 * this also avoid a deadlock when we receive
			 * a purge all requests command
			 */
			continue;
		}

		if (hai->hai_action == HSMA_ARCHIVE) {
			struct mdt_object *obj;
			struct md_hsm hsm;

			obj = mdt_hsm_get_md_hsm(mti, &hai->hai_fid, &hsm);
			if (IS_ERR(obj) && (PTR_ERR(obj) == -ENOENT))
				continue;
			if (IS_ERR(obj))
				GOTO(out, rc = PTR_ERR(obj));

			hsm.mh_flags |= HS_EXISTS;
			hsm.mh_arch_id = hal->hal_archive_id;
			rc = mdt_hsm_attr_set(mti, obj, &hsm);
			mdt_object_put(mti->mti_env, obj);
			if (rc)
				GOTO(out, rc);
		}

		car = mdt_cdt_alloc_request(hal->hal_compound_id,
					    hal->hal_archive_id, hal->hal_flags,
					    uuid, hai);
		if (IS_ERR(car))
			GOTO(out, rc = PTR_ERR(car));

		rc = mdt_cdt_add_request(cdt, car);
		if (rc != 0)
			mdt_cdt_free_request(car);
	}
out:
	RETURN(rc);
}

/**
 * swap layouts between 2 fids
 * \param mti [IN] context
 * \param fid1 [IN]
 * \param fid2 [IN]
 * \param mh_common [IN] MD HSM
 */
static int hsm_swap_layouts(struct mdt_thread_info *mti,
			    const lustre_fid *fid, const lustre_fid *dfid,
			    struct md_hsm *mh_common)
{
	struct mdt_device	*mdt = mti->mti_mdt;
	struct mdt_object	*child1, *child2;
	struct mdt_lock_handle	*lh2;
	int			 rc;
	ENTRY;

	child1 = mdt_object_find(mti->mti_env, mdt, fid);
	if (IS_ERR(child1))
		GOTO(out, rc = PTR_ERR(child1));

	/* we already have layout lock on FID so take only
	 * on dfid */
	lh2 = &mti->mti_lh[MDT_LH_OLD];
	mdt_lock_reg_init(lh2, LCK_EX);
	child2 = mdt_object_find_lock(mti, dfid, lh2, MDS_INODELOCK_LAYOUT);
	if (IS_ERR(child2))
		GOTO(out_child1, rc = PTR_ERR(child2));

	/* if copy tool closes the volatile before sending the final
	 * progress through llapi_hsm_copy_end(), all the objects
	 * are removed and mdd_swap_layout LBUG */
	if (!mdt_object_exists(child2)) {
		CERROR("%s: Copytool has closed volatile file "DFID"\n",
		       mdt_obd_name(mti->mti_mdt), PFID(dfid));
		GOTO(out_child2, rc = -ENOENT);
	}
	/* Since we only handle restores here, unconditionally use
	 * SWAP_LAYOUTS_MDS_HSM flag to ensure original layout will
	 * be preserved in case of failure during swap_layout and not
	 * leave a file in an intermediate but incoherent state.
	 * But need to setup HSM xattr of data FID before, reuse
	 * mti and mh presets for FID in hsm_cdt_request_completed(),
	 * only need to clear RELEASED and DIRTY.
	 */
	mh_common->mh_flags &= ~(HS_RELEASED | HS_DIRTY);
	rc = mdt_hsm_attr_set(mti, child2, mh_common);
	if (rc == 0)
		rc = mo_swap_layouts(mti->mti_env,
				     mdt_object_child(child1),
				     mdt_object_child(child2),
				     SWAP_LAYOUTS_MDS_HSM);

out_child2:
	mdt_object_unlock_put(mti, child2, lh2, 1);
out_child1:
	mdt_object_put(mti->mti_env, child1);
out:
	RETURN(rc);
}

/**
 * update status of a completed request
 * \param mti [IN] context
 * \param pgs [IN] progress of the copy tool
 * \param update_record [IN] update llog record
 * \retval 0 success
 * \retval -ve failure
 */
static int hsm_cdt_request_completed(struct mdt_thread_info *mti,
				     struct hsm_progress_kernel *pgs,
				     const struct cdt_agent_req *car,
				     enum agent_req_status *status)
{
	const struct lu_env	*env = mti->mti_env;
	struct mdt_device	*mdt = mti->mti_mdt;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct mdt_object	*obj = NULL;
	int			 cl_flags = 0, rc = 0;
	struct md_hsm		 mh;
	bool			 is_mh_changed;
	ENTRY;

	/* default is to retry */
	*status = ARS_WAITING;

	/* find object by FID */
	obj = mdt_hsm_get_md_hsm(mti, &car->car_hai->hai_fid, &mh);
	/* we will update MD HSM only if needed */
	is_mh_changed = false;
	if (IS_ERR(obj)) {
		/* object removed */
		*status = ARS_SUCCEED;
		goto unlock;
	}

	/* no need to change mh->mh_arch_id
	 * mdt_hsm_get_md_hsm() got it from disk and it is still valid
	 */
	if (pgs->hpk_errval != 0) {
		switch (pgs->hpk_errval) {
		case ENOSYS:
			/* the copy tool does not support cancel
			 * so the cancel request is failed
			 * As we cannot distinguish a cancel progress
			 * from another action progress (they have the
			 * same cookie), we suppose here the CT returns
			 * ENOSYS only if does not support cancel
			 */
			/* this can also happen when cdt calls it to
			 * for a timed out request */
			*status = ARS_FAILED;
			/* to have a cancel event in changelog */
			pgs->hpk_errval = ECANCELED;
			break;
		case ECANCELED:
			/* the request record has already been set to
			 * ARS_CANCELED, this set the cancel request
			 * to ARS_SUCCEED */
			*status = ARS_SUCCEED;
			break;
		default:
			*status = (cdt->cdt_policy & CDT_NORETRY_ACTION ||
				   !(pgs->hpk_flags & HP_FLAG_RETRY) ?
				   ARS_FAILED : ARS_WAITING);
			break;
		}

		if (pgs->hpk_errval > CLF_HSM_MAXERROR) {
			CERROR("%s: Request "LPX64" on "DFID
			       " failed, error code %d too large\n",
			       mdt_obd_name(mdt),
			       pgs->hpk_cookie, PFID(&pgs->hpk_fid),
			       pgs->hpk_errval);
			hsm_set_cl_error(&cl_flags,
					 CLF_HSM_ERROVERFLOW);
			rc = -EINVAL;
		} else {
			hsm_set_cl_error(&cl_flags, pgs->hpk_errval);
		}

		switch (car->car_hai->hai_action) {
		case HSMA_ARCHIVE:
			hsm_set_cl_event(&cl_flags, HE_ARCHIVE);
			break;
		case HSMA_RESTORE:
			hsm_set_cl_event(&cl_flags, HE_RESTORE);
			break;
		case HSMA_REMOVE:
			hsm_set_cl_event(&cl_flags, HE_REMOVE);
			break;
		case HSMA_CANCEL:
			hsm_set_cl_event(&cl_flags, HE_CANCEL);
			CERROR("%s: Failed request "LPX64" on "DFID
			       " cannot be a CANCEL\n",
			       mdt_obd_name(mdt),
			       pgs->hpk_cookie,
			       PFID(&pgs->hpk_fid));
			break;
		default:
			CERROR("%s: Failed request "LPX64" on "DFID
			       " %d is an unknown action\n",
			       mdt_obd_name(mdt),
			       pgs->hpk_cookie, PFID(&pgs->hpk_fid),
			       car->car_hai->hai_action);
			rc = -EINVAL;
			break;
		}
	} else {
		*status = ARS_SUCCEED;
		switch (car->car_hai->hai_action) {
		case HSMA_ARCHIVE:
			hsm_set_cl_event(&cl_flags, HE_ARCHIVE);
			/* set ARCHIVE keep EXIST and clear LOST and
			 * DIRTY */
			mh.mh_arch_ver = pgs->hpk_data_version;
			mh.mh_flags |= HS_ARCHIVED;
			mh.mh_flags &= ~(HS_LOST|HS_DIRTY);
			is_mh_changed = true;
			break;
		case HSMA_RESTORE:
			hsm_set_cl_event(&cl_flags, HE_RESTORE);

			/* do not clear RELEASED and DIRTY here
			 * this will occur in hsm_swap_layouts()
			 */

			/* Restoring has changed the file version on
			 * disk. */
			mh.mh_arch_ver = pgs->hpk_data_version;
			is_mh_changed = true;
			break;
		case HSMA_REMOVE:
			hsm_set_cl_event(&cl_flags, HE_REMOVE);
			/* clear ARCHIVED EXISTS and LOST */
			mh.mh_flags &= ~(HS_ARCHIVED | HS_EXISTS | HS_LOST);
			is_mh_changed = true;
			break;
		case HSMA_CANCEL:
			hsm_set_cl_event(&cl_flags, HE_CANCEL);
			CERROR("%s: Successful request "LPX64
			       " on "DFID
			       " cannot be a CANCEL\n",
			       mdt_obd_name(mdt),
			       pgs->hpk_cookie,
			       PFID(&pgs->hpk_fid));
			break;
		default:
			CERROR("%s: Successful request "LPX64
			       " on "DFID
			       " %d is an unknown action\n",
			       mdt_obd_name(mdt),
			       pgs->hpk_cookie, PFID(&pgs->hpk_fid),
			       car->car_hai->hai_action);
			rc = -EINVAL;
			break;
		}
	}

	/* rc != 0 means error when analysing action, it may come from
	 * a crasy CT no need to manage DIRTY
	 */
	if (rc == 0)
		hsm_set_cl_flags(&cl_flags,
				 mh.mh_flags & HS_DIRTY ? CLF_HSM_DIRTY : 0);

	/* unlock is done later, after layout lock management */
	if (is_mh_changed)
		rc = mdt_hsm_attr_set(mti, obj, &mh);

unlock:
	/* we give back layout lock only if restore was successful or
	 * if restore was canceled or if policy is to not retry
	 * in other cases we just unlock the object */
	if (car->car_hai->hai_action == HSMA_RESTORE &&
	    (pgs->hpk_errval == 0 || pgs->hpk_errval == ECANCELED ||
	     cdt->cdt_policy & CDT_NORETRY_ACTION)) {
		struct cdt_restore_handle	*crh;

		/* restore in data FID done, we swap the layouts
		 * only if restore is successfull */
		if (pgs->hpk_errval == 0) {
			rc = hsm_swap_layouts(mti, &car->car_hai->hai_fid,
					      &car->car_hai->hai_dfid, &mh);
			if (rc) {
				if (cdt->cdt_policy & CDT_NORETRY_ACTION)
					*status = ARS_FAILED;
				pgs->hpk_errval = -rc;
			}
		}
		/* we have to retry, so keep layout lock */
		if (*status == ARS_WAITING)
			GOTO(out, rc);

		/* give back layout lock */
		mutex_lock(&cdt->cdt_restore_lock);
		crh = hsm_restore_hdl_find(cdt, &car->car_hai->hai_fid);
		if (crh != NULL)
			list_del(&crh->crh_list);
		mutex_unlock(&cdt->cdt_restore_lock);
		/* just give back layout lock, we keep
		 * the reference which is given back
		 * later with the lock for HSM flags */
		if (!IS_ERR(obj) && crh != NULL)
			mdt_object_unlock(mti, obj, &crh->crh_lh, 1);

		if (crh != NULL)
			OBD_SLAB_FREE_PTR(crh, mdt_hsm_cdt_kmem);
	}

	GOTO(out, rc);

out:
	if (obj != NULL && !IS_ERR(obj)) {
		mo_changelog(env, CL_HSM, cl_flags,
			     mdt_object_child(obj));
		mdt_object_put(mti->mti_env, obj);
	}

	RETURN(rc);
}

/**
 * update status of a request
 * \param mti [IN] context
 * \param pgs [IN] progress of the copy tool
 * \param update_record [IN] update llog record
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_hsm_update_request_state(struct mdt_thread_info *mti,
				 struct hsm_progress_kernel *pgs,
				 const int update_record)
{
	struct mdt_device	*mdt = mti->mti_mdt;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct cdt_agent_req	*car;
	int			 rc = 0;
	ENTRY;

	/* no coordinator started, so we cannot serve requests */
	if (cdt->cdt_state == CDT_STOPPED)
		RETURN(-EAGAIN);

	/* first do sanity checks */
	car = mdt_cdt_update_request(cdt, pgs);
	if (IS_ERR(car)) {
		CERROR("%s: Cannot find running request for cookie "LPX64
		       " on fid="DFID"\n",
		       mdt_obd_name(mdt),
		       pgs->hpk_cookie, PFID(&pgs->hpk_fid));
		if (car == NULL)
			RETURN(-ENOENT);
		RETURN(PTR_ERR(car));
	}

	CDEBUG(D_HSM, "Progress received for fid="DFID" cookie="LPX64
		      " action=%s flags=%d err=%d fid="DFID" dfid="DFID"\n",
		      PFID(&pgs->hpk_fid), pgs->hpk_cookie,
		      hsm_copytool_action2name(car->car_hai->hai_action),
		      pgs->hpk_flags, pgs->hpk_errval,
		      PFID(&car->car_hai->hai_fid),
		      PFID(&car->car_hai->hai_dfid));

	/* progress is done on FID or data FID depending of the action and
	 * of the copy progress */
	/* for restore progress is used to send back the data FID to cdt */
	if (car->car_hai->hai_action == HSMA_RESTORE &&
	    lu_fid_eq(&car->car_hai->hai_fid, &car->car_hai->hai_dfid))
		car->car_hai->hai_dfid = pgs->hpk_fid;

	if ((car->car_hai->hai_action == HSMA_RESTORE ||
	     car->car_hai->hai_action == HSMA_ARCHIVE) &&
	    (!lu_fid_eq(&pgs->hpk_fid, &car->car_hai->hai_dfid) &&
	     !lu_fid_eq(&pgs->hpk_fid, &car->car_hai->hai_fid))) {
		CERROR("%s: Progress on "DFID" for cookie "LPX64
		       " does not match request FID "DFID" nor data FID "
		       DFID"\n",
		       mdt_obd_name(mdt),
		       PFID(&pgs->hpk_fid), pgs->hpk_cookie,
		       PFID(&car->car_hai->hai_fid),
		       PFID(&car->car_hai->hai_dfid));
		GOTO(out, rc = -EINVAL);
	}

	if (pgs->hpk_errval != 0 && !(pgs->hpk_flags & HP_FLAG_COMPLETED)) {
		CERROR("%s: Progress on "DFID" for cookie "LPX64" action=%s"
		       " is not coherent (err=%d and not completed"
		       " (flags=%d))\n",
		       mdt_obd_name(mdt),
		       PFID(&pgs->hpk_fid), pgs->hpk_cookie,
		       hsm_copytool_action2name(car->car_hai->hai_action),
		       pgs->hpk_errval, pgs->hpk_flags);
		GOTO(out, rc = -EINVAL);
	}

	/* now progress is valid */

	/* we use a root like ucred */
	hsm_init_ucred(mdt_ucred(mti));

	if (pgs->hpk_flags & HP_FLAG_COMPLETED) {
		enum agent_req_status	 status;

		rc = hsm_cdt_request_completed(mti, pgs, car, &status);

		/* remove request from memory list */
		mdt_cdt_remove_request(cdt, pgs->hpk_cookie);

		CDEBUG(D_HSM, "Updating record: fid="DFID" cookie="LPX64
			      " action=%s status=%s\n", PFID(&pgs->hpk_fid),
		       pgs->hpk_cookie,
		       hsm_copytool_action2name(car->car_hai->hai_action),
		       agent_req_status2name(status));

		if (update_record) {
			int rc1;

			rc1 = mdt_agent_record_update(mti->mti_env, mdt,
						     &pgs->hpk_cookie, 1,
						     status);
			if (rc1)
				CERROR("%s: mdt_agent_record_update() failed,"
				       " rc=%d, cannot update status to %s"
				       " for cookie "LPX64"\n",
				       mdt_obd_name(mdt), rc1,
				       agent_req_status2name(status),
				       pgs->hpk_cookie);
			rc = (rc != 0 ? rc : rc1);
		}
		/* ct has completed a request, so a slot is available, wakeup
		 * cdt to find new work */
		mdt_hsm_cdt_wakeup(mdt);
	} else {
		/* if copytool send a progress on a canceled request
		 * we inform copytool it should stop
		 */
		if (car->car_canceled == 1)
			rc = -ECANCELED;
	}
	GOTO(out, rc);

out:
	/* remove ref got from mdt_cdt_update_request() */
	mdt_cdt_put_request(car);

	return rc;
}


/**
 * data passed to llog_cat_process() callback
 * to cancel requests
 */
struct hsm_cancel_all_data {
	struct mdt_device	*mdt;
};

/**
 *  llog_cat_process() callback, used to:
 *  - purge all requests
 * \param env [IN] environment
 * \param llh [IN] llog handle
 * \param hdr [IN] llog record
 * \param data [IN] cb data = struct hsm_cancel_all_data
 * \retval 0 success
 * \retval -ve failure
 */
static int mdt_cancel_all_cb(const struct lu_env *env,
			     struct llog_handle *llh,
			     struct llog_rec_hdr *hdr, void *data)
{
	struct llog_agent_req_rec	*larr;
	struct hsm_cancel_all_data	*hcad;
	int				 rc = 0;
	ENTRY;

	larr = (struct llog_agent_req_rec *)hdr;
	hcad = data;
	if (larr->arr_status == ARS_WAITING ||
	    larr->arr_status == ARS_STARTED) {
		larr->arr_status = ARS_CANCELED;
		larr->arr_req_change = cfs_time_current_sec();
		rc = mdt_agent_llog_update_rec(env, hcad->mdt, llh, larr);
		if (rc == 0)
			RETURN(LLOG_DEL_RECORD);
	}
	RETURN(rc);
}

/**
 * cancel all actions
 * \param obd [IN] MDT device
 */
static int hsm_cancel_all_actions(struct mdt_device *mdt)
{
	struct mdt_thread_info		*mti;
	struct coordinator		*cdt = &mdt->mdt_coordinator;
	struct cdt_agent_req		*car;
	struct hsm_action_list		*hal = NULL;
	struct hsm_action_item		*hai;
	struct hsm_cancel_all_data	 hcad;
	int				 hal_sz = 0, hal_len, rc;
	enum cdt_states			 save_state;
	ENTRY;

	/* retrieve coordinator context */
	mti = lu_context_key_get(&cdt->cdt_env.le_ctx, &mdt_thread_key);

	/* disable coordinator */
	save_state = cdt->cdt_state;
	cdt->cdt_state = CDT_DISABLE;

	/* send cancel to all running requests */
	down_read(&cdt->cdt_request_lock);
	list_for_each_entry(car, &cdt->cdt_requests, car_request_list) {
		mdt_cdt_get_request(car);
		/* request is not yet removed from list, it will be done
		 * when copytool will return progress
		 */

		if (car->car_hai->hai_action == HSMA_CANCEL) {
			mdt_cdt_put_request(car);
			continue;
		}

		/* needed size */
		hal_len = sizeof(*hal) + cfs_size_round(MTI_NAME_MAXLEN + 1) +
			  cfs_size_round(car->car_hai->hai_len);

		if (hal_len > hal_sz && hal_sz > 0) {
			/* not enough room, free old buffer */
			OBD_FREE(hal, hal_sz);
			hal = NULL;
		}

		/* empty buffer, allocate one */
		if (hal == NULL) {
			hal_sz = hal_len;
			OBD_ALLOC(hal, hal_sz);
			if (hal == NULL) {
				mdt_cdt_put_request(car);
				up_read(&cdt->cdt_request_lock);
				GOTO(out, rc = -ENOMEM);
			}
		}

		hal->hal_version = HAL_VERSION;
		obd_uuid2fsname(hal->hal_fsname, mdt_obd_name(mdt),
				MTI_NAME_MAXLEN);
		hal->hal_fsname[MTI_NAME_MAXLEN] = '\0';
		hal->hal_compound_id = car->car_compound_id;
		hal->hal_archive_id = car->car_archive_id;
		hal->hal_flags = car->car_flags;
		hal->hal_count = 0;

		hai = hai_first(hal);
		memcpy(hai, car->car_hai, car->car_hai->hai_len);
		hai->hai_action = HSMA_CANCEL;
		hal->hal_count = 1;

		/* it is possible to safely call mdt_hsm_agent_send()
		 * (ie without a deadlock on cdt_request_lock), because the
		 * write lock is taken only if we are not in purge mode
		 * (mdt_hsm_agent_send() does not call mdt_cdt_add_request()
		 *   nor mdt_cdt_remove_request())
		 */
		/* no conflict with cdt thread because cdt is disable and we
		 * have the request lock */
		mdt_hsm_agent_send(mti, hal, 1);

		mdt_cdt_put_request(car);
	}
	up_read(&cdt->cdt_request_lock);

	if (hal != NULL)
		OBD_FREE(hal, hal_sz);

	/* cancel all on-disk records */
	hcad.mdt = mdt;

	rc = cdt_llog_process(mti->mti_env, mti->mti_mdt,
			      mdt_cancel_all_cb, &hcad);
out:
	/* enable coordinator */
	cdt->cdt_state = save_state;

	RETURN(rc);
}

/**
 * check if a request is comptaible with file status
 * \param hai [IN] request description
 * \param hal_an [IN] request archive number (not used)
 * \param rq_flags [IN] request flags
 * \param hsm [IN] file HSM metadata
 * \retval boolean
 */
bool mdt_hsm_is_action_compat(const struct hsm_action_item *hai,
			      const int hal_an, const __u64 rq_flags,
			      const struct md_hsm *hsm)
{
	int	 is_compat = false;
	int	 hsm_flags;
	ENTRY;

	hsm_flags = hsm->mh_flags;
	switch (hai->hai_action) {
	case HSMA_ARCHIVE:
		if (!(hsm_flags & HS_NOARCHIVE) &&
		    (hsm_flags & HS_DIRTY || !(hsm_flags & HS_ARCHIVED)))
			is_compat = true;
		break;
	case HSMA_RESTORE:
		if (!(hsm_flags & HS_DIRTY) && (hsm_flags & HS_RELEASED) &&
		    hsm_flags & HS_ARCHIVED && !(hsm_flags & HS_LOST))
			is_compat = true;
		break;
	case HSMA_REMOVE:
		if (!(hsm_flags & HS_RELEASED) &&
		    (hsm_flags & (HS_ARCHIVED | HS_EXISTS)))
			is_compat = true;
		break;
	case HSMA_CANCEL:
		is_compat = true;
		break;
	}
	CDEBUG(D_HSM, "fid="DFID" action=%s flags="LPX64
		      " extent="LPX64"-"LPX64" hsm_flags=%.8X %s\n",
		      PFID(&hai->hai_fid),
		      hsm_copytool_action2name(hai->hai_action), rq_flags,
		      hai->hai_extent.offset, hai->hai_extent.length,
		      hsm->mh_flags,
		      (is_compat ? "compatible" : "uncompatible"));

	RETURN(is_compat);
}

/*
 * /proc interface used to get/set HSM behaviour (cdt->cdt_policy)
 */
static const struct {
	__u64		 bit;
	char		*name;
	char		*nickname;
} hsm_policy_names[] = {
	{ CDT_NONBLOCKING_RESTORE,	"NonBlockingRestore",	"NBR"},
	{ CDT_NORETRY_ACTION,		"NoRetryAction",	"NRA"},
	{ 0 },
};

/**
 * convert a policy name to a bit
 * \param name [IN] policy name
 * \retval 0 unknown
 * \retval   policy bit
 */
static __u64 hsm_policy_str2bit(const char *name)
{
	int	 i;

	for (i = 0; hsm_policy_names[i].bit != 0; i++)
		if (strcmp(hsm_policy_names[i].nickname, name) == 0 ||
		    strcmp(hsm_policy_names[i].name, name) == 0)
			return hsm_policy_names[i].bit;
	return 0;
}

/**
 * convert a policy bit field to a string
 * \param mask [IN] policy bit field
 * \param hexa [IN] print mask before bit names
 * \param buffer [OUT] string
 * \param count [IN] size of buffer
 */
static void hsm_policy_bit2str(struct seq_file *m, const __u64 mask,
				const bool hexa)
{
	int	 i, j;
	__u64	 bit;
	ENTRY;

	if (hexa)
		seq_printf(m, "("LPX64") ", mask);

	for (i = 0; i < CDT_POLICY_SHIFT_COUNT; i++) {
		bit = (1ULL << i);

		for (j = 0; hsm_policy_names[j].bit != 0; j++) {
			if (hsm_policy_names[j].bit == bit)
				break;
		}
		if (bit & mask)
			seq_printf(m, "[%s] ", hsm_policy_names[j].name);
		else
			seq_printf(m, "%s ", hsm_policy_names[j].name);
	}
	/* remove last ' ' */
	m->count--;
	seq_putc(m, '\0');
}

/* methods to read/write HSM policy flags */
static int mdt_hsm_policy_seq_show(struct seq_file *m, void *data)
{
	struct mdt_device	*mdt = m->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	ENTRY;

	hsm_policy_bit2str(m, cdt->cdt_policy, false);
	RETURN(0);
}

static ssize_t
mdt_hsm_policy_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct mdt_device	*mdt = m->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	char			*start, *token, sign;
	char			*buf;
	__u64			 policy;
	__u64			 add_mask, remove_mask, set_mask;
	int			 rc;
	ENTRY;

	if (count + 1 > PAGE_SIZE)
		RETURN(-EINVAL);

	OBD_ALLOC(buf, count + 1);
	if (buf == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(buf, buffer, count))
		GOTO(out, rc = -EFAULT);

	buf[count] = '\0';

	start = buf;
	CDEBUG(D_HSM, "%s: receive new policy: '%s'\n", mdt_obd_name(mdt),
	       start);

	add_mask = remove_mask = set_mask = 0;
	do {
		token = strsep(&start, "\n ");
		sign = *token;

		if (sign == '\0')
			continue;

		if (sign == '-' || sign == '+')
			token++;

		policy = hsm_policy_str2bit(token);
		if (policy == 0) {
			CWARN("%s: '%s' is unknown, "
			      "supported policies are:\n", mdt_obd_name(mdt),
			      token);
			hsm_policy_bit2str(m, 0, false);
			GOTO(out, rc = -EINVAL);
		}
		switch (sign) {
		case '-':
			remove_mask |= policy;
			break;
		case '+':
			add_mask |= policy;
			break;
		default:
			set_mask |= policy;
			break;
		}

	} while (start != NULL);

	CDEBUG(D_HSM, "%s: new policy: rm="LPX64" add="LPX64" set="LPX64"\n",
	       mdt_obd_name(mdt), remove_mask, add_mask, set_mask);

	/* if no sign in all string, it is a clear and set
	 * if some sign found, all unsigned are converted
	 * to add
	 * P1 P2 = set to P1 and P2
	 * P1 -P2 = add P1 clear P2 same as +P1 -P2
	 */
	if (remove_mask == 0 && add_mask == 0) {
		cdt->cdt_policy = set_mask;
	} else {
		cdt->cdt_policy |= set_mask | add_mask;
		cdt->cdt_policy &= ~remove_mask;
	}

	GOTO(out, rc = count);

out:
	OBD_FREE(buf, count + 1);
	RETURN(rc);
}
LPROC_SEQ_FOPS(mdt_hsm_policy);

#define GENERATE_PROC_METHOD(VAR)					\
static int mdt_hsm_##VAR##_seq_show(struct seq_file *m, void *data)	\
{									\
	struct mdt_device	*mdt = m->private;			\
	struct coordinator	*cdt = &mdt->mdt_coordinator;		\
	ENTRY;								\
									\
	seq_printf(m, LPU64"\n", (__u64)cdt->VAR);			\
	RETURN(0);							\
}									\
static ssize_t								\
mdt_hsm_##VAR##_seq_write(struct file *file, const char __user *buffer,	\
			  size_t count, loff_t *off)			\
									\
{									\
	struct seq_file		*m = file->private_data;		\
	struct mdt_device	*mdt = m->private;			\
	struct coordinator	*cdt = &mdt->mdt_coordinator;		\
	int			 val;					\
	int			 rc;					\
	ENTRY;								\
									\
	rc = lprocfs_write_helper(buffer, count, &val);			\
	if (rc)								\
		RETURN(rc);						\
	if (val > 0) {							\
		cdt->VAR = val;						\
		RETURN(count);						\
	}								\
	RETURN(-EINVAL);						\
}									\

GENERATE_PROC_METHOD(cdt_loop_period)
GENERATE_PROC_METHOD(cdt_grace_delay)
GENERATE_PROC_METHOD(cdt_active_req_timeout)
GENERATE_PROC_METHOD(cdt_max_requests)
GENERATE_PROC_METHOD(cdt_default_archive_id)

/*
 * procfs write method for MDT/hsm_control
 * proc entry is in mdt directory so data is mdt obd_device pointer
 */
#define CDT_ENABLE_CMD   "enabled"
#define CDT_STOP_CMD     "shutdown"
#define CDT_DISABLE_CMD  "disabled"
#define CDT_PURGE_CMD    "purge"
#define CDT_HELP_CMD     "help"
#define CDT_MAX_CMD_LEN  10

ssize_t
mdt_hsm_cdt_control_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
	struct mdt_device	*mdt = mdt_dev(obd->obd_lu_dev);
	struct coordinator	*cdt = &(mdt->mdt_coordinator);
	int			 rc, usage = 0;
	char			 kernbuf[CDT_MAX_CMD_LEN];
	ENTRY;

	if (count == 0 || count >= sizeof(kernbuf))
		RETURN(-EINVAL);

	if (copy_from_user(kernbuf, buffer, count))
		RETURN(-EFAULT);
	kernbuf[count] = 0;

	if (kernbuf[count - 1] == '\n')
		kernbuf[count - 1] = 0;

	rc = 0;
	if (strcmp(kernbuf, CDT_ENABLE_CMD) == 0) {
		if (cdt->cdt_state == CDT_DISABLE) {
			cdt->cdt_state = CDT_RUNNING;
			mdt_hsm_cdt_wakeup(mdt);
		} else {
			rc = mdt_hsm_cdt_start(mdt);
		}
	} else if (strcmp(kernbuf, CDT_STOP_CMD) == 0) {
		if ((cdt->cdt_state == CDT_STOPPING) ||
		    (cdt->cdt_state == CDT_STOPPED)) {
			CERROR("%s: Coordinator already stopped\n",
			       mdt_obd_name(mdt));
			rc = -EALREADY;
		} else {
			cdt->cdt_state = CDT_STOPPING;
		}
	} else if (strcmp(kernbuf, CDT_DISABLE_CMD) == 0) {
		if ((cdt->cdt_state == CDT_STOPPING) ||
		    (cdt->cdt_state == CDT_STOPPED)) {
			CERROR("%s: Coordinator is stopped\n",
			       mdt_obd_name(mdt));
			rc = -EINVAL;
		} else {
			cdt->cdt_state = CDT_DISABLE;
		}
	} else if (strcmp(kernbuf, CDT_PURGE_CMD) == 0) {
		rc = hsm_cancel_all_actions(mdt);
	} else if (strcmp(kernbuf, CDT_HELP_CMD) == 0) {
		usage = 1;
	} else {
		usage = 1;
		rc = -EINVAL;
	}

	if (usage == 1)
		CERROR("%s: Valid coordinator control commands are: "
		       "%s %s %s %s %s\n", mdt_obd_name(mdt),
		       CDT_ENABLE_CMD, CDT_STOP_CMD, CDT_DISABLE_CMD,
		       CDT_PURGE_CMD, CDT_HELP_CMD);

	if (rc)
		RETURN(rc);

	RETURN(count);
}

int mdt_hsm_cdt_control_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct coordinator	*cdt;
	ENTRY;

	cdt = &(mdt_dev(obd->obd_lu_dev)->mdt_coordinator);

	if (cdt->cdt_state == CDT_INIT)
		seq_printf(m, "init\n");
	else if (cdt->cdt_state == CDT_RUNNING)
		seq_printf(m, "enabled\n");
	else if (cdt->cdt_state == CDT_STOPPING)
		seq_printf(m, "stopping\n");
	else if (cdt->cdt_state == CDT_STOPPED)
		seq_printf(m, "stopped\n");
	else if (cdt->cdt_state == CDT_DISABLE)
		seq_printf(m, "disabled\n");
	else
		seq_printf(m, "unknown\n");

	RETURN(0);
}

static int
mdt_hsm_request_mask_show(struct seq_file *m, __u64 mask)
{
	int i, rc = 0;
	ENTRY;

	for (i = 0; i < 8 * sizeof(mask); i++) {
		if (mask & (1UL << i))
			rc += seq_printf(m, "%s%s", rc == 0 ? "" : " ",
					hsm_copytool_action2name(i));
	}
	rc += seq_printf(m, "\n");

	RETURN(rc);
}

static int
mdt_hsm_user_request_mask_seq_show(struct seq_file *m, void *data)
{
	struct mdt_device *mdt = m->private;
	struct coordinator *cdt = &mdt->mdt_coordinator;

	return mdt_hsm_request_mask_show(m, cdt->cdt_user_request_mask);
}

static int
mdt_hsm_group_request_mask_seq_show(struct seq_file *m, void *data)
{
	struct mdt_device *mdt = m->private;
	struct coordinator *cdt = &mdt->mdt_coordinator;

	return mdt_hsm_request_mask_show(m, cdt->cdt_group_request_mask);
}

static int
mdt_hsm_other_request_mask_seq_show(struct seq_file *m, void *data)
{
	struct mdt_device *mdt = m->private;
	struct coordinator *cdt = &mdt->mdt_coordinator;

	return mdt_hsm_request_mask_show(m, cdt->cdt_other_request_mask);
}

static inline enum hsm_copytool_action
hsm_copytool_name2action(const char *name)
{
	if (strcasecmp(name, "NOOP") == 0)
		return HSMA_NONE;
	else if (strcasecmp(name, "ARCHIVE") == 0)
		return HSMA_ARCHIVE;
	else if (strcasecmp(name, "RESTORE") == 0)
		return HSMA_RESTORE;
	else if (strcasecmp(name, "REMOVE") == 0)
		return HSMA_REMOVE;
	else if (strcasecmp(name, "CANCEL") == 0)
		return HSMA_CANCEL;
	else
		return -1;
}

static ssize_t
mdt_write_hsm_request_mask(struct file *file, const char __user *user_buf,
			    size_t user_count, __u64 *mask)
{
	char *buf, *pos, *name;
	size_t buf_size;
	__u64 new_mask = 0;
	int rc;
	ENTRY;

	if (!(user_count < 4096))
		RETURN(-ENOMEM);

	buf_size = user_count + 1;

	OBD_ALLOC(buf, buf_size);
	if (buf == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(buf, user_buf, buf_size - 1))
		GOTO(out, rc = -EFAULT);

	buf[buf_size - 1] = '\0';

	pos = buf;
	while ((name = strsep(&pos, " \t\v\n")) != NULL) {
		int action;

		if (*name == '\0')
			continue;

		action = hsm_copytool_name2action(name);
		if (action < 0)
			GOTO(out, rc = -EINVAL);

		new_mask |= (1UL << action);
	}

	*mask = new_mask;
	rc = user_count;
out:
	OBD_FREE(buf, buf_size);

	RETURN(rc);
}

static ssize_t
mdt_hsm_user_request_mask_seq_write(struct file *file, const char __user *buf,
					size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct mdt_device	*mdt = m->private;
	struct coordinator *cdt = &mdt->mdt_coordinator;

	return mdt_write_hsm_request_mask(file, buf, count,
					   &cdt->cdt_user_request_mask);
}

static ssize_t
mdt_hsm_group_request_mask_seq_write(struct file *file, const char __user *buf,
					size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct mdt_device	*mdt = m->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;

	return mdt_write_hsm_request_mask(file, buf, count,
					   &cdt->cdt_group_request_mask);
}

static ssize_t
mdt_hsm_other_request_mask_seq_write(struct file *file, const char __user *buf,
					size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct mdt_device	*mdt = m->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;

	return mdt_write_hsm_request_mask(file, buf, count,
					   &cdt->cdt_other_request_mask);
}

LPROC_SEQ_FOPS(mdt_hsm_cdt_loop_period);
LPROC_SEQ_FOPS(mdt_hsm_cdt_grace_delay);
LPROC_SEQ_FOPS(mdt_hsm_cdt_active_req_timeout);
LPROC_SEQ_FOPS(mdt_hsm_cdt_max_requests);
LPROC_SEQ_FOPS(mdt_hsm_cdt_default_archive_id);
LPROC_SEQ_FOPS(mdt_hsm_user_request_mask);
LPROC_SEQ_FOPS(mdt_hsm_group_request_mask);
LPROC_SEQ_FOPS(mdt_hsm_other_request_mask);

static struct lprocfs_vars lprocfs_mdt_hsm_vars[] = {
	{ .name	=	"agents",
	  .fops	=	&mdt_hsm_agent_fops			},
	{ .name	=	"actions",
	  .fops	=	&mdt_hsm_actions_fops,
	  .proc_mode =	0444					},
	{ .name	=	"default_archive_id",
	  .fops	=	&mdt_hsm_cdt_default_archive_id_fops	},
	{ .name	=	"grace_delay",
	  .fops	=	&mdt_hsm_cdt_grace_delay_fops		},
	{ .name	=	"loop_period",
	  .fops	=	&mdt_hsm_cdt_loop_period_fops		},
	{ .name	=	"max_requests",
	  .fops	=	&mdt_hsm_cdt_max_requests_fops		},
	{ .name	=	"policy",
	  .fops	=	&mdt_hsm_policy_fops			},
	{ .name	=	"active_request_timeout",
	  .fops	=	&mdt_hsm_cdt_active_req_timeout_fops	},
	{ .name	=	"active_requests",
	  .fops	=	&mdt_hsm_active_requests_fops		},
	{ .name	=	"user_request_mask",
	  .fops	=	&mdt_hsm_user_request_mask_fops,	},
	{ .name	=	"group_request_mask",
	  .fops	=	&mdt_hsm_group_request_mask_fops,	},
	{ .name	=	"other_request_mask",
	  .fops	=	&mdt_hsm_other_request_mask_fops,	},
	{ 0 }
};
