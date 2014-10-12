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
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 */
/*
 * lustre/mdt/mdt_hsm_cdt_requests.c
 *
 * Lustre HSM Coordinator
 *
 * Author: Jacques-Charles Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_support.h>
#include <lustre/lustre_user.h>
#include <lprocfs_status.h>
#include "mdt_internal.h"

/**
 * dump requests list
 * \param cdt [IN] coordinator
 */
void dump_requests(char *prefix, struct coordinator *cdt)
{
	struct cdt_agent_req	*car;

	down_read(&cdt->cdt_request_lock);
	list_for_each_entry(car, &cdt->cdt_requests, car_request_list) {
		CDEBUG(D_HSM, "%s fid="DFID" dfid="DFID
		       " compound/cookie="LPX64"/"LPX64
		       " action=%s archive#=%d flags="LPX64
		       " extent="LPX64"-"LPX64
		       " gid="LPX64" refcount=%d canceled=%d\n",
		       prefix, PFID(&car->car_hai->hai_fid),
		       PFID(&car->car_hai->hai_dfid),
		       car->car_compound_id, car->car_hai->hai_cookie,
		       hsm_copytool_action2name(car->car_hai->hai_action),
		       car->car_archive_id, car->car_flags,
		       car->car_hai->hai_extent.offset,
		       car->car_hai->hai_extent.length,
		       car->car_hai->hai_gid,
		       atomic_read(&car->car_refcount),
		       car->car_canceled);
	}
	up_read(&cdt->cdt_request_lock);
}

struct req_interval_data {
	struct cdt_req_progress	*crp;
	__u64			 done_sz;
};

/**
 * interval tree cb, used to go through all the tree of extent done
 */
static enum interval_iter req_interval_cb(struct interval_node *node,
					  void *args)
{
	struct req_interval_data	*data;
	ENTRY;

	data = args;
	data->done_sz += node->in_extent.end - node->in_extent.start;
	RETURN(INTERVAL_ITER_CONT);
}

/**
 * scan the interval tree associated to a request
 * to compute the amount of work done
 * \param car [IN] request
 * \param done_sz [OUT] will be set to the size of work done
 */
void mdt_cdt_get_work_done(struct cdt_agent_req *car, __u64 *done_sz)
{
	struct req_interval_data	 rid;
	struct cdt_req_progress		*crp = &car->car_progress;

	mutex_lock(&crp->crp_lock);

	rid.crp = crp;
	rid.done_sz = 0;
	interval_iterate(crp->crp_root, req_interval_cb, &rid);
	*done_sz = rid.done_sz;

	mutex_unlock(&crp->crp_lock);
}

#define NODE_VECTOR_SZ 256
/**
 * free the interval tree associated to a request
 */
static void mdt_cdt_free_request_tree(struct cdt_req_progress *crp)
{
	struct interval_node	*node, *vn;
	int			 i;
	ENTRY;

	mutex_lock(&crp->crp_lock);

	if (crp->crp_max == 0)
		goto out;

	/* remove all nodes from tree */
	for (i = 0 ; i < crp->crp_cnt ; i++) {
		vn = crp->crp_node[i / NODE_VECTOR_SZ];
		node = &vn[i % NODE_VECTOR_SZ];
		interval_erase(node, &crp->crp_root);
	}
	/* free all sub vectors */
	for (i = 0 ; i <= crp->crp_max / NODE_VECTOR_SZ ; i++)
		OBD_FREE(crp->crp_node[i],
			 NODE_VECTOR_SZ * sizeof(crp->crp_node[i][0]));

	/* free main vector */
	OBD_FREE(crp->crp_node,
		 sizeof(crp->crp_node[0]) *
		  (crp->crp_max / NODE_VECTOR_SZ + 1));

	crp->crp_cnt = 0;
	crp->crp_max = 0;
out:
	mutex_unlock(&crp->crp_lock);
	EXIT;
}

/**
 * update data moved information during a request
 */
static int hsm_update_work(struct cdt_req_progress *crp,
			   const struct hsm_extent *extent)
{
	int			  rc, osz, nsz;
	struct interval_node	**new_vv;
	struct interval_node	 *v, *node;
	__u64			  end;
	ENTRY;

	end = extent->offset + extent->length;
	if (end <= extent->offset)
		RETURN(-EINVAL);

	mutex_lock(&crp->crp_lock);
	/* new node index */

	if (crp->crp_cnt >= crp->crp_max) {
		/* no more room */
		/* allocate a new vector */
		OBD_ALLOC(v, NODE_VECTOR_SZ * sizeof(v[0]));
		if (v == NULL)
			GOTO(out, rc = -ENOMEM);

		if (crp->crp_max == 0)
			osz = 0;
		else
			osz = sizeof(new_vv[0]) *
			      (crp->crp_max / NODE_VECTOR_SZ + 1);

		nsz = osz + sizeof(new_vv[0]);
		/* increase main vector size */
		OBD_ALLOC(new_vv, nsz);
		if (new_vv == NULL) {
			OBD_FREE(v, NODE_VECTOR_SZ * sizeof(v[0]));
			GOTO(out, rc = -ENOMEM);
		}

		if (osz == 0) {
			crp->crp_max = NODE_VECTOR_SZ - 1;
		} else {
			memcpy(new_vv, crp->crp_node, osz);
			OBD_FREE(crp->crp_node, osz);
			crp->crp_max += NODE_VECTOR_SZ;
		}

		crp->crp_node = new_vv;
		crp->crp_node[crp->crp_max / NODE_VECTOR_SZ] = v;
	}

	v = crp->crp_node[crp->crp_cnt / NODE_VECTOR_SZ];
	node = &v[crp->crp_cnt % NODE_VECTOR_SZ];
	interval_set(node, extent->offset, end);
	/* try to insert, if entry already exist ignore the new one
	 * it can happen if ct sends 2 times the same progress */
	if (interval_insert(node, &crp->crp_root) == NULL)
		crp->crp_cnt++;

	rc = 0;
out:
	mutex_unlock(&crp->crp_lock);
	RETURN(rc);
}

/**
 * init the interval tree associated to a request
 */
static void mdt_cdt_init_request_tree(struct cdt_req_progress *crp)
{
	mutex_init(&crp->crp_lock);
	crp->crp_root = NULL;
	crp->crp_cnt = 0;
	crp->crp_max = 0;
}

/** Allocate/init a agent request and its sub-structures.
 *
 * \param compound_id [IN]
 * \param archive_id [IN]
 * \param flags [IN]
 * \param uuid [IN]
 * \param hai [IN]
 * \retval car [OUT] success valid structure
 * \retval car [OUT]
 */
struct cdt_agent_req *mdt_cdt_alloc_request(__u64 compound_id, __u32 archive_id,
					    __u64 flags, struct obd_uuid *uuid,
					    struct hsm_action_item *hai)
{
	struct cdt_agent_req *car;
	ENTRY;

	OBD_SLAB_ALLOC_PTR(car, mdt_hsm_car_kmem);
	if (car == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	atomic_set(&car->car_refcount, 1);
	car->car_compound_id = compound_id;
	car->car_archive_id = archive_id;
	car->car_flags = flags;
	car->car_canceled = 0;
	car->car_req_start = cfs_time_current_sec();
	car->car_req_update = car->car_req_start;
	car->car_uuid = *uuid;
	OBD_ALLOC(car->car_hai, hai->hai_len);
	if (car->car_hai == NULL) {
		OBD_SLAB_FREE_PTR(car, mdt_hsm_car_kmem);
		RETURN(ERR_PTR(-ENOMEM));
	}
	memcpy(car->car_hai, hai, hai->hai_len);
	mdt_cdt_init_request_tree(&car->car_progress);

	RETURN(car);
}

/**
 * Free a agent request and its sub-structures.
 *
 * \param car [IN]  Request to be freed.
 */
void mdt_cdt_free_request(struct cdt_agent_req *car)
{
	mdt_cdt_free_request_tree(&car->car_progress);
	OBD_FREE(car->car_hai, car->car_hai->hai_len);
	OBD_SLAB_FREE_PTR(car, mdt_hsm_car_kmem);
}

/**
 * inc refcount of a request
 * \param car [IN] request
 */
void mdt_cdt_get_request(struct cdt_agent_req *car)
{
	atomic_inc(&car->car_refcount);
}

/**
 * dec refcount of a request
 * free if no more refcount
 * \param car [IN] request
 */
void mdt_cdt_put_request(struct cdt_agent_req *car)
{
	LASSERT(atomic_read(&car->car_refcount) > 0);
	if (atomic_dec_and_test(&car->car_refcount))
		mdt_cdt_free_request(car);
}

/**
 * find request in the list by cookie or by fid
 * lock cdt_request_lock needs to be hold by caller
 * \param cdt [IN] coordinator
 * \param cookie [IN] request cookie
 * \param fid [IN] fid
 * \retval request pointer or NULL if not found
 */
static struct cdt_agent_req *cdt_find_request_nolock(struct coordinator *cdt,
						     __u64 cookie,
						     const struct lu_fid *fid)
{
	struct cdt_agent_req *car;
	struct cdt_agent_req *found = NULL;
	ENTRY;

	list_for_each_entry(car, &cdt->cdt_requests, car_request_list) {
		if (car->car_hai->hai_cookie == cookie ||
		    (fid != NULL && lu_fid_eq(fid, &car->car_hai->hai_fid))) {
			mdt_cdt_get_request(car);
			found = car;
			break;
		}
	}

	RETURN(found);
}

/**
 * add a request to the list
 * \param cdt [IN] coordinator
 * \param car [IN] request
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_cdt_add_request(struct coordinator *cdt, struct cdt_agent_req *new_car)
{
	struct cdt_agent_req	*car;
	ENTRY;

	/* cancel requests are not kept in memory */
	LASSERT(new_car->car_hai->hai_action != HSMA_CANCEL);

	down_write(&cdt->cdt_request_lock);
	car = cdt_find_request_nolock(cdt, new_car->car_hai->hai_cookie, NULL);
	if (car != NULL) {
		mdt_cdt_put_request(car);
		up_write(&cdt->cdt_request_lock);
		RETURN(-EEXIST);
	}

	list_add_tail(&new_car->car_request_list, &cdt->cdt_requests);
	up_write(&cdt->cdt_request_lock);

	mdt_hsm_agent_update_statistics(cdt, 0, 0, 1, &new_car->car_uuid);

	atomic_inc(&cdt->cdt_request_count);

	RETURN(0);
}

/**
 * find request in the list by cookie or by fid
 * \param cdt [IN] coordinator
 * \param cookie [IN] request cookie
 * \param fid [IN] fid
 * \retval request pointer or NULL if not found
 */
struct cdt_agent_req *mdt_cdt_find_request(struct coordinator *cdt,
					   const __u64 cookie,
					   const struct lu_fid *fid)
{
	struct cdt_agent_req	*car;
	ENTRY;

	down_read(&cdt->cdt_request_lock);
	car = cdt_find_request_nolock(cdt, cookie, fid);
	up_read(&cdt->cdt_request_lock);

	RETURN(car);
}

/**
 * remove request from the list
 * \param cdt [IN] coordinator
 * \param cookie [IN] request cookie
 * \retval request pointer
 */
int mdt_cdt_remove_request(struct coordinator *cdt, __u64 cookie)
{
	struct cdt_agent_req *car;
	ENTRY;

	down_write(&cdt->cdt_request_lock);
	car = cdt_find_request_nolock(cdt, cookie, NULL);
	if (car != NULL) {
		list_del(&car->car_request_list);
		up_write(&cdt->cdt_request_lock);

		/* reference from cdt_requests list */
		mdt_cdt_put_request(car);

		/* reference from cdt_find_request_nolock() */
		mdt_cdt_put_request(car);

		LASSERT(atomic_read(&cdt->cdt_request_count) >= 1);
		atomic_dec(&cdt->cdt_request_count);

		RETURN(0);
	}
	up_write(&cdt->cdt_request_lock);

	RETURN(-ENOENT);
}

/**
 * update a request in the list
 * on success, add a ref to the request returned
 * \param cdt [IN] coordinator
 * \param pgs [IN] progression (cookie + extent + err)
 * \retval request pointer
 * \retval -ve failure
 */
struct cdt_agent_req *mdt_cdt_update_request(struct coordinator *cdt,
					  const struct hsm_progress_kernel *pgs)
{
	struct cdt_agent_req	*car;
	int			 rc;
	ENTRY;

	car = mdt_cdt_find_request(cdt, pgs->hpk_cookie, NULL);
	if (car == NULL)
		RETURN(ERR_PTR(-ENOENT));

	car->car_req_update = cfs_time_current_sec();

	/* update progress done by copy tool */
	if (pgs->hpk_errval == 0 && pgs->hpk_extent.length != 0) {
		rc = hsm_update_work(&car->car_progress, &pgs->hpk_extent);
		if (rc) {
			mdt_cdt_put_request(car);
			RETURN(ERR_PTR(rc));
		}
	}

	if (pgs->hpk_flags & HP_FLAG_COMPLETED) {
		if (pgs->hpk_errval != 0)
			mdt_hsm_agent_update_statistics(cdt, 0, 1, 0,
							&car->car_uuid);
		else
			mdt_hsm_agent_update_statistics(cdt, 1, 0, 0,
							&car->car_uuid);
	}
	RETURN(car);
}

/**
 * seq_file method called to start access to /proc file
 */
static void *mdt_hsm_active_requests_proc_start(struct seq_file *s, loff_t *p)
{
	struct mdt_device	*mdt = s->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct list_head	*pos;
	loff_t			 i;
	ENTRY;

	down_read(&cdt->cdt_request_lock);

	if (list_empty(&cdt->cdt_requests))
		RETURN(NULL);

	if (*p == 0)
		RETURN(SEQ_START_TOKEN);

	i = 0;
	list_for_each(pos, &cdt->cdt_requests) {
		i++;
		if (i >= *p)
			RETURN(pos);
	}
	RETURN(NULL);
}

/**
 * seq_file method called to get next item
 * just returns NULL at eof
 */
static void *mdt_hsm_active_requests_proc_next(struct seq_file *s, void *v,
					       loff_t *p)
{
	struct mdt_device	*mdt = s->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	struct list_head	*pos = v;
	ENTRY;

	if (pos == SEQ_START_TOKEN)
		pos = cdt->cdt_requests.next;
	else
		pos = pos->next;

	(*p)++;
	if (pos != &cdt->cdt_requests)
		RETURN(pos);
	else
		RETURN(NULL);
}

/**
 * display request data
 */
static int mdt_hsm_active_requests_proc_show(struct seq_file *s, void *v)
{
	struct list_head	*pos = v;
	struct cdt_agent_req	*car;
	char			 buf[12];
	__u64			 data_moved;
	ENTRY;

	if (pos == SEQ_START_TOKEN)
		RETURN(0);

	car = list_entry(pos, struct cdt_agent_req, car_request_list);
	mdt_cdt_get_work_done(car, &data_moved);

	seq_printf(s, "fid="DFID" dfid="DFID
		   " compound/cookie="LPX64"/"LPX64
		   " action=%s archive#=%d flags="LPX64
		   " extent="LPX64"-"LPX64" gid="LPX64
		   " data=[%s] canceled=%d uuid=%s done="LPU64"\n",
		   PFID(&car->car_hai->hai_fid),
		   PFID(&car->car_hai->hai_dfid),
		   car->car_compound_id, car->car_hai->hai_cookie,
		   hsm_copytool_action2name(car->car_hai->hai_action),
		   car->car_archive_id, car->car_flags,
		   car->car_hai->hai_extent.offset,
		   car->car_hai->hai_extent.length,
		   car->car_hai->hai_gid,
		   hai_dump_data_field(car->car_hai, buf, sizeof(buf)),
		   car->car_canceled, obd_uuid2str(&car->car_uuid),
		   data_moved);
	RETURN(0);
}

/**
 * seq_file method called to stop access to /proc file
 */
static void mdt_hsm_active_requests_proc_stop(struct seq_file *s, void *v)
{
	struct mdt_device	*mdt = s->private;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	ENTRY;

	up_read(&cdt->cdt_request_lock);

	EXIT;
}

/* hsm agent list proc functions */
static const struct seq_operations mdt_hsm_active_requests_proc_ops = {
	.start		= mdt_hsm_active_requests_proc_start,
	.next		= mdt_hsm_active_requests_proc_next,
	.show		= mdt_hsm_active_requests_proc_show,
	.stop		= mdt_hsm_active_requests_proc_stop,
};

/**
 * public function called at open of /proc file to get
 * list of agents
 */
static int lprocfs_open_hsm_active_requests(struct inode *inode,
					    struct file *file)
{
	struct seq_file	*s;
	int		 rc;
	ENTRY;

	rc = seq_open(file, &mdt_hsm_active_requests_proc_ops);
	if (rc) {
		RETURN(rc);
	}
	s = file->private_data;
	s->private = PDE_DATA(inode);

	RETURN(rc);
}

/* methods to access hsm request list */
const struct file_operations mdt_hsm_active_requests_fops = {
	.owner		= THIS_MODULE,
	.open		= lprocfs_open_hsm_active_requests,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= lprocfs_seq_release,
};

