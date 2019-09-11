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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef OSC_INTERNAL_H
#define OSC_INTERNAL_H

#define OAP_MAGIC 8675309

#include <libcfs/linux/linux-mem.h>
#include <lustre_osc.h>

extern atomic_t osc_pool_req_count;
extern unsigned int osc_reqpool_maxreqcount;
extern struct ptlrpc_request_pool *osc_rq_pool;

int osc_shrink_grant_to_target(struct client_obd *cli, __u64 target_bytes);
void osc_update_next_shrink(struct client_obd *cli);
int lru_queue_work(const struct lu_env *env, void *data);
int osc_extent_finish(const struct lu_env *env, struct osc_extent *ext,
		      int sent, int rc);
int osc_extent_release(const struct lu_env *env, struct osc_extent *ext);
int osc_lock_discard_pages(const struct lu_env *env, struct osc_object *osc,
			   pgoff_t start, pgoff_t end, bool discard);

extern struct ptlrpc_request_set *PTLRPCD_SET;

void osc_lock_lvb_update(const struct lu_env *env,
			 struct osc_object *osc,
			 struct ldlm_lock *dlmlock,
			 struct ost_lvb *lvb);

int osc_enqueue_base(struct obd_export *exp, struct ldlm_res_id *res_id,
		     __u64 *flags, union ldlm_policy_data *policy,
		     struct ost_lvb *lvb, osc_enqueue_upcall_f upcall,
		     void *cookie, struct ldlm_enqueue_info *einfo,
		     struct ptlrpc_request_set *rqset, int async,
		     bool speculative);

int osc_match_base(const struct lu_env *env, struct obd_export *exp,
		   struct ldlm_res_id *res_id, enum ldlm_type type,
		   union ldlm_policy_data *policy, enum ldlm_mode mode,
		   __u64 *flags, struct osc_object *obj,
		   struct lustre_handle *lockh, int unref);

int osc_setattr_async(struct obd_export *exp, struct obdo *oa,
		      obd_enqueue_update_f upcall, void *cookie,
		      struct ptlrpc_request_set *rqset);
int osc_sync_base(struct osc_object *obj, struct obdo *oa,
		  obd_enqueue_update_f upcall, void *cookie,
		  struct ptlrpc_request_set *rqset);
int osc_ladvise_base(struct obd_export *exp, struct obdo *oa,
		     struct ladvise_hdr *ladvise_hdr,
		     obd_enqueue_update_f upcall, void *cookie,
		     struct ptlrpc_request_set *rqset);
int osc_process_config_base(struct obd_device *obd, struct lustre_cfg *cfg);
int osc_build_rpc(const struct lu_env *env, struct client_obd *cli,
		  struct list_head *ext_list, int cmd);
unsigned long osc_lru_reserve(struct client_obd *cli, unsigned long npages);
void osc_lru_unreserve(struct client_obd *cli, unsigned long npages);

extern struct lu_kmem_descr osc_caches[];

unsigned long osc_ldlm_weigh_ast(struct ldlm_lock *dlmlock);

int osc_cleanup(struct obd_device *obd);
int osc_setup(struct obd_device *obd, struct lustre_cfg *lcfg);

int osc_tunables_init(struct obd_device *obd);

extern struct lu_device_type osc_device_type;

static inline struct cl_io *osc_env_thread_io(const struct lu_env *env)
{
	struct cl_io *io = &osc_env_info(env)->oti_io;

	memset(io, 0, sizeof(*io));
	return io;
}

static inline int osc_is_object(const struct lu_object *obj)
{
	return obj->lo_dev->ld_type == &osc_device_type;
}

static inline struct osc_lock *osc_lock_at(const struct cl_lock *lock)
{
	return cl2osc_lock(cl_lock_at(lock, &osc_device_type));
}

int osc_lock_init(const struct lu_env *env, struct cl_object *obj,
		  struct cl_lock *lock, const struct cl_io *io);
int osc_io_init(const struct lu_env *env, struct cl_object *obj,
		struct cl_io *io);
struct lu_object *osc_object_alloc(const struct lu_env *env,
				   const struct lu_object_header *hdr,
				   struct lu_device *dev);

static inline int osc_recoverable_error(int rc)
{
        return (rc == -EIO || rc == -EROFS || rc == -ENOMEM ||
                rc == -EAGAIN || rc == -EINPROGRESS);
}

static inline unsigned long rpcs_in_flight(struct client_obd *cli)
{
	return cli->cl_r_in_flight + cli->cl_w_in_flight;
}

static inline char *cli_name(struct client_obd *cli)
{
	return cli->cl_import->imp_obd->obd_name;
}

#ifndef min_t
#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#endif

struct osc_async_args {
	struct obd_info	*aa_oi;
};

int osc_quota_setup(struct obd_device *obd);
int osc_quota_cleanup(struct obd_device *obd);
int osc_quota_setdq(struct client_obd *cli, __u64 xid, const unsigned int qid[],
		    u64 valid, u32 flags);
int osc_quota_chkdq(struct client_obd *cli, const unsigned int qid[]);
int osc_quotactl(struct obd_device *unused, struct obd_export *exp,
                 struct obd_quotactl *oqctl);
void osc_inc_unstable_pages(struct ptlrpc_request *req);
void osc_dec_unstable_pages(struct ptlrpc_request *req);
bool osc_over_unstable_soft_limit(struct client_obd *cli);
void osc_page_touch_at(const struct lu_env *env, struct cl_object *obj,
		       pgoff_t idx, size_t to);

struct ldlm_lock *osc_obj_dlmlock_at_pgoff(const struct lu_env *env,
					   struct osc_object *obj,
					   pgoff_t index,
					   enum osc_dap_flags flags);

int osc_object_invalidate(const struct lu_env *env, struct osc_object *osc);

/** osc shrink list to link all osc client obd */
extern struct list_head osc_shrink_list;
/** spin lock to protect osc_shrink_list */
extern spinlock_t osc_shrink_lock;
extern unsigned long osc_cache_shrink_count(struct shrinker *sk,
					    struct shrink_control *sc);
extern unsigned long osc_cache_shrink_scan(struct shrinker *sk,
					   struct shrink_control *sc);

static inline void osc_set_io_portal(struct ptlrpc_request *req)
{
	struct obd_import *imp = req->rq_import;

	/* Distinguish OSC from MDC here to use OST or MDS portal */
	if (OCD_HAS_FLAG(&imp->imp_connect_data, IBITS))
		req->rq_request_portal = MDS_IO_PORTAL;
	else
		req->rq_request_portal = OST_IO_PORTAL;
}
#endif /* OSC_INTERNAL_H */
