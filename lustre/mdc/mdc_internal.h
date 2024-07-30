/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _MDC_INTERNAL_H
#define _MDC_INTERNAL_H

#include <lustre_mdc.h>

int mdc_tunables_init(struct obd_device *obd);

void mdc_pack_body(struct req_capsule *pill, const struct lu_fid *fid,
		   u64 valid, size_t ea_size, u32 suppgid, u32 flags);
void mdc_swap_layouts_pack(struct req_capsule *pill,
			   struct md_op_data *op_data);
void mdc_readdir_pack(struct req_capsule *pill, __u64 pgoff, size_t size,
		      const struct lu_fid *fid);
void mdc_getattr_pack(struct req_capsule *pill, __u64 valid, __u32 flags,
		      struct md_op_data *data, size_t ea_size);
void mdc_setattr_pack(struct req_capsule *pill, struct md_op_data *op_data,
		      void *ea, size_t ealen);
void mdc_create_pack(struct req_capsule *pill, struct md_op_data *op_data,
		     const void *data, size_t datalen, umode_t mode,
		     uid_t uid, gid_t gid, kernel_cap_t cap_effective, u64 rdev,
		     struct sptlrpc_sepol *sepol);
void mdc_open_pack(struct req_capsule *pill, struct md_op_data *op_data,
		   umode_t mode, __u64 rdev, __u64 flags, const void *lmm,
		   size_t lmmlen, struct sptlrpc_sepol *sepol);
void mdc_file_secctx_pack(struct req_capsule *pill,
			  const char *secctx_name,
			  const void *secctx, size_t secctx_size);
void mdc_file_encctx_pack(struct req_capsule *pill,
			  const void *encctx, size_t encctx_size);
void mdc_file_sepol_pack(struct req_capsule *pill, struct sptlrpc_sepol *p);

void mdc_unlink_pack(struct req_capsule *pill, struct md_op_data *op_data,
		     struct sptlrpc_sepol *sepol);
void mdc_link_pack(struct req_capsule *pill, struct md_op_data *op_data,
		   struct sptlrpc_sepol *sepol);
void mdc_rename_pack(struct req_capsule *pill, struct md_op_data *op_data,
		     const char *old, size_t oldlen,
		     const char *new, size_t newlen,
		     struct sptlrpc_sepol *sepol);
void mdc_migrate_pack(struct req_capsule *pill, struct md_op_data *op_data,
			const char *name, size_t namelen);
void mdc_close_pack(struct req_capsule *pill, struct md_op_data *op_data);

/* mdc/mdc_locks.c */
int mdc_set_lock_data(struct obd_export *exp,
		      const struct lustre_handle *lockh,
		      void *data, __u64 *bits);

int mdc_null_inode(struct obd_export *exp, const struct lu_fid *fid);

int mdc_intent_lock(struct obd_export *exp,
		    struct md_op_data *op_data,
		    struct lookup_intent *it,
		    struct ptlrpc_request **reqp,
		    ldlm_blocking_callback cb_blocking,
		    __u64 extra_lock_flags);

int mdc_enqueue(struct obd_export *exp, struct ldlm_enqueue_info *einfo,
		const union ldlm_policy_data *policy,
		struct md_op_data *op_data,
		struct lustre_handle *lockh, __u64 extra_lock_flags);
int mdc_resource_get_unused_res(struct obd_export *exp,
				struct ldlm_res_id *res_id,
				struct list_head *cancels,
				enum ldlm_mode mode, __u64 bits);
int mdc_resource_get_unused(struct obd_export *exp, const struct lu_fid *fid,
			    struct list_head *cancels, enum ldlm_mode mode,
                            __u64 bits);
/* mdc/mdc_request.c */
int mdc_fid_alloc(const struct lu_env *env, struct obd_export *exp,
		  struct lu_fid *fid, struct md_op_data *op_data);
int mdc_setup(struct obd_device *obd, struct lustre_cfg *cfg);

struct obd_client_handle;

int mdc_set_open_replay_data(struct obd_export *exp,
			     struct obd_client_handle *och,
			     struct lookup_intent *it);
int mdc_save_lmm(struct ptlrpc_request *req, void *data, u32 size);

void mdc_commit_open(struct ptlrpc_request *req);
void mdc_replay_open(struct ptlrpc_request *req);

int mdc_create(struct obd_export *exp, struct md_op_data *op_data,
		const void *data, size_t datalen,
		umode_t mode, uid_t uid, gid_t gid,
		kernel_cap_t capability, __u64 rdev,
		struct ptlrpc_request **request);
int mdc_link(struct obd_export *exp, struct md_op_data *op_data,
             struct ptlrpc_request **request);
int mdc_rename(struct obd_export *exp, struct md_op_data *op_data,
		const char *old, size_t oldlen, const char *new, size_t newlen,
		struct ptlrpc_request **request);
int mdc_setattr(struct obd_export *exp, struct md_op_data *op_data,
		void *ea, size_t ealen, struct ptlrpc_request **request);
int mdc_unlink(struct obd_export *exp, struct md_op_data *op_data,
	       struct ptlrpc_request **request);
int mdc_file_resync(struct obd_export *exp, struct md_op_data *data);
int mdc_cancel_unused(struct obd_export *exp, const struct lu_fid *fid,
		      union ldlm_policy_data *policy, enum ldlm_mode mode,
		      enum ldlm_cancel_flags flags, void *opaque);

int mdc_revalidate_lock(struct obd_export *exp, struct lookup_intent *it,
                        struct lu_fid *fid, __u64 *bits);

int mdc_intent_getattr_async(struct obd_export *exp, struct md_op_item *item);

int mdc_batch_add(struct obd_export *exp, struct lu_batch *bh,
		  struct md_op_item *item);

enum ldlm_mode mdc_lock_match(struct obd_export *exp, __u64 flags,
			      const struct lu_fid *fid, enum ldlm_type type,
			      union ldlm_policy_data *policy,
			      enum ldlm_mode mode, struct lustre_handle *lockh);


#define MDC_CHANGELOG_DEV_COUNT LMV_MAX_STRIPE_COUNT
#define MDC_CHANGELOG_DEV_NAME	"changelog"
extern struct class *mdc_changelog_class;
extern dev_t mdc_changelog_dev;
extern struct idr mdc_changelog_minor_idr;

int mdc_changelog_cdev_init(struct obd_device *obd);

void mdc_changelog_cdev_finish(struct obd_device *obd);

static inline int mdc_prep_elc_req(struct obd_export *exp,
				   struct ptlrpc_request *req, int opc,
				   struct list_head *cancels, int count)
{
	return ldlm_prep_elc_req(exp, req, LUSTRE_MDS_VERSION, opc, 0, cancels,
				 count);
}

#ifdef CONFIG_LUSTRE_FS_POSIX_ACL
int mdc_unpack_acl(struct req_capsule *pill, struct lustre_md *md);
#else
static inline
int mdc_unpack_acl(struct req_capsule *pill, struct lustre_md *md)
{
	return 0;
}
#endif

static inline void mdc_body2lvb(struct mdt_body *body, struct ost_lvb *lvb)
{
	LASSERT(body->mbo_valid & OBD_MD_DOM_SIZE);
	lvb->lvb_mtime = body->mbo_mtime;
	lvb->lvb_atime = body->mbo_atime;
	lvb->lvb_ctime = body->mbo_ctime;
	lvb->lvb_blocks = body->mbo_dom_blocks;
	lvb->lvb_size = body->mbo_dom_size;
}

static inline unsigned long hash_x_index(__u64 hash, int hash64)
{
	if (BITS_PER_LONG == 32 && hash64)
		hash >>= 32;
	/* save hash 0 with hash 1 */
	return ~0UL - (hash + !hash);
}

/* mdc_dev.c */
extern struct lu_device_type mdc_device_type;
int mdc_ldlm_blocking_ast(struct ldlm_lock *dlmlock,
			  struct ldlm_lock_desc *new, void *data, int flag);
int mdc_ldlm_glimpse_ast(struct ldlm_lock *dlmlock, void *data);
int mdc_fill_lvb(struct req_capsule *pill, struct ost_lvb *lvb);

int mdc_finish_enqueue(struct obd_export *exp,
		       struct req_capsule *pill,
		       struct ldlm_enqueue_info *einfo,
		       struct lookup_intent *it,
		       struct lustre_handle *lockh, int rc);

/* the minimum inline repsize should be PAGE_SIZE at least */
#define MDC_DOM_DEF_INLINE_REPSIZE max(8192UL, PAGE_SIZE)
#define MDC_DOM_MAX_INLINE_REPSIZE XATTR_SIZE_MAX

#endif
