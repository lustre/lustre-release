// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE
#include <lustre_dlm.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/user_namespace.h>
#include <linux/capability.h>
#include <linux/uidgid.h>
#include <linux/falloc.h>
#include <linux/ktime.h>
#ifdef HAVE_LINUX_FILELOCK_HEADER
#include <linux/filelock.h>
#endif

#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_swab.h>
#include <libcfs/linux/linux-misc.h>

#include "cl_object.h"
#include "llite_internal.h"
#include "vvp_internal.h"

struct split_param {
	struct inode	*sp_inode;
	__u16		sp_mirror_id;
};

struct pcc_param {
	__u64	pa_data_version;
	__u32	pa_archive_id;
	__u32	pa_layout_gen;
};

struct swap_layouts_param {
	struct inode *slp_inode;
	__u64         slp_dv1;
	__u64         slp_dv2;
};

static int
ll_put_grouplock(struct inode *inode, struct file *file, unsigned long arg);

static int ll_lease_close(struct obd_client_handle *och, struct inode *inode,
			  bool *lease_broken);

static struct ll_file_data *ll_file_data_get(void)
{
	struct ll_file_data *lfd;

	OBD_SLAB_ALLOC_PTR_GFP(lfd, ll_file_data_slab, GFP_NOFS);
	if (lfd == NULL)
		return NULL;

	lfd->fd_write_failed = false;
	pcc_file_init(&lfd->fd_pcc_file);

	return lfd;
}

static void ll_file_data_put(struct ll_file_data *lfd)
{
	if (lfd != NULL)
		OBD_SLAB_FREE_PTR(lfd, ll_file_data_slab);
}

/* Packs all the attributes into @op_data for the CLOSE rpc.  */
static void ll_prepare_close(struct inode *inode, struct md_op_data *op_data,
			     struct obd_client_handle *och)
{
	ENTRY;
	ll_prep_md_op_data(op_data, inode, NULL, NULL,
			   0, 0, LUSTRE_OPC_ANY, NULL);

	op_data->op_attr.ia_mode = inode->i_mode;
	op_data->op_attr.ia_atime = inode_get_atime(inode);
	op_data->op_attr.ia_mtime = inode_get_mtime(inode);
	op_data->op_attr.ia_ctime = inode_get_ctime(inode);
	/* In case of encrypted file without the key, visible size was rounded
	 * up to next LUSTRE_ENCRYPTION_UNIT_SIZE, and clear text size was
	 * stored into lli_lazysize in ll_merge_attr(), so set proper file size
	 * now that we are closing.
	 */
	if (IS_ENCRYPTED(inode) && !ll_has_encryption_key(inode) &&
	    ll_i2info(inode)->lli_attr_valid & OBD_MD_FLLAZYSIZE) {
		op_data->op_attr.ia_size = ll_i2info(inode)->lli_lazysize;
		if (IS_PCCCOPY(inode)) {
			inode->i_flags &= ~S_PCCCOPY;
			i_size_write(inode, op_data->op_attr.ia_size);
		}
	} else {
		op_data->op_attr.ia_size = i_size_read(inode);
	}
	op_data->op_attr.ia_valid |= (ATTR_MODE | ATTR_ATIME | ATTR_ATIME_SET |
				      ATTR_MTIME | ATTR_MTIME_SET |
				      ATTR_CTIME);
	op_data->op_xvalid |= OP_XVALID_CTIME_SET;
	op_data->op_attr_blocks = inode->i_blocks;
	op_data->op_attr_flags = ll_inode2ext_flags(inode);
	op_data->op_open_handle = och->och_open_handle;

	if (och->och_flags & MDS_FMODE_WRITE &&
	    test_and_clear_bit(LLIF_DATA_MODIFIED,
			       &ll_i2info(inode)->lli_flags))
		/* For HSM: if inode data has been modified, pack it so that
		 * MDT can set data dirty flag in the archive.
		 */
		op_data->op_bias |= MDS_DATA_MODIFIED;

	EXIT;
}

/*
 * Perform a close, possibly with a bias.
 * The meaning of "data" depends on the value of "bias".
 *
 * If \a bias is MDS_HSM_RELEASE then \a data is a pointer to the data version.
 * If \a bias is MDS_CLOSE_LAYOUT_SWAP then \a data is a pointer to a
 * struct swap_layouts_param containing the inode to swap with and the old and
 * new dataversion
 */
static int ll_close_inode_openhandle(struct inode *inode,
				     struct obd_client_handle *och,
				     enum mds_op_bias bias, void *data)
{
	struct obd_export *md_exp = ll_i2mdexp(inode);
	const struct ll_inode_info *lli = ll_i2info(inode);
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	int rc;

	ENTRY;
	if (class_exp2obd(md_exp) == NULL) {
		rc = 0;
		CERROR("%s: invalid MDC connection handle closing "DFID": rc = %d\n",
		       ll_i2sbi(inode)->ll_fsname, PFID(&lli->lli_fid), rc);
		GOTO(out, rc);
	}

	OBD_ALLOC_PTR(op_data);
	/* We leak openhandle and request here on error, but not much to be
	 * done in OOM case since app won't retry close on error either.
	 */
	if (op_data == NULL)
		GOTO(out, rc = -ENOMEM);

	ll_prepare_close(inode, op_data, och);
	switch (bias) {
	case MDS_CLOSE_LAYOUT_MERGE:
		/* merge blocks from the victim inode */
		op_data->op_attr_blocks += ((struct inode *)data)->i_blocks;
		op_data->op_attr.ia_valid |= ATTR_SIZE;
		op_data->op_xvalid |= OP_XVALID_BLOCKS;
		fallthrough;
	case MDS_CLOSE_LAYOUT_SPLIT: {
		struct split_param *sp = data;

		LASSERT(data != NULL);
		op_data->op_bias |= bias;
		op_data->op_data_version = 0;
		op_data->op_lease_handle = och->och_lease_handle;
		if (bias == MDS_CLOSE_LAYOUT_SPLIT) {
			op_data->op_fid2 = *ll_inode2fid(sp->sp_inode);
			op_data->op_mirror_id = sp->sp_mirror_id;
		} else { /* MDS_CLOSE_LAYOUT_MERGE */
			op_data->op_fid2 = *ll_inode2fid(data);
		}
		break;
	}
	case MDS_CLOSE_LAYOUT_SWAP: {
		struct swap_layouts_param *slp = data;

		LASSERT(data != NULL);
		op_data->op_bias |= (bias | MDS_CLOSE_LAYOUT_SWAP_HSM);
		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_fid2 = *ll_inode2fid(slp->slp_inode);
		op_data->op_data_version = slp->slp_dv1;
		op_data->op_data_version2 = slp->slp_dv2;
		break;
	}

	case MDS_CLOSE_RESYNC_DONE: {
		struct ll_ioc_lease *ioc = data;

		LASSERT(data != NULL);
		op_data->op_attr_blocks +=
			ioc->lil_count * op_data->op_attr_blocks;
		op_data->op_attr.ia_valid |= ATTR_SIZE;
		op_data->op_xvalid |= OP_XVALID_BLOCKS;
		op_data->op_bias |= MDS_CLOSE_RESYNC_DONE;

		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_data = &ioc->lil_ids[0];
		op_data->op_data_size =
			ioc->lil_count * sizeof(ioc->lil_ids[0]);
		break;
	}

	case MDS_PCC_ATTACH: {
		struct pcc_param *param = data;

		LASSERT(data != NULL);
		op_data->op_bias |= MDS_HSM_RELEASE | MDS_PCC_ATTACH;
		op_data->op_archive_id = param->pa_archive_id;
		op_data->op_data_version = param->pa_data_version;
		op_data->op_lease_handle = och->och_lease_handle;
		break;
	}

	case MDS_HSM_RELEASE:
		LASSERT(data != NULL);
		op_data->op_bias |= MDS_HSM_RELEASE;
		op_data->op_data_version = *(__u64 *)data;
		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_attr.ia_valid |= ATTR_SIZE;
		op_data->op_xvalid |= OP_XVALID_BLOCKS;
		break;

	default:
		LASSERT(data == NULL);
		break;
	}

	if (!(op_data->op_attr.ia_valid & ATTR_SIZE))
		op_data->op_xvalid |= OP_XVALID_LAZYSIZE;
	if (!(op_data->op_xvalid & OP_XVALID_BLOCKS))
		op_data->op_xvalid |= OP_XVALID_LAZYBLOCKS;

	rc = md_close(md_exp, op_data, och->och_mod, &req);
	if (rc != 0 && rc != -EINTR)
		CERROR("%s: inode "DFID" mdc close failed: rc = %d\n",
		       md_exp->exp_obd->obd_name, PFID(&lli->lli_fid), rc);

	if (rc == 0 && op_data->op_bias & bias) {
		struct mdt_body *body;

		body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
		if (!(body->mbo_valid & OBD_MD_CLOSE_INTENT_EXECED))
			rc = -EBUSY;

		if (bias & MDS_PCC_ATTACH) {
			struct pcc_param *param = data;

			param->pa_layout_gen = body->mbo_layout_gen;
		}
	}

	ll_finish_md_op_data(op_data);
	EXIT;
out:

	md_clear_open_replay_data(md_exp, och);
	och->och_open_handle.cookie = DEAD_HANDLE_MAGIC;
	OBD_FREE_PTR(och);

	ptlrpc_req_put(req);	/* This is close request */
	return rc;
}

/**
 * ll_md_real_close() - called when file is closed. Called from ll_file_release
 *
 * @inode: inode which is getting closed
 * @fd_open_mode: MDS flags passed from client
 *
 * Return:
 * * 0 on success
 * * <0 on error
 */
int ll_md_real_close(struct inode *inode, enum mds_open_flags fd_open_mode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct obd_client_handle **och_p;
	struct obd_client_handle *och;
	__u64 *och_usecount;
	int rc = 0;

	ENTRY;
	if (fd_open_mode & MDS_FMODE_WRITE) {
		och_p = &lli->lli_mds_write_och;
		och_usecount = &lli->lli_open_fd_write_count;
	} else if (fd_open_mode & MDS_FMODE_EXEC) {
		och_p = &lli->lli_mds_exec_och;
		och_usecount = &lli->lli_open_fd_exec_count;
	} else {
		LASSERT(fd_open_mode & MDS_FMODE_READ);
		och_p = &lli->lli_mds_read_och;
		och_usecount = &lli->lli_open_fd_read_count;
	}

	mutex_lock(&lli->lli_och_mutex);
	if (*och_usecount > 0) {
		/* There are still users of this handle, so skip freeing it */
		mutex_unlock(&lli->lli_och_mutex);
		RETURN(0);
	}

	och = *och_p;
	*och_p = NULL;
	mutex_unlock(&lli->lli_och_mutex);

	if (och != NULL) {
		/* There might be race and this handle may already be closed. */
		rc = ll_close_inode_openhandle(inode, och, 0, NULL);
	}

	RETURN(rc);
}

static int ll_md_close(struct inode *inode, struct file *file)
{
	union ldlm_policy_data policy = {
		.l_inodebits	= { MDS_INODELOCK_OPEN },
	};
	__u64 flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_TEST_LOCK;
	struct ll_file_data *lfd = file->private_data;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lustre_handle lockh;
	enum ldlm_mode lockmode;
	int rc = 0;

	ENTRY;
	/* clear group lock, if present */
	if (unlikely(lfd->lfd_file_flags & LL_FILE_GROUP_LOCKED))
		ll_put_grouplock(inode, file, lfd->fd_grouplock.lg_gid);

	mutex_lock(&lli->lli_och_mutex);
	if (lfd->fd_lease_och != NULL) {
		bool lease_broken;
		struct obd_client_handle *lease_och;

		lease_och = lfd->fd_lease_och;
		lfd->fd_lease_och = NULL;
		mutex_unlock(&lli->lli_och_mutex);

		/* Usually the lease is not released when the
		 * application crashed, we need to release here.
		 */
		rc = ll_lease_close(lease_och, inode, &lease_broken);

		mutex_lock(&lli->lli_och_mutex);

		CDEBUG_LIMIT(rc ? D_ERROR : D_INODE,
			     "Clean up lease "DFID" %d/%d\n",
			     PFID(&lli->lli_fid), rc, lease_broken);
	}

	if (lfd->fd_och != NULL) {
		struct obd_client_handle *och;

		och = lfd->fd_och;
		lfd->fd_och = NULL;
		mutex_unlock(&lli->lli_och_mutex);

		rc = ll_close_inode_openhandle(inode, och, 0, NULL);
		GOTO(out, rc);
	}

	/* Let's see if we have good enough OPEN lock on the file and if we can
	 * skip talking to MDS
	 */
	if (lfd->fd_open_mode & MDS_FMODE_WRITE) {
		lockmode = LCK_CW;
		LASSERT(lli->lli_open_fd_write_count);
		lli->lli_open_fd_write_count--;
	} else if (lfd->fd_open_mode & MDS_FMODE_EXEC) {
		lockmode = LCK_PR;
		LASSERT(lli->lli_open_fd_exec_count);
		lli->lli_open_fd_exec_count--;
	} else {
		lockmode = LCK_CR;
		LASSERT(lli->lli_open_fd_read_count);
		lli->lli_open_fd_read_count--;
	}
	mutex_unlock(&lli->lli_och_mutex);

	/* LU-4398: do not cache write open lock if the file has exec bit */
	if ((lockmode == LCK_CW && inode->i_mode & 0111) ||
	    !md_lock_match(ll_i2mdexp(inode), flags, ll_inode2fid(inode),
			   LDLM_IBITS, &policy, lockmode, 0, &lockh))
		rc = ll_md_real_close(inode, lfd->fd_open_mode);

out:
	file->private_data = NULL;
	ll_file_data_put(lfd);

	RETURN(rc);
}

/* While this returns an error code, fput() the caller does not, so we need
 * to make every effort to clean up all of our state here.  Also, applications
 * rarely check close errors and even if an error is returned they will not
 * re-try the close call.
 */
int ll_file_release(struct inode *inode, struct file *file)
{
	struct ll_file_data *lfd;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ll_inode_info *lli = ll_i2info(inode);
	ktime_t kstart = ktime_get();
	int rc;

	ENTRY;
	CDEBUG(D_VFSTRACE|D_IOTRACE,
	       "START file "DNAME":"DFID"(%p), flags %o\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       inode, file->f_flags);

	lfd = file->private_data;
	LASSERT(lfd != NULL);

	/* The last ref on @file, maybe not the the owner pid of statahead,
	 * because parent and child process can share the same file handle.
	 */
	if (S_ISDIR(inode->i_mode) &&
	    (lli->lli_opendir_key == lfd || lfd->fd_sai))
		ll_deauthorize_statahead(inode, lfd);

	if (is_root_inode(inode)) {
		file->private_data = NULL;
		ll_file_data_put(lfd);
		GOTO(out, rc = 0);
	}

	pcc_file_release(inode, file);

	if (!S_ISDIR(inode->i_mode)) {
		if (lli->lli_clob != NULL)
			lov_read_and_clear_async_rc(lli->lli_clob);
		lli->lli_async_rc = 0;
	}

	lli->lli_close_fd_time = ktime_get();

	rc = ll_md_close(inode, file);

	if (CFS_FAIL_TIMEOUT_MS(OBD_FAIL_PTLRPC_DUMP_LOG, cfs_fail_val))
		libcfs_debug_dumplog();

out:
	if (!rc && !is_root_inode(inode))
		ll_stats_ops_tally(sbi, LPROC_LL_RELEASE,
				   ktime_us_delta(ktime_get(), kstart));
	CDEBUG(D_IOTRACE,
	       "COMPLETED file "DNAME":"DFID"(%p), flags %o, rc = %d\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       inode, file->f_flags, rc);

	RETURN(rc);
}

static inline int ll_dom_readpage(void *data, struct page *page)
{
	/* since ll_dom_readpage is a page cache helper, it is safe to assume
	 * mapping and host pointers are set here
	 */
	struct inode *inode;
	struct niobuf_local *lnb = data;
	void *kaddr;
	int rc = 0;

	inode = page2inode(page);

	kaddr = kmap_local_page(page);
	memcpy(kaddr, lnb->lnb_data, lnb->lnb_len);
	if (lnb->lnb_len < PAGE_SIZE)
		memset(kaddr + lnb->lnb_len, 0,
		       PAGE_SIZE - lnb->lnb_len);
	kunmap_local(kaddr);

	if (inode && IS_ENCRYPTED(inode) && S_ISREG(inode->i_mode)) {
		if (!ll_has_encryption_key(inode)) {
			CDEBUG(D_SEC, "no enc key for "DFID"\n",
			       PFID(ll_inode2fid(inode)));
			rc = -ENOKEY;
		} else {
			unsigned int offs = 0;

			while (offs < PAGE_SIZE) {
				/* decrypt only if page is not empty */
				if (memcmp(page_address(page) + offs,
					   page_address(ZERO_PAGE(0)),
					   LUSTRE_ENCRYPTION_UNIT_SIZE) == 0)
					break;

				rc = llcrypt_decrypt_pagecache_blocks(page,
						    LUSTRE_ENCRYPTION_UNIT_SIZE,
								      offs);
				if (rc)
					break;

				offs += LUSTRE_ENCRYPTION_UNIT_SIZE;
			}
		}
	}
	if (!rc) {
		flush_dcache_page(page);
		SetPageUptodate(page);
	}
	unlock_page(page);

	return rc;
}

#ifdef HAVE_READ_CACHE_PAGE_WANTS_FILE
static inline int ll_dom_read_folio(struct file *file, struct folio *folio0)
{
	return ll_dom_readpage(file->private_data, folio_page(folio0, 0));
}
#else
#define ll_dom_read_folio	ll_dom_readpage
#endif

void ll_dom_finish_open(struct inode *inode, struct ptlrpc_request *req)
{
	struct lu_env *env;
	struct cl_io *io;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct address_space *mapping = inode->i_mapping;
	struct page *vmpage;
	struct niobuf_remote *rnb;
	struct mdt_body *body;
	char *data;
	unsigned long index, start;
	struct niobuf_local lnb;
	__u16 refcheck;
	int rc;

	ENTRY;
	if (obj == NULL)
		RETURN_EXIT;

	if (!req_capsule_field_present(&req->rq_pill, &RMF_NIOBUF_INLINE,
				       RCL_SERVER))
		RETURN_EXIT;

	rnb = req_capsule_server_get(&req->rq_pill, &RMF_NIOBUF_INLINE);
	if (rnb == NULL || rnb->rnb_len == 0)
		RETURN_EXIT;

	/* LU-11595: Server may return whole file and that is OK always or
	 * it may return just file tail and its offset must be aligned with
	 * client PAGE_SIZE to be used on that client, if server's PAGE_SIZE is
	 * smaller then offset may be not aligned and that data is just ignored.
	 */
	if (rnb->rnb_offset & ~PAGE_MASK)
		RETURN_EXIT;

	/* Server returns whole file or just file tail if it fills in reply
	 * buffer, in both cases total size should be equal to the file size.
	 */
	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	if (rnb->rnb_offset + rnb->rnb_len != body->mbo_dom_size &&
	    !(inode && IS_ENCRYPTED(inode))) {
		CERROR("%s: server returns off/len %llu/%u but size %llu\n",
		       ll_i2sbi(inode)->ll_fsname, rnb->rnb_offset,
		       rnb->rnb_len, body->mbo_dom_size);
		RETURN_EXIT;
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN_EXIT;
	io = vvp_env_new_io(env);
	io->ci_obj = obj;
	rc = cl_io_init(env, io, CIT_MISC, obj);
	if (rc)
		GOTO(out_io, rc);

	CDEBUG(D_INFO, "Get data along with open at %llu len %i, size %llu\n",
	       rnb->rnb_offset, rnb->rnb_len, body->mbo_dom_size);

	data = (char *)rnb + sizeof(*rnb);

	lnb.lnb_file_offset = rnb->rnb_offset;
	start = lnb.lnb_file_offset >> PAGE_SHIFT;
	index = 0;
	LASSERT((lnb.lnb_file_offset & ~PAGE_MASK) == 0);
	lnb.lnb_page_offset = 0;
	do {
		struct cl_page *page;

		lnb.lnb_data = data + (index << PAGE_SHIFT);
		lnb.lnb_len = rnb->rnb_len - (index << PAGE_SHIFT);
		if (lnb.lnb_len > PAGE_SIZE)
			lnb.lnb_len = PAGE_SIZE;

		vmpage = ll_read_cache_page(mapping, index + start,
					    ll_dom_read_folio, &lnb);
		if (IS_ERR(vmpage)) {
			CWARN("%s: cannot fill page %lu for "DFID" with data: rc = %li\n",
			      ll_i2sbi(inode)->ll_fsname, index + start,
			      PFID(lu_object_fid(&obj->co_lu)),
			      PTR_ERR(vmpage));
			break;
		}
		lock_page(vmpage);
		if (vmpage->mapping == NULL) {
			unlock_page(vmpage);
			put_page(vmpage);
			/* page was truncated */
			break;
		}
		/* attach VM page to CL page cache */
		page = cl_page_find(env, obj, vmpage->index, vmpage,
				    CPT_CACHEABLE);
		if (IS_ERR(page)) {
			ClearPageUptodate(vmpage);
			unlock_page(vmpage);
			put_page(vmpage);
			break;
		}
		SetPageUptodate(vmpage);
		cl_page_put(env, page);
		unlock_page(vmpage);
		put_page(vmpage);
		index++;
	} while (rnb->rnb_len > (index << PAGE_SHIFT));

out_io:
	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);

	EXIT;
}
void ll_dir_finish_open(struct inode *inode, struct ptlrpc_request *req)
{
	struct obd_export *exp = ll_i2mdexp(inode);
	void *data;
	struct page *page;
	struct lu_dirpage *dp;
	int is_hash64;
	int rc;
	unsigned long	offset;
	__u64		hash;
	unsigned int i;
	unsigned int npages;

	ENTRY;

	if (!exp_connect_open_readdir(exp))
		RETURN_EXIT;

	if (!req_capsule_field_present(&req->rq_pill, &RMF_NIOBUF_INLINE,
				       RCL_SERVER))
		RETURN_EXIT;

	data = req_capsule_server_get(&req->rq_pill, &RMF_NIOBUF_INLINE);
	if (data == NULL)
		RETURN_EXIT;

	npages = req_capsule_get_size(&req->rq_pill, &RMF_NIOBUF_INLINE,
				      RCL_SERVER);
	if (npages < sizeof(*dp))
		RETURN_EXIT;

	/* div rou*/
	npages = DIV_ROUND_UP(npages, PAGE_SIZE);
	is_hash64 = test_bit(LL_SBI_64BIT_HASH, ll_i2sbi(inode)->ll_flags);

	for (i = 0; i < npages; i++) {
		page = __page_cache_alloc(mapping_gfp_mask(inode->i_mapping));
		if (!page)
			continue;

		lock_page(page);
		SetPageUptodate(page);

		dp = kmap_local_page(page);
		memcpy(dp, data, PAGE_SIZE);
		hash = le64_to_cpu(dp->ldp_hash_start);
		kunmap_local(dp);

		offset = hash_x_index(hash, is_hash64);

		prefetchw(&page->flags);
		rc = add_to_page_cache_lru(page, inode->i_mapping, offset,
				   GFP_KERNEL);
		if (rc == 0)
			unlock_page(page);

		put_page(page);
	}
	EXIT;
}


static int ll_intent_file_open(struct dentry *de, void *lmm, ssize_t lmmsize,
				struct lookup_intent *itp)
{
	struct ll_sb_info *sbi = ll_i2sbi(de->d_inode);
	struct dentry *parent = dget_parent(de);
	char *name = NULL;
	int len = 0;
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	int rc;

	ENTRY;
	LASSERT(parent != NULL);
	LASSERT(itp->it_open_flags & MDS_OPEN_BY_FID);

	/* if server supports open-by-fid, or file name is invalid, don't pack
	 * name in open request
	 */
	if (CFS_FAIL_CHECK(OBD_FAIL_LLITE_OPEN_BY_NAME) ||
	    !(exp_connect_flags(sbi->ll_md_exp) & OBD_CONNECT_OPEN_BY_FID)) {
retry:
		len = de->d_name.len;
		name = kmalloc(len + 1, GFP_NOFS);
		if (!name)
			GOTO(out_put, rc = -ENOMEM);

		/* race here */
		spin_lock(&de->d_lock);
		if (len != de->d_name.len) {
			spin_unlock(&de->d_lock);
			kfree(name);
			goto retry;
		}
		memcpy(name, de->d_name.name, len);
		name[len] = '\0';
		spin_unlock(&de->d_lock);

		if (!lu_name_is_valid_2(name, len)) {
			kfree(name);
			GOTO(out_put, rc = -ESTALE);
		}
	}

	op_data = ll_prep_md_op_data(NULL, parent->d_inode, de->d_inode,
				     name, len, 0, LUSTRE_OPC_OPEN, NULL);
	if (IS_ERR(op_data)) {
		kfree(name);
		GOTO(out_put, rc = PTR_ERR(op_data));
	}
	op_data->op_data = lmm;
	op_data->op_data_size = lmmsize;

	if (!sbi->ll_dir_open_read && S_ISDIR(de->d_inode->i_mode))
		op_data->op_cli_flags &= ~CLI_READ_ON_OPEN;

	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_OPEN_DELAY, cfs_fail_val);

	rc = ll_intent_lock(sbi->ll_md_exp, op_data, itp, &req,
			    &ll_md_blocking_ast, 0, true);
	kfree(name);
	ll_finish_md_op_data(op_data);
	if (rc == -ESTALE) {
		/* reason for keep own exit path - don`t flood log
		 * with messages with -ESTALE errors.
		 */
		if (!it_disposition(itp, DISP_OPEN_OPEN) ||
		     it_open_error(DISP_OPEN_OPEN, itp))
			GOTO(out, rc);
		ll_release_openhandle(de, itp);
		GOTO(out, rc);
	}

	if (it_disposition(itp, DISP_LOOKUP_NEG))
		GOTO(out, rc = -ENOENT);

	if (rc != 0 || it_open_error(DISP_OPEN_OPEN, itp)) {
		rc = rc ? rc : it_open_error(DISP_OPEN_OPEN, itp);
		CDEBUG(D_VFSTRACE, "lock enqueue: err: %d\n", rc);
		GOTO(out, rc);
	}

	rc = ll_prep_inode(&de->d_inode, &req->rq_pill, NULL, itp);

	if (!rc && itp->it_lock_mode) {
		enum mds_ibits_locks bits = MDS_INODELOCK_NONE;

		/* if DoM bit returned along with LAYOUT bit then there
		 * can be read-on-open data returned.
		 */
		ll_set_lock_data(sbi->ll_md_exp, de->d_inode, itp, &bits);
		if (bits & MDS_INODELOCK_DOM && bits & MDS_INODELOCK_LAYOUT)
			ll_dom_finish_open(de->d_inode, req);
		if (bits & MDS_INODELOCK_UPDATE && S_ISDIR(de->d_inode->i_mode))
			ll_dir_finish_open(de->d_inode, req);
	}
	/* open may not fetch LOOKUP lock, update dir depth and default LMV
	 * anyway.
	 */
	if (!rc && !d_lustre_invalid(de) && S_ISDIR(de->d_inode->i_mode))
		ll_update_dir_depth_dmv(parent->d_inode, de);

out:
	ptlrpc_req_put(req);
	ll_intent_drop_lock(itp);

	/* We did open by fid, but by the time we got to the server, the object
	 * disappeared.  This is possible if the object was unlinked, but it's
	 * also possible if the object was unlinked by a rename.  In the case
	 * of an object renamed over our existing one, we can't fail this open.
	 * O_CREAT also goes through this path if we had an existing dentry,
	 * and it's obviously wrong to return ENOENT for O_CREAT.
	 *
	 * Instead let's return -ESTALE, and the VFS will retry the open with
	 * LOOKUP_REVAL, which we catch in ll_revalidate_dentry and fail to
	 * revalidate, causing a lookup.  This causes extra lookups in the case
	 * where we had a dentry in cache but the file is being unlinked and we
	 * lose the race with unlink, but this should be very rare.
	 */
	if (rc == -ENOENT)
		rc = -ESTALE;
out_put:
	dput(parent);
	RETURN(rc);
}

static int ll_och_fill(struct obd_export *md_exp, struct lookup_intent *it,
		       struct obd_client_handle *och)
{
	struct mdt_body *body;

	body = req_capsule_server_get(&it->it_request->rq_pill, &RMF_MDT_BODY);
	och->och_open_handle = body->mbo_open_handle;
	och->och_fid = body->mbo_fid1;
	och->och_lease_handle.cookie = it->it_lock_handle;
	och->och_magic = OBD_CLIENT_HANDLE_MAGIC;
	och->och_flags = it->it_open_flags;

	return md_set_open_replay_data(md_exp, och, it);
}

/**
 * ll_kernel_to_mds_open_flags() - Convert kernel flags to MDS flags (Access
 *				   mode)
 *
 * @kernel_open_flags: kernel input (struct file.f_flags)
 *
 * Returns:
 * * mds_open_flags
 */
enum mds_open_flags ll_kernel_to_mds_open_flags(unsigned int kernel_open_flags)
{
	enum mds_open_flags mds_open_flags = MDS_FMODE_CLOSED;

	if (kernel_open_flags & FMODE_READ)
		mds_open_flags |= MDS_FMODE_READ;

	if (kernel_open_flags & FMODE_WRITE)
		mds_open_flags |= MDS_FMODE_WRITE;

	if (kernel_open_flags & O_CREAT)
		mds_open_flags |= MDS_OPEN_CREAT;

	if (kernel_open_flags & O_EXCL)
		mds_open_flags |= MDS_OPEN_EXCL;

	if (kernel_open_flags & O_TRUNC)
		mds_open_flags |= MDS_OPEN_TRUNC;

	if (kernel_open_flags & O_APPEND)
		mds_open_flags |= MDS_OPEN_APPEND;

	if (kernel_open_flags & O_SYNC)
		mds_open_flags |= MDS_OPEN_SYNC;

	if (kernel_open_flags & O_DIRECTORY)
		mds_open_flags |= MDS_OPEN_DIRECTORY;

	/* FMODE_EXEC is only valid with fmode_t, use __FMODE_EXEC instead
	 * which indicates file is opened for execution with sys_execve
	 */
	if (kernel_open_flags & __FMODE_EXEC)
		mds_open_flags |= MDS_FMODE_EXECUTE;

	if (ll_lov_delay_create_is_set(kernel_open_flags))
		mds_open_flags |= O_LOV_DELAY_CREATE;

	if (kernel_open_flags & O_LARGEFILE)
		mds_open_flags |= MDS_OPEN_LARGEFILE;

	if (kernel_open_flags & O_NONBLOCK)
		mds_open_flags |= MDS_OPEN_NORESTORE;

	if (kernel_open_flags & O_NOCTTY)
		mds_open_flags |= MDS_OPEN_NOCTTY;

	if (kernel_open_flags & O_NONBLOCK)
		mds_open_flags |= MDS_OPEN_NONBLOCK;

	if (kernel_open_flags & O_NOFOLLOW)
		mds_open_flags |= MDS_OPEN_NOFOLLOW;

	if (kernel_open_flags & FASYNC)
		mds_open_flags |= MDS_OPEN_FASYNC;

	return mds_open_flags;
}

static int ll_local_open(struct file *file, struct lookup_intent *it,
			 struct ll_file_data *lfd,
			 struct obd_client_handle *och)
{
	struct inode *inode = file_inode(file);

	ENTRY;
	LASSERT(!file->private_data);

	LASSERT(lfd != NULL);

	if (och) {
		int rc;

		rc = ll_och_fill(ll_i2sbi(inode)->ll_md_exp, it, och);
		if (rc != 0)
			RETURN(rc);
	}

	file->private_data = lfd;
	ll_readahead_init(inode, &lfd->fd_ras);
	lfd->fd_open_mode = it->it_open_flags & (MDS_FMODE_READ |
						 MDS_FMODE_WRITE |
						 MDS_FMODE_EXEC);

	RETURN(0);
}

void ll_track_file_opens(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);

	/* do not skew results with delays from never-opened inodes */
	if (ktime_to_ns(lli->lli_close_fd_time))
		ll_stats_ops_tally(sbi, LPROC_LL_INODE_OPCLTM,
			   ktime_us_delta(ktime_get(), lli->lli_close_fd_time));

	if (ktime_after(ktime_get(),
			ktime_add_ms(lli->lli_close_fd_time,
				     sbi->ll_oc_max_ms))) {
		lli->lli_open_fd_count = 1;
		lli->lli_close_fd_time = ns_to_ktime(0);
	} else {
		lli->lli_open_fd_count++;
	}

	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_INODE_OCOUNT,
			   lli->lli_open_fd_count);
}

/**
 * ll_file_open() - setup and handle file open
 * @inode: inode of the file being opened
 * @file: Open file pointer in the kernel
 *
 * Open a file, and (for the very first open) create objects on the OSTs at
 * this time.  If opened with O_LOV_DELAY_CREATE, then we don't do the object
 * creation or open until ll_lov_setstripe() ioctl is called.
 *
 * If we already have the stripe MD locally then we don't request it in
 * md_open(), by passing a lmm_size = 0.
 *
 * It is up to the application to ensure no other processes open this file
 * in the O_LOV_DELAY_CREATE case, or the default striping pattern will be
 * used.  We might be able to avoid races of that sort by getting lli_open_sem
 * before returning in the O_LOV_DELAY_CREATE case and dropping it here
 * or in ll_file_release(), but I'm not sure that is desirable/necessary.
 *
 *  Return:
 * * %0: Success
 * * %-ERRNO: Failure
 */
int ll_file_open(struct inode *inode, struct file *file)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lookup_intent *it, oit = { .it_op = IT_OPEN,
					  .it_open_flags = file->f_flags };
	struct obd_client_handle **och_p = NULL;
	__u64 *och_usecount = NULL;
	struct ll_file_data *lfd;
	ktime_t kstart = ktime_get();
	int rc = 0;

	ENTRY;
	CDEBUG(D_VFSTRACE|D_IOTRACE,
	       "START file "DNAME":"DFID"(%p), flags %o\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       inode, file->f_flags);

	it = file->private_data; /* XXX: compat macro */
	file->private_data = NULL; /* prevent ll_local_open assertion */

	if (S_ISREG(inode->i_mode)) {
		rc = ll_file_open_encrypt(inode, file);
		if (rc) {
			if (it && it->it_disposition)
				ll_release_openhandle(file_dentry(file), it);
			GOTO(out_nofiledata, rc);
		}
	}

	lfd = ll_file_data_get();
	if (lfd == NULL)
		GOTO(out_nofiledata, rc = -ENOMEM);

	lfd->fd_file = file;
	if (S_ISDIR(inode->i_mode))
		ll_authorize_statahead(inode, lfd);

	ll_track_file_opens(inode);
	if (is_root_inode(inode)) {
		file->private_data = lfd;
		RETURN(0);
	}

	if (!it || !it->it_disposition) {
		unsigned int kernel_flags = file->f_flags;

		/* Convert f_flags into access mode. We cannot use file->f_mode,
		 * because everything but O_ACCMODE mask was stripped from there
		 */
		if ((oit.it_open_flags + MDS_FMODE_READ) & O_ACCMODE)
			kernel_flags++;

		oit.it_open_flags = ll_kernel_to_mds_open_flags(kernel_flags);

		if (file->f_flags & O_TRUNC)
			oit.it_open_flags |= MDS_FMODE_WRITE;

		/* kernel only call f_op->open in dentry_open.  filp_open calls
		 * dentry_open after call to open_namei that checks permissions.
		 * Only nfsd_open call dentry_open directly without checking
		 * permissions and because of that this code below is safe.
		 */
		if (oit.it_open_flags & (MDS_FMODE_WRITE | MDS_FMODE_READ))
			oit.it_open_flags |= MDS_OPEN_OWNEROVERRIDE;

		/* We do not want O_EXCL here, presumably we opened the file
		 * already? XXX - NFS implications?
		 */
		oit.it_open_flags &= ~MDS_OPEN_EXCL;

		/* bug20584, if "it_open_flags" contains O_CREAT, file will be
		 * created if necessary, then "IT_CREAT" should be set to keep
		 * consistent with it
		 */
		if (oit.it_open_flags & MDS_OPEN_CREAT)
			oit.it_op |= IT_CREAT;

		it = &oit;
	}

restart:
	/* Let's see if we have file open on MDS already. */
	if (it->it_open_flags & MDS_FMODE_WRITE) {
		och_p = &lli->lli_mds_write_och;
		och_usecount = &lli->lli_open_fd_write_count;
	} else if (it->it_open_flags & MDS_FMODE_EXEC) {
		och_p = &lli->lli_mds_exec_och;
		och_usecount = &lli->lli_open_fd_exec_count;
	} else {
		och_p = &lli->lli_mds_read_och;
		och_usecount = &lli->lli_open_fd_read_count;
	}

	mutex_lock(&lli->lli_och_mutex);
	if (*och_p) { /* Open handle is present */
		if (it_disposition(it, DISP_OPEN_OPEN)) {
			/* Well, there's extra open request that we do not need,
			 * let's close it somehow. This will decref request.
			 */
			rc = it_open_error(DISP_OPEN_OPEN, it);
			if (rc) {
				mutex_unlock(&lli->lli_och_mutex);
				GOTO(out_openerr, rc);
			}

			ll_release_openhandle(file_dentry(file), it);
		}
		(*och_usecount)++;

		rc = ll_local_open(file, it, lfd, NULL);
		if (rc) {
			(*och_usecount)--;
			mutex_unlock(&lli->lli_och_mutex);
			GOTO(out_openerr, rc);
		}
	} else {
		LASSERT(*och_usecount == 0);
		if (!it->it_disposition) {
			struct dentry *dentry = file_dentry(file);
			struct ll_sb_info *sbi = ll_i2sbi(inode);
			int open_threshold = sbi->ll_oc_thrsh_count;

			/* We cannot just request lock handle now, new ELC code
			 * means that one of other OPEN locks for this file
			 * could be cancelled, and since blocking ast handler
			 * would attempt to grab och_mutex as well, that would
			 * result in a deadlock
			 */
			mutex_unlock(&lli->lli_och_mutex);
			/*
			 * Normally called under two situations:
			 * 1. fhandle / NFS export.
			 * 2. A race/condition on MDS resulting in no open
			 *    handle to be returned from LOOKUP|OPEN request,
			 *    for example if the target entry was a symlink.
			 *
			 * For NFSv3 we need to always cache the open lock
			 * for pre 5.5 Linux kernels.
			 *
			 * After reaching number of opens of this inode
			 * we always ask for an open lock on it to handle
			 * bad userspace actors that open and close files
			 * in a loop for absolutely no good reason
			 */
			/* fhandle / NFS path. */
			if (lli->lli_open_thrsh_count != UINT_MAX)
				open_threshold = lli->lli_open_thrsh_count;

			if (filename_is_volatile(dentry->d_name.name,
						 dentry->d_name.len,
						 NULL)) {
				/* There really is nothing here, but this
				 * make this more readable I think.
				 * We do not want openlock for volatile
				 * files under any circumstances
				 */
			} else if (open_threshold > 0) {
				/* Take MDS_OPEN_LOCK with many opens */
				if (lli->lli_open_fd_count >= open_threshold)
					it->it_open_flags |= MDS_OPEN_LOCK;

				/* If this is open after we just closed */
				else if (ktime_before(ktime_get(),
					    ktime_add_ms(lli->lli_close_fd_time,
							 sbi->ll_oc_thrsh_ms)))
					it->it_open_flags |= MDS_OPEN_LOCK;
			}

			/*
			 * Always specify MDS_OPEN_BY_FID because we don't want
			 * to get file with different fid.
			 */
			it->it_open_flags |= MDS_OPEN_BY_FID;
			rc = ll_intent_file_open(dentry, NULL, 0, it);
			if (rc)
				GOTO(out_openerr, rc);

			goto restart;
		}
		OBD_ALLOC(*och_p, sizeof(struct obd_client_handle));
		if (!*och_p)
			GOTO(out_och_free, rc = -ENOMEM);

		(*och_usecount)++;

		/* md_intent_lock() didn't get a request ref if there was an
		 * open error, so don't do cleanup on the request here
		 * (bug b=3430)
		 *
		 * XXX (green): Should not we bail out on any error here, not
		 * just open error?
		 */
		rc = it_open_error(DISP_OPEN_OPEN, it);
		if (rc != 0)
			GOTO(out_och_free, rc);

		LASSERTF(it_disposition(it, DISP_ENQ_OPEN_REF),
			 "inode %px: disposition %x, status %d\n", inode,
			 it_disposition(it, ~0), it->it_status);

		rc = ll_local_open(file, it, lfd, *och_p);
		if (rc)
			GOTO(out_och_free, rc);
	}

	mutex_unlock(&lli->lli_och_mutex);

	/* It is not from atomic_open(). */
	if (it == &oit) {
		rc = pcc_file_open(inode, file);
		if (rc)
			GOTO(out_och_free, rc);
	}

	lfd = NULL;

	/* Must do this outside lli_och_mutex lock to prevent deadlock where
	 * different kind of OPEN lock for this same inode gets cancelled by
	 * ldlm_cancel_lru
	 */
	if (!S_ISREG(inode->i_mode))
		GOTO(out_och_free, rc);
	cl_lov_delay_create_clear(&file->f_flags);
	GOTO(out_och_free, rc);

out_och_free:
	if (rc) {
		if (och_p && *och_p) {
			OBD_FREE(*och_p, sizeof(struct obd_client_handle));
			*och_p = NULL; /* OBD_FREE writes some magic there */
			(*och_usecount)--;
		}
		mutex_unlock(&lli->lli_och_mutex);

out_openerr:
		if (lli->lli_opendir_key == lfd)
			ll_deauthorize_statahead(inode, lfd);

		if (lfd != NULL)
			ll_file_data_put(lfd);
	} else {
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_OPEN,
				   ktime_us_delta(ktime_get(), kstart));
	}

out_nofiledata:
	if (it && it_disposition(it, DISP_ENQ_OPEN_REF)) {
		ptlrpc_req_put(it->it_request);
		it_clear_disposition(it, DISP_ENQ_OPEN_REF);
	}

	CDEBUG(D_IOTRACE,
	       "COMPLETED file "DNAME":"DFID"(%p), flags %o, rc = %d\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       inode, file->f_flags, rc);

	return rc;
}

static int ll_md_blocking_lease_ast(struct ldlm_lock *lock,
			struct ldlm_lock_desc *desc, void *data, int flag)
{
	int rc;
	struct lustre_handle lockh;

	ENTRY;
	switch (flag) {
	case LDLM_CB_BLOCKING:
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		if (rc < 0) {
			CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
			RETURN(rc);
		}
		break;
	case LDLM_CB_CANCELING:
		/* do nothing */
		break;
	}
	RETURN(0);
}

/*
 * When setting a lease on a file, we take ownership of the lli_mds_*_och
 * and save it as fd->fd_och so as to force client to reopen the file even
 * if it has an open lock in cache already.
 */
static int ll_lease_och_acquire(struct inode *inode, struct file *file,
				struct lustre_handle *old_open_handle)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *lfd = file->private_data;
	struct obd_client_handle **och_p;
	__u64 *och_usecount;
	int rc = 0;

	ENTRY;
	/* Get the openhandle of the file */
	mutex_lock(&lli->lli_och_mutex);
	if (lfd->fd_lease_och != NULL)
		GOTO(out_unlock, rc = -EBUSY);

	if (lfd->fd_och == NULL) {
		if (file->f_mode & FMODE_WRITE) {
			LASSERT(lli->lli_mds_write_och != NULL);
			och_p = &lli->lli_mds_write_och;
			och_usecount = &lli->lli_open_fd_write_count;
		} else {
			LASSERT(lli->lli_mds_read_och != NULL);
			och_p = &lli->lli_mds_read_och;
			och_usecount = &lli->lli_open_fd_read_count;
		}

		if (*och_usecount > 1)
			GOTO(out_unlock, rc = -EBUSY);

		lfd->fd_och = *och_p;
		*och_usecount = 0;
		*och_p = NULL;
	}

	*old_open_handle = lfd->fd_och->och_open_handle;

	EXIT;
out_unlock:
	mutex_unlock(&lli->lli_och_mutex);
	return rc;
}

/* Release ownership on lli_mds_*_och when putting back a file lease.  */
static int ll_lease_och_release(struct inode *inode, struct file *file)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *lfd = file->private_data;
	struct obd_client_handle **och_p;
	struct obd_client_handle *old_och = NULL;
	__u64 *och_usecount;
	int rc = 0;

	ENTRY;
	mutex_lock(&lli->lli_och_mutex);
	if (file->f_mode & FMODE_WRITE) {
		och_p = &lli->lli_mds_write_och;
		och_usecount = &lli->lli_open_fd_write_count;
	} else {
		och_p = &lli->lli_mds_read_och;
		och_usecount = &lli->lli_open_fd_read_count;
	}

	/* The file may have been open by another process (broken lease) so
	 * *och_p is not NULL. In this case we should simply increase usecount
	 * and close fd_och.
	 */
	if (*och_p != NULL) {
		old_och = lfd->fd_och;
		(*och_usecount)++;
	} else {
		*och_p = lfd->fd_och;
		*och_usecount = 1;
	}
	lfd->fd_och = NULL;
	mutex_unlock(&lli->lli_och_mutex);

	if (old_och != NULL)
		rc = ll_close_inode_openhandle(inode, old_och, 0, NULL);

	RETURN(rc);
}

/**
 * ll_lease_open() - Acquire a lease(block other open() call on this file)
 *		     and open the file.
 *
 * @inode: mount point
 * @file: file to open
 * @fmode: Kernel mode open flag pass to open() (permissions)
 * @open_flags: MDS flags passed from client
 *
 * Return:
 * * populate obd_client_handle object on success
 */
static struct obd_client_handle *
ll_lease_open(struct inode *inode, struct file *file, fmode_t fmode,
	      enum mds_open_flags open_flags)
{
	struct lookup_intent it = { .it_op = IT_OPEN };
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	struct lustre_handle old_open_handle = { 0 };
	struct obd_client_handle *och = NULL;
	int rc;
	int rc2;

	ENTRY;
	if (fmode != FMODE_WRITE && fmode != FMODE_READ)
		RETURN(ERR_PTR(-EINVAL));

	if (file != NULL) {
		if (!(fmode & file->f_mode) || (file->f_mode & FMODE_EXEC))
			RETURN(ERR_PTR(-EPERM));

		rc = ll_lease_och_acquire(inode, file, &old_open_handle);
		if (rc)
			RETURN(ERR_PTR(rc));
	}

	OBD_ALLOC_PTR(och);
	if (och == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	op_data = ll_prep_md_op_data(NULL, inode, inode, NULL, 0, 0,
					LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		GOTO(out, rc = PTR_ERR(op_data));

	/* To tell the MDT this openhandle is from the same owner */
	op_data->op_open_handle = old_open_handle;

	it.it_open_flags = fmode | open_flags;
	it.it_open_flags |= MDS_OPEN_LOCK | MDS_OPEN_BY_FID | MDS_OPEN_LEASE;
	rc = ll_intent_lock(sbi->ll_md_exp, op_data, &it, &req,
			    &ll_md_blocking_lease_ast,
	/* LDLM_FL_NO_LRU: To not put the lease lock into LRU list, otherwise
	 * it can be cancelled which may mislead applications that the lease is
	 * broken;
	 * LDLM_FL_EXCL: Set this flag so that it won't be matched by normal
	 * open in ll_md_blocking_ast(). Otherwise as ll_md_blocking_lease_ast
	 * doesn't deal with openhandle, so normal openhandle will be leaked.
	 */
			    LDLM_FL_NO_LRU | LDLM_FL_EXCL,
			    true);
	ll_finish_md_op_data(op_data);
	ptlrpc_req_put(req);
	if (rc < 0)
		GOTO(out_release_it, rc);

	if (it_disposition(&it, DISP_LOOKUP_NEG))
		GOTO(out_release_it, rc = -ENOENT);

	rc = it_open_error(DISP_OPEN_OPEN, &it);
	if (rc)
		GOTO(out_release_it, rc);

	LASSERT(it_disposition(&it, DISP_ENQ_OPEN_REF));
	rc = ll_och_fill(sbi->ll_md_exp, &it, och);
	if (rc)
		GOTO(out_release_it, rc);

	if (!it_disposition(&it, DISP_OPEN_LEASE)) /* old server? */
		GOTO(out_close, rc = -EOPNOTSUPP);

	/* already get lease, handle lease lock */
	ll_set_lock_data(sbi->ll_md_exp, inode, &it, NULL);
	if (!it.it_lock_mode ||
	    !(it.it_lock_bits & MDS_INODELOCK_OPEN)) {
		/* open lock must return for lease */
		rc = -EPROTO;
		CERROR("%s: "DFID" lease granted but no open lock, %d/%lu: rc = %d\n",
		       sbi->ll_fsname, PFID(ll_inode2fid(inode)),
		       it.it_lock_mode, it.it_lock_bits, rc);
		GOTO(out_close, rc);
	}

	ll_intent_release(&it);
	RETURN(och);

out_close:
	/* Cancel open lock */
	if (it.it_lock_mode != 0) {
		ldlm_lock_decref_and_cancel(&och->och_lease_handle,
					    it.it_lock_mode);
		it.it_lock_mode = 0;
		och->och_lease_handle.cookie = 0ULL;
	}
	rc2 = ll_close_inode_openhandle(inode, och, 0, NULL);
	if (rc2 < 0)
		CERROR("%s: error closing file "DFID": %d\n",
		       sbi->ll_fsname, PFID(&ll_i2info(inode)->lli_fid), rc2);
	och = NULL; /* och has been freed in ll_close_inode_openhandle() */
out_release_it:
	ll_intent_release(&it);
out:
	OBD_FREE_PTR(och);
	RETURN(ERR_PTR(rc));
}

/**
 * ll_check_swap_layouts_validity() - Check whether a layout swap can be done
 * between two inodes.
 * @inode1:  First inode to check
 * @inode2:  Second inode to check
 *
 * Return:
 * * %0 on success, layout swap can be performed between both inodes
 * * %negative error code if requirements are not met
 */
static int ll_check_swap_layouts_validity(struct inode *inode1,
					  struct inode *inode2)
{
	if (!S_ISREG(inode1->i_mode) || !S_ISREG(inode2->i_mode))
		return -EINVAL;

	if (inode_permission(&nop_mnt_idmap, inode1, MAY_WRITE) ||
	    inode_permission(&nop_mnt_idmap, inode2, MAY_WRITE))
		return -EPERM;

	if (inode1->i_sb != inode2->i_sb)
		return -EXDEV;

	return 0;
}

static int ll_swap_layouts_close(struct obd_client_handle *och,
				 struct inode *inode, struct inode *inode2,
				 struct lustre_swap_layouts *lsl)
{
	const struct lu_fid *fid1 = ll_inode2fid(inode);
	struct swap_layouts_param slp;
	const struct lu_fid *fid2;
	int  rc;

	ENTRY;
	CDEBUG(D_INODE, "%s: biased close of file "DFID"\n",
	       ll_i2sbi(inode)->ll_fsname, PFID(fid1));

	rc = ll_check_swap_layouts_validity(inode, inode2);
	if (rc < 0)
		GOTO(out_free_och, rc);

	/* We now know that inode2 is a lustre inode */
	fid2 = ll_inode2fid(inode2);

	rc = lu_fid_cmp(fid1, fid2);
	if (rc == 0)
		GOTO(out_free_och, rc = -EINVAL);

	/* Close the file and {swap,merge} layouts between inode & inode2.
	 * NB: local lease handle is released in mdc_close_intent_pack()
	 * because we still need it to pack l_remote_handle to MDT.
	 */
	slp.slp_inode = inode2;
	slp.slp_dv1 = lsl->sl_dv1;
	slp.slp_dv2 = lsl->sl_dv2;
	rc = ll_close_inode_openhandle(inode, och, MDS_CLOSE_LAYOUT_SWAP, &slp);

	och = NULL; /* freed in ll_close_inode_openhandle() */

out_free_och:
	OBD_FREE_PTR(och);

	RETURN(rc);
}

/*
 * Release lease and close the file.
 * It will check if the lease has ever broken.
 */
static int ll_lease_close_intent(struct obd_client_handle *och,
				 struct inode *inode,
				 bool *lease_broken, enum mds_op_bias bias,
				 void *data)
{
	struct ldlm_lock *lock;
	bool cancelled = true;
	int rc;

	ENTRY;
	lock = ldlm_handle2lock(&och->och_lease_handle);
	if (lock != NULL) {
		lock_res_and_lock(lock);
		cancelled = ldlm_is_cancel(lock);
		unlock_res_and_lock(lock);
		ldlm_lock_put(lock);
	}

	CDEBUG(D_INODE, "lease for "DFID" broken? %d, bias: %x\n",
	       PFID(&ll_i2info(inode)->lli_fid), cancelled, bias);

	if (lease_broken != NULL)
		*lease_broken = cancelled;

	if (!cancelled && !bias)
		ldlm_cli_cancel(&och->och_lease_handle, 0);

	if (cancelled) { /* no need to excute intent */
		bias = 0;
		data = NULL;
	}

	rc = ll_close_inode_openhandle(inode, och, bias, data);
	RETURN(rc);
}

static int ll_lease_close(struct obd_client_handle *och, struct inode *inode,
			  bool *lease_broken)
{
	return ll_lease_close_intent(och, inode, lease_broken, 0, NULL);
}

/* After lease is taken, send the RPC MDS_REINT_RESYNC to the MDT */
static int ll_lease_file_resync(struct obd_client_handle *och,
				struct inode *inode, void __user *uarg)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct md_op_data *op_data;
	struct ll_ioc_lease_id ioc;
	__u64 data_version_unused;
	int rc;

	ENTRY;
	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	if (copy_from_user(&ioc, uarg, sizeof(ioc)))
		RETURN(-EFAULT);

	/* before starting file resync, it's necessary to clean up page cache
	 * in client memory, otherwise once the layout version is increased,
	 * writing back cached data will be denied the OSTs.
	 */
	rc = ll_data_version(inode, &data_version_unused, LL_DV_WR_FLUSH);
	if (rc)
		GOTO(out, rc);

	op_data->op_lease_handle = och->och_lease_handle;
	op_data->op_mirror_id = ioc.lil_mirror_id;
	rc = md_file_resync(sbi->ll_md_exp, op_data);
	if (rc)
		GOTO(out, rc);

	EXIT;
out:
	ll_finish_md_op_data(op_data);
	return rc;
}

static int ll_merge_attr_nolock(const struct lu_env *env, struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct cl_attr *attr = vvp_env_new_attr(env);
	s64 atime;
	s64 mtime;
	s64 ctime;
	int rc = 0;

	ENTRY;
	/* Merge timestamps the most recently obtained from MDS with
	 * timestamps obtained from OSTs.
	 *
	 * Do not overwrite atime of inode because it may be refreshed
	 * by file_accessed() function. If the read was served by cache
	 * data, there is no RPC to be sent so that atime may not be
	 * transferred to OSTs at all. MDT only updates atime at close time
	 * if it's at least 'mdd.*.atime_diff' older.
	 * All in all, the atime in Lustre does not strictly comply with
	 * POSIX. Solving this problem needs to send an RPC to MDT for each
	 * read, this will hurt performance.
	 */
	if (test_and_clear_bit(LLIF_UPDATE_ATIME, &lli->lli_flags) ||
	    inode_get_atime_sec(inode) < lli->lli_atime)
		inode_set_atime(inode, lli->lli_atime, 0);

	inode_set_mtime(inode, lli->lli_mtime, 0);
	inode_set_ctime(inode, lli->lli_ctime, 0);

	mtime = inode_get_mtime_sec(inode);
	atime = inode_get_atime_sec(inode);
	ctime = inode_get_ctime_sec(inode);

	cl_object_attr_lock(obj);
	if (CFS_FAIL_CHECK(OBD_FAIL_MDC_MERGE))
		rc = -EINVAL;
	else
		rc = cl_object_attr_get(env, obj, attr);
	cl_object_attr_unlock(obj);

	if (rc != 0)
		GOTO(out, rc = (rc == -ENODATA ? 0 : rc));

	CFS_RACE(OBD_FAIL_LLITE_STAT_RACE2);
	/*
	 * let a awaken stat thread a chance to get intermediate
	 * attributes from inode
	 */
	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_STAT_RACE2, 1);

	if (atime < attr->cat_atime)
		atime = attr->cat_atime;

	if (ctime < attr->cat_ctime)
		ctime = attr->cat_ctime;

	if (mtime < attr->cat_mtime)
		mtime = attr->cat_mtime;

	CDEBUG(D_VFSTRACE, DFID" updating i_size %llu i_blocks %llu\n",
	       PFID(&lli->lli_fid), attr->cat_size, attr->cat_blocks);

	if (IS_ENCRYPTED(inode) && !ll_has_encryption_key(inode)) {
		/* Without the key, round up encrypted file size to next
		 * LUSTRE_ENCRYPTION_UNIT_SIZE. Clear text size is put in
		 * lli_lazysize for proper file size setting at close time.
		 */
		lli->lli_attr_valid |= OBD_MD_FLLAZYSIZE;
		lli->lli_lazysize = attr->cat_size;
		attr->cat_size = round_up(attr->cat_size,
					  LUSTRE_ENCRYPTION_UNIT_SIZE);
	}
	i_size_write(inode, attr->cat_size);
	inode->i_blocks = attr->cat_blocks;

	inode_set_mtime(inode, mtime, 0);
	inode_set_atime(inode, atime, 0);
	inode_set_ctime(inode, ctime, 0);

	EXIT;
out:
	return rc;
}

int ll_merge_attr(const struct lu_env *env, struct inode *inode)
{
	int rc;

	ll_inode_size_lock(inode);
	rc = ll_merge_attr_nolock(env, inode);
	ll_inode_size_unlock(inode);

	return rc;
}

/* Use to update size and blocks on inode for LSOM if there is no contention */
int ll_merge_attr_try(const struct lu_env *env, struct inode *inode)
{
	int rc = 0;

	if (ll_inode_size_trylock(inode)) {
		rc = ll_merge_attr_nolock(env, inode);
		ll_inode_size_unlock(inode);
	}

	return rc;
}

/*
 * Set designated mirror for I/O.
 *
 * So far only read, write, and truncated can support to issue I/O to
 * designated mirror.
 */
void ll_io_set_mirror(struct cl_io *io, const struct file *file)
{
	struct ll_file_data *lfd = file->private_data;

	/* clear layout version for generic(non-resync) I/O in case it carries
	 * stale layout version due to I/O restart
	 */
	io->ci_layout_version = 0;

	/* FLR: disable non-delay for designated mirror I/O because obviously
	 * only one mirror is available
	 */
	if (lfd->fd_designated_mirror > 0) {
		io->ci_ndelay = 0;
		io->ci_designated_mirror = lfd->fd_designated_mirror;
		io->ci_layout_version = lfd->fd_layout_version;
	}

	CDEBUG(D_VFSTRACE, DNAME": desiginated mirror: %d\n",
	       encode_fn_file(file), io->ci_designated_mirror);
}

/* This is relatime_need_update() from Linux 5.17, which is not exported */
static int relatime_need_update(struct vfsmount *mnt, struct inode *inode,
				struct timespec64 now)
{
	struct timespec64 ts;
	struct timespec64 atime;

	if (!(mnt->mnt_flags & MNT_RELATIME))
		return 1;
	/* Is mtime younger than atime? If yes, update atime: */
	atime = inode_get_atime(inode);
	ts = inode_get_mtime(inode);
	if (timespec64_compare(&ts, &atime) >= 0)
		return 1;
	/* Is ctime younger than atime? If yes, update atime: */
	ts = inode_get_ctime(inode);
	if (timespec64_compare(&ts, &atime) >= 0)
		return 1;

	/* Is the previous atime value older than a day? If yes, update atime */
	if ((long)(now.tv_sec - atime.tv_sec) >= 24*60*60)
		return 1;
	/* Good, we can skip the atime update: */
	return 0;
}

/* Very similar to kernel function: !__atime_needs_update() */
static bool file_is_noatime(const struct file *file)
{
	struct vfsmount *mnt = file->f_path.mnt;
	struct inode *inode = file_inode((struct file *)file);
	struct timespec64 now;

	if (file->f_flags & O_NOATIME)
		return true;

	if (inode->i_flags & S_NOATIME)
		return true;

	if (IS_NOATIME(inode))
		return true;

	if (mnt->mnt_flags & (MNT_NOATIME | MNT_READONLY))
		return true;

	if ((mnt->mnt_flags & MNT_NODIRATIME) && S_ISDIR(inode->i_mode))
		return true;

	if ((inode->i_sb->s_flags & SB_NODIRATIME) && S_ISDIR(inode->i_mode))
		return true;

	now = current_time(inode);

	if (!relatime_need_update(mnt, inode, now))
		return true;

	return false;
}

void ll_io_init(struct cl_io *io, struct file *file, enum cl_io_type iot,
		struct vvp_io_args *args)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *lfd  = file->private_data;
	int flags = vvp_io_args_flags(file, args);

	io->u.ci_rw.crw_nonblock = file->f_flags & O_NONBLOCK;
	io->ci_lock_no_expand = lfd->lfd_lock_no_expand;

	if (iot == CIT_WRITE) {
		io->u.ci_wr.wr_append = iocb_ki_flags_check(flags, APPEND);
		io->u.ci_wr.wr_sync   = !!(iocb_ki_flags_check(flags, SYNC) ||
					   iocb_ki_flags_check(flags, DSYNC) ||
					   IS_SYNC(inode));
	}

#ifdef IOCB_NOWAIT
	io->ci_iocb_nowait = iocb_ki_flags_check(flags, NOWAIT);
#endif

	io->ci_obj = ll_i2info(inode)->lli_clob;
	io->ci_lockreq = CILR_MAYBE;
	if (ll_file_nolock(file)) {
		io->ci_lockreq = CILR_NEVER;
		io->ci_no_srvlock = 1;
	} else if (iocb_ki_flags_check(flags, APPEND)) {
		io->ci_lockreq = CILR_MANDATORY;
	}
	io->ci_noatime = file_is_noatime(file);
	io->ci_async_readahead = false;

	/* FLR: only use non-delay I/O for read as there is only one
	 * avaliable mirror for write.
	 */
	io->ci_ndelay = !(iot == CIT_WRITE);
	/* unaligned DIO has compat issues with some older servers, but we find
	 * out if there are such servers while setting up the IO, so it starts
	 * out allowed
	 */
	io->ci_allow_unaligned_dio = true;
	if (args)
		io->ci_hybrid_switched = args->via_hybrid_switched;

	ll_io_set_mirror(io, file);
}

static void ll_heat_add(struct inode *inode, enum cl_io_type iot,
			__u64 count)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	enum obd_heat_type sample_type;
	enum obd_heat_type iobyte_type;
	__u64 now = ktime_get_real_seconds();

	if (!ll_sbi_has_file_heat(sbi) ||
	    lli->lli_heat_flags & LU_HEAT_FLAG_OFF)
		return;

	if (iot == CIT_READ) {
		sample_type = OBD_HEAT_READSAMPLE;
		iobyte_type = OBD_HEAT_READBYTE;
	} else if (iot == CIT_WRITE) {
		sample_type = OBD_HEAT_WRITESAMPLE;
		iobyte_type = OBD_HEAT_WRITEBYTE;
	} else {
		return;
	}

	spin_lock(&lli->lli_heat_lock);
	obd_heat_add(&lli->lli_heat_instances[sample_type], now, 1,
		     sbi->ll_heat_decay_weight, sbi->ll_heat_period_second);
	obd_heat_add(&lli->lli_heat_instances[iobyte_type], now, count,
		     sbi->ll_heat_decay_weight, sbi->ll_heat_period_second);
	spin_unlock(&lli->lli_heat_lock);
}

static bool
ll_hybrid_bio_dio_switch_check(struct file *file, struct kiocb *iocb,
			       enum cl_io_type iot, size_t count)
{
	/* we can only do this with IOCB_FLAGS, since we can't modify f_flags
	 * because they're visible in userspace.  so we check for IOCB_DIRECT
	 */
#ifdef IOCB_DIRECT
	struct inode *inode = file_inode(file);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	int op = LPROC_LL_HYBRID_NOSWITCH;
	int dio_switch = false;

	ENTRY;
	/* it doesn't make sense to switch unless it's READ or WRITE */
	if (iot != CIT_WRITE && iot != CIT_READ)
		RETURN(false);

	if (!iocb)
		RETURN(false);

	/* Already using direct I/O, no need to switch. */
	if (iocb->ki_flags & IOCB_DIRECT)
		RETURN(false);

	if (!test_bit(LL_SBI_HYBRID_IO, sbi->ll_flags))
		RETURN(false);

	/* we only log hybrid IO stats if we hit the actual switching logic -
	 * not if hybrid IO is disabled or the IO was never a candidate to
	 * switch
	 */
	if (iot == CIT_WRITE &&
	    count >= sbi->ll_hybrid_io_write_threshold_bytes) {
		op = LPROC_LL_HYBRID_WRITESIZE_SWITCH;
		GOTO(out, dio_switch = true);
	}

	if (iot == CIT_READ &&
	    count >= sbi->ll_hybrid_io_read_threshold_bytes) {
		op = LPROC_LL_HYBRID_READSIZE_SWITCH;
		GOTO(out, dio_switch = true);
	}

out:
	ll_stats_ops_tally(sbi, op, 1);
	RETURN(dio_switch);
#else
	RETURN(false);
#endif
}

static ssize_t
ll_file_io_generic(const struct lu_env *env, struct vvp_io_args *args,
		   struct file *file, enum cl_io_type iot,
		   loff_t *ppos, size_t bytes)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *lfd  = file->private_data;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct vvp_io *vio = vvp_env_io(env);
	struct cl_dio_aio *ci_dio_aio = NULL;
	struct range_lock range;
	struct cl_io *io;
	int flags = vvp_io_args_flags(file, args);
	bool is_parallel_dio = false;
	bool range_locked = false;
	unsigned int retried = 0;
	bool dio_lock = false;
	bool is_aio = false;
	size_t max_io_bytes;
	ssize_t result = 0;
	int retries = 1000;
	size_t per_bytes;
	bool partial_io;
	int rc2 = 0;
	int rc = 0;

	ENTRY;
	CDEBUG(D_VFSTRACE, DNAME": %s ppos: %llu, bytes: %zu\n",
	       encode_fn_file(file),
	       iot == CIT_READ ? "read" : "write", *ppos, bytes);

	max_io_bytes = min_t(size_t, PTLRPC_MAX_BRW_PAGES * OBD_MAX_RIF_DEFAULT,
			     sbi->ll_cache->ccc_lru_max >> 2) << PAGE_SHIFT;

	io = vvp_env_new_io(env);
	if (iocb_ki_flags_check(flags, DIRECT)) {
		if (iocb_ki_flags_check(flags, APPEND))
			dio_lock = true;
		if (!is_sync_kiocb(args->u.normal.via_iocb) &&
		/* hybrid IO is also potentially async */
		    !args->via_hybrid_switched)
			is_aio = true;

		/* the kernel does not support AIO on pipes, and parallel DIO
		 * uses part of the AIO path, so we must not do parallel dio
		 * to pipes
		 */
		is_parallel_dio = !iov_iter_is_pipe(args->u.normal.via_iter) &&
				  !is_aio;

		if (!ll_sbi_has_parallel_dio(sbi))
			is_parallel_dio = false;

		ci_dio_aio = cl_dio_aio_alloc(args->u.normal.via_iocb,
					  ll_i2info(inode)->lli_clob, is_aio);
		if (!ci_dio_aio)
			GOTO(out, rc = -ENOMEM);
	}

restart:
	/*
	 * IO block size need be aware of cached page limit, otherwise
	 * if we have small max_cached_mb but large block IO issued, io
	 * could not be finished and blocked whole client.
	 */
	if (iocb_ki_flags_check(flags, DIRECT) || bytes < max_io_bytes) {
		per_bytes = bytes;
		partial_io = false;
	} else {
		per_bytes = max_io_bytes;
		partial_io = true;
	}
	io = vvp_env_new_io(env);
	ll_io_init(io, file, iot, args);
	io->ci_dio_aio = ci_dio_aio;
	io->ci_dio_lock = dio_lock;
	io->ci_ndelay_tried = retried;
	io->ci_parallel_dio = is_parallel_dio;

	if (cl_io_rw_init(env, io, iot, *ppos, per_bytes) == 0) {
		if (iocb_ki_flags_check(flags, APPEND))
			range_lock_init(&range, 0, LUSTRE_EOF);
		else
			range_lock_init(&range, *ppos, *ppos + per_bytes - 1);

		vio->vui_fd  = file->private_data;
		vio->vui_iter = args->u.normal.via_iter;
		vio->vui_iocb = args->u.normal.via_iocb;
		/* Direct IO reads must also take range lock,
		 * or multiple reads will try to work on the same pages
		 * See LU-6227 for details.
		 */
		if (((iot == CIT_WRITE) ||
		    (iot == CIT_READ && iocb_ki_flags_check(flags, DIRECT))) &&
		    !(vio->vui_fd->lfd_file_flags & LL_FILE_GROUP_LOCKED)) {
			CDEBUG(D_VFSTRACE, "Range lock "RL_FMT"\n",
			       RL_PARA(&range));
			rc = range_lock(&lli->lli_write_tree, &range);
			if (rc < 0)
				GOTO(out, rc);

			range_locked = true;
		}

		ll_cl_add(inode, env, io, LCC_RW);
		rc = cl_io_loop(env, io);
		ll_cl_remove(inode, env);
	} else {
		/* cl_io_rw_init() handled IO */
		rc = io->ci_result;
	}

	if (io->ci_dio_aio && !is_aio) {
		struct cl_sync_io *anchor = &io->ci_dio_aio->cda_sync;

		/* for dio, EIOCBQUEUED is an implementation detail,
		 * and we don't return it to userspace
		 */
		if (rc == -EIOCBQUEUED)
			rc = 0;

		/* N/B: parallel DIO may be disabled during i/o submission;
		 * if that occurs, I/O shifts to sync, so it's all resolved
		 * before we get here, and this wait call completes
		 * immediately.
		 */
		rc2 = cl_sync_io_wait_recycle(env, anchor, 0, 0);
		if (rc2 < 0)
			rc = rc2;
	}

	if (range_locked) {
		CDEBUG(D_VFSTRACE, "Range unlock "RL_FMT"\n",
		       RL_PARA(&range));
		range_unlock(&lli->lli_write_tree, &range);
			range_locked = false;
	}

	if (io->ci_bytes > 0) {
		if (rc2 == 0) {
			result += io->ci_bytes;
			*ppos = io->u.ci_wr.wr.crw_pos; /* for splice */
		} else if (rc2) {
			result = 0;
		}
		bytes -= io->ci_bytes;

		/* prepare IO restart */
		if (bytes > 0)
			args->u.normal.via_iter = vio->vui_iter;

		if (partial_io) {
			/*
			 * Reexpand iov count because it was zero
			 * after IO finish.
			 */
			iov_iter_reexpand(vio->vui_iter, bytes);
			if (per_bytes == io->ci_bytes)
				io->ci_need_restart = 1;
		}
	}
out:
	cl_io_fini(env, io);

	CDEBUG(D_VFSTRACE,
	       DNAME": %d io complete with rc: %d, result: %zd, restart: %d\n",
	       encode_fn_file(file), iot, rc, result, io->ci_need_restart);

	if ((!rc || rc == -ENODATA || rc == -ENOLCK || rc == -EIOCBQUEUED) &&
	    bytes > 0 && io->ci_need_restart && retries-- > 0) {
		CDEBUG(D_VFSTRACE,
		       DNAME": restart %s from ppos=%lld bytes=%zu retries=%u ret=%zd: rc = %d\n",
		       encode_fn_file(file), iot == CIT_READ ? "read" : "write",
		       *ppos, bytes, retries, result, rc);
		/* preserve the tried count for FLR */
		retried = io->ci_ndelay_tried;
		dio_lock = io->ci_dio_lock;
		goto restart;
	}

	/* update inode size */
	if (io->ci_type == CIT_WRITE)
		ll_merge_attr(env, inode);

	if (io->ci_dio_aio) {
		/* set the number of bytes successfully moved in the aio */
		if (result > 0)
			io->ci_dio_aio->cda_bytes = result;
		/*
		 * VFS will call aio_complete() if no -EIOCBQUEUED
		 * is returned for AIO, so we can not call aio_complete()
		 * in our end_io().  (cda_no_aio_complete is always set for
		 * normal DIO.)
		 *
		 * NB: Setting cda_no_aio_complete like this is safe because
		 * the atomic_dec_and_lock in cl_sync_io_note has implicit
		 * memory barriers, so this will be seen by whichever thread
		 * completes the DIO/AIO, even if it's not this one.
		 */
		if (is_aio && rc != -EIOCBQUEUED)
			io->ci_dio_aio->cda_no_aio_complete = 1;
		/* if an aio enqueued successfully (-EIOCBQUEUED), then Lustre
		 * will call aio_complete rather than the vfs, so we return 0
		 * to tell the VFS we're handling it
		 */
		else if (is_aio) /* rc == -EIOCBQUEUED */
			result = 0;
		/*
		 * Drop the reference held by the llite layer on this top level
		 * IO context.
		 *
		 * For DIO, this frees it here, since IO is complete, and for
		 * AIO, we will call aio_complete() (and then free this top
		 * level context) once all the outstanding chunks of this AIO
		 * have completed.
		 */
		cl_sync_io_note(env, &io->ci_dio_aio->cda_sync,
				rc == -EIOCBQUEUED ? 0 : rc);
		if (!is_aio) {
			LASSERT(io->ci_dio_aio->cda_creator_free);
			cl_dio_aio_free(env, io->ci_dio_aio);
			io->ci_dio_aio = NULL;
		}
	}

	if (iot == CIT_READ) {
		if (result > 0) {
			ll_stats_ops_tally(ll_i2sbi(inode),
					   LPROC_LL_READ_BYTES, result);
			if (args->via_hybrid_switched)
				ll_stats_ops_tally(ll_i2sbi(inode),
						   LPROC_LL_HIO_READ, result);
		}
	} else if (iot == CIT_WRITE) {
		if (result > 0) {
			ll_stats_ops_tally(ll_i2sbi(inode),
					   LPROC_LL_WRITE_BYTES, result);
			if (args->via_hybrid_switched)
				ll_stats_ops_tally(ll_i2sbi(inode),
						   LPROC_LL_HIO_WRITE, result);
			lfd->fd_write_failed = false;
		} else if (result == 0 && rc == 0) {
			rc = io->ci_result;
			if (rc < 0)
				lfd->fd_write_failed = true;
			else
				lfd->fd_write_failed = false;
		} else if (rc != -ERESTARTSYS) {
			lfd->fd_write_failed = true;
		}
	}

	CDEBUG(D_VFSTRACE, "iot: %d, result: %zd\n", iot, result);
	if (result > 0)
		ll_heat_add(inode, iot, result);

	RETURN(result > 0 ? result : rc);
}

/**
 * ll_do_fast_read() - read data directly from the page cache
 * @iocb: kiocb from kernel
 * @iter: user space buffers where the data will be copied
 *
 * The purpose of fast read is to overcome per I/O overhead and improve IOPS
 * especially for small I/O.
 *
 * To serve a read request, CLIO has to create and initialize a cl_io and
 * then request DLM lock. This has turned out to have siginificant overhead
 * and affects the performance of small I/O dramatically.
 *
 * It's not necessary to create a cl_io for each I/O. Under the help of read
 * ahead, most of the pages being read are already in memory cache and we can
 * read those pages directly because if the pages exist, the corresponding DLM
 * lock must exist so that page content must be valid.
 *
 * In fast read implementation, the llite speculatively finds and reads pages
 * in memory cache. There are three scenarios for fast read:
 *   - If the page exists and is uptodate, kernel VM will provide the data and
 *     CLIO won't be intervened;
 *   - If the page was brought into memory by read ahead, it will be exported
 *     and read ahead parameters will be updated;
 *   - Otherwise the page is not in memory, we can't do fast read. Therefore,
 *     it will go back and invoke normal read, i.e., a cl_io will be created
 *     and DLM lock will be requested.
 *
 * POSIX compliance: posix standard states that read is intended to be atomic.
 * Lustre read implementation is in line with Linux kernel read implementation
 * and neither of them complies with POSIX standard in this matter. Fast read
 * doesn't make the situation worse on single node but it may interleave write
 * results from multiple nodes due to short read handling in ll_file_aio_read().
 *
 * Returns number of bytes have been read, or error code if error occurred.
 */
static ssize_t
ll_do_fast_read(struct kiocb *iocb, struct iov_iter *iter)
{
	struct ll_inode_info *lli = ll_i2info(file_inode(iocb->ki_filp));
	int flags = iocb_ki_flags_get(iocb->ki_filp, iocb);
	ssize_t result;

	if (!ll_sbi_has_fast_read(ll_i2sbi(file_inode(iocb->ki_filp))))
		return 0;

	/* NB: we can't do direct IO for fast read because it will need a lock
	 * to make IO engine happy.
	 */
	if (iocb_ki_flags_check(flags, DIRECT))
		return 0;

	if (ll_layout_version_get(lli) == CL_LAYOUT_GEN_NONE)
		return 0;

	result = generic_file_read_iter(iocb, iter);

	/* If the first page is not in cache, generic_file_aio_read() will be
	 * returned with -ENODATA.  Fall back to full read path.
	 * See corresponding code in ll_readpage().
	 *
	 * if we raced with page deletion, we might get EIO.  Rather than add
	 * locking to the fast path for this rare case, fall back to the full
	 * read path.  (See vvp_io_read_start() for rest of handling.
	 */
	if (result == -ENODATA || result == -EIO)
		result = 0;

	if (result > 0) {
		ll_heat_add(file_inode(iocb->ki_filp), CIT_READ, result);
		ll_stats_ops_tally(ll_i2sbi(file_inode(iocb->ki_filp)),
				   LPROC_LL_READ_BYTES, result);
	}

	return result;
}

/**
 * file_read_confine_iter() - Confine read iter lest read beyond the EOF
 * @env: execution environment for this thread
 * @iocb: kernel iocb
 * @to: reader iov_iter
 *
 * Returns:
 * * %0 success
 * * <0 failure
 * * >0 @iocb->ki_pos has passed the EOF
 */
static int file_read_confine_iter(struct lu_env *env, struct kiocb *iocb,
				  struct iov_iter *to)
{
	struct cl_io *io;
	struct cl_attr *attr = vvp_env_new_attr(env);
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	loff_t read_end = iocb->ki_pos + iov_iter_count(to);
	loff_t kms;
	loff_t size;
	int rc = 0;

	ENTRY;
	if (!obj)
		RETURN(rc);

	io = vvp_env_new_io(env);
	io->ci_obj = obj;
	rc = cl_io_init(env, io, CIT_MISC, obj);
	if (rc < 0)
		GOTO(fini_io, rc);

	cl_object_attr_lock(lli->lli_clob);
	rc = cl_object_attr_get(env, lli->lli_clob, attr);
	cl_object_attr_unlock(lli->lli_clob);

fini_io:
	cl_io_fini(env, io);
	if (rc < 0)
		RETURN(rc);

	kms = attr->cat_kms;
	/* if read beyond end-of-file, adjust read count */
	if (kms > 0 && (iocb->ki_pos >= kms || read_end > kms)) {
		rc = ll_glimpse_size(inode);
		if (rc != 0)
			RETURN(rc);

		size = i_size_read(inode);
		if (iocb->ki_pos >= size || read_end > size) {
			CDEBUG(D_VFSTRACE,
			       DNAME": read [%llu, %llu] over eof, kms %llu, file_size %llu.\n",
			       encode_fn_file(file), iocb->ki_pos, read_end,
			       kms, size);

			if (iocb->ki_pos >= size)
				RETURN(1);

			if (read_end > size)
				iov_iter_truncate(to, size - iocb->ki_pos);
		}
	}

	RETURN(rc);
}

#ifdef HAVE_IOV_ITER_INIT_DIRECTION
# define ll_iov_iter_init(i, d, v, n, l) \
	 iov_iter_init((i), (d), (v), (n), (l))
# else
# define ll_iov_iter_init(i, d, v, n, l) \
	 iov_iter_init((i), (v), (n), (l), 0)
# endif

typedef ssize_t (*iter_fn_t)(struct kiocb *, struct iov_iter *);

static ssize_t do_loop_readv_writev(struct kiocb *iocb, const struct iovec *iov,
				    int rw, unsigned long nr_segs, iter_fn_t fn)
{
	const struct iovec *vector = iov;
	ssize_t ret = 0;

	while (nr_segs > 0) {
		struct iov_iter	i;
		ssize_t nr;
		size_t len = vector->iov_len;

		ll_iov_iter_init(&i, rw, vector, 1, len);
		nr = fn(iocb, &i);
		if (nr < 0) {
			if (!ret)
				ret = nr;
			break;
		}
		ret += nr;
		if (nr != len)
			break;
		vector++;
		nr_segs--;
	}

	return ret;
}

/*
 * Check if we need loop over the iovec and submit each segment in a loop.
 * This is needed when:
 *   - Prior to the introduction of HAVE_DIO_ITER
 *   - unaligned direct i/o
 * Returns true for the above cases and false otherwise.
 *
 * Note that looping is always safe although it is preferable to pass the
 * iovec down unmodified when the appropriate support is available.
 */
static bool is_unaligned_directio(struct kiocb *iocb, struct iov_iter *iter,
				 enum cl_io_type io_type)
{
#ifdef HAVE_DIO_ITER
	struct file *file = iocb->ki_filp;
	int iocb_flags = iocb_ki_flags_get(file, iocb);
	bool direct_io = iocb_ki_flags_check(iocb_flags, DIRECT);
	bool unaligned = false;

/* This I/O could be switched to direct i/o if the kernel is new enough */
#ifdef IOCB_DIRECT
	if (ll_hybrid_bio_dio_switch_check(file, iocb, io_type,
					   iov_iter_count(iter)))
		direct_io = true;
#endif

	if (direct_io) {
		if (iocb->ki_pos & ~PAGE_MASK)
			unaligned = true;
		else
			unaligned = ll_iov_iter_is_unaligned(iter);
	}
	return unaligned;
#else
	return true;
#endif /* HAVE_DIO_ITER */
}

/* Read from a file (through the page cache) */
static ssize_t do_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct lu_env *env;
	struct vvp_io_args *args;
	struct file *file = iocb->ki_filp;
	loff_t orig_ki_pos = iocb->ki_pos;
	ssize_t result;
	ssize_t rc2;
	__u16 refcheck;
	ktime_t kstart = ktime_get();
	bool cached;
	bool stale_data = false;

	ENTRY;
	CDEBUG(D_VFSTRACE|D_IOTRACE,
	       "START file "DNAME":"DFID", ppos: %lld, count: %zu\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       iocb->ki_pos, iov_iter_count(to));

	if (!iov_iter_count(to))
		RETURN(0);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	result = file_read_confine_iter(env, iocb, to);
	if (result < 0)
		GOTO(out, result);
	else if (result > 0)
		stale_data = true;

	CFS_FAIL_TIMEOUT_ORSET(OBD_FAIL_LLITE_READ_PAUSE, CFS_FAIL_ONCE,
			       cfs_fail_val);
	/**
	 * Currently when PCC read failed, we do not fall back to the
	 * normal read path, just return the error.
	 * The resaon is that: for RW-PCC, the file data may be modified
	 * in the PCC and inconsistent with the data on OSTs (or file
	 * data has been removed from the Lustre file system), at this
	 * time, fallback to the normal read path may read the wrong
	 * data.
	 * TODO: for RO-PCC (readonly PCC), fall back to normal read
	 * path: read data from data copy on OSTs.
	 */
	result = pcc_file_read_iter(iocb, to, &cached);
	if (cached)
		GOTO(out, result);

	ll_ras_enter(file, iocb->ki_pos, iov_iter_count(to));

	args = ll_env_args(env);
	args->u.normal.via_iter = to;
	args->u.normal.via_iocb = iocb;

	if (ll_hybrid_bio_dio_switch_check(file, iocb, CIT_READ,
					   iov_iter_count(to)) ||
	    CFS_FAIL_CHECK(OBD_FAIL_LLITE_FORCE_BIO_AS_DIO)) {
#ifdef IOCB_DIRECT
		iocb->ki_flags |= IOCB_DIRECT;
		CDEBUG(D_VFSTRACE, "switching to DIO\n");
		args->via_hybrid_switched = 1;
#endif
	}

	result = ll_do_fast_read(iocb, to);
	if (result < 0 || iov_iter_count(to) == 0)
		GOTO(out, result);

	rc2 = ll_file_io_generic(env, args, file, CIT_READ,
				 &iocb->ki_pos, iov_iter_count(to));
	if (rc2 > 0)
		result += rc2;
	else if (result == 0)
		result = rc2;

out:
	cl_env_put(env, &refcheck);

	if (stale_data && result > 0) {
		/*
		 * we've reached EOF before the read, the data read are cached
		 * stale data.
		 */
		iocb->ki_pos = orig_ki_pos;
		iov_iter_truncate(to, 0);
		result = 0;
	}

	if (result > 0) {
		ll_rw_stats_tally(ll_i2sbi(file_inode(file)), current->pid,
				  file->private_data, iocb->ki_pos, result,
				  READ);
		ll_stats_ops_tally(ll_i2sbi(file_inode(file)), LPROC_LL_READ,
				   ktime_us_delta(ktime_get(), kstart));
	}

	CDEBUG(D_IOTRACE,
	       "COMPLETED: file "DNAME":"DFID", ppos: %lld, count: %zu, rc = %zu\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       iocb->ki_pos, iov_iter_count(to), result);

	RETURN(result);
}

static ssize_t ll_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	if (iter->nr_segs > 1 && is_unaligned_directio(iocb, iter, CIT_READ))
		return do_loop_readv_writev(iocb, iter->__iov, READ,
					    iter->nr_segs, do_file_read_iter);
	return do_file_read_iter(iocb, iter);
}

/*
 * Similar trick to ll_do_fast_read, this improves write speed for tiny writes.
 * If a page is already in the page cache and dirty (and some other things -
 * See ll_tiny_write_begin for the instantiation of these rules), then we can
 * write to it without doing a full I/O, because Lustre already knows about it
 * and will write it out.  This saves a lot of processing time.
 *
 * All writes here are within one page, so exclusion is handled by the page
 * lock on the vm page.  We do not do tiny writes for writes which touch
 * multiple pages because it's very unlikely multiple sequential pages are
 * are already dirty.
 *
 * We limit these to < PAGE_SIZE because PAGE_SIZE writes are relatively common
 * and are unlikely to be to already dirty pages.
 *
 * Attribute updates are important here, we do them in ll_tiny_write_end.
 */
static ssize_t ll_do_tiny_write(struct kiocb *iocb, struct iov_iter *iter)
{
	ssize_t count = iov_iter_count(iter);
	struct  file *file = iocb->ki_filp;
	struct  inode *inode = file_inode(file);
	bool    lock_inode = !IS_NOSEC(inode);
	ssize_t result = 0;

	ENTRY;
	/* Restrict writes to single page and < PAGE_SIZE.  See comment at top
	 * of function for why.
	 */
	if (count >= PAGE_SIZE ||
	    (iocb->ki_pos & (PAGE_SIZE-1)) + count > PAGE_SIZE)
		RETURN(0);
	/* For aarch64's 64k pages maxbytes is inside of a page. */
	if (iocb->ki_pos + count > ll_file_maxbytes(inode))
		RETURN(-EFBIG);

	if (unlikely(lock_inode))
		ll_inode_lock(inode);
	result = __generic_file_write_iter(iocb, iter);

	if (unlikely(lock_inode))
		ll_inode_unlock(inode);

	/* If the page is not already dirty, ll_tiny_write_begin returns
	 * -ENODATA.  We continue on to normal write.
	 */
	if (result == -ENODATA)
		result = 0;

	if (result > 0) {
		ll_heat_add(inode, CIT_WRITE, result);
		set_bit(LLIF_DATA_MODIFIED, &ll_i2info(inode)->lli_flags);
	}

	CDEBUG(D_VFSTRACE, "result: %zu, original count %zu\n", result, count);

	RETURN(result);
}

/* Write to a file (through the page cache).*/
static ssize_t do_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct vvp_io_args *args;
	struct lu_env *env;
	int flags = iocb_ki_flags_get(file, iocb);
	ktime_t kstart = ktime_get();
	bool hybrid_switched = false;
	ssize_t rc_tiny = 0;
	ssize_t rc_normal;
	__u16 refcheck;
	bool cached;
	int result;

	ENTRY;
	CDEBUG(D_VFSTRACE|D_IOTRACE,
	       "START file "DNAME":"DFID", ppos: %lld, count: %zu\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       iocb->ki_pos, iov_iter_count(from));

	if (!iov_iter_count(from))
		GOTO(out, rc_normal = 0);

	/*
	 * When PCC write failed, we usually do not fall back to the normal
	 * write path, just return the error. But there is a special case when
	 * returned error code is -ENOSPC due to running out of space on PCC HSM
	 * bakcend. At this time, it will fall back to normal I/O path and
	 * retry the I/O. As the file is in HSM released state, it will restore
	 * the file data to OSTs first and redo the write again. And the
	 * restore process will revoke the layout lock and detach the file
	 * from PCC cache automatically.
	 */
	result = pcc_file_write_iter(iocb, from, &cached);
	if (cached && result != -ENOSPC && result != -EDQUOT)
		GOTO(out, rc_normal = result);

	if (ll_hybrid_bio_dio_switch_check(file, iocb, CIT_WRITE,
					   iov_iter_count(from)) ||
	    CFS_FAIL_CHECK(OBD_FAIL_LLITE_FORCE_BIO_AS_DIO)) {
#ifdef IOCB_DIRECT
		iocb->ki_flags |= IOCB_DIRECT;
		CDEBUG(D_VFSTRACE, "switching to DIO\n");
		hybrid_switched = true;
#endif
	}

	/* NB: we can't do direct IO for tiny writes because they use the page
	 * cache, we can't do sync writes because tiny writes can't flush
	 * pages, and we can't do append writes because we can't guarantee the
	 * required DLM locks are held to protect file size.
	 */
	if (ll_sbi_has_tiny_write(ll_i2sbi(file_inode(file))) &&
	    !(flags &
	      (ki_flag(DIRECT) | ki_flag(DSYNC) | ki_flag(SYNC) |
	       ki_flag(APPEND))))
		rc_tiny = ll_do_tiny_write(iocb, from);

	/* In case of error, go on and try normal write - Only stop if tiny
	 * write completed I/O.
	 */
	if (iov_iter_count(from) == 0)
		GOTO(out, rc_normal = rc_tiny);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	args = ll_env_args(env);
	args->u.normal.via_iter = from;
	args->u.normal.via_iocb = iocb;
	args->via_hybrid_switched = hybrid_switched;

	rc_normal = ll_file_io_generic(env, args, file, CIT_WRITE,
				       &iocb->ki_pos, iov_iter_count(from));

	/* On success, combine bytes written. */
	if (rc_tiny >= 0 && rc_normal > 0)
		rc_normal += rc_tiny;
	/* On error, only return error from normal write if tiny write did not
	 * write any bytes.  Otherwise return bytes written by tiny write.
	 */
	else if (rc_tiny > 0)
		rc_normal = rc_tiny;

	cl_env_put(env, &refcheck);
out:
	if (rc_normal > 0) {
		ll_rw_stats_tally(ll_i2sbi(file_inode(file)), current->pid,
				  file->private_data, iocb->ki_pos,
				  rc_normal, WRITE);
		ll_stats_ops_tally(ll_i2sbi(file_inode(file)), LPROC_LL_WRITE,
				   ktime_us_delta(ktime_get(), kstart));
	}

	CDEBUG(D_IOTRACE,
	       "COMPLETED: file "DNAME":"DFID", ppos: %lld, count: %zu, rc = %zu\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       iocb->ki_pos, iov_iter_count(from), rc_normal);

	RETURN(rc_normal);
}

static ssize_t ll_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	if (iter->nr_segs > 1 && is_unaligned_directio(iocb, iter, CIT_WRITE))
		return do_loop_readv_writev(iocb, iter->__iov, WRITE,
					    iter->nr_segs, do_file_write_iter);
	return do_file_write_iter(iocb, iter);
}

#ifndef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
/*
 * XXX: exact copy from kernel code (__generic_file_aio_write_nolock)
 */
static int ll_file_get_iov_count(const struct iovec *iov,
				 unsigned long *nr_segs, size_t *count,
				 int access_flags)
{
	size_t cnt = 0;
	unsigned long seg;

	for (seg = 0; seg < *nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		cnt += iv->iov_len;
		if (unlikely((ssize_t)(cnt|iv->iov_len) < 0))
			return -EINVAL;
		if (access_ok(access_flags, iv->iov_base, iv->iov_len))
			continue;
		if (seg == 0)
			return -EFAULT;
		*nr_segs = seg;
		cnt -= iv->iov_len;	/* This segment is no good */
		break;
	}
	*count = cnt;
	return 0;
}

static ssize_t ll_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	struct iov_iter to;
	size_t iov_count;
	ssize_t result;

	ENTRY;
	result = ll_file_get_iov_count(iov, &nr_segs, &iov_count, VERIFY_READ);
	if (result)
		RETURN(result);

	if (!iov_count)
		RETURN(0);

	ll_iov_iter_init(&to, READ, iov, nr_segs, iov_count);

	RETURN(ll_file_read_iter(iocb, &to));
}

static ssize_t ll_file_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = count };
	struct kiocb kiocb;
	ssize_t result;

	ENTRY;
	if (!count)
		RETURN(0);

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = *ppos;
#ifdef HAVE_KIOCB_KI_LEFT
	kiocb.ki_left = count;
#elif defined(HAVE_KI_NBYTES)
	kiocb.i_nbytes = count;
#endif

	result = ll_file_aio_read(&kiocb, &iov, 1, kiocb.ki_pos);
	*ppos = kiocb.ki_pos;

	RETURN(result);
}

/* Write to a file (through the page cache). AIO stuff */
static ssize_t ll_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
				 unsigned long nr_segs, loff_t pos)
{
	struct iov_iter from;
	size_t iov_count;
	ssize_t result;

	ENTRY;
	result = ll_file_get_iov_count(iov, &nr_segs, &iov_count, VERIFY_WRITE);
	if (result)
		RETURN(result);

	if (!iov_count)
		RETURN(0);

	ll_iov_iter_init(&from, WRITE, iov, nr_segs, iov_count);

	RETURN(ll_file_write_iter(iocb, &from));
}

static ssize_t ll_file_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct iovec   iov = { .iov_base = (void __user *)buf,
			       .iov_len = count };
	struct kiocb kiocb;
	ssize_t result;

	ENTRY;
	if (!count)
		RETURN(0);

	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = *ppos;
#ifdef HAVE_KIOCB_KI_LEFT
	kiocb.ki_left = count;
#elif defined(HAVE_KI_NBYTES)
	kiocb.ki_nbytes = count;
#endif

	result = ll_file_aio_write(&kiocb, &iov, 1, kiocb.ki_pos);
	*ppos = kiocb.ki_pos;

	RETURN(result);
}
#endif /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */

int ll_lov_setstripe_ea_info(struct inode *inode, struct dentry *dentry,
			     __u64 flags, struct lov_user_md *lum,
			     ssize_t lum_size)
{
	struct lookup_intent oit = {
		.it_op = IT_OPEN,
		.it_open_flags = flags | MDS_OPEN_BY_FID,
	};
	int rc;

	ENTRY;
	if ((__swab32(lum->lmm_magic) & le32_to_cpu(LOV_MAGIC_MASK)) ==
	    le32_to_cpu(LOV_MAGIC_MAGIC)) {
		/* this code will only exist for big-endian systems */
		lustre_swab_lov_user_md(lum, 0);
	}

	ll_inode_size_lock(inode);
	rc = ll_intent_file_open(dentry, lum, lum_size, &oit);
	if (rc < 0)
		GOTO(out_unlock, rc);

	ll_release_openhandle(dentry, &oit);

out_unlock:
	ll_inode_size_unlock(inode);
	ll_intent_release(&oit);

	RETURN(rc);
}

int ll_lov_getstripe_ea_info(struct inode *inode, const char *filename,
			     struct lov_mds_md **lmmp, int *lmm_size,
			     struct ptlrpc_request **request)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct mdt_body  *body;
	struct lov_mds_md *lmm = NULL;
	struct ptlrpc_request *req = NULL;
	struct md_op_data *op_data;
	int rc, lmmsize;
	int namesize;

	ENTRY;
	rc = ll_get_default_mdsize(sbi, &lmmsize);
	if (rc)
		RETURN(rc);

	namesize = filename ? strlen(filename) : 0;
	op_data = ll_prep_md_op_data(NULL, inode, NULL, filename, namesize,
				     lmmsize, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA;
	rc = md_getattr_name(sbi->ll_md_exp, op_data, &req);
	ll_finish_md_op_data(op_data);
	if (rc < 0) {
		CDEBUG(D_INFO, "md_getattr_name failed on %s: rc %d\n",
		       encode_fn_len(filename, namesize), rc);
		GOTO(out, rc);
	}

	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	LASSERT(body != NULL); /* checked by mdc_getattr_name */

	lmmsize = body->mbo_eadatasize;

	if (!(body->mbo_valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) ||
	    lmmsize == 0)
		GOTO(out, rc = -ENODATA);

	lmm = req_capsule_server_sized_get(&req->rq_pill, &RMF_MDT_MD, lmmsize);
	LASSERT(lmm != NULL);

	if (lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V1) &&
	    lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V3) &&
	    lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_COMP_V1) &&
	    lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_FOREIGN))
		GOTO(out, rc = -EPROTO);

	/*
	 * This is coming from the MDS, so is probably in
	 * little endian. We convert it to host endian before
	 * passing it to userspace.
	 */
	if (cpu_to_le32(LOV_MAGIC) != LOV_MAGIC) {
		int stripe_count = 0;

		if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V1) ||
		    lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V3)) {
			stripe_count = le16_to_cpu(lmm->lmm_stripe_count);
			if (le32_to_cpu(lmm->lmm_pattern) &
			    LOV_PATTERN_F_RELEASED)
				stripe_count = 0;
			lustre_swab_lov_user_md((struct lov_user_md *)lmm, 0);

			/* if function called for directory - we should
			 * avoid swab not existent lsm objects
			 */
			if (lmm->lmm_magic == LOV_MAGIC_V1 &&
			    S_ISREG(body->mbo_mode))
				lustre_swab_lov_user_md_objects(
				((struct lov_user_md_v1 *)lmm)->lmm_objects,
				stripe_count);
			else if (lmm->lmm_magic == LOV_MAGIC_V3 &&
				 S_ISREG(body->mbo_mode))
				lustre_swab_lov_user_md_objects(
				((struct lov_user_md_v3 *)lmm)->lmm_objects,
				stripe_count);
		} else if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_COMP_V1)) {
			lustre_swab_lov_comp_md_v1(
				(struct lov_comp_md_v1 *)lmm);
		}
	}

	if (lmm->lmm_magic == LOV_MAGIC_COMP_V1) {
		struct lov_comp_md_v1 *comp_v1 = NULL;
		struct lov_comp_md_entry_v1 *ent;
		struct lov_user_md_v1 *v1 = NULL;
		__u32 off;
		int i = 0;

		comp_v1 = (struct lov_comp_md_v1 *)lmm;
		/* Dump the striping information */
		for (; i < comp_v1->lcm_entry_count; i++) {
			ent = &comp_v1->lcm_entries[i];
			off = ent->lcme_offset;
			v1 = (struct lov_user_md_v1 *)((char *)lmm + off);
			CDEBUG(D_INFO,
			       "comp[%d]: stripe_count=%u, stripe_size=%u\n",
			       i, v1->lmm_stripe_count, v1->lmm_stripe_size);

			if (unlikely(CFS_FAIL_CHECK(OBD_FAIL_LOV_COMP_MAGIC) &&
				     (cfs_fail_val == i + 1)))
				v1->lmm_magic = LOV_MAGIC_BAD;

			if (unlikely(CFS_FAIL_CHECK(OBD_FAIL_LOV_COMP_PATTERN) &&
				     (cfs_fail_val == i + 1)))
				v1->lmm_pattern = LOV_PATTERN_BAD;
		}

		if (v1 == NULL)
			GOTO(out, rc = -EINVAL);

		lmm->lmm_stripe_count = v1->lmm_stripe_count;
		lmm->lmm_stripe_size = v1->lmm_stripe_size;
		/*
		 * Return valid stripe_count and stripe_size instead of 0 for
		 * DoM files to avoid divide-by-zero for older userspace that
		 * calls this ioctl, e.g. lustre ADIO driver.
		 */
		if (lmm->lmm_stripe_count == 0)
			lmm->lmm_stripe_count = 1;
		if (lmm->lmm_stripe_size == 0) {
			/* Since the first component of the file data is placed
			 * on the MDT for faster access, the stripe_size of the
			 * second one is always that applications which are
			 * doing large IOs.
			 */
			if (lmm->lmm_pattern & LOV_PATTERN_MDT)
				i = comp_v1->lcm_entry_count > 1 ? 1 : 0;
			else
				i = comp_v1->lcm_entry_count > 1 ?
				    comp_v1->lcm_entry_count - 1 : 0;
			ent = &comp_v1->lcm_entries[i];
			off = ent->lcme_offset;
			v1 = (struct lov_user_md_v1 *)((char *)lmm + off);
			lmm->lmm_stripe_size = v1->lmm_stripe_size;
		}
	}
out:
	*lmmp = lmm;
	*lmm_size = lmmsize;
	*request = req;
	RETURN(rc);
}

static int ll_lov_setea(struct inode *inode, struct file *file,
			void __user *arg)
{
	__u64 flags = MDS_OPEN_HAS_OBJS | FMODE_WRITE;
	struct lov_user_md *lump;
	ssize_t lum_size = sizeof(*lump) + sizeof(struct lov_user_ost_data);
	int rc;

	ENTRY;
	if (!capable(CAP_SYS_ADMIN))
		RETURN(-EPERM);

	OBD_ALLOC_LARGE(lump, lum_size);
	if (lump == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(lump, arg, lum_size))
		GOTO(out_lump, rc = -EFAULT);

	rc = ll_lov_setstripe_ea_info(inode, file_dentry(file), flags, lump,
				      lum_size);
	cl_lov_delay_create_clear(&file->f_flags);

out_lump:
	OBD_FREE_LARGE(lump, lum_size);
	RETURN(rc);
}

static int ll_file_getstripe(struct inode *inode, void __user *lum, size_t size)
{
	struct lu_env *env;
	__u16 refcheck;
	int rc;

	ENTRY;
	/* exit before doing any work if pointer is bad */
	if (unlikely(!ll_access_ok(lum, sizeof(struct lov_user_md))))
		RETURN(-EFAULT);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	rc = cl_object_getstripe(env, ll_i2info(inode)->lli_clob, lum, size);
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

static ssize_t ll_lov_setstripe(struct inode *inode, struct file *file,
			    void __user *arg)
{
	struct lov_user_md __user *lum = arg;
	struct lov_user_md *klum;
	ssize_t	lum_size;
	int rc;
	__u64 flags = FMODE_WRITE;

	ENTRY;
	lum_size = ll_copy_user_md(lum, &klum);
	if (lum_size < 0)
		RETURN(lum_size);

	rc = ll_lov_setstripe_ea_info(inode, file_dentry(file), flags, klum,
				      lum_size);
	if (!rc) {
		__u32 gen;

		rc = put_user(0, &lum->lmm_stripe_count);
		if (rc)
			GOTO(out, rc);

		rc = ll_layout_refresh(inode, &gen);
		if (rc)
			GOTO(out, rc);

		rc = ll_file_getstripe(inode, arg, lum_size);
		if (S_ISREG(inode->i_mode) && IS_ENCRYPTED(inode) &&
		    ll_i2info(inode)->lli_clob) {
			struct iattr attr = { 0 };

			rc = cl_setattr_ost(inode, &attr, OP_XVALID_FLAGS,
					    LUSTRE_ENCRYPT_FL);
		}
	}
	cl_lov_delay_create_clear(&file->f_flags);

out:
	OBD_FREE_LARGE(klum, lum_size);
	RETURN(rc);
}


static int
ll_get_grouplock(struct inode *inode, struct file *file, unsigned long arg)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct ll_file_data *lfd = file->private_data;
	struct ll_grouplock grouplock;
	int rc;

	ENTRY;

	if (arg == 0) {
		rc = -EINVAL;
		CWARN("%s: group id for group lock on "DFID" is 0: rc = %d\n",
		      ll_i2sbi(inode)->ll_fsname, PFID(&lli->lli_fid), rc);
		RETURN(rc);
	}

	if (ll_file_nolock(file))
		RETURN(-EOPNOTSUPP);
retry:
	if (file->f_flags & O_NONBLOCK) {
		if (!mutex_trylock(&lli->lli_group_mutex))
			RETURN(-EAGAIN);
	} else {
		mutex_lock(&lli->lli_group_mutex);
	}

	if (lfd->lfd_file_flags & LL_FILE_GROUP_LOCKED) {
		rc =  -EINVAL;
		CWARN("%s: group lock already exists with gid %lu on "DFID": rc = %d\n",
		      ll_i2sbi(inode)->ll_fsname, lfd->fd_grouplock.lg_gid,
		      PFID(&lli->lli_fid), rc);
		GOTO(out, rc);
	}
	if (arg != lli->lli_group_gid && lli->lli_group_users != 0) {
		if (file->f_flags & O_NONBLOCK)
			GOTO(out, rc = -EAGAIN);
		mutex_unlock(&lli->lli_group_mutex);
		wait_var_event(&lli->lli_group_users, !lli->lli_group_users);
		GOTO(retry, rc = 0);
	}
	LASSERT(lfd->fd_grouplock.lg_lock == NULL);

	/*
	 * XXX: group lock needs to protect all OST objects while PFL
	 * can add new OST objects during the IO, so we'd instantiate
	 * all OST objects before getting its group lock.
	 */
	if (obj) {
		struct lu_env *env;
		__u16 refcheck;
		struct cl_layout cl = {
			.cl_is_composite = false,
		};
		struct lu_extent ext = {
			.e_start = 0,
			.e_end = OBD_OBJECT_EOF,
		};

		env = cl_env_get(&refcheck);
		if (IS_ERR(env))
			GOTO(out, rc = PTR_ERR(env));

		rc = cl_object_layout_get(env, obj, &cl);
		if (rc >= 0 && cl.cl_is_composite)
			rc = ll_layout_write_intent(inode, LAYOUT_INTENT_WRITE,
						    &ext);

		cl_env_put(env, &refcheck);
		if (rc < 0)
			GOTO(out, rc);
	}

	rc = cl_get_grouplock(ll_i2info(inode)->lli_clob,
			      arg, (file->f_flags & O_NONBLOCK), &grouplock);

	if (rc)
		GOTO(out, rc);

	lfd->lfd_file_flags |= LL_FILE_GROUP_LOCKED;
	lfd->fd_grouplock = grouplock;
	if (lli->lli_group_users == 0)
		lli->lli_group_gid = grouplock.lg_gid;
	lli->lli_group_users++;

	CDEBUG(D_INFO, "group lock %lu obtained on "DFID"\n",
	       arg, PFID(&lli->lli_fid));
out:
	mutex_unlock(&lli->lli_group_mutex);

	RETURN(rc);
}

static int ll_put_grouplock(struct inode *inode, struct file *file,
			    unsigned long arg)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *lfd = file->private_data;
	struct ll_grouplock grouplock;
	int rc;

	ENTRY;
	mutex_lock(&lli->lli_group_mutex);
	if (!(lfd->lfd_file_flags & LL_FILE_GROUP_LOCKED)) {
		rc = -EINVAL;
		CWARN("%s: no group lock held on "DFID": rc = %d\n",
		      ll_i2sbi(inode)->ll_fsname, PFID(&lli->lli_fid), rc);
		GOTO(out, rc);
	}

	LASSERT(lfd->fd_grouplock.lg_lock != NULL);

	if (lfd->fd_grouplock.lg_gid != arg) {
		rc = -EINVAL;
		CWARN("%s: group lock %lu doesn't match current id %lu on "DFID": rc = %d\n",
		      ll_i2sbi(inode)->ll_fsname, arg, lfd->fd_grouplock.lg_gid,
		      PFID(&lli->lli_fid), rc);
		GOTO(out, rc);
	}

	grouplock = lfd->fd_grouplock;
	memset(&lfd->fd_grouplock, 0, sizeof(lfd->fd_grouplock));
	lfd->lfd_file_flags &= ~LL_FILE_GROUP_LOCKED;

	cl_put_grouplock(&grouplock);

	lli->lli_group_users--;
	if (lli->lli_group_users == 0) {
		lli->lli_group_gid = 0;
		wake_up_var(&lli->lli_group_users);
	}
	CDEBUG(D_INFO, "group lock %lu on "DFID" released\n", arg,
	       PFID(&lli->lli_fid));
	GOTO(out, rc = 0);
out:
	mutex_unlock(&lli->lli_group_mutex);

	RETURN(rc);
}

/**
 * ll_release_openhandle() - Close inode open handle
 * @dentry: dentry which contains the inode
 * @it: [in,out] intent which contains open info and result
 *
 * Return:
 * * %0: Success
 * * <0: Failure
 */
int ll_release_openhandle(struct dentry *dentry, struct lookup_intent *it)
{
	struct inode *inode = dentry->d_inode;
	struct obd_client_handle *och;
	int rc;

	ENTRY;
	LASSERT(inode);

	/* Root ? Do nothing. */
	if (is_root_inode(inode))
		RETURN(0);

	/* No open handle to close? Move away */
	if (!it_disposition(it, DISP_OPEN_OPEN))
		RETURN(0);

	LASSERT(it_open_error(DISP_OPEN_OPEN, it) == 0);

	OBD_ALLOC(och, sizeof(*och));
	if (!och)
		GOTO(out, rc = -ENOMEM);

	rc = ll_och_fill(ll_i2sbi(inode)->ll_md_exp, it, och);
	if (rc)
		GOTO(out, rc);

	rc = ll_close_inode_openhandle(inode, och, 0, NULL);
out:
	/* this one is in place of ll_file_open */
	if (it_disposition(it, DISP_ENQ_OPEN_REF)) {
		ptlrpc_req_put(it->it_request);
		it_clear_disposition(it, DISP_ENQ_OPEN_REF);
	}
	RETURN(rc);
}

/*
 * Get size for inode for which FIEMAP mapping is requested.
 * Make the FIEMAP get_info call and returns the result.
 * \param fiemap	kernel buffer to hold extens
 * \param num_bytes	kernel buffer size
 */
static int ll_do_fiemap(struct inode *inode, struct fiemap *fiemap,
			size_t num_bytes)
{
	struct lu_env *env;
	__u16 refcheck;
	int rc = 0;
	struct ll_fiemap_info_key fmkey = { .lfik_name = KEY_FIEMAP, };

	ENTRY;
	/* Checks for fiemap flags */
	if (fiemap->fm_flags & ~LUSTRE_FIEMAP_FLAGS_COMPAT) {
		fiemap->fm_flags &= ~LUSTRE_FIEMAP_FLAGS_COMPAT;
		return -EBADR;
	}

	/* Check for FIEMAP_FLAG_SYNC */
	if (fiemap->fm_flags & FIEMAP_FLAG_SYNC) {
		rc = filemap_write_and_wait(inode->i_mapping);
		if (rc)
			return rc;
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	if (i_size_read(inode) == 0) {
		rc = ll_glimpse_size(inode);
		if (rc)
			GOTO(out, rc);
	}

	fmkey.lfik_oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP | OBD_MD_FLPROJID;
	obdo_from_inode(&fmkey.lfik_oa, inode, OBD_MD_FLSIZE);
	obdo_set_parent_fid(&fmkey.lfik_oa, &ll_i2info(inode)->lli_fid);

	/* If filesize is 0, then there would be no objects for mapping */
	if (fmkey.lfik_oa.o_size == 0) {
		fiemap->fm_mapped_extents = 0;
		GOTO(out, rc = 0);
	}

	fmkey.lfik_fiemap = *fiemap;

	rc = cl_object_fiemap(env, ll_i2info(inode)->lli_clob,
			      &fmkey, fiemap, &num_bytes);
out:
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

static int fid2path_for_enc_file(struct inode *parent, char *gfpath,
				 __u32 gfpathlen)
{
	struct dentry *de = NULL, *de_parent = d_find_any_alias(parent);
	struct llcrypt_str lltr = LLTR_INIT(NULL, 0);
	struct llcrypt_str de_name;
	char *p, *ptr = gfpath;
	size_t len = 0, len_orig = 0;
	int enckey = -1, nameenc = -1;
	int rc = 0;

	gfpath++;
	while ((p = strsep(&gfpath, "/")) != NULL) {
		struct lu_fid fid;

		de = NULL;
		if (!*p) {
			dput(de_parent);
			break;
		}
		len_orig = strlen(p);

		rc = sscanf(p, "["SFID"]", RFID(&fid));
		if (rc == 3)
			p = strchr(p, ']') + 1;
		else
			fid_zero(&fid);
		rc = 0;
		len = strlen(p);

		if (!IS_ENCRYPTED(parent)) {
			if (gfpathlen < len + 1) {
				dput(de_parent);
				rc = -EOVERFLOW;
				break;
			}
			memmove(ptr, p, len);
			p = ptr;
			ptr += len;
			*(ptr++) = '/';
			gfpathlen -= len + 1;
			goto lookup;
		}

		/* From here, we know parent is encrypted */

		if (enckey != 0) {
			rc = llcrypt_prepare_readdir(parent);
			if (rc && rc != -ENOKEY) {
				dput(de_parent);
				break;
			}
		}

		if (enckey == -1) {
			if (llcrypt_has_encryption_key(parent))
				enckey = 1;
			else
				enckey = 0;
			if (enckey == 1)
				nameenc =
					llcrypt_policy_has_filename_enc(parent);
		}

		/* Even if names are not encrypted, we still need to call
		 * ll_fname_disk_to_usr in order to decode names as they are
		 * coming from the wire.
		 */
		rc = llcrypt_fname_alloc_buffer(parent, NAME_MAX + 1, &lltr);
		if (rc < 0) {
			dput(de_parent);
			break;
		}

		de_name.name = p;
		de_name.len = len;
		rc = ll_fname_disk_to_usr(parent, 0, 0, &de_name,
					  &lltr, &fid);
		if (rc) {
			llcrypt_fname_free_buffer(&lltr);
			dput(de_parent);
			break;
		}
		lltr.name[lltr.len] = '\0';

		if (lltr.len <= len_orig && gfpathlen >= lltr.len + 1) {
			memcpy(ptr, lltr.name, lltr.len);
			p = ptr;
			len = lltr.len;
			ptr += lltr.len;
			*(ptr++) = '/';
			gfpathlen -= lltr.len + 1;
		} else {
			rc = -EOVERFLOW;
		}
		llcrypt_fname_free_buffer(&lltr);

		if (rc == -EOVERFLOW) {
			dput(de_parent);
			break;
		}

lookup:
		if (!gfpath) {
			/* We reached the end of the string, which means
			 * we are dealing with the last component in the path.
			 * So save a useless lookup and exit.
			 */
			dput(de_parent);
			break;
		}

		if (enckey == 0 || nameenc == 0)
			continue;

		ll_inode_lock(parent);
		de = lookup_one_len(p, de_parent, len);
		ll_inode_unlock(parent);
		if (IS_ERR_OR_NULL(de) || !de->d_inode) {
			dput(de_parent);
			rc = -ENODATA;
			break;
		}

		parent = de->d_inode;
		dput(de_parent);
		de_parent = de;
	}

	if (len)
		*(ptr - 1) = '\0';
	if (!IS_ERR_OR_NULL(de))
		dput(de);
	return rc;
}

/**
 * The FID provided could be either an MDT FID or an OST FID, both need to
 * be handled here.
 * 1. query from fldb-server the actual type of this FID
 * 2a. if it's an OST-FID, try OSC_IOCONTROL(FID2PATH) with given FID, which
 * should return the corresponding parent FID, i.e. the MDT FID
 * 2b. otherwise it's a MDT FID already, continue to step 3
 * 3. take the MDT FID calling MDC_IOCONTROL(FID2PATH)
 */
int __ll_fid2path(struct inode *inode, struct getinfo_fid2path *gfout,
		  size_t outsize, __u32 pathlen_orig)
{
	struct obd_export *exp = ll_i2mdexp(inode);
	struct obd_device *md_exp = ll_i2sbi(inode)->ll_md_exp->exp_obd;
	struct lmv_obd *lmv = &md_exp->u.lmv;
	struct lu_seq_range res = {0};
	int rc;

	rc = fld_client_lookup(&lmv->lmv_fld, fid_seq(&gfout->gf_fid),
			       LU_SEQ_RANGE_ANY, NULL, &res);
	if (rc) {
		CDEBUG(D_IOCTL,
		       "%s: Error looking for target idx. Seq %#llx: rc=%d\n",
		       md_exp->obd_name, fid_seq(&gfout->gf_fid), rc);
		RETURN(rc);
	}

	/* Call osc_iocontrol */
	if (res.lsr_flags == LU_SEQ_RANGE_OST) {
		__u64 gf_recno = gfout->gf_recno;
		__u32 gf_linkno = gfout->gf_linkno;
		struct obd_export *dt_exp = ll_i2dtexp(inode);

		/* Pass 'ost_idx' down to the lower layer via u.gf_root_fid,
		 * which is a non-functional field in the OST context
		 */
		gfout->gf_u.gf_root_fid->f_oid = res.lsr_index;

		rc = obd_iocontrol(OBD_IOC_FID2PATH, dt_exp, outsize, gfout,
				   NULL);
		if (rc) {
			CDEBUG(D_IOCTL,
			       "%s: Err on FID2PATH(OST), Seq %#llx: rc=%d\n",
			       md_exp->obd_name, fid_seq(&gfout->gf_fid), rc);
			RETURN(rc);
		}
		gfout->gf_recno = gf_recno;
		gfout->gf_linkno = gf_linkno;
	}

	/* Append root FID after gfout to let MDT know the root FID so that
	 * it can lookup the correct path, this is mainly for fileset.
	 * old server without fileset mount support will ignore this.
	 */
	*gfout->gf_u.gf_root_fid = *ll_inode2fid(inode);

	/* Call mdc_iocontrol */
	rc = obd_iocontrol(OBD_IOC_FID2PATH, exp, outsize, gfout, NULL);

	if (!rc && gfout->gf_pathlen && gfout->gf_u.gf_path[0] == '/') {
		/* by convention, server side (mdt_path_current()) puts
		 * a leading '/' to tell client that we are dealing with
		 * an encrypted file
		 */
		rc = fid2path_for_enc_file(inode, gfout->gf_u.gf_path,
					   gfout->gf_pathlen);
		if (!rc && strlen(gfout->gf_u.gf_path) > pathlen_orig)
			rc = -EOVERFLOW;
	}

	return rc;
}

int ll_fid2path(struct inode *inode, void __user *arg)
{
	const struct getinfo_fid2path __user *gfin = arg;
	__u32 pathlen, pathlen_orig;
	struct getinfo_fid2path *gfout;
	size_t outsize;
	int rc = 0;

	ENTRY;
	if (!capable(CAP_DAC_READ_SEARCH) &&
	    !test_bit(LL_SBI_USER_FID2PATH, ll_i2sbi(inode)->ll_flags))
		RETURN(-EPERM);

	/* Only need to get the buflen */
	if (get_user(pathlen, &gfin->gf_pathlen))
		RETURN(-EFAULT);

	pathlen_orig = pathlen;

gf_alloc:
	outsize = sizeof(*gfout) + pathlen;
	OBD_ALLOC(gfout, outsize);
	if (gfout == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(gfout, arg, sizeof(*gfout)))
		GOTO(gf_free, rc = -EFAULT);

	gfout->gf_pathlen = pathlen;
	rc = __ll_fid2path(inode, gfout, outsize, pathlen_orig);
	if (rc)
		GOTO(gf_free, rc);

	if (copy_to_user(arg, gfout, sizeof(*gfout) + pathlen_orig))
		rc = -EFAULT;

gf_free:
	OBD_FREE(gfout, outsize);
	if (rc == -ENAMETOOLONG) {
		pathlen += PATH_MAX;
		GOTO(gf_alloc, rc);
	}
	RETURN(rc);
}

static int
ll_ioc_data_version(struct inode *inode, struct ioc_data_version *ioc)
{
	struct cl_object *obj = ll_i2info(inode)->lli_clob;
	struct lu_env *env;
	struct cl_io *io;
	__u16  refcheck;
	int result;

	ENTRY;
	ioc->idv_version = 0;
	ioc->idv_layout_version = UINT_MAX;

	/* If no file object initialized, we consider its version is 0. */
	if (obj == NULL)
		RETURN(0);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = vvp_env_new_io(env);
	io->ci_obj = obj;
	io->u.ci_data_version.dv_data_version = 0;
	io->u.ci_data_version.dv_layout_version = UINT_MAX;
	io->u.ci_data_version.dv_flags = ioc->idv_flags;

restart:
	if (cl_io_init(env, io, CIT_DATA_VERSION, io->ci_obj) == 0)
		result = cl_io_loop(env, io);
	else
		result = io->ci_result;

	ioc->idv_version = io->u.ci_data_version.dv_data_version;
	ioc->idv_layout_version = io->u.ci_data_version.dv_layout_version;
	cl_io_fini(env, io);

	if (unlikely(io->ci_need_restart))
		goto restart;

	cl_env_put(env, &refcheck);

	RETURN(result);
}

/**
 * ll_data_version() - retrieve the data version of a file
 * @inode: inode of the file for which the data version is being queried
 * @data_version: store the retrieved data version
 * @flags:  if do sync on the OST side;
 *		0: no sync
 *		LL_DV_RD_FLUSH: flush dirty pages, LCK_PR on OSTs
 *		LL_DV_WR_FLUSH: drop all caching pages, LCK_PW on OSTs
 *
 * This value is computed using stripe object version on OST.
 * Version is computed using server side locking.
 *
 * Return:
 * * %0: Success
 * * %<0: Failure
 */
int ll_data_version(struct inode *inode, __u64 *data_version, int flags)
{
	struct ioc_data_version ioc = { .idv_flags = flags };
	int rc;

	rc = ll_ioc_data_version(inode, &ioc);
	if (!rc)
		*data_version = ioc.idv_version;

	return rc;
}

/* Trigger a HSM release request for the provided inode.  */
int ll_hsm_release(struct inode *inode)
{
	struct lu_env *env;
	struct obd_client_handle *och = NULL;
	__u64 data_version = 0;
	__u16 refcheck;
	int rc;

	ENTRY;
	CDEBUG(D_INODE, "%s: Releasing file "DFID".\n",
	       ll_i2sbi(inode)->ll_fsname,
	       PFID(&ll_i2info(inode)->lli_fid));

	och = ll_lease_open(inode, NULL, FMODE_WRITE, MDS_OPEN_RELEASE);
	if (IS_ERR(och))
		GOTO(out, rc = PTR_ERR(och));

	/* Grab latest data_version and [am]time values */
	rc = ll_data_version(inode, &data_version,
			     LL_DV_WR_FLUSH | LL_DV_SZ_UPDATE);
	if (rc != 0)
		GOTO(out, rc);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		GOTO(out, rc = PTR_ERR(env));

	rc = ll_merge_attr(env, inode);
	cl_env_put(env, &refcheck);

	/* If error happen, we have the wrong size for a file.
	 * Don't release it.
	 */
	if (rc != 0)
		GOTO(out, rc);

	/* Release the file. NB: lease lock handle is released in
	 * mdc_hsm_release_pack() because we still need it to pack
	 * l_remote_handle to MDT.
	 */
	rc = ll_close_inode_openhandle(inode, och, MDS_HSM_RELEASE,
				       &data_version);
	och = NULL;

	EXIT;
out:
	if (och != NULL && !IS_ERR(och)) /* close the file */
		ll_lease_close(och, inode, NULL);

	return rc;
}

struct ll_swap_stack {
	__u64			 dv1;
	__u64			 dv2;
	struct inode		*inode1;
	struct inode		*inode2;
	bool			 check_dv1;
	bool			 check_dv2;
};

static int ll_swap_layouts(struct file *file1, struct file *file2,
			   struct lustre_swap_layouts *lsl)
{
	struct mdc_swap_layouts msl;
	struct md_op_data *op_data;
	__u32 gid;
	__u64 dv;
	struct ll_swap_stack *llss = NULL;
	int rc;

	OBD_ALLOC_PTR(llss);
	if (llss == NULL)
		RETURN(-ENOMEM);

	llss->inode1 = file_inode(file1);
	llss->inode2 = file_inode(file2);

	rc = ll_check_swap_layouts_validity(llss->inode1, llss->inode2);
	if (rc < 0)
		GOTO(free, rc);

	/* we use 2 bool because it is easier to swap than 2 bits */
	if (lsl->sl_flags & SWAP_LAYOUTS_CHECK_DV1)
		llss->check_dv1 = true;

	if (lsl->sl_flags & SWAP_LAYOUTS_CHECK_DV2)
		llss->check_dv2 = true;

	/* we cannot use lsl->sl_dvX directly because we may swap them */
	llss->dv1 = lsl->sl_dv1;
	llss->dv2 = lsl->sl_dv2;

	rc = lu_fid_cmp(ll_inode2fid(llss->inode1), ll_inode2fid(llss->inode2));
	if (rc == 0) /* same file, done! */
		GOTO(free, rc);

	if (rc < 0) { /* sequentialize it */
		swap(llss->inode1, llss->inode2);
		swap(file1, file2);
		swap(llss->dv1, llss->dv2);
		swap(llss->check_dv1, llss->check_dv2);
	}

	gid = lsl->sl_gid;
	if (gid != 0) { /* application asks to flush dirty cache */
		rc = ll_get_grouplock(llss->inode1, file1, gid);
		if (rc < 0)
			GOTO(free, rc);

		rc = ll_get_grouplock(llss->inode2, file2, gid);
		if (rc < 0) {
			ll_put_grouplock(llss->inode1, file1, gid);
			GOTO(free, rc);
		}
	}

	/* ultimate check, before swaping the layouts we check if
	 * dataversion has changed (if requested)
	 */
	if (llss->check_dv1) {
		rc = ll_data_version(llss->inode1, &dv, 0);
		if (rc)
			GOTO(putgl, rc);
		if (dv != llss->dv1)
			GOTO(putgl, rc = -EAGAIN);
	}

	if (llss->check_dv2) {
		rc = ll_data_version(llss->inode2, &dv, 0);
		if (rc)
			GOTO(putgl, rc);
		if (dv != llss->dv2)
			GOTO(putgl, rc = -EAGAIN);
	}

	/* struct md_op_data is used to send the swap args to the mdt
	 * only flags is missing, so we use struct mdc_swap_layouts
	 * through the md_op_data->op_data
	 *
	 * flags from user space have to be converted before they are send to
	 * server, no flag is sent today, they are only used on the client
	 */
	msl.msl_flags = 0;
	rc = -ENOMEM;
	op_data = ll_prep_md_op_data(NULL, llss->inode1, llss->inode2, NULL, 0,
				     0, LUSTRE_OPC_ANY, &msl);
	if (IS_ERR(op_data))
		GOTO(free, rc = PTR_ERR(op_data));

	rc = obd_iocontrol(LL_IOC_LOV_SWAP_LAYOUTS, ll_i2mdexp(llss->inode1),
			   sizeof(*op_data), op_data, NULL);
	ll_finish_md_op_data(op_data);

	if (rc < 0)
		GOTO(putgl, rc);

putgl:
	if (gid != 0) {
		ll_put_grouplock(llss->inode2, file2, gid);
		ll_put_grouplock(llss->inode1, file1, gid);
	}

free:
	OBD_FREE_PTR(llss);

	RETURN(rc);
}

int ll_hsm_state_set(struct inode *inode, struct hsm_state_set *hss)
{
	struct obd_export *exp = ll_i2mdexp(inode);
	struct md_op_data *op_data;
	int rc;

	ENTRY;
	/* Detect out-of range masks */
	if ((hss->hss_setmask | hss->hss_clearmask) & ~HSM_FLAGS_MASK)
		RETURN(-EINVAL);

	/* Non-root users are forbidden to set or clear flags which are
	 * NOT defined in HSM_USER_MASK.
	 */
	if (((hss->hss_setmask | hss->hss_clearmask) & ~HSM_USER_MASK) &&
	    !capable(CAP_SYS_ADMIN))
		RETURN(-EPERM);

	if (!exp_connect_archive_id_array(exp)) {
		/* Detect out-of range archive id */
		if ((hss->hss_valid & HSS_ARCHIVE_ID) &&
		    (hss->hss_archive_id > LL_HSM_ORIGIN_MAX_ARCHIVE))
			RETURN(-EINVAL);
	}

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, hss);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	rc = obd_iocontrol(LL_IOC_HSM_STATE_SET, exp, sizeof(*op_data),
			   op_data, NULL);

	ll_finish_md_op_data(op_data);

	RETURN(rc);
}

static int ll_hsm_data_version_sync(struct inode *inode, __u64 data_version)
{
	struct obd_export *exp = ll_i2mdexp(inode);
	struct md_op_data *op_data;
	int rc;
	ENTRY;

	if (!data_version)
		RETURN(-EINVAL);

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_data_version = data_version;

	rc = obd_iocontrol(LL_IOC_HSM_DATA_VERSION, exp, sizeof(*op_data),
			   op_data, NULL);

	ll_finish_md_op_data(op_data);

	RETURN(rc);
}

static int ll_hsm_import(struct inode *inode, struct file *file,
			 struct hsm_user_import *hui)
{
	struct hsm_state_set *hss = NULL;
	struct iattr *attr = NULL;
	int rc;

	ENTRY;
	if (!S_ISREG(inode->i_mode))
		RETURN(-EINVAL);

	/* set HSM flags */
	OBD_ALLOC_PTR(hss);
	if (hss == NULL)
		GOTO(out, rc = -ENOMEM);

	hss->hss_valid = HSS_SETMASK | HSS_ARCHIVE_ID;
	hss->hss_archive_id = hui->hui_archive_id;
	hss->hss_setmask = HS_ARCHIVED | HS_EXISTS | HS_RELEASED;
	rc = ll_hsm_state_set(inode, hss);
	if (rc != 0)
		GOTO(out, rc);

	OBD_ALLOC_PTR(attr);
	if (attr == NULL)
		GOTO(out, rc = -ENOMEM);

	attr->ia_mode = hui->hui_mode & (0777);
	attr->ia_mode |= S_IFREG;
	attr->ia_uid = make_kuid(&init_user_ns, hui->hui_uid);
	attr->ia_gid = make_kgid(&init_user_ns, hui->hui_gid);
	attr->ia_size = hui->hui_size;
	attr->ia_mtime.tv_sec = hui->hui_mtime;
	attr->ia_mtime.tv_nsec = hui->hui_mtime_ns;
	attr->ia_atime.tv_sec = hui->hui_atime;
	attr->ia_atime.tv_nsec = hui->hui_atime_ns;

	attr->ia_valid = ATTR_SIZE | ATTR_MODE | ATTR_FORCE |
			 ATTR_UID | ATTR_GID |
			 ATTR_MTIME | ATTR_MTIME_SET |
			 ATTR_ATIME | ATTR_ATIME_SET;

	inode_lock(inode);
	/* inode lock owner set in ll_setattr_raw()*/
	rc = ll_setattr_raw(file_dentry(file), attr, 0, true);
	if (rc == -ENODATA)
		rc = 0;
	inode_unlock(inode);

out:
	OBD_FREE_PTR(hss);

	OBD_FREE_PTR(attr);

	RETURN(rc);
}

static inline long ll_lease_type_from_open_flags(enum mds_open_flags
						 fd_open_mode)
{
	return ((fd_open_mode & MDS_FMODE_READ) ? LL_LEASE_RDLCK : 0) |
	       ((fd_open_mode & MDS_FMODE_WRITE) ? LL_LEASE_WRLCK : 0);
}

static int ll_file_futimes_3(struct file *file, const struct ll_futimes_3 *lfu)
{
	struct inode *inode = file_inode(file);
	struct iattr ia = {
		.ia_valid = ATTR_ATIME | ATTR_ATIME_SET |
			    ATTR_MTIME | ATTR_MTIME_SET |
			    ATTR_CTIME,
		.ia_atime = {
			.tv_sec = lfu->lfu_atime_sec,
			.tv_nsec = lfu->lfu_atime_nsec,
		},
		.ia_mtime = {
			.tv_sec = lfu->lfu_mtime_sec,
			.tv_nsec = lfu->lfu_mtime_nsec,
		},
		.ia_ctime = {
			.tv_sec = lfu->lfu_ctime_sec,
			.tv_nsec = lfu->lfu_ctime_nsec,
		},
	};
	int rc;

	ENTRY;
	if (!capable(CAP_SYS_ADMIN))
		RETURN(-EPERM);

	if (!S_ISREG(inode->i_mode))
		RETURN(-EINVAL);

	inode_lock(inode);
	/* inode lock owner set in ll_setattr_raw()*/
	rc = ll_setattr_raw(file_dentry(file), &ia, OP_XVALID_CTIME_SET,
			    false);
	inode_unlock(inode);

	RETURN(rc);
}

static enum cl_lock_mode cl_mode_user_to_kernel(enum lock_mode_user mode)
{
	switch (mode) {
	case MODE_READ_USER:
		return CLM_READ;
	case MODE_WRITE_USER:
		return CLM_WRITE;
	default:
		return -EINVAL;
	}
}

static const char *const user_lockname[] = LOCK_MODE_NAMES;

/**
 * ll_file_lock_ahead() -
 * @file: file this ladvise lock request is on
 * @ladvise: ladvise struct describing this lock request
 *
 * Used to allow the upper layers of the client to request an LDLM lock
 * without doing an actual read or write.
 *
 * Used for ladvise lockahead to manually request specific locks.
 *
 * Return:
 * * %0: success, no detailed result available (sync requests
 *       and requests sent to the server [not handled locally]
 *       cannot return detailed results)
 * * %<0: negative errno on error
 * * LLA_RESULT_{SAME,DIFFERENT} - detailed result of the lock request,
 *					 see definitions for details.
 */
int ll_file_lock_ahead(struct file *file, struct llapi_lu_ladvise *ladvise)
{
	struct lu_env *env = NULL;
	struct cl_io *io  = NULL;
	struct cl_lock *lock = NULL;
	struct cl_lock_descr *descr = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	enum cl_lock_mode cl_mode;
	off_t start = ladvise->lla_start;
	off_t end = ladvise->lla_end;
	int result;
	__u16 refcheck;

	ENTRY;
	CDEBUG(D_VFSTRACE,
	       "Lock request: file="DNAME", inode=%p, mode=%s start=%llu, end=%llu\n",
	       encode_fn_dentry(dentry), dentry->d_inode,
	       user_lockname[ladvise->lla_lockahead_mode], (__u64) start,
	       (__u64) end);

	cl_mode = cl_mode_user_to_kernel(ladvise->lla_lockahead_mode);
	if (cl_mode < 0)
		GOTO(out, result = cl_mode);

	/* Get IO environment */
	result = cl_io_get(inode, &env, &io, &refcheck);
	if (result <= 0)
		GOTO(out, result);

	result = cl_io_init(env, io, CIT_MISC, io->ci_obj);
	if (result > 0) {
		/*
		 * nothing to do for this io. This currently happens when
		 * stripe sub-object's are not yet created.
		 */
		result = io->ci_result;
	} else if (result == 0) {
		lock = vvp_env_new_lock(env);
		descr = &lock->cll_descr;

		descr->cld_obj   = io->ci_obj;
		/* Convert byte offsets to pages */
		descr->cld_start = start >> PAGE_SHIFT;
		descr->cld_end   = end >> PAGE_SHIFT;
		descr->cld_mode  = cl_mode;
		/* CEF_MUST is used because we do not want to convert a
		 * lockahead request to a lockless lock
		 */
		descr->cld_enq_flags = CEF_MUST | CEF_LOCK_NO_EXPAND;

		if (ladvise->lla_peradvice_flags & LF_ASYNC)
			descr->cld_enq_flags |= CEF_SPECULATIVE;

		result = cl_lock_request(env, io, lock);

		/* On success, we need to release the lock */
		if (result >= 0)
			cl_lock_release(env, lock);
	}
	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);

	/* -ECANCELED indicates a matching lock with a different extent
	 * was already present, and -EEXIST indicates a matching lock
	 * on exactly the same extent was already present.
	 * We convert them to positive values for userspace to make
	 * recognizing true errors easier.
	 * Note we can only return these detailed results on async requests,
	 * as sync requests look the same as i/o requests for locking.
	 */
	if (result == -ECANCELED)
		result = LLA_RESULT_DIFFERENT;
	else if (result == -EEXIST)
		result = LLA_RESULT_SAME;

out:
	RETURN(result);
}
static const char *const ladvise_names[] = LU_LADVISE_NAMES;

static int ll_ladvise_sanity(struct inode *inode,
			     struct llapi_lu_ladvise *ladvise)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	enum lu_ladvise_type advice = ladvise->lla_advice;
	/* Note the peradvice flags is a 32 bit field, so per advice flags must
	 * be in the first 32 bits of enum ladvise_flags
	 */
	__u32 flags = ladvise->lla_peradvice_flags;
	/* 3 lines at 80 characters per line, should be plenty */
	int rc = 0;

	if (advice > LU_LADVISE_MAX || advice == LU_LADVISE_INVALID) {
		rc = -EINVAL;
		CDEBUG(D_VFSTRACE,
		       "%s: advice with value '%d' not recognized, last supported advice is %s (value '%d'): rc = %d\n",
		       sbi->ll_fsname, advice,
		       ladvise_names[LU_LADVISE_MAX-1], LU_LADVISE_MAX-1, rc);
		GOTO(out, rc);
	}

	/* Per-advice checks */
	switch (advice) {
	case LU_LADVISE_LOCKNOEXPAND:
		if (flags & ~LF_LOCKNOEXPAND_MASK) {
			rc = -EINVAL;
			CDEBUG(D_VFSTRACE, "%s: Invalid flags (%x) for %s: rc = %d\n",
			       sbi->ll_fsname, flags,
			       ladvise_names[advice], rc);
			GOTO(out, rc);
		}
		break;
	case LU_LADVISE_LOCKAHEAD:
		/* Currently only READ and WRITE modes can be requested */
		if (ladvise->lla_lockahead_mode >= MODE_MAX_USER ||
		    ladvise->lla_lockahead_mode == 0) {
			rc = -EINVAL;
			CDEBUG(D_VFSTRACE, "%s: Invalid mode (%d) for %s: rc = %d\n",
			       sbi->ll_fsname,
			       ladvise->lla_lockahead_mode,
			       ladvise_names[advice], rc);
			GOTO(out, rc);
		}
		fallthrough;
	case LU_LADVISE_WILLREAD:
	case LU_LADVISE_DONTNEED:
	default:
		/* Note fall through above - These checks apply to all advices
		 * except LOCKNOEXPAND
		 */
		if (flags & ~LF_DEFAULT_MASK) {
			rc = -EINVAL;
			CDEBUG(D_VFSTRACE, "%s: Invalid flags (%x) for %s: rc = %d\n",
			       sbi->ll_fsname, flags,
			       ladvise_names[advice], rc);
			GOTO(out, rc);
		}
		if (ladvise->lla_start >= ladvise->lla_end) {
			rc = -EINVAL;
			CDEBUG(D_VFSTRACE, "%s: Invalid range (%llu to %llu) for %s: rc = %d\n",
			       sbi->ll_fsname,
			       ladvise->lla_start, ladvise->lla_end,
			       ladvise_names[advice], rc);
			GOTO(out, rc);
		}
		break;
	}

out:
	return rc;
}
#undef ERRSIZE

/*
 * Give file access advices
 *
 * The ladvise interface is similar to Linux fadvise() system call, except it
 * forwards the advices directly from Lustre client to server. The server side
 * codes will apply appropriate read-ahead and caching techniques for the
 * corresponding files.
 *
 * A typical workload for ladvise is e.g. a bunch of different clients are
 * doing small random reads of a file, so prefetching pages into OSS cache
 * with big linear reads before the random IO is a net benefit. Fetching
 * all that data into each client cache with fadvise() may not be, due to
 * much more data being sent to the client.
 */
static int ll_ladvise(struct inode *inode, struct file *file, __u64 flags,
		      struct llapi_lu_ladvise *ladvise)
{
	struct lu_env *env;
	struct cl_io *io;
	struct cl_ladvise_io *lio;
	int rc;
	__u16 refcheck;

	ENTRY;
	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = vvp_env_new_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;

	/* initialize parameters for ladvise */
	lio = &io->u.ci_ladvise;
	lio->lio_start = ladvise->lla_start;
	lio->lio_end = ladvise->lla_end;
	lio->lio_fid = ll_inode2fid(inode);
	lio->lio_advice = ladvise->lla_advice;
	lio->lio_flags = flags;

	if (cl_io_init(env, io, CIT_LADVISE, io->ci_obj) == 0)
		rc = cl_io_loop(env, io);
	else
		rc = io->ci_result;

	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

static int ll_lock_noexpand(struct file *file, int flags)
{
	struct ll_file_data *lfd = file->private_data;

	lfd->lfd_lock_no_expand = !(flags & LF_UNSET);

	return 0;
}

#ifndef HAVE_FILEATTR_GET
int ll_ioctl_fsgetxattr(struct inode *inode, unsigned int cmd,
			void __user *uarg)
{
	struct fsxattr fsxattr;

	if (copy_from_user(&fsxattr, uarg, sizeof(fsxattr)))
		RETURN(-EFAULT);

	fsxattr.fsx_xflags = ll_inode_flags_to_xflags(inode->i_flags);
	if (test_bit(LLIF_PROJECT_INHERIT, &ll_i2info(inode)->lli_flags))
		fsxattr.fsx_xflags |= FS_XFLAG_PROJINHERIT;
	fsxattr.fsx_projid = ll_i2info(inode)->lli_projid;
	if (copy_to_user(uarg, &fsxattr, sizeof(fsxattr)))
		RETURN(-EFAULT);

	RETURN(0);
}
#endif

int ll_ioctl_check_project(struct inode *inode, __u32 xflags,
			   __u32 projid)
{
	/*
	 * Project Quota ID state is only allowed to change from within the init
	 * namespace. Enforce that restriction only if we are trying to change
	 * the quota ID state. Everything else is allowed in user namespaces.
	 */
	if (current_user_ns() == &init_user_ns) {
		/*
		 * Caller is allowed to change the project ID. if it is being
		 * changed, make sure that the new value is valid.
		 */
		if (ll_i2info(inode)->lli_projid != projid &&
		     !projid_valid(make_kprojid(&init_user_ns, projid)))
			return -EINVAL;

		return 0;
	}

	if (ll_i2info(inode)->lli_projid != projid)
		return -EINVAL;

	if (test_bit(LLIF_PROJECT_INHERIT, &ll_i2info(inode)->lli_flags)) {
		if (!(xflags & FS_XFLAG_PROJINHERIT))
			return -EINVAL;
	} else {
		if (xflags & FS_XFLAG_PROJINHERIT)
			return -EINVAL;
	}

	return 0;
}

int ll_set_project(struct inode *inode, __u32 xflags, __u32 projid)
{
	struct ptlrpc_request *req = NULL;
	struct md_op_data *op_data;
	int rc = 0;

	CDEBUG(D_QUOTA, DFID" xflags=%x projid=%u\n",
	       PFID(ll_inode2fid(inode)), xflags, projid);
	rc = ll_ioctl_check_project(inode, xflags, projid);
	if (rc)
		RETURN(rc);

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_attr_flags = ll_xflags_to_ext_flags(xflags);

	/* pass projid to md_op_data */
	op_data->op_projid = projid;

	op_data->op_xvalid |= OP_XVALID_PROJID | OP_XVALID_FLAGS;
	rc = md_setattr(ll_i2sbi(inode)->ll_md_exp, op_data, NULL, 0, &req);
	ptlrpc_req_put(req);
	if (rc)
		GOTO(out_fsxattr, rc);
	ll_update_inode_flags(inode, op_data->op_attr_flags);

	/* Avoid OST RPC if this is only ioctl setting project inherit flag */
	if (xflags == 0 || xflags == FS_XFLAG_PROJINHERIT)
		GOTO(out_fsxattr, rc);

	if (ll_i2info(inode)->lli_clob) {
		struct iattr attr = { 0 };

		rc = cl_setattr_ost(inode, &attr, OP_XVALID_FLAGS, xflags);
	}

out_fsxattr:
	ll_finish_md_op_data(op_data);
	RETURN(rc);
}

#ifndef HAVE_FILEATTR_GET
int ll_ioctl_fssetxattr(struct inode *inode, unsigned int cmd,
			void __user *uarg)
{
	struct fsxattr fsxattr;

	ENTRY;
	if (copy_from_user(&fsxattr, uarg, sizeof(fsxattr)))
		RETURN(-EFAULT);

	RETURN(ll_set_project(inode, fsxattr.fsx_xflags,
			      fsxattr.fsx_projid));
}
#endif

int ll_ioctl_project(struct file *file, unsigned int cmd, void __user *uarg)
{
	struct lu_project lu_project;
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = file_inode(file);
	struct dentry *child_dentry = NULL;
	int rc = 0, name_len;

	if (copy_from_user(&lu_project, uarg, sizeof(lu_project)))
		RETURN(-EFAULT);

	/* apply child dentry if name is valid */
	name_len = strnlen(lu_project.project_name, NAME_MAX);
	if (name_len > 0 && name_len <= NAME_MAX) {
		ll_inode_lock(inode);
		child_dentry = lookup_one_len(lu_project.project_name,
					      dentry, name_len);
		ll_inode_unlock(inode);
		if (IS_ERR(child_dentry)) {
			rc = PTR_ERR(child_dentry);
			goto out;
		}
		inode = child_dentry->d_inode;
		if (!inode) {
			rc = -ENOENT;
			goto out;
		}
	} else if (name_len > NAME_MAX) {
		rc = -EINVAL;
		goto out;
	}

	switch (lu_project.project_type) {
	case LU_PROJECT_SET:
		rc = ll_set_project(inode, lu_project.project_xflags,
				    lu_project.project_id);
		break;
	case LU_PROJECT_GET:
		lu_project.project_xflags =
				ll_inode_flags_to_xflags(inode->i_flags);
		if (test_bit(LLIF_PROJECT_INHERIT,
			     &ll_i2info(inode)->lli_flags))
			lu_project.project_xflags |= FS_XFLAG_PROJINHERIT;
		lu_project.project_id = ll_i2info(inode)->lli_projid;
		if (copy_to_user(uarg, &lu_project, sizeof(lu_project))) {
			rc = -EFAULT;
			goto out;
		}
		break;
	default:
		rc = -EINVAL;
		break;
	}
out:
	if (!IS_ERR_OR_NULL(child_dentry))
		dput(child_dentry);
	RETURN(rc);
}

static long ll_file_unlock_lease(struct file *file, struct ll_ioc_lease *ioc,
				 void __user *uarg)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *lfd = file->private_data;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct obd_client_handle *och = NULL;
	struct split_param sp;
	struct pcc_param param;
	bool lease_broken = false;
	enum mds_open_flags open_flags = MDS_FMODE_CLOSED;
	enum mds_op_bias bias = 0;
	__u32 fdv;
	struct file *layout_file = NULL;
	void *data = NULL;
	size_t data_size = 0;
	bool attached = false;
	long rc, rc2 = 0;

	ENTRY;
	mutex_lock(&lli->lli_och_mutex);
	if (lfd->fd_lease_och != NULL) {
		och = lfd->fd_lease_och;
		lfd->fd_lease_och = NULL;
	}
	mutex_unlock(&lli->lli_och_mutex);

	if (och == NULL)
		RETURN(-ENOLCK);

	open_flags = och->och_flags;

	switch (ioc->lil_flags) {
	case LL_LEASE_RESYNC_DONE:
		if (ioc->lil_count > IOC_IDS_MAX)
			GOTO(out_lease_close, rc = -EINVAL);

		data_size = offsetof(typeof(*ioc), lil_ids[ioc->lil_count]);
		OBD_ALLOC(data, data_size);
		if (!data)
			GOTO(out_lease_close, rc = -ENOMEM);

		if (copy_from_user(data, uarg, data_size))
			GOTO(out_lease_close, rc = -EFAULT);

		bias = MDS_CLOSE_RESYNC_DONE;
		break;
	case LL_LEASE_LAYOUT_MERGE:
		if (ioc->lil_count != 1)
			GOTO(out_lease_close, rc = -EINVAL);

		uarg += sizeof(*ioc);
		if (copy_from_user(&fdv, uarg, sizeof(fdv)))
			GOTO(out_lease_close, rc = -EFAULT);

		layout_file = fget(fdv);
		if (!layout_file)
			GOTO(out_lease_close, rc = -EBADF);

		if ((file->f_flags & O_ACCMODE) == O_RDONLY ||
				(layout_file->f_flags & O_ACCMODE) == O_RDONLY)
			GOTO(out_lease_close, rc = -EPERM);

		data = file_inode(layout_file);
		bias = MDS_CLOSE_LAYOUT_MERGE;
		break;
	case LL_LEASE_LAYOUT_SPLIT: {
		__u32 mirror_id;

		if (ioc->lil_count != 2)
			GOTO(out_lease_close, rc = -EINVAL);

		uarg += sizeof(*ioc);
		if (copy_from_user(&fdv, uarg, sizeof(fdv)))
			GOTO(out_lease_close, rc = -EFAULT);

		uarg += sizeof(fdv);
		if (copy_from_user(&mirror_id, uarg, sizeof(mirror_id)))
			GOTO(out_lease_close, rc = -EFAULT);
		if (mirror_id >= MIRROR_ID_NEG)
			GOTO(out_lease_close, rc = -EINVAL);

		layout_file = fget(fdv);
		if (!layout_file)
			GOTO(out_lease_close, rc = -EBADF);

		/* if layout_file == file, it means to destroy the mirror */
		sp.sp_inode = file_inode(layout_file);
		sp.sp_mirror_id = (__u16)mirror_id;
		data = &sp;
		bias = MDS_CLOSE_LAYOUT_SPLIT;
		break;
	}
	case LL_LEASE_PCC_ATTACH:
		if (ioc->lil_count != 1)
			RETURN(-EINVAL);

		/* PCC-RW is not supported for encrypted files. */
		if (IS_ENCRYPTED(inode))
			RETURN(-EOPNOTSUPP);

		uarg += sizeof(*ioc);
		if (copy_from_user(&param.pa_archive_id, uarg, sizeof(__u32)))
			GOTO(out_lease_close, rc2 = -EFAULT);

		rc2 = pcc_readwrite_attach(file, inode, param.pa_archive_id);
		if (rc2)
			GOTO(out_lease_close, rc2);

		attached = true;
		/* Grab latest data version */
		rc2 = ll_data_version(inode, &param.pa_data_version,
				     LL_DV_WR_FLUSH);
		if (rc2)
			GOTO(out_lease_close, rc2);

		data = &param;
		bias = MDS_PCC_ATTACH;
		break;
	default:
		/* without close intent */
		break;
	}

out_lease_close:
	rc = ll_lease_close_intent(och, inode, &lease_broken, bias, data);
	if (rc < 0)
		GOTO(out, rc);

	rc = ll_lease_och_release(inode, file);
	if (rc < 0)
		GOTO(out, rc);

	if (lease_broken)
		open_flags = MDS_FMODE_CLOSED;
	EXIT;

out:
	if (ioc->lil_flags == LL_LEASE_RESYNC_DONE && data)
		OBD_FREE(data, data_size);

	if (layout_file)
		fput(layout_file);

	if (ioc->lil_flags == LL_LEASE_PCC_ATTACH) {
		if (!rc)
			rc = rc2;
		rc = pcc_readwrite_attach_fini(file, inode,
					       param.pa_layout_gen,
					       lease_broken, rc,
					       attached);
	}

	ll_layout_refresh(inode, &lfd->fd_layout_version);

	if (!rc)
		rc = ll_lease_type_from_open_flags(open_flags);
	RETURN(rc);
}

static long ll_file_set_lease(struct file *file, struct ll_ioc_lease *ioc,
			      void __user *uarg)
{
	struct inode *inode = file_inode(file);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *lfd = file->private_data;
	struct obd_client_handle *och = NULL;
	enum mds_open_flags open_flags = MDS_FMODE_CLOSED;
	bool lease_broken;
	fmode_t fmode; /* kernel permissions */
	long rc;

	ENTRY;
	switch (ioc->lil_mode) {
	case LL_LEASE_WRLCK:
		if (!(file->f_mode & FMODE_WRITE))
			RETURN(-EPERM);
		fmode = FMODE_WRITE;
		break;
	case LL_LEASE_RDLCK:
		if (!(file->f_mode & FMODE_READ))
			RETURN(-EPERM);
		fmode = FMODE_READ;
		break;
	case LL_LEASE_UNLCK:
		RETURN(ll_file_unlock_lease(file, ioc, uarg));
	default:
		RETURN(-EINVAL);
	}

	CDEBUG(D_INODE, "Set lease with mode %u\n", fmode);

	/* apply for lease */
	if (ioc->lil_flags & LL_LEASE_RESYNC)
		open_flags = MDS_OPEN_RESYNC;
	och = ll_lease_open(inode, file, fmode, open_flags);
	if (IS_ERR(och))
		RETURN(PTR_ERR(och));

	if (ioc->lil_flags & LL_LEASE_RESYNC) {
		rc = ll_lease_file_resync(och, inode, uarg);
		if (rc) {
			ll_lease_close(och, inode, NULL);
			RETURN(rc);
		}
		rc = ll_layout_refresh(inode, &lfd->fd_layout_version);
		if (rc) {
			ll_lease_close(och, inode, NULL);
			RETURN(rc);
		}
	}

	rc = 0;
	mutex_lock(&lli->lli_och_mutex);
	if (lfd->fd_lease_och == NULL) {
		lfd->fd_lease_och = och;
		och = NULL;
	}
	mutex_unlock(&lli->lli_och_mutex);
	if (och != NULL) {
		/* impossible now that only excl is supported for now */
		ll_lease_close(och, inode, &lease_broken);
		rc = -EBUSY;
	}
	RETURN(rc);
}

static void ll_heat_get(struct inode *inode, struct lu_heat *heat)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	__u64 now = ktime_get_real_seconds();
	int i;

	spin_lock(&lli->lli_heat_lock);
	heat->lh_flags = lli->lli_heat_flags;
	for (i = 0; i < heat->lh_count; i++)
		heat->lh_heat[i] = obd_heat_get(&lli->lli_heat_instances[i],
						now, sbi->ll_heat_decay_weight,
						sbi->ll_heat_period_second);
	spin_unlock(&lli->lli_heat_lock);
}

static int ll_heat_set(struct inode *inode, enum lu_heat_flag flags)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	int rc = 0;

	spin_lock(&lli->lli_heat_lock);
	if (flags & LU_HEAT_FLAG_CLEAR)
		obd_heat_clear(lli->lli_heat_instances, OBD_HEAT_COUNT);

	if (flags & LU_HEAT_FLAG_OFF)
		lli->lli_heat_flags |= LU_HEAT_FLAG_OFF;
	else
		lli->lli_heat_flags &= ~LU_HEAT_FLAG_OFF;

	spin_unlock(&lli->lli_heat_lock);

	RETURN(rc);
}

static long
ll_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *lfd = file->private_data;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	void __user *uarg = (void __user *)arg;
	int rc;

	ENTRY;
	CDEBUG(D_VFSTRACE|D_IOCTL, "VFS Op:inode="DFID"(%pK) cmd=%x arg=%lx\n",
	       PFID(ll_inode2fid(inode)), inode, cmd, arg);
	ll_stats_ops_tally(sbi, LPROC_LL_IOCTL, 1);

	/* asm-ppc{,64} declares TCGETS, et. al. as type 't' not 'T' */
	if (_IOC_TYPE(cmd) == 'T' || _IOC_TYPE(cmd) == 't') /* tty ioctls */
		RETURN(-ENOTTY);

	/* can't do a generic karg == NULL check here, since it is too noisy and
	 * we need to return -ENOTTY for unsupported ioctls instead of -EINVAL.
	 */
	switch (cmd) {
	case LL_IOC_GETFLAGS:
		/* Get the current value of the Lustre file flags */
		return put_user(lfd->lfd_file_flags, (int __user *)arg);
	case LL_IOC_SETFLAGS:
	case LL_IOC_CLRFLAGS: {
		enum ll_file_flags lfd_file_flags;

		/* Set or clear specific Lustre file flags */
		/* XXX This probably needs checks to ensure the flags are
		 *     not abused, and to handle any flag side effects.
		 */
		if (get_user(lfd_file_flags, (int __user *)arg))
			RETURN(-EFAULT);

		/* LL_FILE_GROUP_LOCKED is managed via its own ioctls */
		if (lfd_file_flags & LL_FILE_GROUP_LOCKED)
			RETURN(-EINVAL);

		if (cmd == LL_IOC_SETFLAGS) {
			if ((lfd_file_flags & LL_FILE_IGNORE_LOCK) &&
			    !(file->f_flags & O_DIRECT)) {
				rc = -EINVAL;
				CERROR("%s: unable to disable locking on non-O_DIRECT file "DFID": rc = %d\n",
				       current->comm, PFID(ll_inode2fid(inode)),
				       rc);
				RETURN(rc);
			}

			lfd->lfd_file_flags |= lfd_file_flags;
		} else {
			lfd->lfd_file_flags &= ~lfd_file_flags;
		}
		RETURN(0);
	}
	case LL_IOC_LOV_SETSTRIPE:
	case LL_IOC_LOV_SETSTRIPE_NEW:
		if (sbi->ll_enable_setstripe_gid != -1 &&
		    !capable(CAP_SYS_RESOURCE) &&
		    /* in_group_p always returns true for gid == 0, so we check
		     * for this case directly
		     */
		    (sbi->ll_enable_setstripe_gid == 0 ||
		     !in_group_p(KGIDT_INIT(sbi->ll_enable_setstripe_gid)))) {
			/* for lfs we return EACCES, so we can print an error
			 * from the tool
			 */
			if (!strcmp(current->comm, "lfs"))
				RETURN(-EACCES);
			/* otherwise, setstripe is refused silently so
			 * applications do not fail
			 */
			RETURN(0);
		}

		RETURN(ll_lov_setstripe(inode, file, uarg));
	case LL_IOC_LOV_SETEA:
		RETURN(ll_lov_setea(inode, file, uarg));
	case LL_IOC_LOV_SWAP_LAYOUTS: {
		struct file *file2;
		struct lustre_swap_layouts lsl;

		if (copy_from_user(&lsl, uarg, sizeof(lsl)))
			RETURN(-EFAULT);

		if ((file->f_flags & O_ACCMODE) == O_RDONLY)
			RETURN(-EPERM);

		file2 = fget(lsl.sl_fd);
		if (file2 == NULL)
			RETURN(-EBADF);

		/* O_WRONLY or O_RDWR */
		if ((file2->f_flags & O_ACCMODE) == O_RDONLY)
			GOTO(out, rc = -EPERM);

		if (lsl.sl_flags & SWAP_LAYOUTS_CLOSE) {
			struct obd_client_handle *och = NULL;
			struct ll_inode_info *lli;
			struct inode *inode2;

			lli = ll_i2info(inode);
			mutex_lock(&lli->lli_och_mutex);
			if (lfd->fd_lease_och != NULL) {
				och = lfd->fd_lease_och;
				lfd->fd_lease_och = NULL;
			}
			mutex_unlock(&lli->lli_och_mutex);
			if (och == NULL)
				GOTO(out, rc = -ENOLCK);
			inode2 = file_inode(file2);
			rc = ll_swap_layouts_close(och, inode, inode2, &lsl);
		} else {
			rc = ll_swap_layouts(file, file2, &lsl);
		}
out:
		fput(file2);
		RETURN(rc);
	}
	case LL_IOC_LOV_GETSTRIPE:
	case LL_IOC_LOV_GETSTRIPE_NEW:
		RETURN(ll_file_getstripe(inode, uarg, 0));
	case LL_IOC_GROUP_LOCK:
		RETURN(ll_get_grouplock(inode, file, arg));
	case LL_IOC_GROUP_UNLOCK:
		RETURN(ll_put_grouplock(inode, file, arg));
	case LL_IOC_DATA_VERSION: {
		struct ioc_data_version idv;
		int rc;

		if (copy_from_user(&idv, uarg, sizeof(idv)))
			RETURN(-EFAULT);

		idv.idv_flags &= LL_DV_RD_FLUSH | LL_DV_WR_FLUSH;
		rc = ll_ioc_data_version(inode, &idv);

		if (rc == 0 && copy_to_user(uarg, &idv, sizeof(idv)))
			RETURN(-EFAULT);

		RETURN(rc);
	}
	case LL_IOC_HSM_STATE_GET: {
		struct md_op_data *op_data;
		struct hsm_user_state *hus;
		int rc;

		if (!ll_access_ok(uarg, sizeof(*hus)))
			RETURN(-EFAULT);

		OBD_ALLOC_PTR(hus);
		if (hus == NULL)
			RETURN(-ENOMEM);

		op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
					     LUSTRE_OPC_ANY, hus);
		if (IS_ERR(op_data)) {
			rc = PTR_ERR(op_data);
		} else {
			rc = obd_iocontrol(cmd, ll_i2mdexp(inode),
					   sizeof(*op_data), op_data, NULL);

			if (copy_to_user(uarg, hus, sizeof(*hus)))
				rc = -EFAULT;

			ll_finish_md_op_data(op_data);
		}
		OBD_FREE_PTR(hus);
		RETURN(rc);
	}
	case LL_IOC_HSM_STATE_SET: {
		struct hsm_state_set *hss;
		int rc;

		OBD_ALLOC_PTR(hss);
		if (hss == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(hss, uarg, sizeof(*hss)))
			rc = -EFAULT;
		else
			rc = ll_hsm_state_set(inode, hss);

		OBD_FREE_PTR(hss);
		RETURN(rc);
	}
	case LL_IOC_HSM_ACTION: {
		struct md_op_data *op_data;
		struct hsm_current_action *hca;
		const char *action;
		int rc;

		if (!ll_access_ok(uarg, sizeof(*hca)))
			RETURN(-EFAULT);

		OBD_ALLOC_PTR(hca);
		if (hca == NULL)
			RETURN(-ENOMEM);

		op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
					     LUSTRE_OPC_ANY, hca);
		if (IS_ERR(op_data)) {
			OBD_FREE_PTR(hca);
			RETURN(PTR_ERR(op_data));
		}

		rc = obd_iocontrol(cmd, ll_i2mdexp(inode), sizeof(*op_data),
				   op_data, NULL);
		if (rc < 0)
			GOTO(skip_copy, rc);

		/* The hsm_current_action retreived from the server could
		 * contain corrupt information. If it is incorrect data collect
		 * debug information. We still send the data even if incorrect
		 * to user land to handle.
		 */
		action = hsm_user_action2name(hca->hca_action);
		if (strcmp(action, "UNKNOWN") == 0 ||
		    hca->hca_state > HPS_DONE) {
			CDEBUG(D_HSM,
			       "HSM current state %s action %s, offset = %llu, length %llu\n",
			       hsm_progress_state2name(hca->hca_state), action,
			       hca->hca_location.offset,
			       hca->hca_location.length);
		}

		if (copy_to_user(uarg, hca, sizeof(*hca)))
			rc = -EFAULT;
skip_copy:
		ll_finish_md_op_data(op_data);
		OBD_FREE_PTR(hca);
		RETURN(rc);
	}
	case LL_IOC_HSM_DATA_VERSION: {
		__u64 data_version;

		if (get_user(data_version, (u64 __user *)arg))
			RETURN(-EFAULT);

		rc = ll_hsm_data_version_sync(inode, data_version);

		RETURN(rc);
	}
	case LL_IOC_SET_LEASE_OLD: {
		struct ll_ioc_lease ioc = { .lil_mode = arg };

		RETURN(ll_file_set_lease(file, &ioc, 0));
	}
	case LL_IOC_SET_LEASE: {
		struct ll_ioc_lease ioc;

		if (copy_from_user(&ioc, uarg, sizeof(ioc)))
			RETURN(-EFAULT);

		RETURN(ll_file_set_lease(file, &ioc, uarg));
	}
	case LL_IOC_GET_LEASE: {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct ldlm_lock *lock = NULL;
		enum mds_open_flags open_flags = MDS_FMODE_CLOSED;

		mutex_lock(&lli->lli_och_mutex);
		if (lfd->fd_lease_och != NULL) {
			struct obd_client_handle *och = lfd->fd_lease_och;

			lock = ldlm_handle2lock(&och->och_lease_handle);
			if (lock != NULL) {
				lock_res_and_lock(lock);
				if (!ldlm_is_cancel(lock))
					open_flags = och->och_flags;

				unlock_res_and_lock(lock);
				ldlm_lock_put(lock);
			}
		}
		mutex_unlock(&lli->lli_och_mutex);

		RETURN(ll_lease_type_from_open_flags(open_flags));
	}
	case LL_IOC_HSM_IMPORT: {
		struct hsm_user_import *hui;

		OBD_ALLOC_PTR(hui);
		if (hui == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(hui, uarg, sizeof(*hui)))
			rc = -EFAULT;
		else
			rc = ll_hsm_import(inode, file, hui);

		OBD_FREE_PTR(hui);
		RETURN(rc);
	}
	case LL_IOC_FUTIMES_3: {
		struct ll_futimes_3 lfu;

		if (copy_from_user(&lfu, uarg, sizeof(lfu)))
			RETURN(-EFAULT);

		RETURN(ll_file_futimes_3(file, &lfu));
	}
	case LL_IOC_LADVISE: {
		struct llapi_ladvise_hdr *k_ladvise_hdr;
		struct llapi_ladvise_hdr __user *u_ladvise_hdr;
		int i;
		int num_advise;
		int alloc_size = sizeof(*k_ladvise_hdr);

		rc = 0;
		u_ladvise_hdr = uarg;
		OBD_ALLOC_PTR(k_ladvise_hdr);
		if (k_ladvise_hdr == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(k_ladvise_hdr, u_ladvise_hdr, alloc_size))
			GOTO(out_ladvise, rc = -EFAULT);

		if (k_ladvise_hdr->lah_magic != LADVISE_MAGIC ||
		    k_ladvise_hdr->lah_count < 1)
			GOTO(out_ladvise, rc = -EINVAL);

		num_advise = k_ladvise_hdr->lah_count;
		if (num_advise >= LAH_COUNT_MAX)
			GOTO(out_ladvise, rc = -EFBIG);

		OBD_FREE_PTR(k_ladvise_hdr);
		alloc_size = offsetof(typeof(*k_ladvise_hdr),
				      lah_advise[num_advise]);
		OBD_ALLOC(k_ladvise_hdr, alloc_size);
		if (k_ladvise_hdr == NULL)
			RETURN(-ENOMEM);

		/*
		 * TODO: submit multiple advices to one server in a single RPC
		 */
		if (copy_from_user(k_ladvise_hdr, u_ladvise_hdr, alloc_size))
			GOTO(out_ladvise, rc = -EFAULT);

		for (i = 0; i < num_advise; i++) {
			struct llapi_lu_ladvise *k_ladvise =
					&k_ladvise_hdr->lah_advise[i];
			struct llapi_lu_ladvise __user *u_ladvise =
					&u_ladvise_hdr->lah_advise[i];

			rc = ll_ladvise_sanity(inode, k_ladvise);
			if (rc)
				GOTO(out_ladvise, rc);

			switch (k_ladvise->lla_advice) {
			case LU_LADVISE_LOCKNOEXPAND:
				rc = ll_lock_noexpand(file,
					       k_ladvise->lla_peradvice_flags);
				GOTO(out_ladvise, rc);
			case LU_LADVISE_LOCKAHEAD:

				rc = ll_file_lock_ahead(file, k_ladvise);

				if (rc < 0)
					GOTO(out_ladvise, rc);

				if (put_user(rc,
					     &u_ladvise->lla_lockahead_result))
					GOTO(out_ladvise, rc = -EFAULT);
				break;
			default:
				rc = ll_ladvise(inode, file,
						k_ladvise_hdr->lah_flags,
						k_ladvise);
				if (rc)
					GOTO(out_ladvise, rc);
				break;
			}

		}

out_ladvise:
		OBD_FREE(k_ladvise_hdr, alloc_size);
		RETURN(rc);
	}
	case LL_IOC_FLR_SET_MIRROR: {
		/* mirror I/O must be direct to avoid polluting page cache
		 * by stale data.
		 */
		if (!(file->f_flags & O_DIRECT))
			RETURN(-EINVAL);

		lfd->fd_designated_mirror = arg;
		RETURN(0);
	}
	case LL_IOC_HEAT_GET: {
		struct lu_heat uheat;
		struct lu_heat *heat;
		int size;

		if (copy_from_user(&uheat, uarg, sizeof(uheat)))
			RETURN(-EFAULT);

		if (uheat.lh_count > OBD_HEAT_COUNT)
			uheat.lh_count = OBD_HEAT_COUNT;

		size = offsetof(typeof(uheat), lh_heat[uheat.lh_count]);
		OBD_ALLOC(heat, size);
		if (heat == NULL)
			RETURN(-ENOMEM);

		heat->lh_count = uheat.lh_count;
		ll_heat_get(inode, heat);
		rc = copy_to_user(uarg, heat, size);
		OBD_FREE(heat, size);
		RETURN(rc ? -EFAULT : 0);
	}
	case LL_IOC_HEAT_SET: {
		__u64 heat_flags;

		if (copy_from_user(&heat_flags, uarg, sizeof(heat_flags)))
			RETURN(-EFAULT);

		rc = ll_heat_set(inode, heat_flags);
		RETURN(rc);
	}
	case LL_IOC_PCC_ATTACH: {
		struct lu_pcc_attach *attach;

		if (!S_ISREG(inode->i_mode))
			RETURN(-EINVAL);

		if (!pcc_inode_permission(inode))
			RETURN(-EPERM);

		OBD_ALLOC_PTR(attach);
		if (attach == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(attach,
				   (const struct lu_pcc_attach __user *)arg,
				   sizeof(*attach)))
			GOTO(out_pcc, rc = -EFAULT);

		/* We only support pcc for encrypted files if we have the
		 * encryption key and if it is PCC-RO.
		 */
		if (IS_ENCRYPTED(inode) &&
		    (!llcrypt_has_encryption_key(inode) ||
		     attach->pcca_type != LU_PCC_READONLY))
			GOTO(out_pcc, rc = -EOPNOTSUPP);

		rc = pcc_ioctl_attach(file, inode, attach);
out_pcc:
		OBD_FREE_PTR(attach);
		RETURN(rc);
	}
	case LL_IOC_PCC_DETACH: {
		struct lu_pcc_detach *detach;

		OBD_ALLOC_PTR(detach);
		if (detach == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(detach, uarg, sizeof(*detach)))
			GOTO(out_detach_free, rc = -EFAULT);

		if (!S_ISREG(inode->i_mode))
			GOTO(out_detach_free, rc = -EINVAL);

		if (!pcc_inode_permission(inode))
			GOTO(out_detach_free, rc = -EPERM);

		rc = pcc_ioctl_detach(inode, &detach->pccd_flags);
		if (rc)
			GOTO(out_detach_free, rc);

		if (copy_to_user((char __user *)arg, detach, sizeof(*detach)))
			GOTO(out_detach_free, rc = -EFAULT);
out_detach_free:
		OBD_FREE_PTR(detach);
		RETURN(rc);
	}
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 18, 53, 0)
	case LL_IOC_PCC_STATE: {
		struct lu_pcc_state __user *ustate = uarg;
		struct lu_pcc_state *state;

		OBD_ALLOC_PTR(state);
		if (state == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(state, ustate, sizeof(*state)))
			GOTO(out_state, rc = -EFAULT);

		rc = pcc_ioctl_state(file, inode, state);
		if (rc)
			GOTO(out_state, rc);

		if (copy_to_user(ustate, state, sizeof(*state)))
			GOTO(out_state, rc = -EFAULT);

out_state:
		OBD_FREE_PTR(state);
		RETURN(rc);
	}
#endif
	default:
		rc = ll_iocontrol(inode, file, cmd, uarg);
		if (rc != -ENOTTY)
			RETURN(rc);
		RETURN(obd_iocontrol(cmd, ll_i2dtexp(inode), 0, NULL, uarg));
	}
}

static loff_t ll_lseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file_inode(file);
	struct lu_env *env;
	struct cl_io *io;
	struct cl_lseek_io *lsio;
	__u16 refcheck;
	int rc;
	loff_t retval;

	ENTRY;
	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = vvp_env_new_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;
	ll_io_set_mirror(io, file);

	lsio = &io->u.ci_lseek;
	lsio->ls_start = offset;
	lsio->ls_whence = whence;
	lsio->ls_result = -ENXIO;

	do {
		rc = cl_io_init(env, io, CIT_LSEEK, io->ci_obj);
		if (!rc) {
			struct vvp_io *vio = vvp_env_io(env);

			vio->vui_fd = file->private_data;
			rc = cl_io_loop(env, io);
		} else {
			rc = io->ci_result;
		}
		retval = rc ? : lsio->ls_result;
		cl_io_fini(env, io);
	} while (unlikely(io->ci_need_restart));

	cl_env_put(env, &refcheck);

	/* Without the key, SEEK_HOLE return value has to be
	 * rounded up to next LUSTRE_ENCRYPTION_UNIT_SIZE.
	 */
	if (IS_ENCRYPTED(inode) && !ll_has_encryption_key(inode) &&
	    whence == SEEK_HOLE)
		retval = round_up(retval, LUSTRE_ENCRYPTION_UNIT_SIZE);

	RETURN(retval);
}

#define LU_SEEK_NAMES {					\
	[SEEK_SET]	= "SEEK_SET",			\
	[SEEK_CUR]	= "SEEK_CUR",			\
	[SEEK_DATA]	= "SEEK_DATA",			\
	[SEEK_HOLE]	= "SEEK_HOLE",			\
}

static const char *const ll_seek_names[] = LU_SEEK_NAMES;

static loff_t ll_file_seek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file_inode(file);
	loff_t retval = offset, eof = 0;
	ktime_t kstart = ktime_get();

	ENTRY;
	CDEBUG(D_VFSTRACE|D_IOTRACE,
	       "START file "DNAME":"DFID", offset: %lld, type: %s\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       offset, ll_seek_names[origin]);

	if (origin == SEEK_END) {
		retval = ll_glimpse_size(inode);
		if (retval != 0)
			RETURN(retval);
		eof = i_size_read(inode);
	}

	if (origin == SEEK_HOLE || origin == SEEK_DATA) {
		if (offset < 0)
			return -ENXIO;

		/* flush local cache first if any */
		cl_sync_file_range(inode, offset, OBD_OBJECT_EOF,
				   CL_FSYNC_LOCAL, 0, IO_PRIO_NORMAL);

		retval = ll_lseek(file, offset, origin);
		if (retval < 0)
			return retval;
		retval = vfs_setpos(file, retval, ll_file_maxbytes(inode));
	} else {
		retval = generic_file_llseek_size(file, offset, origin,
						  ll_file_maxbytes(inode), eof);
	}
	if (retval >= 0)
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_LLSEEK,
				   ktime_us_delta(ktime_get(), kstart));
	CDEBUG(D_VFSTRACE|D_IOTRACE,
	       "COMPLETED file "DNAME":"DFID", offset: %lld, type: %s, rc = %lld\n",
	       encode_fn_file(file), PFID(ll_inode2fid(file_inode(file))),
	       offset, ll_seek_names[origin], retval);

	RETURN(retval);
}

static int ll_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *lfd = file->private_data;
	int rc, err;

	LASSERT(!S_ISDIR(inode->i_mode));

	/* catch async errors that were recorded back when async writeback
	 * failed for pages in this mapping.
	 */
	rc = lli->lli_async_rc;
	lli->lli_async_rc = 0;
	if (lli->lli_clob != NULL) {
		err = lov_read_and_clear_async_rc(lli->lli_clob);
		if (rc == 0)
			rc = err;
	}

	/* The application has been told write failure already.
	 * Do not report failure again.
	 */
	if (lfd->fd_write_failed)
		return 0;
	return rc ? -EIO : 0;
}

/*
 * Called to make sure a portion of file has been written out.
 * if @mode is not CL_FSYNC_LOCAL, it will send OST_SYNC RPCs to OST.
 *
 * Return how many pages have been written.
 */
int cl_sync_file_range(struct inode *inode, loff_t start, loff_t end,
		       enum cl_fsync_mode mode, int ignore_layout,
		       enum cl_io_priority prio)
{
	struct lu_env *env;
	struct cl_io *io;
	struct cl_fsync_io *fio;
	int result;
	__u16 refcheck;

	ENTRY;
	if (mode != CL_FSYNC_NONE && mode != CL_FSYNC_LOCAL &&
	    mode != CL_FSYNC_DISCARD && mode != CL_FSYNC_ALL &&
	    mode != CL_FSYNC_RECLAIM)
		RETURN(-EINVAL);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = vvp_env_new_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;
	cl_object_get(io->ci_obj);
	io->ci_ignore_layout = ignore_layout;

	/* initialize parameters for sync */
	fio = &io->u.ci_fsync;
	fio->fi_start = start;
	fio->fi_end = end;
	fio->fi_fid = ll_inode2fid(inode);
	fio->fi_mode = mode;
	fio->fi_nr_written = 0;
	fio->fi_prio = prio;

	if (cl_io_init(env, io, CIT_FSYNC, io->ci_obj) == 0)
		result = cl_io_loop(env, io);
	else
		result = io->ci_result;
	if (result == 0)
		result = fio->fi_nr_written;
	cl_io_fini(env, io);
	cl_object_put(env, io->ci_obj);
	cl_env_put(env, &refcheck);

	RETURN(result);
}

/*
 * When dentry is provided (the 'else' case), file_dentry() may be
 * null and dentry must be used directly rather than pulled from
 * file_dentry() as is done otherwise.
 */
int ll_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = dentry->d_inode;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ptlrpc_request *req;
	ktime_t kstart = ktime_get();
	int rc, err;

	ENTRY;
	CDEBUG(D_VFSTRACE,
	       "VFS Op:inode="DFID"(%p), start %lld, end %lld, datasync %d\n",
	       PFID(ll_inode2fid(inode)), inode, start, end, datasync);

	/* fsync's caller has already called _fdata{sync,write}, we want
	 * that IO to finish before calling the osc and mdc sync methods
	 */
	rc = filemap_write_and_wait_range(inode->i_mapping, start, end);

	/* catch async errors that were recorded back when async writeback
	 * failed for pages in this mapping.
	 */
	if (!S_ISDIR(inode->i_mode)) {
		err = lli->lli_async_rc;
		lli->lli_async_rc = 0;
		if (rc == 0)
			rc = err;
		if (lli->lli_clob != NULL) {
			err = lov_read_and_clear_async_rc(lli->lli_clob);
			if (rc == 0)
				rc = err;
		}
	}

	if (S_ISREG(inode->i_mode) && !lli->lli_synced_to_mds) {
		/*
		 * only the first sync on MDS makes sense,
		 * everything else is stored on OSTs
		 */
		err = md_fsync(ll_i2sbi(inode)->ll_md_exp,
			       ll_inode2fid(inode), &req);
		if (!rc)
			rc = err;
		if (!err) {
			lli->lli_synced_to_mds = true;
			ptlrpc_req_put(req);
		}
	}

	if (S_ISREG(inode->i_mode)) {
		struct ll_file_data *lfd = file->private_data;
		bool cached;

		/* Sync metadata on MDT first, and then sync the cached data
		 * on PCC.
		 */
		err = pcc_fsync(file, start, end, datasync, &cached);
		if (!cached)
			err = cl_sync_file_range(inode, start, end,
						 CL_FSYNC_ALL, 0,
						 IO_PRIO_NORMAL);
		if (rc == 0 && err < 0)
			rc = err;
		if (rc < 0)
			lfd->fd_write_failed = true;
		else
			lfd->fd_write_failed = false;
	}

	if (!rc)
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FSYNC,
				   ktime_us_delta(ktime_get(), kstart));
	RETURN(rc);
}

static int ll_file_flc2policy(struct file_lock *file_lock, int cmd,
		       union ldlm_policy_data *flock)
{
	ENTRY;

	if (file_lock->C_FLC_FLAGS & FL_FLOCK) {
		LASSERT((cmd == F_SETLKW) || (cmd == F_SETLK));
		/* flocks are whole-file locks */
		flock->l_flock.end = OFFSET_MAX;
		/* For flocks owner is determined by the local file desctiptor*/
		flock->l_flock.owner = (unsigned long)file_lock->C_FLC_FILE;
	} else if (file_lock->C_FLC_FLAGS & FL_POSIX) {
		flock->l_flock.owner = (unsigned long)file_lock->C_FLC_OWNER;
		flock->l_flock.start = file_lock->fl_start;
		flock->l_flock.end = file_lock->fl_end;
	} else {
		RETURN(-EINVAL);
	}
	flock->l_flock.pid = file_lock->C_FLC_PID;

#if defined(HAVE_LM_COMPARE_OWNER) || defined(lm_compare_owner)
	/* Somewhat ugly workaround for svc lockd.
	 * lockd installs custom fl_lmops->lm_compare_owner that checks
	 * for the fl_owner to be the same (which it always is on local node
	 * I guess between lockd processes) and then compares pid.
	 * As such we assign pid to the owner field to make it all work,
	 * conflict with normal locks is unlikely since pid space and
	 * pointer space for current->files are not intersecting
	 */
	if (file_lock->fl_lmops && file_lock->fl_lmops->lm_compare_owner)
		flock->l_flock.owner = (unsigned long)file_lock->C_FLC_PID;
#endif

	RETURN(0);
}

static int ll_file_flock_lock(struct file *file, struct file_lock *file_lock)
{
	int rc = -EINVAL;

	/* We don't need to sleep on conflicting locks.
	 * It is called in following usecases :
	 * 1. adding new lock - no conflicts exist as it is already granted
	 *    on the server.
	 * 2. unlock - never conflicts with anything.
	 */
	file_lock->C_FLC_FLAGS &= ~FL_SLEEP;
#ifdef HAVE_LOCKS_LOCK_FILE_WAIT
	rc = locks_lock_file_wait(file, file_lock);
#else
	if (file_lock->C_FLC_FLAGS & FL_FLOCK)
		rc = flock_lock_file_wait(file, file_lock);
	else if (file_lock->C_FLC_FLAGS & FL_POSIX)
		rc = posix_lock_file(file, file_lock, NULL);
#endif /* HAVE_LOCKS_LOCK_FILE_WAIT */
	if (rc)
		CDEBUG_LIMIT(rc == -ENOENT ? D_DLMTRACE : D_ERROR,
		       "kernel lock failed: rc = %d\n", rc);

	return rc;
}

static int ll_flock_upcall(void *cookie, int err);
static int
ll_flock_completion_ast_async(struct ldlm_lock *lock, __u64 flags, void *data);

static int ll_file_flock_async_unlock(struct inode *inode,
				      struct file_lock *file_lock)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ldlm_enqueue_info einfo = { .ei_type = LDLM_FLOCK,
					   .ei_cb_cp =
					      ll_flock_completion_ast_async,
					   .ei_mode = LCK_NL,
					   .ei_cbdata = NULL };
	union ldlm_policy_data flock = { {0} };
	struct md_op_data *op_data;
	int rc;

	ENTRY;
	rc = ll_file_flc2policy(file_lock, F_SETLK, &flock);
	if (rc)
		RETURN(rc);

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	rc = md_enqueue_async(sbi->ll_md_exp, &einfo, ll_flock_upcall,
			      op_data, &flock, 0);

	ll_finish_md_op_data(op_data);

	RETURN(rc);
}

/* This function is called only once after ldlm callback. Args are already
 * detached from lock. So, locking isn't needed.
 * It should only report lock status to kernel.
 */
static void ll_file_flock_async_cb(struct ldlm_flock_info *args)
{
	struct file_lock *file_lock = args->fa_fl;
	struct file_lock *flc = &args->fa_flc;
	struct file *file = args->fa_file;
	struct inode *inode = file->f_path.dentry->d_inode;
	int err = args->fa_err;
	int rc;

	ENTRY;
	CDEBUG(D_INFO, "err=%d file_lock=%p file=%p start=%llu end=%llu\n",
	       err, file_lock, file, flc->fl_start, flc->fl_end);

	/* The kernel is responsible for resolving grant vs F_CANCELK or
	 * grant vs. cleanup races, it may happen that CANCELED flag
	 * isn't set and err == 0, because f_CANCELK/cleanup happens between
	 * ldlm_flock_completion_ast_async() and ll_flock_run_flock_cb().
	 * In this case notify() returns error for already canceled flock.
	 */
	if (!(args->fa_flags & FA_FL_CANCELED)) {
		struct file_lock notify_lock;

		locks_init_lock(&notify_lock);
		locks_copy_lock(&notify_lock, flc);

		if (err == 0)
			ll_file_flock_lock(file, flc);

		wait_event_idle(args->fa_waitq, args->fa_ready);

#ifdef HAVE_LM_GRANT_2ARGS
		rc = args->fa_notify(&notify_lock, err);
#else
		rc = args->fa_notify(&notify_lock, NULL, err);
#endif
		if (rc) {
			CDEBUG_LIMIT(D_ERROR,
				     "notify failed file_lock=%p err=%d\n",
				     file_lock, err);
			if (err == 0) {
				flc->C_FLC_TYPE = F_UNLCK;
				ll_file_flock_lock(file, flc);
				ll_file_flock_async_unlock(inode, flc);
			}
		}
	}

	fput(file);

	EXIT;
}

static void ll_flock_run_flock_cb(struct ldlm_flock_info *args)
{
	if (args) {
		ll_file_flock_async_cb(args);
		OBD_FREE_PTR(args);
	}
}

static int ll_flock_upcall(void *cookie, int err)
{
	struct ldlm_flock_info *args;
	struct ldlm_lock *lock = cookie;

	if (err != 0) {
		CERROR("ldlm_cli_enqueue_fini lock=%p : rc = %d\n", lock, err);

		lock_res_and_lock(lock);
		args = lock->l_ast_data;
		lock->l_ast_data = NULL;
		unlock_res_and_lock(lock);

		if (args)
			args->fa_err = err;
		ll_flock_run_flock_cb(args);
	}

	return 0;
}

static int
ll_flock_completion_ast_async(struct ldlm_lock *lock, __u64 flags, void *data)
{
	struct ldlm_flock_info *args;

	ENTRY;

	args = ldlm_flock_completion_ast_async(lock, flags, data);
	if (args && args->fa_flags & FA_FL_CANCELED) {
		/* lock was cancelled in a race */
		struct inode *inode = args->fa_file->f_path.dentry->d_inode;

		ll_file_flock_async_unlock(inode, &args->fa_flc);
	}

	ll_flock_run_flock_cb(args);

	RETURN(0);
}

static int
ll_file_flock(struct file *file, int cmd, struct file_lock *file_lock)
{
	struct inode *inode = file_inode(file);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ldlm_enqueue_info einfo = {
		.ei_type	= LDLM_FLOCK,
		.ei_cb_cp	= ldlm_flock_completion_ast,
		.ei_cbdata	= NULL,
	};
	struct md_op_data *op_data;
	struct lustre_handle lockh = { 0 };
	union ldlm_policy_data flock = { { 0 } };
	int fl_type = file_lock->C_FLC_TYPE;
	ktime_t kstart = ktime_get();
	__u64 flags = 0;
	struct ldlm_flock_info *cb_data = NULL;
	int rc;

	ENTRY;
	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID" file_lock=%p\n",
	       PFID(ll_inode2fid(inode)), file_lock);

	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FLOCK, 1);

	rc = ll_file_flc2policy(file_lock, cmd, &flock);
	if (rc)
		RETURN(rc);

	switch (fl_type) {
	case F_RDLCK:
		einfo.ei_mode = LCK_PR;
		break;
	case F_UNLCK:
		/* An unlock request may or may not have any relation to
		 * existing locks so we may not be able to pass a lock handle
		 * via a normal ldlm_lock_cancel() request. The request may even
		 * unlock a byte range in the middle of an existing lock. In
		 * order to process an unlock request we need all of the same
		 * information that is given with a normal read or write record
		 * lock request. To avoid creating another ldlm unlock (cancel)
		 * message we'll treat a LCK_NL flock request as an unlock.
		 */
		einfo.ei_mode = LCK_NL;
		break;
	case F_WRLCK:
		einfo.ei_mode = LCK_PW;
		break;
	default:
		rc = -EINVAL;
		CERROR("%s: fcntl from '%s' unknown lock type=%d: rc = %d\n",
		       sbi->ll_fsname, current->comm, fl_type, rc);
		RETURN(rc);
	}

	switch (cmd) {
	case F_SETLKW:
#ifdef F_SETLKW64
	case F_SETLKW64:
#endif
		flags = 0;
		break;
	case F_SETLK:
#ifdef F_SETLK64
	case F_SETLK64:
#endif
		flags = LDLM_FL_BLOCK_NOWAIT;
		break;
	case F_GETLK:
#ifdef F_GETLK64
	case F_GETLK64:
#endif
		flags = LDLM_FL_TEST_LOCK;
		break;
	case F_CANCELLK:
		CDEBUG(D_DLMTRACE, "F_CANCELLK owner=%llx %llu-%llu\n",
		       flock.l_flock.owner, flock.l_flock.start,
		       flock.l_flock.end);
		file_lock->C_FLC_TYPE = F_UNLCK;
		einfo.ei_mode = LCK_NL;
		break;
	default:
		rc = -EINVAL;
		CERROR("%s: fcntl from '%s' unknown lock command=%d: rc = %d\n",
		       sbi->ll_fsname, current->comm, cmd, rc);
		RETURN(rc);
	}

	CDEBUG(D_DLMTRACE,
	       "inode="DFID", pid=%u, owner=%#llx, flags=%#llx, mode=%u, start=%llu, end=%llu\n",
	       PFID(ll_inode2fid(inode)), flock.l_flock.pid,
	       flock.l_flock.owner, flags, einfo.ei_mode,
	       flock.l_flock.start, flock.l_flock.end);

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	OBD_ALLOC_PTR(cb_data);
	if (!cb_data)
		GOTO(out, rc = -ENOMEM);

	cb_data->fa_file = file;
	cb_data->fa_fl = file_lock;
	cb_data->fa_mode = einfo.ei_mode;
	init_waitqueue_head(&cb_data->fa_waitq);
	locks_init_lock(&cb_data->fa_flc);
	locks_copy_lock(&cb_data->fa_flc, file_lock);
	if (cmd == F_CANCELLK)
		cb_data->fa_flags |= FA_FL_CANCEL_RQST;
	einfo.ei_cbdata = cb_data;

	if (file_lock->fl_lmops && file_lock->fl_lmops->lm_grant &&
	    file_lock->C_FLC_TYPE != F_UNLCK &&
	    flags == LDLM_FL_BLOCK_NOWAIT /* F_SETLK/F_SETLK64 */) {

		cb_data->fa_notify = file_lock->fl_lmops->lm_grant;
		flags = (file_lock->C_FLC_FLAGS & FL_SLEEP) ?
			0 : LDLM_FL_BLOCK_NOWAIT;
		einfo.ei_cb_cp = ll_flock_completion_ast_async;
		get_file(file);

		rc = md_enqueue_async(sbi->ll_md_exp, &einfo,
				      ll_flock_upcall, op_data, &flock, flags);
		if (rc) {
			fput(file);
			OBD_FREE_PTR(cb_data);
			cb_data = NULL;
		} else {
			rc = FILE_LOCK_DEFERRED;
		}
	} else {
		if (file_lock->C_FLC_TYPE == F_UNLCK &&
		    flags != LDLM_FL_TEST_LOCK) {
			/* We unlock kernel lock before ldlm one to avoid race
			 * with reordering of unlock & lock responses from
			 * server.
			 */
			cb_data->fa_flc.C_FLC_FLAGS |= FL_EXISTS;
			rc = ll_file_flock_lock(file, &cb_data->fa_flc);
			if (rc) {
				if (rc == -ENOENT) {
					if (!(file_lock->C_FLC_TYPE &
								FL_EXISTS))
						rc = 0;
				} else {
					CDEBUG_LIMIT(D_ERROR,
					       "local unlock failed rc=%d\n",
					       rc);
				}
				OBD_FREE_PTR(cb_data);
				cb_data = NULL;
				GOTO(out, rc);
			}
		}

		rc = md_enqueue(sbi->ll_md_exp, &einfo, &flock, op_data,
				&lockh, flags);


		if (!rc && file_lock->C_FLC_TYPE != F_UNLCK &&
		    !(flags & LDLM_FL_TEST_LOCK)) {
			int rc2;

			rc2 = ll_file_flock_lock(file, file_lock);

			if (rc2) {
				einfo.ei_mode = LCK_NL;
				cb_data->fa_mode = einfo.ei_mode;
				md_enqueue(sbi->ll_md_exp, &einfo, &flock,
					   op_data, &lockh, flags);
				rc = rc2;
			}
		}
		OBD_FREE_PTR(cb_data);
		cb_data = NULL;
	}
out:
	ll_finish_md_op_data(op_data);
	if (cb_data) {
		cb_data->fa_ready = 1;
		wake_up(&cb_data->fa_waitq);
	}

	if (rc == 0 && (flags & LDLM_FL_TEST_LOCK) &&
	    file_lock->C_FLC_TYPE != F_UNLCK) {
		struct file_lock flbuf = { .fl_ops = NULL, };
		/* The parallel-scale-nfs test_2 checks this line */
		char __maybe_unused *str = "Invoke locks_copy_lock for NFSv3";

		/* Take a extra reference for lockowner while
		 * working with lockd.
		 */
		locks_copy_lock(&flbuf, file_lock);
	}

	if (!rc)
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FLOCK,
				   ktime_us_delta(ktime_get(), kstart));
	RETURN(rc);
}

int ll_get_fid_by_name(struct inode *parent, const char *name,
		       int namelen, struct lu_fid *fid,
		       struct inode **inode)
{
	struct md_op_data *op_data = NULL;
	struct mdt_body *body;
	struct ptlrpc_request *req;
	int rc;

	ENTRY;
	op_data = ll_prep_md_op_data(NULL, parent, NULL, name, namelen, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_valid = OBD_MD_FLID | OBD_MD_FLTYPE;
	rc = md_getattr_name(ll_i2sbi(parent)->ll_md_exp, op_data, &req);
	ll_finish_md_op_data(op_data);
	if (rc < 0)
		RETURN(rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	if (body == NULL)
		GOTO(out_req, rc = -EFAULT);
	if (fid != NULL)
		*fid = body->mbo_fid1;

	if (inode != NULL)
		rc = ll_prep_inode(inode, &req->rq_pill, parent->i_sb, NULL);
out_req:
	ptlrpc_req_put(req);
	RETURN(rc);
}

int ll_migrate(struct inode *parent, struct file *file, struct lmv_user_md *lum,
	       const char *name, __u32 flags)
{
	struct dentry *dchild = NULL;
	struct inode *child_inode = NULL;
	struct md_op_data *op_data;
	struct ptlrpc_request *request = NULL;
	struct obd_client_handle *och = NULL;
	struct qstr qstr;
	struct mdt_body *body;
	__u64 data_version = 0;
	size_t namelen = strlen(name);
	int lumlen = lmv_user_md_size(lum->lum_stripe_count, lum->lum_magic);
	bool locked = false;
	int rc;

	ENTRY;
	CDEBUG(D_VFSTRACE, "migrate "DFID"/%s to MDT%04x stripe count %d\n",
	       PFID(ll_inode2fid(parent)), encode_fn_len(name, namelen),
	       lum->lum_stripe_offset, lum->lum_stripe_count);

	if (lum->lum_magic != cpu_to_le32(LMV_USER_MAGIC) &&
	    lum->lum_magic != cpu_to_le32(LMV_USER_MAGIC_SPECIFIC))
		lustre_swab_lmv_user_md(lum);

	/* Get child FID first */
	qstr.hash = ll_full_name_hash(file_dentry(file), name, namelen);
	qstr.name = name;
	qstr.len = namelen;
	dchild = d_lookup(file_dentry(file), &qstr);
	if (dchild) {
		if (dchild->d_inode)
			child_inode = igrab(dchild->d_inode);
		dput(dchild);
	}

	if (!child_inode) {
		rc = ll_get_fid_by_name(parent, name, namelen, NULL,
					&child_inode);
		if (rc)
			RETURN(rc);
	}

	if (!child_inode)
		RETURN(-ENOENT);

	if (!(exp_connect_flags2(ll_i2sbi(parent)->ll_md_exp) &
	      OBD_CONNECT2_DIR_MIGRATE)) {
		if (le32_to_cpu(lum->lum_stripe_count) > 1 ||
		    ll_dir_striped(child_inode)) {
			rc = -EOPNOTSUPP;
			CERROR("%s: MDT doesn't support stripe directory migration!: rc = %d\n",
			       ll_i2sbi(parent)->ll_fsname, rc);
			GOTO(out_iput, rc);
		}
	}

	/*
	 * lfs migrate command needs to be blocked on the client
	 * by checking the migrate FID against the FID of the
	 * filesystem root.
	 */
	if (is_root_inode(child_inode))
		GOTO(out_iput, rc = -EINVAL);

	/*
	 * setxattr() used for finishing the dir migration, has the same
	 * capability check for updating attributes in "trusted" namespace.
	 */
	if (!capable(CAP_SYS_ADMIN))
		GOTO(out_iput, rc = -EPERM);

	op_data = ll_prep_md_op_data(NULL, parent, NULL, name, namelen,
				     child_inode->i_mode, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		GOTO(out_iput, rc = PTR_ERR(op_data));

	op_data->op_fid3 = *ll_inode2fid(child_inode);
	if (!fid_is_sane(&op_data->op_fid3)) {
		rc = -EINVAL;
		CERROR("%s: migrate %s, but FID "DFID" is insane: rc = %d\n",
		       ll_i2sbi(parent)->ll_fsname, name,
		       PFID(&op_data->op_fid3), rc);
		GOTO(out_data, rc);
	}

	op_data->op_cli_flags |= CLI_MIGRATE | CLI_SET_MEA;
	op_data->op_data = lum;
	op_data->op_data_size = lumlen;

	/* migrate dirent only for subdirs if MDS_MIGRATE_NSONLY set */
	if (S_ISDIR(child_inode->i_mode) && (flags & MDS_MIGRATE_NSONLY) &&
	    lmv_dir_layout_changing(op_data->op_lso1))
		op_data->op_bias |= MDS_MIGRATE_NSONLY;

again:
	if (S_ISREG(child_inode->i_mode)) {
		och = ll_lease_open(child_inode, NULL, FMODE_WRITE, 0);
		if (IS_ERR(och)) {
			rc = PTR_ERR(och);
			och = NULL;
			GOTO(out_data, rc);
		}

		rc = ll_data_version(child_inode, &data_version,
				     LL_DV_WR_FLUSH);
		if (rc != 0)
			GOTO(out_close, rc);

		op_data->op_open_handle = och->och_open_handle;
		op_data->op_data_version = data_version;
		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_bias |= MDS_CLOSE_MIGRATE;

		spin_lock(&och->och_mod->mod_open_req->rq_lock);
		och->och_mod->mod_open_req->rq_replay = 0;
		spin_unlock(&och->och_mod->mod_open_req->rq_lock);
	}
	LASSERT(locked == false);
	ll_inode_lock(child_inode);
	locked = true;

	rc = md_rename(ll_i2sbi(parent)->ll_md_exp, op_data,
		       op_data->op_name, op_data->op_namelen,
		       op_data->op_name, op_data->op_namelen, &request);
	if (rc == 0) {
		LASSERT(request != NULL);
		ll_update_times(request, parent);
	}

	if (rc == 0 || rc == -EAGAIN) {
		body = req_capsule_server_get(&request->rq_pill, &RMF_MDT_BODY);
		LASSERT(body != NULL);

		/* If the server does release layout lock, then we cleanup
		 * the client och here, otherwise release it in out_close:
		 */
		if (och && body->mbo_valid & OBD_MD_CLOSE_INTENT_EXECED) {
			obd_mod_put(och->och_mod);
			md_clear_open_replay_data(ll_i2sbi(parent)->ll_md_exp,
						  och);
			och->och_open_handle.cookie = DEAD_HANDLE_MAGIC;
			OBD_FREE_PTR(och);
			och = NULL;
		}
	}

	if (request != NULL) {
		ptlrpc_req_put(request);
		request = NULL;
	}

	/* Try again if the lease has cancelled. */
	if (rc == -EAGAIN && S_ISREG(child_inode->i_mode)) {
		LASSERT(locked == true);
		ll_inode_unlock(child_inode);
		locked = false;
		goto again;
	}

out_close:
	if (och)
		ll_lease_close(och, child_inode, NULL);
	if (!rc)
		clear_nlink(child_inode);
out_data:
	ll_finish_md_op_data(op_data);
out_iput:
	if (locked)
		ll_inode_unlock(child_inode);
	iput(child_inode);
	RETURN(rc);
}

static int
ll_file_noflock(struct file *file, int cmd, struct file_lock *file_lock)
{
	struct ll_file_data *lfd = file->private_data;

	ENTRY;
	/*
	 * In order to avoid flood of warning messages, only print one message
	 * for one file. And the entire message rate on the client is limited
	 * by CDEBUG_LIMIT too.
	 */
	if (!(lfd->lfd_file_flags & LL_FILE_FLOCK_WARNING)) {
		lfd->lfd_file_flags |= LL_FILE_FLOCK_WARNING;
		CDEBUG_LIMIT(D_CONSOLE,
			     "flock disabled, mount with '-o [local]flock' to enable\r\n");
	}
	RETURN(-ENOSYS);
}

/*
 * test if some locks matching bits and l_req_mode are acquired
 * - bits can be in different locks
 * - if found clear the common lock bits in *bits
 * - the bits not found, are kept in *bits
 * \param inode [IN]
 * \param bits [IN]		searched lock bits [IN]
 * \param l_req_mode [IN]	searched lock mode
 * \param match_flags [IN]	match flags
 * \retval boolean, true iff all bits are found
 */
int ll_have_md_lock(struct obd_export *exp, struct inode *inode,
		    enum mds_ibits_locks *bits, enum ldlm_mode l_req_mode,
		    enum ldlm_match_flags match_flags)
{
	struct lustre_handle lockh;
	union ldlm_policy_data policy;
	enum ldlm_mode mode = (l_req_mode == LCK_MODE_MIN) ?
			      (LCK_CR | LCK_CW | LCK_PR | LCK_PW) : l_req_mode;
	struct lu_fid *fid;
	__u64 flags;
	int i;

	ENTRY;
	if (!inode)
		RETURN(0);

	fid = &ll_i2info(inode)->lli_fid;
	CDEBUG(D_INFO, "trying to match res "DFID" mode %s\n", PFID(fid),
	       ldlm_lockname[mode]);

	flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING | LDLM_FL_TEST_LOCK;
	for (i = 0; i < MDS_INODELOCK_NUMBITS && *bits != 0; i++) {
		policy.l_inodebits.bits = *bits & BIT(i);
		if (policy.l_inodebits.bits == MDS_INODELOCK_NONE)
			continue;

		if (md_lock_match(exp, flags, fid, LDLM_IBITS, &policy, mode,
				  match_flags, &lockh)) {
			struct ldlm_lock *lock;

			lock = ldlm_handle2lock(&lockh);
			if (lock) {
				*bits &=
					~(lock->l_policy_data.l_inodebits.bits);
				ldlm_lock_put(lock);
			} else {
				*bits &= ~policy.l_inodebits.bits;
			}
		}
	}
	RETURN(*bits == 0);
}

enum ldlm_mode ll_take_md_lock(struct inode *inode, __u64 bits,
			       struct lustre_handle *lockh, __u64 flags,
			       enum ldlm_mode mode)
{
	union ldlm_policy_data policy = { .l_inodebits = { bits } };
	struct lu_fid *fid;
	enum ldlm_mode rc;

	ENTRY;
	fid = &ll_i2info(inode)->lli_fid;
	CDEBUG(D_INFO, "trying to match res "DFID"\n", PFID(fid));

	rc = md_lock_match(ll_i2mdexp(inode), LDLM_FL_BLOCK_GRANTED|flags,
			   fid, LDLM_IBITS, &policy, mode, 0, lockh);

	RETURN(rc);
}

static int ll_inode_revalidate_fini(struct inode *inode, int rc)
{
	/* Already unlinked. Just update nlink and return success */
	if (rc == -ENOENT) {
		clear_nlink(inode);
		/* If it is striped directory, and there is bad stripe
		 * Let's revalidate the dentry again, instead of returning
		 * error
		 */
		if (ll_dir_striped(inode))
			return 0;

		/* This path cannot be hit for regular files unless in
		 * case of obscure races, so no need to to validate
		 * size.
		 */
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			return 0;
	} else if (rc != 0) {
		CDEBUG_LIMIT((rc == -EACCES || rc == -EIDRM) ? D_INFO : D_ERROR,
			     "%s: revalidate FID "DFID" error: rc = %d\n",
			     ll_i2sbi(inode)->ll_fsname,
			     PFID(ll_inode2fid(inode)), rc);
	}

	return rc;
}

static int ll_inode_revalidate(struct dentry *dentry, enum ldlm_intent_flags op)
{
	struct dentry *parent = NULL;
	struct inode *dir;
	struct inode *inode = dentry->d_inode;
	struct obd_export *exp = ll_i2mdexp(inode);
	struct lookup_intent oit = {
		.it_op = op,
	};
	struct ptlrpc_request *req = NULL;
	struct md_op_data *op_data;
	const char *name = NULL;
	size_t namelen = 0;
	int flags = 0;
	int rc = 0;

	ENTRY;
	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p),name="DNAME"\n",
	       PFID(ll_inode2fid(inode)), inode, encode_fn_dentry(dentry));

	/* Call getattr by fid */
	if ((exp_connect_flags2(exp) & OBD_CONNECT2_GETATTR_PFID) &&
		!d_lustre_invalid(dentry)) {
		flags = MF_GETATTR_BY_FID;
		parent = dget_parent(dentry);
		dir = d_inode(parent);
		name = dentry->d_name.name;
		namelen = dentry->d_name.len;
	} else {
		dir = inode;
	}

	op_data = ll_prep_md_op_data(NULL, dir, inode, name, namelen, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (parent)
		dput(parent);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_flags |= flags;
	rc = ll_intent_lock(exp, op_data, &oit, &req,
			    &ll_md_blocking_ast, 0, true);
	ll_finish_md_op_data(op_data);
	if (rc < 0) {
		rc = ll_inode_revalidate_fini(inode, rc);
		GOTO(out, rc);
	}

	rc = ll_revalidate_it_finish(req, &oit, dentry);
	if (rc != 0) {
		ll_intent_release(&oit);
		GOTO(out, rc);
	}

	/* Unlinked? Unhash dentry, so it is not picked up later by
	 * do_lookup() -> ll_revalidate_it(). We cannot use d_drop here to
	 * preserve get_cwd functionality on 2.6. Bug 10503
	 */
	if (!dentry->d_inode->i_nlink)
		d_lustre_invalidate(dentry);

	ll_lookup_finish_locks(&oit, dentry);
out:
	ptlrpc_req_put(req);

	return rc;
}

static int ll_merge_md_attr(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lmv_stripe_object *lsm_obj;
	struct cl_attr attr = { 0 };
	int rc;

	if (!ll_dir_striped(inode))
		RETURN(0);

	down_read(&lli->lli_lsm_sem);
	if (!ll_dir_striped_locked(inode)) {
		up_read(&lli->lli_lsm_sem);
		RETURN(0);
	}
	LASSERT(lli->lli_lsm_obj != NULL);

	lsm_obj = lmv_stripe_object_get(lli->lli_lsm_obj);
	up_read(&lli->lli_lsm_sem);

	rc = md_merge_attr(ll_i2mdexp(inode), lsm_obj,
			   &attr, ll_md_blocking_ast);
	lmv_stripe_object_put(&lsm_obj);
	if (rc != 0)
		RETURN(rc);

	spin_lock(&inode->i_lock);
	set_nlink(inode, attr.cat_nlink);
	spin_unlock(&inode->i_lock);

	inode->i_blocks = attr.cat_blocks;
	i_size_write(inode, attr.cat_size);

	ll_i2info(inode)->lli_atime = attr.cat_atime;
	ll_i2info(inode)->lli_mtime = attr.cat_mtime;
	ll_i2info(inode)->lli_ctime = attr.cat_ctime;

	RETURN(0);
}

int ll_getattr_dentry(struct dentry *de, struct kstat *stat, u32 request_mask,
		      unsigned int flags, bool foreign)
{
	struct inode *inode = de->d_inode;
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct dentry *parent;
	struct inode *dir;
	bool need_glimpse = true;
	ktime_t kstart = ktime_get();
	int rc;

	CDEBUG(D_VFSTRACE|D_IOTRACE,
	       "START file "DNAME":"DFID"(%p), request_mask %d, flags %u, foreign %d\n",
	       encode_fn_dentry(de), PFID(ll_inode2fid(inode)), inode,
	       request_mask, flags, foreign);

	/* The OST object(s) determine the file size, blocks and mtime. */
	if (!(request_mask & STATX_SIZE || request_mask & STATX_BLOCKS ||
	      request_mask & STATX_MTIME))
		need_glimpse = false;

	parent = dget_parent(de);
	dir = d_inode(parent);
	ll_statahead_enter(dir, de);
	if (dentry_may_statahead(dir, de))
		ll_start_statahead(dir, de, need_glimpse &&
				   !(flags & AT_STATX_DONT_SYNC));
	dput(parent);

	if (flags & AT_STATX_DONT_SYNC)
		GOTO(fill_attr, rc = 0);

	rc = ll_inode_revalidate(de, IT_GETATTR);
	if (rc < 0)
		RETURN(rc);

	/* foreign file/dir are always of zero length, so don't
	 * need to validate size.
	 */
	if (S_ISREG(inode->i_mode) && !foreign) {
		bool cached;

		if (!need_glimpse)
			GOTO(fill_attr, rc);

		rc = pcc_inode_getattr(inode, request_mask, flags, &cached);
		if (cached && rc < 0)
			RETURN(rc);

		if (cached)
			GOTO(fill_attr, rc);

		/*
		 * If the returned attr is masked with OBD_MD_FLSIZE &
		 * OBD_MD_FLBLOCKS & OBD_MD_FLMTIME, it means that the file size
		 * or blocks obtained from MDT is strictly correct, and the file
		 * is usually not being modified by clients, and the [a|m|c]time
		 * got from MDT is also strictly correct.
		 * Under this circumstance, it does not need to send glimpse
		 * RPCs to OSTs for file attributes such as the size and blocks.
		 */
		if (lli->lli_attr_valid & OBD_MD_FLSIZE &&
		    lli->lli_attr_valid & OBD_MD_FLBLOCKS &&
		    lli->lli_attr_valid & OBD_MD_FLMTIME) {
			inode_set_mtime(inode, lli->lli_mtime, 0);
			if (lli->lli_attr_valid & OBD_MD_FLATIME)
				inode_set_atime(inode, lli->lli_atime, 0);
			if (lli->lli_attr_valid & OBD_MD_FLCTIME)
				inode_set_ctime(inode, lli->lli_ctime, 0);
			GOTO(fill_attr, rc);
		}

		/* In case of restore, the MDT has the right size and has
		 * already send it back without granting the layout lock,
		 * inode is up-to-date so glimpse is useless.
		 * Also to glimpse we need the layout, in case of a running
		 * restore the MDT holds the layout lock so the glimpse will
		 * block up to the end of restore (getattr will block)
		 */
		if (!test_bit(LLIF_FILE_RESTORING, &lli->lli_flags)) {
			rc = ll_glimpse_size(inode);
			if (rc < 0)
				RETURN(rc);
		}
	} else {
		/* If object isn't regular file then don't validate size.
		 * foreign dir is not striped dir
		 */
		if (!foreign) {
			rc = ll_merge_md_attr(inode);
			if (rc < 0)
				RETURN(rc);
		}

		if (lli->lli_attr_valid & OBD_MD_FLATIME)
			inode_set_atime(inode, lli->lli_atime, 0);
		if (lli->lli_attr_valid & OBD_MD_FLMTIME)
			inode_set_mtime(inode, lli->lli_mtime, 0);
		if (lli->lli_attr_valid & OBD_MD_FLCTIME)
			inode_set_ctime(inode, lli->lli_ctime, 0);
	}

fill_attr:
	CFS_FAIL_TIMEOUT(OBD_FAIL_GETATTR_DELAY, 30);

	if (ll_need_32bit_api(sbi)) {
		stat->ino = cl_fid_build_ino(&lli->lli_fid, 1);
		stat->dev = ll_compat_encode_dev(inode->i_sb->s_dev);
		stat->rdev = ll_compat_encode_dev(inode->i_rdev);
	} else {
		stat->ino = inode->i_ino;
		stat->dev = inode->i_sb->s_dev;
		stat->rdev = inode->i_rdev;
	}

	/* foreign symlink to be exposed as a real symlink */
	if (!foreign)
		stat->mode = inode->i_mode;
	else
		stat->mode = (inode->i_mode & ~S_IFMT) | S_IFLNK;

	CFS_FAIL_CHECK_RESET(OBD_FAIL_LLITE_STAT_RACE1,
			     OBD_FAIL_LLITE_STAT_RACE2);
	/* pause to let other stat to do intermediate changes to inode */
	CFS_RACE(OBD_FAIL_LLITE_STAT_RACE2);

	/*
	 * ll_merge_attr() (in case of regular files) does not update
	 * inode's timestamps atomically. Protect against intermediate
	 * values
	 */
	if (!S_ISDIR(inode->i_mode))
		ll_inode_size_lock(inode);
	stat->uid = inode->i_uid;
	stat->gid = inode->i_gid;
	stat->atime = inode_get_atime(inode);
	stat->mtime = inode_get_mtime(inode);
	stat->ctime = inode_get_ctime(inode);

	/* stat->blksize is used to tell about preferred IO size */
	if (sbi->ll_stat_blksize)
		stat->blksize = sbi->ll_stat_blksize;
	else if (S_ISREG(inode->i_mode))
		stat->blksize = min(PTLRPC_MAX_BRW_SIZE,
				    1U << LL_MAX_BLKSIZE_BITS);
	else if (S_ISDIR(inode->i_mode))
		stat->blksize = min(MD_MAX_BRW_SIZE,
				    1U << LL_MAX_BLKSIZE_BITS);
	else
		stat->blksize = 1 << inode->i_sb->s_blocksize_bits;

	stat->nlink = inode->i_nlink;
	stat->size = i_size_read(inode);
	stat->blocks = inode->i_blocks;

	if (!S_ISDIR(inode->i_mode))
		ll_inode_size_unlock(inode);

#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_INODEOPS_ENHANCED_GETATTR)
	if (flags & AT_STATX_DONT_SYNC) {
		if (stat->size == 0 &&
		    lli->lli_attr_valid & OBD_MD_FLLAZYSIZE)
			stat->size = lli->lli_lazysize;
		if (stat->blocks == 0 &&
		    lli->lli_attr_valid & OBD_MD_FLLAZYBLOCKS)
			stat->blocks = lli->lli_lazyblocks;
	}

	if (lli->lli_attr_valid & OBD_MD_FLBTIME) {
		stat->result_mask |= STATX_BTIME;
		stat->btime.tv_sec = lli->lli_btime;
	}

	stat->attributes_mask = STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND;
#ifdef HAVE_LUSTRE_CRYPTO
	stat->attributes_mask |= STATX_ATTR_ENCRYPTED;
#endif
	stat->attributes |= ll_inode_to_ext_flags(inode->i_flags);
	/* if Lustre specific LUSTRE_ENCRYPT_FL flag is set, also set
	 * ext4 equivalent to please statx
	 */
	if (stat->attributes & LUSTRE_ENCRYPT_FL)
		stat->attributes |= STATX_ATTR_ENCRYPTED;
	stat->result_mask &= request_mask;
#endif

	ll_stats_ops_tally(sbi, LPROC_LL_GETATTR,
			   ktime_us_delta(ktime_get(), kstart));

	CDEBUG(D_IOTRACE,
	       "COMPLETED file "DNAME":"DFID"(%p), request_mask %d, flags %u, foreign %d\n",
	       encode_fn_dentry(de), PFID(ll_inode2fid(inode)), inode,
	       request_mask, flags, foreign);

	return 0;
}

#if defined(HAVE_USER_NAMESPACE_ARG) || defined(HAVE_INODEOPS_ENHANCED_GETATTR)
int ll_getattr(struct mnt_idmap *map, const struct path *path,
	       struct kstat *stat, u32 request_mask, unsigned int flags)
{
	return ll_getattr_dentry(path->dentry, stat, request_mask, flags,
				 false);
}
#else
int ll_getattr(struct vfsmount *mnt, struct dentry *de, struct kstat *stat)
{
	return ll_getattr_dentry(de, stat, STATX_BASIC_STATS,
				 AT_STATX_SYNC_AS_STAT, false);
}
#endif

static int cl_falloc(struct file *file, struct inode *inode, int mode,
		     loff_t offset, loff_t len)
{
	loff_t size = i_size_read(inode);
	struct lu_env *env;
	struct cl_io *io;
	__u16 refcheck;
	int rc;

	ENTRY;
	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = vvp_env_new_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;
	ll_io_set_mirror(io, file);

	io->ci_verify_layout = 1;
	io->u.ci_setattr.sa_parent_fid = lu_object_fid(&io->ci_obj->co_lu);
	io->u.ci_setattr.sa_falloc_mode = mode;
	io->u.ci_setattr.sa_falloc_offset = offset;
	io->u.ci_setattr.sa_falloc_end = offset + len;
	io->u.ci_setattr.sa_subtype = CL_SETATTR_FALLOCATE;

	CDEBUG(D_INODE, "UID %u GID %u PRJID %u\n",
	       from_kuid(&init_user_ns, inode->i_uid),
	       from_kgid(&init_user_ns, inode->i_gid),
	       ll_i2info(inode)->lli_projid);

	io->u.ci_setattr.sa_attr_uid = from_kuid(&init_user_ns, inode->i_uid);
	io->u.ci_setattr.sa_attr_gid = from_kgid(&init_user_ns, inode->i_gid);
	io->u.ci_setattr.sa_attr_projid = ll_i2info(inode)->lli_projid;

	if (io->u.ci_setattr.sa_falloc_end > size) {
		loff_t newsize = io->u.ci_setattr.sa_falloc_end;

		/* Check new size against VFS/VM file size limit and rlimit */
		rc = inode_newsize_ok(inode, newsize);
		if (rc)
			goto out;
		if (newsize > ll_file_maxbytes(inode)) {
			CDEBUG(D_INODE, "file size too large %llu > %llu\n",
			       (unsigned long long)newsize,
			       ll_file_maxbytes(inode));
			rc = -EFBIG;
			goto out;
		}
	}

	do {
		rc = cl_io_init(env, io, CIT_SETATTR, io->ci_obj);
		if (!rc)
			rc = cl_io_loop(env, io);
		else
			rc = io->ci_result;
		cl_io_fini(env, io);
	} while (unlikely(io->ci_need_restart));

out:
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

static long ll_fallocate(struct file *filp, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(filp);
	int rc;

	CDEBUG(D_VFSTRACE,  "VFS Op: "DNAME", mode %x, offset %lld, len %lld\n",
	       encode_fn_file(filp), mode, offset, len);

	if (offset < 0 || len <= 0)
		RETURN(-EINVAL);
	/*
	 * Encrypted inodes can't handle collapse range or zero range or insert
	 * range since we would need to re-encrypt blocks with a different IV or
	 * XTS tweak (which are based on the logical block number).
	 * Similar to what ext4 does.
	 */
	if (IS_ENCRYPTED(inode) &&
	    (mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE |
		     FALLOC_FL_ZERO_RANGE)))
		RETURN(-EOPNOTSUPP);

	/*
	 * mode == 0 (which is standard prealloc) and PUNCH/ZERO are supported
	 * Rest of mode options are not supported yet.
	 */
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_ZERO_RANGE))
		RETURN(-EOPNOTSUPP);

	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FALLOCATE, 1);

	rc = cl_falloc(filp, inode, mode, offset, len);
	/*
	 * ENOTSUPP (524) is an NFSv3 specific error code erroneously
	 * used by Lustre in several places. Retuning it here would
	 * confuse applications that explicity test for EOPNOTSUPP
	 * (95) and fall back to ftruncate().
	 */
	if (rc == -ENOTSUPP)
		rc = -EOPNOTSUPP;

	RETURN(rc);
}

static int ll_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		     __u64 start, __u64 len)
{
	int rc;
	size_t num_bytes;
	struct fiemap *fiemap;
	unsigned int extent_count = fieinfo->fi_extents_max;

	num_bytes = sizeof(*fiemap) + (extent_count *
				       sizeof(struct fiemap_extent));
	OBD_ALLOC_LARGE(fiemap, num_bytes);
	if (fiemap == NULL)
		RETURN(-ENOMEM);

	fiemap->fm_flags = fieinfo->fi_flags;
	fiemap->fm_extent_count = fieinfo->fi_extents_max;
	fiemap->fm_start = start;
	fiemap->fm_length = len;
	if (extent_count > 0 &&
	    copy_from_user(&fiemap->fm_extents[0], fieinfo->fi_extents_start,
			   sizeof(struct fiemap_extent)) != 0)
		GOTO(out, rc = -EFAULT);

	rc = ll_do_fiemap(inode, fiemap, num_bytes);

	if (IS_ENCRYPTED(inode) && extent_count > 0) {
		int i;

		for (i = 0; i < fiemap->fm_mapped_extents; i++)
			fiemap->fm_extents[i].fe_flags |=
				FIEMAP_EXTENT_DATA_ENCRYPTED |
				FIEMAP_EXTENT_ENCODED;
	}

	fieinfo->fi_flags = fiemap->fm_flags;
	fieinfo->fi_extents_mapped = fiemap->fm_mapped_extents;
	if (extent_count > 0 &&
	    copy_to_user(fieinfo->fi_extents_start, &fiemap->fm_extents[0],
			 fiemap->fm_mapped_extents *
			 sizeof(struct fiemap_extent)) != 0)
		GOTO(out, rc = -EFAULT);
out:
	OBD_FREE_LARGE(fiemap, num_bytes);
	return rc;
}

int ll_inode_permission(struct mnt_idmap *idmap, struct inode *inode, int mask)
{
	int rc = 0;
	struct ll_sb_info *sbi;
	struct root_squash_info *squash;
	struct cred *cred = NULL;
	const struct cred *old_cred = NULL;
	bool squash_id = false;
	ktime_t kstart = ktime_get();

	ENTRY;
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	/*
	 * as root inode are NOT getting validated in lookup operation,
	 * need to revalidate PERM before permission check.
	 */
	if (is_root_inode(inode)) {
		rc = ll_inode_revalidate(inode->i_sb->s_root, IT_GETATTR);
		if (rc)
			RETURN(rc);
	}

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), inode mode %x mask %o\n",
	       PFID(ll_inode2fid(inode)), inode, inode->i_mode, mask);

	/* squash fsuid/fsgid if needed */
	sbi = ll_i2sbi(inode);
	squash = &sbi->ll_squash;
	if (unlikely(squash->rsi_uid != 0 &&
		     uid_eq(current_fsuid(), GLOBAL_ROOT_UID) &&
		     !test_bit(LL_SBI_NOROOTSQUASH, sbi->ll_flags))) {
		squash_id = true;
	}
	if (squash_id) {
		CDEBUG(D_OTHER, "squash creds (%d:%d)=>(%d:%d)\n",
		       __kuid_val(current_fsuid()), __kgid_val(current_fsgid()),
		       squash->rsi_uid, squash->rsi_gid);

		/* update current process's credentials and FS capability */
		cred = prepare_creds();
		if (cred == NULL)
			RETURN(-ENOMEM);

		cred->fsuid = make_kuid(&init_user_ns, squash->rsi_uid);
		cred->fsgid = make_kgid(&init_user_ns, squash->rsi_gid);
		cred->cap_effective = cap_drop_nfsd_set(cred->cap_effective);
		cred->cap_effective = cap_drop_fs_set(cred->cap_effective);

		old_cred = override_creds(cred);
	}

	rc = generic_permission(idmap, inode, mask);
	/* restore current process's credentials and FS capability */
	if (squash_id) {
		revert_creds(old_cred);
		put_cred(cred);
	}

	if (!rc)
		ll_stats_ops_tally(sbi, LPROC_LL_INODE_PERM,
				   ktime_us_delta(ktime_get(), kstart));

	RETURN(rc);
}

# define ll_splice_read		pcc_file_splice_read

/* -o localflock - only provides locally consistent flock locks */
static const struct file_operations ll_file_operations = {
#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
# ifdef HAVE_SYNC_READ_WRITE
	.read		= new_sync_read,
	.write		= new_sync_write,
# endif
	.read_iter	= ll_file_read_iter,
	.write_iter	= ll_file_write_iter,
#else /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.read		= ll_file_read,
	.aio_read	= ll_file_aio_read,
	.write		= ll_file_write,
	.aio_write	= ll_file_aio_write,
#endif /* HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.unlocked_ioctl	= ll_file_ioctl,
	.open		= ll_file_open,
	.release	= ll_file_release,
	.mmap		= ll_file_mmap,
	.llseek		= ll_file_seek,
	.splice_read	= ll_splice_read,
#ifdef HAVE_ITER_FILE_SPLICE_WRITE
	.splice_write	= iter_file_splice_write,
#endif
	.fsync		= ll_fsync,
	.flush		= ll_flush,
	.fallocate	= ll_fallocate,
};

static const struct file_operations ll_file_operations_flock = {
#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
# ifdef HAVE_SYNC_READ_WRITE
	.read		= new_sync_read,
	.write		= new_sync_write,
# endif /* HAVE_SYNC_READ_WRITE */
	.read_iter	= ll_file_read_iter,
	.write_iter	= ll_file_write_iter,
#else /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.read		= ll_file_read,
	.aio_read	= ll_file_aio_read,
	.write		= ll_file_write,
	.aio_write	= ll_file_aio_write,
#endif /* HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.unlocked_ioctl	= ll_file_ioctl,
	.open		= ll_file_open,
	.release	= ll_file_release,
	.mmap		= ll_file_mmap,
	.llseek		= ll_file_seek,
	.splice_read	= ll_splice_read,
#ifdef HAVE_ITER_FILE_SPLICE_WRITE
	.splice_write	= iter_file_splice_write,
#endif
	.fsync		= ll_fsync,
	.flush		= ll_flush,
	.flock		= ll_file_flock,
	.lock		= ll_file_flock,
	.fallocate	= ll_fallocate,
};

/* These are for -o noflock - to return ENOSYS on flock calls */
static const struct file_operations ll_file_operations_noflock = {
#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
# ifdef HAVE_SYNC_READ_WRITE
	.read		= new_sync_read,
	.write		= new_sync_write,
# endif /* HAVE_SYNC_READ_WRITE */
	.read_iter	= ll_file_read_iter,
	.write_iter	= ll_file_write_iter,
#else /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.read		= ll_file_read,
	.aio_read	= ll_file_aio_read,
	.write		= ll_file_write,
	.aio_write	= ll_file_aio_write,
#endif /* HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.unlocked_ioctl	= ll_file_ioctl,
	.open		= ll_file_open,
	.release	= ll_file_release,
	.mmap		= ll_file_mmap,
	.llseek		= ll_file_seek,
	.splice_read	= ll_splice_read,
#ifdef HAVE_ITER_FILE_SPLICE_WRITE
	.splice_write	= iter_file_splice_write,
#endif
	.fsync		= ll_fsync,
	.flush		= ll_flush,
	.flock		= ll_file_noflock,
	.lock		= ll_file_noflock,
	.fallocate	= ll_fallocate,
};

const struct inode_operations ll_file_inode_operations = {
	.setattr	= ll_setattr,
	.getattr	= ll_getattr,
	.permission	= ll_inode_permission,
#ifdef HAVE_IOP_XATTR
	.setxattr	= ll_setxattr,
	.getxattr	= ll_getxattr,
	.removexattr	= ll_removexattr,
#endif
	.listxattr	= ll_listxattr,
	.fiemap		= ll_fiemap,
#ifdef HAVE_IOP_GET_INODE_ACL
	.get_inode_acl	= ll_get_inode_acl,
#endif
	.get_acl	= ll_get_acl,
#ifdef HAVE_IOP_SET_ACL
	.set_acl	= ll_set_acl,
#endif
#ifdef HAVE_FILEATTR_GET
	.fileattr_get	= ll_fileattr_get,
	.fileattr_set	= ll_fileattr_set,
#endif
};

const struct file_operations *ll_select_file_operations(struct ll_sb_info *sbi)
{
	const struct file_operations *fops = &ll_file_operations_noflock;

	if (test_bit(LL_SBI_FLOCK, sbi->ll_flags))
		fops = &ll_file_operations_flock;
	else if (test_bit(LL_SBI_LOCALFLOCK, sbi->ll_flags))
		fops = &ll_file_operations;

	return fops;
}

int ll_layout_conf(struct inode *inode, const struct cl_object_conf *conf)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct lu_env *env;
	int rc;
	__u16 refcheck;

	ENTRY;
	if (obj == NULL)
		RETURN(0);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	rc = cl_conf_set(env, lli->lli_clob, conf);
	if (rc < 0)
		GOTO(out, rc);

	if (conf->coc_opc == OBJECT_CONF_SET) {
		struct ldlm_lock *lock = conf->coc_lock;
		struct cl_layout cl = {
			.cl_layout_gen = 0,
		};

		LASSERT(lock != NULL);
		LASSERT(ldlm_has_layout(lock));

		/* it can only be allowed to match after layout is
		 * applied to inode otherwise false layout would be
		 * seen. Applying layout shoud happen before dropping
		 * the intent lock.
		 */
		ldlm_lock_allow_match(lock);

		rc = cl_object_layout_get(env, obj, &cl);
		if (rc < 0)
			GOTO(out, rc);

		CDEBUG(D_VFSTRACE,
		       DFID": layout version change: %u -> %u\n",
		       PFID(&lli->lli_fid), ll_layout_version_get(lli),
		       cl.cl_layout_gen);
		ll_layout_version_set(lli, cl.cl_layout_gen);
	}

out:
	cl_env_put(env, &refcheck);

	RETURN(rc < 0 ? rc : 0);
}

/* Fetch layout from MDT with getxattr request, if it's not ready yet */
static int ll_layout_fetch(struct inode *inode, struct ldlm_lock *lock)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req;
	void *lvbdata;
	void *lmm;
	int lmmsize;
	int rc;

	ENTRY;
	CDEBUG(D_INODE, DFID" LVB_READY=%d l_lvb_data=%p l_lvb_len=%u\n",
	       PFID(ll_inode2fid(inode)), ldlm_is_lvb_ready(lock),
	       lock->l_lvb_data, lock->l_lvb_len);

	if (lock->l_lvb_data != NULL)
		RETURN(0);

	/* if layout lock was granted right away, the layout is returned
	 * within DLM_LVB of dlm reply; otherwise if the lock was ever
	 * blocked and then granted via completion ast, we have to fetch
	 * layout here. Please note that we can't use the LVB buffer in
	 * completion AST because it doesn't have a large enough buffer
	 */
	rc = ll_get_default_mdsize(sbi, &lmmsize);
	if (rc < 0)
		RETURN(rc);

	rc = md_getxattr(sbi->ll_md_exp, ll_inode2fid(inode), OBD_MD_FLXATTR,
			 XATTR_NAME_LOV, lmmsize, ll_i2projid(inode), &req);
	if (rc < 0) {
		if (rc == -ENODATA)
			GOTO(out, rc = 0); /* empty layout */
		else
			RETURN(rc);
	}

	lmmsize = rc;
	rc = 0;
	if (lmmsize == 0) /* empty layout */
		GOTO(out, rc = 0);

	lmm = req_capsule_server_sized_get(&req->rq_pill, &RMF_EADATA, lmmsize);
	if (lmm == NULL)
		GOTO(out, rc = -EFAULT);

	OBD_ALLOC_LARGE(lvbdata, lmmsize);
	if (lvbdata == NULL)
		GOTO(out, rc = -ENOMEM);

	memcpy(lvbdata, lmm, lmmsize);
	lock_res_and_lock(lock);
	if (unlikely(lock->l_lvb_data == NULL)) {
		lock->l_lvb_type = LVB_T_LAYOUT;
		lock->l_lvb_data = lvbdata;
		lock->l_lvb_len = lmmsize;
		lvbdata = NULL;
	}
	unlock_res_and_lock(lock);

	if (lvbdata)
		OBD_FREE_LARGE(lvbdata, lmmsize);

	EXIT;

out:
	ptlrpc_req_put(req);
	return rc;
}

/*
 * Apply the layout to the inode. Layout lock is held and will be released
 * in this function.
 */
static int ll_layout_lock_set(struct lustre_handle *lockh, enum ldlm_mode mode,
			      struct inode *inode, bool try)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info    *sbi = ll_i2sbi(inode);
	struct ldlm_lock *lock;
	struct cl_object_conf conf;
	int rc = 0;
	bool lvb_ready;
	bool wait_layout = false;

	ENTRY;
	LASSERT(lustre_handle_is_used(lockh));

	lock = ldlm_handle2lock(lockh);
	LASSERT(lock != NULL);

	if (!ldlm_has_layout(lock))
		GOTO(out, rc = -EAGAIN);

	LDLM_DEBUG(lock, "file "DFID"(%p) being reconfigured",
		   PFID(&lli->lli_fid), inode);

	/* in case this is a caching lock and reinstate with new inode */
	md_set_lock_data(sbi->ll_md_exp, lockh, inode, NULL);

	lock_res_and_lock(lock);
	lvb_ready = ldlm_is_lvb_ready(lock);
	unlock_res_and_lock(lock);

	/* checking lvb_ready is racy but this is okay. The worst case is
	 * that multi processes may configure the file on the same time.
	 */
	if (lvb_ready)
		GOTO(out, rc = 0);

	rc = ll_layout_fetch(inode, lock);
	if (rc < 0)
		GOTO(out, rc);

	/* for layout lock, lmm is stored in lock's lvb.
	 * lvb_data is immutable if the lock is held so it's safe to access it
	 * without res lock.
	 *
	 * set layout to file. Unlikely this will fail as old layout was
	 * surely eliminated
	 */
	memset(&conf, 0, sizeof(conf));
	conf.coc_opc = OBJECT_CONF_SET;
	conf.coc_inode = inode;
	conf.coc_lock = lock;
	conf.coc_try = try;
	conf.u.coc_layout.lb_buf = lock->l_lvb_data;
	conf.u.coc_layout.lb_len = lock->l_lvb_len;
	rc = ll_layout_conf(inode, &conf);

	/* refresh layout failed, need to wait */
	wait_layout = rc == -EBUSY;
	EXIT;
out:
	ldlm_lock_put(lock);
	ldlm_lock_decref(lockh, mode);

	/* wait for IO to complete if it's still being used. */
	if (wait_layout) {
		CDEBUG(D_INODE, "%s: "DFID"(%p) wait for layout reconf\n",
		       sbi->ll_fsname, PFID(&lli->lli_fid), inode);

		memset(&conf, 0, sizeof(conf));
		conf.coc_opc = OBJECT_CONF_WAIT;
		conf.coc_inode = inode;
		rc = ll_layout_conf(inode, &conf);
		if (rc == 0)
			rc = -ERESTARTSYS;

		CDEBUG(D_INODE, "%s file="DFID" waiting layout return: %d\n",
		       sbi->ll_fsname, PFID(&lli->lli_fid), rc);
	}

	if (rc == -ERESTARTSYS) {
		__u16 refcheck;
		struct lu_env *env;
		struct cl_object *obj = lli->lli_clob;

		env = cl_env_get(&refcheck);
		if (IS_ERR(env))
			RETURN(PTR_ERR(env));

		CDEBUG(D_INODE, "prune without lock "DFID"\n",
				PFID(lu_object_fid(&obj->co_lu)));

		trunc_sem_down_write(&lli->lli_trunc_sem);
		cl_object_prune(env, obj);
		trunc_sem_up_write(&lli->lli_trunc_sem);
		cl_env_put(env, &refcheck);

		rc = -EAGAIN;
	}

	RETURN(rc);
}

/**
 * ll_layout_intent() - Issue layout intent RPC to MDS.
 * @inode: file inode
 * @intent: layout intent
 *
 * Return:
 * * %0  on success
 * * %<0 error code
 */
static int ll_layout_intent(struct inode *inode, struct layout_intent *intent)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct md_op_data *op_data;
	struct lookup_intent it;
	struct ptlrpc_request *req;
	int rc;

	ENTRY;
	op_data = ll_prep_md_op_data(NULL, inode, inode, NULL,
				     0, 0, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_data = intent;
	op_data->op_data_size = sizeof(*intent);

	memset(&it, 0, sizeof(it));
	it.it_op = IT_LAYOUT;
	if (intent->lai_opc == LAYOUT_INTENT_WRITE ||
	    intent->lai_opc == LAYOUT_INTENT_TRUNC ||
	    intent->lai_opc == LAYOUT_INTENT_PCCRO_SET ||
	    intent->lai_opc == LAYOUT_INTENT_PCCRO_CLEAR)
		it.it_open_flags = MDS_FMODE_WRITE;

	LDLM_DEBUG_NOLOCK("%s: requeue layout lock for file "DFID"(%p)",
			  sbi->ll_fsname, PFID(&lli->lli_fid), inode);

	rc = ll_intent_lock(sbi->ll_md_exp, op_data, &it, &req,
			    &ll_md_blocking_ast, 0, true);
	if (it.it_request != NULL)
		ptlrpc_req_put(it.it_request);
	it.it_request = NULL;

	ll_finish_md_op_data(op_data);

	/* set lock data in case this is a new lock */
	if (!rc)
		ll_set_lock_data(sbi->ll_md_exp, inode, &it, NULL);

	ll_intent_drop_lock(&it);

	RETURN(rc);
}

/*
 * This function checks if there exists a LAYOUT lock on the client side,
 * or enqueues it if it doesn't have one in cache.
 *
 * This function will not hold layout lock so it may be revoked any time after
 * this function returns. Any operations depend on layout should be redone
 * in that case.
 *
 * This function should be called before lov_io_init() to get an uptodate
 * layout version, the caller should save the version number and after IO
 * is finished, this function should be called again to verify that layout
 * is not changed during IO time.
 */
int ll_layout_refresh(struct inode *inode, __u32 *gen)
{
	struct ll_inode_info	*lli = ll_i2info(inode);
	struct ll_sb_info	*sbi = ll_i2sbi(inode);
	struct lustre_handle lockh;
	struct layout_intent intent = {
		.lai_opc = LAYOUT_INTENT_ACCESS,
	};
	enum ldlm_mode mode;
	int rc;
	bool try = true;

	ENTRY;
	*gen = ll_layout_version_get(lli);
	if (!test_bit(LL_SBI_LAYOUT_LOCK, sbi->ll_flags) ||
	    *gen != CL_LAYOUT_GEN_NONE)
		RETURN(0);

	/* sanity checks */
	LASSERT(fid_is_sane(ll_inode2fid(inode)));
	LASSERT(S_ISREG(inode->i_mode));

	while (1) {
		/* mostly layout lock is caching on the local side, so try to
		 * match it before grabbing layout lock mutex.
		 */
		mode = ll_take_md_lock(inode, MDS_INODELOCK_LAYOUT, &lockh, 0,
				       LCK_CR | LCK_CW | LCK_PR |
				       LCK_PW | LCK_EX);
		if (mode != 0) { /* hit cached lock */
			rc = ll_layout_lock_set(&lockh, mode, inode, try);
			try = false;
			if (rc == -EAGAIN)
				continue;
			break;
		}

		/* take layout lock mutex to enqueue layout lock exclusively. */
		mutex_lock(&lli->lli_layout_mutex);
		rc = ll_layout_intent(inode, &intent);
		mutex_unlock(&lli->lli_layout_mutex);
		if (rc != 0)
			break;
	}

	if (rc == 0)
		*gen = ll_layout_version_get(lli);

	RETURN(rc);
}

/**
 * ll_layout_write_intent() - Issue layout intent RPC indicating where in a file
 * an IO is about to write.
 * @inode: file inode.
 * @opc: type of layout operation being requested
 * @ext: write range with start offset of fille in bytes where an IO is
 * about to write, and exclusive end offset in bytes.
 *
 * Return:
 * * %0 on success
 * * <0 error code
 */
int ll_layout_write_intent(struct inode *inode, enum layout_intent_opc opc,
			   struct lu_extent *ext)
{
	struct layout_intent intent = {
		.lai_opc = opc,
		.lai_extent.e_start = ext->e_start,
		.lai_extent.e_end = ext->e_end,
	};
	int rc;

	ENTRY;
	rc = ll_layout_intent(inode, &intent);

	RETURN(rc);
}

/* This function send a restore request to the MDT */
int ll_layout_restore(struct inode *inode, loff_t offset, __u64 length)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct hsm_user_request *hur;
	int len, rc;

	ENTRY;
	len = sizeof(struct hsm_user_request) +
	      sizeof(struct hsm_user_item);
	OBD_ALLOC(hur, len);
	if (hur == NULL)
		RETURN(-ENOMEM);

	hur->hur_request.hr_action = HUA_RESTORE;
	hur->hur_request.hr_archive_id = 0;
	hur->hur_request.hr_flags = HSM_REQ_BLOCKING;
	memcpy(&hur->hur_user_item[0].hui_fid, &ll_i2info(inode)->lli_fid,
	       sizeof(hur->hur_user_item[0].hui_fid));
	hur->hur_user_item[0].hui_extent.offset = offset;
	hur->hur_user_item[0].hui_extent.length = length;
	hur->hur_request.hr_itemcount = 1;
	rc = mutex_lock_interruptible(&lli->lli_layout_mutex);
	if (rc)
		GOTO(out_free, rc);
	rc = obd_iocontrol(LL_IOC_HSM_REQUEST, ll_i2sbi(inode)->ll_md_exp,
			   len, hur, NULL);
	mutex_unlock(&lli->lli_layout_mutex);
out_free:
	OBD_FREE(hur, len);
	RETURN(rc);
}
