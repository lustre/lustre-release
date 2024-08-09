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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/delay.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_dlm.h>
#include "llite_internal.h"

#define SA_OMITTED_ENTRY_MAX 8ULL

enum sa_entry_state {
	/** negative values are for error cases */
	SA_ENTRY_INIT = 0,      /** init entry */
	SA_ENTRY_SUCC = 1,      /** stat succeed */
	SA_ENTRY_INVA = 2,      /** invalid entry */
};

/*
 * sa_entry is not refcounted: statahead thread allocates it and do async stat,
 * and in async stat callback ll_statahead_interpret() will prepare the inode
 * and set lock data in the ptlrpcd context. Then the scanner process will be
 * woken up if this entry is the waiting one, can access and free it.
 */
struct sa_entry {
	/* link into sai_entries */
	struct list_head		 se_list;
	/* link into sai hash table locally */
	struct list_head		 se_hash;
	/* entry index in the sai */
	__u64				 se_index;
	/* low layer ldlm lock handle */
	__u64				 se_handle;
	/* entry status */
	enum sa_entry_state		 se_state;
	/* entry size, contains name */
	int				 se_size;
	/* pointer to the target inode */
	struct inode			*se_inode;
	/* pointer to @sai per process struct */
	struct ll_statahead_info	*se_sai;
	/* entry name */
	struct qstr			 se_qstr;
	/* entry fid */
	struct lu_fid			 se_fid;
};

static unsigned int sai_generation;
static DEFINE_SPINLOCK(sai_generation_lock);

static inline int sa_unhashed(struct sa_entry *entry)
{
	return list_empty(&entry->se_hash);
}

/* sa_entry is ready to use */
static inline int sa_ready(struct sa_entry *entry)
{
	/* Make sure sa_entry is updated and ready to use */
	smp_rmb();
	return (entry->se_state != SA_ENTRY_INIT);
}

/* hash value to put in sai_cache */
static inline int sa_hash(int val)
{
	return val & LL_SA_CACHE_MASK;
}

/* hash entry into sax_cache */
static inline void
sa_rehash(struct ll_statahead_context *ctx, struct sa_entry *entry)
{
	int i = sa_hash(entry->se_qstr.hash);

	spin_lock(&ctx->sax_cache_lock[i]);
	list_add_tail(&entry->se_hash, &ctx->sax_cache[i]);
	spin_unlock(&ctx->sax_cache_lock[i]);
}

/* unhash entry from sai_cache */
static inline int sa_unhash(struct ll_statahead_context *ctx,
			    struct sa_entry *entry, bool inuse_check)
{
	struct ll_statahead_info *sai = entry->se_sai;
	int i = sa_hash(entry->se_qstr.hash);
	int rc = 0;

	if (inuse_check && atomic_read(&sai->sai_inuse_count) > 0)
		return -EAGAIN;

	spin_lock(&ctx->sax_cache_lock[i]);
	if (inuse_check && atomic_read(&sai->sai_inuse_count) > 0)
		rc = -EAGAIN;
	else
		list_del_init(&entry->se_hash);
	spin_unlock(&ctx->sax_cache_lock[i]);

	return rc;
}

static inline int agl_should_run(struct ll_statahead_info *sai,
				 struct inode *inode)
{
	return inode && S_ISREG(inode->i_mode) && sai->sai_agl_task;
}

static inline struct ll_inode_info *
agl_first_entry(struct ll_statahead_info *sai)
{
	return list_first_entry(&sai->sai_agls, struct ll_inode_info,
				lli_agl_list);
}

/* statahead window is full */
static inline int sa_sent_full(struct ll_statahead_info *sai)
{
	return atomic_read(&sai->sai_cache_count) >= sai->sai_max;
}

/* Batch metadata handle */
static inline bool sa_has_batch_handle(struct ll_statahead_info *sai)
{
	return sai->sai_bh != NULL;
}

static inline void ll_statahead_flush_nowait(struct ll_statahead_info *sai)
{
	if (sa_has_batch_handle(sai)) {
		sai->sai_index_end = sai->sai_index - 1;
		(void) md_batch_flush(ll_i2mdexp(sai->sai_dentry->d_inode),
				      sai->sai_bh, false);
	}
}

static inline int agl_list_empty(struct ll_statahead_info *sai)
{
	return list_empty(&sai->sai_agls);
}

/**
 * (1) hit ratio less than 80%
 * or
 * (2) consecutive miss more than 32
 * then means low hit.
 */
static inline int sa_low_hit(struct ll_statahead_info *sai)
{
	return ((sai->sai_hit > 32 && sai->sai_hit < 4 * sai->sai_miss) ||
		(sai->sai_consecutive_miss > 32));
}

/*
 * if the given index is behind of statahead window more than
 * SA_OMITTED_ENTRY_MAX, then it is old.
 */
static inline int is_omitted_entry(struct ll_statahead_info *sai, __u64 index)
{
	return ((__u64)sai->sai_max + index + SA_OMITTED_ENTRY_MAX <
		sai->sai_index);
}

/* allocate sa_entry and hash it to allow scanner process to find it */
static struct sa_entry *
sa_alloc(struct dentry *parent, struct ll_statahead_info *sai, __u64 index,
	 const char *name, int len, const struct lu_fid *fid)
{
	struct ll_inode_info *lli;
	struct sa_entry *entry;
	int entry_size;
	char *dname;

	ENTRY;

	entry_size = sizeof(struct sa_entry) +
		     round_up(len + 1 /* for trailing NUL */, 4);
	OBD_ALLOC(entry, entry_size);
	if (unlikely(!entry))
		RETURN(ERR_PTR(-ENOMEM));

	CDEBUG(D_READA, "alloc sa entry %.*s(%p) index %llu\n",
	       len, name, entry, index);

	entry->se_index = index;
	entry->se_sai = sai;

	entry->se_state = SA_ENTRY_INIT;
	entry->se_size = entry_size;
	dname = (char *)entry + sizeof(struct sa_entry);
	memcpy(dname, name, len);
	dname[len] = 0;
	entry->se_qstr.hash = ll_full_name_hash(parent, name, len);
	entry->se_qstr.len = len;
	entry->se_qstr.name = dname;

	if (fid)
		entry->se_fid = *fid;

	lli = ll_i2info(sai->sai_dentry->d_inode);
	spin_lock(&lli->lli_sa_lock);
	INIT_LIST_HEAD(&entry->se_list);
	sa_rehash(lli->lli_sax, entry);
	spin_unlock(&lli->lli_sa_lock);

	atomic_inc(&sai->sai_cache_count);

	RETURN(entry);
}

/* free sa_entry, which should have been unhashed and not in any list */
static void sa_free(struct ll_statahead_context *ctx, struct sa_entry *entry)
{
	CDEBUG(D_READA, "free sa entry %.*s(%p) index %llu\n",
	       entry->se_qstr.len, entry->se_qstr.name, entry,
	       entry->se_index);

	LASSERT(list_empty(&entry->se_list));
	LASSERT(sa_unhashed(entry));

	OBD_FREE(entry, entry->se_size);
}

/*
 * Find sa_entry by name, used by directory scanner. If @sai_pid is not the PID
 * of the scanner (which means it may do statahead wrongly, return -EINVAL
 * immediately.
 */
static struct sa_entry *sa_get(struct ll_statahead_context *ctx,
			       const struct qstr *qstr,
			       struct ll_statahead_info **info)
{
	struct sa_entry *entry;
	int i = sa_hash(qstr->hash);

	spin_lock(&ctx->sax_cache_lock[i]);
	list_for_each_entry(entry, &ctx->sax_cache[i], se_hash) {
		if (entry->se_qstr.hash == qstr->hash &&
		    entry->se_qstr.len == qstr->len &&
		    memcmp(entry->se_qstr.name, qstr->name, qstr->len) == 0) {
			struct ll_statahead_info *sai = entry->se_sai;

			if (sai->sai_pid != current->pid) {
				CDEBUG(D_CACHE,
				       "%s: wrong pid=%d:%d for entry %.*s\n",
				       ll_i2sbi(ctx->sax_inode)->ll_fsname,
				       sai->sai_pid, current->pid,
				       entry->se_qstr.len, entry->se_qstr.name);
				entry = ERR_PTR(-EINVAL);
				*info = sai;
			}

			atomic_inc(&sai->sai_inuse_count);
			spin_unlock(&ctx->sax_cache_lock[i]);
			return entry;
		}
	}
	spin_unlock(&ctx->sax_cache_lock[i]);
	return NULL;
}

/* unhash and unlink sa_entry, and then free it */
static inline int sa_kill(struct ll_statahead_info *sai, struct sa_entry *entry,
			  bool locked, bool inuse_check)
{
	struct inode *dir = sai->sai_dentry->d_inode;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_context *ctx = lli->lli_sax;
	int rc;

	LASSERT(!list_empty(&entry->se_list));
	LASSERT(sa_ready(entry));

	rc = sa_unhash(ctx, entry, inuse_check);
	if (rc)
		return rc;

	if (!locked)
		spin_lock(&lli->lli_sa_lock);
	list_del_init(&entry->se_list);
	spin_unlock(&lli->lli_sa_lock);

	iput(entry->se_inode);
	atomic_dec(&sai->sai_cache_count);

	sa_free(ctx, entry);
	if (locked)
		spin_lock(&lli->lli_sa_lock);

	return 0;
}

static inline int sa_kill_try(struct ll_statahead_info *sai,
			      struct sa_entry *entry, bool locked)
{
	return sa_kill(sai, entry, locked, true);
}

/* called by scanner after use, sa_entry will be killed */
static void
sa_put(struct inode *dir, struct ll_statahead_info *sai, struct sa_entry *entry)
{
	struct ll_inode_info *lli = ll_i2info(dir);
	struct sa_entry *tmp;
	bool wakeup = false;
	bool inuse = false;

	if (entry && entry->se_state == SA_ENTRY_SUCC) {
		struct ll_sb_info *sbi = ll_i2sbi(sai->sai_dentry->d_inode);

		sai->sai_hit++;
		sai->sai_consecutive_miss = 0;
		if (sai->sai_max < sbi->ll_sa_max) {
			sai->sai_max = min(2 * sai->sai_max, sbi->ll_sa_max);
			wakeup = true;
		} else if (sai->sai_max_batch_count > 0) {
			if (sai->sai_max >= sai->sai_max_batch_count &&
			   (sai->sai_index_end - entry->se_index) %
			   sai->sai_max_batch_count == 0) {
				wakeup = true;
			} else if (entry->se_index == sai->sai_index_end) {
				wakeup = true;
			}
		} else {
			wakeup = true;
		}
	} else if (sai) {
		sai->sai_miss++;
		sai->sai_consecutive_miss++;
		wakeup = true;
	}

	if (entry) {
		inuse = true;
		sa_kill(sai, entry, false, false);
		CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_STATAHEAD_PAUSE, cfs_fail_val);
	}

	spin_lock(&lli->lli_sa_lock);
	if (inuse) {
		/*
		 * kill old completed entries. Maybe kicking old entries can
		 * be ignored?
		 */
		while ((tmp = list_first_entry_or_null(&sai->sai_entries,
				struct sa_entry, se_list))) {
			if (!is_omitted_entry(sai, tmp->se_index))
				break;

			/* ll_sa_lock is dropped by sa_kill(), restart list */
			sa_kill(sai, tmp, true, false);
		}
	}
	if (wakeup && sai->sai_task)
		wake_up_process(sai->sai_task);
	if (inuse)
		atomic_dec(&sai->sai_inuse_count);
	spin_unlock(&lli->lli_sa_lock);
}

/*
 * update state and sort add entry to sai_entries by index, return true if
 * scanner is waiting on this entry.
 */
static bool
__sa_make_ready(struct ll_statahead_info *sai, struct sa_entry *entry, int ret)
{
	struct sa_entry *se;
	struct list_head *pos = &sai->sai_entries;
	__u64 index = entry->se_index;

	LASSERT(!sa_ready(entry));
	LASSERT(list_empty(&entry->se_list));

	list_for_each_entry_reverse(se, &sai->sai_entries, se_list) {
		if (se->se_index < entry->se_index) {
			pos = &se->se_list;
			break;
		}
	}
	list_add(&entry->se_list, pos);
	/*
	 * LU-9210: ll_statahead_interpet must be able to see this before
	 * we wake it up
	 */
	smp_store_release(&entry->se_state,
			  ret < 0 ? SA_ENTRY_INVA : SA_ENTRY_SUCC);

	return (index == sai->sai_index_wait);
}

/* finish async stat RPC arguments */
static void sa_fini_data(struct md_op_item *item)
{
	struct md_op_data *op_data = &item->mop_data;

	if (op_data->op_flags & MF_OPNAME_KMALLOCED)
		/* allocated via ll_setup_filename called from sa_prep_data */
		kfree(op_data->op_name);
	ll_unlock_md_op_lsm(&item->mop_data);
	iput(item->mop_dir);
	if (item->mop_subpill_allocated)
		OBD_FREE_PTR(item->mop_pill);
	OBD_FREE_PTR(item);
}

static int ll_statahead_interpret(struct md_op_item *item, int rc);

/*
 * prepare arguments for async stat RPC.
 */
static struct md_op_item *
sa_prep_data(struct inode *dir, struct inode *child, struct sa_entry *entry)
{
	struct md_op_item *item;
	struct ldlm_enqueue_info *einfo;
	struct md_op_data *op_data;

	OBD_ALLOC_PTR(item);
	if (!item)
		return ERR_PTR(-ENOMEM);

	op_data = ll_prep_md_op_data(&item->mop_data, dir, child,
				     entry->se_qstr.name, entry->se_qstr.len, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data)) {
		OBD_FREE_PTR(item);
		return (struct md_op_item *)op_data;
	}

	if (!child)
		op_data->op_fid2 = entry->se_fid;

	item->mop_opc = MD_OP_GETATTR;
	item->mop_it.it_op = IT_GETATTR;
	item->mop_dir = igrab(dir);
	item->mop_cb = ll_statahead_interpret;
	item->mop_cbdata = entry;

	einfo = &item->mop_einfo;
	einfo->ei_type = LDLM_IBITS;
	einfo->ei_mode = it_to_lock_mode(&item->mop_it);
	einfo->ei_cb_bl = ll_md_blocking_ast;
	einfo->ei_cb_cp = ldlm_completion_ast;
	einfo->ei_cb_gl = NULL;
	einfo->ei_cbdata = NULL;
	einfo->ei_req_slot = 1;

	return item;
}

/*
 * release resources used in async stat RPC, update entry state and wakeup if
 * scanner process it waiting on this entry.
 */
static void
sa_make_ready(struct ll_statahead_info *sai, struct sa_entry *entry, int ret)
{
	struct ll_inode_info *lli = ll_i2info(sai->sai_dentry->d_inode);
	bool wakeup;

	spin_lock(&lli->lli_sa_lock);
	wakeup = __sa_make_ready(sai, entry, ret);
	spin_unlock(&lli->lli_sa_lock);

	if (wakeup)
		wake_up(&sai->sai_waitq);
}

/* insert inode into the list of sai_agls */
static void ll_agl_add(struct ll_statahead_info *sai,
		       struct inode *inode, int index)
{
	struct ll_inode_info *child  = ll_i2info(inode);
	struct ll_inode_info *parent = ll_i2info(sai->sai_dentry->d_inode);

	spin_lock(&child->lli_agl_lock);
	if (child->lli_agl_index == 0) {
		child->lli_agl_index = index;
		spin_unlock(&child->lli_agl_lock);

		LASSERT(list_empty(&child->lli_agl_list));

		spin_lock(&parent->lli_agl_lock);
		/* Re-check under the lock */
		if (agl_should_run(sai, inode)) {
			if (agl_list_empty(sai))
				wake_up_process(sai->sai_agl_task);
			igrab(inode);
			list_add_tail(&child->lli_agl_list, &sai->sai_agls);
		} else
			child->lli_agl_index = 0;
		spin_unlock(&parent->lli_agl_lock);
	} else {
		spin_unlock(&child->lli_agl_lock);
	}
}

/* Allocate sax */
static struct ll_statahead_context *ll_sax_alloc(struct inode *dir)
{
	struct ll_statahead_context *ctx;
	int i;

	ENTRY;

	OBD_ALLOC_PTR(ctx);
	if (ctx == NULL)
		RETURN(NULL);

	ctx->sax_inode = igrab(dir);
	atomic_set(&ctx->sax_refcount, 1);
	INIT_LIST_HEAD(&ctx->sax_sai_list);
	for (i = 0; i < LL_SA_CACHE_SIZE; i++) {
		INIT_LIST_HEAD(&ctx->sax_cache[i]);
		spin_lock_init(&ctx->sax_cache_lock[i]);
	}

	RETURN(ctx);
}

static inline void ll_sax_free(struct ll_statahead_context *ctx)
{
	LASSERT(ctx->sax_inode != NULL);
	iput(ctx->sax_inode);
	OBD_FREE_PTR(ctx);
}

static inline void __ll_sax_get(struct ll_statahead_context *ctx)
{
	atomic_inc(&ctx->sax_refcount);
}

static inline struct ll_statahead_context *ll_sax_get(struct inode *dir)
{
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_context *ctx = NULL;

	spin_lock(&lli->lli_sa_lock);
	ctx = lli->lli_sax;
	if (ctx)
		__ll_sax_get(ctx);
	spin_unlock(&lli->lli_sa_lock);

	return ctx;
}

static inline void ll_sax_put(struct inode *dir,
			      struct ll_statahead_context *ctx)
{
	struct ll_inode_info *lli = ll_i2info(dir);

	if (atomic_dec_and_lock(&ctx->sax_refcount, &lli->lli_sa_lock)) {
		LASSERT(list_empty(&ctx->sax_sai_list));
		lli->lli_sai = NULL;
		lli->lli_sax = NULL;
		if (lli->lli_sa_pattern & (LSA_PATTERN_ADVISE |
					   LSA_PATTERN_FNAME)) {
			lli->lli_opendir_key = NULL;
			lli->lli_stat_pid = 0;
			lli->lli_sa_enabled = 0;
		}
		lli->lli_sa_pattern = LSA_PATTERN_NONE;
		spin_unlock(&lli->lli_sa_lock);

		ll_sax_free(ctx);
	}
}

/* allocate sai */
static struct ll_statahead_info *ll_sai_alloc(struct dentry *dentry)
{
	struct ll_statahead_info *sai;
	struct ll_inode_info *lli = ll_i2info(dentry->d_inode);

	ENTRY;

	OBD_ALLOC_PTR(sai);
	if (!sai)
		RETURN(NULL);

	sai->sai_dentry = dget(dentry);
	atomic_set(&sai->sai_refcount, 1);
	sai->sai_max = ll_i2sbi(dentry->d_inode)->ll_sa_min;
	sai->sai_index = 1;
	init_waitqueue_head(&sai->sai_waitq);

	INIT_LIST_HEAD(&sai->sai_item);
	INIT_LIST_HEAD(&sai->sai_entries);
	INIT_LIST_HEAD(&sai->sai_agls);

	atomic_set(&sai->sai_cache_count, 0);
	atomic_set(&sai->sai_inuse_count, 0);
	spin_lock(&sai_generation_lock);
	lli->lli_sa_generation = ++sai_generation;
	if (unlikely(sai_generation == 0))
		lli->lli_sa_generation = ++sai_generation;
	spin_unlock(&sai_generation_lock);

	RETURN(sai);
}

/* free sai */
static inline void ll_sai_free(struct ll_statahead_info *sai)
{
	LASSERT(sai->sai_dentry != NULL);
	dput(sai->sai_dentry);
	OBD_FREE_PTR(sai);
}

static inline struct ll_statahead_info *
__ll_sai_get(struct ll_statahead_info *sai)
{
	atomic_inc(&sai->sai_refcount);
	return sai;
}

/*
 * put sai refcount after use, if refcount reaches zero, free sai and sa_entries
 * attached to it.
 */
static void ll_sai_put(struct ll_statahead_info *sai)
{
	struct ll_inode_info *lli = ll_i2info(sai->sai_dentry->d_inode);

	if (atomic_dec_and_lock(&sai->sai_refcount, &lli->lli_sa_lock)) {
		struct ll_sb_info *sbi = ll_i2sbi(sai->sai_dentry->d_inode);

		lli->lli_sai = NULL;
		list_del_init(&sai->sai_item);
		spin_unlock(&lli->lli_sa_lock);

		LASSERT(!sai->sai_task);
		LASSERT(!sai->sai_agl_task);
		LASSERT(sai->sai_sent == sai->sai_replied);

		LASSERT(atomic_read(&sai->sai_cache_count) == 0);
		LASSERT(agl_list_empty(sai));

		ll_sai_free(sai);
		atomic_dec(&sbi->ll_sa_running);
	}
}

/* Do NOT forget to drop inode refcount when into sai_agls. */
static void ll_agl_trigger(struct inode *inode, struct ll_statahead_info *sai)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	u64 index = lli->lli_agl_index;
	ktime_t expire;
	int rc;

	ENTRY;

	LASSERT(list_empty(&lli->lli_agl_list));

	/* AGL maybe fall behind statahead with one entry */
	if (is_omitted_entry(sai, index + 1)) {
		lli->lli_agl_index = 0;
		iput(inode);
		RETURN_EXIT;
	}

	/*
	 * In case of restore, the MDT has the right size and has already
	 * sent it back without granting the layout lock, inode is up-to-date.
	 * Then AGL (async glimpse lock) is useless.
	 * Also to glimpse we need the layout, in case of a runninh restore
	 * the MDT holds the layout lock so the glimpse will block up to the
	 * end of restore (statahead/agl will block)
	 */
	if (test_bit(LLIF_FILE_RESTORING, &lli->lli_flags)) {
		lli->lli_agl_index = 0;
		iput(inode);
		RETURN_EXIT;
	}

	/* Someone is in glimpse (sync or async), do nothing. */
	rc = down_write_trylock(&lli->lli_glimpse_sem);
	if (rc == 0) {
		lli->lli_agl_index = 0;
		iput(inode);
		RETURN_EXIT;
	}

	/*
	 * Someone triggered glimpse within 1 sec before.
	 * 1) The former glimpse succeeded with glimpse lock granted by OST, and
	 *    if the lock is still cached on client, AGL needs to do nothing. If
	 *    it is cancelled by other client, AGL maybe cannot obtaion new lock
	 *    for no glimpse callback triggered by AGL.
	 * 2) The former glimpse succeeded, but OST did not grant glimpse lock.
	 *    Under such case, it is quite possible that the OST will not grant
	 *    glimpse lock for AGL also.
	 * 3) The former glimpse failed, compared with other two cases, it is
	 *    relative rare. AGL can ignore such case, and it will not muchly
	 *    affect the performance.
	 */
	expire = ktime_sub_ns(ktime_get(), NSEC_PER_SEC);
	if (ktime_to_ns(lli->lli_glimpse_time) &&
	    ktime_before(expire, lli->lli_glimpse_time)) {
		up_write(&lli->lli_glimpse_sem);
		lli->lli_agl_index = 0;
		iput(inode);
		RETURN_EXIT;
	}

	CDEBUG(D_READA,
	       "Handling (init) async glimpse: inode = " DFID", idx = %llu\n",
	       PFID(&lli->lli_fid), index);

	cl_agl(inode);
	lli->lli_agl_index = 0;
	lli->lli_glimpse_time = ktime_get();
	up_write(&lli->lli_glimpse_sem);

	CDEBUG(D_READA,
	       "Handled (init) async glimpse: inode= " DFID", idx = %llu, rc = %d\n",
	       PFID(&lli->lli_fid), index, rc);

	iput(inode);

	EXIT;
}

static void ll_statahead_interpret_fini(struct ll_inode_info *lli,
					struct ll_statahead_info *sai,
					struct md_op_item *item,
					struct sa_entry *entry,
					struct ptlrpc_request *req,
					int rc)
{
	/*
	 * First it will drop ldlm ibits lock refcount by calling
	 * ll_intent_drop_lock() in spite of failures. Do not worry about
	 * calling ll_intent_drop_lock() more than once.
	 */
	ll_intent_release(&item->mop_it);
	sa_fini_data(item);
	if (req)
		ptlrpc_req_put(req);
	sa_make_ready(sai, entry, rc);

	spin_lock(&lli->lli_sa_lock);
	sai->sai_replied++;
	spin_unlock(&lli->lli_sa_lock);
}

static void ll_statahead_interpret_work(struct work_struct *work)
{
	struct md_op_item *item = container_of(work, struct md_op_item,
					       mop_work);
	struct req_capsule *pill = item->mop_pill;
	struct inode *dir = item->mop_dir;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_info *sai;
	struct lookup_intent *it;
	struct sa_entry *entry;
	struct mdt_body *body;
	struct inode *child;
	int rc;

	ENTRY;

	entry = (struct sa_entry *)item->mop_cbdata;
	LASSERT(entry->se_handle != 0);

	sai = entry->se_sai;
	it = &item->mop_it;
	body = req_capsule_server_get(pill, &RMF_MDT_BODY);
	if (!body)
		GOTO(out, rc = -EFAULT);

	child = entry->se_inode;
	/* revalidate; unlinked and re-created with the same name */
	if (unlikely(!fid_is_zero(&item->mop_data.op_fid2) &&
		     !lu_fid_eq(&item->mop_data.op_fid2, &body->mbo_fid1))) {
		if (child) {
			entry->se_inode = NULL;
			iput(child);
		}
		/* The mdt_body is invalid. Skip this entry */
		GOTO(out, rc = -EAGAIN);
	}

	it->it_lock_handle = entry->se_handle;
	rc = md_revalidate_lock(ll_i2mdexp(dir), it, ll_inode2fid(dir), NULL);
	if (rc != 1)
		GOTO(out, rc = -EAGAIN);

	rc = ll_prep_inode(&child, pill, dir->i_sb, it);
	if (rc) {
		CERROR("%s: getattr callback for %.*s "DFID": rc = %d\n",
		       ll_i2sbi(dir)->ll_fsname, entry->se_qstr.len,
		       entry->se_qstr.name, PFID(&entry->se_fid), rc);
		GOTO(out, rc);
	}

	/* If encryption context was returned by MDT, put it in
	 * inode now to save an extra getxattr.
	 */
	if (body->mbo_valid & OBD_MD_ENCCTX) {
		void *encctx = req_capsule_server_get(pill, &RMF_FILE_ENCCTX);
		__u32 encctxlen = req_capsule_get_size(pill, &RMF_FILE_ENCCTX,
						       RCL_SERVER);

		if (encctxlen) {
			CDEBUG(D_SEC,
			       "server returned encryption ctx for "DFID"\n",
			       PFID(ll_inode2fid(child)));
			rc = ll_xattr_cache_insert(child,
						   xattr_for_enc(child),
						   encctx, encctxlen);
			if (rc)
				CWARN("%s: cannot set enc ctx for "DFID": rc = %d\n",
				      ll_i2sbi(child)->ll_fsname,
				      PFID(ll_inode2fid(child)), rc);
		}
	}

	CDEBUG(D_READA, "%s: setting %.*s"DFID" l_data to inode %p\n",
	       ll_i2sbi(dir)->ll_fsname, entry->se_qstr.len,
	       entry->se_qstr.name, PFID(ll_inode2fid(child)), child);
	ll_set_lock_data(ll_i2sbi(dir)->ll_md_exp, child, it, NULL);

	entry->se_inode = child;

	if (agl_should_run(sai, child))
		ll_agl_add(sai, child, entry->se_index);
out:
	ll_statahead_interpret_fini(lli, sai, item, entry, pill->rc_req, rc);
}

/*
 * Callback for async stat RPC, this is called in ptlrpcd context. It prepares
 * the inode and set lock data directly in the ptlrpcd context. It will wake up
 * the directory listing process if the dentry is the waiting one.
 */
static int ll_statahead_interpret(struct md_op_item *item, int rc)
{
	struct req_capsule *pill = item->mop_pill;
	struct lookup_intent *it = &item->mop_it;
	struct inode *dir = item->mop_dir;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct sa_entry *entry = (struct sa_entry *)item->mop_cbdata;
	struct work_struct *work = &item->mop_work;
	struct ll_statahead_info *sai;
	struct mdt_body *body;
	struct inode *child;
	__u64 handle = 0;

	ENTRY;

	if (it_disposition(it, DISP_LOOKUP_NEG))
		rc = -ENOENT;

	/*
	 * because statahead thread will wait for all inflight RPC to finish,
	 * sai should be always valid, no need to refcount
	 */
	LASSERT(entry != NULL);
	sai = entry->se_sai;
	LASSERT(sai != NULL);

	CDEBUG(D_READA, "sa_entry %.*s rc %d\n",
	       entry->se_qstr.len, entry->se_qstr.name, rc);

	if (rc != 0)
		GOTO(out, rc);

	body = req_capsule_server_get(pill, &RMF_MDT_BODY);
	if (!body)
		GOTO(out, rc = -EFAULT);

	child = entry->se_inode;
	/*
	 * revalidate; unlinked and re-created with the same name.
	 * exclude the case where FID is zero as it was from statahead with
	 * regularized file name pattern and had no idea for the FID of the
	 * children file.
	 */
	if (unlikely(!fid_is_zero(&item->mop_data.op_fid2) &&
		     !lu_fid_eq(&item->mop_data.op_fid2, &body->mbo_fid1))) {
		if (child) {
			entry->se_inode = NULL;
			iput(child);
		}
		/* The mdt_body is invalid. Skip this entry */
		GOTO(out, rc = -EAGAIN);
	}

	entry->se_handle = it->it_lock_handle;
	/*
	 * In ptlrpcd context, it is not allowed to generate new RPCs
	 * especially for striped directories or regular files with layout
	 * change.
	 */
	/*
	 * release ibits lock ASAP to avoid deadlock when statahead
	 * thread enqueues lock on parent in readdir and another
	 * process enqueues lock on child with parent lock held, eg.
	 * unlink.
	 */
	handle = it->it_lock_handle;
	ll_intent_drop_lock(it);
	ll_unlock_md_op_lsm(&item->mop_data);

	/*
	 * If the statahead entry is a striped directory or regular file with
	 * layout change, it will generate a new RPC and long wait in the
	 * ptlrpcd context.
	 * However, it is dangerous of blocking in ptlrpcd thread.
	 * Here we use work queue or the separate statahead thread to handle
	 * the extra RPC and long wait:
	 *	(@ll_prep_inode->@lmv_revalidate_slaves);
	 *	(@ll_prep_inode->@lov_layout_change->osc_cache_wait_range);
	 */
	INIT_WORK(work, ll_statahead_interpret_work);
	ptlrpc_request_addref(pill->rc_req);
	schedule_work(work);
	RETURN(0);
out:
	ll_statahead_interpret_fini(lli, sai, item, entry, NULL, rc);
	RETURN(rc);
}

static inline int sa_getattr(struct ll_statahead_info *sai, struct inode *dir,
			     struct md_op_item *item)
{
	int rc;

	if (sa_has_batch_handle(sai))
		rc = md_batch_add(ll_i2mdexp(dir), sai->sai_bh, item);
	else
		rc = md_intent_getattr_async(ll_i2mdexp(dir), item);

	return rc;
}

/* async stat for file not found in dcache */
static int sa_lookup(struct inode *dir, struct sa_entry *entry)
{
	struct md_op_item *item;
	int rc;

	ENTRY;

	item = sa_prep_data(dir, NULL, entry);
	if (IS_ERR(item))
		RETURN(PTR_ERR(item));

	rc = sa_getattr(entry->se_sai, dir, item);
	if (rc < 0)
		sa_fini_data(item);

	RETURN(rc);
}

/**
 * async stat for file found in dcache, similar to .revalidate
 *
 * \retval	1 dentry valid, no RPC sent
 * \retval	0 dentry invalid, will send async stat RPC
 * \retval	negative number upon error
 */
static int sa_revalidate(struct inode *dir, struct sa_entry *entry,
			 struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct lookup_intent it = { .it_op = IT_GETATTR,
				    .it_lock_handle = 0 };
	struct md_op_item *item;
	int rc;

	ENTRY;

	if (unlikely(!inode))
		RETURN(1);

	if (d_mountpoint(dentry))
		RETURN(1);

	item = sa_prep_data(dir, inode, entry);
	if (IS_ERR(item))
		RETURN(PTR_ERR(item));

	entry->se_inode = igrab(inode);
	rc = md_revalidate_lock(ll_i2mdexp(dir), &it, ll_inode2fid(inode),
				NULL);
	if (rc == 1) {
		entry->se_handle = it.it_lock_handle;
		ll_intent_release(&it);
		sa_fini_data(item);
		RETURN(1);
	}

	rc = sa_getattr(entry->se_sai, dir, item);
	if (rc < 0) {
		entry->se_inode = NULL;
		iput(inode);
		sa_fini_data(item);
	}

	RETURN(rc);
}

/* async stat for file with @name */
static void sa_statahead(struct ll_statahead_info *sai, struct dentry *parent,
			 const char *name, int len, const struct lu_fid *fid)
{
	struct inode *dir = parent->d_inode;
	struct dentry *dentry = NULL;
	struct sa_entry *entry;
	int rc;

	ENTRY;

	entry = sa_alloc(parent, sai, sai->sai_index, name, len, fid);
	if (IS_ERR(entry))
		RETURN_EXIT;

	dentry = d_lookup(parent, &entry->se_qstr);
	if (!dentry) {
		rc = sa_lookup(dir, entry);
	} else {
		rc = sa_revalidate(dir, entry, dentry);
		if (rc == 1 && agl_should_run(sai, dentry->d_inode))
			ll_agl_add(sai, dentry->d_inode, entry->se_index);
	}

	if (dentry)
		dput(dentry);

	if (rc != 0)
		sa_make_ready(sai, entry, rc);
	else
		sai->sai_sent++;

	sai->sai_index++;

	if (sa_sent_full(sai))
		ll_statahead_flush_nowait(sai);

	EXIT;
}

/* async glimpse (agl) thread main function */
static int ll_agl_thread(void *arg)
{
	/*
	 * We already own this reference, so it is safe to take it
	 * without a lock.
	 */
	struct ll_statahead_info *sai = (struct ll_statahead_info *)arg;
	struct dentry *parent = sai->sai_dentry;
	struct inode *dir = parent->d_inode;
	struct ll_inode_info *plli = ll_i2info(dir);
	struct ll_inode_info *clli;

	ENTRY;

	CDEBUG(D_READA, "agl thread started: sai %p, parent %pd\n",
	       sai, parent);

	while (({set_current_state(TASK_IDLE);
		 !kthread_should_stop(); })) {
		spin_lock(&plli->lli_agl_lock);
		clli = list_first_entry_or_null(&sai->sai_agls,
						struct ll_inode_info,
						lli_agl_list);
		if (clli) {
			__set_current_state(TASK_RUNNING);
			list_del_init(&clli->lli_agl_list);
			spin_unlock(&plli->lli_agl_lock);
			ll_agl_trigger(&clli->lli_vfs_inode, sai);
			cond_resched();
		} else {
			spin_unlock(&plli->lli_agl_lock);
			schedule();
		}
	}
	__set_current_state(TASK_RUNNING);
	RETURN(0);
}

static void ll_stop_agl(struct ll_statahead_info *sai)
{
	struct dentry *parent = sai->sai_dentry;
	struct ll_inode_info *plli = ll_i2info(parent->d_inode);
	struct ll_inode_info *clli;
	struct task_struct *agl_task;

	spin_lock(&plli->lli_agl_lock);
	agl_task = sai->sai_agl_task;
	sai->sai_agl_task = NULL;
	spin_unlock(&plli->lli_agl_lock);
	if (!agl_task)
		return;

	CDEBUG(D_READA, "stop agl thread: sai %p pid %u\n",
	       sai, (unsigned int)agl_task->pid);
	kthread_stop(agl_task);

	spin_lock(&plli->lli_agl_lock);
	while ((clli = list_first_entry_or_null(&sai->sai_agls,
						struct ll_inode_info,
						lli_agl_list)) != NULL) {
		list_del_init(&clli->lli_agl_list);
		spin_unlock(&plli->lli_agl_lock);
		clli->lli_agl_index = 0;
		iput(&clli->lli_vfs_inode);
		spin_lock(&plli->lli_agl_lock);
	}
	spin_unlock(&plli->lli_agl_lock);
	CDEBUG(D_READA, "agl thread stopped: sai %p, parent %pd\n",
	       sai, parent);
	ll_sai_put(sai);
}

/* start agl thread */
static void ll_start_agl(struct dentry *parent, struct ll_statahead_info *sai)
{
	int node = cfs_cpt_spread_node(cfs_cpt_tab, CFS_CPT_ANY);
	struct ll_inode_info *plli;
	struct task_struct *task;

	ENTRY;

	CDEBUG(D_READA, "start agl thread: sai %p, parent %pd\n",
	       sai, parent);

	plli = ll_i2info(parent->d_inode);
	task = kthread_create_on_node(ll_agl_thread, sai, node, "ll_agl_%d",
				      plli->lli_stat_pid);
	if (IS_ERR(task)) {
		CERROR("can't start ll_agl thread, rc: %ld\n", PTR_ERR(task));
		RETURN_EXIT;
	}
	sai->sai_agl_task = task;
	atomic_inc(&ll_i2sbi(d_inode(parent))->ll_agl_total);
	/* Get an extra reference that the thread holds */
	__ll_sai_get(sai);

	wake_up_process(task);

	EXIT;
}

static int ll_statahead_by_list(struct dentry *parent)
{
	struct inode *dir = parent->d_inode;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_info *sai = lli->lli_sai;
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct md_op_data *op_data;
	struct page *page = NULL;
	__u64 pos = 0;
	int first = 0;
	int rc = 0;

	ENTRY;

	CDEBUG(D_READA, "statahead thread starting: sai %p, parent %pd\n",
	       sai, parent);

	OBD_ALLOC_PTR(op_data);
	if (!op_data)
		RETURN(-ENOMEM);

	while (pos != MDS_DIR_END_OFF &&
	       /* matches smp_store_release() in ll_deauthorize_statahead() */
	       smp_load_acquire(&sai->sai_task) &&
	       lli->lli_sa_enabled) {
		struct lu_dirpage *dp;
		struct lu_dirent  *ent;

		op_data = ll_prep_md_op_data(op_data, dir, dir, NULL, 0, 0,
					     LUSTRE_OPC_ANY, dir);
		if (IS_ERR(op_data)) {
			rc = PTR_ERR(op_data);
			break;
		}

		page = ll_get_dir_page(dir, op_data, pos, NULL);
		ll_unlock_md_op_lsm(op_data);
		if (IS_ERR(page)) {
			rc = PTR_ERR(page);
			CDEBUG(D_READA,
			       "error reading dir "DFID" at %llu /%llu stat_pid = %u: rc = %d\n",
			       PFID(ll_inode2fid(dir)), pos, sai->sai_index,
			       lli->lli_stat_pid, rc);
			break;
		}

		dp = page_address(page);
		for (ent = lu_dirent_start(dp);
		     /* matches smp_store_release() in ll_deauthorize_statahead() */
		     ent != NULL && smp_load_acquire(&sai->sai_task) &&
		     !sa_low_hit(sai) && lli->lli_sa_enabled;
		     ent = lu_dirent_next(ent)) {
			__u64 hash;
			int namelen;
			char *name;
			struct lu_fid fid;
			struct llcrypt_str lltr = LLTR_INIT(NULL, 0);

			hash = le64_to_cpu(ent->lde_hash);
			if (unlikely(hash < pos))
				/*
				 * Skip until we find target hash value.
				 */
				continue;

			namelen = le16_to_cpu(ent->lde_namelen);
			if (unlikely(namelen == 0))
				/*
				 * Skip dummy record.
				 */
				continue;

			name = ent->lde_name;
			if (name[0] == '.') {
				if (namelen == 1) {
					/*
					 * skip "."
					 */
					continue;
				} else if (name[1] == '.' && namelen == 2) {
					/*
					 * skip ".."
					 */
					continue;
				} else if (!sai->sai_ls_all) {
					/*
					 * skip hidden files.
					 */
					sai->sai_skip_hidden++;
					continue;
				}
			}

			/*
			 * don't stat-ahead first entry.
			 */
			if (unlikely(++first == 1))
				continue;

			fid_le_to_cpu(&fid, &ent->lde_fid);

			while (({set_current_state(TASK_IDLE);
				 /* matches smp_store_release() in
				  * ll_deauthorize_statahead()
				  */
				 smp_load_acquire(&sai->sai_task); })) {
				long timeout;

				spin_lock(&lli->lli_agl_lock);
				while (sa_sent_full(sai) &&
				       !agl_list_empty(sai)) {
					struct ll_inode_info *clli;

					__set_current_state(TASK_RUNNING);
					clli = agl_first_entry(sai);
					list_del_init(&clli->lli_agl_list);
					spin_unlock(&lli->lli_agl_lock);

					ll_agl_trigger(&clli->lli_vfs_inode,
						       sai);
					cond_resched();
					spin_lock(&lli->lli_agl_lock);
				}
				spin_unlock(&lli->lli_agl_lock);

				if (!sa_sent_full(sai))
					break;

				/*
				 * If the thread is not doing stat in
				 * @sbi->ll_sa_timeout (30s) then it probably
				 * does not care too much about performance,
				 * or is no longer using this directory.
				 * Stop the statahead thread in this case.
				 */
				timeout = schedule_timeout(
					cfs_time_seconds(sbi->ll_sa_timeout));
				if (timeout == 0) {
					lli->lli_sa_enabled = 0;
					break;
				}
			}
			__set_current_state(TASK_RUNNING);

			if (IS_ENCRYPTED(dir)) {
				struct llcrypt_str de_name =
					LLTR_INIT(ent->lde_name, namelen);
				struct lu_fid fid;

				rc = llcrypt_fname_alloc_buffer(dir, NAME_MAX,
								&lltr);
				if (rc < 0)
					continue;

				fid_le_to_cpu(&fid, &ent->lde_fid);
				if (ll_fname_disk_to_usr(dir, 0, 0, &de_name,
							 &lltr, &fid)) {
					llcrypt_fname_free_buffer(&lltr);
					continue;
				}

				name = lltr.name;
				namelen = lltr.len;
			}

			sa_statahead(sai, parent, name, namelen, &fid);
			llcrypt_fname_free_buffer(&lltr);
		}

		pos = le64_to_cpu(dp->ldp_hash_end);
		ll_release_page(dir, page,
				le32_to_cpu(dp->ldp_flags) & LDF_COLLIDE);

		if (sa_low_hit(sai)) {
			rc = -EFAULT;
			atomic_inc(&sbi->ll_sa_wrong);
			CDEBUG(D_READA,
			       "Statahead for dir "DFID" hit ratio too low: hit/miss %llu/%llu, sent/replied %llu/%llu, stoppingstatahead thread: pid %d\n",
			       PFID(&lli->lli_fid), sai->sai_hit,
			       sai->sai_miss, sai->sai_sent,
			       sai->sai_replied, current->pid);
			break;
		}
	}
	ll_finish_md_op_data(op_data);

	RETURN(rc);
}

static void ll_statahead_handle(struct ll_statahead_info *sai,
				struct dentry *parent, const char *name,
				int len, const struct lu_fid *fid)
{
	struct inode *dir = parent->d_inode;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	long timeout;

	while (({set_current_state(TASK_IDLE);
		/* matches smp_store_release() in ll_deauthorize_statahead() */
		 smp_load_acquire(&sai->sai_task); })) {
		spin_lock(&lli->lli_agl_lock);
		while (sa_sent_full(sai) && !agl_list_empty(sai)) {
			struct ll_inode_info *clli;

			__set_current_state(TASK_RUNNING);
			clli = agl_first_entry(sai);
			list_del_init(&clli->lli_agl_list);
			spin_unlock(&lli->lli_agl_lock);

			ll_agl_trigger(&clli->lli_vfs_inode, sai);
			cond_resched();
			spin_lock(&lli->lli_agl_lock);
		}
		spin_unlock(&lli->lli_agl_lock);

		if (!sa_sent_full(sai))
			break;

		/*
		 * If the thread is not doing a stat in 30s then it probably
		 * does not care too much about performance, or is no longer
		 * using this directory. Stop the statahead thread in this case.
		 */
		timeout = schedule_timeout(
				cfs_time_seconds(sbi->ll_sa_timeout));
		if (timeout == 0) {
			lli->lli_sa_enabled = 0;
			break;
		}
	}
	__set_current_state(TASK_RUNNING);

	sa_statahead(sai, parent, name, len, fid);
}

static int ll_statahead_by_advise(struct ll_statahead_info *sai,
				  struct dentry *parent)
{
	struct inode *dir = parent->d_inode;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	size_t max_len;
	size_t len;
	char *fname;
	char *ptr;
	int rc = 0;
	__u64 i = 0;

	ENTRY;

	CDEBUG(D_READA, "%s: ADVISE statahead: parent %pd fname prefix %s\n",
	       sbi->ll_fsname, parent, sai->sai_fname);

	OBD_ALLOC(fname, NAME_MAX);
	if (fname == NULL)
		RETURN(-ENOMEM);

	len = strlen(sai->sai_fname);
	memcpy(fname, sai->sai_fname, len);
	max_len = sizeof(sai->sai_fname) - len;
	ptr = fname + len;

	/* matches smp_store_release() in ll_deauthorize_statahead() */
	while (smp_load_acquire(&sai->sai_task) && lli->lli_sa_enabled) {
		size_t numlen;

		numlen = snprintf(ptr, max_len, "%llu",
				  sai->sai_fstart + i);

		ll_statahead_handle(sai, parent, fname, len + numlen, NULL);
		if (++i >= sai->sai_fend)
			break;
	}

	OBD_FREE(fname, NAME_MAX);
	RETURN(rc);
}

static int ll_statahead_by_fname(struct ll_statahead_info *sai,
				 struct dentry *parent)
{
	struct inode *dir = parent->d_inode;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	size_t max_len;
	size_t len;
	char *fname;
	char *ptr;
	int rc = 0;

	ENTRY;

	CDEBUG(D_READA, "%s: FNAME statahead: parent %pd fname prefix %s\n",
	       sbi->ll_fsname, parent, sai->sai_fname);

	OBD_ALLOC(fname, NAME_MAX);
	if (fname == NULL)
		RETURN(-ENOMEM);

	len = strlen(sai->sai_fname);
	memcpy(fname, sai->sai_fname, len);
	max_len = sizeof(sai->sai_fname) - len;
	ptr = fname + len;

	/* matches smp_store_release() in ll_deauthorize_statahead() */
	while (smp_load_acquire(&sai->sai_task) && lli->lli_sa_enabled) {
		size_t numlen;

		if (sai->sai_fname_zeroed_len)
			numlen = snprintf(ptr, max_len, "%0*llu",
					  sai->sai_fname_zeroed_len,
					  ++sai->sai_fname_index);
		else
			numlen = snprintf(ptr, max_len, "%llu",
					  ++sai->sai_fname_index);

		ll_statahead_handle(sai, parent, fname, len + numlen, NULL);

		if (sa_low_hit(sai)) {
			rc = -EFAULT;
			atomic_inc(&sbi->ll_sa_wrong);
			CDEBUG(D_CACHE, "%s: low hit ratio for %pd "DFID": hit=%llu miss=%llu sent=%llu replied=%llu, stopping PID %d\n",
			       sbi->ll_fsname, parent, PFID(ll_inode2fid(dir)),
			       sai->sai_hit, sai->sai_miss, sai->sai_sent,
			       sai->sai_replied, current->pid);
			break;
		}
	}

	OBD_FREE(fname, NAME_MAX);
	RETURN(rc);
}

/* statahead thread main function */
static int ll_statahead_thread(void *arg)
{
	struct ll_statahead_info *sai = (struct ll_statahead_info *)arg;
	struct dentry *parent = sai->sai_dentry;
	struct inode *dir = parent->d_inode;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct lu_batch *bh = NULL;
	struct sa_entry *entry;
	int tries = 0;
	int rc = 0;

	ENTRY;

	CDEBUG(D_READA, "statahead thread starting: sai %p, parent %pd\n",
	       sai, parent);

	if (exp_connect_batch_rpc(sbi->ll_md_exp))
		sai->sai_max_batch_count = sbi->ll_sa_batch_max;
	else
		sai->sai_max_batch_count = 0;

	if (sai->sai_max_batch_count) {
		bh = md_batch_create(ll_i2mdexp(dir), BATCH_FL_RDONLY,
				     sai->sai_max_batch_count);
		if (IS_ERR(bh))
			GOTO(out_stop_agl, rc = PTR_ERR(bh));
	}

	sai->sai_bh = bh;

	switch (lli->lli_sa_pattern & LSA_PATTERN_MASK) {
	case LSA_PATTERN_LIST:
		rc = ll_statahead_by_list(parent);
		break;
	case LSA_PATTERN_ADVISE:
		rc = ll_statahead_by_advise(sai, parent);
		break;
	case LSA_PATTERN_FNAME:
		rc = ll_statahead_by_fname(sai, parent);
		break;
	default:
		rc = -EFAULT;
		break;
	}

	if (rc < 0) {
		spin_lock(&lli->lli_sa_lock);
		sai->sai_task = NULL;
		spin_unlock(&lli->lli_sa_lock);
	}

	ll_statahead_flush_nowait(sai);

	/*
	 * statahead is finished, but statahead entries need to be cached, wait
	 * for file release closedir() call to stop me.
	 */
	while (({set_current_state(TASK_IDLE);
		/* matches smp_store_release() in ll_deauthorize_statahead() */
		smp_load_acquire(&sai->sai_task) && lli->lli_sa_enabled; })) {
		schedule();
	}
	__set_current_state(TASK_RUNNING);

	EXIT;

	if (bh) {
		rc = md_batch_stop(ll_i2mdexp(dir), sai->sai_bh);
		sai->sai_bh = NULL;
	}

out_stop_agl:
	ll_stop_agl(sai);

	/*
	 * wait for inflight statahead RPCs to finish, and then we can free sai
	 * safely because statahead RPC will access sai data
	 */
	while (sai->sai_sent != sai->sai_replied)
		/* in case we're not woken up, timeout wait */
		msleep(125);

	CDEBUG(D_READA, "%s: statahead thread stopped: sai %p, parent %pd hit %llu miss %llu\n",
	       sbi->ll_fsname, sai, parent, sai->sai_hit, sai->sai_miss);

	spin_lock(&lli->lli_sa_lock);
	sai->sai_task = NULL;
	spin_unlock(&lli->lli_sa_lock);
	wake_up(&sai->sai_waitq);

	atomic_add(sai->sai_hit, &sbi->ll_sa_hit_total);
	atomic_add(sai->sai_miss, &sbi->ll_sa_miss_total);

	/* Kill all local cached entry. */
	spin_lock(&lli->lli_sa_lock);
	while ((entry = list_first_entry_or_null(&sai->sai_entries,
						 struct sa_entry, se_list))) {
		/*
		 * If the entry is being used by the user process, wait for
		 * inuse entry finished and restart to kill local cached
		 * entries.
		 */
		if (sa_kill_try(sai, entry, true)) {
			spin_unlock(&lli->lli_sa_lock);
			msleep(125);
			if (++tries % 1024 == 0) {
				CWARN("%s: statahead thread waited %lums for inuse entry "DFID" to be finished\n",
				      sbi->ll_fsname, tries * 125/MSEC_PER_SEC,
				      PFID(&entry->se_fid));
			}
			spin_lock(&lli->lli_sa_lock);
		}
	}
	spin_unlock(&lli->lli_sa_lock);

	ll_sai_put(sai);
	ll_sax_put(dir, lli->lli_sax);

	return rc;
}

/* authorize opened dir handle @key to statahead */
void ll_authorize_statahead(struct inode *dir, void *key)
{
	struct ll_inode_info *lli = ll_i2info(dir);

	spin_lock(&lli->lli_sa_lock);
	if (!lli->lli_opendir_key && !lli->lli_sai) {
		/*
		 * if lli_sai is not NULL, it means previous statahead is not
		 * finished yet, we'd better not start a new statahead for now.
		 */
		lli->lli_opendir_key = key;
		lli->lli_stat_pid = current->pid;
		lli->lli_sa_enabled = 1;
		lli->lli_sa_pattern |= LSA_PATTERN_OPENDIR;
	}
	spin_unlock(&lli->lli_sa_lock);
}

static void ll_deauthorize_statahead_advise(struct inode *dir, void *key)
{
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_file_data *lfd = (struct ll_file_data *)key;
	struct ll_statahead_info *sai = lfd->fd_sai;

	if (sai == NULL)
		return;

	spin_lock(&lli->lli_sa_lock);
	if (sai->sai_task) {
		struct task_struct *task = sai->sai_task;

		/* matches smp_load_acquire() in ll_statahead_thread() */
		smp_store_release(&sai->sai_task, NULL);
		wake_up_process(task);
	}
	lfd->fd_sai = NULL;
	spin_unlock(&lli->lli_sa_lock);
	ll_sai_put(sai);
	LASSERT(lli->lli_sax != NULL);
	ll_sax_put(dir, lli->lli_sax);
}

/*
 * deauthorize opened dir handle @key to statahead, and notify statahead thread
 * to quit if it's running.
 */
void ll_deauthorize_statahead(struct inode *dir, void *key)
{
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_info *sai;

	CDEBUG(D_READA, "deauthorize statahead for "DFID"\n",
	       PFID(&lli->lli_fid));

	if (lli->lli_sa_pattern & LSA_PATTERN_ADVISE) {
		ll_deauthorize_statahead_advise(dir, key);
		return;
	}

	LASSERT(lli->lli_stat_pid != 0);
	LASSERT(lli->lli_opendir_key == key);
	spin_lock(&lli->lli_sa_lock);
	lli->lli_opendir_key = NULL;
	lli->lli_stat_pid = 0;
	lli->lli_sa_enabled = 0;
	lli->lli_sa_pattern = LSA_PATTERN_NONE;
	lli->lli_sa_fname_index = 0;
	lli->lli_sa_match_count = 0;
	sai = lli->lli_sai;
	if (sai && sai->sai_task) {
		/*
		 * statahead thread may not have quit yet because it needs to
		 * cache entries, now it's time to tell it to quit.
		 *
		 * wake_up_process() provides the necessary barriers
		 * to pair with set_current_state().
		 */
		struct task_struct *task = sai->sai_task;

		/* matches smp_load_acquire() in ll_statahead_thread() */
		smp_store_release(&sai->sai_task, NULL);
		wake_up_process(task);
	}
	spin_unlock(&lli->lli_sa_lock);
}

enum {
	/**
	 * not first dirent, or is "."
	 */
	LS_NOT_FIRST_DE = 0,
	/**
	 * the first non-hidden dirent
	 */
	LS_FIRST_DE,
	/**
	 * the first hidden dirent, that is "."
	 */
	LS_FIRST_DOT_DE
};

/* file is first dirent under @dir */
static int is_first_dirent(struct inode *dir, struct dentry *dentry)
{
	struct qstr *target = &dentry->d_name;
	struct md_op_data *op_data;
	int dot_de;
	struct page *page = NULL;
	int rc = LS_NOT_FIRST_DE;
	__u64 pos = 0;
	struct llcrypt_str lltr = LLTR_INIT(NULL, 0);

	ENTRY;

	op_data = ll_prep_md_op_data(NULL, dir, dir, NULL, 0, 0,
				     LUSTRE_OPC_ANY, dir);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	if (IS_ENCRYPTED(dir)) {
		int rc2 = llcrypt_fname_alloc_buffer(dir, NAME_MAX, &lltr);

		if (rc2 < 0)
			RETURN(rc2);
	}

	/**
	 *FIXME choose the start offset of the readdir
	 */

	page = ll_get_dir_page(dir, op_data, 0, NULL);

	while (1) {
		struct lu_dirpage *dp;
		struct lu_dirent  *ent;

		if (IS_ERR(page)) {
			struct ll_inode_info *lli = ll_i2info(dir);

			rc = PTR_ERR(page);
			CERROR("%s: reading dir "DFID" at %llu stat_pid = %u : rc = %d\n",
			       ll_i2sbi(dir)->ll_fsname,
			       PFID(ll_inode2fid(dir)), pos,
			       lli->lli_stat_pid, rc);
			break;
		}

		dp = page_address(page);
		for (ent = lu_dirent_start(dp); ent != NULL;
		     ent = lu_dirent_next(ent)) {
			__u64 hash;
			int namelen;
			char *name;

			hash = le64_to_cpu(ent->lde_hash);
			/*
			 * The ll_get_dir_page() can return any page containing
			 * the given hash which may be not the start hash.
			 */
			if (unlikely(hash < pos))
				continue;

			namelen = le16_to_cpu(ent->lde_namelen);
			if (unlikely(namelen == 0))
				/*
				 * skip dummy record.
				 */
				continue;

			name = ent->lde_name;
			if (name[0] == '.') {
				if (namelen == 1)
					/*
					 * skip "."
					 */
					continue;
				else if (name[1] == '.' && namelen == 2)
					/*
					 * skip ".."
					 */
					continue;
				else
					dot_de = 1;
			} else {
				dot_de = 0;
			}

			if (dot_de && target->name[0] != '.') {
				CDEBUG(D_READA, "%.*s skip hidden file %.*s\n",
				       target->len, target->name,
				       namelen, name);
				continue;
			}

			if (IS_ENCRYPTED(dir)) {
				struct llcrypt_str de_name =
					LLTR_INIT(ent->lde_name, namelen);
				struct lu_fid fid;

				fid_le_to_cpu(&fid, &ent->lde_fid);
				if (ll_fname_disk_to_usr(dir, 0, 0, &de_name,
							 &lltr, &fid))
					continue;
				name = lltr.name;
				namelen = lltr.len;
			}

			if (target->len != namelen ||
			    memcmp(target->name, name, namelen) != 0)
				rc = LS_NOT_FIRST_DE;
			else if (!dot_de)
				rc = LS_FIRST_DE;
			else
				rc = LS_FIRST_DOT_DE;

			ll_release_page(dir, page, false);
			GOTO(out, rc);
		}
		pos = le64_to_cpu(dp->ldp_hash_end);
		if (pos == MDS_DIR_END_OFF) {
			/*
			 * End of directory reached.
			 */
			ll_release_page(dir, page, false);
			GOTO(out, rc);
		} else {
			/*
			 * chain is exhausted
			 * Normal case: continue to the next page.
			 */
			ll_release_page(dir, page, le32_to_cpu(dp->ldp_flags) &
					      LDF_COLLIDE);
			page = ll_get_dir_page(dir, op_data, pos, NULL);
		}
	}
	EXIT;
out:
	llcrypt_fname_free_buffer(&lltr);
	ll_finish_md_op_data(op_data);

	return rc;
}

static struct ll_statahead_info *
ll_find_sai_locked(struct ll_statahead_context *ctx, pid_t pid)
{
	struct ll_statahead_info *sai;

	list_for_each_entry(sai, &ctx->sax_sai_list, sai_item) {
		if (sai->sai_pid == pid)
			return sai;
	}
	return NULL;
}

static int start_statahead_thread(struct inode *dir, struct dentry *dentry,
				  bool agl);

static int ll_shared_statahead_check(struct inode *dir, struct dentry *dentry,
				     struct ll_statahead_context *ctx)
{
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_info *sai;

	ENTRY;

	spin_lock(&lli->lli_sa_lock);
	sai = lli->lli_sai;
	if (sai) {
		if (sai->sai_pid == current->pid) {
			spin_unlock(&lli->lli_sa_lock);
			RETURN(0);
		}
		lli->lli_sai = NULL;
		lli->lli_sa_pattern |= LSA_PATTERN_FN_SHARED;
	}

	sai = ll_find_sai_locked(ctx, current->pid);
	if (sai) {
		spin_unlock(&lli->lli_sa_lock);
		RETURN(-EEXIST);
	}

	lli->lli_sa_pattern |= LSA_PATTERN_FN_SHARED;
	spin_unlock(&lli->lli_sa_lock);

	RETURN(start_statahead_thread(dir, dentry, true));
}

/**
 * revalidate @dentryp from statahead cache
 *
 * \param[in] dir	parent directory
 * \param[in] sai	sai structure
 * \param[out] dentryp	pointer to dentry which will be revalidated
 * \param[in] unplug	unplug statahead window only (normally for negative
 *			dentry)
 * \retval		1 on success, dentry is saved in @dentryp
 * \retval		0 if revalidation failed (no proper lock on client)
 * \retval		negative number upon error
 */
static int revalidate_statahead_dentry(struct inode *dir,
				       struct ll_statahead_context *ctx,
				       struct dentry **dentryp,
				       bool unplug)
{
	struct sa_entry *entry = NULL;
	struct ll_dentry_data *lld;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_info *sai = lli->lli_sai;
	struct ll_statahead_info *info = NULL;
	int rc = 0;

	ENTRY;

	if (sai && (*dentryp)->d_name.name[0] == '.') {
		if (sai->sai_ls_all ||
		    sai->sai_miss_hidden >= sai->sai_skip_hidden) {
			/*
			 * Hidden dentry is the first one, or statahead
			 * thread does not skip so many hidden dentries
			 * before "sai_ls_all" enabled as below.
			 */
		} else {
			if (!sai->sai_ls_all)
				/*
				 * It maybe because hidden dentry is not
				 * the first one, "sai_ls_all" was not
				 * set, then "ls -al" missed. Enable
				 * "sai_ls_all" for such case.
				 */
				sai->sai_ls_all = 1;

			/*
			 * Such "getattr" has been skipped before
			 * "sai_ls_all" enabled as above.
			 */
			sai->sai_miss_hidden++;
			RETURN(-EAGAIN);
		}
	}

	if (unplug)
		GOTO(out, rc = 1);

	entry = sa_get(ctx, &(*dentryp)->d_name, &info);
	if (entry == ERR_PTR(-EINVAL)) {
		sai = info;
		spin_lock(&lli->lli_sa_lock);
		if (sai->sai_task) {
			struct task_struct *task = sai->sai_task;

			/*
			 * matches smp_load_acquire() in
			 * ll_statahead_thread().
			 * Notify to stop statahead thread immediately.
			 */
			smp_store_release(&sai->sai_task, NULL);
			wake_up_process(task);
		}
		atomic_dec(&sai->sai_inuse_count);
		spin_unlock(&lli->lli_sa_lock);
		RETURN(-EINVAL);
	} else if (entry == NULL) {
		if (lli->lli_sa_pattern & LSA_PATTERN_FNAME)
			rc = ll_shared_statahead_check(dir, *dentryp, ctx);
		GOTO(out, rc = rc == 0 ? -EAGAIN : rc);
	}

	if (lli->lli_sa_pattern & LSA_PATTERN_LIST)
		LASSERT(sai == entry->se_sai);
	else if (lli->lli_sa_pattern & LSA_PATTERN_FNAME ||
		 lli->lli_sa_pattern == LSA_PATTERN_ADVISE)
		sai = entry->se_sai;
	else
		sai = entry->se_sai;

	LASSERTF(sai != NULL, "pattern %#X entry %p se_sai %p %pd lli %p\n",
		 lli->lli_sa_pattern, entry, entry->se_sai, *dentryp, lli);
	if (!sa_ready(entry)) {
		spin_lock(&lli->lli_sa_lock);
		sai->sai_index_wait = entry->se_index;
		spin_unlock(&lli->lli_sa_lock);
		rc = wait_event_idle_timeout(sai->sai_waitq, sa_ready(entry),
					     cfs_time_seconds(30));
		if (rc == 0) {
			/*
			 * entry may not be ready, so it may be used by inflight
			 * statahead RPC, don't free it.
			 */
			entry = NULL;
			GOTO(out, rc = -EAGAIN);
		}
	}

	/*
	 * We need to see the value that was set immediately before we
	 * were woken up.
	 */
	if (smp_load_acquire(&entry->se_state) == SA_ENTRY_SUCC &&
	    entry->se_inode) {
		struct inode *inode = entry->se_inode;
		struct lookup_intent it = { .it_op = IT_GETATTR,
					    .it_lock_handle =
						entry->se_handle };
		__u64 bits;

		rc = md_revalidate_lock(ll_i2mdexp(dir), &it,
					ll_inode2fid(inode), &bits);
		if (rc == 1) {
			if (!(*dentryp)->d_inode) {
				struct dentry *alias;

				alias = ll_splice_alias(inode, *dentryp);
				if (IS_ERR(alias)) {
					ll_intent_release(&it);
					GOTO(out, rc = PTR_ERR(alias));
				}
				*dentryp = alias;
				/*
				 * statahead prepared this inode, transfer inode
				 * refcount from sa_entry to dentry
				 */
				entry->se_inode = NULL;
			} else if ((*dentryp)->d_inode != inode) {
				/* revalidate, but inode is recreated */
				CDEBUG(D_READA,
				       "%s: stale dentry %pd inode " DFID", statahead inode "DFID "\n",
				       ll_i2sbi(inode)->ll_fsname, *dentryp,
				       PFID(ll_inode2fid((*dentryp)->d_inode)),
				       PFID(ll_inode2fid(inode)));
				ll_intent_release(&it);
				GOTO(out, rc = -ESTALE);
			}

			if (bits & MDS_INODELOCK_LOOKUP) {
				d_lustre_revalidate(*dentryp);
				if (S_ISDIR(inode->i_mode))
					ll_update_dir_depth_dmv(dir, *dentryp);
			}

			ll_intent_release(&it);
		}
	}
out:
	/*
	 * statahead cached sa_entry can be used only once, and will be killed
	 * right after use, so if lookup/revalidate accessed statahead cache,
	 * set dentry ldd_sa_generation to parent lli_sa_generation, later if we
	 * stat this file again, we know we've done statahead before, see
	 * dentry_may_statahead().
	 */
	rcu_read_lock();
	lld = ll_d2d(*dentryp);
	if (lld)
		lld->lld_sa_generation = lli->lli_sa_generation;
	rcu_read_unlock();
	sa_put(dir, sai, entry);

	RETURN(rc);
}

static inline bool
sa_pattern_list_detect(struct inode *dir, struct dentry *dchild, int *first)
{
	struct ll_inode_info *lli = ll_i2info(dir);

	if (lli->lli_stat_pid == 0)
		return false;

	/* Directory listing needs to call opendir()/readdir()/stat(). */
	if (!(lli->lli_sa_pattern & LSA_PATTERN_OPENDIR))
		return false;

	if (lli->lli_sa_enabled == 0)
		return false;

	if (lli->lli_sa_pattern & LSA_PATTERN_LS_NOT_FIRST_DE)
		return false;

	*first = is_first_dirent(dir, dchild);
	if (*first == LS_NOT_FIRST_DE) {
		/*
		 * It is not "ls -{a}l" operation, no need statahead for it.
		 * Disable statahead so that subsequent stat() won't waste
		 * time to try it.
		 */
		spin_lock(&lli->lli_sa_lock);
		if (lli->lli_stat_pid == current->pid) {
			lli->lli_sa_enabled = 0;
			lli->lli_sa_pattern |= LSA_PATTERN_LS_NOT_FIRST_DE;
		}
		spin_unlock(&lli->lli_sa_lock);
		return false;
	}

	spin_lock(&lli->lli_sa_lock);
	lli->lli_sa_pattern |= LSA_PATTERN_LIST;
	spin_unlock(&lli->lli_sa_lock);
	return true;
}

static inline bool
sa_pattern_fname_detect(struct inode *dir, struct dentry *dchild)
{
	struct ll_inode_info *lli = ll_i2info(dir);
	struct qstr *dname = &dchild->d_name;
	const unsigned char *name = dname->name;
	bool rc = false;
	int i;

	if (ll_i2sbi(dir)->ll_enable_statahead_fname == 0)
		return false;
	if (lli->lli_sa_pattern & LSA_PATTERN_FN_SHARED)
		return true;

	/*
	 * Parse the format of the file name to determine whether it matches
	 * the supported file name pattern for statahead (i.e. mdtest.$rank.$i).
	 */
	i = dname->len - 1;
	if (isdigit(name[i])) {
		long num;
		int ret;

		if (lli->lli_stat_pid == 0) {
			lli->lli_stat_pid = current->pid;
		} else if (lli->lli_stat_pid != current->pid) {
			/*
			 * More than two processes (MPI ranks) doing stat()
			 * calls under this directory, consider it as a mdtest
			 * shared dir stat() workload.
			 */
			spin_lock(&lli->lli_sa_lock);
			lli->lli_stat_pid = current->pid;
			if (lli->lli_sa_pattern & LSA_PATTERN_FNAME) {
				lli->lli_sai = NULL;
				rc = false;
			} else {
				lli->lli_sa_pattern |= LSA_PATTERN_FNAME;
				rc = true;
			}
			lli->lli_sa_pattern |= LSA_PATTERN_FN_SHARED;
			spin_unlock(&lli->lli_sa_lock);
			return rc;
		}

		while (--i >= 0 && isdigit(name[i]))
			; /* do nothing */
		i++;
		ret = kstrtol(&name[i], 0, &num);
		if (ret)
			GOTO(out, rc);

		/*
		 * The traversing program do multiple stat() calls on the same
		 * children entry. i.e. ls $dir*.
		 */
		if (lli->lli_sa_fname_index == num)
			return false;

		if (lli->lli_sa_match_count == 0 ||
		    num == lli->lli_sa_fname_index + 1) {
			lli->lli_sa_match_count++;
			lli->lli_sa_fname_index = num;

			if (lli->lli_sa_match_count > LSA_FN_MATCH_HIT)
				GOTO(out, rc = true);

			return false;
		}
	}
out:
	spin_lock(&lli->lli_sa_lock);
	if (rc) {
		lli->lli_sa_pattern |= LSA_PATTERN_FNAME;
	} else {
		lli->lli_sa_pattern = LSA_PATTERN_NONE;
		lli->lli_sa_match_count = 0;
		lli->lli_sa_fname_index = 0;
		lli->lli_sa_enabled = 0;
	}
	spin_unlock(&lli->lli_sa_lock);

	return rc;
}

/* detect the statahead pattern. */
static inline bool
sa_pattern_detect(struct inode *dir, struct dentry *dchild, int *first)
{
	return sa_pattern_list_detect(dir, dchild, first) ||
	       sa_pattern_fname_detect(dir, dchild);
}

static inline int ll_sax_add_sai(struct ll_statahead_context *ctx,
				 struct ll_statahead_info *sai)
{
	if (ll_find_sai_locked(ctx, sai->sai_pid) != NULL)
		return -EEXIST;

	list_add_tail(&sai->sai_item, &ctx->sax_sai_list);
	return 0;
}

/**
 * start statahead thread
 *
 * \param[in] dir	parent directory
 * \param[in] dentry	dentry that triggers statahead, normally the first
 *			dirent under @dir
 * \param[in] agl	indicate whether AGL is needed
 * \retval		-EAGAIN on success, because when this function is
 *			called, it's already in lookup call, so client should
 *			do it itself instead of waiting for statahead thread
 *			to do it asynchronously.
 * \retval		negative number upon error
 */
static int start_statahead_thread(struct inode *dir, struct dentry *dentry,
				  bool agl)
{
	int node = cfs_cpt_spread_node(cfs_cpt_tab, CFS_CPT_ANY);
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_info *sai = NULL;
	struct ll_statahead_context *ctx = NULL;
	struct dentry *parent;
	struct task_struct *task;
	struct ll_sb_info *sbi;
	int first = LS_FIRST_DE;
	int rc = 0;

	ENTRY;

	if (sa_pattern_detect(dir, dentry, &first) == false)
		RETURN(0);

	parent = dget_parent(dentry);
	sbi = ll_i2sbi(d_inode(parent));
	if (unlikely(atomic_inc_return(&sbi->ll_sa_running) >
				       sbi->ll_sa_running_max)) {
		CDEBUG(D_READA,
		       "Too many concurrent statahead instances, avoid new statahead instance temporarily.\n");
		dput(parent);
		GOTO(out, rc = -EMFILE);
	}

	/* on success ll_sai_alloc holds a ref on parent */
	sai = ll_sai_alloc(parent);
	dput(parent);
	if (!sai)
		GOTO(out, rc = -ENOMEM);

	sai->sai_ls_all = (first == LS_FIRST_DOT_DE);
	sai->sai_pid = current->pid;

	if (lli->lli_sa_pattern & LSA_PATTERN_FNAME) {
		struct qstr *dname = &dentry->d_name;
		const unsigned char *name = dname->name;
		long num;
		int i;

		if (dname->len >= sizeof(sai->sai_fname))
			GOTO(out, rc = -ERANGE);

		i = dname->len;
		while (--i >= 0 && isdigit(name[i]))
			; /* do nothing */
		i++;
		rc = kstrtol(&name[i], 0, &num);
		if (rc)
			GOTO(out, rc);

		memcpy(sai->sai_fname, dname->name, i);
		sai->sai_fname[i] = '\0';
		sai->sai_fname_index = num;
		/* The front part of the file name is zeroed padding. */
		if (name[i] == '0')
			sai->sai_fname_zeroed_len = dname->len - i;
	}

	/* The workload like directory listing or mdtest unique dir stat() */
	if (lli->lli_sa_pattern & LSA_PATTERN_LIST ||
	    (lli->lli_sa_pattern & (LSA_PATTERN_FN_SHARED |
				    LSA_PATTERN_FNAME)) == LSA_PATTERN_FNAME) {
		ctx = ll_sax_alloc(dir);
		if (!ctx)
			GOTO(out, rc = -ENOMEM);

		/*
		 * if current lli_opendir_key was deauthorized, or dir
		 * re-opened by another process, don't start statahead,
		 * otherwise the newly spawned statahead thread won't be
		 * notified to quit.
		 */
		spin_lock(&lli->lli_sa_lock);
		if (unlikely(lli->lli_sai || lli->lli_sax ||
			     ((lli->lli_sa_pattern & LSA_PATTERN_LIST) &&
			      !lli->lli_opendir_key &&
			      lli->lli_stat_pid != current->pid))) {
			spin_unlock(&lli->lli_sa_lock);
			GOTO(out, rc = -EPERM);
		}
		rc = ll_sax_add_sai(ctx, sai);
		if (rc) {
			spin_unlock(&lli->lli_sa_lock);
			GOTO(out, rc);
		}
		lli->lli_sai = sai;
		lli->lli_sax = ctx;
		spin_unlock(&lli->lli_sa_lock);
	} else if (lli->lli_sa_pattern & LSA_PATTERN_FN_SHARED) {
		/* For mdtest shared dir stat() workload */
		LASSERT(lli->lli_sa_pattern & LSA_PATTERN_FNAME);
		ctx = ll_sax_get(dir);
		if (ctx == NULL) {
			ctx = ll_sax_alloc(dir);
			if (ctx == NULL)
				GOTO(out, rc = -ENOMEM);

			spin_lock(&lli->lli_sa_lock);
			if (lli->lli_sax) {
				struct ll_statahead_context *tmp = ctx;

				if (lli->lli_sa_pattern &
				    LSA_PATTERN_FN_SHARED) {
					ctx = lli->lli_sax;
					__ll_sax_get(ctx);
					rc = ll_sax_add_sai(ctx, sai);
				} else {
					CWARN("%s: invalid pattern %#X.\n",
					      sbi->ll_fsname,
					      lli->lli_sa_pattern);
					rc = -EINVAL;
				}

				spin_unlock(&lli->lli_sa_lock);
				ll_sax_free(tmp);
				if (rc)
					GOTO(out, rc);
			} else {
				lli->lli_sax = ctx;
				rc = ll_sax_add_sai(ctx, sai);
				spin_unlock(&lli->lli_sa_lock);
			}
		} else {
			spin_lock(&lli->lli_sa_lock);
			if (!(lli->lli_sa_pattern & LSA_PATTERN_FN_SHARED)) {
				spin_unlock(&lli->lli_sa_lock);
				GOTO(out, rc = -EINVAL);
			}

			rc = ll_sax_add_sai(ctx, sai);
			spin_unlock(&lli->lli_sa_lock);
		}

		if (rc)
			GOTO(out, rc);
	} else {
		CERROR("%s: unsupported statahead pattern %#X.\n",
		       sbi->ll_fsname, lli->lli_sa_pattern);
		GOTO(out, rc = -EOPNOTSUPP);
	}

	CDEBUG(D_READA, "start statahead thread: [pid %d] [parent %pd]\n",
	       current->pid, parent);

	task = kthread_create_on_node(ll_statahead_thread, sai, node,
				      "ll_sa_%u", lli->lli_stat_pid);
	if (IS_ERR(task)) {
		spin_lock(&lli->lli_sa_lock);
		lli->lli_sai = NULL;
		spin_unlock(&lli->lli_sa_lock);
		rc = PTR_ERR(task);
		CERROR("can't start ll_sa thread, rc: %d\n", rc);
		GOTO(out, rc);
	}

	if (test_bit(LL_SBI_AGL_ENABLED, sbi->ll_flags) && agl)
		ll_start_agl(parent, sai);

	atomic_inc(&sbi->ll_sa_total);
	if (lli->lli_sa_pattern & LSA_PATTERN_LIST)
		atomic_inc(&sbi->ll_sa_list_total);
	else if (lli->lli_sa_pattern & LSA_PATTERN_FNAME)
		atomic_inc(&sbi->ll_sa_fname_total);

	sai->sai_task = task;
	wake_up_process(task);
	/*
	 * We don't stat-ahead for the first dirent since we are already in
	 * lookup.
	 */
	RETURN(-EAGAIN);

out:
	/*
	 * once we start statahead thread failed, disable statahead so that
	 * subsequent stat won't waste time to try it.
	 */
	spin_lock(&lli->lli_sa_lock);
	if (lli->lli_stat_pid == current->pid)
		lli->lli_sa_enabled = 0;
	spin_unlock(&lli->lli_sa_lock);

	if (sai)
		ll_sai_put(sai);

	if (ctx)
		ll_sax_put(dir, ctx);

	if (rc)
		atomic_dec(&sbi->ll_sa_running);

	RETURN(rc);
}

/*
 * Check whether statahead for @dir was started.
 */
static inline bool ll_statahead_started(struct inode *dir, bool agl)
{
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_context *ctx;
	struct ll_statahead_info *sai;

	spin_lock(&lli->lli_sa_lock);
	ctx = lli->lli_sax;
	sai = lli->lli_sai;
	if (sai && (sai->sai_agl_task != NULL) != agl)
		CDEBUG(D_READA,
		       "%s: Statahead AGL hint changed from %d to %d\n",
		       ll_i2sbi(dir)->ll_fsname,
		       sai->sai_agl_task != NULL, agl);
	spin_unlock(&lli->lli_sa_lock);

	return !!ctx;
}

/**
 * statahead entry function, this is called when client getattr on a file, it
 * will start statahead thread if this is the first dir entry, else revalidate
 * dentry from statahead cache.
 *
 * \param[in]  dir	parent directory
 * \param[out] dentryp	dentry to getattr
 * \param[in]  agl	whether start the agl thread
 *
 * \retval		1 on success
 * \retval		0 revalidation from statahead cache failed, caller needs
 *			to getattr from server directly
 * \retval		negative number on error, caller often ignores this and
 *			then getattr from server
 */
int ll_start_statahead(struct inode *dir, struct dentry *dentry, bool agl)
{
	if (!ll_statahead_started(dir, agl))
		return start_statahead_thread(dir, dentry, agl);
	return 0;
}

/**
 * revalidate dentry from statahead cache.
 *
 * \param[in]  dir	parent directory
 * \param[out] dentryp	dentry to getattr
 * \param[in]  unplug	unplug statahead window only (normally for negative
 *			dentry)
 * \retval		1 on success
 * \retval		0 revalidation from statahead cache failed, caller needs
 *			to getattr from server directly
 * \retval		negative number on error, caller often ignores this and
 *			then getattr from server
 */
int ll_revalidate_statahead(struct inode *dir, struct dentry **dentryp,
			    bool unplug)
{
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_statahead_context *ctx;
	struct ll_statahead_info *sai = NULL;
	int rc = 0;

	spin_lock(&lli->lli_sa_lock);
	ctx = lli->lli_sax;
	if (ctx) {
		sai = lli->lli_sai;
		if (sai) {
			atomic_inc(&sai->sai_refcount);
		} else if (lli->lli_sa_pattern & LSA_PATTERN_LIST) {
			spin_unlock(&lli->lli_sa_lock);
			return 0;
		}
		__ll_sax_get(ctx);
	}
	spin_unlock(&lli->lli_sa_lock);
	if (ctx) {
		rc = revalidate_statahead_dentry(dir, ctx, dentryp, unplug);
		CDEBUG(D_READA, "revalidate statahead %pd: rc = %d.\n",
		       *dentryp, rc);
		if (sai)
			ll_sai_put(sai);
		ll_sax_put(dir, ctx);
	}
	return rc;
}

int ll_ioctl_ahead(struct file *file, struct llapi_lu_ladvise2 *ladvise)
{
	int node = cfs_cpt_spread_node(cfs_cpt_tab, CFS_CPT_ANY);
	struct ll_file_data *lfd = file->private_data;
	struct dentry *dentry = file_dentry(file);
	struct inode *dir = dentry->d_inode;
	struct ll_inode_info *lli = ll_i2info(dir);
	struct ll_sb_info *sbi = ll_i2sbi(dir);
	struct ll_statahead_info *sai = NULL;
	struct ll_statahead_context *ctx = NULL;
	struct task_struct *task;
	bool agl = true;
	int rc;

	ENTRY;

	if (sbi->ll_sa_max == 0)
		RETURN(0);

	if (!S_ISDIR(dir->i_mode))
		RETURN(-EINVAL);

	if (lfd->fd_sai) {
		rc = -EALREADY;
		CWARN("%s: already set statahead hint for dir %pd: rc = %d\n",
		      sbi->ll_fsname, dentry, rc);
		RETURN(rc);
	}

	if (unlikely(atomic_inc_return(&sbi->ll_sa_running) >
				       sbi->ll_sa_running_max)) {
		CDEBUG(D_READA,
		       "Too many concurrent statahead instances, avoid new statahead instance temporarily.\n");
		GOTO(out, rc = -EMFILE);
	}

	sai = ll_sai_alloc(dentry);
	if (sai == NULL)
		GOTO(out, rc = -ENOMEM);

	sai->sai_fstart = ladvise->lla_start;
	sai->sai_fend = ladvise->lla_end;
	sai->sai_ls_all = 0;
	sai->sai_max = sbi->ll_sa_max;
	strncpy(sai->sai_fname, ladvise->lla_fname, sizeof(sai->sai_fname));
	sai->sai_pid = current->pid;

	ctx = ll_sax_get(dir);
	if (ctx == NULL) {
		ctx = ll_sax_alloc(dir);
		if (ctx == NULL)
			GOTO(out, rc = -ENOMEM);

		spin_lock(&lli->lli_sa_lock);
		if (unlikely(lli->lli_sax)) {
			struct ll_statahead_context *tmp = ctx;

			if (lli->lli_sa_pattern == LSA_PATTERN_NONE ||
			    lli->lli_sa_pattern == LSA_PATTERN_ADVISE) {
				lli->lli_sa_pattern = LSA_PATTERN_ADVISE;
				ctx = lli->lli_sax;
				__ll_sax_get(ctx);
				lfd->fd_sai = __ll_sai_get(sai);
				rc = 0;
			} else {
				rc = -EINVAL;
				CWARN("%s: pattern %X is not ADVISE: rc = %d\n",
				      sbi->ll_fsname, lli->lli_sa_pattern, rc);
			}

			spin_unlock(&lli->lli_sa_lock);
			ll_sax_free(tmp);
			if (rc)
				GOTO(out, rc);
		} else {
			lli->lli_sa_pattern = LSA_PATTERN_ADVISE;
			lli->lli_sax = ctx;
			lfd->fd_sai = __ll_sai_get(sai);
			spin_unlock(&lli->lli_sa_lock);
		}
	} else {
		spin_lock(&lli->lli_sa_lock);
		if (!(lli->lli_sa_pattern == LSA_PATTERN_ADVISE ||
		      lli->lli_sa_pattern == LSA_PATTERN_NONE)) {
			spin_unlock(&lli->lli_sa_lock);
			GOTO(out, rc = -EINVAL);
		}

		lli->lli_sa_pattern = LSA_PATTERN_ADVISE;
		lfd->fd_sai = __ll_sai_get(sai);
		spin_unlock(&lli->lli_sa_lock);
	}

	__ll_sax_get(ctx);
	CDEBUG(D_READA,
	       "start statahead thread: [pid %d] [parent %pd] sai %p ctx %p\n",
	       current->pid, dentry, sai, ctx);

	task = kthread_create_on_node(ll_statahead_thread, sai, node,
				      "ll_sa_%u", current->pid);
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start ll_sa thread: rc = %d\n",
		       sbi->ll_fsname, rc);
		GOTO(out, rc);
	}

	if (test_bit(LL_SBI_AGL_ENABLED, sbi->ll_flags) && agl)
		ll_start_agl(dentry, sai);

	atomic_inc(&sbi->ll_sa_total);
	sai->sai_task = task;
	wake_up_process(task);

	RETURN(0);
out:
	if (lfd->fd_sai) {
		ll_sai_put(sai);
		ll_sax_put(dir, ctx);
		lfd->fd_sai = NULL;
	}

	if (sai)
		ll_sai_put(sai);

	if (ctx)
		ll_sax_put(dir, ctx);

	atomic_dec(&sbi->ll_sa_running);
	RETURN(rc);
}

/*
 * This function is called in each stat() system call to do statahead check.
 * When the files' naming of stat() call sequence under a directory follows
 * a certain name rule roughly, this directory is considered as an condicant
 * to do statahead.
 * For an example, the file naming rule is mdtest.$rank.$i, the suffix of
 * the stat() dentry name is number and do stat() for dentries with name
 * ending with number more than @LSA_FN_PREDICT_HIT, then the corresponding
 * directory is met the requrirement for statahead.
 */
void ll_statahead_enter(struct inode *dir, struct dentry *dchild)
{
	struct ll_inode_info *lli;
	struct qstr *dname = &dchild->d_name;

	if (ll_i2sbi(dir)->ll_sa_max == 0)
		return;

	if (ll_i2sbi(dir)->ll_enable_statahead_fname == 0)
		return;

	lli = ll_i2info(dir);
	if (lli->lli_sa_enabled)
		return;

	if (lli->lli_sa_pattern & (LSA_PATTERN_FN_PREDICT | LSA_PATTERN_LIST))
		return;

	/*
	 * Now support number indexing regularized statahead pattern only.
	 * Quick check whether the last character is digit.
	 */
	if (!isdigit(dname->name[dname->len - 1])) {
		lli->lli_sa_pattern &= ~LSA_PATTERN_FN_PREDICT;
		lli->lli_sa_match_count = 0;
		return;
	}

	lli->lli_sa_match_count++;
	if (lli->lli_sa_match_count > LSA_FN_PREDICT_HIT) {
		spin_lock(&lli->lli_sa_lock);
		lli->lli_sa_pattern |= LSA_PATTERN_FN_PREDICT;
		spin_unlock(&lli->lli_sa_lock);
		lli->lli_sa_enabled = 1;
		lli->lli_sa_match_count = 0;
	}
}
