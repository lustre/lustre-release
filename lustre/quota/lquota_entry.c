/* GPL HEADER START
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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2015, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <linux/module.h>
#include <linux/slab.h>
#include <obd_class.h>
#include "lquota_internal.h"

static int hash_lqs_cur_bits = HASH_LQE_CUR_BITS;
module_param(hash_lqs_cur_bits, int, 0444);
MODULE_PARM_DESC(hash_lqs_cur_bits, "the current bits of lqe hash");

static unsigned
lqe64_hash_hash(struct cfs_hash *hs, const void *key, unsigned mask)
{
	return cfs_hash_u64_hash(*((__u64 *)key), mask);
}

static void *lqe64_hash_key(struct hlist_node *hnode)
{
	struct lquota_entry *lqe;
	lqe = hlist_entry(hnode, struct lquota_entry, lqe_hash);
	return &lqe->lqe_id.qid_uid;
}

static int lqe64_hash_keycmp(const void *key, struct hlist_node *hnode)
{
	struct lquota_entry *lqe;
	lqe = hlist_entry(hnode, struct lquota_entry, lqe_hash);
	return (lqe->lqe_id.qid_uid == *((__u64*)key));
}

static void *lqe_hash_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct lquota_entry, lqe_hash);
}

static void lqe_hash_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct lquota_entry *lqe;
	lqe = hlist_entry(hnode, struct lquota_entry, lqe_hash);
	lqe_getref(lqe);
}

static void lqe_hash_put_locked(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct lquota_entry *lqe;
	lqe = hlist_entry(hnode, struct lquota_entry, lqe_hash);
	lqe_putref(lqe);
}

static void lqe_hash_exit(struct cfs_hash *hs, struct hlist_node *hnode)
{
	CERROR("Should not have any item left!\n");
}

/* lqe hash methods for 64-bit uid/gid, new hash functions would have to be
 * defined for per-directory quota relying on a 128-bit FID */
static struct cfs_hash_ops lqe64_hash_ops = {
	.hs_hash       = lqe64_hash_hash,
	.hs_key        = lqe64_hash_key,
	.hs_keycmp     = lqe64_hash_keycmp,
	.hs_object     = lqe_hash_object,
	.hs_get        = lqe_hash_get,
	.hs_put_locked = lqe_hash_put_locked,
	.hs_exit       = lqe_hash_exit
};

/* Logging helper function */
void lquota_lqe_debug0(struct lquota_entry *lqe,
		       struct libcfs_debug_msg_data *msgdata,
		       const char *fmt, ...)
{
	struct lquota_site *site = lqe->lqe_site;
	struct va_format vaf;
	va_list args;

	LASSERT(site->lqs_ops->lqe_debug != NULL);

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	site->lqs_ops->lqe_debug(lqe, site->lqs_parent, msgdata, &vaf);
	va_end(args);
}

struct lqe_iter_data {
	unsigned long	lid_inuse;
	unsigned long	lid_freed;
	bool		lid_free_all;
};

static int lqe_iter_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
		       struct hlist_node *hnode, void *data)
{
	struct lqe_iter_data *d = (struct lqe_iter_data *)data;
	struct lquota_entry  *lqe;

	lqe = hlist_entry(hnode, struct lquota_entry, lqe_hash);
	LASSERT(atomic_read(&lqe->lqe_ref) > 0);

	/* Only one reference held by hash table, and nobody else can
	 * grab the entry at this moment, it's safe to remove it from
	 * the hash and free it. */
	if (atomic_read(&lqe->lqe_ref) == 1) {
		if (!lqe_is_master(lqe)) {
			LASSERT(lqe->lqe_pending_write == 0);
			LASSERT(lqe->lqe_pending_req == 0);
		}
		if (d->lid_free_all || lqe->lqe_enforced) {
			d->lid_freed++;
			cfs_hash_bd_del_locked(hs, bd, hnode);
			return 0;
		}
	}
	d->lid_inuse++;

	if (d->lid_free_all)
		LQUOTA_ERROR(lqe, "Inuse quota entry");
	return 0;
}

/**
 * Cleanup the entries in the hashtable
 *
 * \param hash     - hash table which stores quota entries
 * \param free_all - free all entries or only free the entries
 *                   without quota enforce ?
 */
static void lqe_cleanup(struct cfs_hash *hash, bool free_all)
{
	struct lqe_iter_data	d;
	int			repeat = 0;
	ENTRY;
retry:
	memset(&d, 0, sizeof(d));
	d.lid_free_all = free_all;

	cfs_hash_for_each_safe(hash, lqe_iter_cb, &d);

	/* In most case, when this function is called on master or
	 * slave finalization, there should be no inuse quota entry.
	 *
	 * If the per-fs quota updating thread is still holding
	 * some entries, we just wait for it's finished. */
	if (free_all && d.lid_inuse) {
		CDEBUG(D_QUOTA, "Hash:%p has entries inuse: inuse:%lu, "
			"freed:%lu, repeat:%u\n", hash,
			d.lid_inuse, d.lid_freed, repeat);
		repeat++;
		schedule_timeout_interruptible(cfs_time_seconds(1));
		goto retry;
	}
	EXIT;
}

/*
 * Allocate a new lquota site.
 *
 * \param env    - the environment passed by the caller
 * \param parent - is a pointer to the parent structure, either a qmt_pool_info
 *                 structure on the master or a qsd_qtype_info structure on the
 *                 slave.
 * \param is_master - is set when the site belongs to a QMT.
 * \param qtype     - is the quota type managed by this site
 * \param ops       - is the quota entry operation vector to be used for quota
 *                    entry belonging to this site.
 *
 * \retval 0     - success
 * \retval -ve   - failure
 */
struct lquota_site *lquota_site_alloc(const struct lu_env *env, void *parent,
				      bool is_master, short qtype,
				      const struct lquota_entry_operations *ops)
{
	struct lquota_site	*site;
	char			 hashname[15];
	ENTRY;

	if (qtype >= LL_MAXQUOTAS)
		RETURN(ERR_PTR(-ENOTSUPP));

	OBD_ALLOC_PTR(site);
	if (site == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	/* assign parameters */
	site->lqs_qtype  = qtype;
	site->lqs_parent = parent;
	site->lqs_is_mst = is_master;
	site->lqs_ops    = ops;

	/* allocate hash table */
	memset(hashname, 0, sizeof(hashname));
	snprintf(hashname, sizeof(hashname), "LQUOTA_HASH%hu", qtype);
	site->lqs_hash= cfs_hash_create(hashname, hash_lqs_cur_bits,
					HASH_LQE_MAX_BITS,
					min(hash_lqs_cur_bits,
					    HASH_LQE_BKT_BITS),
					0, CFS_HASH_MIN_THETA,
					CFS_HASH_MAX_THETA, &lqe64_hash_ops,
					CFS_HASH_RW_SEM_BKTLOCK |
					CFS_HASH_COUNTER |
					CFS_HASH_REHASH |
					CFS_HASH_BIGNAME);

	if (site->lqs_hash == NULL) {
		OBD_FREE_PTR(site);
		RETURN(ERR_PTR(-ENOMEM));
	}

	RETURN(site);
}

/*
 * Destroy a lquota site.
 *
 * \param env  - the environment passed by the caller
 * \param site - lquota site to be destroyed
 *
 * \retval 0     - success
 * \retval -ve   - failure
 */
void lquota_site_free(const struct lu_env *env, struct lquota_site *site)
{
	/* cleanup hash table */
	lqe_cleanup(site->lqs_hash, true);
	cfs_hash_putref(site->lqs_hash);

	site->lqs_parent = NULL;
	OBD_FREE_PTR(site);
}

/*
 * Initialize qsd/qmt-specific fields of quota entry.
 *
 * \param lqe - is the quota entry to initialize
 */
static void lqe_init(struct lquota_entry *lqe)
{
	struct lquota_site *site;
	ENTRY;

	LASSERT(lqe != NULL);
	site = lqe->lqe_site;
	LASSERT(site != NULL);
	LASSERT(site->lqs_ops->lqe_init != NULL);

	LQUOTA_DEBUG(lqe, "init");

	site->lqs_ops->lqe_init(lqe, site->lqs_parent);
}

/*
 * Update a lquota entry. This is done by reading quota settings from the
 * on-disk index. The lquota entry must be write locked.
 *
 * \param env - the environment passed by the caller
 * \param lqe - is the quota entry to refresh
 * \param find - don't create entry on disk if true
 */
static int lqe_read(const struct lu_env *env,
		    struct lquota_entry *lqe, bool find)
{
	struct lquota_site	*site;
	int			 rc;
	ENTRY;

	LASSERT(lqe != NULL);
	site = lqe->lqe_site;
	LASSERT(site != NULL);
	LASSERT(site->lqs_ops->lqe_read != NULL);

	LQUOTA_DEBUG(lqe, "read");

	rc = site->lqs_ops->lqe_read(env, lqe, site->lqs_parent, find);
	if (rc == 0)
		/* mark the entry as up-to-date */
		lqe->lqe_uptodate = true;

	RETURN(rc);
}

/*
 * Find or create a quota entry.
 *
 * \param env  - the environment passed by the caller
 * \param site - lquota site which stores quota entries in a hash table
 * \param qid  - is the quota ID to be found/created
 * \param find - don't create lqe on disk in case of ENOENT if true
 *
 * \retval 0     - success
 * \retval -ve   - failure
 */
struct lquota_entry *lqe_locate_find(const struct lu_env *env,
				     struct lquota_site *site,
				     union lquota_id *qid,
				     bool find)
{
	struct lquota_entry	*lqe, *new = NULL;
	int			 rc = 0;
	ENTRY;

	lqe = cfs_hash_lookup(site->lqs_hash, (void *)&qid->qid_uid);
	if (lqe != NULL) {
		LASSERT(lqe->lqe_uptodate);
		RETURN(lqe);
	}

	OBD_SLAB_ALLOC_PTR_GFP(new, lqe_kmem, GFP_NOFS);
	if (new == NULL) {
		CERROR("Fail to allocate lqe for id:%llu, "
			"hash:%s\n", qid->qid_uid, site->lqs_hash->hs_name);
		RETURN(ERR_PTR(-ENOMEM));
	}

	atomic_set(&new->lqe_ref, 1); /* hold 1 for caller */
	new->lqe_id     = *qid;
	new->lqe_site   = site;
	INIT_LIST_HEAD(&new->lqe_link);

	/* quota settings need to be updated from disk, that's why
	 * lqe->lqe_uptodate isn't set yet */
	new->lqe_uptodate = false;

	/* perform qmt/qsd specific initialization */
	lqe_init(new);

	/* read quota settings from disk and mark lqe as up-to-date */
	rc = lqe_read(env, new, find);
	if (rc)
		GOTO(out, lqe = ERR_PTR(rc));

	/* add new entry to hash */
	lqe = cfs_hash_findadd_unique(site->lqs_hash, &new->lqe_id.qid_uid,
				      &new->lqe_hash);
	if (lqe == new)
		new = NULL;
out:
	if (new)
		lqe_putref(new);
	RETURN(lqe);
}
