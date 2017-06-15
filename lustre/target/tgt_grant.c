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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * lustre/target/tgt_grant.c
 *
 * This file provides code related to grant space management on Lustre Targets
 * (OSTs and MDTs). Grant is a mechanism used by client nodes to reserve disk
 * space on a target for the data writeback cache. The Lustre client is thus
 * assured that enough space will be available when flushing dirty pages
 * asynchronously. Each client node is granted an initial amount of reserved
 * space at connect time and gets additional space back from target in bulk
 * write reply.
 *
 * We actually support three different cases:
 * - The client supports the new grant parameters (i.e. OBD_CONNECT_GRANT_PARAM)
 *   which means that all grant overhead calculation happens on the client side.
 *   The server reports at connect time the backend filesystem block size, the
 *   maximum extent size as well as the extent insertion cost and it is then up
 *   to the osc layer to the track dirty extents and consume grant accordingly
 *   (see osc_cache.c). In each bulk write request, the client provides how much
 *   grant space was consumed for this RPC.
 * - The client does not support OBD_CONNECT_GRANT_PARAM and always assumes a
 *   a backend file system block size of 4KB. We then have two cases:
 *   - If the block size is really 4KB, then the client can deal with grant
 *     allocation for partial block writes, but won't take extent insertion cost
 *     into account. For such clients, we inflate grant by 100% on the server
 *     side. It means that when 32MB of grant is hold by the client, 64MB of
 *     grant space is actually reserved on the server. All grant counters
 *     provided by such a client are inflated by 100%.
 *   - The backend filesystem block size is bigger than 4KB, which isn't
 *     supported by the client. In this case, we emulate a 4KB block size and
 *     consume one block size on the server for each 4KB of grant returned to
 *     client. With a 128KB blocksize, it means that 32MB dirty pages of 4KB
 *     on the client will actually consume 1GB of grant on the server.
 *     All grant counters provided by such a client are inflated by the block
 *     size ratio.
 *
 * This file handles the core logic for:
 * - grant allocation strategy
 * - maintaining per-client as well as global grant space accounting
 * - processing grant information packed in incoming requests
 * - allocating server-side grant space for synchronous write RPCs which did not
 *   consume grant on the client side (OBD_BRW_FROM_GRANT flag not set). If not
 *   enough space is available, such RPCs fail with ENOSPC
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <obd.h>
#include <obd_class.h>

#include "tgt_internal.h"

/* Clients typically hold 2x their max_rpcs_in_flight of grant space */
#define TGT_GRANT_SHRINK_LIMIT(exp)	(2ULL * 8 * exp_max_brw_size(exp))

/* Helpers to inflate/deflate grants for clients that do not support the grant
 * parameters */
static inline u64 tgt_grant_inflate(struct tg_grants_data *tgd, u64 val)
{
	if (tgd->tgd_blockbits > COMPAT_BSIZE_SHIFT)
		/* Client does not support such large block size, grant
		 * is thus inflated. We already significantly overestimate
		 * overhead, no need to add the extent tax in this case */
		return val << (tgd->tgd_blockbits - COMPAT_BSIZE_SHIFT);
	return val;
}

/* Companion of tgt_grant_inflate() */
static inline u64 tgt_grant_deflate(struct tg_grants_data *tgd, u64 val)
{
	if (tgd->tgd_blockbits > COMPAT_BSIZE_SHIFT)
		return val >> (tgd->tgd_blockbits - COMPAT_BSIZE_SHIFT);
	return val;
}

/* Grant chunk is used as a unit for grant allocation. It should be inflated
 * if the client does not support the grant paramaters.
 * Check connection flag against \a data if not NULL. This is used during
 * connection creation where exp->exp_connect_data isn't populated yet */
static inline u64 tgt_grant_chunk(struct obd_export *exp,
				  struct lu_target *lut,
				  struct obd_connect_data *data)
{
	struct tg_grants_data *tgd = &lut->lut_tgd;
	u64 chunk = exp_max_brw_size(exp);
	u64 tax;

	if (exp->exp_obd->obd_self_export == exp)
		/* Grant enough space to handle a big precreate request */
		return OST_MAX_PRECREATE * lut->lut_dt_conf.ddp_inodespace / 2;

	if ((data == NULL && !(exp_grant_param_supp(exp))) ||
	    (data != NULL && !OCD_HAS_FLAG(data, GRANT_PARAM)))
		/* Try to grant enough space to send 2 full-size RPCs */
		return tgt_grant_inflate(tgd, chunk) << 1;

	/* Try to return enough to send two full-size RPCs
	 * = 2 * (BRW_size + #extents_in_BRW * grant_tax) */
	tax = 1ULL << tgd->tgd_blockbits;	     /* block size */
	tax *= lut->lut_dt_conf.ddp_max_extent_blks; /* max extent size */
	tax = (chunk + tax - 1) / tax;		     /* #extents in a RPC */
	tax *= lut->lut_dt_conf.ddp_extent_tax;	     /* extent tax for a RPC */
	chunk = (chunk + tax) * 2;		     /* we said two full RPCs */
	return chunk;
}

static int tgt_check_export_grants(struct obd_export *exp, u64 *dirty,
				   u64 *pending, u64 *granted, u64 maxsize)
{
	struct tg_export_data *ted = &exp->exp_target_data;
	int level = D_CACHE;

	if (ted->ted_grant < 0 || ted->ted_pending < 0 || ted->ted_dirty < 0)
		level = D_ERROR;
	CDEBUG_LIMIT(level, "%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
		     exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
		     ted->ted_dirty, ted->ted_pending, ted->ted_grant);

	if (ted->ted_grant + ted->ted_pending > maxsize) {
		CERROR("%s: cli %s/%p ted_grant(%ld) + ted_pending(%ld)"
			" > maxsize(%llu)\n", exp->exp_obd->obd_name,
			exp->exp_client_uuid.uuid, exp, ted->ted_grant,
			ted->ted_pending, maxsize);
		return -EFAULT;
	}
	if (ted->ted_dirty > maxsize) {
		CERROR("%s: cli %s/%p ted_dirty(%ld) > maxsize(%llu)\n",
			exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
			exp, ted->ted_dirty, maxsize);
		return -EFAULT;
	}
	*granted += ted->ted_grant + ted->ted_pending;
	*pending += ted->ted_pending;
	*dirty += ted->ted_dirty;
	return 0;
}

/**
 * Perform extra sanity checks for grant accounting.
 *
 * This function scans the export list, sanity checks per-export grant counters
 * and verifies accuracy of global grant accounting. If an inconsistency is
 * found, a CERROR is printed with the function name \func that was passed as
 * argument. LBUG is only called in case of serious counter corruption (i.e.
 * value larger than the device size).
 * Those sanity checks can be pretty expensive and are disabled if the OBD
 * device has more than 100 connected exports.
 *
 * \param[in] obd	OBD device for which grant accounting should be
 *			verified
 * \param[in] func	caller's function name
 */
void tgt_grant_sanity_check(struct obd_device *obd, const char *func)
{
	struct lu_target *lut = obd->u.obt.obt_lut;
	struct tg_grants_data *tgd = &lut->lut_tgd;
	struct obd_export *exp;
	struct tg_export_data *ted;
	u64		   maxsize;
	u64		   tot_dirty = 0;
	u64		   tot_pending = 0;
	u64		   tot_granted = 0;
	u64		   fo_tot_granted;
	u64		   fo_tot_pending;
	u64		   fo_tot_dirty;
	int		   error;

	if (list_empty(&obd->obd_exports))
		return;

	/* We don't want to do this for large machines that do lots of
	 * mounts or unmounts.  It burns... */
	if (obd->obd_num_exports > 100)
		return;

	maxsize = tgd->tgd_osfs.os_blocks << tgd->tgd_blockbits;

	spin_lock(&obd->obd_dev_lock);
	spin_lock(&tgd->tgd_grant_lock);
	exp = obd->obd_self_export;
	ted = &exp->exp_target_data;
	CDEBUG(D_CACHE, "%s: processing self export: %ld %ld "
	       "%ld\n", obd->obd_name, ted->ted_grant,
	       ted->ted_pending, ted->ted_dirty);
	tot_granted += ted->ted_grant + ted->ted_pending;
	tot_pending += ted->ted_pending;
	tot_dirty += ted->ted_dirty;

	list_for_each_entry(exp, &obd->obd_exports, exp_obd_chain) {
		error = tgt_check_export_grants(exp, &tot_dirty, &tot_pending,
						&tot_granted, maxsize);
		if (error < 0) {
			spin_unlock(&obd->obd_dev_lock);
			spin_unlock(&tgd->tgd_grant_lock);
			LBUG();
		}
	}

	/* exports about to be unlinked should also be taken into account since
	 * they might still hold pending grant space to be released at
	 * commit time */
	list_for_each_entry(exp, &obd->obd_unlinked_exports, exp_obd_chain) {
		error = tgt_check_export_grants(exp, &tot_dirty, &tot_pending,
						&tot_granted, maxsize);
		if (error < 0) {
			spin_unlock(&obd->obd_dev_lock);
			spin_unlock(&tgd->tgd_grant_lock);
			LBUG();
		}
	}

	fo_tot_granted = tgd->tgd_tot_granted;
	fo_tot_pending = tgd->tgd_tot_pending;
	fo_tot_dirty = tgd->tgd_tot_dirty;
	spin_unlock(&obd->obd_dev_lock);
	spin_unlock(&tgd->tgd_grant_lock);

	if (tot_granted != fo_tot_granted)
		CERROR("%s: tot_granted %llu != fo_tot_granted %llu\n",
		       func, tot_granted, fo_tot_granted);
	if (tot_pending != fo_tot_pending)
		CERROR("%s: tot_pending %llu != fo_tot_pending %llu\n",
		       func, tot_pending, fo_tot_pending);
	if (tot_dirty != fo_tot_dirty)
		CERROR("%s: tot_dirty %llu != fo_tot_dirty %llu\n",
		       func, tot_dirty, fo_tot_dirty);
	if (tot_pending > tot_granted)
		CERROR("%s: tot_pending %llu > tot_granted %llu\n",
		       func, tot_pending, tot_granted);
	if (tot_granted > maxsize)
		CERROR("%s: tot_granted %llu > maxsize %llu\n",
		       func, tot_granted, maxsize);
	if (tot_dirty > maxsize)
		CERROR("%s: tot_dirty %llu > maxsize %llu\n",
		       func, tot_dirty, maxsize);
}
EXPORT_SYMBOL(tgt_grant_sanity_check);

/**
 * Get file system statistics of target.
 *
 * Helper function for statfs(), also used by grant code.
 * Implements caching for statistics to avoid calling OSD device each time.
 *
 * \param[in]  env	  execution environment
 * \param[in]  lut	  LU target
 * \param[out] osfs	  statistic data to return
 * \param[in]  max_age	  maximum age for cached data
 * \param[in]  from_cache show that data was get from cache or not
 *
 * \retval		0 if successful
 * \retval		negative value on error
 */
int tgt_statfs_internal(const struct lu_env *env, struct lu_target *lut,
			struct obd_statfs *osfs, __u64 max_age, int *from_cache)
{
	struct tg_grants_data *tgd = &lut->lut_tgd;
	int rc = 0;
	ENTRY;

	spin_lock(&tgd->tgd_osfs_lock);
	if (cfs_time_before_64(tgd->tgd_osfs_age, max_age) || max_age == 0) {
		u64 unstable;

		/* statfs data are too old, get up-to-date one.
		 * we must be cautious here since multiple threads might be
		 * willing to update statfs data concurrently and we must
		 * grant that cached statfs data are always consistent */

		if (tgd->tgd_statfs_inflight == 0)
			/* clear inflight counter if no users, although it would
			 * take a while to overflow this 64-bit counter ... */
			tgd->tgd_osfs_inflight = 0;
		/* notify tgt_grant_commit() that we want to track writes
		 * completed as of now */
		tgd->tgd_statfs_inflight++;
		/* record value of inflight counter before running statfs to
		 * compute the diff once statfs is completed */
		unstable = tgd->tgd_osfs_inflight;
		spin_unlock(&tgd->tgd_osfs_lock);

		/* statfs can sleep ... hopefully not for too long since we can
		 * call it fairly often as space fills up */
		rc = dt_statfs(env, lut->lut_bottom, osfs);
		if (unlikely(rc))
			GOTO(out, rc);

		spin_lock(&tgd->tgd_grant_lock);
		spin_lock(&tgd->tgd_osfs_lock);
		/* calculate how much space was written while we released the
		 * tgd_osfs_lock */
		unstable = tgd->tgd_osfs_inflight - unstable;
		tgd->tgd_osfs_unstable = 0;
		if (unstable) {
			/* some writes committed while we were running statfs
			 * w/o the tgd_osfs_lock. Those ones got added to
			 * the cached statfs data that we are about to crunch.
			 * Take them into account in the new statfs data */
			osfs->os_bavail -= min_t(u64, osfs->os_bavail,
					       unstable >> tgd->tgd_blockbits);
			/* However, we don't really know if those writes got
			 * accounted in the statfs call, so tell
			 * tgt_grant_space_left() there is some uncertainty
			 * on the accounting of those writes.
			 * The purpose is to prevent spurious error messages in
			 * tgt_grant_space_left() since those writes might be
			 * accounted twice. */
			tgd->tgd_osfs_unstable += unstable;
		}
		/* similarly, there is some uncertainty on write requests
		 * between prepare & commit */
		tgd->tgd_osfs_unstable += tgd->tgd_tot_pending;
		spin_unlock(&tgd->tgd_grant_lock);

		/* finally udpate cached statfs data */
		tgd->tgd_osfs = *osfs;
		tgd->tgd_osfs_age = cfs_time_current_64();

		tgd->tgd_statfs_inflight--; /* stop tracking */
		if (tgd->tgd_statfs_inflight == 0)
			tgd->tgd_osfs_inflight = 0;
		spin_unlock(&tgd->tgd_osfs_lock);

		if (from_cache)
			*from_cache = 0;
	} else {
		/* use cached statfs data */
		*osfs = tgd->tgd_osfs;
		spin_unlock(&tgd->tgd_osfs_lock);
		if (from_cache)
			*from_cache = 1;
	}
	GOTO(out, rc);

out:
	return rc;
}
EXPORT_SYMBOL(tgt_statfs_internal);

/**
 * Update cached statfs information from the OSD layer
 *
 * Refresh statfs information cached in tgd::tgd_osfs if the cache is older
 * than 1s or if force is set. The OSD layer is in charge of estimating data &
 * metadata overhead.
 * This function can sleep so it should not be called with any spinlock held.
 *
 * \param[in] env		LU environment passed by the caller
 * \param[in] exp		export used to print client info in debug
 *				messages
 * \param[in] force		force a refresh of statfs information
 * \param[out] from_cache	returns whether the statfs information are
 *				taken from cache
 */
static void tgt_grant_statfs(const struct lu_env *env, struct obd_export *exp,
			     int force, int *from_cache)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lu_target	*lut = obd->u.obt.obt_lut;
	struct tg_grants_data	*tgd = &lut->lut_tgd;
	struct tgt_thread_info	*tti;
	struct obd_statfs	*osfs;
	__u64			 max_age;
	int			 rc;

	if (force)
		max_age = 0; /* get fresh statfs data */
	else
		max_age = cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS);

	tti = tgt_th_info(env);
	osfs = &tti->tti_u.osfs;
	rc = tgt_statfs_internal(env, lut, osfs, max_age, from_cache);
	if (unlikely(rc)) {
		if (from_cache)
			*from_cache = 0;
		return;
	}

	CDEBUG(D_CACHE, "%s: cli %s/%p free: %llu avail: %llu\n",
	       obd->obd_name, exp->exp_client_uuid.uuid, exp,
	       osfs->os_bfree << tgd->tgd_blockbits,
	       osfs->os_bavail << tgd->tgd_blockbits);
}

/**
 * Figure out how much space is available on the backend filesystem after
 * removing grant space already booked by clients.
 *
 * This is done by accessing cached statfs data previously populated by
 * tgt_grant_statfs(), from which we withdraw the space already granted to
 * clients and the reserved space.
 * Caller must hold tgd_grant_lock spinlock.
 *
 * \param[in] exp	export associated with the device for which the amount
 *			of available space is requested
 * \retval		amount of non-allocated space, in bytes
 */
static u64 tgt_grant_space_left(struct obd_export *exp)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lu_target	*lut = obd->u.obt.obt_lut;
	struct tg_grants_data	*tgd = &lut->lut_tgd;
	u64			 tot_granted;
	u64			 left;
	u64			 avail;
	u64			 unstable;

	ENTRY;
	assert_spin_locked(&tgd->tgd_grant_lock);

	spin_lock(&tgd->tgd_osfs_lock);
	/* get available space from cached statfs data */
	left = tgd->tgd_osfs.os_bavail << tgd->tgd_blockbits;
	unstable = tgd->tgd_osfs_unstable; /* those might be accounted twice */
	spin_unlock(&tgd->tgd_osfs_lock);

	tot_granted = tgd->tgd_tot_granted;

	if (left < tot_granted) {
		int mask = (left + unstable <
			    tot_granted - tgd->tgd_tot_pending) ?
			    D_ERROR : D_CACHE;

		CDEBUG_LIMIT(mask, "%s: cli %s/%p left %llu < tot_grant "
			     "%llu unstable %llu pending %llu "
			     "dirty %llu\n",
			     obd->obd_name, exp->exp_client_uuid.uuid, exp,
			     left, tot_granted, unstable,
			     tgd->tgd_tot_pending,
			     tgd->tgd_tot_dirty);
		RETURN(0);
	}

	avail = left;
	/* Withdraw space already granted to clients */
	left -= tot_granted;

	/* Align left on block size */
	left &= ~((1ULL << tgd->tgd_blockbits) - 1);

	CDEBUG(D_CACHE, "%s: cli %s/%p avail %llu left %llu unstable "
	       "%llu tot_grant %llu pending %llu\n", obd->obd_name,
	       exp->exp_client_uuid.uuid, exp, avail, left, unstable,
	       tot_granted, tgd->tgd_tot_pending);

	RETURN(left);
}

/**
 * Process grant information from obdo structure packed in incoming BRW
 * and inflate grant counters if required.
 *
 * Grab the dirty and seen grant announcements from the incoming obdo and
 * inflate all grant counters passed in the request if the client does not
 * support the grant parameters.
 * We will later calculate the client's new grant and return it.
 * Caller must hold tgd_grant_lock spinlock.
 *
 * \param[in] env	LU environment supplying osfs storage
 * \param[in] exp	export for which we received the request
 * \param[in,out] oa	incoming obdo sent by the client
 */
static void tgt_grant_incoming(const struct lu_env *env, struct obd_export *exp,
			       struct obdo *oa, long chunk)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct obd_device	*obd = exp->exp_obd;
	struct tg_grants_data	*tgd = &obd->u.obt.obt_lut->lut_tgd;
	long			 dirty;
	long			 dropped;
	ENTRY;

	assert_spin_locked(&tgd->tgd_grant_lock);

	if ((oa->o_valid & (OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) !=
					(OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) {
		oa->o_valid &= ~OBD_MD_FLGRANT;
		RETURN_EXIT;
	}

	/* Add some margin, since there is a small race if other RPCs arrive
	 * out-or-order and have already consumed some grant.  We want to
	 * leave this here in case there is a large error in accounting. */
	CDEBUG(D_CACHE,
	       "%s: cli %s/%p reports grant %llu dropped %u, local %lu\n",
	       obd->obd_name, exp->exp_client_uuid.uuid, exp, oa->o_grant,
	       oa->o_dropped, ted->ted_grant);

	if ((long long)oa->o_dirty < 0)
		oa->o_dirty = 0;

	/* inflate grant counters if required */
	if (!exp_grant_param_supp(exp)) {
		oa->o_grant	= tgt_grant_inflate(tgd, oa->o_grant);
		oa->o_dirty	= tgt_grant_inflate(tgd, oa->o_dirty);
		oa->o_dropped	= tgt_grant_inflate(tgd, (u64)oa->o_dropped);
		oa->o_undirty	= tgt_grant_inflate(tgd, oa->o_undirty);
	}

	dirty = oa->o_dirty;
	dropped = oa->o_dropped;

	/* Update our accounting now so that statfs takes it into account.
	 * Note that ted_dirty is only approximate and can become incorrect
	 * if RPCs arrive out-of-order.  No important calculations depend
	 * on ted_dirty however, but we must check sanity to not assert. */
	if (dirty > ted->ted_grant + 4 * chunk)
		dirty = ted->ted_grant + 4 * chunk;
	tgd->tgd_tot_dirty += dirty - ted->ted_dirty;
	if (ted->ted_grant < dropped) {
		CDEBUG(D_CACHE,
		       "%s: cli %s/%p reports %lu dropped > grant %lu\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp, dropped,
		       ted->ted_grant);
		dropped = 0;
	}
	if (tgd->tgd_tot_granted < dropped) {
		CERROR("%s: cli %s/%p reports %lu dropped > tot_grant %llu\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       dropped, tgd->tgd_tot_granted);
		dropped = 0;
	}
	tgd->tgd_tot_granted -= dropped;
	ted->ted_grant -= dropped;
	ted->ted_dirty = dirty;

	if (ted->ted_dirty < 0 || ted->ted_grant < 0 || ted->ted_pending < 0) {
		CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       ted->ted_dirty, ted->ted_pending, ted->ted_grant);
		spin_unlock(&tgd->tgd_grant_lock);
		LBUG();
	}
	EXIT;
}

/**
 * Grant shrink request handler.
 *
 * Client nodes can explicitly release grant space (i.e. process called grant
 * shrinking). This function proceeds with the shrink request when there is
 * less ungranted space remaining than the amount all of the connected clients
 * would consume if they used their full grant.
 * Caller must hold tgd_grant_lock spinlock.
 *
 * \param[in] exp		export releasing grant space
 * \param[in,out] oa		incoming obdo sent by the client
 * \param[in] left_space	remaining free space with space already granted
 *				taken out
 */
static void tgt_grant_shrink(struct obd_export *exp, struct obdo *oa,
			     u64 left_space)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct obd_device	*obd = exp->exp_obd;
	struct tg_grants_data	*tgd = &obd->u.obt.obt_lut->lut_tgd;
	long			 grant_shrink;

	assert_spin_locked(&tgd->tgd_grant_lock);
	LASSERT(exp);
	if (left_space >= tgd->tgd_tot_granted_clients *
			  TGT_GRANT_SHRINK_LIMIT(exp))
		return;

	grant_shrink = oa->o_grant;

	ted->ted_grant -= grant_shrink;
	tgd->tgd_tot_granted -= grant_shrink;

	CDEBUG(D_CACHE, "%s: cli %s/%p shrink %ld ted_grant %ld total %llu\n",
	       obd->obd_name, exp->exp_client_uuid.uuid, exp, grant_shrink,
	       ted->ted_grant, tgd->tgd_tot_granted);

	/* client has just released some grant, don't grant any space back */
	oa->o_grant = 0;
}

/**
 * Calculate how much space is required to write a given network buffer
 *
 * This function takes block alignment into account to estimate how much on-disk
 * space will be required to successfully write the whole niobuf.
 * Estimated space is inflated if the export does not support
 * OBD_CONNECT_GRANT_PARAM and if the backend filesystem has a block size
 * larger than the minimal supported page size (i.e. 4KB).
 *
 * \param[in] exp	export associated which the write request
 *			if NULL, then size estimate is done for server-side
 *			grant allocation.
 * \param[in] lut	LU target handling the request
 * \param[in] rnb	network buffer to estimate size of
 *
 * \retval		space (in bytes) that will be consumed to write the
 *			network buffer
 */
static inline u64 tgt_grant_rnb_size(struct obd_export *exp,
				     struct lu_target *lut,
				     struct niobuf_remote *rnb)
{
	struct tg_grants_data *tgd = &lut->lut_tgd;
	u64 blksize;
	u64 bytes;
	u64 end;

	if (exp && !exp_grant_param_supp(exp) &&
	    tgd->tgd_blockbits > COMPAT_BSIZE_SHIFT)
		blksize = 1ULL << COMPAT_BSIZE_SHIFT;
	else
		blksize = 1ULL << tgd->tgd_blockbits;

	/* The network buffer might span several blocks, align it on block
	 * boundaries */
	bytes  = rnb->rnb_offset & (blksize - 1);
	bytes += rnb->rnb_len;
	end    = bytes & (blksize - 1);
	if (end)
		bytes += blksize - end;

	if (exp == NULL || exp_grant_param_supp(exp)) {
		/* add per-extent insertion cost */
		u64 max_ext;
		int nr_ext;

		max_ext = blksize * lut->lut_dt_conf.ddp_max_extent_blks;
		nr_ext = (bytes + max_ext - 1) / max_ext;
		bytes += nr_ext * lut->lut_dt_conf.ddp_extent_tax;
	} else {
		/* Inflate grant space if client does not support extent-based
		 * grant allocation */
		bytes = tgt_grant_inflate(tgd, (u64)bytes);
	}

	return bytes;
}

/**
 * Validate grant accounting for each incoming remote network buffer.
 *
 * When clients have dirtied as much space as they've been granted they
 * fall through to sync writes. These sync writes haven't been expressed
 * in grants and need to error with ENOSPC when there isn't room in the
 * filesystem for them after grants are taken into account. However,
 * writeback of the dirty data that was already granted space can write
 * right on through.
 * The OBD_BRW_GRANTED flag will be set in the rnb_flags of each network
 * buffer which has been granted enough space to proceed. Buffers without
 * this flag will fail to be written with -ENOSPC (see tgt_preprw_write().
 * Caller must hold tgd_grant_lock spinlock.
 *
 * \param[in] env	LU environment passed by the caller
 * \param[in] exp	export identifying the client which sent the RPC
 * \param[in] oa	incoming obdo in which we should return the pack the
 *			additional grant
 * \param[in,out] rnb	the list of network buffers
 * \param[in] niocount	the number of network buffers in the list
 * \param[in] left	the remaining free space with space already granted
 *			taken out
 */
static void tgt_grant_check(const struct lu_env *env, struct obd_export *exp,
			    struct obdo *oa, struct niobuf_remote *rnb,
			    int niocount, u64 *left)
{
	struct tg_export_data	*ted = &exp->exp_target_data;
	struct obd_device	*obd = exp->exp_obd;
	struct lu_target	*lut = obd->u.obt.obt_lut;
	struct tg_grants_data	*tgd = &lut->lut_tgd;
	unsigned long		 ungranted = 0;
	unsigned long		 granted = 0;
	int			 i;
	bool			 skip = false;

	ENTRY;

	assert_spin_locked(&tgd->tgd_grant_lock);

	if (obd->obd_recovering) {
		/* Replaying write. Grant info have been processed already so no
		 * need to do any enforcement here. It is worth noting that only
		 * bulk writes with all rnbs having OBD_BRW_FROM_GRANT can be
		 * replayed. If one page hasn't OBD_BRW_FROM_GRANT set, then
		 * the whole bulk is written synchronously */
		skip = true;
		CDEBUG(D_CACHE, "Replaying write, skipping accounting\n");
	} else if ((oa->o_valid & OBD_MD_FLFLAGS) &&
		   (oa->o_flags & OBD_FL_RECOV_RESEND)) {
		/* Recoverable resend, grant info have already been processed as
		 * well */
		skip = true;
		CDEBUG(D_CACHE, "Recoverable resend arrived, skipping "
				"accounting\n");
	} else if (exp_grant_param_supp(exp) && oa->o_grant_used > 0) {
		/* Client supports the new grant parameters and is telling us
		 * how much grant space it consumed for this bulk write.
		 * Although all rnbs are supposed to have the OBD_BRW_FROM_GRANT
		 * flag set, we will scan the rnb list and looks for non-cache
		 * I/O in case it changes in the future */
		if (ted->ted_grant >= oa->o_grant_used) {
			/* skip grant accounting for rnbs with
			 * OBD_BRW_FROM_GRANT and just used grant consumption
			 * claimed in the request */
			granted = oa->o_grant_used;
			skip = true;
		} else {
			/* client has used more grants for this request that
			 * it owns ... */
			CERROR("%s: cli %s claims %lu GRANT, real grant %lu\n",
			       exp->exp_obd->obd_name,
			       exp->exp_client_uuid.uuid,
			       (unsigned long)oa->o_grant_used, ted->ted_grant);

			/* check whether we can fill the gap with unallocated
			 * grant */
			if (*left > (oa->o_grant_used - ted->ted_grant)) {
				/* ouf .. we are safe for now */
				granted = ted->ted_grant;
				ungranted = oa->o_grant_used - granted;
				*left -= ungranted;
				skip = true;
			}
			/* too bad, but we cannot afford to blow up our grant
			 * accounting. The loop below will handle each rnb in
			 * case by case. */
		}
	}

	for (i = 0; i < niocount; i++) {
		int bytes;

		if ((rnb[i].rnb_flags & OBD_BRW_FROM_GRANT)) {
			if (skip) {
				rnb[i].rnb_flags |= OBD_BRW_GRANTED;
				continue;
			}

			/* compute how much grant space is actually needed for
			 * this rnb, inflate grant if required */
			bytes = tgt_grant_rnb_size(exp, lut, &rnb[i]);
			if (ted->ted_grant >= granted + bytes) {
				granted += bytes;
				rnb[i].rnb_flags |= OBD_BRW_GRANTED;
				continue;
			}

			CDEBUG(D_CACHE, "%s: cli %s/%p claims %ld+%d GRANT, "
			       "real grant %lu idx %d\n", obd->obd_name,
			       exp->exp_client_uuid.uuid, exp, granted, bytes,
			       ted->ted_grant, i);
		}

		if (obd->obd_recovering)
			CERROR("%s: cli %s is replaying OST_WRITE while one rnb"
			       " hasn't OBD_BRW_FROM_GRANT set (0x%x)\n",
			       obd->obd_name, exp->exp_client_uuid.uuid,
			       rnb[i].rnb_flags);

		/* Consume grant space on the server.
		 * Unlike above, tgt_grant_rnb_size() is called with exp = NULL
		 * so that the required grant space isn't inflated. This is
		 * done on purpose since the server can deal with large block
		 * size, unlike some clients */
		bytes = tgt_grant_rnb_size(NULL, lut, &rnb[i]);
		if (*left > bytes) {
			/* if enough space, pretend it was granted */
			ungranted += bytes;
			*left -= bytes;
			rnb[i].rnb_flags |= OBD_BRW_GRANTED;
			continue;
		}

		/* We can't check for already-mapped blocks here (make sense
		 * when backend filesystem does not use COW) as it requires
		 * dropping the grant lock.
		 * Instead, we clear OBD_BRW_GRANTED and in that case we need
		 * to go through and verify if all of the blocks not marked
		 *  BRW_GRANTED are already mapped and we can ignore this error.
		 */
		rnb[i].rnb_flags &= ~OBD_BRW_GRANTED;
		CDEBUG(D_CACHE, "%s: cli %s/%p idx %d no space for %d\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp, i, bytes);
	}

	/* record in o_grant_used the actual space reserved for the I/O, will be
	 * used later in tgt_grant_commmit() */
	oa->o_grant_used = granted + ungranted;

	/* record space used for the I/O, will be used in tgt_grant_commmit() */
	/* Now substract what the clients has used already.  We don't subtract
	 * this from the tot_granted yet, so that other client's can't grab
	 * that space before we have actually allocated our blocks. That
	 * happens in tgt_grant_commit() after the writes are done. */
	ted->ted_grant -= granted;
	ted->ted_pending += oa->o_grant_used;
	tgd->tgd_tot_granted += ungranted;
	tgd->tgd_tot_pending += oa->o_grant_used;

	CDEBUG(D_CACHE,
	       "%s: cli %s/%p granted: %lu ungranted: %lu grant: %lu dirty: %lu"
	       "\n", obd->obd_name, exp->exp_client_uuid.uuid, exp,
	       granted, ungranted, ted->ted_grant, ted->ted_dirty);

	if (obd->obd_recovering || (oa->o_valid & OBD_MD_FLGRANT) == 0)
		/* don't update dirty accounting during recovery or
		 * if grant information got discarded (e.g. during resend) */
		RETURN_EXIT;

	if (ted->ted_dirty < granted) {
		CWARN("%s: cli %s/%p claims granted %lu > ted_dirty %lu\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       granted, ted->ted_dirty);
		granted = ted->ted_dirty;
	}
	tgd->tgd_tot_dirty -= granted;
	ted->ted_dirty -= granted;

	if (ted->ted_dirty < 0 || ted->ted_grant < 0 || ted->ted_pending < 0) {
		CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       ted->ted_dirty, ted->ted_pending, ted->ted_grant);
		spin_unlock(&tgd->tgd_grant_lock);
		LBUG();
	}
	EXIT;
}

/**
 * Allocate additional grant space to a client
 *
 * Calculate how much grant space to return to client, based on how much space
 * is currently free and how much of that is already granted.
 * Caller must hold tgd_grant_lock spinlock.
 *
 * \param[in] exp		export of the client which sent the request
 * \param[in] curgrant		current grant claimed by the client
 * \param[in] want		how much grant space the client would like to
 *				have
 * \param[in] left		remaining free space with granted space taken
 *				out
 * \param[in] conservative	if set to true, the server should be cautious
 *				and limit how much space is granted back to the
 *				client. Otherwise, the server should try hard to
 *				satisfy the client request.
 *
 * \retval			amount of grant space allocated
 */
static long tgt_grant_alloc(struct obd_export *exp, u64 curgrant,
			    u64 want, u64 left, long chunk,
			    bool conservative)
{
	struct obd_device	*obd = exp->exp_obd;
	struct tg_grants_data	*tgd = &obd->u.obt.obt_lut->lut_tgd;
	struct tg_export_data	*ted = &exp->exp_target_data;
	u64			 grant;

	ENTRY;

	/* When tgd_grant_compat_disable is set, we don't grant any space to
	 * clients not supporting OBD_CONNECT_GRANT_PARAM.
	 * Otherwise, space granted to such a client is inflated since it
	 * consumes PAGE_SIZE of grant space per block */
	if ((obd->obd_self_export != exp && !exp_grant_param_supp(exp) &&
	     tgd->tgd_grant_compat_disable) || left == 0 || exp->exp_failed)
		RETURN(0);

	if (want > 0x7fffffff) {
		CERROR("%s: client %s/%p requesting > 2GB grant %llu\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp, want);
		RETURN(0);
	}

	/* Grant some fraction of the client's requested grant space so that
	 * they are not always waiting for write credits (not all of it to
	 * avoid overgranting in face of multiple RPCs in flight).  This
	 * essentially will be able to control the OSC_MAX_RIF for a client.
	 *
	 * If we do have a large disparity between what the client thinks it
	 * has and what we think it has, don't grant very much and let the
	 * client consume its grant first.  Either it just has lots of RPCs
	 * in flight, or it was evicted and its grants will soon be used up. */
	if (curgrant >= want || curgrant >= ted->ted_grant + chunk)
		RETURN(0);

	if (obd->obd_recovering)
		conservative = false;

	if (conservative)
		/* don't grant more than 1/8th of the remaining free space in
		 * one chunk */
		left >>= 3;
	grant = min(want - curgrant, left);
	/* round grant up to the next block size */
	grant = (grant + (1 << tgd->tgd_blockbits) - 1) &
		~((1ULL << tgd->tgd_blockbits) - 1);

	if (!grant)
		RETURN(0);

	/* Limit to grant_chunk if not reconnect/recovery */
	if ((grant > chunk) && conservative)
		grant = chunk;

	tgd->tgd_tot_granted += grant;
	ted->ted_grant += grant;

	if (ted->ted_grant < 0) {
		CERROR("%s: cli %s/%p grant %ld want %llu current %llu\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       ted->ted_grant, want, curgrant);
		spin_unlock(&tgd->tgd_grant_lock);
		LBUG();
	}

	CDEBUG(D_CACHE,
	       "%s: cli %s/%p wants: %llu current grant %llu"
	       " granting: %llu\n", obd->obd_name, exp->exp_client_uuid.uuid,
	       exp, want, curgrant, grant);
	CDEBUG(D_CACHE,
	       "%s: cli %s/%p tot cached:%llu granted:%llu"
	       " num_exports: %d\n", obd->obd_name, exp->exp_client_uuid.uuid,
	       exp, tgd->tgd_tot_dirty, tgd->tgd_tot_granted,
	       obd->obd_num_exports);

	RETURN(grant);
}

/**
 * Handle grant space allocation on client connection & reconnection.
 *
 * A new non-readonly connection gets an initial grant allocation equals to
 * tgt_grant_chunk() (i.e. twice the max BRW size in most of the cases).
 * On reconnection, grant counters between client & target are resynchronized
 * and additional space might be granted back if possible.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] exp	client's export which is (re)connecting
 * \param[in,out] data	obd_connect_data structure sent by the client in the
 *			connect request
 * \param[in] new_conn	must set to true if this is a new connection and false
 *			for a reconnection
 */
void tgt_grant_connect(const struct lu_env *env, struct obd_export *exp,
		       struct obd_connect_data *data, bool new_conn)
{
	struct lu_target	*lut = exp->exp_obd->u.obt.obt_lut;
	struct tg_grants_data	*tgd = &lut->lut_tgd;
	struct tg_export_data	*ted = &exp->exp_target_data;
	u64			 left = 0;
	u64			 want;
	long			 chunk;
	int			 from_cache;
	int			 force = 0; /* can use cached data */

	/* don't grant space to client with read-only access */
	if (OCD_HAS_FLAG(data, RDONLY) ||
	    (!OCD_HAS_FLAG(data, GRANT_PARAM) &&
	     tgd->tgd_grant_compat_disable)) {
		data->ocd_grant = 0;
		data->ocd_connect_flags &= ~(OBD_CONNECT_GRANT |
					     OBD_CONNECT_GRANT_PARAM);
		RETURN_EXIT;
	}

	if (OCD_HAS_FLAG(data, GRANT_PARAM))
		want = data->ocd_grant;
	else
		want = tgt_grant_inflate(tgd, data->ocd_grant);
	chunk = tgt_grant_chunk(exp, lut, data);
refresh:
	tgt_grant_statfs(env, exp, force, &from_cache);

	spin_lock(&tgd->tgd_grant_lock);

	/* Grab free space from cached info and take out space already granted
	 * to clients as well as reserved space */
	left = tgt_grant_space_left(exp);

	/* get fresh statfs data if we are short in ungranted space */
	if (from_cache && left < 32 * chunk) {
		spin_unlock(&tgd->tgd_grant_lock);
		CDEBUG(D_CACHE, "fs has no space left and statfs too old\n");
		force = 1;
		goto refresh;
	}

	tgt_grant_alloc(exp, (u64)ted->ted_grant, want, left, chunk, new_conn);

	/* return to client its current grant */
	if (OCD_HAS_FLAG(data, GRANT_PARAM))
		data->ocd_grant = ted->ted_grant;
	else
		/* deflate grant */
		data->ocd_grant = tgt_grant_deflate(tgd, (u64)ted->ted_grant);

	/* reset dirty accounting */
	tgd->tgd_tot_dirty -= ted->ted_dirty;
	ted->ted_dirty = 0;

	if (new_conn && OCD_HAS_FLAG(data, GRANT))
		tgd->tgd_tot_granted_clients++;

	spin_unlock(&tgd->tgd_grant_lock);

	CDEBUG(D_CACHE, "%s: cli %s/%p ocd_grant: %d want: %llu left: %llu\n",
	       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
	       exp, data->ocd_grant, want, left);

	EXIT;
}
EXPORT_SYMBOL(tgt_grant_connect);

/**
 * Release all grant space attached to a given export.
 *
 * Remove a client from the grant accounting totals.  We also remove
 * the export from the obd device under the osfs and dev locks to ensure
 * that the tgt_grant_sanity_check() calculations are always valid.
 * The client should do something similar when it invalidates its import.
 *
 * \param[in] exp	client's export to remove from grant accounting
 */
void tgt_grant_discard(struct obd_export *exp)
{
	struct obd_device	*obd = exp->exp_obd;
	struct tg_grants_data	*tgd = &obd->u.obt.obt_lut->lut_tgd;
	struct tg_export_data	*ted = &exp->exp_target_data;

	spin_lock(&tgd->tgd_grant_lock);
	LASSERTF(tgd->tgd_tot_granted >= ted->ted_grant,
		 "%s: tot_granted %llu cli %s/%p ted_grant %ld\n",
		 obd->obd_name, tgd->tgd_tot_granted,
		 exp->exp_client_uuid.uuid, exp, ted->ted_grant);
	tgd->tgd_tot_granted -= ted->ted_grant;
	ted->ted_grant = 0;
	LASSERTF(tgd->tgd_tot_pending >= ted->ted_pending,
		 "%s: tot_pending %llu cli %s/%p ted_pending %ld\n",
		 obd->obd_name, tgd->tgd_tot_pending,
		 exp->exp_client_uuid.uuid, exp, ted->ted_pending);
	/* tgd_tot_pending is handled in tgt_grant_commit as bulk
	 * commmits */
	LASSERTF(tgd->tgd_tot_dirty >= ted->ted_dirty,
		 "%s: tot_dirty %llu cli %s/%p ted_dirty %ld\n",
		 obd->obd_name, tgd->tgd_tot_dirty,
		 exp->exp_client_uuid.uuid, exp, ted->ted_dirty);
	tgd->tgd_tot_dirty -= ted->ted_dirty;
	ted->ted_dirty = 0;
	spin_unlock(&tgd->tgd_grant_lock);
}
EXPORT_SYMBOL(tgt_grant_discard);

/**
 * Process grant information from incoming bulk read request.
 *
 * Extract grant information packed in obdo structure (OBD_MD_FLGRANT set in
 * o_valid). Bulk reads usually comes with grant announcements (number of dirty
 * blocks, remaining amount of grant space, ...) and could also include a grant
 * shrink request. Unlike bulk write, no additional grant space is returned on
 * bulk read request.
 *
 * \param[in] env	is the lu environment provided by the caller
 * \param[in] exp	is the export of the client which sent the request
 * \param[in,out] oa	is the incoming obdo sent by the client
 */
void tgt_grant_prepare_read(const struct lu_env *env,
			    struct obd_export *exp, struct obdo *oa)
{
	struct lu_target	*lut = exp->exp_obd->u.obt.obt_lut;
	struct tg_grants_data	*tgd = &lut->lut_tgd;
	int			 do_shrink;
	u64			 left = 0;

	ENTRY;

	if (!oa)
		RETURN_EXIT;

	if ((oa->o_valid & OBD_MD_FLGRANT) == 0)
		/* The read request does not contain any grant
		 * information */
		RETURN_EXIT;

	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_SHRINK_GRANT)) {
		/* To process grant shrink request, we need to know how much
		 * available space remains on the backend filesystem.
		 * Shrink requests are not so common, we always get fresh
		 * statfs information. */
		tgt_grant_statfs(env, exp, 1, NULL);

		/* protect all grant counters */
		spin_lock(&tgd->tgd_grant_lock);

		/* Grab free space from cached statfs data and take out space
		 * already granted to clients as well as reserved space */
		left = tgt_grant_space_left(exp);

		/* all set now to proceed with shrinking */
		do_shrink = 1;
	} else {
		/* no grant shrinking request packed in the obdo and
		 * since we don't grant space back on reads, no point
		 * in running statfs, so just skip it and process
		 * incoming grant data directly. */
		spin_lock(&tgd->tgd_grant_lock);
		do_shrink = 0;
	}

	/* extract incoming grant information provided by the client and
	 * inflate grant counters if required */
	tgt_grant_incoming(env, exp, oa, tgt_grant_chunk(exp, lut, NULL));

	/* unlike writes, we don't return grants back on reads unless a grant
	 * shrink request was packed and we decided to turn it down. */
	if (do_shrink)
		tgt_grant_shrink(exp, oa, left);
	else
		oa->o_grant = 0;

	if (!exp_grant_param_supp(exp))
		oa->o_grant = tgt_grant_deflate(tgd, oa->o_grant);
	spin_unlock(&tgd->tgd_grant_lock);
	EXIT;
}
EXPORT_SYMBOL(tgt_grant_prepare_read);

/**
 * Process grant information from incoming bulk write request.
 *
 * This function extracts client's grant announcements from incoming bulk write
 * request and attempts to allocate grant space for network buffers that need it
 * (i.e. OBD_BRW_FROM_GRANT not set in rnb_fags).
 * Network buffers which aren't granted the OBD_BRW_GRANTED flag should not
 * proceed further and should fail with -ENOSPC.
 * Whenever possible, additional grant space will be returned to the client
 * in the bulk write reply.
 * tgt_grant_prepare_write() must be called before writting any buffers to
 * the backend storage. This function works in pair with tgt_grant_commit()
 * which must be invoked once all buffers have been written to disk in order
 * to release space from the pending grant counter.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] exp	export of the client which sent the request
 * \param[in] oa	incoming obdo sent by the client
 * \param[in] rnb	list of network buffers
 * \param[in] niocount	number of network buffers in the list
 */
void tgt_grant_prepare_write(const struct lu_env *env,
			     struct obd_export *exp, struct obdo *oa,
			     struct niobuf_remote *rnb, int niocount)
{
	struct obd_device	*obd = exp->exp_obd;
	struct lu_target	*lut = obd->u.obt.obt_lut;
	struct tg_grants_data	*tgd = &lut->lut_tgd;
	u64			 left;
	int			 from_cache;
	int			 force = 0; /* can use cached data intially */
	long			 chunk = tgt_grant_chunk(exp, lut, NULL);

	ENTRY;

refresh:
	/* get statfs information from OSD layer */
	tgt_grant_statfs(env, exp, force, &from_cache);

	spin_lock(&tgd->tgd_grant_lock); /* protect all grant counters */

	/* Grab free space from cached statfs data and take out space already
	 * granted to clients as well as reserved space */
	left = tgt_grant_space_left(exp);

	/* Get fresh statfs data if we are short in ungranted space */
	if (from_cache && left < 32 * chunk) {
		spin_unlock(&tgd->tgd_grant_lock);
		CDEBUG(D_CACHE, "%s: fs has no space left and statfs too old\n",
		       obd->obd_name);
		force = 1;
		goto refresh;
	}

	/* When close to free space exhaustion, trigger a sync to force
	 * writeback cache to consume required space immediately and release as
	 * much space as possible. */
	if (!obd->obd_recovering && force != 2 && left < chunk) {
		bool from_grant = true;
		int  i;

		/* That said, it is worth running a sync only if some pages did
		 * not consume grant space on the client and could thus fail
		 * with ENOSPC later in tgt_grant_check() */
		for (i = 0; i < niocount; i++)
			if (!(rnb[i].rnb_flags & OBD_BRW_FROM_GRANT))
				from_grant = false;

		if (!from_grant) {
			/* at least one network buffer requires acquiring grant
			 * space on the server */
			spin_unlock(&tgd->tgd_grant_lock);
			/* discard errors, at least we tried ... */
			dt_sync(env, lut->lut_bottom);
			force = 2;
			goto refresh;
		}
	}

	/* extract incoming grant information provided by the client,
	 * and inflate grant counters if required */
	tgt_grant_incoming(env, exp, oa, chunk);

	/* check limit */
	tgt_grant_check(env, exp, oa, rnb, niocount, &left);

	if (!(oa->o_valid & OBD_MD_FLGRANT)) {
		spin_unlock(&tgd->tgd_grant_lock);
		RETURN_EXIT;
	}

	/* if OBD_FL_SHRINK_GRANT is set, the client is willing to release some
	 * grant space. */
	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_SHRINK_GRANT))
		tgt_grant_shrink(exp, oa, left);
	else
		/* grant more space back to the client if possible */
		oa->o_grant = tgt_grant_alloc(exp, oa->o_grant, oa->o_undirty,
					      left, chunk, true);

	if (!exp_grant_param_supp(exp))
		oa->o_grant = tgt_grant_deflate(tgd, oa->o_grant);
	spin_unlock(&tgd->tgd_grant_lock);
	EXIT;
}
EXPORT_SYMBOL(tgt_grant_prepare_write);

/**
 * Consume grant space reserved for object creation.
 *
 * Grant space is allocated to the local self export for object precreation.
 * This is required to prevent object precreation from consuming grant space
 * allocated to client nodes for the data writeback cache.
 * This function consumes enough space to create \a nr objects and allocates
 * more grant space to the self export for future precreation requests, if
 * possible.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] exp	export holding the grant space for precreation (= self
 *			export currently)
 * \param[in] nr	number of objects to be created
 *
 * \retval >= 0		amount of grant space allocated to the precreate request
 * \retval -ENOSPC	on failure
 */
long tgt_grant_create(const struct lu_env *env, struct obd_export *exp, s64 *nr)
{
	struct lu_target	*lut = exp->exp_obd->u.obt.obt_lut;
	struct tg_grants_data	*tgd = &lut->lut_tgd;
	struct tg_export_data	*ted = &exp->exp_target_data;
	u64			 left = 0;
	unsigned long		 wanted;
	unsigned long		 granted;
	ENTRY;

	if (exp->exp_obd->obd_recovering ||
	    lut->lut_dt_conf.ddp_inodespace == 0)
		/* don't enforce grant during recovery */
		RETURN(0);

	/* Update statfs data if required */
	tgt_grant_statfs(env, exp, 1, NULL);

	/* protect all grant counters */
	spin_lock(&tgd->tgd_grant_lock);

	/* fail precreate request if there is not enough blocks available for
	 * writing */
	if (tgd->tgd_osfs.os_bavail - (ted->ted_grant >> tgd->tgd_blockbits) <
	    (tgd->tgd_osfs.os_blocks >> 10)) {
		spin_unlock(&tgd->tgd_grant_lock);
		CDEBUG(D_RPCTRACE, "%s: not enough space for create %llu\n",
		       exp->exp_obd->obd_name,
		       tgd->tgd_osfs.os_bavail * tgd->tgd_osfs.os_blocks);
		RETURN(-ENOSPC);
	}

	/* Grab free space from cached statfs data and take out space
	 * already granted to clients as well as reserved space */
	left = tgt_grant_space_left(exp);

	/* compute how much space is required to handle the precreation
	 * request */
	wanted = *nr * lut->lut_dt_conf.ddp_inodespace;
	if (wanted > ted->ted_grant + left) {
		/* that's beyond what remains, adjust the number of objects that
		 * can be safely precreated */
		wanted = ted->ted_grant + left;
		*nr = wanted / lut->lut_dt_conf.ddp_inodespace;
		if (*nr == 0) {
			/* we really have no space any more for precreation,
			 * fail the precreate request with ENOSPC */
			spin_unlock(&tgd->tgd_grant_lock);
			RETURN(-ENOSPC);
		}
		/* compute space needed for the new number of creations */
		wanted = *nr * lut->lut_dt_conf.ddp_inodespace;
	}
	LASSERT(wanted <= ted->ted_grant + left);

	if (wanted <= ted->ted_grant) {
		/* we've enough grant space to handle this precreate request */
		ted->ted_grant -= wanted;
	} else {
		/* we need to take some space from the ungranted pool */
		tgd->tgd_tot_granted += wanted - ted->ted_grant;
		left -= wanted - ted->ted_grant;
		ted->ted_grant = 0;
	}
	granted = wanted;
	ted->ted_pending += granted;
	tgd->tgd_tot_pending += granted;

	/* grant more space for precreate purpose if possible. */
	wanted = OST_MAX_PRECREATE * lut->lut_dt_conf.ddp_inodespace / 2;
	if (wanted > ted->ted_grant) {
		long chunk;

		/* always try to book enough space to handle a large precreate
		 * request */
		chunk = tgt_grant_chunk(exp, lut, NULL);
		wanted -= ted->ted_grant;
		tgt_grant_alloc(exp, ted->ted_grant, wanted, left, chunk,
				false);
	}
	spin_unlock(&tgd->tgd_grant_lock);
	RETURN(granted);
}
EXPORT_SYMBOL(tgt_grant_create);

/**
 * Release grant space added to the pending counter by tgt_grant_prepare_write()
 *
 * Update pending grant counter once buffers have been written to the disk.
 *
 * \param[in] exp	export of the client which sent the request
 * \param[in] pending	amount of reserved space to be released
 * \param[in] rc	return code of pre-commit operations
 */
void tgt_grant_commit(struct obd_export *exp, unsigned long pending,
		      int rc)
{
	struct tg_grants_data *tgd = &exp->exp_obd->u.obt.obt_lut->lut_tgd;

	ENTRY;

	/* get space accounted in tot_pending for the I/O, set in
	 * tgt_grant_check() */
	if (pending == 0)
		RETURN_EXIT;

	spin_lock(&tgd->tgd_grant_lock);
	/* Don't update statfs data for errors raised before commit (e.g.
	 * bulk transfer failed, ...) since we know those writes have not been
	 * processed. For other errors hit during commit, we cannot really tell
	 * whether or not something was written, so we update statfs data.
	 * In any case, this should not be fatal since we always get fresh
	 * statfs data before failing a request with ENOSPC */
	if (rc == 0) {
		spin_lock(&tgd->tgd_osfs_lock);
		/* Take pending out of cached statfs data */
		tgd->tgd_osfs.os_bavail -= min_t(u64,
						 tgd->tgd_osfs.os_bavail,
						 pending >> tgd->tgd_blockbits);
		if (tgd->tgd_statfs_inflight)
			/* someone is running statfs and want to be notified of
			 * writes happening meanwhile */
			tgd->tgd_osfs_inflight += pending;
		spin_unlock(&tgd->tgd_osfs_lock);
	}

	if (exp->exp_target_data.ted_pending < pending) {
		CERROR("%s: cli %s/%p ted_pending(%lu) < grant_used(%lu)\n",
		       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       exp->exp_target_data.ted_pending, pending);
		spin_unlock(&tgd->tgd_grant_lock);
		LBUG();
	}
	exp->exp_target_data.ted_pending -= pending;

	if (tgd->tgd_tot_granted < pending) {
		CERROR("%s: cli %s/%p tot_granted(%llu) < grant_used(%lu)\n",
		       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       tgd->tgd_tot_granted, pending);
		spin_unlock(&tgd->tgd_grant_lock);
		LBUG();
	}
	tgd->tgd_tot_granted -= pending;

	if (tgd->tgd_tot_pending < pending) {
		CERROR("%s: cli %s/%p tot_pending(%llu) < grant_used(%lu)\n",
		       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       tgd->tgd_tot_pending, pending);
		spin_unlock(&tgd->tgd_grant_lock);
		LBUG();
	}
	tgd->tgd_tot_pending -= pending;
	spin_unlock(&tgd->tgd_grant_lock);
	EXIT;
}
EXPORT_SYMBOL(tgt_grant_commit);

struct tgt_grant_cb {
	/* commit callback structure */
	struct dt_txn_commit_cb	 tgc_cb;
	/* export associated with the bulk write */
	struct obd_export	*tgc_exp;
	/* pending grant to be released */
	unsigned long		 tgc_granted;
};

/**
 * Callback function for grant releasing
 *
 * Release grant space reserved by the client node.
 *
 * \param[in] env	execution environment
 * \param[in] th	transaction handle
 * \param[in] cb	callback data
 * \param[in] err	error code
 */
static void tgt_grant_commit_cb(struct lu_env *env, struct thandle *th,
				struct dt_txn_commit_cb *cb, int err)
{
	struct tgt_grant_cb *tgc;

	tgc = container_of(cb, struct tgt_grant_cb, tgc_cb);

	tgt_grant_commit(tgc->tgc_exp, tgc->tgc_granted, err);
	class_export_cb_put(tgc->tgc_exp);
	OBD_FREE_PTR(tgc);
}

/**
 * Add callback for grant releasing
 *
 * Register a commit callback to release grant space.
 *
 * \param[in] th	transaction handle
 * \param[in] exp	OBD export of client
 * \param[in] granted	amount of grant space to be released upon commit
 *
 * \retval		0 on successful callback adding
 * \retval		negative value on error
 */
int tgt_grant_commit_cb_add(struct thandle *th, struct obd_export *exp,
			    unsigned long granted)
{
	struct tgt_grant_cb	*tgc;
	struct dt_txn_commit_cb	*dcb;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(tgc);
	if (tgc == NULL)
		RETURN(-ENOMEM);

	tgc->tgc_exp = class_export_cb_get(exp);
	tgc->tgc_granted = granted;

	dcb = &tgc->tgc_cb;
	dcb->dcb_func = tgt_grant_commit_cb;
	INIT_LIST_HEAD(&dcb->dcb_linkage);
	strlcpy(dcb->dcb_name, "tgt_grant_commit_cb", sizeof(dcb->dcb_name));

	rc = dt_trans_cb_add(th, dcb);
	if (rc) {
		class_export_cb_put(tgc->tgc_exp);
		OBD_FREE_PTR(tgc);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(tgt_grant_commit_cb_add);
