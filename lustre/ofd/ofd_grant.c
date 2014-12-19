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
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
/*
 * lustre/ofd/ofd_grant.c
 *
 * This file provides code related to grant space management on Object Storage
 * Targets (OSTs). Grant is a mechanism used by client nodes to reserve disk
 * space on OSTs for the data writeback cache. The Lustre client is thus assured
 * that enough space will be available when flushing dirty pages asynchronously.
 * Each client node is granted an initial amount of reserved space at connect
 * time and gets additional space back from OST in bulk write reply.
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

#include "ofd_internal.h"

/* At least enough to send a couple of 1MB RPCs, even if not max sized */
#define OFD_GRANT_CHUNK			(2ULL * DT_MAX_BRW_SIZE)

/* Clients typically hold 2x their max_rpcs_in_flight of grant space */
#define OFD_GRANT_SHRINK_LIMIT(exp)	(2ULL * 8 * exp_max_brw_size(exp))

static inline u64 ofd_grant_from_cli(struct obd_export *exp,
				     struct ofd_device *ofd, u64 val)
{
	if (ofd_grant_compat(exp, ofd))
		/* clients not supporting OBD_CONNECT_GRANT_PARAM actually
		 * consume 4KB of grant per block, we should thus inflate
		 * the grant counters to reflect what was actually consumed */
		return val << (ofd->ofd_blockbits - COMPAT_BSIZE_SHIFT);
	return val;
}

static inline u64 ofd_grant_to_cli(struct obd_export *exp,
				   struct ofd_device *ofd, u64 val)
{
	if (ofd_grant_compat(exp, ofd))
		return val >> (ofd->ofd_blockbits - COMPAT_BSIZE_SHIFT);
	return val;
}

static inline u64 ofd_grant_chunk(struct obd_export *exp,
				  struct ofd_device *ofd)
{
	if (ofd_obd(ofd)->obd_self_export == exp)
		/* Grant enough space to handle a big precreate request */
		return OST_MAX_PRECREATE * ofd->ofd_dt_conf.ddp_inodespace / 2;

	if (ofd_grant_compat(exp, ofd))
		/* Try to grant enough space to send a full-size RPC */
		return exp_max_brw_size(exp) <<
		       (ofd->ofd_blockbits - COMPAT_BSIZE_SHIFT);

	/* Try to return enough to send two full RPCs, if needed */
	return exp_max_brw_size(exp) * 2;
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
void ofd_grant_sanity_check(struct obd_device *obd, const char *func)
{
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	struct obd_export *exp;
	u64		   maxsize;
	u64		   tot_dirty = 0;
	u64		   tot_pending = 0;
	u64		   tot_granted = 0;
	u64		   fo_tot_granted;
	u64		   fo_tot_pending;
	u64		   fo_tot_dirty;

	if (list_empty(&obd->obd_exports))
		return;

	/* We don't want to do this for large machines that do lots of
	 * mounts or unmounts.  It burns... */
	if (obd->obd_num_exports > 100)
		return;

	maxsize = ofd->ofd_osfs.os_blocks << ofd->ofd_blockbits;

	spin_lock(&obd->obd_dev_lock);
	spin_lock(&ofd->ofd_grant_lock);
	list_for_each_entry(exp, &obd->obd_exports, exp_obd_chain) {
		struct filter_export_data	*fed;
		int				 error = 0;

		fed = &exp->exp_filter_data;

		if (obd->obd_self_export == exp)
			CDEBUG(D_CACHE, "%s: processing self export: %ld %ld "
			       "%ld\n", obd->obd_name, fed->fed_grant,
			       fed->fed_pending, fed->fed_dirty);

		if (fed->fed_grant < 0 || fed->fed_pending < 0 ||
		    fed->fed_dirty < 0)
			error = 1;
		if (fed->fed_grant + fed->fed_pending > maxsize) {
			CERROR("%s: cli %s/%p fed_grant(%ld) + fed_pending(%ld)"
			       " > maxsize("LPU64")\n", obd->obd_name,
			       exp->exp_client_uuid.uuid, exp, fed->fed_grant,
			       fed->fed_pending, maxsize);
			spin_unlock(&obd->obd_dev_lock);
			spin_unlock(&ofd->ofd_grant_lock);
			LBUG();
		}
		if (fed->fed_dirty > maxsize) {
			CERROR("%s: cli %s/%p fed_dirty(%ld) > maxsize("LPU64
			       ")\n", obd->obd_name, exp->exp_client_uuid.uuid,
			       exp, fed->fed_dirty, maxsize);
			spin_unlock(&obd->obd_dev_lock);
			spin_unlock(&ofd->ofd_grant_lock);
			LBUG();
		}
		CDEBUG_LIMIT(error ? D_ERROR : D_CACHE, "%s: cli %s/%p dirty "
			     "%ld pend %ld grant %ld\n", obd->obd_name,
			     exp->exp_client_uuid.uuid, exp, fed->fed_dirty,
			     fed->fed_pending, fed->fed_grant);
		tot_granted += fed->fed_grant + fed->fed_pending;
		tot_pending += fed->fed_pending;
		tot_dirty += fed->fed_dirty;
	}
	spin_unlock(&obd->obd_dev_lock);
	fo_tot_granted = ofd->ofd_tot_granted;
	fo_tot_pending = ofd->ofd_tot_pending;
	fo_tot_dirty = ofd->ofd_tot_dirty;

	if (tot_granted != fo_tot_granted)
		CERROR("%s: tot_granted "LPU64" != fo_tot_granted "LPU64"\n",
		       func, tot_granted, fo_tot_granted);
	if (tot_pending != fo_tot_pending)
		CERROR("%s: tot_pending "LPU64" != fo_tot_pending "LPU64"\n",
		       func, tot_pending, fo_tot_pending);
	if (tot_dirty != fo_tot_dirty)
		CERROR("%s: tot_dirty "LPU64" != fo_tot_dirty "LPU64"\n",
		       func, tot_dirty, fo_tot_dirty);
	if (tot_pending > tot_granted)
		CERROR("%s: tot_pending "LPU64" > tot_granted "LPU64"\n",
		       func, tot_pending, tot_granted);
	if (tot_granted > maxsize)
		CERROR("%s: tot_granted "LPU64" > maxsize "LPU64"\n",
		       func, tot_granted, maxsize);
	if (tot_dirty > maxsize)
		CERROR("%s: tot_dirty "LPU64" > maxsize "LPU64"\n",
		       func, tot_dirty, maxsize);
	spin_unlock(&ofd->ofd_grant_lock);
}

/**
 * Update cached statfs information from the OSD layer
 *
 * Refresh statfs information cached in ofd::ofd_osfs if the cache is older
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
static void ofd_grant_statfs(const struct lu_env *env, struct obd_export *exp,
			     int force, int *from_cache)
{
	struct obd_device	*obd = exp->exp_obd;
	struct ofd_device	*ofd = ofd_exp(exp);
	struct obd_statfs	*osfs = &ofd_info(env)->fti_u.osfs;
	__u64			 max_age;
	int			 rc;

	if (force)
		max_age = 0; /* get fresh statfs data */
	else
		max_age = cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS);

	rc = ofd_statfs_internal(env, ofd, osfs, max_age, from_cache);
	if (unlikely(rc)) {
		if (from_cache)
			*from_cache = 0;
		return;
	}

	CDEBUG(D_CACHE, "%s: cli %s/%p free: "LPU64" avail: "LPU64"\n",
	       obd->obd_name, exp->exp_client_uuid.uuid, exp,
	       osfs->os_bfree << ofd->ofd_blockbits,
	       osfs->os_bavail << ofd->ofd_blockbits);
}

/**
 * Figure out how much space is available on the backend filesystem after
 * removing grant space already booked by clients.
 *
 * This is done by accessing cached statfs data previously populated by
 * ofd_grant_statfs(), from which we withdraw the space already granted to
 * clients and the reserved space.
 * Caller must hold ofd_grant_lock spinlock.
 *
 * \param[in] exp	export associated with the device for which the amount
 *			of available space is requested
 * \retval		amount of non-allocated space, in bytes
 */
static u64 ofd_grant_space_left(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct ofd_device *ofd = ofd_exp(exp);
	u64		   tot_granted;
	u64		   left;
	u64		   avail;
	u64		   unstable;

	ENTRY;
	assert_spin_locked(&ofd->ofd_grant_lock);

	spin_lock(&ofd->ofd_osfs_lock);
	/* get available space from cached statfs data */
	left = ofd->ofd_osfs.os_bavail << ofd->ofd_blockbits;
	unstable = ofd->ofd_osfs_unstable; /* those might be accounted twice */
	spin_unlock(&ofd->ofd_osfs_lock);

	tot_granted = ofd->ofd_tot_granted;

	if (left < tot_granted) {
		int mask = (left + unstable <
			    tot_granted - ofd->ofd_tot_pending) ?
			    D_ERROR : D_CACHE;

		CDEBUG_LIMIT(mask, "%s: cli %s/%p left "LPU64" < tot_grant "
			     LPU64" unstable "LPU64" pending "LPU64" "
			     "dirty "LPU64"\n",
			     obd->obd_name, exp->exp_client_uuid.uuid, exp,
			     left, tot_granted, unstable,
			     ofd->ofd_tot_pending, ofd->ofd_tot_dirty);
		RETURN(0);
	}

	avail = left;
	/* Withdraw space already granted to clients */
	left -= tot_granted;

	/* If the left space is below the grant threshold x available space,
	 * stop granting space to clients.
	 * The purpose of this threshold is to keep some error margin on the
	 * overhead estimate made by the OSD layer. If we grant all the free
	 * space, we have no way (grant space cannot be revoked yet) to
	 * adjust if the write overhead has been underestimated. */
	left -= min_t(u64, left, ofd_grant_reserved(ofd, avail));

	/* Align left on block size */
	left &= ~((1ULL << ofd->ofd_blockbits) - 1);

	CDEBUG(D_CACHE, "%s: cli %s/%p avail "LPU64" left "LPU64" unstable "
	       LPU64" tot_grant "LPU64" pending "LPU64"\n", obd->obd_name,
	       exp->exp_client_uuid.uuid, exp, avail, left, unstable,
	       tot_granted, ofd->ofd_tot_pending);

	RETURN(left);
}

/**
 * Process grant information from obdo structure packed in incoming BRW
 *
 * Grab the dirty and seen grant announcements from the incoming obdo.
 * We will later calculate the client's new grant and return it.
 * Caller must hold ofd_grant_lock spinlock.
 *
 * \param[in] env	LU environment supplying osfs storage
 * \param[in] exp	export for which we received the request
 * \param[in,out] oa	incoming obdo sent by the client
 *
 */
static void ofd_grant_incoming(const struct lu_env *env, struct obd_export *exp,
			       struct obdo *oa)
{
	struct filter_export_data	*fed;
	struct ofd_device		*ofd = ofd_exp(exp);
	struct obd_device		*obd = exp->exp_obd;
	long				 dirty;
	long				 dropped;
	long				 grant_chunk;
	ENTRY;

	assert_spin_locked(&ofd->ofd_grant_lock);

	if ((oa->o_valid & (OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) !=
					(OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) {
		oa->o_valid &= ~OBD_MD_FLGRANT;
		RETURN_EXIT;
	}

	fed = &exp->exp_filter_data;

	/* Add some margin, since there is a small race if other RPCs arrive
	 * out-or-order and have already consumed some grant.  We want to
	 * leave this here in case there is a large error in accounting. */
	CDEBUG(D_CACHE,
	       "%s: cli %s/%p reports grant "LPU64" dropped %u, local %lu\n",
	       obd->obd_name, exp->exp_client_uuid.uuid, exp, oa->o_grant,
	       oa->o_dropped, fed->fed_grant);

	if ((long long)oa->o_dirty < 0)
		oa->o_dirty = 0;

	dirty       = ofd_grant_from_cli(exp, ofd, oa->o_dirty);
	dropped     = ofd_grant_from_cli(exp, ofd, (u64)oa->o_dropped);
	grant_chunk = ofd_grant_chunk(exp, ofd);

	/* Update our accounting now so that statfs takes it into account.
	 * Note that fed_dirty is only approximate and can become incorrect
	 * if RPCs arrive out-of-order.  No important calculations depend
	 * on fed_dirty however, but we must check sanity to not assert. */
	if (dirty > fed->fed_grant + 4 * grant_chunk)
		dirty = fed->fed_grant + 4 * grant_chunk;
	ofd->ofd_tot_dirty += dirty - fed->fed_dirty;
	if (fed->fed_grant < dropped) {
		CDEBUG(D_CACHE,
		       "%s: cli %s/%p reports %lu dropped > grant %lu\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp, dropped,
		       fed->fed_grant);
		dropped = 0;
	}
	if (ofd->ofd_tot_granted < dropped) {
		CERROR("%s: cli %s/%p reports %lu dropped > tot_grant "LPU64
		       "\n", obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       dropped, ofd->ofd_tot_granted);
		dropped = 0;
	}
	ofd->ofd_tot_granted -= dropped;
	fed->fed_grant -= dropped;
	fed->fed_dirty = dirty;

	if (fed->fed_dirty < 0 || fed->fed_grant < 0 || fed->fed_pending < 0) {
		CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       fed->fed_dirty, fed->fed_pending, fed->fed_grant);
		spin_unlock(&ofd->ofd_grant_lock);
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
 * Caller must hold ofd_grant_lock spinlock.
 *
 * \param[in] exp		export releasing grant space
 * \param[in,out] oa		incoming obdo sent by the client
 * \param[in] left_space	remaining free space with space already granted
 *				taken out
 */
static void ofd_grant_shrink(struct obd_export *exp, struct obdo *oa,
			     u64 left_space)
{
	struct filter_export_data	*fed;
	struct ofd_device		*ofd = ofd_exp(exp);
	struct obd_device		*obd = exp->exp_obd;
	long				 grant_shrink;

	assert_spin_locked(&ofd->ofd_grant_lock);
	LASSERT(exp);
	if (left_space >= ofd->ofd_tot_granted_clients *
			  OFD_GRANT_SHRINK_LIMIT(exp))
		return;

	grant_shrink = ofd_grant_from_cli(exp, ofd, oa->o_grant);

	fed = &exp->exp_filter_data;
	fed->fed_grant       -= grant_shrink;
	ofd->ofd_tot_granted -= grant_shrink;

	CDEBUG(D_CACHE, "%s: cli %s/%p shrink %ld fed_grant %ld total "
	       LPU64"\n", obd->obd_name, exp->exp_client_uuid.uuid,
	       exp, grant_shrink, fed->fed_grant, ofd->ofd_tot_granted);

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
 * \param[in] ofd	ofd device handling the request
 * \param[in] rnb	network buffer to estimate size of
 *
 * \retval		space (in bytes) that will be consumed to write the
 *			network buffer
 */
static inline u64 ofd_grant_rnb_size(struct obd_export *exp,
				     struct ofd_device *ofd,
				     struct niobuf_remote *rnb)
{
	u64 blocksize;
	u64 bytes;
	u64 end;

	if (exp && ofd_grant_compat(exp, ofd))
		blocksize = 1ULL << COMPAT_BSIZE_SHIFT;
	else
		blocksize = 1ULL << ofd->ofd_blockbits;

	/* The network buffer might span several blocks, align it on block
	 * boundaries */
	bytes  = rnb->rnb_offset & (blocksize - 1);
	bytes += rnb->rnb_len;
	end    = bytes & (blocksize - 1);
	if (end)
		bytes += blocksize - end;
	if (exp)
		/* Apply per-export pecularities if one is given */
		bytes = ofd_grant_from_cli(exp, ofd, bytes);
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
 * this flag will fail to be written with -ENOSPC (see ofd_preprw_write().
 * Caller must hold ofd_grant_lock spinlock.
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
static void ofd_grant_check(const struct lu_env *env, struct obd_export *exp,
			    struct obdo *oa, struct niobuf_remote *rnb,
			    int niocount, u64 *left)
{
	struct filter_export_data	*fed = &exp->exp_filter_data;
	struct obd_device		*obd = exp->exp_obd;
	struct ofd_device		*ofd = ofd_exp(exp);
	unsigned long			 ungranted = 0;
	unsigned long			 granted = 0;
	int				 i;
	int				 resend = 0;
	struct ofd_thread_info		*info = ofd_info(env);

	ENTRY;

	assert_spin_locked(&ofd->ofd_grant_lock);

	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_RECOV_RESEND)) {
		resend = 1;
		CDEBUG(D_CACHE, "Recoverable resend arrived, skipping "
				"accounting\n");
	}

	for (i = 0; i < niocount; i++) {
		int bytes;

		if (obd->obd_recovering) {
			/* Replaying write. Grant info have been processed
			 * already so no need to do any enforcement here.
			 * It is worth noting that only bulk writes with all
			 * rnbs having OBD_BRW_FROM_GRANT can be replayed.
			 * If one page hasn't OBD_BRW_FROM_GRANT set, then
			 * the whole bulk is written synchronously */
			if (rnb[i].rnb_flags & OBD_BRW_FROM_GRANT) {
				 rnb[i].rnb_flags |= OBD_BRW_GRANTED;
				 continue;
			} else {
				CERROR("%s: cli %s is replaying OST_WRITE "
				       "while one rnb hasn't OBD_BRW_FROM_GRANT"
				       " set (0x%x)\n", exp->exp_obd->obd_name,
					exp->exp_client_uuid.uuid,
					rnb[i].rnb_flags);

			}
		} else if ((oa->o_valid & OBD_MD_FLGRANT) &&
			   (rnb[i].rnb_flags & OBD_BRW_FROM_GRANT)) {
			if (resend) {
				/* This is a recoverable resend so grant
				 * information have already been processed */
				rnb[i].rnb_flags |= OBD_BRW_GRANTED;
				continue;
			}

			/* inflate consumed space if needed */
			bytes = ofd_grant_rnb_size(exp, ofd, &rnb[i]);
			if (fed->fed_grant < granted + bytes) {
				CDEBUG(D_CACHE, "%s: cli %s/%p claims %ld+%d "
				       "GRANT, real grant %lu idx %d\n",
				       exp->exp_obd->obd_name,
				       exp->exp_client_uuid.uuid, exp,
				       granted, bytes, fed->fed_grant, i);
			} else {
				granted += bytes;
				rnb[i].rnb_flags |= OBD_BRW_GRANTED;
				continue;
			}
		}

		/* Consume grant space on the server.
		 * Unlike above, ofd_grant_rnb_size() is called with exp = NULL
		 * so that the required grant space isn't inflated. This is
		 * done on purpose since the server can deal with large block
		 * size, unlike some clients */
		bytes = ofd_grant_rnb_size(NULL, ofd, &rnb[i]);
		if (*left > ungranted + bytes) {
			/* if enough space, pretend it was granted */
			ungranted += bytes;
			rnb[i].rnb_flags |= OBD_BRW_GRANTED;
			continue;
		}

		/* We can't check for already-mapped blocks here (make sense
		 * when backend filesystem does not use COW) as it requires
		 * dropping the grant lock.
		 * Instead, we clear ~OBD_BRW_GRANTED and in that case we need
		 * to go through and verify if all of the blocks not marked
		 *  BRW_GRANTED are already mapped and we can ignore this error.
		 */
		rnb[i].rnb_flags &= ~OBD_BRW_GRANTED;
		CDEBUG(D_CACHE,"%s: cli %s/%p idx %d no space for %d\n",
				exp->exp_obd->obd_name,
				exp->exp_client_uuid.uuid, exp, i, bytes);
	}

	/* record space used for the I/O, will be used in ofd_grant_commmit() */
	/* Now substract what the clients has used already.  We don't subtract
	 * this from the tot_granted yet, so that other client's can't grab
	 * that space before we have actually allocated our blocks. That
	 * happens in ofd_grant_commit() after the writes are done. */
	info->fti_used = granted + ungranted;
	*left -= ungranted;
	fed->fed_grant -= granted;
	fed->fed_pending += info->fti_used;
	ofd->ofd_tot_granted += ungranted;
	ofd->ofd_tot_pending += info->fti_used;

	CDEBUG(D_CACHE,
	       "%s: cli %s/%p granted: %lu ungranted: %lu grant: %lu dirty: %lu"
	       "\n", obd->obd_name, exp->exp_client_uuid.uuid, exp,
	       granted, ungranted, fed->fed_grant, fed->fed_dirty);

	if (obd->obd_recovering)
		/* don't update dirty accounting during recovery */
		RETURN_EXIT;

	if (fed->fed_dirty < granted) {
		CWARN("%s: cli %s/%p claims granted %lu > fed_dirty %lu\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       granted, fed->fed_dirty);
		granted = fed->fed_dirty;
	}
	ofd->ofd_tot_dirty -= granted;
	fed->fed_dirty -= granted;

	if (fed->fed_dirty < 0 || fed->fed_grant < 0 || fed->fed_pending < 0) {
		CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       fed->fed_dirty, fed->fed_pending, fed->fed_grant);
		spin_unlock(&ofd->ofd_grant_lock);
		LBUG();
	}
	EXIT;
}

/**
 * Allocate additional grant space to a client
 *
 * Calculate how much grant space to return to client, based on how much space
 * is currently free and how much of that is already granted.
 * Caller must hold ofd_grant_lock spinlock.
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
static long ofd_grant_alloc(struct obd_export *exp, u64 curgrant,
			    u64 want, u64 left, bool conservative)
{
	struct obd_device		*obd = exp->exp_obd;
	struct ofd_device		*ofd = ofd_exp(exp);
	struct filter_export_data	*fed = &exp->exp_filter_data;
	long				 grant_chunk;
	u64				 grant;

	ENTRY;

	if (ofd_grant_prohibit(exp, ofd) || left == 0 || exp->exp_failed)
		RETURN(0);

	if (want > 0x7fffffff) {
		CERROR("%s: client %s/%p requesting > 2GB grant "LPU64"\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp, want);
		RETURN(0);
	}

	/* client not supporting OBD_CONNECT_GRANT_PARAM works with a 4KB block
	 * size while the reality is different */
	curgrant = ofd_grant_from_cli(exp, ofd, curgrant);
	want = ofd_grant_from_cli(exp, ofd, want);
	grant_chunk = ofd_grant_chunk(exp, ofd);

	/* Grant some fraction of the client's requested grant space so that
	 * they are not always waiting for write credits (not all of it to
	 * avoid overgranting in face of multiple RPCs in flight).  This
	 * essentially will be able to control the OSC_MAX_RIF for a client.
	 *
	 * If we do have a large disparity between what the client thinks it
	 * has and what we think it has, don't grant very much and let the
	 * client consume its grant first.  Either it just has lots of RPCs
	 * in flight, or it was evicted and its grants will soon be used up. */
	if (curgrant >= want || curgrant >= fed->fed_grant + grant_chunk)
		   RETURN(0);

	if (obd->obd_recovering)
		conservative = false;

	if (conservative)
		/* don't grant more than 1/8th of the remaining free space in
		 * one chunk */
		left >>= 3;
	grant = min(want, left);
	/* round grant upt to the next block size */
	grant = (grant + (1 << ofd->ofd_blockbits) - 1) &
		~((1ULL << ofd->ofd_blockbits) - 1);

	if (!grant)
		RETURN(0);

	/* Limit to ofd_grant_chunk() if not reconnect/recovery */
	if ((grant > grant_chunk) && conservative)
		grant = grant_chunk;

	ofd->ofd_tot_granted += grant;
	fed->fed_grant += grant;

	if (fed->fed_grant < 0) {
		CERROR("%s: cli %s/%p grant %ld want "LPU64" current "LPU64"\n",
		       obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       fed->fed_grant, want, curgrant);
		spin_unlock(&ofd->ofd_grant_lock);
		LBUG();
	}

	CDEBUG(D_CACHE,
	       "%s: cli %s/%p wants: "LPU64" current grant "LPU64
	       " granting: "LPU64"\n", obd->obd_name, exp->exp_client_uuid.uuid,
	       exp, want, curgrant, grant);
	CDEBUG(D_CACHE,
	       "%s: cli %s/%p tot cached:"LPU64" granted:"LPU64
	       " num_exports: %d\n", obd->obd_name, exp->exp_client_uuid.uuid,
	       exp, ofd->ofd_tot_dirty, ofd->ofd_tot_granted,
	       obd->obd_num_exports);

	RETURN(ofd_grant_to_cli(exp, ofd, grant));
}

/**
 * Handle grant space allocation on client connection & reconnection.
 *
 * A new non-readonly connection gets an initial grant allocation equals to
 * ofd_grant_chunk() (i.e. twice the max BRW size in most of the cases).
 * On reconnection, grant counters between client & OST are resynchronized
 * and additional space might be granted back if possible.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] exp	client's export which is (re)connecting
 * \param[in] want	how much grant space the client would like to get
 * \param[in] new_conn	must set to true if this is a new connection and false
 *			for a reconnection
 *
 * \retval		amount of grant space currently owned by the client
 */
long ofd_grant_connect(const struct lu_env *env, struct obd_export *exp,
		       u64 want, bool new_conn)
{
	struct ofd_device		*ofd = ofd_exp(exp);
	struct filter_export_data	*fed = &exp->exp_filter_data;
	u64				 left = 0;
	long				 grant;
	int				 from_cache;
	int				 force = 0; /* can use cached data */

	/* don't grant space to client with read-only access */
	if ((exp_connect_flags(exp) & OBD_CONNECT_RDONLY) ||
	    ofd_grant_prohibit(exp, ofd))
		return 0;

refresh:
	ofd_grant_statfs(env, exp, force, &from_cache);

	spin_lock(&ofd->ofd_grant_lock);

	/* Grab free space from cached info and take out space already granted
	 * to clients as well as reserved space */
	left = ofd_grant_space_left(exp);

	/* get fresh statfs data if we are short in ungranted space */
	if (from_cache && left < 32 * ofd_grant_chunk(exp, ofd)) {
		spin_unlock(&ofd->ofd_grant_lock);
		CDEBUG(D_CACHE, "fs has no space left and statfs too old\n");
		force = 1;
		goto refresh;
	}

	ofd_grant_alloc(exp,
			ofd_grant_to_cli(exp, ofd, (u64)fed->fed_grant),
			want, left, new_conn);

	/* return to client its current grant */
	grant = ofd_grant_to_cli(exp, ofd, (u64)fed->fed_grant);
	ofd->ofd_tot_granted_clients++;

	spin_unlock(&ofd->ofd_grant_lock);

	CDEBUG(D_CACHE, "%s: cli %s/%p ocd_grant: %ld want: "LPU64" left: "
	       LPU64"\n", exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
	       exp, grant, want, left);

	return grant;
}

/**
 * Release all grant space attached to a given export.
 *
 * Remove a client from the grant accounting totals.  We also remove
 * the export from the obd device under the osfs and dev locks to ensure
 * that the ofd_grant_sanity_check() calculations are always valid.
 * The client should do something similar when it invalidates its import.
 *
 * \param[in] exp	client's export to remove from grant accounting
 */
void ofd_grant_discard(struct obd_export *exp)
{
	struct obd_device		*obd = exp->exp_obd;
	struct ofd_device		*ofd = ofd_exp(exp);
	struct filter_export_data	*fed = &exp->exp_filter_data;

	spin_lock(&ofd->ofd_grant_lock);
	LASSERTF(ofd->ofd_tot_granted >= fed->fed_grant,
		 "%s: tot_granted "LPU64" cli %s/%p fed_grant %ld\n",
		 obd->obd_name, ofd->ofd_tot_granted,
		 exp->exp_client_uuid.uuid, exp, fed->fed_grant);
	ofd->ofd_tot_granted -= fed->fed_grant;
	fed->fed_grant = 0;
	LASSERTF(ofd->ofd_tot_pending >= fed->fed_pending,
		 "%s: tot_pending "LPU64" cli %s/%p fed_pending %ld\n",
		 obd->obd_name, ofd->ofd_tot_pending,
		 exp->exp_client_uuid.uuid, exp, fed->fed_pending);
	/* ofd_tot_pending is handled in ofd_grant_commit as bulk
	 * finishes */
	LASSERTF(ofd->ofd_tot_dirty >= fed->fed_dirty,
		 "%s: tot_dirty "LPU64" cli %s/%p fed_dirty %ld\n",
		 obd->obd_name, ofd->ofd_tot_dirty,
		 exp->exp_client_uuid.uuid, exp, fed->fed_dirty);
	ofd->ofd_tot_dirty -= fed->fed_dirty;
	fed->fed_dirty = 0;
	spin_unlock(&ofd->ofd_grant_lock);
}

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
void ofd_grant_prepare_read(const struct lu_env *env,
			    struct obd_export *exp, struct obdo *oa)
{
	struct ofd_device	*ofd = ofd_exp(exp);
	int			 do_shrink;
	u64			 left = 0;

	if (!oa)
		return;

	if ((oa->o_valid & OBD_MD_FLGRANT) == 0)
		/* The read request does not contain any grant
		 * information */
		return;

	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_SHRINK_GRANT)) {
		/* To process grant shrink request, we need to know how much
		 * available space remains on the backend filesystem.
		 * Shrink requests are not so common, we always get fresh
		 * statfs information. */
		ofd_grant_statfs(env, exp, 1, NULL);

		/* protect all grant counters */
		spin_lock(&ofd->ofd_grant_lock);

		/* Grab free space from cached statfs data and take out space
		 * already granted to clients as well as reserved space */
		left = ofd_grant_space_left(exp);

		/* all set now to proceed with shrinking */
		do_shrink = 1;
	} else {
		/* no grant shrinking request packed in the obdo and
		 * since we don't grant space back on reads, no point
		 * in running statfs, so just skip it and process
		 * incoming grant data directly. */
		spin_lock(&ofd->ofd_grant_lock);
		do_shrink = 0;
	}

	/* extract incoming grant infomation provided by the client */
	ofd_grant_incoming(env, exp, oa);

	/* unlike writes, we don't return grants back on reads unless a grant
	 * shrink request was packed and we decided to turn it down. */
	if (do_shrink)
		ofd_grant_shrink(exp, oa, left);
	else
		oa->o_grant = 0;

	spin_unlock(&ofd->ofd_grant_lock);
}

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
 * ofd_grant_prepare_write() must be called before writting any buffers to
 * the backend storage. This function works in pair with ofd_grant_commit()
 * which must be invoked once all buffers have been written to disk in order
 * to release space from the pending grant counter.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] exp	export of the client which sent the request
 * \param[in] oa	incoming obdo sent by the client
 * \param[in] rnb	list of network buffers
 * \param[in] niocount	number of network buffers in the list
 */
void ofd_grant_prepare_write(const struct lu_env *env,
			     struct obd_export *exp, struct obdo *oa,
			     struct niobuf_remote *rnb, int niocount)
{
	struct obd_device	*obd = exp->exp_obd;
	struct ofd_device	*ofd = ofd_exp(exp);
	u64			 left;
	int			 from_cache;
	int			 force = 0; /* can use cached data intially */
	int			 rc;

	ENTRY;

refresh:
	/* get statfs information from OSD layer */
	ofd_grant_statfs(env, exp, force, &from_cache);

	spin_lock(&ofd->ofd_grant_lock); /* protect all grant counters */

	/* Grab free space from cached statfs data and take out space already
	 * granted to clients as well as reserved space */
	left = ofd_grant_space_left(exp);

	/* Get fresh statfs data if we are short in ungranted space */
	if (from_cache && left < 32 * ofd_grant_chunk(exp, ofd)) {
		spin_unlock(&ofd->ofd_grant_lock);
		CDEBUG(D_CACHE, "%s: fs has no space left and statfs too old\n",
		       obd->obd_name);
		force = 1;
		goto refresh;
	}

	/* When close to free space exhaustion, trigger a sync to force
	 * writeback cache to consume required space immediately and release as
	 * much space as possible. */
	if (!obd->obd_recovering && force != 2 && left < OFD_GRANT_CHUNK) {
		bool from_grant = true;
		int  i;

		/* That said, it is worth running a sync only if some pages did
		 * not consume grant space on the client and could thus fail
		 * with ENOSPC later in ofd_grant_check() */
		for (i = 0; i < niocount; i++)
			if (!(rnb[i].rnb_flags & OBD_BRW_FROM_GRANT))
				from_grant = false;

		if (!from_grant) {
			/* at least one network buffer requires acquiring grant
			 * space on the server */
			spin_unlock(&ofd->ofd_grant_lock);
			/* discard errors, at least we tried ... */
			rc = dt_sync(env, ofd->ofd_osd);
			force = 2;
			goto refresh;
		}
	}

	/* extract incoming grant information provided by the client */
	ofd_grant_incoming(env, exp, oa);

	/* check limit */
	ofd_grant_check(env, exp, oa, rnb, niocount, &left);

	if (!(oa->o_valid & OBD_MD_FLGRANT)) {
		spin_unlock(&ofd->ofd_grant_lock);
		RETURN_EXIT;
	}

	/* if OBD_FL_SHRINK_GRANT is set, the client is willing to release some
	 * grant space. */
	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    (oa->o_flags & OBD_FL_SHRINK_GRANT))
		ofd_grant_shrink(exp, oa, left);
	else
		/* grant more space back to the client if possible */
		oa->o_grant = ofd_grant_alloc(exp, oa->o_grant, oa->o_undirty,
					      left, true);
	spin_unlock(&ofd->ofd_grant_lock);
}

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
 * \retval 0		for success
 * \retval -ENOSPC	on failure
 */
int ofd_grant_create(const struct lu_env *env, struct obd_export *exp, int *nr)
{
	struct ofd_thread_info		*info = ofd_info(env);
	struct ofd_device		*ofd = ofd_exp(exp);
	struct filter_export_data	*fed = &exp->exp_filter_data;
	u64				 left = 0;
	unsigned long			 wanted;
	ENTRY;

	info->fti_used = 0;

	if (exp->exp_obd->obd_recovering ||
	    ofd->ofd_dt_conf.ddp_inodespace == 0)
		/* don't enforce grant during recovery */
		RETURN(0);

	/* Update statfs data if required */
	ofd_grant_statfs(env, exp, 1, NULL);

	/* protect all grant counters */
	spin_lock(&ofd->ofd_grant_lock);

	/* fail precreate request if there is not enough blocks available for
	 * writing */
	if (ofd->ofd_osfs.os_bavail - (fed->fed_grant >> ofd->ofd_blockbits) <
	    (ofd->ofd_osfs.os_blocks >> 10)) {
		spin_unlock(&ofd->ofd_grant_lock);
		CDEBUG(D_RPCTRACE, "%s: not enough space for create "LPU64"\n",
		       ofd_name(ofd),
		       ofd->ofd_osfs.os_bavail * ofd->ofd_osfs.os_blocks);
		RETURN(-ENOSPC);
	}

	/* Grab free space from cached statfs data and take out space
	 * already granted to clients as well as reserved space */
	left = ofd_grant_space_left(exp);

	/* compute how much space is required to handle the precreation
	 * request */
	wanted = *nr * ofd->ofd_dt_conf.ddp_inodespace;
	if (wanted > fed->fed_grant + left) {
		/* that's beyond what remains, adjust the number of objects that
		 * can be safely precreated */
		wanted = fed->fed_grant + left;
		*nr = wanted / ofd->ofd_dt_conf.ddp_inodespace;
		if (*nr == 0) {
			/* we really have no space any more for precreation,
			 * fail the precreate request with ENOSPC */
			spin_unlock(&ofd->ofd_grant_lock);
			RETURN(-ENOSPC);
		}
		/* compute space needed for the new number of creations */
		wanted = *nr * ofd->ofd_dt_conf.ddp_inodespace;
	}
	LASSERT(wanted <= fed->fed_grant + left);

	if (wanted <= fed->fed_grant) {
		/* we've enough grant space to handle this precreate request */
		fed->fed_grant -= wanted;
	} else {
		/* we need to take some space from the ungranted pool */
		ofd->ofd_tot_granted += wanted - fed->fed_grant;
		left -= wanted - fed->fed_grant;
		fed->fed_grant = 0;
	}
	info->fti_used = wanted;
	fed->fed_pending += info->fti_used;
	ofd->ofd_tot_pending += info->fti_used;

	/* grant more space for precreate purpose if possible. */
	wanted = OST_MAX_PRECREATE * ofd->ofd_dt_conf.ddp_inodespace / 2;
	if (wanted > fed->fed_grant) {
		/* always try to book enough space to handle a large precreate
		 * request */
		wanted -= fed->fed_grant;
		ofd_grant_alloc(exp, fed->fed_grant, wanted, left, false);
	}
	spin_unlock(&ofd->ofd_grant_lock);
	RETURN(0);
}

/**
 * Release grant space added to the pending counter by ofd_grant_prepare_write()
 *
 * Update pending grant counter once buffers have been written to the disk.
 *
 * \param[in] env	LU environment provided by the caller
 * \param[in] exp	export of the client which sent the request
 * \param[in] rc	return code of pre-commit operations
 */
void ofd_grant_commit(const struct lu_env *env, struct obd_export *exp,
		      int rc)
{
	struct ofd_device	*ofd  = ofd_exp(exp);
	struct ofd_thread_info	*info = ofd_info(env);
	unsigned long		 pending;

	ENTRY;

	/* get space accounted in tot_pending for the I/O, set in
	 * ofd_grant_check() */
	pending = info->fti_used;
	if (pending == 0)
		RETURN_EXIT;

	spin_lock(&ofd->ofd_grant_lock);
	/* Don't update statfs data for errors raised before commit (e.g.
	 * bulk transfer failed, ...) since we know those writes have not been
	 * processed. For other errors hit during commit, we cannot really tell
	 * whether or not something was written, so we update statfs data.
	 * In any case, this should not be fatal since we always get fresh
	 * statfs data before failing a request with ENOSPC */
	if (rc == 0) {
		spin_lock(&ofd->ofd_osfs_lock);
		/* Take pending out of cached statfs data */
		ofd->ofd_osfs.os_bavail -= min_t(u64,
						 ofd->ofd_osfs.os_bavail,
						 pending >> ofd->ofd_blockbits);
		if (ofd->ofd_statfs_inflight)
			/* someone is running statfs and want to be notified of
			 * writes happening meanwhile */
			ofd->ofd_osfs_inflight += pending;
		spin_unlock(&ofd->ofd_osfs_lock);
	}

	if (exp->exp_filter_data.fed_pending < pending) {
		CERROR("%s: cli %s/%p fed_pending(%lu) < grant_used(%lu)\n",
		       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
		       exp->exp_filter_data.fed_pending, pending);
		spin_unlock(&ofd->ofd_grant_lock);
		LBUG();
	}
	exp->exp_filter_data.fed_pending -= pending;

	if (ofd->ofd_tot_granted < pending) {
		 CERROR("%s: cli %s/%p tot_granted("LPU64") < grant_used(%lu)"
			"\n", exp->exp_obd->obd_name,
			exp->exp_client_uuid.uuid, exp, ofd->ofd_tot_granted,
			pending);
		spin_unlock(&ofd->ofd_grant_lock);
		LBUG();
	}
	ofd->ofd_tot_granted -= pending;

	if (ofd->ofd_tot_pending < pending) {
		 CERROR("%s: cli %s/%p tot_pending("LPU64") < grant_used(%lu)"
			"\n", exp->exp_obd->obd_name, exp->exp_client_uuid.uuid,
			exp, ofd->ofd_tot_pending, pending);
		spin_unlock(&ofd->ofd_grant_lock);
		LBUG();
	}
	ofd->ofd_tot_pending -= pending;
	spin_unlock(&ofd->ofd_grant_lock);
	EXIT;
}
