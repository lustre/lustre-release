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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdfilter/filter_io.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/module.h>
#include <linux/pagemap.h> // XXX kill me soon
#include <linux/version.h>

#include <obd_class.h>
#include <obd_ost.h>
#include <lustre_fsfilt.h>
#include "filter_internal.h"

int *obdfilter_created_scratchpad;

/* Grab the dirty and seen grant announcements from the incoming obdo.
 * We will later calculate the clients new grant and return it.
 * Caller must hold osfs lock */
void filter_grant_incoming(struct obd_export *exp, struct obdo *oa)
{
        struct filter_export_data *fed;
        struct obd_device *obd = exp->exp_obd;
        ENTRY;

        LASSERT_SPIN_LOCKED(&obd->obd_osfs_lock);

        if ((oa->o_valid & (OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) !=
                                        (OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) {
                oa->o_valid &= ~OBD_MD_FLGRANT;
                EXIT;
                return;
        }

        fed = &exp->exp_filter_data;

        /* Add some margin, since there is a small race if other RPCs arrive
         * out-or-order and have already consumed some grant.  We want to
         * leave this here in case there is a large error in accounting. */
        CDEBUG(D_CACHE,
               "%s: cli %s/%p reports grant: "LPU64" dropped: %u, local: %lu\n",
               obd->obd_name, exp->exp_client_uuid.uuid, exp, oa->o_grant,
               oa->o_dropped, fed->fed_grant);

        /* Update our accounting now so that statfs takes it into account.
         * Note that fed_dirty is only approximate and can become incorrect
         * if RPCs arrive out-of-order.  No important calculations depend
         * on fed_dirty however, but we must check sanity to not assert. */
        if ((long long)oa->o_dirty < 0)
                oa->o_dirty = 0;
        else if (oa->o_dirty > fed->fed_grant + 4 * FILTER_GRANT_CHUNK)
                oa->o_dirty = fed->fed_grant + 4 * FILTER_GRANT_CHUNK;
        obd->u.filter.fo_tot_dirty += oa->o_dirty - fed->fed_dirty;
        if (fed->fed_grant < oa->o_dropped) {
                CDEBUG(D_CACHE,"%s: cli %s/%p reports %u dropped > grant %lu\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       oa->o_dropped, fed->fed_grant);
                oa->o_dropped = 0;
        }
        if (obd->u.filter.fo_tot_granted < oa->o_dropped) {
                CERROR("%s: cli %s/%p reports %u dropped > tot_grant "LPU64"\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       oa->o_dropped, obd->u.filter.fo_tot_granted);
                oa->o_dropped = 0;
        }
        obd->u.filter.fo_tot_granted -= oa->o_dropped;
        fed->fed_grant -= oa->o_dropped;
        fed->fed_dirty = oa->o_dirty;

        if (oa->o_valid & OBD_MD_FLFLAGS && oa->o_flags & OBD_FL_SHRINK_GRANT) {
                obd_size left_space = filter_grant_space_left(exp);
                struct filter_obd *filter = &exp->exp_obd->u.filter;

                /*Only if left_space < fo_tot_clients * 32M,
                 *then the grant space could be shrinked */
                if (left_space < filter->fo_tot_granted_clients *
                                 FILTER_GRANT_SHRINK_LIMIT) {
                        fed->fed_grant -= oa->o_grant;
                        filter->fo_tot_granted -= oa->o_grant;
                        CDEBUG(D_CACHE, "%s: cli %s/%p shrink "LPU64
                               "fed_grant %ld total "LPU64"\n",
                               obd->obd_name, exp->exp_client_uuid.uuid,
                               exp, oa->o_grant, fed->fed_grant,
                               filter->fo_tot_granted);
                        oa->o_grant = 0;
                }
        }

        if (fed->fed_dirty < 0 || fed->fed_grant < 0 || fed->fed_pending < 0) {
                CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       fed->fed_dirty, fed->fed_pending, fed->fed_grant);
                cfs_spin_unlock(&obd->obd_osfs_lock);
                LBUG();
        }
        EXIT;
}

/* Figure out how much space is available between what we've granted
 * and what remains in the filesystem.  Compensate for ext3 indirect
 * block overhead when computing how much free space is left ungranted.
 *
 * Caller must hold obd_osfs_lock. */
obd_size filter_grant_space_left(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        int blockbits = obd->u.obt.obt_sb->s_blocksize_bits;
        obd_size tot_granted = obd->u.filter.fo_tot_granted, avail, left = 0;
        int rc, statfs_done = 0;

        LASSERT_SPIN_LOCKED(&obd->obd_osfs_lock);

        if (cfs_time_before_64(obd->obd_osfs_age,
                               cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS))) {
restat:
                rc = fsfilt_statfs(obd, obd->u.obt.obt_sb,
                                   cfs_time_shift_64(OBD_STATFS_CACHE_SECONDS));
                if (rc) /* N.B. statfs can't really fail */
                        RETURN(0);
                statfs_done = 1;
        }

        avail = obd->obd_osfs.os_bavail;
        left = avail - (avail >> (blockbits - 3)); /* (d)indirect */
        if (left > GRANT_FOR_LLOG(obd)) {
                left = (left - GRANT_FOR_LLOG(obd)) << blockbits;
        } else {
                left = 0 /* << blockbits */;
        }

        if (!statfs_done && left < 32 * FILTER_GRANT_CHUNK + tot_granted) {
                CDEBUG(D_CACHE, "fs has no space left and statfs too old\n");
                goto restat;
        }

        if (left >= tot_granted) {
                left -= tot_granted;
        } else {
                if (left < tot_granted - obd->u.filter.fo_tot_pending) {
                        CERROR("%s: cli %s/%p grant "LPU64" > available "
                               LPU64" and pending "LPU64"\n", obd->obd_name,
                               exp->exp_client_uuid.uuid, exp, tot_granted,
                               left, obd->u.filter.fo_tot_pending);
                }
                left = 0;
        }

        CDEBUG(D_CACHE, "%s: cli %s/%p free: "LPU64" avail: "LPU64" grant "LPU64
               " left: "LPU64" pending: "LPU64"\n", obd->obd_name,
               exp->exp_client_uuid.uuid, exp,
               obd->obd_osfs.os_bfree << blockbits, avail << blockbits,
               tot_granted, left, obd->u.filter.fo_tot_pending);

        return left;
}

/* Calculate how much grant space to allocate to this client, based on how
 * much space is currently free and how much of that is already granted.
 *
 * if @conservative != 0, we limit the maximum grant to FILTER_GRANT_CHUNK;
 * otherwise we'll satisfy the requested amount as possible as we can, this
 * is usually due to client reconnect.
 *
 * Caller must hold obd_osfs_lock. */
long filter_grant(struct obd_export *exp, obd_size current_grant,
                  obd_size want, obd_size fs_space_left, int conservative)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_export_data *fed = &exp->exp_filter_data;
        int blockbits = obd->u.obt.obt_sb->s_blocksize_bits;
        __u64 grant = 0;

        LASSERT_SPIN_LOCKED(&obd->obd_osfs_lock);

        /* Grant some fraction of the client's requested grant space so that
         * they are not always waiting for write credits (not all of it to
         * avoid overgranting in face of multiple RPCs in flight).  This
         * essentially will be able to control the OSC_MAX_RIF for a client.
         *
         * If we do have a large disparity between what the client thinks it
         * has and what we think it has, don't grant very much and let the
         * client consume its grant first.  Either it just has lots of RPCs
         * in flight, or it was evicted and its grants will soon be used up. */
        if (want > 0x7fffffff) {
                CERROR("%s: client %s/%p requesting > 2GB grant "LPU64"\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp, want);
        } else if (current_grant < want &&
                   current_grant < fed->fed_grant + FILTER_GRANT_CHUNK) {
                grant = min(want + (1 << blockbits) - 1, fs_space_left / 8);
                grant &= ~((1ULL << blockbits) - 1);

                if (grant) {
                        if (grant > FILTER_GRANT_CHUNK && conservative)
                                grant = FILTER_GRANT_CHUNK;

                        obd->u.filter.fo_tot_granted += grant;
                        fed->fed_grant += grant;
                        if (fed->fed_grant < 0) {
                                CERROR("%s: cli %s/%p grant %ld want "LPU64
                                       "current"LPU64"\n",
                                       obd->obd_name, exp->exp_client_uuid.uuid,
                                       exp, fed->fed_grant, want,current_grant);
                                cfs_spin_unlock(&obd->obd_osfs_lock);
                                LBUG();
                        }
                }
        }

        CDEBUG(D_CACHE,
               "%s: cli %s/%p wants: "LPU64" current grant "LPU64
               " granting: "LPU64"\n", obd->obd_name, exp->exp_client_uuid.uuid,
               exp, want, current_grant, grant);
        CDEBUG(D_CACHE,
               "%s: cli %s/%p tot cached:"LPU64" granted:"LPU64
               " num_exports: %d\n", obd->obd_name, exp->exp_client_uuid.uuid,
               exp, obd->u.filter.fo_tot_dirty,
               obd->u.filter.fo_tot_granted, obd->obd_num_exports);

        return grant;
}

/*
 * the routine is used to request pages from pagecache
 *
 * use GFP_NOFS for requests from a local client not allowing to enter FS
 * as we might end up waiting on a page he sent in the request we're serving.
 * use __GFP_HIGHMEM so that the pages can use all of the available memory
 * on 32-bit machines
 * use more aggressive GFP_HIGHUSER flags from non-local clients to be able to
 * generate more memory pressure.
 *
 * See Bug 19529 and Bug 19917 for details.
 */
static struct page *filter_get_page(struct obd_device *obd,
                                    struct inode *inode,
                                    obd_off offset,
                                    int localreq)
{
        struct page *page;

        page = find_or_create_page(inode->i_mapping, offset >> CFS_PAGE_SHIFT,
                                   (localreq ? (GFP_NOFS | __GFP_HIGHMEM)
                                             : GFP_HIGHUSER));
        if (unlikely(page == NULL))
                lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_NO_PAGE, 1);

        return page;
}

/*
 * the routine initializes array of local_niobuf from remote_niobuf
 */
static int filter_map_remote_to_local(int objcount, struct obd_ioobj *obj,
                                      struct niobuf_remote *nb,
                                      int *nrpages, struct niobuf_local *res)
{
        struct niobuf_remote *rnb;
        struct niobuf_local *lnb;
        int i, max;
        ENTRY;

        /* we don't support multiobject RPC yet
         * ost_brw_read() and ost_brw_write() check this */
        LASSERT(objcount == 1);

        max = *nrpages;
        *nrpages = 0;
        for (i = 0, rnb = nb, lnb = res; i < obj->ioo_bufcnt; i++, rnb++) {
                obd_off offset = rnb->offset;
                unsigned int len = rnb->len;

                while (len > 0) {
                        int poff = offset & (CFS_PAGE_SIZE - 1);
                        int plen = CFS_PAGE_SIZE - poff;

                        if (*nrpages >= max) {
                                CERROR("small array of local bufs: %d\n", max);
                                RETURN(-EINVAL);
                        }

                        if (plen > len)
                                plen = len;
			lnb->lnb_file_offset = offset;
			lnb->lnb_page_offset = poff;
                        lnb->len = plen;
                        lnb->flags = rnb->flags;
                        lnb->page = NULL;
                        lnb->rc = 0;
                        lnb->lnb_grant_used = 0;

                        LASSERTF(plen <= len, "plen %u, len %u\n", plen, len);
                        offset += plen;
                        len -= plen;
                        lnb++;
                        (*nrpages)++;
                }
        }
        RETURN(0);
}

/*
 * the invalidate above doesn't work during read because lnet pins pages.
 * The truncate is used here instead to drop pages from cache
 */
void filter_release_cache(struct obd_device *obd, struct obd_ioobj *obj,
                          struct niobuf_remote *rnb, struct inode *inode)
{
        int i;

        LASSERT(inode != NULL);
        for (i = 0; i < obj->ioo_bufcnt; i++, rnb++) {
                /* remove pages in which range is fit */
                truncate_inode_pages_range(inode->i_mapping,
                                           rnb->offset & CFS_PAGE_MASK,
                                           (rnb->offset + rnb->len - 1) |
                                           ~CFS_PAGE_MASK);
        }
}

static int filter_preprw_read(int cmd, struct obd_export *exp, struct obdo *oa,
                              int objcount, struct obd_ioobj *obj,
                              struct niobuf_remote *nb,
                              int *npages, struct niobuf_local *res,
                              struct obd_trans_info *oti,
                              struct lustre_capa *capa)
{
        struct obd_device *obd = exp->exp_obd;
        struct timeval start, end;
        struct lvfs_run_ctxt saved;
        struct niobuf_local *lnb;
        struct dentry *dentry = NULL;
        struct inode *inode = NULL;
        void *iobuf = NULL;
        int rc = 0, i, tot_bytes = 0;
        unsigned long now = jiffies;
        long timediff;
        loff_t isize;
        ENTRY;

        /* We are currently not supporting multi-obj BRW_READ RPCS at all.
         * When we do this function's dentry cleanup will need to be fixed.
         * These values are verified in ost_brw_write() from the wire. */
        LASSERTF(objcount == 1, "%d\n", objcount);
        LASSERTF(obj->ioo_bufcnt > 0, "%d\n", obj->ioo_bufcnt);

        rc = filter_auth_capa(exp, NULL, oa->o_seq, capa,
                              CAPA_OPC_OSS_READ);
        if (rc)
                RETURN(rc);

        if (oa && oa->o_valid & OBD_MD_FLGRANT) {
                cfs_spin_lock(&obd->obd_osfs_lock);
                filter_grant_incoming(exp, oa);

                if (!(oa->o_valid & OBD_MD_FLFLAGS) ||
                    !(oa->o_flags & OBD_FL_SHRINK_GRANT))
                        oa->o_grant = 0;
                cfs_spin_unlock(&obd->obd_osfs_lock);
        }

        iobuf = filter_iobuf_get(&obd->u.filter, oti);
        if (IS_ERR(iobuf))
                RETURN(PTR_ERR(iobuf));

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        dentry = filter_oa2dentry(obd, &oa->o_oi);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                dentry = NULL;
                GOTO(cleanup, rc);
        }

        inode = dentry->d_inode;
        isize = i_size_read(inode);

        obdo_to_inode(inode, oa, OBD_MD_FLATIME);

        rc = filter_map_remote_to_local(objcount, obj, nb, npages, res);
        if (rc)
                GOTO(cleanup, rc);

        fsfilt_check_slow(obd, now, "preprw_read setup");

        /* find pages for all segments, fill array with them */
        cfs_gettimeofday(&start);
        for (i = 0, lnb = res; i < *npages; i++, lnb++) {

                lnb->dentry = dentry;

		if (isize <= lnb->lnb_file_offset)
			/* If there's no more data, abort early.  lnb->rc == 0,
			 * so it's easy to detect later. */
			break;

		lnb->page = filter_get_page(obd, inode, lnb->lnb_file_offset,
					    0);
		if (lnb->page == NULL)
			GOTO(cleanup, rc = -ENOMEM);

		lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_CACHE_ACCESS, 1);

		if (isize < lnb->lnb_file_offset + lnb->len - 1)
			lnb->rc = isize - lnb->lnb_file_offset;
                else
                        lnb->rc = lnb->len;

                tot_bytes += lnb->rc;

                if (PageUptodate(lnb->page)) {
                        lprocfs_counter_add(obd->obd_stats,
                                            LPROC_FILTER_CACHE_HIT, 1);
                        continue;
                }

                lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_CACHE_MISS, 1);
                filter_iobuf_add_page(obd, iobuf, inode, lnb->page);
        }
        cfs_gettimeofday(&end);
        timediff = cfs_timeval_sub(&end, &start, NULL);
        lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_GET_PAGE, timediff);

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_NOMEM))
                GOTO(cleanup, rc = -ENOMEM);

        fsfilt_check_slow(obd, now, "start_page_read");

        rc = filter_direct_io(OBD_BRW_READ, dentry, iobuf,
                              exp, NULL, NULL, NULL);
        if (rc)
                GOTO(cleanup, rc);

        lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_READ_BYTES, tot_bytes);

        if (exp->exp_nid_stats && exp->exp_nid_stats->nid_stats)
                lprocfs_counter_add(exp->exp_nid_stats->nid_stats,
                                    LPROC_FILTER_READ_BYTES, tot_bytes);
	filter_counter_incr(exp, LPROC_FILTER_STATS_READ,
			    oti ? oti->oti_jobid : NULL, tot_bytes);
        EXIT;

 cleanup:
        /* unlock pages to allow access from concurrent OST_READ */
        for (i = 0, lnb = res; i < *npages; i++, lnb++) {
                if (lnb->page) {
                        LASSERT(PageLocked(lnb->page));
                        unlock_page(lnb->page);

                        if (rc) {
                                page_cache_release(lnb->page);
                                lnb->page = NULL;
                        }
                }
        }

        if (rc != 0) {
                if (dentry != NULL)
                        f_dput(dentry);
        }

        filter_iobuf_put(&obd->u.filter, iobuf, oti);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (rc)
                CERROR("io error %d\n", rc);

        return rc;
}

/* When clients have dirtied as much space as they've been granted they
 * fall through to sync writes.  These sync writes haven't been expressed
 * in grants and need to error with ENOSPC when there isn't room in the
 * filesystem for them after grants are taken into account.  However,
 * writeback of the dirty data that was already granted space can write
 * right on through.
 *
 * Caller must hold obd_osfs_lock. */
static int filter_grant_check(struct obd_export *exp, struct obdo *oa,
                              int objcount, struct fsfilt_objinfo *fso,
                              int niocount, struct niobuf_local *lnb,
                              obd_size *left, struct inode *inode)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        int blocksize = exp->exp_obd->u.obt.obt_sb->s_blocksize;
        unsigned long used = 0, ungranted = 0, using;
        int i, rc = -ENOSPC, obj, n = 0;
        int resend = 0;

        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            (oa->o_flags & OBD_FL_RECOV_RESEND)) {
                resend = 1;
                CDEBUG(D_CACHE, "Recoverable resend arrived, skipping "
                       "accounting\n");
        }

        LASSERT_SPIN_LOCKED(&exp->exp_obd->obd_osfs_lock);

        for (obj = 0; obj < objcount; obj++) {
                for (i = 0; i < fso[obj].fso_bufcnt; i++, n++) {
                        int tmp, bytes;

                        /* should match the code in osc_exit_cache */
                        bytes = lnb[n].len;
			bytes += lnb[n].lnb_file_offset & (blocksize - 1);
			tmp = (lnb[n].lnb_file_offset + lnb[n].len) &
			      (blocksize - 1);
                        if (tmp)
                                bytes += blocksize - tmp;

			lnb[n].rc = 0;
                        if ((lnb[n].flags & OBD_BRW_FROM_GRANT) &&
                            (oa->o_valid & OBD_MD_FLGRANT)) {
                                if (resend) {
                                        /* this is a recoverable resent */
                                        lnb[n].flags |= OBD_BRW_GRANTED;
                                        rc = 0;
                                        continue;
                                } else if (fed->fed_grant < used + bytes) {
                                        CDEBUG(D_CACHE,
                                               "%s: cli %s/%p claims %ld+%d "
                                               "GRANT, real grant %lu idx %d\n",
                                               exp->exp_obd->obd_name,
                                               exp->exp_client_uuid.uuid, exp,
                                               used, bytes, fed->fed_grant, n);
                                } else {
                                        used += bytes;
                                        lnb[n].flags |= OBD_BRW_GRANTED;
                                        lnb[n].lnb_grant_used = bytes;
                                        CDEBUG(0, "idx %d used=%lu\n", n, used);
                                        rc = 0;
                                        continue;
                                }
                        }
                        if (*left > ungranted + bytes) {
                                /* if enough space, pretend it was granted */
                                ungranted += bytes;
                                lnb[n].flags |= OBD_BRW_GRANTED;
                                lnb[n].lnb_grant_used = bytes;
                                CDEBUG(0, "idx %d ungranted=%lu\n",n,ungranted);
                                rc = 0;
                                continue;
                        }

                        /* We can't check for already-mapped blocks here, as
                         * it requires dropping the osfs lock to do the bmap.
                         * Instead, we return ENOSPC and in that case we need
                         * to go through and verify if all of the blocks not
                         * marked BRW_GRANTED are already mapped and we can
                         * ignore this error. */
                        lnb[n].rc = -ENOSPC;
                        lnb[n].flags &= ~OBD_BRW_GRANTED;
                        CDEBUG(D_CACHE,"%s: cli %s/%p idx %d no space for %d\n",
                               exp->exp_obd->obd_name,
                               exp->exp_client_uuid.uuid, exp, n, bytes);
                }
        }

        /* Now substract what client have used already.  We don't subtract
         * this from the tot_granted yet, so that other client's can't grab
         * that space before we have actually allocated our blocks.  That
         * happens in filter_grant_commit() after the writes are done. */
        *left -= ungranted;
        fed->fed_grant -= used;
        fed->fed_pending += used + ungranted;
        exp->exp_obd->u.filter.fo_tot_granted += ungranted;
        exp->exp_obd->u.filter.fo_tot_pending += used + ungranted;

        CDEBUG(D_CACHE,
               "%s: cli %s/%p used: %lu ungranted: %lu grant: %lu dirty: %lu\n",
               exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp, used,
               ungranted, fed->fed_grant, fed->fed_dirty);

        /* Rough calc in case we don't refresh cached statfs data */
        using = (used + ungranted + 1 ) >>
                exp->exp_obd->u.obt.obt_sb->s_blocksize_bits;
        if (exp->exp_obd->obd_osfs.os_bavail > using)
                exp->exp_obd->obd_osfs.os_bavail -= using;
        else
                exp->exp_obd->obd_osfs.os_bavail = 0;

        if (fed->fed_dirty < used) {
                CERROR("%s: cli %s/%p claims used %lu > fed_dirty %lu\n",
                       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       used, fed->fed_dirty);
                used = fed->fed_dirty;
        }
        exp->exp_obd->u.filter.fo_tot_dirty -= used;
        fed->fed_dirty -= used;

        if (fed->fed_dirty < 0 || fed->fed_grant < 0 || fed->fed_pending < 0) {
                CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
                       exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       fed->fed_dirty, fed->fed_pending, fed->fed_grant);
                cfs_spin_unlock(&exp->exp_obd->obd_osfs_lock);
                LBUG();
        }
        return rc;
}

/* If we ever start to support multi-object BRW RPCs, we will need to get locks
 * on mulitple inodes.  That isn't all, because there still exists the
 * possibility of a truncate starting a new transaction while holding the ext3
 * rwsem = write while some writes (which have started their transactions here)
 * blocking on the ext3 rwsem = read => lock inversion.
 *
 * The handling gets very ugly when dealing with locked pages.  It may be easier
 * to just get rid of the locked page code (which has problems of its own) and
 * either discover we do not need it anymore (i.e. it was a symptom of another
 * bug) or ensure we get the page locks in an appropriate order. */
static int filter_preprw_write(int cmd, struct obd_export *exp, struct obdo *oa,
                               int objcount, struct obd_ioobj *obj,
                               struct niobuf_remote *nb, int *npages,
                               struct niobuf_local *res,
                               struct obd_trans_info *oti,
                               struct lustre_capa *capa)
{
        struct obd_device *obd = exp->exp_obd;
        struct timeval start, end;
        struct lvfs_run_ctxt saved;
        struct niobuf_local *lnb = res;
        struct fsfilt_objinfo fso;
        struct filter_mod_data *fmd;
        struct dentry *dentry = NULL;
        void *iobuf;
        obd_size left;
        unsigned long now = jiffies, timediff;
        int rc = 0, i, tot_bytes = 0, cleanup_phase = 0, localreq = 0;
	int retries = 0;
        ENTRY;
        LASSERT(objcount == 1);
        LASSERT(obj->ioo_bufcnt > 0);

        rc = filter_auth_capa(exp, NULL, oa->o_seq, capa,
                              CAPA_OPC_OSS_WRITE);
        if (rc)
                RETURN(rc);

        if (exp->exp_connection &&
            exp->exp_connection->c_peer.nid == exp->exp_connection->c_self)
                localreq = 1;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        iobuf = filter_iobuf_get(&obd->u.filter, oti);
        if (IS_ERR(iobuf))
                GOTO(cleanup, rc = PTR_ERR(iobuf));
        cleanup_phase = 1;

        dentry = filter_fid2dentry(obd, NULL, obj->ioo_seq,
                                   obj->ioo_id);
        if (IS_ERR(dentry))
                GOTO(cleanup, rc = PTR_ERR(dentry));
        cleanup_phase = 2;

        if (dentry->d_inode == NULL) {
                if (exp->exp_obd->obd_recovering) {
                        struct obdo *noa = oa;

                        if (oa == NULL) {
                                OBDO_ALLOC(noa);
                                if (noa == NULL)
                                        GOTO(recreate_out, rc = -ENOMEM);
                                noa->o_id = obj->ioo_id;
                                noa->o_valid = OBD_MD_FLID;
                        }

                        if (filter_create(NULL, exp, noa, NULL, oti) == 0) {
                                f_dput(dentry);
                                dentry = filter_fid2dentry(exp->exp_obd, NULL,
                                                           obj->ioo_seq,
                                                           obj->ioo_id);
                        }
                        if (oa == NULL)
                                OBDO_FREE(noa);
                }
    recreate_out:
                if (IS_ERR(dentry) || dentry->d_inode == NULL) {
                        CERROR("%s: BRW to missing obj "LPU64"/"LPU64":rc %d\n",
                               exp->exp_obd->obd_name,
                               obj->ioo_id, obj->ioo_seq,
                               IS_ERR(dentry) ? (int)PTR_ERR(dentry) : -ENOENT);
                        if (IS_ERR(dentry))
                                cleanup_phase = 1;
                        GOTO(cleanup, rc = -ENOENT);
                }
        }

        if (oa->o_valid & (OBD_MD_FLUID | OBD_MD_FLGID) &&
            dentry->d_inode->i_mode & (S_ISUID | S_ISGID)) {
                rc = filter_capa_fixoa(exp, oa, oa->o_seq, capa);
                if (rc)
                        GOTO(cleanup, rc);
        }

        rc = filter_map_remote_to_local(objcount, obj, nb, npages, res);
        if (rc)
                GOTO(cleanup, rc);

        fsfilt_check_slow(obd, now, "preprw_write setup");

        /* Filter truncate first locks i_mutex then partially truncated
         * page, filter write code first locks pages then take
         * i_mutex.  To avoid a deadlock in case of concurrent
         * punch/write requests from one client, filter writes and
         * filter truncates are serialized by i_alloc_sem, allowing
         * multiple writes or single truncate. */
        down_read(&dentry->d_inode->i_alloc_sem);
        fsfilt_check_slow(obd, now, "i_alloc_sem");

        /* Don't update inode timestamps if this write is older than a
         * setattr which modifies the timestamps. b=10150 */
        /* XXX when we start having persistent reservations this needs to
         * be changed to filter_fmd_get() to create the fmd if it doesn't
         * already exist so we can store the reservation handle there. */
        fmd = filter_fmd_find(exp, obj->ioo_id, obj->ioo_seq);

	LASSERT(oa != NULL);
retry:
	cfs_spin_lock(&obd->obd_osfs_lock);
	if (retries == 0)
		filter_grant_incoming(exp, oa);
	if (fmd && fmd->fmd_mactime_xid > oti->oti_xid)
		oa->o_valid &= ~(OBD_MD_FLMTIME | OBD_MD_FLCTIME |
				 OBD_MD_FLATIME);
	else
		obdo_to_inode(dentry->d_inode, oa, OBD_MD_FLATIME |
			      OBD_MD_FLMTIME | OBD_MD_FLCTIME);
	cleanup_phase = 3;

	left = filter_grant_space_left(exp);

	fso.fso_dentry = dentry;
	fso.fso_bufcnt = *npages;

	rc = filter_grant_check(exp, oa, objcount, &fso, *npages, res,
				&left, dentry->d_inode);

	/* do not zero out oa->o_valid as it is used in filter_commitrw_write()
	 * for setting UID/GID and fid EA in first write time. */
	/* If OBD_FL_SHRINK_GRANT is set, the client just returned us some grant
	 * so no sense in allocating it some more. We either return the grant
	 * back to the client if we have plenty of space or we don't return
	 * anything if we are short. This was decided in filter_grant_incoming*/
	if ((retries == 0) && (oa->o_valid & OBD_MD_FLGRANT) &&
	    (!(oa->o_valid & OBD_MD_FLFLAGS) ||
	     !(oa->o_flags & OBD_FL_SHRINK_GRANT)))
		oa->o_grant = filter_grant(exp, oa->o_grant, oa->o_undirty,
					   left, 1);

	cfs_spin_unlock(&obd->obd_osfs_lock);

	if (rc == -ENOSPC && retries == 0) {
		void *handle = NULL;

		CDEBUG(D_INODE, "retry after commit pending journals");

		retries = 1;
		handle = fsfilt_start(obd, dentry->d_inode,
				      FSFILT_OP_SETATTR, NULL);
		if (handle != NULL &&
		    fsfilt_commit(obd, dentry->d_inode, handle, 1) == 0)
			goto retry;
	}

        filter_fmd_put(exp, fmd);

        OBD_FAIL_TIMEOUT(OBD_FAIL_OST_BRW_PAUSE_BULK2, (obd_timeout + 1) / 4);

        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 4;

        cfs_gettimeofday(&start);
        for (i = 0, lnb = res; i < *npages; i++, lnb++) {

                /* We still set up for ungranted pages so that granted pages
                 * can be written to disk as they were promised, and portals
                 * needs to keep the pages all aligned properly. */
                lnb->dentry = dentry;

		lnb->page = filter_get_page(obd, dentry->d_inode,
					    lnb->lnb_file_offset, localreq);
                if (lnb->page == NULL)
                        GOTO(cleanup, rc = -ENOMEM);

                /* DLM locking protects us from write and truncate competing
                 * for same region, but truncate can leave dirty page in the
                 * cache. it's possible the writeout on a such a page is in
                 * progress when we access it. it's also possible that during
                 * this writeout we put new (partial) data, but then won't
                 * be able to proceed in filter_commitrw_write(). thus let's
                 * just wait for writeout completion, should be rare enough.
                 * -bzzz */
                wait_on_page_writeback(lnb->page);
                BUG_ON(PageWriteback(lnb->page));

                /* If the filter writes a partial page, then has the file
                 * extended, the client will read in the whole page.  the
                 * filter has to be careful to zero the rest of the partial
                 * page on disk.  we do it by hand for partial extending
                 * writes, send_bio() is responsible for zeroing pages when
                 * asked to read unmapped blocks -- brw_kiovec() does this. */
                if (lnb->len != CFS_PAGE_SIZE) {
                        __s64 maxidx;

                        maxidx = ((i_size_read(dentry->d_inode) +
                                   CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT) - 1;
                        if (maxidx >= lnb->page->index) {
                                LL_CDEBUG_PAGE(D_PAGE, lnb->page, "write %u @ "
                                               LPU64" flg %x before EOF %llu\n",
					       lnb->len, lnb->lnb_file_offset,
					       lnb->flags,
                                               i_size_read(dentry->d_inode));
                                filter_iobuf_add_page(obd, iobuf,
                                                      dentry->d_inode,
                                                      lnb->page);
                        } else {
                                long off;
                                char *p = kmap(lnb->page);

                                off = lnb->lnb_file_offset & ~CFS_PAGE_MASK;
                                if (off)
                                        memset(p, 0, off);
				off = (lnb->lnb_file_offset + lnb->len) &
				      ~CFS_PAGE_MASK;
                                if (off)
                                        memset(p + off, 0, CFS_PAGE_SIZE - off);
                                kunmap(lnb->page);
                        }
                }
                if (lnb->rc == 0)
                        tot_bytes += lnb->len;
        }
        cfs_gettimeofday(&end);
        timediff = cfs_timeval_sub(&end, &start, NULL);
        lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_GET_PAGE, timediff);

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_NOMEM))
                GOTO(cleanup, rc = -ENOMEM);

        /* don't unlock pages to prevent any access */
        rc = filter_direct_io(OBD_BRW_READ, dentry, iobuf, exp,
                              NULL, NULL, NULL);

        fsfilt_check_slow(obd, now, "start_page_write");

        lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_WRITE_BYTES,
                            tot_bytes);

        if (exp->exp_nid_stats && exp->exp_nid_stats->nid_stats)
                lprocfs_counter_add(exp->exp_nid_stats->nid_stats,
                                    LPROC_FILTER_WRITE_BYTES, tot_bytes);
	filter_counter_incr(exp, LPROC_FILTER_STATS_WRITE,
			    oti ? oti->oti_jobid : NULL, tot_bytes);
        EXIT;
cleanup:
        switch(cleanup_phase) {
        case 4:
                if (rc) {
                        for (i = 0, lnb = res; i < *npages; i++, lnb++) {
                                if (lnb->page != NULL) {
                                        unlock_page(lnb->page);
                                        page_cache_release(lnb->page);
                                        lnb->page = NULL;
                                }
                        }
                }
        case 3:
                if (rc)
                        up_read(&dentry->d_inode->i_alloc_sem);

                filter_iobuf_put(&obd->u.filter, iobuf, oti);
        case 2:
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        f_dput(dentry);
                break;
        case 1:
                filter_iobuf_put(&obd->u.filter, iobuf, oti);
        case 0:
                cfs_spin_lock(&obd->obd_osfs_lock);
                if (oa)
                        filter_grant_incoming(exp, oa);
                cfs_spin_unlock(&obd->obd_osfs_lock);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                break;
        default:;
        }
        return rc;
}

int filter_preprw(const struct lu_env *env, int cmd, struct obd_export *exp,
                  struct obdo *oa, int objcount, struct obd_ioobj *obj,
                  struct niobuf_remote *nb, int *npages,
                  struct niobuf_local *res, struct obd_trans_info *oti,
                  struct lustre_capa *capa)
{
        if (cmd == OBD_BRW_WRITE)
                return filter_preprw_write(cmd, exp, oa, objcount, obj,
                                           nb, npages, res, oti, capa);
        if (cmd == OBD_BRW_READ)
                return filter_preprw_read(cmd, exp, oa, objcount, obj,
                                          nb, npages, res, oti, capa);
        LBUG();
        return -EPROTO;
}

static int filter_commitrw_read(struct obd_export *exp, struct obdo *oa,
                                int objcount, struct obd_ioobj *obj,
                                struct niobuf_remote *rnb,
                                int npages, struct niobuf_local *res,
                                struct obd_trans_info *oti, int rc)
{
        struct filter_obd *fo = &exp->exp_obd->u.filter;
        struct inode *inode = NULL;
        struct ldlm_res_id res_id;
        struct ldlm_resource *resource = NULL;
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        struct niobuf_local *lnb;
        int i;
        ENTRY;

        osc_build_res_name(obj->ioo_id, obj->ioo_seq, &res_id);
        /* If oa != NULL then filter_preprw_read updated the inode atime
         * and we should update the lvb so that other glimpses will also
         * get the updated value. bug 5972 */
        if (oa && ns && ns->ns_lvbo && ns->ns_lvbo->lvbo_update) {
                resource = ldlm_resource_get(ns, NULL, &res_id, LDLM_EXTENT, 0);

                if (resource != NULL) {
                        LDLM_RESOURCE_ADDREF(resource);
                        ns->ns_lvbo->lvbo_update(resource, NULL, 1);
                        LDLM_RESOURCE_DELREF(resource);
                        ldlm_resource_putref(resource);
                }
        }

        if (res->dentry != NULL)
                inode = res->dentry->d_inode;

        for (i = 0, lnb = res; i < npages; i++, lnb++) {
                if (lnb->page != NULL) {
                        page_cache_release(lnb->page);
                        lnb->page = NULL;
                }
        }
        if (inode && (fo->fo_read_cache == 0 ||
                      i_size_read(inode) > fo->fo_readcache_max_filesize))
                filter_release_cache(exp->exp_obd, obj, rnb, inode);

        if (res->dentry != NULL)
                f_dput(res->dentry);
        RETURN(rc);
}

void filter_grant_commit(struct obd_export *exp, int niocount,
                         struct niobuf_local *res)
{
        struct filter_obd *filter = &exp->exp_obd->u.filter;
        struct niobuf_local *lnb = res;
        unsigned long pending = 0;
        int i;

        cfs_spin_lock(&exp->exp_obd->obd_osfs_lock);
        for (i = 0, lnb = res; i < niocount; i++, lnb++)
                pending += lnb->lnb_grant_used;

        LASSERTF(exp->exp_filter_data.fed_pending >= pending,
                 "%s: cli %s/%p fed_pending: %lu grant_used: %lu\n",
                 exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
                 exp->exp_filter_data.fed_pending, pending);
        exp->exp_filter_data.fed_pending -= pending;
        LASSERTF(filter->fo_tot_granted >= pending,
                 "%s: cli %s/%p tot_granted: "LPU64" grant_used: %lu\n",
                 exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
                 exp->exp_obd->u.filter.fo_tot_granted, pending);
        filter->fo_tot_granted -= pending;
        LASSERTF(filter->fo_tot_pending >= pending,
                 "%s: cli %s/%p tot_pending: "LPU64" grant_used: %lu\n",
                 exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
                 filter->fo_tot_pending, pending);
        filter->fo_tot_pending -= pending;

        cfs_spin_unlock(&exp->exp_obd->obd_osfs_lock);
}

int filter_commitrw(const struct lu_env *env, int cmd, struct obd_export *exp,
                    struct obdo *oa, int objcount, struct obd_ioobj *obj,
                    struct niobuf_remote *nb, int npages,
                    struct niobuf_local *res, struct obd_trans_info *oti,
                    int rc)
{
        if (cmd == OBD_BRW_WRITE)
                return filter_commitrw_write(exp, oa, objcount, obj,
                                             nb, npages, res, oti, rc);
        if (cmd == OBD_BRW_READ)
                return filter_commitrw_read(exp, oa, objcount, obj,
                                            nb, npages, res, oti, rc);
        LBUG();
        return -EPROTO;
}
