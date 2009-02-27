/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/ofd/ofd_grant.c
 *
 *  Copyright (c) 2007 Cluster File Systems, Inc.
 *   Author: Atul Vidwansa <atul.vidwansa@sun.com>
 *   Author: Mike Pershin <tappro@sun.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <libcfs/libcfs.h>
#include <obd_class.h>
#include <lustre_fsfilt.h>
#include "ofd_internal.h"

/* Do extra sanity checks for grant accounting.  We do this at connect,
 * disconnect, and statfs RPC time, so it shouldn't be too bad.  We can
 * always get rid of it or turn it off when we know accounting is good. 
 */
void filter_grant_sanity_check(struct obd_device *obd, const char *func)
{
        struct filter_export_data *fed;
        struct filter_device *ofd = filter_dev(obd->obd_lu_dev);
        struct obd_export *exp;
        obd_size maxsize = obd->obd_osfs.os_blocks * obd->obd_osfs.os_bsize;
        obd_size tot_dirty = 0, tot_pending = 0, tot_granted = 0;
        obd_size fo_tot_dirty, fo_tot_pending, fo_tot_granted;

        if (list_empty(&obd->obd_exports))
                return;

        /* We don't want to do this for large machines that do lots of
         * mounts or unmounts.  It burns... */
        if (obd->obd_num_exports > 100)
                return;

        spin_lock(&obd->obd_osfs_lock);
        spin_lock(&obd->obd_dev_lock);
        list_for_each_entry(exp, &obd->obd_exports, exp_obd_chain) {
                int error = 0;
                fed = &exp->exp_filter_data;
                if (fed->fed_grant < 0 || fed->fed_pending < 0 ||
                    fed->fed_dirty < 0)
                        error = 1;
                if (maxsize > 0) { /* we may not have done a statfs yet */
                        LASSERTF(fed->fed_grant + fed->fed_pending <= maxsize,
                                 "%s: cli %s/%p %ld+%ld > "LPU64"\n", func,
                                 exp->exp_client_uuid.uuid, exp,
                                 fed->fed_grant, fed->fed_pending, maxsize);
                        LASSERTF(fed->fed_dirty <= maxsize,
                                 "%s: cli %s/%p %ld > "LPU64"\n", func,
                                 exp->exp_client_uuid.uuid, exp,
                                 fed->fed_dirty, maxsize);
                }
                if (error)
                        CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
                               obd->obd_name, exp->exp_client_uuid.uuid, exp,
                               fed->fed_dirty, fed->fed_pending,fed->fed_grant);
                else
                        CDEBUG(D_CACHE, "%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
                               obd->obd_name, exp->exp_client_uuid.uuid, exp,
                               fed->fed_dirty, fed->fed_pending,fed->fed_grant);
                tot_granted += fed->fed_grant + fed->fed_pending;
                tot_pending += fed->fed_pending;
                tot_dirty += fed->fed_dirty;
        }
        fo_tot_granted = ofd->ofd_tot_granted;
        fo_tot_pending = ofd->ofd_tot_pending;
        fo_tot_dirty = ofd->ofd_tot_dirty;
        spin_unlock(&obd->obd_dev_lock);
        spin_unlock(&obd->obd_osfs_lock);

        /* Do these assertions outside the spinlocks so we don't kill system */
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
}

/* Remove this client from the grant accounting totals.  We also remove
 * the export from the obd device under the osfs and dev locks to ensure
 * that the filter_grant_sanity_check() calculations are always valid.
 * The client should do something similar when it invalidates its import. 
 */
void filter_grant_discard(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_device *ofd = filter_exp(exp);
        struct filter_export_data *fed = &exp->exp_filter_data;

        spin_lock(&obd->obd_osfs_lock);
        spin_lock(&obd->obd_dev_lock);
        list_del_init(&exp->exp_obd_chain);
        spin_unlock(&obd->obd_dev_lock);

        LASSERTF(ofd->ofd_tot_granted >= fed->fed_grant,
                 "%s: tot_granted "LPU64" cli %s/%p fed_grant %ld\n",
                 obd->obd_name, ofd->ofd_tot_granted,
                 exp->exp_client_uuid.uuid, exp, fed->fed_grant);
        ofd->ofd_tot_granted -= fed->fed_grant;
        LASSERTF(ofd->ofd_tot_pending >= fed->fed_pending,
                 "%s: tot_pending "LPU64" cli %s/%p fed_pending %ld\n",
                 obd->obd_name, ofd->ofd_tot_pending,
                 exp->exp_client_uuid.uuid, exp, fed->fed_pending);
        /* ofd_tot_pending is handled in filter_grant_commit as bulk finishes */
        LASSERTF(ofd->ofd_tot_dirty >= fed->fed_dirty,
                 "%s: tot_dirty "LPU64" cli %s/%p fed_dirty %ld\n",
                 obd->obd_name, ofd->ofd_tot_dirty,
                 exp->exp_client_uuid.uuid, exp, fed->fed_dirty);
        ofd->ofd_tot_dirty -= fed->fed_dirty;
        fed->fed_dirty = 0;
        fed->fed_grant = 0;
        spin_unlock(&obd->obd_osfs_lock);
}

/* 
 * Grab the dirty and seen grant announcements from the incoming obdo.
 * We will later calculate the clients new grant and return it. 
 * Caller must hold osfs lock. 
 */
void filter_grant_incoming(struct obd_export *exp, struct obdo *oa)
{
        struct filter_export_data *fed;
        struct filter_device *ofd = filter_exp(exp);
        struct obd_device *obd = exp->exp_obd;
        ENTRY;

        LASSERT_SPIN_LOCKED(&obd->obd_osfs_lock);

        /* Check if OST supports grants (OBD_MD_FLGRANT) or allocated block
         * flag is set.
         */ 
        if ((oa->o_valid & (OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) !=
            (OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) {
                oa->o_valid &= ~OBD_MD_FLGRANT;
                EXIT;
                return;
        }

        fed = &exp->exp_filter_data;

        /* Add some margin, since there is a small race if other RPCs arrive
         * out-or-order and have already consumed some grant.  We want to
         * leave this here in case there is a large error in accounting. 
         */
        CDEBUG(D_CACHE,
               "%s: cli %s/%p reports grant: "LPU64" dropped: %u, local: %lu\n",
               obd->obd_name, exp->exp_client_uuid.uuid, exp, oa->o_grant,
               oa->o_dropped, fed->fed_grant);

        /* Update our accounting now so that statfs takes it into account.
         * Note that fed_dirty is only approximate and can become incorrect
         * if RPCs arrive out-of-order.  No important calculations depend
         * on fed_dirty however, but we must check sanity to not assert. 
         */
        if ((long long)oa->o_dirty < 0)
                oa->o_dirty = 0;
        else if (oa->o_dirty > fed->fed_grant + 4 * FILTER_GRANT_CHUNK)
                oa->o_dirty = fed->fed_grant + 4 * FILTER_GRANT_CHUNK;
        ofd->ofd_tot_dirty += oa->o_dirty - fed->fed_dirty;
        if (fed->fed_grant < oa->o_dropped) {
                CDEBUG(D_CACHE,"%s: cli %s/%p reports %u dropped > grant %lu\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       oa->o_dropped, fed->fed_grant);
                oa->o_dropped = 0;
        }
        if (ofd->ofd_tot_granted < oa->o_dropped) {
                CERROR("%s: cli %s/%p reports %u dropped > tot_grant "LPU64"\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       oa->o_dropped, ofd->ofd_tot_granted);
                oa->o_dropped = 0;
        }
        ofd->ofd_tot_granted -= oa->o_dropped;
        fed->fed_grant -= oa->o_dropped;
        fed->fed_dirty = oa->o_dirty;
        if (fed->fed_dirty < 0 || fed->fed_grant < 0 || fed->fed_pending < 0) {
                CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       fed->fed_dirty, fed->fed_pending, fed->fed_grant);
                spin_unlock(&obd->obd_osfs_lock);
                LBUG();
        }
        EXIT;
}

/* Figure out how much space is available between what we've granted
 * and what remains in the filesystem.  Compensate for ext3 indirect
 * block overhead when computing how much free space is left ungranted.
 * Caller must hold obd_osfs_lock. 
 */
obd_size filter_grant_space_left(const struct lu_env *env,
                                 struct obd_export *exp)
{
        struct filter_device *ofd = filter_exp(exp);
        struct obd_device *obd = exp->exp_obd;
        struct filter_thread_info *info = filter_info(env);
        obd_size tot_granted = ofd->ofd_tot_granted, avail, left = 0;
        int statfs_done = 0;
        long frsize;

        LASSERT_SPIN_LOCKED(&obd->obd_osfs_lock);

        if (cfs_time_before_64(obd->obd_osfs_age,
                               cfs_time_current_64() - HZ)) {
restat:
                dt_statfs(env, ofd->ofd_osd, &info->fti_u.ksfs);
                statfs_pack(&obd->obd_osfs, &info->fti_u.ksfs);
                statfs_done = 1;
        }
        frsize = obd->obd_osfs.os_bsize;
        avail = obd->obd_osfs.os_bavail; /* in fragments */
        LASSERT(frsize);
        /*
         * Consider metadata overhead for allocating new blocks while
         * calculating available space left.
         */
#if defined(LINUX)
        left = avail - (avail / (frsize >> 3)); /* (d)indirect */
#else
        left = avail;
#endif
        if (left > GRANT_FOR_LLOG)
                left = (left - GRANT_FOR_LLOG) * frsize;
        else
                left = 0;

        if (!statfs_done && left < 32 * FILTER_GRANT_CHUNK + tot_granted) {
                CDEBUG(D_CACHE, "fs has no space left and statfs too old\n");
                goto restat;
        }

        /* bytes now, is obd_size enough for 'left'? */
        if (left >= tot_granted) {
                left -= tot_granted;
        } else {
                if (left < tot_granted - ofd->ofd_tot_pending) {
                        CERROR("%s: cli %s/%p grant "LPU64" > available "
                               LPU64" and pending "LPU64"\n", obd->obd_name,
                               exp->exp_client_uuid.uuid, exp, tot_granted,
                               left, ofd->ofd_tot_pending);
                }
                left = 0;
        }

        CDEBUG(D_CACHE, "%s: cli %s/%p free: "LPU64" avail: "LPU64" grant "LPU64
               " left: "LPU64" pending: "LPU64"\n", obd->obd_name,
               exp->exp_client_uuid.uuid, exp,
               obd->obd_osfs.os_bfree * frsize, avail * frsize,
               tot_granted, left, ofd->ofd_tot_pending);

        return left;
}

/* Substract what client have used already.  We don't subtract
 * this from the tot_granted yet, so that other client's can't grab
 * that space before we have actually allocated our blocks.  That
 * happens in filter_grant_commit() after the writes are done.
 */
int filter_grant_client_calc(struct obd_export *exp, obd_size *left,
                             unsigned long *used, unsigned long *ungranted)
{
        struct filter_device *ofd = filter_exp(exp);
        struct obd_device *obd = exp->exp_obd;
        struct filter_export_data *fed = &exp->exp_filter_data;
        unsigned long using = 0;
        int rc = 0;

        LASSERT_SPIN_LOCKED(&obd->obd_osfs_lock);

        *left -= *ungranted;
        LASSERT(fed->fed_grant >= *used);
        fed->fed_grant -= *used;
        fed->fed_pending += *used + *ungranted;
        ofd->ofd_tot_granted += *ungranted;
        ofd->ofd_tot_pending += *used + *ungranted;

        CDEBUG(D_CACHE,
               "%s: cli %s/%p used: %lu ungranted: %lu grant: %lu dirty: %lu\n",
               obd->obd_name, exp->exp_client_uuid.uuid, exp, *used,
               *ungranted, fed->fed_grant, fed->fed_dirty);

        /* Rough calc in case we don't refresh cached statfs data,
         * in fragments */
        LASSERT(obd->obd_osfs.os_bsize);
        using = ((*used + *ungranted + 1 ) / obd->obd_osfs.os_bsize);
        if (obd->obd_osfs.os_bavail > using)
                obd->obd_osfs.os_bavail -= using;
        else
                obd->obd_osfs.os_bavail = 0;

        if (fed->fed_dirty < *used) {
                CWARN("%s: cli %s/%p claims used %lu > fed_dirty %lu\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       *used, fed->fed_dirty);
                *used = fed->fed_dirty;
        }
        ofd->ofd_tot_dirty -= *used;
        fed->fed_dirty -= *used;

        if (fed->fed_dirty < 0 || fed->fed_grant < 0 || fed->fed_pending < 0) {
                CERROR("%s: cli %s/%p dirty %ld pend %ld grant %ld\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp,
                       fed->fed_dirty, fed->fed_pending, fed->fed_grant);
                spin_unlock(&obd->obd_osfs_lock);
                LBUG();
        }
        return rc;
}

/* When clients have dirtied as much space as they've been granted they
 * fall through to sync writes.  These sync writes haven't been expressed
 * in grants and need to error with ENOSPC when there isn't room in the
 * filesystem for them after grants are taken into account.  However,
 * writeback of the dirty data that was already granted space can write
 * right on through.
 * Caller must hold obd_osfs_lock. 
 */
int filter_grant_check(const struct lu_env *env, struct obd_export *exp, 
                       struct obdo *oa, int objcount, struct obd_ioobj *objs,
                       struct niobuf_remote *rnb, struct niobuf_local *lnb,
                       obd_size *left, unsigned long *used, unsigned long *ungranted)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        int i, rc = -ENOSPC, obj, n = 0;

        LASSERT_SPIN_LOCKED(&exp->exp_obd->obd_osfs_lock);

        for (obj = 0; obj < objcount; obj++) {
                for (i = 0; i < objs[obj].ioo_bufcnt; i++, n++) {
                        int bytes;

                        bytes = lnb[n].bytes;
                        if ((rnb[n].flags & OBD_BRW_FROM_GRANT) &&
                            (oa->o_valid & OBD_MD_FLGRANT)) {
                                if (fed->fed_grant < *used + bytes) {
                                        CDEBUG(D_CACHE,
                                               "%s: cli %s/%p claims %ld+%d "
                                               "GRANT, real grant %lu idx %d\n",
                                               exp->exp_obd->obd_name,
                                               exp->exp_client_uuid.uuid, exp,
                                               *used, bytes, fed->fed_grant, n);
                                } else {
                                        *used += bytes;
                                        rnb[n].flags |= OBD_BRW_GRANTED;
                                        lnb[n].lnb_grant_used = bytes;
                                        CDEBUG(0, "idx %d used=%lu\n", n, *used);
                                        rc = 0;
                                        continue;
                                }
                        }
                        if (*left > *ungranted + bytes) {
                                /* if enough space, pretend it was granted */
                                *ungranted += bytes;
                                rnb[n].flags |= OBD_BRW_GRANTED;
                                lnb[n].lnb_grant_used = bytes;
                                CDEBUG(0, "idx %d ungranted=%lu\n",n,*ungranted);
                                rc = 0;
                                continue;
                        }

                        /* We can't check for already-mapped blocks here, as
                         * it requires dropping the osfs lock to do the bmap.
                         * Instead, we return ENOSPC and in that case we need
                         * to go through and verify if all of the blocks not
                         * marked BRW_GRANTED are already mapped and we can
                         * ignore this error. 
                         */
                        lnb[n].rc = -ENOSPC;
                        rnb[n].flags &= ~OBD_BRW_GRANTED;
                        CDEBUG(D_CACHE,"%s: cli %s/%p idx %d no space for %d\n",
                               exp->exp_obd->obd_name,
                               exp->exp_client_uuid.uuid, exp, n, bytes);
                }
        }

        return rc;
}

/* Calculate how much grant space to allocate to this client, based on how
 * much space is currently free and how much of that is already granted.
 * Caller must hold obd_osfs_lock.
 */
long _filter_grant(const struct lu_env *env, struct obd_export *exp,
                   obd_size curgrant, obd_size want, obd_size fs_space_left)
{
        struct obd_device          *obd = exp->exp_obd;
        struct filter_device       *ofd = filter_exp(exp);
        struct filter_export_data  *fed = &exp->exp_filter_data;
        long                        frsize = obd->obd_osfs.os_bsize;
        __u64                       grant = 0;

        LASSERT_SPIN_LOCKED(&obd->obd_osfs_lock);
        LASSERT(frsize);

        /* Grant some fraction of the client's requested grant space so that
         * they are not always waiting for write credits (not all of it to
         * avoid overgranting in face of multiple RPCs in flight).  This
         * essentially will be able to control the OSC_MAX_RIF for a client.
         *
         * If we do have a large disparity between what the client thinks it
         * has and what we think it has, don't grant very much and let the
         * client consume its grant first.  Either it just has lots of RPCs
         * in flight, or it was evicted and its grants will soon be used up.
         */
        if (curgrant >= want || curgrant >= fed->fed_grant + FILTER_GRANT_CHUNK)
                   return 0;

#if 0
        grant = (min(want, fs_space_left >> 3) / frsize) * frsize;
#else
        CERROR("not implemented yet\n");
        grant = min(want, fs_space_left >> 3);
#endif
        if (grant) {
                /* Allow >FILTER_GRANT_CHUNK size when clients
                 * reconnect due to a server reboot.
                 */
                if ((grant > FILTER_GRANT_CHUNK) && (!obd->obd_recovering))
                        grant = FILTER_GRANT_CHUNK;

                ofd->ofd_tot_granted += grant;
                fed->fed_grant += grant;

                if (fed->fed_grant < 0) {
                        CERROR("%s: cli %s/%p grant %ld want "LPU64
                               "current"LPU64"\n", obd->obd_name,
                                exp->exp_client_uuid.uuid, exp,
                                fed->fed_grant, want, curgrant);
                        spin_unlock(&obd->obd_osfs_lock);
                        LBUG();
                }
        }

        return grant;
}

long filter_grant(const struct lu_env *env, struct obd_export *exp,
                  obd_size current_grant, obd_size want, obd_size fs_space_left)
{
        struct obd_device     *obd = exp->exp_obd;
        struct filter_device  *ofd = filter_exp(exp);
        __u64                  grant = 0;

        if (want <= 0x7fffffff) {
                grant = _filter_grant(env, exp, current_grant, want, fs_space_left);
        } else {
                CERROR("%s: client %s/%p requesting > 2GB grant "LPU64"\n",
                       obd->obd_name, exp->exp_client_uuid.uuid, exp, want);
        }

        CDEBUG(D_CACHE,
               "%s: cli %s/%p wants: "LPU64" current grant "LPU64
               " granting: "LPU64"\n", obd->obd_name, exp->exp_client_uuid.uuid,
               exp, want, current_grant, grant);
        CDEBUG(D_CACHE,
               "%s: cli %s/%p tot cached:"LPU64" granted:"LPU64
               " num_exports: %d\n", obd->obd_name, exp->exp_client_uuid.uuid,
               exp, ofd->ofd_tot_dirty, ofd->ofd_tot_granted,
               obd->obd_num_exports);

        return grant;
}

void filter_grant_commit(struct obd_export *exp, int niocount,
                         struct niobuf_local *res)
{
        struct filter_device *ofd = filter_exp(exp);
        struct niobuf_local *lnb = res;
        unsigned long pending = 0;
        int i;

        spin_lock(&exp->exp_obd->obd_osfs_lock);
        for (i = 0, lnb = res; i < niocount; i++, lnb++)
                pending += lnb->lnb_grant_used;

        LASSERTF(exp->exp_filter_data.fed_pending >= pending,
                 "%s: cli %s/%p fed_pending: %lu grant_used: %lu\n",
                 exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
                 exp->exp_filter_data.fed_pending, pending);
        exp->exp_filter_data.fed_pending -= pending;
        LASSERTF(ofd->ofd_tot_granted >= pending,
                 "%s: cli %s/%p tot_granted: "LPU64" grant_used: %lu\n",
                 exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
                 ofd->ofd_tot_granted, pending);
        ofd->ofd_tot_granted -= pending;
        LASSERTF(ofd->ofd_tot_pending >= pending,
                 "%s: cli %s/%p tot_pending: "LPU64" grant_used: %lu\n",
                 exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp,
                 ofd->ofd_tot_pending, pending);
        ofd->ofd_tot_pending -= pending;

        spin_unlock(&exp->exp_obd->obd_osfs_lock);
}

