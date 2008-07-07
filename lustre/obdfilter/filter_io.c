/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter_io.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/pagemap.h> // XXX kill me soon
#include <linux/version.h>

#include <obd_class.h>
#include <lustre_fsfilt.h>
#include "filter_internal.h"

int *obdfilter_created_scratchpad;

static int filter_alloc_dio_page(struct obd_device *obd, struct inode *inode,
                                 struct niobuf_local *lnb)
{
        struct page *page;

        LASSERT(lnb->page != NULL);

        page = lnb->page;
#if 0
        POISON_PAGE(page, 0xf1);
        if (lnb->len != CFS_PAGE_SIZE) {
                memset(kmap(page) + lnb->len, 0, CFS_PAGE_SIZE - lnb->len);
                kunmap(page);
        }
#endif
        page->index = lnb->offset >> CFS_PAGE_SHIFT;

        RETURN(0);
}

static void filter_free_dio_pages(int objcount, struct obd_ioobj *obj,
                           int niocount, struct niobuf_local *res)
{
        int i, j;

        for (i = 0; i < objcount; i++, obj++) {
                for (j = 0 ; j < obj->ioo_bufcnt ; j++, res++)
                                res->page = NULL;
        }
}

/* Grab the dirty and seen grant announcements from the incoming obdo.
 * We will later calculate the clients new grant and return it.
 * Caller must hold osfs lock */
static void filter_grant_incoming(struct obd_export *exp, struct obdo *oa)
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
 *
 * Caller must hold obd_osfs_lock. */
obd_size filter_grant_space_left(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        int blockbits = obd->u.obt.obt_sb->s_blocksize_bits;
        obd_size tot_granted = obd->u.filter.fo_tot_granted, avail, left = 0;
        int rc, statfs_done = 0;

        LASSERT_SPIN_LOCKED(&obd->obd_osfs_lock);

        if (cfs_time_before_64(obd->obd_osfs_age, cfs_time_current_64() - HZ)) {
restat:
                rc = fsfilt_statfs(obd, obd->u.obt.obt_sb,
                                   cfs_time_current_64() + HZ);
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
 * Caller must hold obd_osfs_lock. */
long filter_grant(struct obd_export *exp, obd_size current_grant,
                  obd_size want, obd_size fs_space_left)
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
                grant = min((want >> blockbits),
                            (fs_space_left >> blockbits) / 8);
                grant <<= blockbits;

                if (grant) {
                        /* Allow >FILTER_GRANT_CHUNK size when clients
                         * reconnect due to a server reboot.
                         */
                        if ((grant > FILTER_GRANT_CHUNK) &&
                            (!obd->obd_recovering))
                                grant = FILTER_GRANT_CHUNK;

                        obd->u.filter.fo_tot_granted += grant;
                        fed->fed_grant += grant;
                        if (fed->fed_grant < 0) {
                                CERROR("%s: cli %s/%p grant %ld want "LPU64
                                       "current"LPU64"\n",
                                       obd->obd_name, exp->exp_client_uuid.uuid,
                                       exp, fed->fed_grant, want,current_grant);
                                spin_unlock(&obd->obd_osfs_lock);
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

static int filter_preprw_read(int cmd, struct obd_export *exp, struct obdo *oa,
                              int objcount, struct obd_ioobj *obj,
                              int niocount, struct niobuf_remote *nb,
                              struct niobuf_local *res,
                              struct obd_trans_info *oti,
                              struct lustre_capa *capa)
{
        struct obd_device *obd = exp->exp_obd;
        struct lvfs_run_ctxt saved;
        struct niobuf_remote *rnb;
        struct niobuf_local *lnb;
        struct dentry *dentry = NULL;
        struct inode *inode;
        void *iobuf = NULL;
        int rc = 0, i, tot_bytes = 0;
        unsigned long now = jiffies;
        ENTRY;

        /* We are currently not supporting multi-obj BRW_READ RPCS at all.
         * When we do this function's dentry cleanup will need to be fixed.
         * These values are verified in ost_brw_write() from the wire. */
        LASSERTF(objcount == 1, "%d\n", objcount);
        LASSERTF(obj->ioo_bufcnt > 0, "%d\n", obj->ioo_bufcnt);

        rc = filter_auth_capa(exp, NULL, obdo_mdsno(oa), capa,
                              CAPA_OPC_OSS_READ);
        if (rc)
                RETURN(rc);

        if (oa && oa->o_valid & OBD_MD_FLGRANT) {
                spin_lock(&obd->obd_osfs_lock);
                filter_grant_incoming(exp, oa);

                oa->o_grant = 0;
                spin_unlock(&obd->obd_osfs_lock);
        }

        iobuf = filter_iobuf_get(&obd->u.filter, oti);
        if (IS_ERR(iobuf))
                RETURN(PTR_ERR(iobuf));

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        dentry = filter_oa2dentry(obd, oa);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                dentry = NULL;
                GOTO(cleanup, rc);
        }

        inode = dentry->d_inode;

        obdo_to_inode(inode, oa, OBD_MD_FLATIME);
        fsfilt_check_slow(obd, now, "preprw_read setup");

        for (i = 0, lnb = res, rnb = nb; i < obj->ioo_bufcnt;
             i++, rnb++, lnb++) {
                lnb->dentry = dentry;
                lnb->offset = rnb->offset;
                lnb->len    = rnb->len;
                lnb->flags  = rnb->flags;

                /*
                 * ost_brw_write()->ost_nio_pages_get() already initialized
                 * lnb->page to point to the page from the per-thread page
                 * pool (bug 5137), initialize page.
                 */
                LASSERT(lnb->page != NULL);

                if (i_size_read(inode) <= rnb->offset)
                        /* If there's no more data, abort early.  lnb->rc == 0,
                         * so it's easy to detect later. */
                        break;
                else
                        filter_alloc_dio_page(obd, inode, lnb);

                if (i_size_read(inode) < lnb->offset + lnb->len - 1)
                        lnb->rc = i_size_read(inode) - lnb->offset;
                else
                        lnb->rc = lnb->len;

                tot_bytes += lnb->rc;

                filter_iobuf_add_page(obd, iobuf, inode, lnb->page);
        }

        fsfilt_check_slow(obd, now, "start_page_read");

        rc = filter_direct_io(OBD_BRW_READ, dentry, iobuf,
                              exp, NULL, NULL, NULL);
        if (rc)
                GOTO(cleanup, rc);

        lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_READ_BYTES, tot_bytes);

        if (exp->exp_nid_stats && exp->exp_nid_stats->nid_stats)
                lprocfs_counter_add(exp->exp_nid_stats->nid_stats,
                                    LPROC_FILTER_READ_BYTES, tot_bytes);

        EXIT;

 cleanup:
        if (rc != 0) {
                filter_free_dio_pages(objcount, obj, niocount, res);

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
                              int niocount, struct niobuf_remote *rnb,
                              struct niobuf_local *lnb, obd_size *left,
                              struct inode *inode)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        int blocksize = exp->exp_obd->u.obt.obt_sb->s_blocksize;
        unsigned long used = 0, ungranted = 0, using;
        int i, rc = -ENOSPC, obj, n = 0;

        LASSERT_SPIN_LOCKED(&exp->exp_obd->obd_osfs_lock);

        for (obj = 0; obj < objcount; obj++) {
                for (i = 0; i < fso[obj].fso_bufcnt; i++, n++) {
                        int tmp, bytes;

                        /* should match the code in osc_exit_cache */
                        bytes = rnb[n].len;
                        bytes += rnb[n].offset & (blocksize - 1);
                        tmp = (rnb[n].offset + rnb[n].len) & (blocksize - 1);
                        if (tmp)
                                bytes += blocksize - tmp;

                        if ((rnb[n].flags & OBD_BRW_FROM_GRANT) &&
                            (oa->o_valid & OBD_MD_FLGRANT)) {
                                if (fed->fed_grant < used + bytes) {
                                        CDEBUG(D_CACHE,
                                               "%s: cli %s/%p claims %ld+%d "
                                               "GRANT, real grant %lu idx %d\n",
                                               exp->exp_obd->obd_name,
                                               exp->exp_client_uuid.uuid, exp,
                                               used, bytes, fed->fed_grant, n);
                                } else {
                                        used += bytes;
                                        rnb[n].flags |= OBD_BRW_GRANTED;
                                        lnb[n].lnb_grant_used = bytes;
                                        CDEBUG(0, "idx %d used=%lu\n", n, used);
                                        rc = 0;
                                        continue;
                                }
                        }
                        if (*left > ungranted + bytes) {
                                /* if enough space, pretend it was granted */
                                ungranted += bytes;
                                rnb[n].flags |= OBD_BRW_GRANTED;
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
                        rnb[n].flags &= ~OBD_BRW_GRANTED;
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
                spin_unlock(&exp->exp_obd->obd_osfs_lock);
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
                               int niocount, struct niobuf_remote *nb,
                               struct niobuf_local *res,
                               struct obd_trans_info *oti,
                               struct lustre_capa *capa)
{
        struct lvfs_run_ctxt saved;
        struct niobuf_remote *rnb;
        struct niobuf_local *lnb = res;
        struct fsfilt_objinfo fso;
        struct filter_mod_data *fmd;
        struct dentry *dentry = NULL;
        void *iobuf;
        obd_size left;
        unsigned long now = jiffies;
        int rc = 0, i, tot_bytes = 0, cleanup_phase = 0;
        ENTRY;
        LASSERT(objcount == 1);
        LASSERT(obj->ioo_bufcnt > 0);

        rc = filter_auth_capa(exp, NULL, obdo_mdsno(oa), capa,
                              CAPA_OPC_OSS_WRITE);
        if (rc)
                RETURN(rc);

        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
        iobuf = filter_iobuf_get(&exp->exp_obd->u.filter, oti);
        if (IS_ERR(iobuf))
                GOTO(cleanup, rc = PTR_ERR(iobuf));
        cleanup_phase = 1;

        dentry = filter_fid2dentry(exp->exp_obd, NULL, obj->ioo_gr,
                                   obj->ioo_id);
        if (IS_ERR(dentry))
                GOTO(cleanup, rc = PTR_ERR(dentry));
        cleanup_phase = 2;

        if (dentry->d_inode == NULL) {
                CERROR("%s: trying to BRW to non-existent file "LPU64"\n",
                       exp->exp_obd->obd_name, obj->ioo_id);
                GOTO(cleanup, rc = -ENOENT);
        }

        fso.fso_dentry = dentry;
        fso.fso_bufcnt = obj->ioo_bufcnt;

        fsfilt_check_slow(exp->exp_obd, now, "preprw_write setup");

        /* Don't update inode timestamps if this write is older than a
         * setattr which modifies the timestamps. b=10150 */
        /* XXX when we start having persistent reservations this needs to
         * be changed to filter_fmd_get() to create the fmd if it doesn't
         * already exist so we can store the reservation handle there. */
        fmd = filter_fmd_find(exp, obj->ioo_id, obj->ioo_gr);

        LASSERT(oa != NULL);
        spin_lock(&exp->exp_obd->obd_osfs_lock);
        filter_grant_incoming(exp, oa);
        if (fmd && fmd->fmd_mactime_xid > oti->oti_xid)
                oa->o_valid &= ~(OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                                 OBD_MD_FLATIME);
        else
                obdo_to_inode(dentry->d_inode, oa, OBD_MD_FLATIME |
                              OBD_MD_FLMTIME | OBD_MD_FLCTIME);
        cleanup_phase = 3;

        left = filter_grant_space_left(exp);

        rc = filter_grant_check(exp, oa, objcount, &fso, niocount, nb, res,
                                &left, dentry->d_inode);

        /* do not zero out oa->o_valid as it is used in filter_commitrw_write()
         * for setting UID/GID and fid EA in first write time. */
        if (oa->o_valid & OBD_MD_FLGRANT)
                oa->o_grant = filter_grant(exp,oa->o_grant,oa->o_undirty,left);

        spin_unlock(&exp->exp_obd->obd_osfs_lock);
        filter_fmd_put(exp, fmd);

        if (rc)
                GOTO(cleanup, rc);

        for (i = 0, rnb = nb, lnb = res; i < obj->ioo_bufcnt;
             i++, lnb++, rnb++) {
                /* We still set up for ungranted pages so that granted pages
                 * can be written to disk as they were promised, and portals
                 * needs to keep the pages all aligned properly. */
                lnb->dentry = dentry;
                lnb->offset = rnb->offset;
                lnb->len    = rnb->len;
                lnb->flags  = rnb->flags;

                /*
                 * ost_brw_write()->ost_nio_pages_get() already initialized
                 * lnb->page to point to the page from the per-thread page
                 * pool (bug 5137), initialize page.
                 */
                LASSERT(lnb->page != NULL);
                if (lnb->len != CFS_PAGE_SIZE) {
                        memset(kmap(lnb->page) + lnb->len,
                               0, CFS_PAGE_SIZE - lnb->len);
                        kunmap(lnb->page);
                }
                lnb->page->index = lnb->offset >> CFS_PAGE_SHIFT;

                cleanup_phase = 4;

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
                                               lnb->len, lnb->offset,lnb->flags,
                                               i_size_read(dentry->d_inode));
                                filter_iobuf_add_page(exp->exp_obd, iobuf,
                                                      dentry->d_inode,
                                                      lnb->page);
                        } else {
                                long off;
                                char *p = kmap(lnb->page);

                                off = lnb->offset & ~CFS_PAGE_MASK;
                                if (off)
                                        memset(p, 0, off);
                                off = (lnb->offset + lnb->len) & ~CFS_PAGE_MASK;
                                if (off)
                                        memset(p + off, 0, CFS_PAGE_SIZE - off);
                                kunmap(lnb->page);
                        }
                }
                if (lnb->rc == 0)
                        tot_bytes += lnb->len;
        }

        rc = filter_direct_io(OBD_BRW_READ, dentry, iobuf, exp,
                              NULL, NULL, NULL);

        fsfilt_check_slow(exp->exp_obd, now, "start_page_write");

        if (exp->exp_nid_stats && exp->exp_nid_stats->nid_stats)
                lprocfs_counter_add(exp->exp_nid_stats->nid_stats,
                                    LPROC_FILTER_WRITE_BYTES, tot_bytes);
        EXIT;
cleanup:
        switch(cleanup_phase) {
        case 4:
        case 3:
                filter_iobuf_put(&exp->exp_obd->u.filter, iobuf, oti);
        case 2:
                pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        f_dput(dentry);
                break;
        case 1:
                filter_iobuf_put(&exp->exp_obd->u.filter, iobuf, oti);
        case 0:
                spin_lock(&exp->exp_obd->obd_osfs_lock);
                if (oa)
                        filter_grant_incoming(exp, oa);
                spin_unlock(&exp->exp_obd->obd_osfs_lock);
                pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
                break;
        default:;
        }
        return rc;
}

int filter_preprw(int cmd, struct obd_export *exp, struct obdo *oa,
                  int objcount, struct obd_ioobj *obj, int niocount,
                  struct niobuf_remote *nb, struct niobuf_local *res,
                  struct obd_trans_info *oti, struct lustre_capa *capa)
{
        if (cmd == OBD_BRW_WRITE)
                return filter_preprw_write(cmd, exp, oa, objcount, obj,
                                           niocount, nb, res, oti, capa);
        if (cmd == OBD_BRW_READ)
                return filter_preprw_read(cmd, exp, oa, objcount, obj,
                                          niocount, nb, res, oti, capa);
        LBUG();
        return -EPROTO;
}

void filter_release_read_page(struct filter_obd *filter, struct inode *inode,
                              struct page *page)
{
        int drop = 0;

        if (inode != NULL &&
            (i_size_read(inode) > filter->fo_readcache_max_filesize))
                drop = 1;

        /* drop from cache like truncate_list_pages() */
        if (drop && !TryLockPage(page)) {
                if (page->mapping)
                        ll_truncate_complete_page(page);
                unlock_page(page);
        }
        page_cache_release(page);
}

static int filter_commitrw_read(struct obd_export *exp, struct obdo *oa,
                                int objcount, struct obd_ioobj *obj,
                                int niocount, struct niobuf_local *res,
                                struct obd_trans_info *oti, int rc)
{
        struct inode *inode = NULL;
        struct ldlm_res_id res_id = { .name = { obj->ioo_id, 0,
                                                obj->ioo_gr, 0} };
        struct ldlm_resource *resource = NULL;
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        ENTRY;

        /* If oa != NULL then filter_preprw_read updated the inode atime
         * and we should update the lvb so that other glimpses will also
         * get the updated value. bug 5972 */
        if (oa && ns && ns->ns_lvbo && ns->ns_lvbo->lvbo_update) {
                resource = ldlm_resource_get(ns, NULL, &res_id, LDLM_EXTENT, 0);

                if (resource != NULL) {
                        ns->ns_lvbo->lvbo_update(resource, NULL, 0, 1);
                        ldlm_resource_putref(resource);
                }
        }

        if (res->dentry != NULL)
                inode = res->dentry->d_inode;

        filter_free_dio_pages(objcount, obj, niocount, res);

        if (res->dentry != NULL)
                f_dput(res->dentry);
        RETURN(rc);
}

void flip_into_page_cache(struct inode *inode, struct page *new_page)
{
        struct page *old_page;
        int rc;

        do {
                /* the dlm is protecting us from read/write concurrency, so we
                 * expect this find_lock_page to return quickly.  even if we
                 * race with another writer it won't be doing much work with
                 * the page locked.  we do this 'cause t_c_p expects a
                 * locked page, and it wants to grab the pagecache lock
                 * as well. */
                old_page = find_lock_page(inode->i_mapping, new_page->index);
                if (old_page) {
                        ll_truncate_complete_page(old_page);
                        unlock_page(old_page);
                        page_cache_release(old_page);
                }

#if 0 /* this should be a /proc tunable someday */
                /* racing o_directs (no locking ioctl) could race adding
                 * their pages, so we repeat the page invalidation unless
                 * we successfully added our new page */
                rc = add_to_page_cache_unique(new_page, inode->i_mapping,
                                              new_page->index,
                                              page_hash(inode->i_mapping,
                                                        new_page->index));
                if (rc == 0) {
                        /* add_to_page_cache clears uptodate|dirty and locks
                         * the page */
                        SetPageUptodate(new_page);
                        unlock_page(new_page);
                }
#else
                rc = 0;
#endif
        } while (rc != 0);
}

void filter_grant_commit(struct obd_export *exp, int niocount,
                         struct niobuf_local *res)
{
        struct filter_obd *filter = &exp->exp_obd->u.filter;
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

        spin_unlock(&exp->exp_obd->obd_osfs_lock);
}

int filter_commitrw(int cmd, struct obd_export *exp, struct obdo *oa,
                    int objcount, struct obd_ioobj *obj, int niocount,
                    struct niobuf_local *res, struct obd_trans_info *oti,
                    int rc)
{
        if (cmd == OBD_BRW_WRITE)
                return filter_commitrw_write(exp, oa, objcount, obj, niocount,
                                             res, oti, rc);
        if (cmd == OBD_BRW_READ)
                return filter_commitrw_read(exp, oa, objcount, obj, niocount,
                                            res, oti, rc);
        LBUG();
        return -EPROTO;
}

int filter_brw(int cmd, struct obd_export *exp, struct obd_info *oinfo,
               obd_count oa_bufs, struct brw_page *pga,
               struct obd_trans_info *oti)
{
        struct obd_ioobj ioo;
        struct niobuf_local *lnb;
        struct niobuf_remote *rnb;
        obd_count i;
        int ret = 0;
        ENTRY;

        OBD_ALLOC(lnb, oa_bufs * sizeof(struct niobuf_local));
        OBD_ALLOC(rnb, oa_bufs * sizeof(struct niobuf_remote));

        if (lnb == NULL || rnb == NULL)
                GOTO(out, ret = -ENOMEM);

        for (i = 0; i < oa_bufs; i++) {
                lnb[i].page = pga[i].pg;
                rnb[i].offset = pga[i].off;
                rnb[i].len = pga[i].count;
        }

        obdo_to_ioobj(oinfo->oi_oa, &ioo);
        ioo.ioo_bufcnt = oa_bufs;

        ret = filter_preprw(cmd, exp, oinfo->oi_oa, 1, &ioo,
                            oa_bufs, rnb, lnb, oti, oinfo_capa(oinfo));
        if (ret != 0)
                GOTO(out, ret);

        ret = filter_commitrw(cmd, exp, oinfo->oi_oa, 1, &ioo,
                              oa_bufs, lnb, oti, ret);

out:
        if (lnb)
                OBD_FREE(lnb, oa_bufs * sizeof(struct niobuf_local));
        if (rnb)
                OBD_FREE(rnb, oa_bufs * sizeof(struct niobuf_remote));
        RETURN(ret);
}
