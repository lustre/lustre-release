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
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/pagemap.h> // XXX kill me soon
#include <linux/version.h>

#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include "filter_internal.h"

static int filter_start_page_read(struct inode *inode, struct niobuf_local *lnb)
{
        struct address_space *mapping = inode->i_mapping;
        struct page *page;
        unsigned long index = lnb->offset >> PAGE_SHIFT;
        int rc;

        page = grab_cache_page(mapping, index); /* locked page */
        if (page == NULL)
                return lnb->rc = -ENOMEM;

        LASSERT(page->mapping == mapping);

        lnb->page = page;

        if (inode->i_size < lnb->offset + lnb->len - 1)
                lnb->rc = inode->i_size - lnb->offset;
        else
                lnb->rc = lnb->len;

        if (PageUptodate(page)) {
                unlock_page(page);
                return 0;
        }

        rc = mapping->a_ops->readpage(NULL, page);
        if (rc < 0) {
                CERROR("page index %lu, rc = %d\n", index, rc);
                lnb->page = NULL;
                page_cache_release(page);
                return lnb->rc = rc;
        }

        return 0;
}

static int filter_finish_page_read(struct niobuf_local *lnb)
{
        if (lnb->page == NULL)
                return 0;

        if (PageUptodate(lnb->page))
                return 0;

        wait_on_page(lnb->page);
        if (!PageUptodate(lnb->page)) {
                CERROR("page index %lu/offset "LPX64" not uptodate\n",
                       lnb->page->index, lnb->offset);
                GOTO(err_page, lnb->rc = -EIO);
        }
        if (PageError(lnb->page)) {
                CERROR("page index %lu/offset "LPX64" has error\n",
                       lnb->page->index, lnb->offset);
                GOTO(err_page, lnb->rc = -EIO);
        }

        return 0;

err_page:
        page_cache_release(lnb->page);
        lnb->page = NULL;
        return lnb->rc;
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
        CDEBUG(oa->o_grant > fed->fed_grant + FILTER_GRANT_CHUNK ?
               D_WARNING : D_CACHE,
               "%s: cli %s/%p reports grant: "LPU64" dropped: %u, local: %lu\n",
               obd->obd_name, exp->exp_client_uuid.uuid, exp, oa->o_grant,
               oa->o_dropped, fed->fed_grant);

        /* Update our accounting now so that statfs takes it into account.
         * Note that fed_dirty is only approximate and can become incorrect
         * if RPCs arrive out-of-order.  No important calculations depend
         * on fed_dirty however. */
        obd->u.filter.fo_tot_dirty += oa->o_dirty - fed->fed_dirty;
        if (fed->fed_grant < oa->o_dropped) {
                CERROR("%s: cli %s/%p reports %u dropped > fed_grant %lu\n",
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
        EXIT;
}

#define GRANT_FOR_LLOG(obd) 16

/* Figure out how much space is available between what we've granted
 * and what remains in the filesystem.  Compensate for ext3 indirect
 * block overhead when computing how much free space is left ungranted.
 *
 * Caller must hold obd_osfs_lock. */
obd_size filter_grant_space_left(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        int blockbits = obd->u.filter.fo_sb->s_blocksize_bits;
        obd_size tot_granted = obd->u.filter.fo_tot_granted, avail, left = 0;
        int rc, statfs_done = 0;

        LASSERT_SPIN_LOCKED(&obd->obd_osfs_lock);

        if (time_before(obd->obd_osfs_age, jiffies - HZ)) {
restat:
                rc = fsfilt_statfs(obd, obd->u.filter.fo_sb, jiffies + 1);
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
                static unsigned long next;
                if (left < tot_granted - obd->u.filter.fo_tot_pending &&
                    time_after(jiffies, next)) {
                        spin_unlock(&obd->obd_osfs_lock);
                        CERROR("%s: cli %s/%p grant "LPU64" > available "
                               LPU64" and pending "LPU64"\n", obd->obd_name,
                               exp->exp_client_uuid.uuid, exp, tot_granted,
                               left, obd->u.filter.fo_tot_pending);
                        if (next == 0)
                                portals_debug_dumplog();
                        next = jiffies + 20 * HZ;
                        spin_lock(&obd->obd_osfs_lock);
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
        int blockbits = obd->u.filter.fo_sb->s_blocksize_bits;
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
        if (current_grant < want) {
                if (current_grant > fed->fed_grant + FILTER_GRANT_CHUNK)
                        want = 65536;
                grant = min((want >> blockbits) / 2,
                            (fs_space_left >> blockbits) / 8);
                grant <<= blockbits;

                if (grant) {
                        if (grant > FILTER_GRANT_CHUNK)
                                grant = FILTER_GRANT_CHUNK;

                        obd->u.filter.fo_tot_granted += grant;
                        fed->fed_grant += grant;
                }
        }

        CDEBUG(D_CACHE,"%s: cli %s/%p wants: "LPU64" granting: "LPU64"\n",
               obd->obd_name, exp->exp_client_uuid.uuid, exp, want, grant);
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
                              struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_run_ctxt saved;
        struct obd_ioobj *o;
        struct niobuf_remote *rnb;
        struct niobuf_local *lnb = NULL;
        struct fsfilt_objinfo *fso;
        struct dentry *dentry;
        struct inode *inode;
        int rc = 0, i, j, tot_bytes = 0, cleanup_phase = 0;
        unsigned long now = jiffies;
        ENTRY;

        /* We are currently not supporting multi-obj BRW_READ RPCS at all.
         * When we do this function's dentry cleanup will need to be fixed */
        LASSERT(objcount == 1);
        LASSERT(obj->ioo_bufcnt > 0);

        if (oa && oa->o_valid & OBD_MD_FLGRANT) {
                spin_lock(&obd->obd_osfs_lock);
                filter_grant_incoming(exp, oa);

#if 0
                /* Reads do not increase grants */
                oa->o_grant = filter_grant(exp, oa->o_grant, oa->o_undirty,
                                           filter_grant_space_left(exp));
#else
                oa->o_grant = 0;
#endif
                spin_unlock(&obd->obd_osfs_lock);
        }

        OBD_ALLOC(fso, objcount * sizeof(*fso));
        if (fso == NULL)
                RETURN(-ENOMEM);

        memset(res, 0, niocount * sizeof(*res));

        push_ctxt(&saved, &exp->exp_obd->obd_ctxt, NULL);
        for (i = 0, o = obj; i < objcount; i++, o++) {
                LASSERT(o->ioo_bufcnt);

                dentry = filter_oa2dentry(obd, oa);
                if (IS_ERR(dentry))
                        GOTO(cleanup, rc = PTR_ERR(dentry));

                if (dentry->d_inode == NULL) {
                        CERROR("trying to BRW to non-existent file "LPU64"\n",
                               o->ioo_id);
                        f_dput(dentry);
                        GOTO(cleanup, rc = -ENOENT);
                }

                fso[i].fso_dentry = dentry;
                fso[i].fso_bufcnt = o->ioo_bufcnt;
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow preprw_read setup %lus\n", (jiffies - now) / HZ);
        else
                CDEBUG(D_INFO, "preprw_read setup: %lu jiffies\n",
                       (jiffies - now));

        for (i = 0, o = obj, rnb = nb, lnb = res; i < objcount; i++, o++) {
                dentry = fso[i].fso_dentry;
                inode = dentry->d_inode;

                for (j = 0; j < o->ioo_bufcnt; j++, rnb++, lnb++) {
                        lnb->dentry = dentry;
                        lnb->offset = rnb->offset;
                        lnb->len    = rnb->len;
                        lnb->flags  = rnb->flags;

                        if (inode->i_size <= rnb->offset) {
                                /* If there's no more data, abort early.
                                 * lnb->page == NULL and lnb->rc == 0, so it's
                                 * easy to detect later. */
                                break;
                        } else {
                                rc = filter_start_page_read(inode, lnb);
                        }

                        if (rc) {
                                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                                       "page err %u@"LPU64" %u/%u %p: rc %d\n",
                                       lnb->len, lnb->offset, j, o->ioo_bufcnt,
                                       dentry, rc);
                                cleanup_phase = 1;
                                GOTO(cleanup, rc);
                        }

                        tot_bytes += lnb->rc;
                        if (lnb->rc < lnb->len) {
                                /* short read, be sure to wait on it */
                                lnb++;
                                break;
                        }
                }
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow start_page_read %lus\n", (jiffies - now) / HZ);
        else
                CDEBUG(D_INFO, "start_page_read: %lu jiffies\n",
                       (jiffies - now));

        lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_READ_BYTES, tot_bytes);
        while (lnb-- > res) {
                rc = filter_finish_page_read(lnb);
                if (rc) {
                        CERROR("error page %u@"LPU64" %u %p: rc %d\n", lnb->len,
                               lnb->offset, (int)(lnb - res), lnb->dentry, rc);
                        cleanup_phase = 1;
                        GOTO(cleanup, rc);
                }
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow finish_page_read %lus\n", (jiffies - now) / HZ);
        else
                CDEBUG(D_INFO, "finish_page_read: %lu jiffies\n",
                       (jiffies - now));

        filter_tally_read(&exp->exp_obd->u.filter, res, niocount);

        EXIT;

 cleanup:
        switch (cleanup_phase) {
        case 1:
                for (lnb = res; lnb < (res + niocount); lnb++) {
                        if (lnb->page)
                                page_cache_release(lnb->page);
                }
                if (res->dentry != NULL)
                        f_dput(res->dentry);
                else
                        CERROR("NULL dentry in cleanup -- tell CFS\n");
        case 0:
                OBD_FREE(fso, objcount * sizeof(*fso));
                pop_ctxt(&saved, &exp->exp_obd->obd_ctxt, NULL);
        }
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
static int filter_grant_check(struct obd_export *exp, int objcount,
                              struct fsfilt_objinfo *fso, int niocount,
                              struct niobuf_remote *rnb,
                              struct niobuf_local *lnb, obd_size *left,
                              struct inode *inode)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        int blocksize = exp->exp_obd->u.filter.fo_sb->s_blocksize;
        unsigned long used = 0, ungranted = 0, using;
        int i, rc = -ENOSPC, obj, n = 0, mask = D_CACHE;

        LASSERT_SPIN_LOCKED(&exp->exp_obd->obd_osfs_lock);

        for (obj = 0; obj < objcount; obj++) {
                for (i = 0; i < fso[obj].fso_bufcnt; i++, n++) {
                        int tmp, bytes;

                        /* FIXME: this is calculated with PAGE_SIZE on client */
                        bytes = rnb[n].len;
                        bytes += rnb[n].offset & (blocksize - 1);
                        tmp = (rnb[n].offset + rnb[n].len) & (blocksize - 1);
                        if (tmp)
                                bytes += blocksize - tmp;

                        if (rnb[n].flags & OBD_BRW_FROM_GRANT) {
                                if (fed->fed_grant < used + bytes) {
                                        CDEBUG(D_CACHE,
                                               "%s: cli %s/%p claims %ld+%d "
                                               "GRANT, real grant %lu idx %d\n",
                                               exp->exp_obd->obd_name,
                                               exp->exp_client_uuid.uuid, exp,
                                               used, bytes, fed->fed_grant, n);
                                        mask = D_ERROR;
                                } else {
                                        used += bytes;
                                        rnb[n].flags |= OBD_BRW_GRANTED;
                                        lnb[n].lnb_grant_used = bytes;
                                        CDEBUG(0, "idx %d used=%lu\n", n, used);
                                        rc = 0;
                                        continue;
                                }
                        }
                        if (*left > ungranted) {
                                /* if enough space, pretend it was granted */
                                ungranted += bytes;
                                rnb[n].flags |= OBD_BRW_GRANTED;
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
                        rnb[n].flags &= OBD_BRW_GRANTED;
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
        fed->fed_pending += used;
        exp->exp_obd->u.filter.fo_tot_pending += used;

        CDEBUG(mask,
               "%s: cli %s/%p used: %lu ungranted: %lu grant: %lu dirty: %lu\n",
               exp->exp_obd->obd_name, exp->exp_client_uuid.uuid, exp, used,
               ungranted, fed->fed_grant, fed->fed_dirty);

        /* Rough calc in case we don't refresh cached statfs data */
        using = (used + ungranted + 1 ) >>
                exp->exp_obd->u.filter.fo_sb->s_blocksize_bits;
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

        return rc;
}

static int filter_start_page_write(struct inode *inode,
                                   struct niobuf_local *lnb)
{
        struct page *page = alloc_pages(GFP_HIGHUSER, 0);
        if (page == NULL) {
                CERROR("no memory for a temp page\n");
                RETURN(lnb->rc = -ENOMEM);
        }
        POISON_PAGE(page, 0xf1);
        if (lnb->len != PAGE_SIZE) {
                memset(kmap(page) + lnb->len, 0, PAGE_SIZE - lnb->len);
                kunmap(page);
        }
        page->index = lnb->offset >> PAGE_SHIFT;
        lnb->page = page;

        return 0;
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
                               struct obd_trans_info *oti)
{
        struct obd_run_ctxt saved;
        struct niobuf_remote *rnb;
        struct niobuf_local *lnb;
        struct fsfilt_objinfo fso;
        struct dentry *dentry;
        obd_size left;
        unsigned long now = jiffies;
        int rc = 0, i, tot_bytes = 0, cleanup_phase = 1;
        ENTRY;
        LASSERT(objcount == 1);
        LASSERT(obj->ioo_bufcnt > 0);

        memset(res, 0, niocount * sizeof(*res));

        push_ctxt(&saved, &exp->exp_obd->obd_ctxt, NULL);
        dentry = filter_fid2dentry(exp->exp_obd, NULL, obj->ioo_gr,
                                   obj->ioo_id);
        if (IS_ERR(dentry))
                GOTO(cleanup, rc = PTR_ERR(dentry));

        if (dentry->d_inode == NULL) {
                CERROR("trying to BRW to non-existent file "LPU64"\n",
                       obj->ioo_id);
                f_dput(dentry);
                GOTO(cleanup, rc = -ENOENT);
        }

        fso.fso_dentry = dentry;
        fso.fso_bufcnt = obj->ioo_bufcnt;

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow preprw_write setup %lus\n", (jiffies - now) / HZ);
        else
                CDEBUG(D_INFO, "preprw_write setup: %lu jiffies\n",
                       (jiffies - now));

        spin_lock(&exp->exp_obd->obd_osfs_lock);
        if (oa)
                filter_grant_incoming(exp, oa);
        cleanup_phase = 0;

        left = filter_grant_space_left(exp);

        rc = filter_grant_check(exp, objcount, &fso, niocount, nb, res,
                                &left, dentry->d_inode);
        if (oa && oa->o_valid & OBD_MD_FLGRANT)
                oa->o_grant = filter_grant(exp,oa->o_grant,oa->o_undirty,left);

        spin_unlock(&exp->exp_obd->obd_osfs_lock);

        if (rc) {
                f_dput(dentry);
                GOTO(cleanup, rc);
        }

        for (i = 0, rnb = nb, lnb = res; i < obj->ioo_bufcnt;
             i++, lnb++, rnb++) {
                /* We still set up for ungranted pages so that granted pages
                 * can be written to disk as they were promised, and portals
                 * needs to keep the pages all aligned properly. */ 
                lnb->dentry = dentry;
                lnb->offset = rnb->offset;
                lnb->len    = rnb->len;
                lnb->flags  = rnb->flags;

                rc = filter_start_page_write(dentry->d_inode, lnb);
                if (rc) {
                        CERROR("page err %u@"LPU64" %u/%u %p: rc %d\n",
                               lnb->len, lnb->offset,
                               i, obj->ioo_bufcnt, dentry, rc);
                        while (lnb-- > res)
                                __free_pages(lnb->page, 0);
                        f_dput(dentry);
                        GOTO(cleanup, rc);
                }
                if (lnb->rc == 0)
                        tot_bytes += lnb->len;
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow start_page_write %lus\n", (jiffies - now) / HZ);
        else
                CDEBUG(D_INFO, "start_page_write: %lu jiffies\n",
                       (jiffies - now));

        lprocfs_counter_add(exp->exp_obd->obd_stats, LPROC_FILTER_WRITE_BYTES,
                            tot_bytes);
        EXIT;
cleanup:
        switch(cleanup_phase) {
        case 1:
                spin_lock(&exp->exp_obd->obd_osfs_lock);
                if (oa)
                        filter_grant_incoming(exp, oa);
                spin_unlock(&exp->exp_obd->obd_osfs_lock);
        default: ;
        }
        pop_ctxt(&saved, &exp->exp_obd->obd_ctxt, NULL);
        return rc;
}

int filter_preprw(int cmd, struct obd_export *exp, struct obdo *oa,
                  int objcount, struct obd_ioobj *obj, int niocount,
                  struct niobuf_remote *nb, struct niobuf_local *res,
                  struct obd_trans_info *oti)
{
        if (cmd == OBD_BRW_WRITE)
                return filter_preprw_write(cmd, exp, oa, objcount, obj,
                                           niocount, nb, res, oti);

        if (cmd == OBD_BRW_READ)
                return filter_preprw_read(cmd, exp, oa, objcount, obj,
                                          niocount, nb, res, oti);

        LBUG();
        return -EPROTO;
}

static int filter_commitrw_read(struct obd_export *exp, struct obdo *oa,
                                int objcount, struct obd_ioobj *obj,
                                int niocount, struct niobuf_local *res,
                                struct obd_trans_info *oti, int rc)
{
        struct obd_ioobj *o;
        struct niobuf_local *lnb;
        int i, j, drop = 0;
        ENTRY;

        if (res->dentry != NULL)
                drop = (res->dentry->d_inode->i_size >
                        exp->exp_obd->u.filter.fo_readcache_max_filesize);

        for (i = 0, o = obj, lnb = res; i < objcount; i++, o++) {
                for (j = 0 ; j < o->ioo_bufcnt ; j++, lnb++) {
                        if (lnb->page == NULL)
                                continue;
                        /* drop from cache like truncate_list_pages() */
                        if (drop && !TryLockPage(lnb->page)) {
                                if (lnb->page->mapping)
                                        ll_truncate_complete_page(lnb->page);
                                unlock_page(lnb->page);
                        }
                        page_cache_release(lnb->page);
                }
        }

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
                    struct niobuf_local *res, struct obd_trans_info *oti,int rc)
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

int filter_brw(int cmd, struct obd_export *exp, struct obdo *oa,
               struct lov_stripe_md *lsm, obd_count oa_bufs,
               struct brw_page *pga, struct obd_trans_info *oti)
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
                rnb[i].offset = pga[i].off;
                rnb[i].len = pga[i].count;
        }

        obdo_to_ioobj(oa, &ioo);
        ioo.ioo_bufcnt = oa_bufs;

        ret = filter_preprw(cmd, exp, oa, 1, &ioo, oa_bufs, rnb, lnb, oti);
        if (ret != 0)
                GOTO(out, ret);

        for (i = 0; i < oa_bufs; i++) {
                void *virt = kmap(pga[i].pg);
                obd_off off = pga[i].off & ~PAGE_MASK;
                void *addr = kmap(lnb[i].page);

                /* 2 kmaps == vanishingly small deadlock opportunity */

                if (cmd & OBD_BRW_WRITE)
                        memcpy(addr + off, virt + off, pga[i].count);
                else
                        memcpy(virt + off, addr + off, pga[i].count);

                kunmap(lnb[i].page);
                kunmap(pga[i].pg);
        }

        ret = filter_commitrw(cmd, exp, oa, 1, &ioo, oa_bufs, lnb, oti, ret);

out:
        if (lnb)
                OBD_FREE(lnb, oa_bufs * sizeof(struct niobuf_local));
        if (rnb)
                OBD_FREE(rnb, oa_bufs * sizeof(struct niobuf_remote));
        RETURN(ret);
}
