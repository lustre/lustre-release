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
#include <asm/div64.h>

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

/* See if there are unallocated parts in given file region */
static int filter_inode_has_holes(struct inode *inode, obd_size start,
                                  int len)
{
        int j;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        sector_t (*fs_bmap)(struct address_space *,
                            sector_t);
#else
        int (*fs_bmap)(struct address_space *, long);
#endif
        fs_bmap = inode->i_mapping->a_ops->bmap;
        if (fs_bmap) {
                for (j = 0; j <= len ; j++) {
                        if (!fs_bmap(inode->i_mapping, start+j)) {
                                return 1;
                        }
                }
                return 0;
        } else {
                /* Return -1 in case that caller cares about bmap availability.
                 */
                return -1;
        }
}
 
/* Grab the dirty and seen grant announcements from the incoming obdo.
 * We will later calculate the clients new grant and return it. */
static void filter_grant_incoming(struct obd_export *exp, struct obdo *oa)
{
        struct filter_export_data *fed;
        struct obd_device *obd = exp->exp_obd;
        obd_size client_cached;
        ENTRY;

        if (!oa || (oa->o_valid & (OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) !=
                                  (OBD_MD_FLBLOCKS|OBD_MD_FLGRANT)) {
                if (oa)
                        oa->o_valid &= ~OBD_MD_FLGRANT;
                EXIT;
                return;
        }

        client_cached = oa->o_blocks;
        fed = &exp->exp_filter_data;

        if (client_cached > fed->fed_grant)
                CERROR("client %s claims "LPU64" granted, > "LPU64" granted\n",
                       obd->obd_name, client_cached, fed->fed_grant);

        spin_lock(&obd->obd_osfs_lock);
        /* update our accounting now so that statfs takes it into account */
        obd->u.filter.fo_tot_cached += client_cached - fed->fed_cached;
        fed->fed_cached = client_cached;

        /* Acknowledgement that the client has seen our published grant.
         * If the client has met our shrinking target we can reuse its
         * difference from the previous grant.  It is reasonable to announce
         * more dirty that cached as it tries to purge its previously granted
         * dirty data down to its newly received target. */
        if (fed->fed_grant_waiting && (oa->o_grant <= fed->fed_grant_sent)) {
                if (fed->fed_grant_sent < fed->fed_grant) {
                        if (client_cached <= fed->fed_grant_sent) {
                                obd->u.filter.fo_tot_granted -=
                                        fed->fed_grant - oa->o_grant;
                                CDEBUG(D_SUPER, "reduced grant from "LPU64" to "
                                       LPU64", total grant now "LPU64"\n",
                                       fed->fed_grant, oa->o_grant,
                                       obd->u.filter.fo_tot_granted);
                                fed->fed_grant = oa->o_grant;
                                fed->fed_grant_waiting = 0;
                        }
                } else {
                        fed->fed_grant_waiting = 0;
                }
        }
        spin_unlock(&obd->obd_osfs_lock);
        oa->o_valid &= ~(OBD_MD_FLGRANT|OBD_MD_FLBLOCKS);
        EXIT;
}

/* Figure out how much space is available between what we've granted
 * and what remains in the filesystem.  Compensate for ext3 indirect
 * block overhead when computing how much free space is left ungranted.
 *
 * Caller must hold obd_osfs_lock. */
obd_size filter_grant_space_left(struct obd_export *exp)
{
        obd_size left = 0;
        struct obd_device *obd = exp->exp_obd;
        int blockbits = obd->u.filter.fo_sb->s_blocksize_bits;
        /* XXX I disabled statfs caching as it only creates extra problems now.
          -- green*/
        unsigned long max_age = jiffies/* - HZ*/+1;
        struct filter_export_data *fed = &exp->exp_filter_data;
        int rc;

restat:
        rc = fsfilt_statfs(obd, obd->u.filter.fo_sb, max_age);
        if (rc) /* N.B. statfs can't really fail, just for correctness */
                RETURN(0);

        left = obd->obd_osfs.os_bavail << blockbits;
        left -= (left >> (blockbits - 2)) + (left >> (2 * blockbits - 2));
        /* We cannot afford having absolutely no space, we need some for
           llog stuff */
        if ( left >= PAGE_SIZE * 10)
                left -= PAGE_SIZE * 10;
        else
                left = 0;

        /* If fed->fed_grant_waiting is set, this means
           obd->u.filter.fo_tot_granted does not represent actual granted
           amount and client is supposedly actively shrinks its cache, so
           no point in printing this warning */
        if (left < obd->u.filter.fo_tot_granted && !fed->fed_grant_waiting)
                CERROR("granted space "LPU64" more than available "LPU64"\n",
                       obd->u.filter.fo_tot_granted, left);

        left -= min(left, obd->u.filter.fo_tot_granted);
        if (left < FILTER_GRANT_CHUNK && time_after(jiffies,obd->obd_osfs_age)){
                CDEBUG(D_SUPER, "fs has no space left and statfs too old\n");
                max_age = jiffies;
                goto restat;
        }

        CDEBUG(D_SUPER, "free: "LPU64" avail: "LPU64" grant left: "LPU64"\n",
               obd->obd_osfs.os_bfree << blockbits,
               obd->obd_osfs.os_bavail << blockbits, left);

        return left;
}

/* When clients have dirtied as much space as they've been granted they
 * fall through to sync writes.  These sync writes haven't been expressed
 * in grants and need to error with ENOSPC when there isn't room in the
 * filesystem for them after grants are taken into account.  However,
 * writeback of the dirty data that was already granted space can write
 * right on through.  We have no need to stop writes that won't allocate
 * new space, so we bmap to calculate how much this io is going to consume.
 *
 * Caller must hold obd_osfs_lock. */
static int filter_check_space(struct obd_export *exp, int objcount,
                              struct fsfilt_objinfo *fso, int niocount,
                              struct niobuf_remote *rnb,
                              struct niobuf_local *lnb, obd_size *left,
                              obd_size *consumed, struct inode *inode)
{
        int blocksize = exp->exp_obd->u.filter.fo_sb->s_blocksize;
        obd_size bytes, ungranted = 0;
        int i, rc = -ENOSPC, obj, n = 0;

        *consumed = 0;

        for (obj = 0; obj < objcount; obj++) {
                for (i = 0; i < fso[obj].fso_bufcnt; i++, n++) {
                        obd_size tmp;

                        bytes = rnb[n].len;
                        tmp = rnb[n].offset & (blocksize - 1);
                        bytes += tmp;
                        tmp = (rnb[n].offset + rnb[n].len) & (blocksize - 1);
                        if (tmp)
                                bytes += blocksize - tmp;

                        if (rnb[n].flags & OBD_BRW_FROM_GRANT) {
                                *consumed += bytes;
                                rc = 0;
                                continue;
                        }
                        if (*left - *consumed >= bytes) {
                                /* if enough space, pretend it was granted */
                                exp->exp_obd->u.filter.fo_tot_granted += bytes;
                                exp->exp_filter_data.fed_grant += bytes;
                                *consumed += bytes;
                                *left -= bytes;
                                rc = 0;
                                continue;
                        } 
                        spin_unlock(&exp->exp_obd->obd_osfs_lock);
                        if (!filter_inode_has_holes(inode,
                                                   rnb[n].offset >>
                                                   inode->i_blkbits,
                                                   rnb[n].len >>
                                                   inode->i_blkbits)) {
                                rc = 0;
                        } else {
                                rc = lnb[n].rc = -ENOSPC;
                        }
                        spin_lock(&exp->exp_obd->obd_osfs_lock);
                        if (rc)
                                goto leave;
                }
        }

        CDEBUG((*consumed != 0 && ungranted != 0) ? D_ERROR : D_SUPER,
               "consumed: "LPU64" ungranted: "LPU64"\n", *consumed, ungranted);

        if (*consumed > exp->exp_filter_data.fed_grant)
                CERROR("request sent from cache, but not enough grant ("LPU64
                       ","LPU64")\n", *consumed,
                       exp->exp_filter_data.fed_grant);
leave:
        return rc;
}

/* Calculate how much grant space to allocate to this client, based on how
 * much space is currently free and how much of that is already granted.
 *
 * Caller must hold obd_osfs_lock. */
static void filter_grant(struct obd_export *exp, struct obdo *oa,
                         obd_size left, obd_size from_grant)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_export_data *fed = &exp->exp_filter_data;
        obd_size grant, extra;
        int blockbits;

        blockbits = obd->u.filter.fo_sb->s_blocksize_bits;

        /* if things go wrong conservatively try to clamp them from
         * generating more dirty data until things are better on our end */
        grant = fed->fed_cached;

        extra = min(FILTER_GRANT_CHUNK, left / 2);

        if (grant > fed->fed_grant) {
                /* If client has screwed up, force basic grant until fixed */
                CERROR("client %s cached more "LPU64" than granted "LPU64"\n",
                       exp->exp_client_uuid.uuid, fed->fed_cached,
                       fed->fed_grant);
                grant = extra;
        } else if (fed->fed_grant_waiting) {
                /* KISS: only one grant change in flight at a time.  We
                 *       could move it in the "same direction" easily,
                 *       but changing directions (e.g. grow then shrink
                 *       before client ACKs) would be bad. */
                grant = fed->fed_grant_sent;
        } else {
                /* grant will shrink or grow as client cache/extra changes */
                grant = fed->fed_cached + extra;
        }

        /* If we've granted all we're willing, we have to revoke
         * the grant covering what the client just wrote. */
        if (left == 0) {
                grant -= min(from_grant, grant);
        }

        if (!fed->fed_grant_waiting && grant + from_grant > left ) {
                if (from_grant < left)
                        grant = left - from_grant;
                else
                        grant = 0;
        }

        if (grant != fed->fed_grant) {
                fed->fed_grant_waiting = 1;
                fed->fed_grant_sent = grant;
                if (grant > fed->fed_grant) {
                        obd->u.filter.fo_tot_granted += grant - fed->fed_grant;
                        fed->fed_grant = grant;
                }
        }

        CDEBUG(D_SUPER,"cli %s cache:"LPU64" grant:"LPU64", granting:"LPU64"\n",
                        exp->exp_connection->c_remote_uuid.uuid, oa->o_blocks,
                        oa->o_grant, grant);
        CDEBUG(D_SUPER, "fed sent:"LPU64" wt:%d grant:"LPU64"\n",
                        fed->fed_grant_sent, fed->fed_grant_waiting,
                        fed->fed_grant);
        CDEBUG(D_SUPER, "tot cached:"LPU64" granted:"LPU64" num_exports: %d\n",
                        obd->u.filter.fo_tot_cached,
                        obd->u.filter.fo_tot_granted, obd->obd_num_exports);

        oa->o_valid |= OBD_MD_FLGRANT;
        oa->o_grant = grant;
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

        if (oa) {
                spin_lock(&obd->obd_osfs_lock);
                filter_grant(exp, oa, filter_grant_space_left(exp), 0);
                spin_unlock(&obd->obd_osfs_lock);
        }

        for (i = 0, o = obj, rnb = nb, lnb = res; i < objcount; i++, o++) {
                dentry = fso[i].fso_dentry;
                inode = dentry->d_inode;

                for (j = 0; j < o->ioo_bufcnt; j++, rnb++, lnb++) {
                        lnb->dentry = dentry;
                        lnb->offset = rnb->offset;
                        lnb->len    = rnb->len;
                        lnb->flags  = rnb->flags;
                        lnb->start  = jiffies;

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

static int filter_start_page_write(struct inode *inode,
                                   struct niobuf_local *lnb)
{
        struct page *page = alloc_pages(GFP_HIGHUSER, 0);
        if (page == NULL) {
                CERROR("no memory for a temp page\n");
                RETURN(lnb->rc = -ENOMEM);
        }
        POISON_PAGE(page, 0xf1);
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
        struct obd_device *obd = exp->exp_obd;
        struct obd_run_ctxt saved;
        struct niobuf_remote *rnb = nb;
        struct niobuf_local *lnb = res;
        struct fsfilt_objinfo fso;
        struct dentry *dentry;
        int rc = 0, i, tot_bytes = 0;
        obd_size consumed = 0, left;
        unsigned long now = jiffies;
        ENTRY;
        LASSERT(objcount == 1);
        LASSERT(obj->ioo_bufcnt > 0);

        filter_grant_incoming(exp, oa);

        memset(res, 0, niocount * sizeof(*res));

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        dentry = filter_fid2dentry(obd, NULL, obj->ioo_gr, obj->ioo_id);
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

        spin_lock(&obd->obd_osfs_lock);
        left = filter_grant_space_left(exp);

        rc = filter_check_space(exp, objcount, &fso, niocount, rnb, lnb,
                                &left, &consumed, dentry->d_inode);
        if (oa)
                filter_grant(exp, oa, left, consumed);

        spin_unlock(&obd->obd_osfs_lock);

        if (rc) {
                f_dput(dentry);
                GOTO(cleanup, rc);
        }

        for (i = 0, rnb = nb, lnb = res; i < obj->ioo_bufcnt;
             i++, lnb++, rnb++) {

                /* If there were any granting failures, we should not have
                   come here */
                LASSERT (lnb->rc == 0);

                lnb->dentry = dentry;
                lnb->offset = rnb->offset;
                lnb->len    = rnb->len;
                lnb->flags  = rnb->flags;
                lnb->start  = jiffies;

                rc = filter_start_page_write(dentry->d_inode, lnb);
                if (rc) {
                        CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR, "page err %u@"
                               LPU64" %u/%u %p: rc %d\n", lnb->len, lnb->offset,
                               i, obj->ioo_bufcnt, dentry, rc);
                        while (lnb-- > res)
                                __free_pages(lnb->page, 0);
                        f_dput(dentry);
                        GOTO(cleanup, rc);
                }
                tot_bytes += lnb->len;
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow start_page_write %lus\n", (jiffies - now) / HZ);
        else
                CDEBUG(D_INFO, "start_page_write: %lu jiffies\n",
                       (jiffies - now));

        lprocfs_counter_add(obd->obd_stats, LPROC_FILTER_WRITE_BYTES, tot_bytes);
        EXIT;
cleanup:
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);
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
                                struct obd_trans_info *oti)
{
        struct obd_ioobj *o;
        struct niobuf_local *lnb;
        int i, j;
        ENTRY;

        for (i = 0, o = obj, lnb = res; i < objcount; i++, o++) {
                for (j = 0 ; j < o->ioo_bufcnt ; j++, lnb++) {
                        if (lnb->page != NULL)
                                page_cache_release(lnb->page);
                }
        }
        if (res->dentry != NULL)
                f_dput(res->dentry);
        RETURN(0);
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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                        truncate_complete_page(old_page);
#else
                        truncate_complete_page(old_page->mapping, old_page);
#endif
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

/* XXX needs to trickle its oa down */
int filter_commitrw(int cmd, struct obd_export *exp, struct obdo *oa,
                    int objcount, struct obd_ioobj *obj, int niocount,
                    struct niobuf_local *res, struct obd_trans_info *oti)
{
        if (cmd == OBD_BRW_WRITE)
                return filter_commitrw_write(exp, oa, objcount, obj, niocount,
                                             res, oti);
        if (cmd == OBD_BRW_READ)
                return filter_commitrw_read(exp, oa, objcount, obj, niocount,
                                            res, oti);
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

        ret = filter_commitrw(cmd, exp, oa, 1, &ioo, oa_bufs, lnb, oti);

out:
        if (lnb)
                OBD_FREE(lnb, oa_bufs * sizeof(struct niobuf_local));
        if (rnb)
                OBD_FREE(rnb, oa_bufs * sizeof(struct niobuf_remote));
        RETURN(ret);
}
