/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light block IO
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_LLITE

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <fcntl.h>

#include <sysio.h>
#include <fs.h>
#include <mount.h>
#include <inode.h>
#include <file.h>

#undef LIST_HEAD

#include "llite_lib.h"

static int llu_lock_to_stripe_offset(struct inode *inode, struct ldlm_lock *lock)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obd_export *exp = llu_i2obdexp(inode);
        struct {
                char name[16];
                struct ldlm_lock *lock;
                struct lov_stripe_md *lsm;
        } key = { .name = "lock_to_stripe", .lock = lock, .lsm = lsm };
        __u32 stripe, vallen = sizeof(stripe);
        int rc;
        ENTRY;

        if (lsm->lsm_stripe_count == 1)
                RETURN(0);

        /* get our offset in the lov */
        rc = obd_get_info(exp, sizeof(key), &key, &vallen, &stripe);
        if (rc != 0) {
                CERROR("obd_get_info: rc = %d\n", rc);
                LBUG();
        }
        LASSERT(stripe < lsm->lsm_stripe_count);
        RETURN(stripe);
}

static int llu_extent_lock_callback(struct ldlm_lock *lock,
                                    struct ldlm_lock_desc *new, void *data,
                                    int flag)
{
        struct lustre_handle lockh = { 0 };
        int rc;
        ENTRY;

        if ((unsigned long)data > 0 && (unsigned long)data < 0x1000) {
                LDLM_ERROR(lock, "cancelling lock with bad data %p", data);
                LBUG();
        }

        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc != ELDLM_OK)
                        CERROR("ldlm_cli_cancel failed: %d\n", rc);
                break;
        case LDLM_CB_CANCELING: {
                struct inode *inode;
                struct llu_inode_info *lli;
                struct lov_stripe_md *lsm;
                __u32 stripe;
                __u64 kms;

                /* This lock wasn't granted, don't try to evict pages */
                if (lock->l_req_mode != lock->l_granted_mode)
                        RETURN(0);

                inode = llu_inode_from_lock(lock);
                if (!inode)
                        RETURN(0);
                lli= llu_i2info(inode);
                if (!lli)
                        goto iput;
                if (!lli->lli_smd)
                        goto iput;
                lsm = lli->lli_smd;

                stripe = llu_lock_to_stripe_offset(inode, lock);
                kms = ldlm_extent_shift_kms(lock,
                                            lsm->lsm_oinfo[stripe].loi_kms);
                if (lsm->lsm_oinfo[stripe].loi_kms != kms)
                        LDLM_DEBUG(lock, "updating kms from "LPU64" to "LPU64,
                                   lsm->lsm_oinfo[stripe].loi_kms, kms);
                lsm->lsm_oinfo[stripe].loi_kms = kms;
iput:
                I_RELE(inode);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

static int llu_glimpse_callback(struct ldlm_lock *lock, void *reqp)
{
        struct ptlrpc_request *req = reqp;
        struct inode *inode = llu_inode_from_lock(lock);
        struct llu_inode_info *lli;
        struct ost_lvb *lvb;
        int rc, size = sizeof(*lvb), stripe = 0;
        ENTRY;

        if (inode == NULL)
                GOTO(out, rc = -ELDLM_NO_LOCK_DATA);
        lli = llu_i2info(inode);
        if (lli == NULL)
                GOTO(iput, rc = -ELDLM_NO_LOCK_DATA);
        if (lli->lli_smd == NULL)
                GOTO(iput, rc = -ELDLM_NO_LOCK_DATA);

        /* First, find out which stripe index this lock corresponds to. */
        if (lli->lli_smd->lsm_stripe_count > 1)
                stripe = llu_lock_to_stripe_offset(inode, lock);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc) {
                CERROR("lustre_pack_reply: %d\n", rc);
                GOTO(iput, rc);
        }

        lvb = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*lvb));
        lvb->lvb_size = lli->lli_smd->lsm_oinfo[stripe].loi_kms;

        LDLM_DEBUG(lock, "i_size: %llu -> stripe number %u -> kms "LPU64,
                   lli->lli_st_size, stripe, lvb->lvb_size);
 iput:
        I_RELE(inode);
 out:
        /* These errors are normal races, so we don't want to fill the console
         * with messages by calling ptlrpc_error() */
        if (rc == -ELDLM_NO_LOCK_DATA)
                lustre_pack_reply(req, 0, NULL, NULL);

        req->rq_status = rc;
        return rc;
}

__u64 lov_merge_size(struct lov_stripe_md *lsm, int kms);
__u64 lov_merge_mtime(struct lov_stripe_md *lsm, __u64 current_time);

/* NB: lov_merge_size will prefer locally cached writes if they extend the
 * file (because it prefers KMS over RSS when larger) */
int llu_glimpse_size(struct inode *inode, struct ost_lvb *lvb)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        ldlm_policy_data_t policy = { .l_extent = { 0, OBD_OBJECT_EOF } };
        struct lustre_handle lockh = { 0 };
        int rc, flags = LDLM_FL_HAS_INTENT;
        ENTRY;

        CDEBUG(D_DLMTRACE, "Glimpsing inode %lu\n", lli->lli_st_ino);

        rc = obd_enqueue(sbi->ll_osc_exp, lli->lli_smd, LDLM_EXTENT, &policy,
                         LCK_PR, &flags, llu_extent_lock_callback,
                         ldlm_completion_ast, llu_glimpse_callback, inode,
                         sizeof(*lvb), lustre_swab_ost_lvb, &lockh);
        if (rc > 0)
                RETURN(-EIO);

        lvb->lvb_size = lov_merge_size(lli->lli_smd, 0);
        //inode->i_mtime = lov_merge_mtime(lli->lli_smd, inode->i_mtime);

        CDEBUG(D_DLMTRACE, "glimpse: size: "LPU64"\n", lvb->lvb_size);

        obd_cancel(sbi->ll_osc_exp, lli->lli_smd, LCK_PR, &lockh);

        RETURN(rc);
}

int llu_extent_lock(struct ll_file_data *fd, struct inode *inode,
                    struct lov_stripe_md *lsm, int mode,
                    ldlm_policy_data_t *policy, struct lustre_handle *lockh,
                    int ast_flags)
{
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct llu_inode_info *lli = llu_i2info(inode);
        int rc;
        ENTRY;

        LASSERT(lockh->cookie == 0);

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        CDEBUG(D_DLMTRACE, "Locking inode %lu, start "LPU64" end "LPU64"\n",
               lli->lli_st_ino, policy->l_extent.start, policy->l_extent.end);

        rc = obd_enqueue(sbi->ll_osc_exp, lsm, LDLM_EXTENT, policy, mode,
                         &ast_flags, llu_extent_lock_callback,
                         ldlm_completion_ast, llu_glimpse_callback, inode,
                         sizeof(struct ost_lvb), lustre_swab_ost_lvb, lockh);
        if (rc > 0)
                rc = -EIO;

        if (policy->l_extent.start == 0 &&
            policy->l_extent.end == OBD_OBJECT_EOF)
                lli->lli_st_size = lov_merge_size(lsm, 1);

        //inode->i_mtime = lov_merge_mtime(lsm, inode->i_mtime);

        RETURN(rc);
}

#if 0
int llu_extent_lock_no_validate(struct ll_file_data *fd,
                                struct inode *inode,
                                struct lov_stripe_md *lsm,
                                int mode,
                                struct ldlm_extent *extent,
                                struct lustre_handle *lockh,
                                int ast_flags)
{
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct llu_inode_info *lli = llu_i2info(inode);
        int rc;
        ENTRY;

        LASSERT(lockh->cookie == 0);

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        CDEBUG(D_DLMTRACE, "Locking inode %lu, start "LPU64" end "LPU64"\n",
               lli->lli_st_ino, extent->start, extent->end);

        rc = obd_enqueue(sbi->ll_osc_exp, lsm, NULL, LDLM_EXTENT, extent,
                         sizeof(extent), mode, &ast_flags,
                         llu_extent_lock_callback, inode, lockh);

        RETURN(rc);
}

/*
 * this grabs a lock and manually implements behaviour that makes it look like
 * the OST is returning the file size with each lock acquisition.
 */
int llu_extent_lock(struct ll_file_data *fd, struct inode *inode,
                    struct lov_stripe_md *lsm, int mode,
                    struct ldlm_extent *extent, struct lustre_handle *lockh,
                    int nonblock)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct obd_export *exp = llu_i2obdexp(inode);
        struct ldlm_extent size_lock;
        struct lustre_handle match_lockh = {0};
        int flags, rc, matched;
        int astflags = nonblock ? LDLM_FL_BLOCK_NOWAIT : 0;
        ENTRY;

        rc = llu_extent_lock_no_validate(fd, inode, lsm, mode, extent,
                                         lockh, astflags);
        if (rc != ELDLM_OK)
                RETURN(rc);

        if (test_bit(LLI_F_HAVE_OST_SIZE_LOCK, &lli->lli_flags))
                RETURN(0);

        rc = llu_inode_getattr(inode, lsm);
        if (rc) {
                llu_extent_unlock(fd, inode, lsm, mode, lockh);
                RETURN(rc);
        }

        size_lock.start = lli->lli_st_size;
        size_lock.end = OBD_OBJECT_EOF;

        /* XXX I bet we should be checking the lock ignore flags.. */
        /* FIXME use LDLM_FL_TEST_LOCK instead */
        flags = LDLM_FL_CBPENDING | LDLM_FL_BLOCK_GRANTED;
        matched = obd_match(exp, lsm, LDLM_EXTENT, &size_lock,
                            sizeof(size_lock), LCK_PR, &flags, inode,
                            &match_lockh);

        /* hey, alright, we hold a size lock that covers the size we
         * just found, its not going to change for a while.. */
        if (matched == 1) {
                set_bit(LLI_F_HAVE_OST_SIZE_LOCK, &lli->lli_flags);
                obd_cancel(exp, lsm, LCK_PR, &match_lockh);
        }

        RETURN(0);
}
#endif

int llu_extent_unlock(struct ll_file_data *fd, struct inode *inode,
                struct lov_stripe_md *lsm, int mode,
                struct lustre_handle *lockh)
{
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        int rc;
        ENTRY;

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        rc = obd_cancel(sbi->ll_osc_exp, lsm, mode, lockh);

        RETURN(rc);
}

#define LLAP_MAGIC 12346789

struct ll_async_page {
        int             llap_magic;
        void           *llap_cookie;
        int             llap_queued;
        struct page    *llap_page;
        struct inode   *llap_inode;
};

static struct ll_async_page *llap_from_cookie(void *cookie)
{
        struct ll_async_page *llap = cookie;
        if (llap->llap_magic != LLAP_MAGIC)
                return ERR_PTR(-EINVAL);
        return llap;
};

static void llu_ap_fill_obdo(void *data, int cmd, struct obdo *oa)
{
        struct ll_async_page *llap;
        struct inode *inode;
        struct lov_stripe_md *lsm;
        obd_flag valid_flags;
        ENTRY;

        llap = llap_from_cookie(data);
        if (IS_ERR(llap)) {
                EXIT;
                return;
        }

        inode = llap->llap_inode;
        lsm = llu_i2info(inode)->lli_smd;

        oa->o_id = lsm->lsm_object_id;
        oa->o_valid = OBD_MD_FLID;
        valid_flags = OBD_MD_FLTYPE | OBD_MD_FLATIME;
        if (cmd == OBD_BRW_WRITE)
                valid_flags |= OBD_MD_FLMTIME | OBD_MD_FLCTIME;

        obdo_from_inode(oa, inode, valid_flags);
        EXIT;
}

/* called for each page in a completed rpc.*/
static void llu_ap_completion(void *data, int cmd, struct obdo *oa, int rc)
{
        struct ll_async_page *llap;
        struct page *page;

        llap = llap_from_cookie(data);
        if (IS_ERR(llap)) {
                EXIT;
                return;
        }

        llap->llap_queued = 0;
        page = llap->llap_page;

        if (rc != 0) {
                if (cmd == OBD_BRW_WRITE)
                        CERROR("writeback error on page %p index %ld: %d\n", 
                               page, page->index, rc);
        }
        EXIT;
}

static struct obd_async_page_ops llu_async_page_ops = {
        .ap_make_ready =        NULL,
        .ap_refresh_count =     NULL,
        .ap_fill_obdo =         llu_ap_fill_obdo,
        .ap_completion =        llu_ap_completion,
};

static
struct llu_sysio_cookie* get_sysio_cookie(struct inode *inode, int maxpages)
{
        struct llu_sysio_cookie *cookie;
        int rc;

        OBD_ALLOC(cookie, LLU_SYSIO_COOKIE_SIZE(maxpages));
        if (cookie == NULL)
                goto out;

        I_REF(inode);
        cookie->lsc_inode = inode;
        cookie->lsc_maxpages = maxpages;
        cookie->lsc_llap = (struct ll_async_page *)(cookie + 1);
        cookie->lsc_pages = (struct page *) (cookie->lsc_llap + maxpages);

        rc = oig_init(&cookie->lsc_oig);
        if (rc) {
                OBD_FREE(cookie, LLU_SYSIO_COOKIE_SIZE(maxpages));
                cookie = NULL;
        }

out:
        return cookie;
}

static
void put_sysio_cookie(struct llu_sysio_cookie *cookie)
{
        struct lov_stripe_md *lsm = llu_i2info(cookie->lsc_inode)->lli_smd;
        struct obd_export *exp = llu_i2obdexp(cookie->lsc_inode);
        struct ll_async_page *llap = cookie->lsc_llap;
#ifdef LIBLUSTRE_HANDLE_UNALIGNED_PAGE
        struct page *pages = cookie->lsc_pages;
#endif
        int i;

        for (i = 0; i< cookie->lsc_maxpages; i++) {
                if (llap[i].llap_cookie)
                        obd_teardown_async_page(exp, lsm, NULL,
                                                llap[i].llap_cookie);
#ifdef LIBLUSTRE_HANDLE_UNALIGNED_PAGE
                if (pages[i]._managed) {
                        free(pages[i].addr);
                        pages[i]._managed = 0;
                }
#endif
        }

        I_RELE(cookie->lsc_inode);

        oig_release(cookie->lsc_oig);
        OBD_FREE(cookie, LLU_SYSIO_COOKIE_SIZE(cookie->lsc_maxpages));
}

#ifdef LIBLUSTRE_HANDLE_UNALIGNED_PAGE
/* Note: these code should be removed finally, don't need
 * more cleanup
 */
static
int prepare_unaligned_write(struct llu_sysio_cookie *cookie)
{
        struct inode *inode = cookie->lsc_inode;
        struct llu_inode_info *lli = llu_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obdo oa;
        struct page *pages = cookie->lsc_pages;
        int i, pgidx[2] = {0, cookie->lsc_npages-1};
        int rc;
        ENTRY;

        for (i = 0; i < 2; i++) {
                struct page *oldpage = &pages[pgidx[i]];
                struct page newpage;
                struct brw_page pg;
                char *newbuf;

                if (i == 0 && pgidx[0] == pgidx[1])
                        continue;

                LASSERT(oldpage->_offset + oldpage->_count <= PAGE_CACHE_SIZE);

                if (oldpage->_count == PAGE_CACHE_SIZE)
                        continue;

                if (oldpage->index << PAGE_CACHE_SHIFT >=
                    lli->lli_st_size)
                        continue;

                newbuf = malloc(PAGE_CACHE_SIZE);
                if (!newbuf)
                        return -ENOMEM;

                newpage.index = oldpage->index;
                newpage.addr = newbuf;

                pg.pg = &newpage;
                pg.off = ((obd_off)newpage.index << PAGE_CACHE_SHIFT);
                if (pg.off + PAGE_CACHE_SIZE > lli->lli_st_size)
                        pg.count = lli->lli_st_size % PAGE_CACHE_SIZE;
                else
                        pg.count = PAGE_CACHE_SIZE;
                pg.flag = 0;

                oa.o_id = lsm->lsm_object_id;
                oa.o_mode = lli->lli_st_mode;
                oa.o_valid = OBD_MD_FLID | OBD_MD_FLMODE | OBD_MD_FLTYPE;

                /* issue read */
                rc = obd_brw(OBD_BRW_READ, llu_i2obdexp(inode), &oa, lsm, 1, &pg, NULL);
                if (rc) {
                        free(newbuf);
                        RETURN(rc);
                }

                /* copy page content, and reset page params */
                memcpy(newbuf + oldpage->_offset,
                       (char*)oldpage->addr + oldpage->_offset,
                       oldpage->_count);

                oldpage->addr = newbuf;
                if ((((obd_off)oldpage->index << PAGE_CACHE_SHIFT) +
                    oldpage->_offset + oldpage->_count) > lli->lli_st_size)
                        oldpage->_count += oldpage->_offset;
                else
                        oldpage->_count = PAGE_CACHE_SIZE;
                oldpage->_offset = 0;
                oldpage->_managed = 1;
        }

        RETURN(0);
}
#endif

static
int llu_prep_async_io(struct llu_sysio_cookie *cookie, int cmd,
                      char *buf, loff_t pos, size_t count)
{
        struct llu_inode_info *lli = llu_i2info(cookie->lsc_inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obd_export *exp = llu_i2obdexp(cookie->lsc_inode);
        struct page *pages = cookie->lsc_pages;
        struct ll_async_page *llap = cookie->lsc_llap;
        int i, rc, npages = 0;
        ENTRY;

        if (!exp)
                RETURN(-EINVAL);

        /* prepare the pages array */
	do {
                unsigned long index, offset, bytes;

                offset = (pos & ~PAGE_CACHE_MASK);
                index = pos >> PAGE_CACHE_SHIFT;
                bytes = PAGE_CACHE_SIZE - offset;
                if (bytes > count)
                        bytes = count;

                /* prevent read beyond file range */
                if ((cmd == OBD_BRW_READ) &&
                    (pos + bytes) >= lli->lli_st_size) {
                        if (pos >= lli->lli_st_size)
                                break;
                        bytes = lli->lli_st_size - pos;
                }

                /* prepare page for this index */
                pages[npages].index = index;
                pages[npages].addr = buf - offset;

                pages[npages]._offset = offset;
                pages[npages]._count = bytes;

                npages++;
                count -= bytes;
                pos += bytes;
                buf += bytes;

                cookie->lsc_rwcount += bytes;
        } while (count);

        cookie->lsc_npages = npages;

#ifdef LIBLUSTRE_HANDLE_UNALIGNED_PAGE
        if (cmd == OBD_BRW_WRITE) {
                rc = prepare_unaligned_write(cookie);
                if (rc)
                        RETURN(rc);
        }
#endif

        for (i = 0; i < npages; i++) {
                llap[i].llap_magic = LLAP_MAGIC;
                rc = obd_prep_async_page(exp, lsm, NULL, &pages[i],
                                         (obd_off)pages[i].index << PAGE_SHIFT,
                                         &llu_async_page_ops,
                                         &llap[i], &llap[i].llap_cookie);
                if (rc) {
                        llap[i].llap_cookie = NULL;
                        RETURN(rc);
                }
                CDEBUG(D_CACHE, "llap %p page %p cookie %p obj off "LPU64"\n",
                       &llap[i], &pages[i], llap[i].llap_cookie,
                       (obd_off)pages[i].index << PAGE_SHIFT);
                pages[i].private = (unsigned long)&llap[i];
                llap[i].llap_page = &pages[i];
                llap[i].llap_inode = cookie->lsc_inode;

                rc = obd_queue_group_io(exp, lsm, NULL, cookie->lsc_oig,
                                        llap[i].llap_cookie, cmd,
                                        pages[i]._offset, pages[i]._count, 0,
                                        ASYNC_READY | ASYNC_URGENT |
                                        ASYNC_COUNT_STABLE | ASYNC_GROUP_SYNC);
                if (rc)
                        RETURN(rc);

                llap[i].llap_queued = 1;
        }

        RETURN(0);
}

static
int llu_start_async_io(struct llu_sysio_cookie *cookie)
{
        struct lov_stripe_md *lsm = llu_i2info(cookie->lsc_inode)->lli_smd;
        struct obd_export *exp = llu_i2obdexp(cookie->lsc_inode);

        return obd_trigger_group_io(exp, lsm, NULL, cookie->lsc_oig);
}

/*
 * read/write a continuous buffer for an inode (zero-copy)
 */
struct llu_sysio_cookie*
llu_rw(int cmd, struct inode *inode, char *buf, size_t count, loff_t pos)
{
        struct llu_sysio_cookie *cookie;
        int max_pages, rc;
        ENTRY;

        max_pages = (count >> PAGE_SHIFT) + 2;

        cookie = get_sysio_cookie(inode, max_pages);
        if (!cookie)
                RETURN(ERR_PTR(-ENOMEM));

        rc = llu_prep_async_io(cookie, cmd, buf, pos, count);
        if (rc)
                GOTO(out_cleanup, rc);

        rc = llu_start_async_io(cookie);
        if (rc)
                GOTO(out_cleanup, rc);

/*
        rc = oig_wait(&oig);
        if (rc) {
                CERROR("file i/o error!\n");
                rw_count = rc;
        }
*/
        RETURN(cookie);

out_cleanup:
        put_sysio_cookie(cookie);
        RETURN(ERR_PTR(rc));
}

void lov_increase_kms(struct obd_export *exp, struct lov_stripe_md *lsm,
                      obd_off size);

struct llu_sysio_callback_args*
llu_file_write(struct inode *inode, const struct iovec *iovec,
               size_t iovlen, loff_t pos)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct lustre_handle lockh = {0};
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obd_export *exp = NULL;
        ldlm_policy_data_t policy;
        struct llu_sysio_callback_args *lsca;
        struct llu_sysio_cookie *cookie;
        int astflag = (lli->lli_open_flags & O_NONBLOCK) ?
                       LDLM_FL_BLOCK_NOWAIT : 0;
        ldlm_error_t err;
        int iovidx;
        ENTRY;

        /* XXX consider other types later */
        if (!S_ISREG(lli->lli_st_mode))
                LBUG();

        LASSERT(iovlen <= MAX_IOVEC);

        exp = llu_i2obdexp(inode);
        if (exp == NULL)
                RETURN(ERR_PTR(-EINVAL));

        OBD_ALLOC(lsca, sizeof(*lsca));
        if (!lsca)
                RETURN(ERR_PTR(-ENOMEM));

        /* FIXME optimize the following extent locking */
        for (iovidx = 0; iovidx < iovlen; iovidx++) {
                char *buf = (char*)iovec[iovidx].iov_base;
                size_t count = iovec[iovidx].iov_len;

                if (count == 0)
                        continue;

                if (pos + count > lli->lli_maxbytes)
                        GOTO(err_out, err = -ERANGE);

                /* FIXME libsysio haven't handle O_APPEND?? */
                policy.l_extent.start = pos;
                policy.l_extent.end = pos + count - 1;

                err = llu_extent_lock(fd, inode, lsm, LCK_PW, &policy,
                                      &lockh, astflag);
                if (err != ELDLM_OK)
                        GOTO(err_out, err = -ENOLCK);

                CDEBUG(D_INFO, "Writing inode %lu, "LPSZ" bytes, offset %Lu\n",
                       lli->lli_st_ino, count, pos);

                cookie = llu_rw(OBD_BRW_WRITE, inode, buf, count, pos);
                if (!IS_ERR(cookie)) {
                        /* save cookie */
                        lsca->cookies[lsca->ncookies++] = cookie;
                        pos += count;
                        lov_increase_kms(exp, lsm, pos);
                        /* file size grow */
                        if (pos > lli->lli_st_size)
                                lli->lli_st_size = pos;
                } else {
                        llu_extent_unlock(fd, inode, lsm, LCK_PW, &lockh);
                        GOTO(err_out, err = PTR_ERR(cookie));
                }

                /* XXX errors? */
                err = llu_extent_unlock(fd, inode, lsm, LCK_PW, &lockh);
                if (err)
                        CERROR("extent unlock error %d\n", err);
        }

        RETURN(lsca);

err_out:
        /* teardown all async stuff */
        while (lsca->ncookies--) {
                put_sysio_cookie(lsca->cookies[lsca->ncookies]);
        }
        OBD_FREE(lsca, sizeof(*lsca));

        RETURN(ERR_PTR(err));
}

#if 0
static void llu_update_atime(struct inode *inode)
{
        struct llu_inode_info *lli = llu_i2info(inode);

#ifdef USE_ATIME
        struct iattr attr;

        attr.ia_atime = LTIME_S(CURRENT_TIME);
        attr.ia_valid = ATTR_ATIME;

        if (lli->lli_st_atime == attr.ia_atime) return;
        if (IS_RDONLY(inode)) return;
        if (IS_NOATIME(inode)) return;

        /* ll_inode_setattr() sets inode->i_atime from attr.ia_atime */
        llu_inode_setattr(inode, &attr, 0);
#else
        /* update atime, but don't explicitly write it out just this change */
        inode->i_atime = CURRENT_TIME;
#endif
}
#endif

struct llu_sysio_callback_args*
llu_file_read(struct inode *inode, const struct iovec *iovec,
              size_t iovlen, loff_t pos)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct lustre_handle lockh = { 0 };
        ldlm_policy_data_t policy;
        struct llu_sysio_callback_args *lsca;
        struct llu_sysio_cookie *cookie;
        int astflag = (lli->lli_open_flags & O_NONBLOCK) ?
                       LDLM_FL_BLOCK_NOWAIT : 0;
        __u64 kms;
        int iovidx;

        ldlm_error_t err;
        ENTRY;

        OBD_ALLOC(lsca, sizeof(*lsca));
        if (!lsca)
                RETURN(ERR_PTR(-ENOMEM));

        for (iovidx = 0; iovidx < iovlen; iovidx++) {
                char *buf = iovec[iovidx].iov_base;
                size_t count = iovec[iovidx].iov_len;

                /* "If nbyte is 0, read() will return 0 and have no other results."
                 *                      -- Single Unix Spec */
                if (count == 0)
                        continue;

                policy.l_extent.start = pos;
                policy.l_extent.end = pos + count - 1;

                err = llu_extent_lock(fd, inode, lsm, LCK_PR, &policy,
                                      &lockh, astflag);
                if (err != ELDLM_OK)
                        GOTO(err_out, err = -ENOLCK);

                kms = lov_merge_size(lsm, 1);
                if (policy.l_extent.end > kms) {
                        /* A glimpse is necessary to determine whether we
                         * return a short read or some zeroes at the end of
                         * the buffer */
                        struct ost_lvb lvb;
                        if (llu_glimpse_size(inode, &lvb)) {
                                llu_extent_unlock(fd, inode, lsm, LCK_PR, &lockh);
                                GOTO(err_out, err = -ENOLCK);
                        }
                        lli->lli_st_size = lvb.lvb_size;
                } else {
                        lli->lli_st_size = kms;
                }

                CDEBUG(D_INFO, "Reading inode %lu, "LPSZ" bytes, offset %Ld, "
                       "i_size "LPU64"\n", lli->lli_st_ino, count, pos,
                       lli->lli_st_size);

                if (pos >= lli->lli_st_size) {
                        llu_extent_unlock(fd, inode, lsm, LCK_PR, &lockh);
                        break;
                }

                cookie = llu_rw(OBD_BRW_READ, inode, buf, count, pos);
                if (!IS_ERR(cookie)) {
                        /* save cookie */
                        lsca->cookies[lsca->ncookies++] = cookie;
                        pos += count;
                } else {
                        llu_extent_unlock(fd, inode, lsm, LCK_PR, &lockh);
                        GOTO(err_out, err = PTR_ERR(cookie));
                }

                /* XXX errors? */
                err = llu_extent_unlock(fd, inode, lsm, LCK_PR, &lockh);
                if (err)
                        CERROR("extent_unlock fail: %d\n", err);
        }
#if 0
        if (readed > 0)
                llu_update_atime(inode);
#endif
        RETURN(lsca);

err_out:
        /* teardown all async stuff */
        while (lsca->ncookies--) {
                put_sysio_cookie(lsca->cookies[lsca->ncookies]);
        }
        OBD_FREE(lsca, sizeof(*lsca));

        RETURN(ERR_PTR(err));
}

int llu_iop_iodone(struct ioctx *ioctxp)
{
        struct llu_sysio_callback_args *lsca = ioctxp->ioctx_private;
        struct llu_sysio_cookie *cookie;
        int i, err = 0, rc = 0;
        ENTRY;

        /* write/read(fd, buf, 0) */
        if (!lsca) {
                ioctxp->ioctx_cc = 0;
                RETURN(1);
        }

        LASSERT(!IS_ERR(lsca));

        for (i = 0; i < lsca->ncookies; i++) {
                cookie = lsca->cookies[i];
                if (cookie) {
                        err = oig_wait(cookie->lsc_oig);
                        if (err && !rc)
                                rc = err;
                        if (!rc)
                                ioctxp->ioctx_cc += cookie->lsc_rwcount;
                        put_sysio_cookie(cookie);
                }
        }

        if (rc) {
                LASSERT(rc < 0);
                ioctxp->ioctx_cc = -1;
                ioctxp->ioctx_errno = -rc;
        }

        OBD_FREE(lsca, sizeof(*lsca));
        ioctxp->ioctx_private = NULL;

        RETURN(1);
}
