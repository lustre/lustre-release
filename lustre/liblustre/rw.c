/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
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
#include <error.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <sysio.h>
#include <fs.h>
#include <mount.h>
#include <inode.h>
#include <file.h>

#include "llite_lib.h"

int llu_iop_iodone(struct ioctx *ioctxp __IS_UNUSED)
{
        return 1;
}

/*
 * this grabs a lock and manually implements behaviour that makes it look
 * like the OST is returning the file size with each lock acquisition
 */
int llu_extent_lock(struct ll_file_data *fd, struct inode *inode,
                   struct lov_stripe_md *lsm,
                   int mode, struct ldlm_extent *extent,
                   struct lustre_handle *lockh)
{
#if 0
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc;
        ENTRY;

        rc = ll_extent_lock_no_validate(fd, inode, lsm, mode, extent, lockh);
        if (rc != ELDLM_OK)
                RETURN(rc);

        /* always do a getattr for the first person to pop out of lock
         * acquisition.. the DID_GETATTR flag and semaphore serialize
         * this initial race.  we used to make a decision based on whether
         * the lock was matched or acquired, but the matcher could win the
         * waking race with the first issuer so that was no good..
         */
        if (test_bit(LLI_F_DID_GETATTR, &lli->lli_flags))
                RETURN(ELDLM_OK);

        down(&lli->lli_getattr_sem);

        if (!test_bit(LLI_F_DID_GETATTR, &lli->lli_flags)) {
                rc = ll_inode_getattr(inode, lsm, fd ? &fd->fd_ost_och : NULL);
                if (rc == 0) {
                        set_bit(LLI_F_DID_GETATTR, &lli->lli_flags);
                } else {
                        /* XXX can this fail? */
                        ll_extent_unlock(fd, inode, lsm, mode, lockh);
                }
        }

        up(&lli->lli_getattr_sem);
        RETURN(rc);
#else
        return ELDLM_OK;
#endif
}

int ll_extent_unlock(struct ll_file_data *fd, struct inode *inode,
                struct lov_stripe_md *lsm, int mode,
                struct lustre_handle *lockh)
{
#if 0
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc;
        ENTRY;

        /* XXX phil: can we do this?  won't it screw the file size up? */
        if ((fd && (fd->fd_flags & LL_FILE_IGNORE_LOCK)) ||
            (sbi->ll_flags & LL_SBI_NOLCK))
                RETURN(0);

        rc = obd_cancel(&sbi->ll_osc_conn, lsm, mode, lockh);

        RETURN(rc);
#else
        return 0;
#endif
}

static int llu_brw(int cmd, struct inode *inode, struct page *page, int flags)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct obd_brw_set *set;
        struct brw_page pg;
        int rc;
        ENTRY;

        set = obd_brw_set_new();
        if (set == NULL)
                RETURN(-ENOMEM);

        pg.pg = page;
        pg.off = ((obd_off)page->index) << PAGE_SHIFT;

        /* FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME */
#if 0
        if (cmd == OBD_BRW_WRITE && (pg.off + PAGE_SIZE > lli->lli_st_size))
                pg.count = lli->lli_st_size % PAGE_SIZE;
        else
#endif
                pg.count = PAGE_SIZE;

        CDEBUG(D_PAGE, "%s %d bytes ino %lu at "LPU64"/"LPX64"\n",
               cmd & OBD_BRW_WRITE ? "write" : "read", pg.count, lli->lli_st_ino,
               pg.off, pg.off);
        if (pg.count == 0) {
                LBUG();
        }

        pg.flag = flags;

        set->brw_callback = ll_brw_sync_wait;
        rc = obd_brw(cmd, llu_i2obdconn(inode), lsm, 1, &pg, set, NULL);
        if (rc) {
                if (rc != -EIO)
                        CERROR("error from obd_brw: rc = %d\n", rc);
        } else {
                rc = ll_brw_sync_wait(set, CB_PHASE_START);
                if (rc)
                        CERROR("error from callback: rc = %d\n", rc);
        }
        obd_brw_set_decref(set);

        RETURN(rc);
}

static int llu_prepare_write(struct inode *inode, struct page *page,
                             unsigned from, unsigned to)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        obd_off offset = ((obd_off)page->index) << PAGE_SHIFT;
        int rc = 0;
        ENTRY;

#if 0
        if (!PageLocked(page))
                LBUG();

        if (PageUptodate(page))
                RETURN(0);

        //POISON(addr + from, 0xca, to - from);
#endif
        /* We're completely overwriting an existing page, so _don't_ set it up
         * to date until commit_write */
        if (from == 0 && to == PAGE_SIZE)
                RETURN(0);

        /* If are writing to a new page, no need to read old data.
         * the extent locking and getattr procedures in ll_file_write have
         * guaranteed that i_size is stable enough for our zeroing needs */
        if (lli->lli_st_size <= offset) {
                memset(kmap(page), 0, PAGE_SIZE);
                kunmap(page);
                GOTO(prepare_done, rc = 0);
        }

        rc = llu_brw(OBD_BRW_READ, inode, page, 0);

        EXIT;

 prepare_done:
        return rc;
}

static int llu_commit_write(struct inode *inode, struct page *page,
                            unsigned from, unsigned to)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        loff_t size;
        int rc;
        ENTRY;
#if 0
        LASSERT(inode == file->f_dentry->d_inode);
        LASSERT(PageLocked(page));

        CDEBUG(D_INODE, "inode %p is writing page %p from %d to %d at %lu\n",
               inode, page, from, to, page->index);
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu,from=%d,to=%d\n",
               inode->i_ino, from, to);
        /* to match full page case in prepare_write */
        SetPageUptodate(page);
        /* mark the page dirty, put it on mapping->dirty,
         * mark the inode PAGES_DIRTY, put it on sb->dirty */
        set_page_dirty(page);
#endif
        rc = llu_brw(OBD_BRW_WRITE, inode, page, 0);
        if (rc)
                return rc;

        /* this is matched by a hack in obdo_to_inode at the moment */
        size = (((obd_off)page->index) << PAGE_SHIFT) + to;
        if (size > lli->lli_st_size)
                lli->lli_st_size = size;

        RETURN(0);
} /* ll_commit_write */

ssize_t
llu_generic_file_write(struct inode *inode, const char *buf,
                       size_t count, loff_t pos)
{
	struct page	*page;
	ssize_t		written;
	long		status = 0;
	int		err;
	unsigned	bytes;

	if ((ssize_t) count < 0)
		return -EINVAL;
#if 0
	down(&inode->i_sem);
#endif
	if (pos < 0)
                return -EINVAL;

	written = 0;

#if 0
	remove_suid(inode);
	update_inode_times(inode);
#endif
	do {
		unsigned long index, offset;
		char *kaddr;

		/*
		 * Try to find the page in the cache. If it isn't there,
		 * allocate a free page.
		 */
		offset = (pos & (PAGE_CACHE_SIZE -1)); /* Within page */
		index = pos >> PAGE_CACHE_SHIFT;
		bytes = PAGE_CACHE_SIZE - offset;
		if (bytes > count) {
			bytes = count;
		}

		status = -ENOMEM;	/* we'll assign it later anyway */
		page = __grab_cache_page(index);
		if (!page)
			break;

		kaddr = kmap(page);
		status = llu_prepare_write(inode, page, offset, offset+bytes);
		if (status)
			goto sync_failure;

		memcpy(kaddr+offset, buf, bytes);

		status = llu_commit_write(inode, page, offset, offset+bytes);
		if (!status)
			status = bytes;

		if (status >= 0) {
			written += status;
			count -= status;
			pos += status;
			buf += status;
		}
unlock:
		kunmap(page);
		page_cache_release(page);

		if (status < 0)
			break;
	} while (count);
done:
	err = written ? written : status;

#if 0
	up(&inode->i_sem);
#endif
	return err;

	status = -EFAULT;
	goto unlock;

sync_failure:
	/*
	 * If blocksize < pagesize, prepare_write() may have instantiated a
	 * few blocks outside i_size.  Trim these off again.
	 */
	kunmap(page);
	page_cache_release(page);
	goto done;
}

ssize_t llu_file_write(struct inode *inode, const struct iovec *iovec,
                       size_t iovlen, loff_t pos)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data; /* XXX not ready don't use it now */
        struct lustre_handle lockh = { 0, 0 };
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct ldlm_extent extent;
        ldlm_error_t err;
        ssize_t retval = 0;
        ENTRY;

        /* XXX consider other types later */
        if (!S_ISREG(lli->lli_st_mode))
                LBUG();
#if 0
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu,size="LPSZ",offset=%Ld\n",
               inode->i_ino, count, *ppos);

        /*
         * sleep doing some writeback work of this mount's dirty data
         * if the VM thinks we're low on memory.. other dirtying code
         * paths should think about doing this, too, but they should be
         * careful not to hold locked pages while they do so.  like
         * ll_prepare_write.  *cough*
         */
        ll_check_dirty(inode->i_sb);
#endif
        while (iovlen--) {
                const char *buf = iovec[iovlen].iov_base;
                size_t count = iovec[iovlen].iov_len;

                /* POSIX, but surprised the VFS doesn't check this already */
                if (count == 0)
                        continue;

#if 0
                if (!S_ISBLK(lli->lli_st_mode) && file->f_flags & O_APPEND) {
                        extent.start = 0;
                        extent.end = OBD_OBJECT_EOF;
                } else  {
                        extent.start = *ppos;
                        extent.end = *ppos + count - 1;
                }
#else
                extent.start = pos;
                extent.end = pos + count - 1;
#endif

                err = llu_extent_lock(fd, inode, lsm, LCK_PW, &extent, &lockh);
                if (err != ELDLM_OK)
                        RETURN(-ENOLCK);

#if 0
                if (!S_ISBLK(inode->i_mode) && file->f_flags & O_APPEND)
                        *ppos = inode->i_size;

                CDEBUG(D_INFO, "Writing inode %lu, "LPSZ" bytes, offset %Lu\n",
                       inode->i_ino, count, *ppos);
#endif
                retval += llu_generic_file_write(inode, buf, count, pos);
        }

        /* XXX errors? */
        ll_extent_unlock(fd, inode, lsm, LCK_PW, &lockh);
        return(retval);
}

static void llu_update_atime(struct inode *inode)
{
#if 0
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
#endif
}

static size_t llu_generic_file_read(struct inode *inode, char *buf,
                                    size_t count, loff_t pos)
{
        struct llu_inode_info *lli = llu_i2info(inode);
	unsigned long index, offset;
	int error = 0;
        size_t readed = 0;

	index = pos >> PAGE_CACHE_SHIFT;
	offset = pos & ~PAGE_CACHE_MASK;

	do {
		struct page *page;
		unsigned long end_index, nr;

		end_index = lli->lli_st_size >> PAGE_CACHE_SHIFT;

		if (index > end_index)
			break;
		nr = PAGE_CACHE_SIZE;
		if (index == end_index) {
			nr = lli->lli_st_size & ~PAGE_CACHE_MASK;
			if (nr <= offset)
				break;
		}

		nr = nr - offset;
                if (nr > count)
                        nr = count;

                page = grab_cache_page(index);
                if (!page) {
                        error = -ENOMEM;
                        break;
                }

                error = llu_brw(OBD_BRW_READ, inode, page, 0);
		if (error) {
		        page_cache_release(page);
                        break;
		}

                memcpy(buf, kmap(page)+offset, nr);
		offset += nr;
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;
                readed += nr;
                count -= nr;

		page_cache_release(page);
	} while (count);

        if (error)
                return error;
        return readed;
}

ssize_t llu_file_read(struct inode *inode, const struct iovec *iovec,
                       size_t iovlen, loff_t pos)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct ll_file_data *fd = lli->lli_file_data;
        struct lov_stripe_md *lsm = lli->lli_smd;
        struct lustre_handle lockh = { 0, 0 };
#if 0
        struct ll_read_extent rextent;
#else
        struct ldlm_extent extent;
#endif
        ldlm_error_t err;
        ssize_t retval = 0;
        ENTRY;

        while (iovlen--) {
                char *buf = iovec[iovlen].iov_base;
                size_t count = iovec[iovlen].iov_len;

                /* "If nbyte is 0, read() will return 0 and have no other results."
                 *                      -- Single Unix Spec */
                if (count == 0)
                        RETURN(0);

#if 0
                rextent.re_extent.start = pos;
                rextent.re_extent.end = pos + count - 1;
#else
                extent.start = pos;
                extent.end = pos + count - 1;
#endif
                err = llu_extent_lock(fd, inode, lsm, LCK_PR, &extent, &lockh);
                if (err != ELDLM_OK)
                        RETURN(-ENOLCK);
#if 0
                rextent.re_task = current;
                spin_lock(&lli->lli_read_extent_lock);
                list_add(&rextent.re_lli_item, &lli->lli_read_extents);
                spin_unlock(&lli->lli_read_extent_lock);
#endif
                CDEBUG(D_INFO, "Reading inode %lu, "LPSZ" bytes, offset %Ld\n",
                       lli->lli_st_ino, count, pos);
                retval = llu_generic_file_read(inode, buf, count, pos);
#if 0
                spin_lock(&lli->lli_read_extent_lock);
                list_del(&rextent.re_lli_item);
                spin_unlock(&lli->lli_read_extent_lock);
#endif
        }

        if (retval > 0)
                llu_update_atime(inode);

        /* XXX errors? */
        ll_extent_unlock(fd, inode, lsm, LCK_PR, &lockh);
        RETURN(retval);
}

