/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Lite I/O Page Cache
 *
 * Copyright (C) 2002 Cluster File Systems, Inc. 
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/iobuf.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_mds.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_lib.h>


/* SYNCHRONOUS I/O to object storage for an inode */
static int ll_brw(int rw, struct inode *inode, struct page *page, int create)
{
        struct ll_inode_info *lii = ll_i2info(inode);
        struct lov_stripe_md *md = lii->lli_smd;
        struct brw_page pg; 
        int              err;
        struct io_cb_data *cbd = ll_init_cb();
        ENTRY;
        if (!cbd) 
                RETURN(-ENOMEM); 

        pg.pg = page;
        pg.count = PAGE_SIZE;
        pg.off = ((obd_off)page->index) << PAGE_SHIFT;
        pg.flag = create ? OBD_BRW_CREATE : 0;

        err = obd_brw(rw, ll_i2obdconn(inode), md, 1, &pg, ll_sync_io_cb, cbd);
        RETURN(err);
} /* ll_brw */

/* returns the page unlocked, but with a reference */
static int ll_readpage(struct file *file, struct page *page)
{
        struct inode *inode = page->mapping->host;
        int rc = 0;
        ENTRY;

        if (!PageLocked(page))
                LBUG();

        if (((inode->i_size + PAGE_SIZE - 1) >> PAGE_SHIFT) <= page->index) {
                memset(kmap(page), 0, PAGE_SIZE);
                kunmap(page);
                GOTO(readpage_out, rc);
        }

        if (Page_Uptodate(page)) {
                CERROR("Explain this please?\n");
                GOTO(readpage_out, rc);
        }

        rc = ll_brw(OBD_BRW_READ, inode, page, 0);
        EXIT;

 readpage_out:
        if (!rc)
                SetPageUptodate(page);
        UnlockPage(page);
        return 0;
} /* ll_readpage */


static int ll_prepare_write(struct file *file, struct page *page, unsigned from,
                            unsigned to)
{
        struct inode *inode = page->mapping->host;
        //obd_off offset = ((obd_off)page->index) << PAGE_SHIFT;
        int rc = 0;
        char *addr;
        ENTRY; 
        
        addr = kmap(page);
        if (!PageLocked(page))
                LBUG();

        if (Page_Uptodate(page))
                GOTO(prepare_done, rc);

        memset(addr, 0, PAGE_SIZE);

        /* We're completely overwriting an existing page, so _don't_ set it up
         * to date until commit_write */
        if (from == 0 && to == PAGE_SIZE)
                RETURN(0);
        
        /* prepare write should not read what lies beyond the end of
           the file */


        rc = ll_brw(OBD_BRW_READ, inode, page, 0);

        EXIT;
 prepare_done:
        if (!rc)
                SetPageUptodate(page);

        return rc;
}

/* returns the page unlocked, but with a reference */
static int ll_writepage(struct page *page)
{
        struct inode *inode = page->mapping->host;
        int err;
        ENTRY;

        if (!PageLocked(page))
                LBUG();

        err = ll_brw(OBD_BRW_WRITE, inode, page, 1);
        if ( !err ) {
                //SetPageUptodate(page);
                set_page_clean(page);
        } else {
                CERROR("ll_brw failure %d\n", err);
        }
        UnlockPage(page); 
        RETURN(err);
}


/* SYNCHRONOUS I/O to object storage for an inode -- object attr will be updated
 * too */
static int ll_commit_write(struct file *file, struct page *page,
                           unsigned from, unsigned to)
{
        int create = 1;
        struct inode *inode = page->mapping->host;
        struct ll_inode_info *lii = ll_i2info(inode);
        struct lov_stripe_md *md = lii->lli_smd;
        struct brw_page pg; 
        int              err;
        struct iattr     iattr;
        struct io_cb_data *cbd = ll_init_cb();

        pg.pg = page;
        pg.count = to;
        pg.off = (((obd_off)page->index) << PAGE_SHIFT);
        pg.flag = create ? OBD_BRW_CREATE : 0;

        ENTRY;
        if (!cbd) 
                RETURN(-ENOMEM); 

        SetPageUptodate(page);

        if (!PageLocked(page))
                LBUG();

        CDEBUG(D_INODE, "commit_page writing (at %d) to %d, count %Ld\n",
               from, to, (unsigned long long)pg.count);

        err = obd_brw(OBD_BRW_WRITE, ll_i2obdconn(inode), md,
                      1, &pg, ll_sync_io_cb, cbd);
        kunmap(page);

        iattr.ia_size = pg.off + pg.count;
        if (iattr.ia_size > inode->i_size) {
                /* do NOT truncate when writing in the middle of a file */
                inode->i_size = iattr.ia_size;
                iattr.ia_valid = ATTR_SIZE;
#if 0
                err = ll_inode_setattr(inode, &iattr, 0);
                if (err) {
                        CERROR("failed - %d.\n", err);
                        err = -EIO;
                }
#endif
        }

        RETURN(err);
} /* ll_commit_write */

void ll_truncate(struct inode *inode)
{
        struct obdo oa = {0};
        struct lov_stripe_md *md = ll_i2info(inode)->lli_smd;
        int err;
        ENTRY;

        if (!md) { 
                /* object not yet allocated */
                inode->i_mtime = inode->i_ctime = CURRENT_TIME;
                return;
        }

        CDEBUG(D_INFO, "calling punch for %ld (all bytes after %Ld)\n",
               (long)oa.o_id, (unsigned long long)oa.o_size);

        oa.o_id = md->lmd_object_id;
        oa.o_valid = OBD_MD_FLID;
        /* truncate == punch to/from start from/to end:
           set end to -1 for that. */
        err = obd_punch(ll_i2obdconn(inode), &oa, md, inode->i_size,
                        0xffffffffffffffff);
        if (err)
                CERROR("obd_truncate fails (%d)\n", err);
        else
                /* This is done for us at the OST and MDS, but the
                 * updated timestamps are not sent back to us.
                 * Needed for POSIX.
                 */
                inode->i_mtime = inode->i_ctime = CURRENT_TIME;

        EXIT;
        return;
} /* ll_truncate */

int ll_direct_IO(int rw, struct inode *inode, struct kiobuf *iobuf,
                 unsigned long blocknr, int blocksize)
{
        obd_count        bufs_per_obdo = iobuf->nr_pages;
        struct ll_inode_info *lii = ll_i2info(inode);
        struct lov_stripe_md *md = lii->lli_smd;
        struct brw_page *pga;
        int              rc = 0;
        int i;
        struct io_cb_data *cbd = ll_init_cb();

        ENTRY;
        if (!cbd)
                RETURN(-ENOMEM);

        if (blocksize != PAGE_SIZE) {
                CERROR("direct_IO blocksize != PAGE_SIZE\n");
                return -EINVAL;
        }

        OBD_ALLOC(pga, sizeof(*pga) * bufs_per_obdo);
        if (!pga)
                GOTO(out, rc = -ENOMEM);

        /* NB: we can't use iobuf->maplist[i]->index for the offset
         * instead of "blocknr" because ->index contains garbage.
         */
        for (i = 0; i < bufs_per_obdo; i++, blocknr++) {
                pga[i].pg = iobuf->maplist[i];
                pga[i].count = PAGE_SIZE;
                pga[i].off = (obd_off)blocknr << PAGE_SHIFT;
                pga[i].flag = OBD_BRW_CREATE;
        }

        if (!md || !md->lmd_object_id)
                GOTO(out, rc = -ENOMEM);

        rc = obd_brw(rw == WRITE ? OBD_BRW_WRITE : OBD_BRW_READ,
                     ll_i2obdconn(inode), md, bufs_per_obdo, pga,
                     ll_sync_io_cb, cbd);
        if (rc == 0)
                rc = bufs_per_obdo * PAGE_SIZE;

out:
        OBD_FREE(pga, sizeof(*pga) * bufs_per_obdo);
        RETURN(rc);
}


int ll_flush_inode_pages(struct inode * inode)
{
        obd_count        bufs_per_obdo = 0;
        obd_size         *count = NULL;
        obd_off          *offset = NULL;
        obd_flag         *flags = NULL;
        int              err = 0;

        ENTRY;

        spin_lock(&pagecache_lock);

        spin_unlock(&pagecache_lock);


        OBD_ALLOC(count, sizeof(*count) * bufs_per_obdo);
        OBD_ALLOC(offset, sizeof(*offset) * bufs_per_obdo);
        OBD_ALLOC(flags, sizeof(*flags) * bufs_per_obdo);
        if (!count || !offset || !flags)
                GOTO(out, err=-ENOMEM);

#if 0
        for (i = 0 ; i < bufs_per_obdo ; i++) {
                count[i] = PAGE_SIZE;
                offset[i] = ((obd_off)(iobuf->maplist[i])->index) << PAGE_SHIFT;
                flags[i] = OBD_BRW_CREATE;
        }

        err = obd_brw(OBD_BRW_WRITE, ll_i2obdconn(inode),
                      ll_i2info(inode)->lli_smd, bufs_per_obdo,
                      iobuf->maplist, count, offset, flags, NULL, NULL);
        if (err == 0)
                err = bufs_per_obdo * 4096;
#endif
 out:
        OBD_FREE(flags, sizeof(*flags) * bufs_per_obdo);
        OBD_FREE(count, sizeof(*count) * bufs_per_obdo);
        OBD_FREE(offset, sizeof(*offset) * bufs_per_obdo);
        RETURN(err);
}



struct address_space_operations ll_aops = {
        readpage: ll_readpage,
        writepage: ll_writepage,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,4,17))
        direct_IO: ll_direct_IO,
#endif
        sync_page: block_sync_page,
        prepare_write: ll_prepare_write,
        commit_write: ll_commit_write,
        bmap: NULL
};
