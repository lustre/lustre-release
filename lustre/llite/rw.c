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

struct obdo * ll_oa_from_inode(struct inode *inode, unsigned long valid)
{
        struct ll_inode_info *oinfo = ll_i2info(inode);
        struct obdo *oa = obdo_alloc();
        if ( !oa ) {
                CERROR("no memory to allocate obdo!\n"); 
                return NULL;
        }
        oa->o_valid = valid;

        if ( valid & OBD_MD_FLID )
                oa->o_id = oinfo->lli_objid;
        if ( valid & OBD_MD_FLATIME )
                oa->o_atime = inode->i_atime;
        if ( valid & OBD_MD_FLMTIME )
                oa->o_mtime = inode->i_mtime;
        if ( valid & OBD_MD_FLCTIME )
                oa->o_ctime = inode->i_ctime;
        if ( valid & OBD_MD_FLSIZE )
                oa->o_size = inode->i_size;
        if ( valid & OBD_MD_FLBLOCKS )   /* allocation of space */
                oa->o_blocks = inode->i_blocks;
        if ( valid & OBD_MD_FLBLKSZ )
                oa->o_blksize = inode->i_blksize;
        if ( valid & OBD_MD_FLMODE )
                oa->o_mode = inode->i_mode;
        if ( valid & OBD_MD_FLUID )
                oa->o_uid = inode->i_uid;
        if ( valid & OBD_MD_FLGID )
                oa->o_gid = inode->i_gid;
        if ( valid & OBD_MD_FLFLAGS )
                oa->o_flags = inode->i_flags;
        if ( valid & OBD_MD_FLNLINK )
                oa->o_nlink = inode->i_nlink;
        if ( valid & OBD_MD_FLGENER ) 
                oa->o_generation = inode->i_generation;

        CDEBUG(D_INFO, "src inode %ld, dst obdo %ld valid 0x%08lx\n",
               inode->i_ino, (long)oa->o_id, valid);
#if 0
        /* this will transfer metadata for the logical object to 
           the oa: that metadata could contain the constituent objects
        */
        if (ll_has_inline(inode)) {
                CDEBUG(D_INODE, "copying inline data from inode to obdo\n");
                memcpy(oa->o_inline, oinfo->lli_inline, OBD_INLINESZ);
                oa->o_obdflags |= OBD_FL_INLINEDATA;
                oa->o_valid |= OBD_MD_FLINLINE;
        }
#endif
        return oa;
} /* ll_oa_from_inode */

/* SYNCHRONOUS I/O to object storage for an inode */
static int ll_brw(int rw, struct inode *inode, struct page *page, int create)
{
        obd_count        num_obdo = 1;
        obd_count        bufs_per_obdo = 1;
        struct obdo     *oa;
        obd_size         count = PAGE_SIZE;
        obd_off          offset = ((obd_off)page->index) << PAGE_SHIFT;
        obd_flag         flags = create ? OBD_BRW_CREATE : 0;
        int              err;
        ENTRY;

        oa = ll_oa_from_inode(inode, OBD_MD_FLNOTOBD);
        if (!oa)
                RETURN(-ENOMEM);

        err = obd_brw(rw, ll_i2obdconn(inode), num_obdo, &oa, &bufs_per_obdo,
                      &page, &count, &offset, &flags);

        obdo_free(oa);
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
        obd_count        num_obdo = 1;
        obd_count        bufs_per_obdo = 1;
        struct obdo     *oa;
        obd_size         count = to;
        obd_off          offset = (((obd_off)page->index) << PAGE_SHIFT);
        obd_flag         flags = create ? OBD_BRW_CREATE : 0;
        int              err;
        struct iattr     iattr;

        ENTRY;
        oa = ll_oa_from_inode(inode, OBD_MD_FLNOTOBD);
        if (! oa )
                RETURN(-ENOMEM);

        SetPageUptodate(page);

        if (!PageLocked(page))
                LBUG();

        CDEBUG(D_INODE, "commit_page writing (at %d) to %d, count %Ld\n", 
               from, to, (unsigned long long)count);

        err = obd_brw(OBD_BRW_WRITE, ll_i2obdconn(inode), num_obdo, &oa,
                      &bufs_per_obdo, &page, &count, &offset, &flags);
        kunmap(page);

        iattr.ia_size = offset + to;
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

        obdo_free(oa);
        RETURN(err);
} /* ll_commit_write */

void ll_truncate(struct inode *inode)
{
        struct obdo *oa;
        int err;
        ENTRY;

        oa = ll_oa_from_inode(inode, OBD_MD_FLID | OBD_MD_FLSIZE);
        if (!oa) {
                CERROR("no memory to allocate obdo!\n");
                return;
        }

        CDEBUG(D_INFO, "calling punch for %ld (all bytes after %Lu)\n",
               (long)oa->o_id, (unsigned long long)oa->o_size);
        /* truncate == punch from i_size onwards */
        err = obd_punch(ll_i2obdconn(inode), oa, -1 - oa->o_size, oa->o_size);
        obdo_free(oa);

        if (err)
                CERROR("obd_truncate fails (%d)\n", err);
        else
                /* This is done for us at the OST and MDS, but the
                 * updated values are not sent back to us.
                 * Needed for POSIX.
                 */
                inode->i_mtime = inode->i_ctime = CURRENT_TIME;

        EXIT;
        return;
} /* ll_truncate */

int ll_direct_IO(int rw, struct inode *inode, struct kiobuf *iobuf,
                 unsigned long blocknr, int blocksize)
{
        int i;
        obd_count        num_obdo = 1;
        obd_count        bufs_per_obdo = iobuf->nr_pages;
        struct obdo     *oa = NULL;
        obd_size         *count = NULL;
        obd_off          *offset = NULL;
        obd_flag         *flags = NULL;
        int              rc = 0;

        ENTRY;
        if (blocksize != PAGE_SIZE) {
                CERROR("direct_IO blocksize != PAGE_SIZE\n");
                RETURN(-EINVAL);
        }

        OBD_ALLOC(count, sizeof(obd_size) * bufs_per_obdo);
        OBD_ALLOC(offset, sizeof(obd_off) * bufs_per_obdo);
        OBD_ALLOC(flags, sizeof(obd_flag) * bufs_per_obdo);
        if (!count || !offset || !flags)
                GOTO(out, rc = -ENOMEM);

        /* NB: we can't use iobuf->maplist[i]->index for the offset
         * instead of "blocknr" because ->index contains garbage.
         */
        for (i = 0; i < bufs_per_obdo; i++, blocknr++) {
                count[i] = PAGE_SIZE;
                offset[i] = (obd_off)blocknr << PAGE_SHIFT;
                flags[i] = OBD_BRW_CREATE;
        }

        oa = ll_oa_from_inode(inode, OBD_MD_FLNOTOBD);
        if (!oa)
                GOTO(out, rc = -ENOMEM);

        rc = obd_brw(rw == WRITE ? OBD_BRW_WRITE : OBD_BRW_READ,
                     ll_i2obdconn(inode), num_obdo, &oa, &bufs_per_obdo,
                     iobuf->maplist, count, offset, flags);
        if (rc == 0)
                rc = bufs_per_obdo * PAGE_SIZE;

 out:
        obdo_free(oa);
        OBD_FREE(flags, sizeof(obd_flag) * bufs_per_obdo);
        OBD_FREE(offset, sizeof(obd_off) * bufs_per_obdo);
        OBD_FREE(count, sizeof(obd_count) * bufs_per_obdo);
        RETURN(rc);
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
