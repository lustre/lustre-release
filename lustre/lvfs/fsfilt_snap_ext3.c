/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/ext3_fs.h>
#include <linux/ext3_jbd.h>
#include <linux/ext3_extents.h>
#include <linux/locks.h>
#include <linux/version.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/ext3_xattr.h>
#else
#include <ext3/xattr.h>
#endif

#include <linux/kp30.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/module.h>
#include <linux/iobuf.h>
#endif
#include <linux/lustre_smfs.h>
#include <linux/lustre_snap.h>

/* For snapfs in EXT3 flags --- FIXME will find other ways to store it*/
#define EXT3_COW_FL                     0x00100000 /* inode is snapshot cow */
#define EXT3_DEL_FL                     0x00200000 /* inode is deleting in snapshot */

#define EXT3_SNAP_ATTR "@snap"
#define EXT3_SNAP_GENERATION "@snap_generation"
#define EXT3_MAX_SNAPS 20
#define EXT3_MAX_SNAP_DATA (sizeof(struct snap_ea))
#define EXT3_SNAP_INDEX EXT3_XATTR_INDEX_LUSTRE

#define SB_SNAPTABLE_INO(sb)   (EXT3_SB(sb)->s_es->s_snaptable_ino)
#define SB_FEATURE_COMPAT(sb)  (EXT3_SB(sb)->s_es->s_feature_compat)
                                                                                                                                                                                                     
#define SNAP_HAS_COMPAT_FEATURE(sb,mask)        \
        (SB_FEATURE_COMPAT(sb) & cpu_to_le32(mask))

#define EXT3_FEATURE_COMPAT_SNAPFS             0x0010
#define EXT3_FEATURE_COMPAT_BLOCKCOW           0x0020
/*snaptable info for EXT3*/
#define EXT3_SNAPTABLE_EA       "@snaptable"
                                                                                                                                                                                                     
/* NOTE: these macros are close dependant on the structure of snap ea */
#define SNAP_CNT_FROM_SIZE(size)       ((((size)-sizeof(ino_t)*2)/2)/sizeof(ino_t))
#define SNAP_EA_SIZE_FROM_INDEX(index) (sizeof(ino_t)*2 + 2*sizeof(ino_t)*((index)+1))
                                                                                                                                                                                                     
#define SNAP_EA_INO_BLOCK_SIZE(size)   (((size)-sizeof(ino_t)*2)/2)
#define SNAP_EA_PARENT_OFFSET(size)    (sizeof(ino_t)*2 + SNAP_EA_INO_BLOCK_SIZE((size)))

/* helper functions to manipulate field 'parent' in snap_ea */
static inline int
set_parent_ino(struct snap_ea *pea, int size, int index, ino_t val)
{
       char * p = (char*) pea;
       int offset;
                                                                                                                                                                                                     
       offset = sizeof(ino_t)*2 + (size - sizeof(ino_t)*2)/2;
       offset += sizeof(ino_t) * index;
       *(ino_t*)(p+offset) = val;
                                                                                                                                                                                                     
       return 0;
}
/**
 * fsfilt_ext3_get_indirect - get a specific indirect inode from a primary inode
 * @primary: primary (direct) inode
 * @table: table of @slot + 1 indices in reverse chronological order
 * @slot: starting slot number to check for indirect inode number
 *
 * We locate an indirect inode from a primary inode using the redirection
 * table stored in the primary inode.  Because the desired inode may actually
 * be in a "newer" slot number than the supplied slot, we are given a table
 * of indices in chronological order to search for the correct inode number.
 * We walk table from @slot to 0 looking for a non-zero inode to load.
 *
 * To only load a specific index (and fail if it does not exist), you can
 * pass @table = NULL, and the index number in @slot.  If @slot == 0, the
 * primary inode data is returned.
 *
 * We return a pointer to an inode, or an error.  If the indirect inode for
 * the given index does not exist, NULL is returned.
 */
static struct inode *fsfilt_ext3_get_indirect(struct inode *primary, int *table,
				              int slot)
{
	char buf[EXT3_MAX_SNAP_DATA];
	struct snap_ea *snaps;
	ino_t ino;
	struct inode *inode = NULL;
	int rc = 0, index = 0;

        ENTRY;

	if (slot < 0 || slot > EXT3_MAX_SNAPS || !primary)
		RETURN(NULL);
        
	CDEBUG(D_INODE, "ino %lu, table %p, slot %d\n", primary->i_ino, table,
               slot);
	rc = ext3_xattr_get(primary, EXT3_SNAP_INDEX, EXT3_SNAP_ATTR, buf, 
                             EXT3_MAX_SNAP_DATA); 
	if (rc == -ENODATA) {
		slot = -1;
	} else if (rc < 0) {
		CERROR("attribute read rc=%d \n", rc);
		RETURN(NULL);
	}
	snaps = (struct snap_ea *)buf;

	/* if table is NULL and there is a slot */
	if( !table && slot >= 0) {
		index = slot;
		ino = le32_to_cpu(snaps->ino[index]);
		if(ino)	
                        inode = iget(primary->i_sb, ino);
		GOTO(err_free, rc);
	}
	/* if table is not NULL */
	while (!inode && slot >= 0 && table) {
		index = table[slot];
		ino = le32_to_cpu(snaps->ino[index]);

		CDEBUG(D_INODE, "snap inode at slot %d is %lu\n", slot, ino);
		if (!ino) {
			--slot;
			continue;
		}
		inode = iget(primary->i_sb, ino);
		GOTO(err_free, rc);
	}
	if( slot == -1 && table ) {
		CDEBUG(D_INODE, "redirector not found, using primary\n");
		inode = iget(primary->i_sb, primary->i_ino);
	}
err_free:
	RETURN(inode);
}

/* Save the indirect inode in the snapshot table of the primary inode. */
static int fsfilt_ext3_set_indirect(struct inode *pri, int index, ino_t ind_ino, 
                                    ino_t parent_ino )
{
	char buf[EXT3_MAX_SNAP_DATA];
	struct snap_ea *snaps;
	int err = 0, inlist = 1;
	int ea_size;
	handle_t *handle = NULL;
        ENTRY;
	
	CDEBUG(D_INODE, "(ino %lu, parent %lu): saving ind %lu to index %d\n", 
	       pri->i_ino, parent_ino, ind_ino, index);

	if (index < 0 || index > MAX_SNAPS || !pri)
		RETURN(-EINVAL);
	/* need lock the list before get_attr() to avoid race */
	/* read ea at first */
 	err = ext3_xattr_get(pri, EXT3_SNAP_INDEX ,EXT3_SNAP_ATTR,
		                          buf, EXT3_MAX_SNAP_DATA);
	if (err == -ENODATA || err == -ENOATTR) {
		CDEBUG(D_INODE, "no extended attributes - zeroing\n");
		memset(buf, 0, EXT3_MAX_SNAP_DATA);
		/* XXX
	 	 * To judge a inode in list, we only see if it has snap ea.
	 	 * So take care of snap ea of primary inodes very carefully.
	 	 * Is it right in snapfs EXT3, check it later?
		 */
		inlist = 0; 
	} else if (err < 0 || err > EXT3_MAX_SNAP_DATA) {
		GOTO(out_unlock, err);
	}
	
	handle = ext3_journal_start(pri, SNAP_SETIND_TRANS_BLOCKS);
	if(!handle)
		GOTO(out_unlock, err = PTR_ERR(handle));
	
	snaps = (struct snap_ea *)buf;
	snaps->ino[index] = cpu_to_le32 (ind_ino);
	ea_size = EXT3_MAX_SNAP_DATA;

	set_parent_ino(snaps, ea_size, index, cpu_to_le32(parent_ino));

	err = ext3_xattr_set(handle, pri, EXT3_SNAP_INDEX, EXT3_SNAP_ATTR,
			             buf, EXT3_MAX_SNAP_DATA, 0);
	ext3_mark_inode_dirty(handle, pri);
	ext3_journal_stop(handle, pri);
out_unlock:
	return err;
}

static int ext3_set_generation(struct inode *inode, unsigned long gen)
{
        handle_t *handle;
        int err = 0;
        ENTRY;
                                                                                                                                                                                             
        handle = ext3_journal_start(inode, EXT3_XATTR_TRANS_BLOCKS);
        if( !handle )
                RETURN(-EINVAL);

        err = ext3_xattr_set(handle, inode, EXT3_SNAP_INDEX, 
                             EXT3_SNAP_GENERATION,
                             (char*)&gen, sizeof(int), 0);
        if (err < 0) {
                CERROR("ino %lu, set_ext_attr err %d\n", inode->i_ino, err);
                RETURN(err);
        }
        
        ext3_journal_stop(handle, inode);
        RETURN(0);
}

/*
 * Copy inode metadata from one inode to another, excluding blocks and size.
 * FIXME do we copy EA data - ACLs and such (excluding snapshot data)?
 */
static void ext3_copy_meta(handle_t *handle, struct inode *dst, struct inode *src)
{
	int size;
	
	dst->i_mode = src->i_mode;
	dst->i_nlink = src->i_nlink;
	dst->i_uid = src->i_uid;
	dst->i_gid = src->i_gid;
	dst->i_atime = src->i_atime;
	dst->i_mtime = src->i_mtime;
	dst->i_ctime = src->i_ctime;
//	dst->i_version = src->i_version;
	dst->i_attr_flags = src->i_attr_flags;
	dst->i_generation = src->i_generation;
	dst->u.ext3_i.i_dtime = src->u.ext3_i.i_dtime;
	dst->u.ext3_i.i_flags = src->u.ext3_i.i_flags | EXT3_COW_FL;
#ifdef EXT3_FRAGMENTS
	dst->u.ext3_i.i_faddr = src->u.ext3_i.i_faddr;
	dst->u.ext3_i.i_frag_no = src->u.ext3_i.i_frag_no;
	dst->u.ext3_i.i_frag_size = src->u.ext3_i.i_frag_size;
#endif
	if ((size = ext3_xattr_list(src, NULL, 0)) > 0) {
		char names[size];
		char *name;
		int namelen;

		if (ext3_xattr_list(src, names, 0) < 0)
			return;
		/*
		 * the list of attribute names are stored as NUL terminated
		 * strings, with a double NUL string at the end.
		 */
		name = names;
		while ((namelen = strlen(name))) {
			int attrlen;
			char *buf;
			
			/* don't copy snap data */
			if (!strcmp(name, EXT3_SNAP_ATTR)) {
				CDEBUG(D_INFO, "skipping %s item\n", name);
				continue;
			}
			CDEBUG(D_INODE, "copying %s item\n", name);
			attrlen = ext3_xattr_get(src, EXT3_SNAP_INDEX, 
						 EXT3_SNAP_ATTR, NULL, 0);
			if (attrlen < 0)
				continue;
			OBD_ALLOC(buf, attrlen);
				break;
			if (!buf) {
                                CERROR("No MEM\n");
                                break;
                        }
                        if (ext3_xattr_get(src, EXT3_SNAP_INDEX,
					   EXT3_SNAP_ATTR, buf, attrlen) < 0)
				continue;	
			if (ext3_xattr_set(handle, dst, EXT3_SNAP_INDEX,
					   EXT3_SNAP_ATTR, buf, attrlen, 0) < 0)
				break;
			OBD_FREE(buf, attrlen);
			name += namelen + 1; /* skip name and trailing NUL */
		}
	}
}
static int ext3_copy_reg_block(struct inode *dst, struct inode *src, int blk)
{
        struct page     *src_page, *dst_page; 
        loff_t          offset = blk << src->i_sb->s_blocksize_bits;
        unsigned long   index = offset >> PAGE_CACHE_SHIFT;
        int             rc = 0;
        ENTRY;
        
        /*read the src page*/
        src_page = grab_cache_page(src->i_mapping, index);
        if (src_page == NULL)
                RETURN(-ENOMEM);

        if (!PageUptodate(src_page)) {
                rc = src->i_mapping->a_ops->readpage(NULL, src_page);
                if (rc < 0) {
                        page_cache_release(src_page);
                        RETURN(rc);
                }
        }
        kmap(src_page);
        /*get dst page*/
        
        dst_page = grab_cache_page(dst->i_mapping, index);
        if (dst_page == NULL)
                GOTO(src_page_unlock, rc = -ENOMEM);
        kmap(dst_page);

        rc = dst->i_mapping->a_ops->prepare_write(NULL, dst_page, 0, 
                                                  PAGE_CACHE_SIZE - 1);
        if (rc)
                GOTO(dst_page_unlock, rc = -EFAULT);
        memcpy(page_address(dst_page), page_address(src_page), PAGE_CACHE_SIZE);
        
        flush_dcache_page(dst_page);
        
        rc = dst->i_mapping->a_ops->commit_write(NULL, dst_page, 0, 
                                                 PAGE_CACHE_SIZE - 1);
        if (!rc)
                rc = 1;
dst_page_unlock:
        kunmap(dst_page);
        UnlockPage(dst_page);
        page_cache_release(dst_page);
src_page_unlock:
        kunmap(src_page);
        page_cache_release(src_page);
        RETURN(rc);
}
static int ext3_copy_dir_block(struct inode *dst, struct inode *src, int blk)
{
        struct buffer_head *bh_dst = NULL, *bh_src = NULL;
        int rc = 0;
        handle_t *handle = NULL;
        ENTRY;                                                                                                                                                                                             
        handle = ext3_journal_start(dst, SNAP_COPYBLOCK_TRANS_BLOCKS);
        if( !handle )
                RETURN(-EINVAL);
                                                                                                                                                                                                     
        bh_src = ext3_bread(handle, src, blk, 0, &rc);
        if (!bh_src) {
                CERROR("rcor for src blk %d, rcor %d\n", blk, rc);
                GOTO(exit_relese, rc);
        }
        bh_dst = ext3_getblk(handle, dst, blk, 1, &rc);
        if (!bh_dst) {
                CERROR("rcor for dst blk %d, rcor %d\n", blk, rc);
                GOTO(exit_relese, rc);
        }
        CDEBUG(D_INODE, "copy block %lu to %lu (%ld bytes)\n",
               bh_src->b_blocknr, bh_dst->b_blocknr, src->i_sb->s_blocksize);
        
        ext3_journal_get_write_access(handle, bh_dst);
        memcpy(bh_dst->b_data, bh_src->b_data, src->i_sb->s_blocksize);
        ext3_journal_dirty_metadata(handle, bh_dst);
        rc = 1;

exit_relese:
        if (bh_src) brelse(bh_src);
        if (bh_dst) brelse(bh_dst);
        if (handle)
                ext3_journal_stop(handle, dst);
        RETURN(rc);
}
/* fsfilt_ext3_copy_block - copy one data block from inode @src to @dst.
   No lock here.  User should do the lock.
   User should check the return value to see if the result is correct.
   Return value:
   1:    The block has been copied successfully
   0:    No block is copied, usually this is because src has no such blk
  -1:    Error
*/
                                                                                                                                                                                                     
static int fsfilt_ext3_copy_block (struct inode *dst, struct inode *src, int blk)
{
        int rc = 0;
        ENTRY;                                                                                                                                                                                             
        CDEBUG(D_INODE, "copy blk %d from %lu to %lu \n", blk, src->i_ino, 
               dst->i_ino);
        /*
         * ext3_getblk() require handle!=NULL
         */
        if (S_ISREG(src->i_mode)) { 
                rc = ext3_copy_reg_block(dst, src, blk);
        } else {
                rc = ext3_copy_dir_block(dst, src, blk);
        }

        RETURN(rc);
}
                                                                                                                                                                                             
static inline int ext3_has_ea(struct inode *inode)
{
       return (EXT3_I(inode)->i_file_acl != 0);
}
/* XXXThis function has a very bad effect to
 * the performance of filesystem,
 * will find another way to fix it
 */
static void fs_flushinval_pages(handle_t *handle, struct inode* inode)
{
        if (inode->i_blocks > 0 && inode->i_mapping) {
                fsync_inode_data_buffers(inode);
                truncate_inode_pages(inode->i_mapping, 0);
        }
}
/*  ext3_migrate_data:
 *  MOVE all the data blocks from inode src to inode dst as well as
 *  COPY all attributes(meta data) from inode src to inode dst.
 *  For extended attributes(EA), we COPY all the EAs but skip the Snap EA from 
 *  src to dst. If the dst has Snap EA, then we CAN'T overwrite it. We CAN'T 
 *  copy the src Snap EA. XXX for EA, can we change it to MOVE all the EAs
 *  (exclude Snap EA) to dst and copy it back to src ? This is for LAN free 
 *  backup later.
 */
static int ext3_migrate_data(handle_t *handle, struct inode *dst, 
                             struct inode *src)
{
	unsigned long err = 0;
 	/* 512 byte disk blocks per inode block */
	int bpib = src->i_sb->s_blocksize >> 9;
        ENTRY;
        
	
	if((!dst) || (!src)) 
		RETURN(-EINVAL);
	
	if (dst->i_ino == src->i_ino)
		RETURN(0);

	fs_flushinval_pages(handle, src);
	
	ext3_copy_meta(handle, dst, src);

	CDEBUG(D_INODE, "migrating data blocks from %lu to %lu\n", 
               src->i_ino, dst->i_ino);
	/* Can't check blocks in case of EAs */
       
	memcpy(EXT3_I(dst)->i_data, EXT3_I(src)->i_data,
	       sizeof(EXT3_I(src)->i_data));
       	memset(EXT3_I(src)->i_data, 0, sizeof(EXT3_I(src)->i_data));
	
	ext3_discard_prealloc(src);

	dst->i_size = EXT3_I(dst)->i_disksize = EXT3_I(src)->i_disksize;
        src->i_size = EXT3_I(src)->i_disksize = 0;

	dst->i_blocks = src->i_blocks;
        src->i_blocks = 0;
        /*  Check EA blocks here to modify i_blocks correctly */
        if(ext3_has_ea (src)) {
	        src->i_blocks += bpib;
	        if( ! ext3_has_ea (dst) )
			if( dst->i_blocks >= bpib )
				dst->i_blocks -= bpib;
	} else {
	        if( ext3_has_ea (dst))
			dst->i_blocks += bpib;
	}
	
	CDEBUG(D_INODE, "migrate data from ino %lu to ino %lu\n", src->i_ino, 
               dst->i_ino);
        ext3_mark_inode_dirty(handle, src);
        ext3_mark_inode_dirty(handle, dst);
	RETURN(err);
}

static handle_t * ext3_copy_data(handle_t *handle, struct inode *dst,
				 struct inode *src, int *has_orphan)
{
	unsigned long blocks, blk, cur_blks;
	int low_credits, save_ref;
        ENTRY;

	blocks =(src->i_size + src->i_sb->s_blocksize-1) >>
		 src->i_sb->s_blocksize_bits;
        low_credits = handle->h_buffer_credits - SNAP_BIGCOPY_TRANS_BLOCKS;
	
        CDEBUG(D_INODE, "%lu blocks need to be copied,low credits limit %d\n", 
               blocks, low_credits);

	for (blk = 0, cur_blks= dst->i_blocks; blk < blocks; blk++) {
		if (!ext3_bmap(src->i_mapping, blk))
			continue;
		if(handle->h_buffer_credits <= low_credits) {
			int needed = (blocks - blk) * EXT3_DATA_TRANS_BLOCKS;
			if (needed > 4 * SNAP_COPYBLOCK_TRANS_BLOCKS)
				needed = 4 * SNAP_COPYBLOCK_TRANS_BLOCKS;
			if (journal_extend(handle, needed)) {
				CDEBUG(D_INFO, "create_indirect:fail to extend "
				       "journal, restart trans\n");
                                
                                if(!*has_orphan) {
					CDEBUG(D_INODE, "add orphan ino %lu" 
                                               "nlink %d to orphan list \n",
					        dst->i_ino, dst->i_nlink); 
					ext3_orphan_add(handle, dst);
					*has_orphan = 1;
				}
				dst->u.ext3_i.i_disksize =
					blk * dst->i_sb->s_blocksize;
				dst->i_blocks = cur_blks;
				dst->i_mtime = CURRENT_TIME;
				ext3_mark_inode_dirty(handle, dst);
				/*
				 * We can be sure the last handle was stoped
				 * ONLY if the handle's reference count is 1
				 */
				save_ref = handle->h_ref;
				handle->h_ref = 1;
				if( ext3_journal_stop(handle, dst) ){
					CERROR("fail to stop journal\n");
					handle = NULL;
					break;
				}
				handle = ext3_journal_start(dst,
						low_credits + needed);
				if( !handle ){
					CERROR("fail to restart handle\n");
					break;
				}
				handle->h_ref = save_ref;
			}
		}
		if (fsfilt_ext3_copy_block( dst, src, blk) < 0 )
			break;
		cur_blks += dst->i_sb->s_blocksize / 512;
	}
	
        dst->i_size = dst->u.ext3_i.i_disksize = src->i_size;
	RETURN(handle);
}
/*Here delete the data of that pri inode 
 *FIXME later, should throw the blocks of 
 *primary inode directly
 */
static int ext3_throw_inode_data(handle_t *handle, struct inode *inode)	
{	
        struct inode *tmp = NULL;
        ENTRY;
        
        tmp = ext3_new_inode(handle, inode, (int)inode->i_mode, 0);
        if(tmp) { 
                CERROR("ext3_new_inode error\n");
                RETURN(-EIO);
        }                
	double_down(&inode->i_sem, &tmp->i_sem);
        ext3_migrate_data(handle, tmp, inode);
	double_up(&inode->i_sem, &tmp->i_sem);
        tmp->i_nlink = 0;
        iput(tmp);	
        RETURN(0);
}
/**
 * fsfilt_ext3_create_indirect - copy data, attributes from primary to new indir inode
 * @pri: primary (source) inode
 * @index: index in snapshot table where indirect inode should be stored
 * @delete: flag that the primary inode is being deleted
 *
 * We copy all of the data blocks from the @*src inode to the @*dst inode, as
 * well as copying the attributes from @*src to @*dst.  If @delete == 1, then
 * the primary inode will only be a redirector and will appear deleted.
 *
 * FIXME do we move EAs, only non-snap EAs, what?
 * FIXME we could do readpage/writepage, but we would have to handle block
 *       allocation then, and it ruins sparse files for 1k/2k filesystems,
 *       at the expense of doing a memcpy.
 */
static struct inode* fsfilt_ext3_create_indirect(struct inode *pri, int index, 
                                                 unsigned int gen, 
                                                 struct inode* parent,
			                         int del)
{
	struct inode *ind = NULL;
	handle_t *handle = NULL;
	int err = 0;
	int has_orphan = 0;
        ENTRY;
        
	if( pri == pri->i_sb->u.ext3_sb.s_journal_inode ){
		CERROR("TRY TO COW JOUNRAL\n");
		RETURN(ERR_PTR(-EINVAL));
	}
	CDEBUG(D_INODE, "creating indirect inode for %lu at index %d, %s pri\n",
	       pri->i_ino, index, del ? "deleting" : "preserve");

	ind = fsfilt_ext3_get_indirect(pri, NULL, index);

	handle = ext3_journal_start(pri, SNAP_CREATEIND_TRANS_BLOCKS);
	if( !handle ) {
                CERROR("handle not NULL\n");
		RETURN(ERR_PTR(-EINVAL));
        }
	/* XXX ? We should pass an err argument to get_indirect and precisely
 	 * detect the errors, for some errors, we should exit right away.
 	 */

	/* if the option is SNAP_DEL_PRI_WITH_IND and there is an indirect, 
	 * we just free the primary data blocks and mark this inode delete
	 */
	if((del) && ind && !IS_ERR(ind)) {
		/* for directory, we don't free the data blocks, 
		 * or ext3_rmdir will report errors "bad dir, no data blocks" 
		 */
		CDEBUG(D_INODE, "del==SNAP_DEL_PRI_WITH_IND && ind\n");
		if(!S_ISDIR(pri->i_mode)) {	
                        err = ext3_throw_inode_data(handle, pri);
			if (err)
                                GOTO(exit, err);
                        pri->i_nlink = 1;
		}
		pri->u.ext3_i.i_dtime = CURRENT_TIME;
		ext3_mark_inode_dirty(handle, pri);
		GOTO(exit, err=0);
	}

	if (ind && !IS_ERR(ind)) {
		CDEBUG(D_INODE, "existing indirect ino %lu for %lu: index %d\n",
		       ind->i_ino, pri->i_ino, index);
	
		GOTO(exit, err=0);
        }
	
        /* XXX: check this, ext3_new_inode, the first arg should be "dir" */ 
	ind = ext3_new_inode(handle, pri, (int)pri->i_mode, 0);
	if (IS_ERR(ind))
		GOTO(exit, err);
	CDEBUG(D_INODE, "got new inode %lu\n", ind->i_ino);
	ind->i_rdev = pri->i_rdev;
	ind->i_op = pri->i_op;
      
        /*init ind ops*/ 
        memcpy(ind->i_op, pri->i_op, sizeof(*pri->i_op));
        memcpy(ind->i_fop, pri->i_fop, sizeof(*pri->i_fop));
        memcpy(ind->i_mapping->a_ops, pri->i_mapping->a_ops, 
               sizeof(*pri->i_mapping->a_ops));
         
        ext3_set_generation(ind, (unsigned long)gen);
	/* If we are deleting the primary inode, we want to ensure that it is
	 * written to disk with a non-zero link count, otherwise the next iget
	 * and iput will mark the inode as free (which we don't want, we want
	 * it to stay a redirector).  We fix this in ext3_destroy_indirect()
	 * when the last indirect inode is removed.
	 *
	 * We then do what ext3_delete_inode() does so that the metadata will
	 * appear the same as a deleted inode, and we can detect it later.
	 */
	if (del) {
		CDEBUG(D_INODE, "deleting primary inode\n");
		
		down(&ind->i_sem);
		err = ext3_migrate_data(handle, ind, pri);
		if (err)
			GOTO(exit_unlock, err);

		err = fsfilt_ext3_set_indirect(pri, index, ind->i_ino, parent->i_ino);
		if (err)
			GOTO(exit_unlock, err);

		/* XXX for directory, we copy the block back 
		 * or ext3_rmdir will report errors "bad dir, no data blocks" 
		 */
		if( S_ISDIR(pri->i_mode)) {
			handle = ext3_copy_data(handle, pri, ind, &has_orphan);
			if(!handle) 
				GOTO(exit_unlock, err= -EINVAL);
		}

		pri->u.ext3_i.i_flags |= EXT3_DEL_FL;
		ind->u.ext3_i.i_flags |= EXT3_COW_FL;
		if(S_ISREG(pri->i_mode)) pri->i_nlink = 1;
		pri->u.ext3_i.i_dtime = CURRENT_TIME;
		//pri->u.ext3_i.i_generation++;
		ext3_mark_inode_dirty(handle, pri);
		ext3_mark_inode_dirty(handle, ind);
		up(&ind->i_sem);
	} else {
		down(&ind->i_sem);
		err = ext3_migrate_data(handle, ind, pri);
		if (err)
			goto exit_unlock;

        	/* for regular files we do blocklevel COW's maybe */
        	if (EXT3_HAS_COMPAT_FEATURE(pri->i_sb, EXT3_FEATURE_COMPAT_BLOCKCOW)
            	    && S_ISREG(pri->i_mode)) {

			CDEBUG(D_INODE, "ino %lu, do block cow\n", pri->i_ino);
			/* because after migrate_data , pri->i_size is 0 */
			pri->i_size = ind->i_size;
        	}
		else {
			int bpib = pri->i_sb->s_blocksize >> 9;
			CDEBUG(D_INODE, "ino %lu, do file cow\n", pri->i_ino);

			/* XXX: can we do this better? 
			 * If it's a fast symlink, we should copy i_data back!
			 * The criteria to determine a fast symlink is:
			 * 1) it's a link and its i_blocks is 0
			 * 2) it's a link and its i_blocks is bpib ( the case 
			 *    it has been cowed and has ea )
			 */
                        if( S_ISLNK(ind->i_mode) && ((ind->i_blocks == 0) || 
                            (ext3_has_ea(ind) && ind->i_blocks == bpib))) {
				CDEBUG(D_INODE, "ino %lu is fast symlink\n", pri->i_ino);
				memcpy(EXT3_I(pri)->i_data, EXT3_I(ind)->i_data,
				       sizeof(EXT3_I(ind)->i_data));
				pri->i_size = ind->i_size;
			}
			else {
				handle = ext3_copy_data(handle, pri, ind, &has_orphan);
				if (!handle)
					GOTO(exit_unlock, err);
			}
		}
		/* set cow flag for ind */
		ind->u.ext3_i.i_flags |= EXT3_COW_FL;
		pri->u.ext3_i.i_flags &= ~EXT3_COW_FL;

		ext3_mark_inode_dirty(handle, pri);
		ext3_mark_inode_dirty(handle, ind);

		err = fsfilt_ext3_set_indirect(pri, index, ind->i_ino, parent->i_ino);
		if (err)
			GOTO(exit_unlock, err);
		up(&ind->i_sem);
	}

	if (!EXT3_HAS_COMPAT_FEATURE(pri->i_sb,
	                             EXT3_FEATURE_COMPAT_SNAPFS)) {
		lock_super(pri->i_sb);
		ext3_journal_get_write_access(handle, pri->i_sb->u.ext3_sb.s_sbh);
		pri->i_sb->u.ext3_sb.s_es->s_feature_compat |=
			cpu_to_le32(EXT3_FEATURE_COMPAT_SNAPFS);
		ext3_journal_dirty_metadata(handle, pri->i_sb->u.ext3_sb.s_sbh);
		pri->i_sb->s_dirt = 1;
		unlock_super(pri->i_sb);
	}
	if (has_orphan) {
		CDEBUG(D_INODE, "del %lu nlink %d from orphan list\n", 
		       ind->i_ino, ind->i_nlink);
		ext3_orphan_del(handle, ind);
	}
	ext3_journal_stop(handle, pri);

	RETURN(ind);

exit_unlock:
	up(&ind->i_sem);
	ind->i_nlink = 0;
exit:
	if (has_orphan) {
		CDEBUG(D_INODE, "del %lu nlink %d from orphan list\n", 
		       ind->i_ino, ind->i_nlink);
		ext3_orphan_del(handle, ind);
	}
	iput(ind);
	ext3_journal_stop(handle, pri);
        
        RETURN(ERR_PTR(err));
}

static int fsfilt_ext3_snap_feature (struct super_block *sb, int feature, int op) {
                                                                                                                                                                                                     
        int rc = -EINVAL;
        handle_t *handle;
        ENTRY;
	
	switch (op) {
                case SNAP_SET_FEATURE:
                        handle = ext3_journal_start(sb->s_root->d_inode, 1);
                        lock_super(sb);
                        ext3_journal_get_write_access(handle, EXT3_SB(sb)->s_sbh);
                        SB_FEATURE_COMPAT(sb) |= cpu_to_le32(feature);
                        sb->s_dirt = 1;
                        ext3_journal_dirty_metadata(handle, EXT3_SB(sb)->s_sbh);
                        unlock_super(sb);
                        ext3_journal_stop(handle, sb->s_root->d_inode);
                        break;
                case SNAP_CLEAR_FEATURE:
                        handle = ext3_journal_start(sb->s_root->d_inode, 1);
                        lock_super(sb);
                        ext3_journal_get_write_access(handle, EXT3_SB(sb)->s_sbh);
                        SB_FEATURE_COMPAT(sb) &= ~cpu_to_le32(feature);
                        ext3_journal_dirty_metadata(handle, EXT3_SB(sb)->s_sbh);
                        sb->s_dirt = 1;
                        unlock_super(sb);
                        ext3_journal_stop(handle, sb->s_root->d_inode);
                        break;
                case SNAP_HAS_FEATURE:
                        /*FIXME should lock super or not*/
                        rc = SNAP_HAS_COMPAT_FEATURE(sb, feature);
                        break;
                default:
                        break;
        }
        RETURN(rc);
}
/*
 * is_redirector - determines if a primary inode is a redirector
 * @inode: primary inode to test
 *
 * Returns 1 if the inode is a redirector, 0 otherwise.
 */
static int fsfilt_ext3_is_redirector(struct inode *inode)
{
        int is_redirector = 0;
        int rc;
        ENTRY;
                                                                                                                                                                                                     
        rc = ext3_xattr_get(inode, EXT3_SNAP_INDEX ,EXT3_SNAP_ATTR,
                                          NULL, 0);
        if (rc > 0 && rc <= MAX_SNAP_DATA)
                is_redirector = 1;
        CDEBUG(D_INODE, "inode %lu %s redirector\n", inode->i_ino,
               is_redirector ? "is" : "isn't");
	RETURN(is_redirector);
}
/*if it's indirect inode or not */
static int fsfilt_ext3_is_indirect(struct inode *inode)
{
        if (EXT3_I(inode)->i_flags |= EXT3_COW_FL)
                return 1;
        else
                return 0;
}

/* get the indirect ino at index of the primary inode
 * return value:        postive:        indirect ino number
 *                      negative or 0:  error
 */
static ino_t fsfilt_ext3_get_indirect_ino(struct super_block *sb, 
                                          ino_t primary_ino, int index)
{
        char buf[EXT3_MAX_SNAP_DATA];
        struct inode *primary = NULL;
        struct snap_ea *snaps;
        ino_t ino = 0;
        int err;
        ENTRY;                                                                                                                                                                                             
        if (index < 0 || index > EXT3_MAX_SNAPS || !primary)
                RETURN(0);
        primary = iget(sb, primary_ino);   
       
        if (!primary) {
                err = -EIO;
                CERROR("attribute read error=%d", err);
                GOTO (err_free, ino = err); 
        }                                                                                                                                                                                              
        err = ext3_xattr_get(primary, EXT3_SNAP_INDEX, EXT3_SNAP_ATTR,
                             buf, EXT3_MAX_SNAP_DATA);
        if (err == -ENOATTR) {
                GOTO(err_free, ino = -ENOATTR);
        } else if (err < 0) {
                CERROR(" attribute read error err=%d\n", err);
                GOTO(err_free, ino = err);
        }
        snaps = (struct snap_ea *)buf;
        ino = le32_to_cpu (snaps->ino[index]);
        CDEBUG(D_INODE, "snap ino for %ld at index %d is %lu\n",
               primary->i_ino, index, ino);
err_free:
        if (primary)
                iput(primary); 
        RETURN(ino);
}
                                                                                                                                                                                                     

/* The following functions are used by destroy_indirect */
#define inode_bmap(inode, nr) (EXT3_I(inode)->i_data[(nr)])
#define inode_setbmap(inode, nr, physical) (EXT3_I(inode)->i_data[(nr)]=(physical))
static inline int block_bmap(struct buffer_head * bh, int nr)
{
        int tmp;
                                                                                                                                                                                                     
        if (!bh)
                return 0;
        tmp = le32_to_cpu(((u32 *) bh->b_data)[nr]);
        brelse (bh);
        return tmp;
}
                                                                                                                                                                                                     
static inline int block_setbmap(handle_t *handle, struct buffer_head * bh, 
                                 int nr, int physical)
{
                                                                                                                                                                                                     
        if (!bh)
                return 0;
        ext3_journal_get_write_access(handle, bh);
        ((u32 *) bh->b_data)[nr] = cpu_to_le32(physical);
        ext3_journal_dirty_metadata(handle, bh);
        brelse (bh);
        return 1;
}

static int ext3_migrate_block(handle_t *handle, struct inode * dst, 
                              struct inode *src, int block)
{
	int i1_d=0, i1_s=0, i2_d=0, i2_s=0, i3_d=0, i3_s=0;
	int addr_per_block = EXT3_ADDR_PER_BLOCK(src->i_sb);
	int addr_per_block_bits = EXT3_ADDR_PER_BLOCK_BITS(src->i_sb);
	unsigned long blksz = src->i_sb->s_blocksize;
	kdev_t ddev = dst->i_dev;
	kdev_t sdev = src->i_dev;
	int physical = 0;
        ENTRY;        

	if (block < 0) {
		CWARN("ext3_migrate_block block < 0 %p \n", src->i_sb);
		RETURN(0);
	}
	if (block >= EXT3_NDIR_BLOCKS + addr_per_block +
		(1 << (addr_per_block_bits * 2)) +
		((1 << (addr_per_block_bits * 2)) << addr_per_block_bits)) {
		CWARN("ext3_migrate_block block > big %p \n", src->i_sb);
		RETURN(0);
	}
	/* EXT3_NDIR_BLOCK */
	if (block < EXT3_NDIR_BLOCKS) {
		if(inode_bmap(dst, block))	
                        RETURN(0);
		else {
			if( (physical = inode_bmap(src, block)) ) {
				inode_setbmap (dst, block, physical);
				inode_setbmap (src, block, 0);
				RETURN(1);
			}
			else 
				RETURN(0);
		}
	}
	/* EXT3_IND_BLOCK */
	block -= EXT3_NDIR_BLOCKS;
	if (block < addr_per_block) {
		i1_d = inode_bmap (dst, EXT3_IND_BLOCK);
		if (!i1_d) {
			physical = inode_bmap(src, EXT3_IND_BLOCK);
			if( physical ) {
				inode_setbmap (dst, EXT3_IND_BLOCK, physical);
				inode_setbmap (src, EXT3_IND_BLOCK, 0);
				RETURN(1);
			}
			else 
				RETURN(0);
		}
		if(block_bmap(bread(ddev, i1_d, blksz), block)) 
			RETURN(0);

		i1_s = inode_bmap (src, EXT3_IND_BLOCK);
		if( !i1_s)	RETURN(0);

		physical = block_bmap(bread(sdev, i1_s, blksz), block);

		if( physical) {
			block_setbmap(handle, bread(ddev, i1_d, blksz),block,
                                      physical); 
			block_setbmap(handle, bread(sdev, i1_s, blksz),block,0);
			RETURN(1); 
		}
		else 
			RETURN(0);
	}
	/* EXT3_DIND_BLOCK */
	block -= addr_per_block;
	if (block < (1 << (addr_per_block_bits * 2))) {
		i1_d = inode_bmap (dst, EXT3_DIND_BLOCK);
		i1_s = inode_bmap (src, EXT3_DIND_BLOCK);
		if (!i1_d) {
			if( (physical = inode_bmap(src, EXT3_DIND_BLOCK)) ) {
				inode_setbmap (dst, EXT3_DIND_BLOCK, physical);
				inode_setbmap (src, EXT3_DIND_BLOCK, 0);
				RETURN(1);
			}
			else 
				RETURN(0);
		}
		i2_d = block_bmap (bread (ddev, i1_d, blksz),
				block >> addr_per_block_bits);

		if (!i2_d) {
			
			if(!i1_s) 	RETURN(0);

			physical = block_bmap(bread (sdev, i1_s, blksz),
				               block >> addr_per_block_bits);
			if(physical) {
				block_setbmap(handle, bread (ddev, i1_d,blksz), 
					      block >> addr_per_block_bits, 
                                              physical);
				block_setbmap(handle, bread (sdev, i1_s,blksz), 
					      block >> addr_per_block_bits, 0);
				RETURN(1);
			}
			else
				RETURN(0);
		}
		physical = block_bmap(bread (ddev, i2_d, blksz),
				      block & (addr_per_block - 1));
		if(physical) 
				RETURN(0);
		else {
			i2_s = 	block_bmap (bread (sdev, i1_s, blksz),
				block >> addr_per_block_bits);
			if(!i2_s) 	RETURN(0);
	
			physical = block_bmap(bread (sdev, i2_s, blksz),
				   block & (addr_per_block - 1));
			if(physical) {
				block_setbmap(handle, bread (ddev, i2_d, blksz),
				   block & (addr_per_block - 1), physical);
				block_setbmap(handle, bread (sdev, i2_s, blksz),
				   block & (addr_per_block - 1), 0);
				RETURN(1);
			}
			else 
				RETURN(0);
		}
		
	}
	/* EXT3_TIND_BLOCK */
	block -= (1 << (addr_per_block_bits * 2));
	i1_d = inode_bmap (dst, EXT3_TIND_BLOCK);
	i1_s = inode_bmap (src, EXT3_TIND_BLOCK);
	if (!i1_d) {
		if((physical = inode_bmap(src, EXT3_TIND_BLOCK)) )
		        inode_setbmap (dst, EXT3_TIND_BLOCK, physical);
		else 
			RETURN(0);
	}
	i2_d = block_bmap(bread (ddev, i1_d, blksz),
			   block >> (addr_per_block_bits * 2));

	if(i1_s) i2_s = block_bmap(bread(sdev, i1_s, blksz),
			           block >> (addr_per_block_bits * 2));

	if (!i2_d) {
		if( !i1_s) 	RETURN(0);
		
                physical = block_bmap(bread (sdev, i1_s, blksz),
			               block >> (addr_per_block_bits * 2));
		if(physical) {
			block_setbmap(handle, bread (ddev, i1_d, blksz),
				      block >> (addr_per_block_bits * 2), physical);
			block_setbmap(handle, bread (sdev, i1_s, blksz),
				      block >> (addr_per_block_bits * 2), 0);
			RETURN(1);
		}
		else
			RETURN(0);
	}
	i3_d = block_bmap (bread (ddev, i2_d, blksz),
			(block >> addr_per_block_bits) & (addr_per_block - 1));
	if( i2_s) i3_s = block_bmap (bread (sdev, i2_s, blksz),
			(block >> addr_per_block_bits) & (addr_per_block - 1));
	
	if (!i3_d) {
		if (!i2_s)	RETURN(0);	
		physical = block_bmap (bread (sdev, i2_s, blksz),
			(block >> addr_per_block_bits) & (addr_per_block - 1));
		if( physical) {
			block_setbmap (handle, bread (ddev, i2_d, blksz),
			               (block >> addr_per_block_bits) & 
                                       (addr_per_block - 1), physical);
			block_setbmap (handle, bread (sdev, i2_s, blksz),
			               (block >> addr_per_block_bits) & 
                                       (addr_per_block - 1),0);
			RETURN(1);
		}
		else
			RETURN(0);
	}
	physical = block_bmap (bread (ddev, i3_d, blksz),
			   block & (addr_per_block - 1)) ;
	if(physical)    
                RETURN(0);
	else {
		if(!i3_s)	
                        RETURN(0);	
		physical = block_bmap(bread(sdev, i3_s, blksz),
			              block & (addr_per_block - 1));
		if(physical) {
			block_setbmap (handle, bread (ddev, i3_d, blksz),
			               block & (addr_per_block - 1), physical);
			block_setbmap (handle, bread (sdev, i3_s, blksz),
			               block & (addr_per_block - 1), 0); 
			RETURN(1);
		}
		else
			RETURN(0); 
	}
}

/* Generate i_blocks from blocks for an inode .
 * We also calculate EA block here.
 */
static unsigned long calculate_i_blocks(struct inode *inode, int blocks)
{
        /* 512 byte disk blocks per inode block */
        int bpib = inode->i_sb->s_blocksize >> 9;
        int addr_per_block = EXT3_ADDR_PER_BLOCK(inode->i_sb);
        unsigned long i_blocks = 0;
        int i=0, j=0, meta_blocks = 0;
        ENTRY;                                                                                                                                                                                                     
        if(!inode)    
                RETURN(0);
        
        if( blocks < 0 ) {
                /* re-calculate blocks here */
                blocks = (inode->i_size + inode->i_sb->s_blocksize-1)
                          >> inode->i_sb->s_blocksize_bits;
        }
                                                                                                                                                                                                     
        /* calculate data blocks */
        for(i = 0; i < blocks; i++) {
                if(ext3_bmap(inode->i_mapping, i))
                        i_blocks += bpib;
        }
        /* calculate meta blocks */
        blocks -= EXT3_NDIR_BLOCKS;
        if(blocks > 0) {
                meta_blocks++;
                blocks -= addr_per_block;
        }
        if( blocks > 0 ) meta_blocks++;
        i=0;
        
        while( (blocks > 0) && (i < addr_per_block) ) {
                meta_blocks++;
                blocks -= addr_per_block;
                i++;
        }
        
        if ( blocks > 0 ) meta_blocks += 2;
        i=0; j=0;
        
        while( blocks > 0) {
                meta_blocks++;
                blocks -= addr_per_block;
                i++;
                if(i >= addr_per_block  ) {
                        i=0;
                        j++;
                }
                if( j >= addr_per_block) {
                        j=0;
                        meta_blocks++;
                }
        }
        /* calculate EA blocks */
        if(ext3_has_ea(inode))       
                meta_blocks++;
                                                                                                                                                                                                     
        i_blocks += meta_blocks * bpib;
        CDEBUG(D_INODE, "ino %lu, get i_blocks %lu\n", inode->i_ino, i_blocks);
        
        RETURN(i_blocks);
}

/**
 * fsfilt_ext3_destroy_indirect - delete an indirect inode from the table
 * @pri: primary inode
 * @ind: indirect inode
 * @index: index of inode that should be deleted
 *
 * We delete the @*ind inode, and remove it from the snapshot table.  If @*ind
 * is NULL, we use the inode at @index.
 */
static int fsfilt_ext3_destroy_indirect(struct inode *pri, int index, 
				        struct inode *next_ind)
{
	char buf[EXT3_MAX_SNAP_DATA];
	struct snap_ea *snaps;
	struct inode *ind;
	int save = 0, i=0, err = 0;
	handle_t *handle=NULL;
	time_t ctime;
        ENTRY;

	if (index < 0 || index > EXT3_MAX_SNAPS)
		RETURN(0);

	if( pri == pri->i_sb->u.ext3_sb.s_journal_inode ){
		CERROR("TRY TO DESTROY JOURNAL'S IND\n");
		RETURN(-EINVAL);
	}

	err = ext3_xattr_get(pri, EXT3_SNAP_INDEX, EXT3_SNAP_ATTR,
	                     buf, EXT3_MAX_SNAP_DATA);
	if (err < 0) {
		CERROR("inode %lu attribute read error\n", pri->i_ino);
		RETURN(err);
	}
	
	snaps = (struct snap_ea *)buf;
	if ( !snaps->ino[index] ) {
		CERROR("for pri ino %lu, index %d, redirect ino is 0\n",
		       pri->i_ino, index);	
		RETURN(-EINVAL);
	}

	CDEBUG(D_INODE, "for pri ino %lu, reading inode %lu at index %d\n", 
	       pri->i_ino, (ulong)le32_to_cpu(snaps->ino[index]), index);

	ind = iget(pri->i_sb, le32_to_cpu (snaps->ino[index]));

	if ( !ind || IS_ERR(ind) || is_bad_inode(ind)) 
		RETURN(-EINVAL);

	CDEBUG(D_INODE, "iget ind %lu, ref count = %d\n", 
	       ind->i_ino, atomic_read(&ind->i_count));

	handle = ext3_journal_start(pri, SNAP_DESTROY_TRANS_BLOCKS);
	if (!handle) {
		iput(ind);
		RETURN(-EINVAL);
	}
	/* if it's block level cow, first copy the blocks back */	
  	if (EXT3_HAS_COMPAT_FEATURE(pri->i_sb, EXT3_FEATURE_COMPAT_BLOCKCOW) &&
	    S_ISREG(pri->i_mode)) {
		int blocks;
		
                if (!next_ind) {	
			next_ind = pri;
			down(&ind->i_sem);
		} else {
			double_down(&next_ind->i_sem, &ind->i_sem);
		}
		blocks = (next_ind->i_size + next_ind->i_sb->s_blocksize-1) 
			  >> next_ind->i_sb->s_blocksize_bits;

		CDEBUG(D_INODE, "migrate block back from ino %lu to %lu\n",
		       ind->i_ino, next_ind->i_ino);

		for(i = 0; i < blocks; i++) {
			if( ext3_bmap(next_ind->i_mapping, i) ) 
				continue;
			if( !ext3_bmap(ind->i_mapping, i) ) 
				continue;
			ext3_migrate_block(handle, next_ind, ind, i) ;
		}
		/* Now re-compute the i_blocks */
		/* XXX shall we take care of ind here? probably not */
		next_ind->i_blocks = calculate_i_blocks( next_ind, blocks);
		ext3_mark_inode_dirty(handle, next_ind);

		if (next_ind == pri) 
			up(&ind->i_sem);
		else 
			double_up(&next_ind->i_sem, &ind->i_sem);

	}
	
	CDEBUG(D_INODE, "delete indirect ino %lu\n", ind->i_ino);
	CDEBUG(D_INODE, "iput ind %lu, ref count = %d\n", ind->i_ino, 
               atomic_read(&ind->i_count));
	
        ind->i_nlink = 0;
	iput (ind);

	snaps->ino[index] = cpu_to_le32(0);
	for (i = 0; i < EXT3_MAX_SNAPS; i++)
		save += snaps->ino[i];


	/*Should we remove snap feature here*/
        /*
	 * If we are deleting the last indirect inode, and the primary inode
	 * has already been deleted, then mark the primary for deletion also.
	 * Otherwise, if we are deleting the last indirect inode remove the
	 * snaptable from the inode.	XXX
	 */
	if (!save && pri->u.ext3_i.i_dtime) {
		CDEBUG(D_INODE, "deleting primary %lu\n", pri->i_ino);
		pri->i_nlink = 0;
		/* reset err to 0 now */
		err = 0;
	} else {
		CDEBUG(D_INODE, "%s redirector table\n", 
                       save ? "saving" : "deleting");
		/* XXX: since set ea will modify i_ctime of pri, 
			so save/restore i_ctime. Need this necessary ? */
		ctime = pri->i_ctime;	
		err = ext3_xattr_set(handle, pri, EXT3_SNAP_INDEX, EXT3_SNAP_ATTR,
				     save ? buf : NULL, EXT3_MAX_SNAP_DATA, 0);
		pri->i_ctime = ctime;
		ext3_mark_inode_dirty(handle, pri);
	}
	ext3_journal_stop(handle, pri);
	
        RETURN(err);
}

/* restore a primary inode with the indirect inode at index */
static int fsfilt_ext3_restore_indirect(struct inode *pri, int index)
{
	struct inode *ind;
	int err = 0;
	handle_t *handle = NULL;
        ENTRY;

	if (index < 0 || index > EXT3_MAX_SNAPS)
		RETURN(-EINVAL);

	if( pri == pri->i_sb->u.ext3_sb.s_journal_inode ){
		CERROR("TRY TO RESTORE JOURNAL\n");
		RETURN(-EINVAL);
	}
	CDEBUG(D_INODE, "pri ino %lu, index %d\n", pri->i_ino, index);

	ind = fsfilt_ext3_get_indirect(pri, NULL, index);

	if (!ind) 
		RETURN(-EINVAL);

	CDEBUG(D_INODE, "restore ino %lu to %lu\n", pri->i_ino, ind->i_ino);

	handle = ext3_journal_start(pri, SNAP_RESTORE_TRANS_BLOCKS);
	if( !handle )
		RETURN(-EINVAL);
	/* first destroy all the data blocks in primary inode */
	/* XXX: check this, ext3_new_inode, the first arg should be "dir" */
        err = ext3_throw_inode_data(handle, pri);
	if (err) {
		CERROR("restore_indirect, new_inode err\n");
                RETURN(err);
        }	
	double_down(&pri->i_sem, &ind->i_sem);
	ext3_migrate_data(handle, pri, ind);
	pri->u.ext3_i.i_flags &= ~EXT3_COW_FL;
	ext3_mark_inode_dirty(handle, pri);
	double_up(&pri->i_sem, &ind->i_sem);
	iput(ind);
        
        //fsfilt_ext3_destroy_indirect(pri, index);
	ext3_journal_stop(handle, pri);
	
        RETURN(err);
}

/**
 * ext3_snap_iterate - iterate through all of the inodes
 * @sb: filesystem superblock
 * @repeat: pointer to function called on each valid inode
 * @start: inode to start iterating at
 * @priv: private data to the caller/repeat function
 *
 * If @start is NULL, then we do not return an inode pointer.  If @*start is
 * NULL, then we start at the beginning of the filesystem, and iterate over
 * all of the inodes in the system.  If @*start is non-NULL, then we start
 * iterating at this inode.
 *
 * We call the repeat function for each inode that is in use.  The repeat
 * function must check if this is a redirector (with is_redirector) if it
 * only wants to operate on redirector inodes.  If there is an error or
 * the repeat function returns non-zero, we return the last inode operated
 * on in the @*start parameter.  This allows the caller to restart the
 * iteration at this inode if desired, by returning a positive value.
 * Negative return values indicate an error.
 *
 * NOTE we cannot simply traverse the existing filesystem tree from the root
 *      inode, as there may be disconnected trees from deleted files/dirs
 *
 * FIXME If there was a list of inodes with EAs, we could simply walk the list
 * intead of reading every inode.  This is an internal implementation issue.
 */

static int ext3_iterate_all(struct super_block *sb,
			    int (*repeat)(struct inode *inode,void *priv),
			    struct inode **start, void *priv)
{
	struct inode *tmp = NULL;
	int gstart, gnum, err = 0;
	ino_t istart, ibase;
        ENTRY;

	if (!start)
		start = &tmp;
	if (!*start) {
		*start = iget(sb, EXT3_ROOT_INO);
		if (!*start) 
			GOTO(exit, err = -ENOMEM);
		
                if (is_bad_inode(*start)) 
	                GOTO(exit, err = -EIO);
	}
	if ((*start)->i_ino > le32_to_cpu(EXT3_SB(sb)->s_es->s_inodes_count)) {
		CERROR("invalid starting inode %ld\n",(*start)->i_ino);
	        GOTO(exit, err = -EINVAL); 
	}
	if ((*start)->i_ino < EXT3_FIRST_INO(sb)) {
		if ((err = (*repeat)(*start, priv) != 0))
			GOTO(exit, err);
		iput(*start);
		*start = iget(sb, EXT3_FIRST_INO(sb));
		if (!*start)
                        GOTO(exit, err = -ENOMEM);
		if (is_bad_inode(*start)) 
			GOTO(exit, err = -EIO);
	}

	gstart = ((*start)->i_ino - 1) / EXT3_INODES_PER_GROUP(sb);
	istart = ((*start)->i_ino - 1) % EXT3_INODES_PER_GROUP(sb);
	ibase = gstart * EXT3_INODES_PER_GROUP(sb);
	for (gnum = gstart; gnum < EXT3_SB(sb)->s_groups_count;
	     gnum++, ibase += EXT3_INODES_PER_GROUP(sb)) {
		struct ext3_group_desc * gdp;
		int bitmap_nr, ibyte;
		char *bitmap;

		gdp = ext3_get_group_desc (sb, gnum, NULL);
		if (!gdp || le16_to_cpu(gdp->bg_free_inodes_count) ==
		    EXT3_INODES_PER_GROUP(sb))
			continue;

		bitmap_nr = ext3_load_inode_bitmap(sb, gnum);
		if (bitmap_nr < 0)
			continue;

		bitmap = EXT3_SB(sb)->s_inode_bitmap[bitmap_nr]->b_data;
		for (ibyte = istart >> 3; ibyte < EXT3_INODES_PER_GROUP(sb) >> 3;
		     ibyte++) {
			int i, bit;

			if (!bitmap[ibyte])
				continue;

			/* FIXME need to verify if bit endianness will
			 *       work properly here for all architectures.
			 */
			for (i = 1, bit = 1; i <= 8; i++, bit <<= 1) {
				ino_t ino = ibase + (ibyte << 3) + i;

				if ((bitmap[ibyte] & bit) == 0)
					continue;
				if (*start) {
					if (ino < (*start)->i_ino)
						continue;
				} else {
					*start = iget(sb, ino);
					if (!*start) 
						GOTO(exit, err = -ENOMEM);
					if (is_bad_inode(*start)) 
						GOTO(exit, err = -EIO);
				}
				if ((err = (*repeat)(*start, priv)) != 0)
					GOTO(exit, err);
				iput(*start);
				*start = NULL;
			}
		}
		istart = 0;
	}
exit:
	iput(tmp);
	RETURN(err);
}

static int fsfilt_ext3_iterate(struct super_block *sb,
			       int (*repeat)(struct inode *inode, void *priv),
			       struct inode **start, void *priv, int flag)
{
	switch(flag) {
		case SNAP_ITERATE_ALL_INODE:
			return ext3_iterate_all (sb, repeat, start, priv);
		default:
			return -EINVAL;
	}
}

static int fsfilt_ext3_get_snap_info(struct inode *inode, void *key, 
                                     __u32 keylen, void *val, 
                                     __u32 *vallen) 
{
        int rc = 0;
        ENTRY;

        if (!vallen || !val) {
                CERROR("val and val_size is 0!\n");
                RETURN(-EFAULT);
        }
        if (keylen >= strlen(MAX_SNAPTABLE_COUNT) 
            && strcmp(key, MAX_SNAPTABLE_COUNT) == 0) {
                /*FIXME should get it from the EA_size*/
               *((__u32 *)val) = EXT3_MAX_SNAPS; 
               *vallen = sizeof(int);
               RETURN(rc);
        } else if (keylen >= strlen(SNAPTABLE_INFO) 
                   && strcmp(key, SNAPTABLE_INFO) == 0) {
                rc = ext3_xattr_get(inode, EXT3_SNAP_INDEX, 
                                    EXT3_SNAPTABLE_EA, val, *vallen); 
                RETURN(rc);
        } else if (keylen >= strlen(SNAP_GENERATION) 
                   && strcmp(key, SNAP_GENERATION) == 0) {
                
                rc = ext3_xattr_get(inode, EXT3_SNAP_INDEX,EXT3_SNAP_GENERATION,
                                    (char *)val, *vallen);
                if (rc == -ENOATTR) {
                        *((__u32 *)val) = 0; 
                        *vallen = sizeof(int);
                        rc = 0;
                }
                RETURN(rc);
        } 
        RETURN(-EINVAL);
} 

static int fsfilt_ext3_set_snap_info(struct inode *inode, void *key, 
                                     __u32 keylen, void *val, 
                                     __u32 *vallen)
{
        int rc = 0;
        ENTRY;
        
        if (!vallen || !val) {
                CERROR("val and val_size is 0!\n");
                RETURN(-EFAULT);
        }

        if (keylen >= strlen(SNAPTABLE_INFO) 
            && strcmp(key, SNAPTABLE_INFO) == 0) {
                handle_t *handle;
 
                handle = ext3_journal_start(inode, EXT3_XATTR_TRANS_BLOCKS);
                if( !handle )
                        RETURN(-EINVAL);
                rc = ext3_xattr_set(handle, inode, EXT3_SNAP_INDEX, 
                                    EXT3_SNAPTABLE_EA, val, *vallen, 0); 
	        ext3_journal_stop(handle, inode);
                
                RETURN(rc);
        } else if (keylen >= strlen(SNAP_GENERATION) 
                   && strcmp(key, SNAP_GENERATION) == 0) {
                LASSERT(inode);
                rc = ext3_set_generation(inode, *(int*)val);
                
                RETURN(rc); 
        }
        RETURN(-EINVAL);
}
static int fsfilt_ext3_dir_ent_size(char *name)
{
        if (name) {
                return EXT3_DIR_REC_LEN(strlen(name));
        }
        return 0;
}

static int fsfilt_ext3_set_dir_ent(struct super_block *sb, char *name, 
                                   char *buf, int buf_off, int nlen, size_t count)
{
        int rc = 0; 
        ENTRY;
        if (buf_off == 0 && nlen == 0) {
                struct ext3_dir_entry_2 *de = (struct ext3_dir_entry_2 *)buf;  
                LASSERT(count == PAGE_CACHE_SIZE);
                de->rec_len = count;
                de->inode = 0;
                RETURN(rc);
        } else {
                struct ext3_dir_entry_2 *de, *de1; 
                de = (struct ext3_dir_entry_2 *)(buf + buf_off - nlen); 
                de1 = (struct ext3_dir_entry_2 *)(buf + buf_off); 
                int rlen, nlen;
 
                LASSERT(nlen == EXT3_DIR_REC_LEN_DE(de));
                
                rlen = le16_to_cpu(de->rec_len);
                de->rec_len = cpu_to_le16(nlen);
                
                de1->rec_len = cpu_to_le16(rlen - nlen);
                de1->name_len = strlen(name);
                memcpy (de1->name, name, de->name_len);
                nlen = EXT3_DIR_REC_LEN_DE(de1); 
                RETURN(nlen);
        }        

}
struct fsfilt_operations fsfilt_ext3_snap_ops = {
        .fs_type                = "ext3_snap",
        .fs_owner               = THIS_MODULE,
        .fs_create_indirect     = fsfilt_ext3_create_indirect,
        .fs_get_indirect        = fsfilt_ext3_get_indirect,
        .fs_set_indirect        = fsfilt_ext3_set_indirect,
	.fs_snap_feature	= fsfilt_ext3_snap_feature,
	.fs_is_redirector	= fsfilt_ext3_is_redirector,
	.fs_is_indirect		= fsfilt_ext3_is_indirect,
        .fs_get_indirect_ino    = fsfilt_ext3_get_indirect_ino,
        .fs_destroy_indirect    = fsfilt_ext3_destroy_indirect,
        .fs_restore_indirect    = fsfilt_ext3_restore_indirect,
        .fs_iterate             = fsfilt_ext3_iterate,
        .fs_copy_block          = fsfilt_ext3_copy_block,
        .fs_set_snap_info       = fsfilt_ext3_set_snap_info,
        .fs_get_snap_info       = fsfilt_ext3_get_snap_info,
        .fs_dir_ent_size        = fsfilt_ext3_dir_ent_size,
        .fs_set_dir_ent         = fsfilt_ext3_set_dir_ent,
};


static int __init fsfilt_ext3_snap_init(void)
{
        int rc;

        rc = fsfilt_register_ops(&fsfilt_ext3_snap_ops);

        return rc;
}

static void __exit fsfilt_ext3_snap_exit(void)
{

        fsfilt_unregister_ops(&fsfilt_ext3_snap_ops);
}

module_init(fsfilt_ext3_snap_init);
module_exit(fsfilt_ext3_snap_exit);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre ext3 Filesystem Helper v0.1");
MODULE_LICENSE("GPL");
