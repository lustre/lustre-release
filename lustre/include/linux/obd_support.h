#ifndef _OBD_SUPPORT
#define _OBD_SUPPORT
#include <linux/malloc.h>
#include <linux/vmalloc.h>

#define MIN(a,b) (((a)<(b)) ? (a): (b))
#define MAX(a,b) (((a)>(b)) ? (a): (b))

/*
 * Debug code
 */
/* global variables */
extern int obd_debug_level;
extern int obd_print_entry;

#define EXT2_OBD_DEBUG

#ifdef EXT2_OBD_DEBUG
#define CMD(cmd) (( cmd == READ ) ? "read" : "write")

/* debugging masks */
#define D_PSDEV       1 /* debug information from psdev.c */
#define D_INODE       2
#define D_SUPER       4
#define D_SNAP        8
#define D_UNUSED     16
#define D_WARNING    32 /* misc warnings */
#define D_EXT2       64 /* anything from ext2_debug */
#define D_MALLOC    128 /* print malloc, free information */
#define D_CACHE     256 /* cache-related items */
#define D_INFO      512 /* general information, especially from interface.c */
#define D_IOCTL    1024 /* ioctl related information */
#define D_BLOCKS   2048 /* ext2 block allocation */
#define D_RPC      4096 /* rpc communications */
 
#define CDEBUG(mask, format, a...)                                      \
	do {                                                            \
	if (obd_debug_level & mask) {                                   \
		printk("(%s:%d):", __FUNCTION__, __LINE__);             \
		printk(format, ## a); }                                 \
	} while (0)

#define ENTRY if (obd_print_entry) \
			printk(KERN_INFO "Process %d entered %s\n",\
			       current->pid, __FUNCTION__)

#define EXIT if (obd_print_entry) \
			printk(KERN_INFO "Process %d leaving %s [%d]\n",\
			       current->pid, __FUNCTION__, __LINE__)

/* Inode common information printed out (used by obdfs and ext2obd inodes) */
#define ICDEBUG(inode) { \
	CDEBUG(D_INFO, "]]%s line %d[[ ino %ld, atm %ld, mtm %ld, ctm %ld, "\
	       "size %Ld, blocks %ld\n", __FUNCTION__ , __LINE__,\
	       inode->i_ino, inode->i_atime, inode->i_mtime, inode->i_ctime,\
	       inode->i_size, inode->i_blocks);\
	CDEBUG(D_INFO,\
	       "]]%s line %d[[ mode %o, uid %d, gid %d, nlnk %d, count %d\n",\
	       __FUNCTION__, __LINE__, inode->i_mode, inode->i_uid,\
	       inode->i_gid, inode->i_nlink, inode->i_count);\
}

/* Ext2 inode information */
#define EXDEBUG(inode) { \
	ICDEBUG(inode);\
	CDEBUG(D_INFO, "ext2 blocks: %d %d %d %d %d %d %d %d\n",\
	       inode->u.ext2_i.i_data[0], inode->u.ext2_i.i_data[1],\
	       inode->u.ext2_i.i_data[2], inode->u.ext2_i.i_data[3],\
	       inode->u.ext2_i.i_data[4], inode->u.ext2_i.i_data[5],\
	       inode->u.ext2_i.i_data[6], inode->u.ext2_i.i_data[7]);\
}

/* OBDFS inode information */
#define OIDEBUG(inode) { \
	ICDEBUG(inode);\
	CDEBUG(D_INFO,"oinfo: flags 0x%08x\n", obdfs_i2info(inode)->oi_flags);\
	/* obdfs_print_plist(inode); */\
}

#define ODEBUG(obdo) { \
	CDEBUG(D_INFO, "]]%s line %d[[  id %ld, atm %ld, mtm %ld, ctm %ld, "\
	       "size %ld, blocks %ld\n", __FUNCTION__ , __LINE__,\
	       (long)(obdo)->o_id, (long)(obdo)->o_atime,\
	       (long)(obdo)->o_mtime, (long)(obdo)->o_ctime,\
	       (long)(obdo)->o_size, (long)(obdo)->o_blocks);\
	CDEBUG(D_INFO, "]]%s line %d[[  mode %o, uid %d, gid %d, flg 0x%0x, "\
	       "obdflg 0x%0x, nlnk %d, valid 0x%0x\n", __FUNCTION__ , __LINE__,\
	       (obdo)->o_mode, (obdo)->o_uid, (obdo)->o_gid, (obdo)->o_flags,\
	       (obdo)->o_obdflags, (obdo)->o_nlink, (obdo)->o_valid);\
}


#define PDEBUG(page,cmd) { \
	if (page){\
		char *uptodate = (Page_Uptodate(page)) ? "yes" : "no";\
		char *locked = (PageLocked(page)) ? "yes" : "no";\
		int count = page->count.counter;\
		long index = page->index;\
		CDEBUG(D_CACHE, " ** %s, cmd: %s, off %ld, uptodate: %s, "\
		       "locked: %s, cnt %d page %p pages %ld** \n",\
		       __FUNCTION__, cmd, index, uptodate, locked, count, \
		       page, (!page->mapping) ? -1 : page->mapping->nrpages);\
	} else \
		CDEBUG(D_CACHE, "** %s, no page\n", __FUNCTION__);\
}

#else /* EXT2_OBD_DEBUG */

#define CDEBUG(mask, format, a...) {}
#define ENTRY {}
#define EXIT {}
#define ODEBUG(obdo) {}
#define EXDEBUG(inode) {}
#define OIDEBUG(inode) {}
#define PDEBUG(page, cmd) {}

#endif /* EXT2_OBD_DEBUG */



#define OBD_ALLOC(ptr, cast, size)					\
do {									\
	if (size <= 4096) {						\
		ptr = (cast)kmalloc((unsigned long) size, GFP_KERNEL); \
                CDEBUG(D_MALLOC, "kmalloced: %x at %x.\n",		\
		       (int) size, (int) ptr);				\
	} else {							\
		ptr = (cast)vmalloc((unsigned long) size);		\
		CDEBUG(D_MALLOC, "vmalloced: %x at %x.\n",		\
		       (int) size, (int) ptr);				\
	}								\
	if (ptr == 0) {							\
		printk("kernel malloc returns 0 at %s:%d\n",		\
		       __FILE__, __LINE__);				\
	}								\
	memset(ptr, 0, size);						\
} while (0)

#define OBD_FREE(ptr,size)				\
do {							\
	if (size <= 4096) {				\
		kfree_s((ptr), (size));			\
		CDEBUG(D_MALLOC, "kfreed: %x at %x.\n",	\
		       (int) size, (int) ptr);		\
	} else {					\
		vfree((ptr));				\
		CDEBUG(D_MALLOC, "vfreed: %x at %x.\n",	\
		       (int) size, (int) ptr);		\
	}						\
} while (0)



#endif
