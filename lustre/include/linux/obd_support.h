#ifndef _OBD_SUPPORT
#define _OBD_SUPPORT
#include <linux/malloc.h>
#include <linux/vmalloc.h>

#define SIM_OBD_DEBUG


#define MIN(a,b) (((a)<(b)) ? (a): (b))
#define MAX(a,b) (((a)>(b)) ? (a): (b))

/*
 * Debug code
 */
/* global variables */
extern int obd_debug_level;
extern int obd_print_entry;

/* debugging masks */
#define D_PSDEV       1 /* debug information from psdev.c */
#define D_INODE       2
#define D_UNUSED2     4
#define D_UNUSED3     8
#define D_UNUSED4    16
#define D_WARNING    32 /* misc warnings */
#define D_EXT2       64 /* anything from ext2_debug */
#define D_MALLOC    128 /* print malloc, free information */
#define D_CACHE     256 /* cache-related items */
#define D_INFO      512 /* general information, especially from interface.c */
#define D_IOCTL    1024 /* ioctl related information */
#define D_BLOCKS   2048 /* ext2 block allocation */
 
#ifdef SIM_OBD_DEBUG
#define CDEBUG(mask, format, a...)					\
        do {								\
	if (obd_debug_level & mask) {					\
		printk("(%s,l. %d): ",  __FUNCTION__, __LINE__);	\
		printk(format, ## a); }					\
	} while (0)

#define ENTRY								      \
        if (obd_print_entry)						      \
                printk("Process %d entered %s\n", current->pid, __FUNCTION__)

#define EXIT								      \
        if (obd_print_entry)						      \
                printk("Process %d leaving %s\n", current->pid, __FUNCTION__)

#else /* SIM_OBD_DEBUG */

#       define CDEBUG ;
#       define ENTRY ;
#       define EXIT ;

#endif /* SIM_OBD_DEBUG */


#define CMD(cmd) (( cmd == READ ) ? "read" : "write")

#define PDEBUG(page,cmd)	{if (page){\
		char *uptodate = (Page_Uptodate(page)) ? "yes" : "no";\
		char *locked = (PageLocked(page)) ? "yes" : "no";\
		int count = page->count.counter;\
		long ino = (page->inode) ? page->inode->i_ino : -1;\
                long offset = page->offset / PAGE_SIZE;\
		\
		CDEBUG(D_IOCTL, " ** %s, cmd: %s, ino: %ld, off %ld, uptodate: %s, "\
		       "locked: %s, cnt %d page %p ** \n", __FUNCTION__,\
		       cmd, ino, offset, uptodate, locked, count, page);\
	} else { CDEBUG(D_IOCTL, "** %s, no page\n", __FUNCTION__); }}


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



static inline void inode_to_iattr(struct inode *inode, struct iattr *tmp)
{
	tmp->ia_mode = inode->i_mode;
	tmp->ia_uid = inode->i_uid;
	tmp->ia_gid = inode->i_gid;
	tmp->ia_size = inode->i_size;
	tmp->ia_atime = inode->i_atime;
	tmp->ia_mtime = inode->i_mtime;
	tmp->ia_ctime = inode->i_ctime;
	tmp->ia_attr_flags = inode->i_flags;

	tmp->ia_valid = ~0;
}

static inline void inode_cpy(struct inode *dest, struct inode *src)
{
	dest->i_mode = src->i_mode;
	dest->i_uid = src->i_uid;
	dest->i_gid = src->i_gid;
	dest->i_size = src->i_size;
	dest->i_atime = src->i_atime;
	dest->i_mtime = src->i_mtime;
	dest->i_ctime = src->i_ctime;
	dest->i_attr_flags = src->i_flags;
	/* allocation of space */
	dest->i_blocks = src->i_blocks;

	if ( !dest->i_blocks) 
		memcpy(&dest->u, &src->u, sizeof(src->u));
}










#endif
