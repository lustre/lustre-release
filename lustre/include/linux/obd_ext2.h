#ifndef _OBD_EXT2
#define _OBD_EXT2
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#define OBD_EXT2_RUNIT           _IOWR('f', 61, long)

#include <linux/iobuf.h>

#ifndef OBD_EXT2_DEVICENAME
#define OBD_EXT2_DEVICENAME "obdext2"
#endif

struct ext2_obd {
        struct super_block * ext2_sb;
	struct vfsmount *vfsmnt;
};


/* development definitions */
extern struct obdfs_sb_info *obd_sbi;
extern struct file_operations *obd_fso;

/* ext2_obd.c */
extern struct obd_ops ext2_obd_ops;


#include <linux/ext2_fs.h>

/* super.c */
#ifdef EXT2_OBD_DEBUG
#  undef ext2_debug
#  define ext2_debug(format, a...) CDEBUG(D_EXT2, format, ## a)
#  define ext2_error ext2_warning
#  define ext2_panic ext2_warning
#  define ext2_warning(sb, func, format, a...) CDEBUG(D_WARNING, format, ## a)
#else
#  undef ext2_debug
#  define ext2_debug(format, a...) {}
#  define ext2_error(sb, func, format, a...) printk(KERN_ERR "%s: " format, func, ## a)
#  define ext2_panic(sb, func, format, a...) printk(KERN_CRIT "%s: " format, func, ## a)
#  define ext2_warning(sb, func, format, a...) printk(KERN_WARNING "%s: " format, func, ## a)
#endif

extern struct super_operations ext2_sops;
int obd_remount (struct super_block * sb, int * flags, char * data);
struct super_block * ext2_read_super (struct super_block * sb, void * data,
                                      int silent);

/* punch.c */
void ext2_truncate (struct inode * inode);
int ext2_punch (struct inode * inode, loff_t start, size_t count);

#endif
