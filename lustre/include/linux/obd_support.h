#ifndef _OBD_SUPPORT
#define _OBD_SUPPORT
#include <linux/malloc.h>
#include <linux/vmalloc.h>

#define MIN(a,b) (((a)<(b)) ? (a): (b))
#define MAX(a,b) (((a)>(b)) ? (a): (b))

#define obd_unlock_page(page)   do {    if (PageLocked(page)) { \
                        UnlockPage(page);\
                } else {\
                        printk("file %s, line %d: expecting locked page\n",\
                               __FILE__, __LINE__); \
                }                       \
} while(0)

/*
 * Debug code
 */
/* global variables */
extern int obd_debug_level;
extern int obd_print_entry;
extern int obd_inodes;
extern int obd_pages;
extern long obd_memory;

#define EXT2_OBD_DEBUG

#ifdef EXT2_OBD_DEBUG
#define CMD(cmd) (( cmd == READ ) ? "read" : "write")

/* debugging masks */
#define D_PSDEV   0x001 /* debug information from psdev.c */
#define D_INODE   0x002
#define D_SUPER   0x004
#define D_SNAP    0x008
#define D_UNUSED4 0x010
#define D_WARNING 0x020 /* misc warnings */
#define D_EXT2    0x040 /* anything from ext2_debug */
#define D_MALLOC  0x080 /* print malloc, free information */
#define D_CACHE   0x100 /* cache-related items */
#define D_INFO    0x200 /* general information, especially from interface.c */
#define D_IOCTL   0x400 /* ioctl related information */
#define D_BLOCKS  0x800 /* ext2 block allocation */
#define D_RPC    0x1000 /* rpc communications */
#define D_PUNCH  0x2000
 
#define CDEBUG(mask, format, a...)                                      \
        do {                                                            \
        if (obd_debug_level & mask) {                                   \
                printk("(%s:%d):", __FUNCTION__, __LINE__);             \
                printk(format, ## a); }                                 \
        } while (0)

#define ENTRY if (obd_print_entry)                                      \
        printk(KERN_INFO "Process %d entered %s\n", current->pid, __FUNCTION__)

#define EXIT if (obd_print_entry)                                       \
        printk(KERN_INFO "Process %d leaving %s [%d]\n", current->pid,  \
               __FUNCTION__, __LINE__)

/* Inode common information printed out (used by obdfs and ext2obd inodes) */
#define ICDEBUG(inode) {                                                \
        CDEBUG(D_INFO,                                                  \
               "ino %ld, atm %ld, mtm %ld, ctm %ld, size %Ld, blocks %ld\n",\
               inode->i_ino, inode->i_atime, inode->i_mtime, inode->i_ctime,\
               inode->i_size, inode->i_blocks);                         \
        CDEBUG(D_INFO, "mode %o, uid %d, gid %d, nlnk %d, count %d\n",  \
               inode->i_mode, inode->i_uid, inode->i_gid, inode->i_nlink,\
               atomic_read(&inode->i_count));                                         \
}

/* Ext2 inode information */
#define EXDEBUG(inode) {                                                \
        ICDEBUG(inode);                                                 \
        CDEBUG(D_INFO, "ext2 blocks: %d %d %d %d %d %d %d %d\n",        \
               inode->u.ext2_i.i_data[0], inode->u.ext2_i.i_data[1],    \
               inode->u.ext2_i.i_data[2], inode->u.ext2_i.i_data[3],    \
               inode->u.ext2_i.i_data[4], inode->u.ext2_i.i_data[5],    \
               inode->u.ext2_i.i_data[6], inode->u.ext2_i.i_data[7]);   \
}

/* OBDFS inode information */
#define OIDEBUG(inode) {                                                \
        ICDEBUG(inode);                                                 \
        CDEBUG(D_INFO,"oinfo: flags 0x%08x\n", obdfs_i2info(inode)->oi_flags);\
        /* obdfs_print_plist(inode); */                                 \
}

#define ODEBUG(obdo) {                                                  \
        CDEBUG(D_INFO, "id %ld, atm %ld, mtm %ld, ctm %ld, "            \
               "size %ld, blocks %ld\n",                                \
               (long)(obdo)->o_id, (long)(obdo)->o_atime,               \
               (long)(obdo)->o_mtime, (long)(obdo)->o_ctime,            \
               (long)(obdo)->o_size, (long)(obdo)->o_blocks);           \
        CDEBUG(D_INFO, " mode %o, uid %d, gid %d, flg 0x%0x, "          \
               "obdflg 0x%0x, nlnk %d, valid 0x%0x\n",                  \
               (obdo)->o_mode, (obdo)->o_uid, (obdo)->o_gid, (obdo)->o_flags,\
               (obdo)->o_obdflags, (obdo)->o_nlink, (obdo)->o_valid);   \
}


#define PDEBUG(page,msg) {                                              \
        if (page){                                                      \
                char *uptodate = (Page_Uptodate(page)) ? "upto" : "outof";\
                char *locked = (PageLocked(page)) ? "" : "un";          \
                char *buffer = page->buffers ? "buffer" : "";           \
                int count = page_count(page);                           \
                long index = page->index;                               \
                CDEBUG(D_CACHE, "%s: ** off %ld, %sdate, %slocked, flag %ld,"\
                       " cnt %d page 0x%p pages %ld virt %lx %s**\n",   \
                       msg, index, uptodate, locked, page->flags, count,\
                       page, page->mapping ? page->mapping->nrpages : -1,\
                       page->virtual, buffer);                          \
        } else                                                          \
                CDEBUG(D_CACHE, "** %s: no page\n", msg);               \
}

#if 0
#define iget(sb, ino) obd_iget(sb, ino)
#define iput(sb, ino) obd_iput(sb, ino)

static inline struct inode *obd_iget(struct super_block *sb, unsigned long ino)
{
        struct inode *inode;
        
        if ((inode = iget(sb, ino)) == NULL)
                CDEBUG(D_INODE, "NULL in iget for %ld\n", ino);
        else
                obd_inodes++;
        return inode;
}

static inline void obd_iput(struct inode *inode)
{
        if (inode == NULL)
                CDEBUG(D_INODE, "NULL in iput\n");
        else
                obd_inodes--;
}
#endif

#else /* EXT2_OBD_DEBUG */

#define CDEBUG(mask, format, a...) {}
#define ENTRY {}
#define EXIT {}
#define ODEBUG(obdo) {}
#define EXDEBUG(inode) {}
#define OIDEBUG(inode) {}
#define PDEBUG(page, cmd) {}

#endif /* EXT2_OBD_DEBUG */



#define OBD_ALLOC(ptr, cast, size)                                      \
do {                                                                    \
        if (size <= 4096) {                                             \
                ptr = (cast)kmalloc((unsigned long) size, GFP_KERNEL);  \
                CDEBUG(D_MALLOC, "kmalloced: %d at %x.\n",              \
                       (int) size, (int) ptr);                          \
        } else {                                                        \
                ptr = (cast)vmalloc((unsigned long) size);              \
                CDEBUG(D_MALLOC, "vmalloced: %d at %x.\n",              \
                       (int) size, (int) ptr);                          \
        }                                                               \
        if (ptr == 0) {                                                 \
                printk("kernel malloc returns 0 at %s:%d\n",            \
                       __FILE__, __LINE__);                             \
        } else {                                                        \
                memset(ptr, 0, size);                                   \
                obd_memory += size;                                     \
        }                                                               \
} while (0)

#define OBD_FREE(ptr,size)                              \
do {                                                    \
        if (size <= 4096) {                             \
                kfree((ptr));                   \
                CDEBUG(D_MALLOC, "kfreed: %d at %x.\n", \
                       (int) size, (int) ptr);          \
        } else {                                        \
                vfree((ptr));                           \
                CDEBUG(D_MALLOC, "vfreed: %d at %x.\n", \
                       (int) size, (int) ptr);          \
        }                                               \
        obd_memory -= size;                             \
} while (0)



#endif
