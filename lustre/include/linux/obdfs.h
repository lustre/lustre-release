/* object based disk file system
 * 
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 * 
 * Copyright (C), 1999, Stelias Computing Inc
 *
 *
 */


#ifndef _OBDFS_H
#define _OBDFS_H
#include <linux/obd_class.h>
#include <linux/obdo.h>
#include <linux/list.h>


/* super.c */ 
struct obdfs_pgrq {
        struct list_head         rq_plist;      /* linked list of req's */
        unsigned long            rq_jiffies;
        struct page             *rq_page;       /* page to be written */
};

struct list_head obdfs_super_list;       /* list of all OBDFS superblocks */



/* dir.c */
#define EXT2_DIR_PAD                    4
#define EXT2_DIR_ROUND                  (EXT2_DIR_PAD - 1)
#define EXT2_DIR_REC_LEN(name_len)      (((name_len) + 8 + EXT2_DIR_ROUND) & \
                                         ~EXT2_DIR_ROUND)
#define EXT2_NAME_LEN 255
#if 0
struct ext2_dir_entry_2 {
        __u32   inode;                  /* Inode number */
        __u16   rec_len;                /* Directory entry length */
        __u8    name_len;               /* Name length */
        __u8    file_type;
        char    name[EXT2_NAME_LEN];    /* File name */
};
#endif
int obdfs_check_dir_entry (const char * function, struct inode * dir,
                          struct ext2_dir_entry_2 * de, struct page * page,
                          unsigned long offset);
extern struct file_operations obdfs_dir_operations;
extern struct inode_operations obdfs_dir_inode_operations;

/* file.c */
extern struct file_operations obdfs_file_operations;
extern struct inode_operations obdfs_file_inode_operations;

/* flush.c */
void obdfs_dequeue_pages(struct inode *inode);
int obdfs_flushd_init(void);
int obdfs_flushd_cleanup(void);
int obdfs_flush_reqs(struct list_head *inode_list, unsigned long check_time);
int obdfs_flush_dirty_pages(unsigned long check_time);

/* namei.c */
/*
 * Structure of the super block
 */

#if 0
struct ext2_super_block {
        __u32   s_inodes_count;         /* Inodes count */
        __u32   s_blocks_count;         /* Blocks count */
        __u32   s_r_blocks_count;       /* Reserved blocks count */
        __u32   s_free_blocks_count;    /* Free blocks count */
        __u32   s_free_inodes_count;    /* Free inodes count */
        __u32   s_first_data_block;     /* First Data Block */
        __u32   s_log_block_size;       /* Block size */
        __s32   s_log_frag_size;        /* Fragment size */
        __u32   s_blocks_per_group;     /* # Blocks per group */
        __u32   s_frags_per_group;      /* # Fragments per group */
        __u32   s_inodes_per_group;     /* # Inodes per group */
        __u32   s_mtime;                /* Mount time */
        __u32   s_wtime;                /* Write time */
        __u16   s_mnt_count;            /* Mount count */
        __s16   s_max_mnt_count;        /* Maximal mount count */
        __u16   s_magic;                /* Magic signature */
        __u16   s_state;                /* File system state */
        __u16   s_errors;               /* Behaviour when detecting errors */
        __u16   s_minor_rev_level;      /* minor revision level */
        __u32   s_lastcheck;            /* time of last check */
        __u32   s_checkinterval;        /* max. time between checks */
        __u32   s_creator_os;           /* OS */
        __u32   s_rev_level;            /* Revision level */
        __u16   s_def_resuid;           /* Default uid for reserved blocks */
        __u16   s_def_resgid;           /* Default gid for reserved blocks */
        /*
         * These fields are for EXT2_DYNAMIC_REV superblocks only.
         *
         * Note: the difference between the compatible feature set and
         * the incompatible feature set is that if there is a bit set
         * in the incompatible feature set that the kernel doesn't
         * know about, it should refuse to mount the filesystem.
         * 
         * e2fsck's requirements are more strict; if it doesn't know
         * about a feature in either the compatible or incompatible
         * feature set, it must abort and not try to meddle with
         * things it doesn't understand...
         */
        __u32   s_first_ino;            /* First non-reserved inode */
        __u16   s_inode_size;           /* size of inode structure */
        __u16   s_block_group_nr;       /* block group # of this superblock */
        __u32   s_feature_compat;       /* compatible feature set */
        __u32   s_feature_incompat;     /* incompatible feature set */
        __u32   s_feature_ro_compat;    /* readonly-compatible feature set */
        __u8    s_uuid[16];             /* 128-bit uuid for volume */
        char    s_volume_name[16];      /* volume name */
        char    s_last_mounted[64];     /* directory where last mounted */
        __u32   s_algorithm_usage_bitmap; /* For compression */
        /*
         * Performance hints.  Directory preallocation should only
         * happen if the EXT2_COMPAT_PREALLOC flag is on.
         */
        __u8    s_prealloc_blocks;      /* Nr of blocks to try to preallocate*/
        __u8    s_prealloc_dir_blocks;  /* Nr to preallocate for dirs */
        __u16   s_padding1;
        __u32   s_reserved[204];        /* Padding to the end of the block */
};
#endif

#define EXT2_SB(sb)     (&((sb)->u.ext2_sb))
/*
 * Maximal count of links to a file
 */
#define EXT2_LINK_MAX           32000
/*
 * Ext2 directory file types.  Only the low 3 bits are used.  The
 * other bits are reserved for now.
 */
#define EXT2_FT_UNKNOWN         0
#define EXT2_FT_REG_FILE        1
#define EXT2_FT_DIR             2
#define EXT2_FT_CHRDEV          3
#define EXT2_FT_BLKDEV          4
#define EXT2_FT_FIFO            5
#define EXT2_FT_SOCK            6
#define EXT2_FT_SYMLINK         7

#define EXT2_FT_MAX             8

#define EXT2_BTREE_FL                   0x00001000 /* btree format dir */
#define EXT2_RESERVED_FL                0x80000000 /* reserved for ext2 lib */
#define EXT2_FEATURE_INCOMPAT_FILETYPE          0x0002
#define EXT2_HAS_COMPAT_FEATURE(sb,mask)                        \
        ( EXT2_SB(sb)->s_es->s_feature_compat & cpu_to_le32(mask) )
#define EXT2_HAS_INCOMPAT_FEATURE(sb,mask)                      \
        ( EXT2_SB(sb)->s_es->s_feature_incompat & cpu_to_le32(mask) )

/* rw.c */
int obdfs_do_writepage(struct page *, int sync);
int obdfs_init_pgrqcache(void);
void obdfs_cleanup_pgrqcache(void);
inline void obdfs_pgrq_del(struct obdfs_pgrq *pgrq);
int obdfs_readpage(struct file *file, struct page *page);
int obdfs_prepare_write(struct file *file, struct page *page, unsigned from, unsigned to);
int obdfs_commit_write(struct file *file, struct page *page, unsigned from, unsigned to);
int obdfs_writepage(struct page *page);
struct page *obdfs_getpage(struct inode *inode, unsigned long offset,
                           int create, int locked);
int obdfs_write_one_page(struct file *file, struct page *page,
                         unsigned long offset, unsigned long bytes,
                         const char * buf);
int obdfs_do_vec_wr(struct inode **inodes, obd_count num_io, obd_count num_oa,
                    struct obdo **obdos, obd_count *oa_bufs,
                    struct page **pages, char **bufs, obd_size *counts,
                    obd_off *offsets, obd_flag *flags);
void obdfs_truncate(struct inode *inode);

/* super.c */
extern long obdfs_cache_count;
extern long obdfs_mutex_start;

/* symlink.c */
extern struct inode_operations obdfs_fast_symlink_inode_operations;
extern struct inode_operations obdfs_symlink_inode_operations;

/* sysctl.c */
void obdfs_sysctl_init(void);
void obdfs_sysctl_clean(void);

static inline struct obdfs_sb_info *obdfs_i2sbi(struct inode *inode)
{
        return (struct obdfs_sb_info *) &(inode->i_sb->u.generic_sbp);
}

static inline struct list_head *obdfs_iplist(struct inode *inode) 
{
        struct obdfs_inode_info *info = obdfs_i2info(inode);

        return &info->oi_pages;
}

static inline struct list_head *obdfs_islist(struct inode *inode) 
{
        struct obdfs_inode_info *info = obdfs_i2info(inode);

        return &info->oi_inodes;
}

static inline struct list_head *obdfs_slist(struct inode *inode) 
{
        struct obdfs_sb_info *sbi = obdfs_i2sbi(inode);

        return &sbi->osi_inodes;
}

static void inline obdfs_set_size (struct inode *inode, obd_size size)
{  
       inode->i_size = size;
       inode->i_blocks = (inode->i_size + inode->i_sb->s_blocksize - 1) >>
               inode->i_sb->s_blocksize_bits;
       inode->i_bytes = inode->i_size &
               ((1 << inode->i_sb->s_blocksize_bits) - 1);
} /* obdfs_set_size */



#define obd_down(mutex) {                                               \
        /* CDEBUG(D_INFO, "get lock\n"); */                             \
        obdfs_mutex_start = jiffies;                                    \
        down(mutex);                                                    \
        if (jiffies - obdfs_mutex_start)                                \
                CDEBUG(D_CACHE, "waited on mutex %ld jiffies\n",        \
                       jiffies - obdfs_mutex_start);                    \
}

#define obd_up(mutex) {                                                 \
        up(mutex);                                                      \
        if (jiffies - obdfs_mutex_start > 1)                            \
                CDEBUG(D_CACHE, "held mutex for %ld jiffies\n",         \
                       jiffies - obdfs_mutex_start);                    \
        /* CDEBUG(D_INFO, "free lock\n"); */                            \
}

/* We track if a page has been added to the OBD page cache by stting a
 * flag on the page.  We have chosen a bit that will hopefully not be
 * used for a while.
 */
#define PG_obdcache 29
#define OBDAddCachePage(page)   test_and_set_bit(PG_obdcache, &(page)->flags)
#define OBDClearCachePage(page) clear_bit(PG_obdcache, &(page)->flags)

static inline void obdfs_print_plist(struct inode *inode) 
{
        struct list_head *page_list = obdfs_iplist(inode);
        struct list_head *tmp;

        CDEBUG(D_INFO, "inode %ld: page", inode->i_ino);
        /* obd_down(&obdfs_i2sbi(inode)->osi_list_mutex); */
        if (list_empty(page_list)) {
                CDEBUG(D_INFO, " list empty\n");
                obd_up(&obdfs_i2sbi(inode)->osi_list_mutex);
                return;
        }

        tmp = page_list;
        while ( (tmp = tmp->next) != page_list) {
                struct obdfs_pgrq *pgrq;
                pgrq = list_entry(tmp, struct obdfs_pgrq, rq_plist);
                CDEBUG(D_INFO, " %p", pgrq->rq_page);
        }
        CDEBUG(D_INFO, "\n");
        /* obd_up(&obdfs_i2sbi(inode)->osi_list_mutex); */
}
#include <linux/obdo.h>

#endif

