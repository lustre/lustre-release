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

extern struct list_head obdfs_super_list;       /* list of all OBDFS superblocks */



/* dir.c */
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
} /* obdfs_set_size */


#if 0   /* PAGE CACHE DISABLED */

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
#endif


#endif

