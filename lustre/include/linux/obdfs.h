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
#include <linux/list.h>

static __inline__ struct obdo *obdo_fromid(struct lustre_handle *conn, obd_id id,
                                           obd_mode mode, obd_flag valid)
{
        struct obdo *oa;
        int err;

        ENTRY;
        oa = obdo_alloc();
        if ( !oa ) {
                RETURN(ERR_PTR(-ENOMEM));
        }

        oa->o_id = id;
        oa->o_mode = mode;
        oa->o_valid = valid;
        if ((err = obd_getattr(conn, oa))) {
                obdo_free(oa);
                RETURN(ERR_PTR(err));
        }
        RETURN(oa);
}


struct obdfs_inode_info {
        int              oi_flags;
        struct list_head oi_inodes;
        struct list_head oi_pages;
        char             oi_inline[OBD_INLINESZ];
};

struct obdfs_sb_info {
        struct list_head         osi_list;      /* list of supers */
        struct lustre_handle          osi_conn;
        struct super_block      *osi_super;
        struct obd_device       *osi_obd;
        ino_t                    osi_rootino;   /* number of root inode */
        int                      osi_minor;     /* minor of /dev/obdX */
        struct list_head         osi_inodes;    /* list of dirty inodes */
        unsigned long            osi_cache_count;
        struct semaphore         osi_list_mutex;
};


static inline struct obdfs_inode_info *obdfs_i2info(struct inode *inode)
{
        return (struct obdfs_inode_info *)&(inode->u.generic_ip);
}

static inline int obdfs_has_inline(struct inode *inode)
{
        return (obdfs_i2info(inode)->oi_flags & OBD_FL_INLINEDATA);
}

static void inline obdfs_from_inode(struct obdo *oa, struct inode *inode)
{
        struct obdfs_inode_info *oinfo = obdfs_i2info(inode);

        CDEBUG(D_INFO, "src inode %ld, dst obdo %ld valid 0x%08x\n",
               inode->i_ino, (long)oa->o_id, oa->o_valid);
        obdo_from_inode(oa, inode);
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
                CDEBUG(D_INODE, "copying device %x from inode to obdo\n",
		       inode->i_rdev);
		*((obd_rdev *)oa->o_inline) = kdev_t_to_nr(inode->i_rdev);
                oa->o_obdflags |= OBD_FL_INLINEDATA;
                oa->o_valid |= OBD_MD_FLINLINE;
	} else if (obdfs_has_inline(inode)) {
                CDEBUG(D_INODE, "copying inline data from inode to obdo\n");
                memcpy(oa->o_inline, oinfo->oi_inline, OBD_INLINESZ);
                oa->o_obdflags |= OBD_FL_INLINEDATA;
                oa->o_valid |= OBD_MD_FLINLINE;
        }
} /* obdfs_from_inode */

static void inline obdfs_to_inode(struct inode *inode, struct obdo *oa)
{
        struct obdfs_inode_info *oinfo = obdfs_i2info(inode);

        CDEBUG(D_INFO, "src obdo %ld valid 0x%08x, dst inode %ld\n",
               (long)oa->o_id, oa->o_valid, inode->i_ino);

        obdo_to_inode(inode, oa);

        if (obdo_has_inline(oa)) {
		if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		    S_ISFIFO(inode->i_mode)) {
			obd_rdev rdev = *((obd_rdev *)oa->o_inline);
			CDEBUG(D_INODE,
			       "copying device %x from obdo to inode\n", rdev);
			init_special_inode(inode, inode->i_mode, rdev);
		} else {
			CDEBUG(D_INFO, "copying inline from obdo to inode\n");
			memcpy(oinfo->oi_inline, oa->o_inline, OBD_INLINESZ);
		}
                oinfo->oi_flags |= OBD_FL_INLINEDATA;
        }
} /* obdfs_to_inode */

#define NOLOCK 0
#define LOCKED 1

#ifdef OPS
#warning "*** WARNING redefining OPS"
#else
#define OPS(sb,op) ((struct obdfs_sb_info *)(& (sb)->u.generic_sbp))->osi_ops->o_ ## op
#define IOPS(inode,op) ((struct obdfs_sb_info *)(&(inode)->i_sb->u.generic_sbp))->osi_ops->o_ ## op
#endif

#ifdef ID
#warning "*** WARNING redefining ID"
#else
#define ID(sb) (&((struct obdfs_sb_info *)( &(sb)->u.generic_sbp))->osi_conn)
#define IID(inode) (&((struct obdfs_sb_info *)( &(inode)->i_sb->u.generic_sbp))->osi_conn)
#endif

#define OBDFS_SUPER_MAGIC 0x4711

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

#endif

