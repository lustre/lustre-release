/* object based disk file system
 * 
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 * 
 * Copyright (C), 1999, Stelias Computing Inc
 *
 *
 */


#ifndef _LL_H
#define _LL_H

#include <linux/ext2_fs.h>

#include <linux/lustre_net.h>
#include <linux/lustre_mds.h>
#include <linux/obdo.h>

extern kmem_cache_t *ll_file_data_slab;
struct ll_file_data { 
        __u64 fd_mdshandle; 
};

#define LL_INLINESZ      60
struct ll_inode_info {
        int              lli_flags;
        __u64            lli_objid; 
        char             lli_inline[LL_INLINESZ];
};

#define LL_SUPER_MAGIC 0x0BD00BD0;
struct ll_sb_info {
        struct list_head         ll_list;      /* list of supers */
        struct obd_conn          ll_conn;
        struct super_block      *ll_super;
        ino_t                    ll_rootino;   /* number of root inode */
        int                      ll_minor;     /* minor of /dev/obdX */
        struct list_head         ll_inodes;    /* list of dirty inodes */
        unsigned long            ll_cache_count;
        struct semaphore         ll_list_mutex;
        struct ptlrpc_client     ll_mds_client;
        struct ptlrpc_client     ll_ost_client;
};


static inline struct ll_sb_info *ll_i2sbi(struct inode *inode)
{
        return (struct ll_sb_info *) (inode->i_sb->u.generic_sbp);
}

static inline struct ll_inode_info *ll_i2info(struct inode *inode)
{
        return (struct ll_inode_info *)&(inode->u.generic_ip);
}

static inline int ll_has_inline(struct inode *inode)
{
        return (ll_i2info(inode)->lli_flags & OBD_FL_INLINEDATA);
}


static inline struct obd_conn *ll_i2obdconn(struct inode *inode)
{
        return &(ll_i2sbi(inode))->ll_conn;
}

/* dir.c */
extern struct file_operations ll_dir_operations;
extern struct inode_operations ll_dir_inode_operations;

/* file.c */
extern struct file_operations ll_file_operations;
extern struct inode_operations ll_file_inode_operations;

/* rw.c */
struct page *ll_getpage(struct inode *inode, unsigned long offset,
                           int create, int locked);
void ll_truncate(struct inode *inode);

/* symlink.c */
extern struct inode_operations ll_fast_symlink_inode_operations;
extern struct inode_operations ll_symlink_inode_operations;

/* sysctl.c */
void ll_sysctl_init(void);
void ll_sysctl_clean(void);



static inline struct list_head *ll_slist(struct inode *inode) 
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);

        return &sbi->ll_inodes;
}

#endif

