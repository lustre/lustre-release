#ifndef __LLU_H_
#define __LLU_H_

#include <liblustre.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <portals/procbridge.h>
#include <linux/lustre_lite.h>

#include <sys/types.h>
#include <sys/stat.h>

struct ll_file_data {
        struct obd_client_handle fd_mds_och;
        struct obd_client_handle fd_ost_och;
        __u32 fd_flags;
};

struct llu_sb_info
{
        struct obd_uuid         ll_sb_uuid;
        struct lustre_handle    ll_mdc_conn;
        struct lustre_handle    ll_osc_conn;
        obd_id                  ll_rootino;
        int                     ll_flags;
        struct list_head        ll_conn_chain;
};

struct llu_inode_info {
	struct llu_sb_info	*lli_sbi;
	struct ll_fid		lli_fid;
        struct lov_stripe_md	*lli_smd;
        char                	*lli_symlink_name;
        unsigned long        	lli_flags;
        struct list_head     	lli_read_extents;

	/* in libsysio we have no chance to store data in file,
	 * so place it here */
	struct ll_file_data	*lli_file_data;

	/* stat FIXME not 64 bit clean */
	dev_t			lli_st_dev;
	ino_t			lli_st_ino;
	mode_t			lli_st_mode;
	nlink_t			lli_st_nlink;
	uid_t			lli_st_uid;
	gid_t			lli_st_gid;
	dev_t			lli_st_rdev;
	loff_t			lli_st_size;
	unsigned int		lli_st_blksize;
	unsigned int		lli_st_blocks;
	time_t			lli_st_atime;
	time_t			lli_st_mtime;
	time_t			lli_st_ctime;

	/* not for stat, change it later */
	int			lli_st_flags;
	unsigned long 		lli_st_generation;
};

static inline struct llu_sb_info *llu_fs2sbi(struct filesys *fs)
{
	return (struct llu_sb_info*)(fs->fs_private);
}

static inline struct llu_inode_info *llu_i2info(struct inode *inode)
{
	return (struct llu_inode_info*)(inode->i_private);
}

static inline struct llu_sb_info *llu_i2sbi(struct inode *inode)
{
        return llu_i2info(inode)->lli_sbi;
}

static inline struct client_obd *sbi2mdc(struct llu_sb_info *sbi)
{
	struct obd_device *obd = class_conn2obd(&sbi->ll_mdc_conn);
	if (obd == NULL)
		LBUG();
	return &obd->u.cli;
}

static inline struct lustre_handle *llu_i2obdconn(struct inode *inode)
{
        return &(llu_i2info(inode)->lli_sbi->ll_osc_conn);
}


/* llite_lib.c */
void generate_random_uuid(unsigned char uuid_out[16]);

/* super.c */
void llu_update_inode(struct inode *inode, struct mds_body *body,
                      struct lov_mds_md *lmm);
void obdo_to_inode(struct inode *dst, struct obdo *src, obd_flag valid);
void obdo_from_inode(struct obdo *dst, struct inode *src, obd_flag valid);
struct inode* llu_new_inode(struct filesys *fs, ino_t ino, mode_t mode);

extern struct fssw_ops llu_fssw_ops;

/* file.c */
int llu_create(struct inode *dir, struct pnode_base *pnode, int mode);
int llu_iop_open(struct pnode *pnode, int flags, mode_t mode);
int llu_iop_ipreadv(struct inode *ino,
                    struct io_arguments *ioargs,
                    struct ioctx **ioctxp);
int llu_iop_ipwritev(struct inode *ino,
                     struct io_arguments *ioargs,
                     struct ioctx **ioctxp);

/* rw.c */
int llu_iop_iodone(struct ioctx *ioctxp __IS_UNUSED);
ssize_t llu_file_write(struct inode *inode, const struct iovec *iovec,
		       size_t iovlen, loff_t pos);

#endif
