#ifndef __LLU_H_
#define __LLU_H_

#include <liblustre.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <portals/procbridge.h>
#include <linux/lustre_lite.h>

#include <sys/types.h>
#include <sys/stat.h>

struct ll_sb_info
{
        struct obd_uuid         ll_sb_uuid;
        struct lustre_handle    ll_mdc_conn;
        struct lustre_handle    ll_osc_conn;
        obd_id                  ll_rootino;
        int                     ll_flags;
        struct list_head        ll_conn_chain;
};

struct ll_inode_info {
	struct ll_sb_info	*lli_sbi;
	struct ll_fid		lli_fid;
        struct lov_stripe_md	*lli_smd;
        char                	*lli_symlink_name;
        unsigned long        	lli_flags;
        struct list_head     	lli_read_extents;

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
};

static inline struct ll_sb_info *ll_fs2sbi(struct filesys *fs)
{
	return (struct ll_sb_info*)(fs->fs_private);
}

static inline struct ll_inode_info *ll_i2info(struct inode *inode)
{
	return (struct ll_inode_info*)(inode->i_private);
}

static inline struct ll_sb_info *ll_i2sbi(struct inode *inode)
{
        return ll_i2info(inode)->lli_sbi;
}

static inline struct client_obd *sbi2mdc(struct ll_sb_info *sbi)
{
	struct obd_device *obd = class_conn2obd(&sbi->ll_mdc_conn);
	if (obd == NULL)
		LBUG();
	return &obd->u.cli;
}

#endif
