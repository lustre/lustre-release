#include <../obd/linux/sym_obd.h>


struct obdfs_sb_info {
	struct obd_conn_info osi_conn_info;
	struct super_block *osi_super;
	int osi_obd_minor;
};



void obdfs_sysctl_init(void);
void obdfs_sysctl_clean(void);

struct obdfs_inode_info;

#define OBDFS_SUPER_MAGIC 0x4711
