#ifndef _OBD_RAID1
#define _OBD_RAID1

#include <linux/obd_class.h>

#define MAX_RAID1 16

#ifndef OBD_RAID1_DEVICENAME
#define OBD_RAID1_DEVICENAME "obdraid1"
#endif

struct raid1_obd {
        unsigned int raid1_count; /* how many replicas */
        /* devices to replicate on */
        struct obd_device *raid1_devlist[MAX_RAID1];
        /* connections we make */
        struct obd_conn_info raid1_connections[MAX_RAID1];
        struct list_head raid1_clients;  /* clients we have */
};


/* development definitions */
extern struct obdfs_sb_info *obd_sbi;
extern struct file_operations *obd_fso;

/* obd_raid1.c */
extern struct obd_ops raid1_obd_ops;
inline long ext2_block_map (struct inode * inode, long block);

#endif
