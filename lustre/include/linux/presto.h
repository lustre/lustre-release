#ifndef __PRESTO_H_
#define __PRESTO_H_ 1

struct bottomfs {
	struct super_operations *bottom_sops;

	struct inode_operations *bottom_dir_iops;
	struct inode_operations *bottom_file_iops;
	struct inode_operations *bottom_sym_iops;

	struct file_operations *bottom_dir_fops;
	struct file_operations *bottom_file_fops;
	struct file_operations *bottom_sym_fops;
	kdev_t bottom_dev;
};
extern struct bottomfs *the_bottom;

/* sysctl.c */
void presto_sysctl_init(void);
void presto_sysctl_clean(void);

#endif
