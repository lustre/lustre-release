/* snapctl.h */
#define DEV_NAME_MAX_LEN 64 
struct snap_device {
	char name[DEV_NAME_MAX_LEN];
	char mntpt[DEV_NAME_MAX_LEN];
	unsigned long dev;
	int fd;
};
struct snap_mnt {
	struct snap_device device;
	struct list_head snap_mnt_list;
};
struct open_snap_device {
	struct snap_device device[10];	
	int count;
};
extern void init_snap_list(void);

extern int snap_dev_open(int argc, char **argv);
extern int snap_dev_list(int argc, char **argv);
extern int snap_snap_add(int argc, char **argv);
extern int snap_snap_list(int argc, char **argv);
