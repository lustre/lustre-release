#include <stdio.h>
#include <stdlib.h>
#include <mntent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <portals/list.h>
#include "parser.h"
#include "snapctl.h"
#include <snapfs_internal.h>

#define IOC_BUF_MAX_LEN 8192 
static char rawbuf[IOC_BUF_MAX_LEN];
static char *buf = rawbuf;
/*FIXME add this temporary, will use obd_ioc_data later*/
#define IOC_INIT(ptr)					\
do{							\
	struct ioc_data* pbuf;				\
	memset(buf, 0, sizeof(rawbuf));	 		\
	pbuf = (struct ioc_data*)buf;			\
	pbuf->ioc_inbuf = pbuf->ioc_bulk;		\
	ptr = (struct ioc_snap_tbl_data *)pbuf->ioc_bulk; \
} while(0)

#define IOC_PACK(length)  		\
do{                             	 	\
	struct ioc_data* pbuf;			\
	pbuf = (struct ioc_data*)buf;		\
	pbuf->ioc_inlen = length;		\
} while (0)

static struct list_head snap_list;
struct open_snap_device open_device_table;
struct snap_device snap_device_list[10];


static int get_snaplist()
{
	FILE *mnt_filp = NULL;
	int  error = 0;
	
	/*open mount list*/
	mnt_filp = setmntent("/etc/mtab", "r");

	if (!mnt_filp) 
		return -EINVAL;
	/*get the mentent and check snap mount*/
	while (!feof(mnt_filp)) {
		 struct mntent* entry;

		 entry = getmntent(mnt_filp);

		 if (!entry) continue;

		 if (!strcmp(entry->mnt_type, "snap_current")) {
		 	/*found a snap_mount structure add to the snaplist*/
			struct snap_mnt *s_mnt;
			char *opt = NULL;
			char dev_name[DEV_NAME_MAX_LEN];
			struct stat statbuf;
			
			s_mnt = (struct snap_mnt *) malloc(sizeof(struct snap_mnt));
			if (!s_mnt) {
				error = ENOMEM;
				goto exit;
			}
			memset(s_mnt, 0, sizeof(struct snap_mnt));
			memcpy(&s_mnt->device.name[0], entry->mnt_fsname, strlen(entry->mnt_fsname));
			memcpy(&s_mnt->device.mntpt[0], entry->mnt_dir, strlen(entry->mnt_dir));
			opt = hasmntopt(entry, "loop");
			memset(dev_name, 0, DEV_NAME_MAX_LEN);
			if (opt) {
				/* Loop device mount find the real dev_name*/
				char *name = opt, *name_dev = dev_name;

				while (*name++ != '=');
				while (*name != ',' && *name != ')' && *name ) {
					*name_dev++ = *name++;	
				}
		
			} else {
				memcpy(dev_name, entry->mnt_fsname, strlen(entry->mnt_fsname));	
			}
				
			if ((error = stat(dev_name, &statbuf)) != 0) {
				fprintf(stderr, "can not stat %s", strerror(errno));
				goto exit;
			}
			s_mnt->device.dev = (unsigned long)statbuf.st_rdev;
			list_add(&s_mnt->snap_mnt_list, &snap_list);
		 }
	}
exit:
	if (mnt_filp)
		endmntent(mnt_filp);
	return error;
}

static void release_snap_list()
{
	struct snap_mnt *snaplist;
	
	list_for_each_entry(snaplist, &snap_list, snap_mnt_list) {
		list_del(&snaplist->snap_mnt_list);
		free(snaplist);
	}
}

void init_snap_list()
{
	int i;

	INIT_LIST_HEAD(&snap_list);
	open_device_table.count = 0;
	for(i = 0; i < 10; i++) {
		memset(&open_device_table.device[i].name[0], 
		       0, DEV_NAME_MAX_LEN);
		open_device_table.device[i].fd = -1;
	}
}

static int open_device(char *name, unsigned int dev)
{
	int index=0, error = 0, i = 0, found = 0;

	/*XXX Does these information necessary*/
	for (i = 0; i < open_device_table.count; i++) {
		if (!strcmp(&open_device_table.device[i].name[0], name)) {
			index = i;
			found = 1;
			break;
		}
	}
	if (found == 0) {
		open_device_table.device[index].dev = dev;
		memset(&open_device_table.device[index].name[0], 
		       0, DEV_NAME_MAX_LEN);
		memcpy(&open_device_table.device[index].name[0], 
		       name, strlen(name));
		open_device_table.count ++;
	}
	/*FIXME If there are more than device, how to handle it*/
	if (open_device_table.device[index].fd < 0) {
		/*open device*/
		int fd = open(SNAPDEV_NAME, O_RDWR);
		
		if (fd < 0) {
 			if (errno == ENOENT) {
	                	dev_t snap_dev=makedev(SNAP_PSDEV_MAJOR,SNAP_PSDEV_MINOR);  
				/*create snapdevice node*/
				error = mknod(SNAPDEV_NAME, S_IRUSR|S_IWUSR|S_IFCHR, snap_dev);
				if (error) {
					fprintf(stderr, "Can not make node %s :%s \n", 
						SNAPDEV_NAME, strerror(errno));
					return (-errno);
				}
				if ((fd = open(SNAPDEV_NAME, O_RDWR)) < 0) {
					fprintf(stderr, "Can not open node %s: %s\n", 
						SNAPDEV_NAME, strerror(errno));
					return (-errno);
				}
			} else {
				fprintf(stderr, "Can not open node %s: %s %d \n", 
					SNAPDEV_NAME, strerror(errno), errno);
				return(-errno);
			}
		}
		open_device_table.device[index].fd = fd;
	}
	return 0;
}

int snap_dev_open(int argc, char **argv)
{
	struct snap_mnt *snaplist;
	char *dev_name;
	int rc;

	if (argc != 2) { 
		fprintf(stderr, "The argument count is not right \n");
		return CMD_HELP;
	}
	
	dev_name = argv[1];

	get_snaplist();
	list_for_each_entry(snaplist, &snap_list, snap_mnt_list) {
		if (!strcmp(&snaplist->device.name[0], dev_name)) {
			rc = open_device(&snaplist->device.name[0], 
				    snaplist->device.dev);
			release_snap_list();	
			return rc;
		}
	}
	release_snap_list();	
	fprintf(stderr, "%s are not snapdevice\n", dev_name);
	return (-EINVAL);
}
int snap_dev_list(int argc, char **argv)
{
	struct snap_mnt *snaplist;
	int    index = 0;

	if (argc != 1) { 
		fprintf(stderr, "The argument count is not right \n");
		return CMD_HELP;
	}

	get_snaplist();
	printf("index:\t\tmount_point:\t\tdevice:\n");
	list_for_each_entry(snaplist, &snap_list, snap_mnt_list) {
		printf("%d\t\t%s\t\t%s \n", index,
			&snaplist->device.mntpt[0], 
			&snaplist->device.name[0]);
		index++;
	}
	release_snap_list();
	return 0;
}
static inline void print_snap_table(void * buf)
{
	struct ioc_snap_tbl_data *ptable;
	int    i;

	ptable = (struct ioc_snap_tbl_data*)buf;
	
	printf("There are %d snapshot in the system\n", ptable->count);
	printf("index\t\tname\t\t\ttime\t\t\n"); 
	for (i = 0; i < ptable->count; i++) {
		struct	tm* local_time; 	
		char	time[128];
		
		memset (time, 0, sizeof(time));
		local_time = localtime(&ptable->snaps[i].time);
		if (local_time) 
			strftime(time, sizeof(time), "%a %b %d %Y %H:%M:%S", local_time);			
		printf("%-10d\t%-20s\t%s\n", ptable->snaps[i].index, ptable->snaps[i].name, time); 
	}
}
int snap_snap_list(int argc, char **argv)
{
	int i, rc = 0;

	if (argc != 1 && argc != 2) {
		fprintf(stderr, "The argument count is not right\n");
		return CMD_HELP;
	}
	if (open_device_table.count == 0) {
		fprintf(stderr, "Please open a snapdevice first\n");
		return (-EINVAL);
	}
	
	for (i = 0; i < open_device_table.count; i++) {
		struct ioc_snap_tbl_data *snap_ioc_data;

		IOC_INIT(snap_ioc_data);

		if (argc == 2) { 
			snap_ioc_data->no = atoi(argv[1]);
		} else { 
			snap_ioc_data->no = 0;
		}
		
		IOC_PACK(sizeof(struct ioc_snap_tbl_data));
		
		if ((rc = ioctl(open_device_table.device[i].fd, 
				IOC_SNAP_PRINTTABLE, buf))) {
			fprintf(stderr, "can not retrive snaptable on device %s failed %d \n", 
				&open_device_table.device[i].name[0], rc);
			return (rc);
		}
		if(((struct ioc_data*)buf)->ioc_bulk)
			print_snap_table(((struct ioc_data*)buf)->ioc_bulk);	
	}
	return rc;
}
int snap_snap_add(int argc, char **argv)
{
	int    rc = 0, i;
	
	if (argc != 3 && argc !=2) {
		fprintf(stderr, "The argument count is not right \n");
		return CMD_HELP;
	}

	if (open_device_table.count == 0) {
		fprintf(stderr, "Please open a snapdevice first\n");
		return (-EINVAL);
	}
	for (i = 0; i < open_device_table.count; i++) {
		struct ioc_snap_tbl_data *snap_ioc_data;

		IOC_INIT(snap_ioc_data);

		snap_ioc_data->count = 1;
		snap_ioc_data->dev = open_device_table.device[i].dev;

		if (argc == 3) { 
			snap_ioc_data->no = atoi(argv[1]);
			memcpy(snap_ioc_data->snaps[0].name, 
			       argv[2], strlen(argv[2]));
		} else { 
			snap_ioc_data->no = 0;
			memcpy(snap_ioc_data->snaps[0].name, 
			       argv[1], strlen(argv[1]));
		}
		snap_ioc_data->snaps[0].time = time(NULL);
		
		IOC_PACK(sizeof(struct ioc_snap_tbl_data) + sizeof(struct snap));

		if ((rc = ioctl(open_device_table.device[i].fd, 
					IOC_SNAP_ADD, buf))) {
			fprintf(stderr, "add %s failed \n", argv[1]);
		} else {
			fprintf(stderr, "add %s success\n", argv[1]);
		}
	}
	return rc;
}
