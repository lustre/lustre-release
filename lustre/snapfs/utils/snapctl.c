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

#define IOC_PACK(ioc, length, input) 	\
do{                               	\
	ioc.data = input;	  	\
	ioc.len  = length;		\
}while(0)			  

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

int snapshot_dev(int argc, char **argv)
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
	fprintf(stderr, "can not find the device %s", dev_name);
	return (-EINVAL);
}
int snapshot_list(int argc, char **argv)
{
	struct snap_mnt *snaplist;
	if (argc != 1) { 
		fprintf(stderr, "The argument count is not right \n");
		return CMD_HELP;
	}

	get_snaplist();
	list_for_each_entry(snaplist, &snap_list, snap_mnt_list) {
		fprintf(stderr, "devid: %lu name: %s",
			snaplist->device.dev, 
			&snaplist->device.name[0]);
	}
	release_snap_list();
	return 0;
}
int snapshot_add(int argc, char **argv)
{
	int    rc, i;
	
	if (argc != 3 && argc !=2) {
		fprintf(stderr, "The argument count is not right \n");
		return CMD_HELP;
	}

	if (open_device_table.count == 0) {
		fprintf(stderr, "Please first open a snapdevice \n");
		return (-EINVAL);
	}
	for (i = 0; i < open_device_table.count; i++) {
		struct snap_table_data	*snap_ioc_data;
		struct ioc_data		ioc_data;

		snap_ioc_data = (struct snap_table_data *)
			         malloc(sizeof(struct snap_table_data));
		snap_ioc_data->tblcmd_count = 1;
		snap_ioc_data->dev = open_device_table.device[i].dev;

		if (argc == 3) { 
			snap_ioc_data->tblcmd_no = atoi(argv[1]);
			memcpy(&snap_ioc_data->tblcmd_snaps[0].name[0], 
			       argv[2], strlen(argv[2]));
		} else { 
			snap_ioc_data->tblcmd_no = 0;
			memcpy(&snap_ioc_data->tblcmd_snaps[0].name[0], 
			       argv[1], strlen(argv[1]));
		}
		snap_ioc_data->tblcmd_snaps[0].time = time(NULL);
		IOC_PACK(ioc_data, sizeof(struct snap_table_data), (char*)snap_ioc_data);
	
		if ((rc = ioctl(open_device_table.device[i].fd, 
				IOC_SNAP_ADD, &ioc_data))) {
			fprintf(stderr, "add snapshot %s failed %d \n", 
				&snap_ioc_data->tblcmd_snaps[0].name[0], rc);
		} else {
			fprintf(stderr, "add snapshot %s success\n", 
				&snap_ioc_data->tblcmd_snaps[0].name[0]); 
		}
		free(snap_ioc_data);
		return rc;
	}
	return 0;
}
