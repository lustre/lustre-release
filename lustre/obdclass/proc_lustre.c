/* proc_lustre.c manages /proc/lustre/obd. 
 *
 * OBD devices materialize in /proc as a directory:
 *              /proc/lustre/obd/<number>
 * when /dev/obd<number> is opened. When the device is closed, the 
 * directory entry disappears. 
 * 
 * For each open OBD device, code in this file also creates a file
 * named <status>. "cat /proc/lustre/obd/<number>/status" gives 
 * information about the OBD device's configuration.
 * The class driver manages the "status" entry.
 *
 * Other logical drivers can create their own entries. For example,
 * the obdtrace driver creates /proc/lustre/obd/<obdid>/stats entry.
 *
 * This file defines three functions 
 *               proc_lustre_register_obd_device()
 *               proc_lustre_release_obd_device()
 *               proc_lustre_remove_obd_entry() 
 * that dynamically create/delete /proc/lustre/obd entries:
 *
 *     proc_lustre_register_obd_device() registers an obd device,
 *     and, if this is the first OBD device, creates /proc/lustre/obd.
 *
 *     proc_lustre_release_obd_device() removes device information
 *     from /proc/lustre/obd, and if this is the last OBD device
 *     removes  /proc/lustre/obd.
 *
 *     proc_lustre_remove_obd_entry() removes a
 *     /proc/lustre/obd/<obdid>/ entry by name. This is the only
 *     function that is exported to other modules. 
 *
 * Copyright (c) 2001 Rumi Zahir <rumi.zahir@intel.com>
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>

#include <linux/obd_support.h>
#include <linux/obd_class.h>


#ifdef CONFIG_PROC_FS
extern struct proc_dir_entry proc_root;

static struct proc_dir_entry *proc_lustre_dir_entry = 0;
static struct proc_dir_entry *proc_lustre_obd_dir_entry = 0;

static struct proc_dir_entry *
proc_lustre_mkdir(const char* dname, struct proc_dir_entry *parent)
{
	struct proc_dir_entry *child_dir_entry;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)	/*0x20300 */
	child_dir_entry = proc_mkdir(dname, parent);
#else
	child_dir_entry = create_proc_entry(dname,
					    S_IFDIR | S_IRUGO | S_IXUGO,
					    &proc_root);
#endif
	if (!child_dir_entry)
		printk ("lustre: failed to create /proc  entry %s\n", dname);
	
	return child_dir_entry;
}

static int read_lustre_status(char *page, char **start, off_t offset,
			      int count, int *eof, void *data)
{
	struct obd_device * obddev = (struct obd_device *) data;
	int p;

	p = sprintf(&page[0], "/dev/obd%d: ", obddev->obd_minor);
	
	if (obddev->obd_refcnt==0) { 
		/* obd is unused */
		p += sprintf(&page[p], "open but unused\n");
	}
	else {	/* obd in use */
		p += sprintf(&page[p], "refcnt(%d)", obddev->obd_refcnt);
		
		if  (obddev->obd_flags & OBD_ATTACHED) {
			p += sprintf(&page[p], ", attached(%s)", 
				     obddev->obd_type->typ_name);
		}
		
		if  (obddev->obd_flags & OBD_SET_UP) {
			struct dentry   *my_dentry;
			struct vfsmount *root_mnt;
			char *path;
			char *pathpage;
			
			if (!(pathpage = (char*) __get_free_page(GFP_KERNEL)))
				return -ENOMEM;
		
			my_dentry = obddev->obd_fsname.dentry;
			root_mnt = mntget(current->fs->rootmnt);
			path = d_path(my_dentry,root_mnt,pathpage,PAGE_SIZE);

			p += sprintf(&page[p], ", setup(%s)", path);
			
			free_page((unsigned long) pathpage);
		}
		
		/* print connections */
		{
			struct list_head * lh;
			struct obd_client * cli=0;
			
			lh = &obddev->obd_gen_clients;
			while ((lh = lh->next) != &obddev->obd_gen_clients) {
				p += sprintf(&page[p],
					     ((cli==0) ? ", connections(" : ",") );
				cli = list_entry(lh, struct obd_client, cli_chain);
				p += sprintf(&page[p], "%d", cli->cli_id);
			} /* while */
			if (cli!=0) { /* there was at least one client */
				p += sprintf(&page[p], ")");
			}
		}
		
		p += sprintf(&page[p], "\n");
	}

	/* Compute eof and return value */

	if (offset + count >= p) {
		*eof=1;
		return (p - offset);
	}
	return count;
}

struct proc_dir_entry *
proc_lustre_register_obd_device(struct obd_device *obd)
{
	char obdname[32];
	struct proc_dir_entry *obd_dir;
	struct proc_dir_entry *obd_status = 0;

	if (!proc_lustre_dir_entry) {
		proc_lustre_dir_entry = 
			proc_lustre_mkdir("lustre", &proc_root);
		if (!proc_lustre_dir_entry)
			return 0;
	
		proc_lustre_obd_dir_entry = 
			proc_lustre_mkdir("obd", proc_lustre_dir_entry);
		if (!proc_lustre_obd_dir_entry)
			return 0;
	}

	sprintf(obdname, "%d", obd->obd_minor);

	obd_dir =  proc_lustre_mkdir(obdname, proc_lustre_obd_dir_entry);
	
        if (obd_dir) 
		obd_status = create_proc_entry("status", S_IRUSR | S_IFREG, obd_dir);

	if (obd_status) {
		obd_status->read_proc = read_lustre_status;
		obd_status->data = (void*) obd;
	}

	return obd_dir;
}

void proc_lustre_remove_obd_entry(const char* name, struct obd_device *obd)
{
	struct proc_dir_entry *obd_entry = 0;
	struct proc_dir_entry *obd_dir = obd->obd_proc_entry;
	
	remove_proc_entry(name, obd_dir);

	while (obd_dir->subdir==0) {
		/* if we removed last entry in this directory,
		 * then remove parent directory unless this
		 * is /proc itself
		 */
		if (obd_dir == &proc_root) 
			break;
			
		obd_entry = obd_dir;
		obd_dir = obd_dir->parent;
	
		/* If /proc/lustre/obd/XXX or /proc/lustre/obd or
		 * /proc/lustre are being removed, then reset 
		 * internal variables
		 */
		
		if (obd_entry == obd->obd_proc_entry) 
			obd->obd_proc_entry=0; /* /proc/lustre/obd/XXX */
		else 
			if (obd_entry == proc_lustre_obd_dir_entry)
				proc_lustre_obd_dir_entry=0;
			else 
				if (obd_entry == proc_lustre_dir_entry) 
					proc_lustre_dir_entry=0;

		remove_proc_entry(obd_entry->name, obd_dir);
	}
}

void proc_lustre_release_obd_device(struct obd_device *obd)
{
	proc_lustre_remove_obd_entry("status", obd);
}


#else  /* CONFIG_PROC_FS */

struct proc_dir_entry *proc_lustre_register_obd_device(struct obd_device *obd)
{
	return 0;
}

void proc_lustre_remove_obd_entry(const char* name, struct obd_device *obd) {}
void proc_lustre_release_obd_device(struct obd_device *obd) {}

#endif   /* CONFIG_PROC_FS */
     				   
EXPORT_SYMBOL(proc_lustre_remove_obd_entry);











