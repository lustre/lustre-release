# define DEBUG_SUBSYSTEM S_PORTALS

#include <linux/fs.h>
#include <linux/ctype.h>
#include <asm/uaccess.h>

#include <libcfs/libcfs.h>

cfs_file_t *
cfs_filp_open (const char *name, int flags, int mode, int *err)
{
	/* XXX
	 * Maybe we need to handle flags and mode in the future
	 */
	cfs_file_t	*filp = NULL;

	filp = filp_open(name, flags, mode); 
	if (IS_ERR(filp)) { 
		int rc;

		rc = PTR_ERR(filp); 
		printk(KERN_ERR "LustreError: can't open %s file: err %d\n", 
				name, rc);
		if (err)
			*err = rc;
		filp = NULL;
	}
	return filp;
}

EXPORT_SYMBOL(cfs_filp_open);
