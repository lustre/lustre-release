/*
 * Copryright (C) 2001 Cluster File Systems, Inc.
 *
 */

#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/segment.h>
#include <linux/miscdevice.h>

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>

#define REQUEST_MINOR 244
extern int mds_queue_req(struct mds_request *);

int llight_getattr(ino_t ino, struct  mds_rep  *rep)
{
	struct mds_request *request;
	int rc; 

	request = (struct mds_request *)kmalloc(sizeof(*request), 
						GFP_KERNEL); 
	if (!request) { 
		printk("llight request: out of memory\n");
		return -ENOMEM;
	}

	rc = mds_pack_req(NULL, 0, NULL, 0, 
			  &request->rq_reqhdr, &request->rq_req, 
			  &request->rq_reqlen, &request->rq_reqbuf);
	if (rc) { 
		printk("llight request: cannot pack request %d\n", rc); 
		return rc;
	}
	request->rq_req->fid1.id = ino;

	request->rq_reqhdr->opc = MDS_GETATTR;
	
	rc = mds_queue_req(request);
	if (rc) { 
		printk("llight request: error in handling %d\n", rc); 
		return rc;
	}

	printk("mode: %o\n", request->rq_rep->mode); 
	if (rep) { 
		memcpy(rep, request->rq_repbuf, sizeof(*rep));
	}
	kfree(request->rq_repbuf);
	kfree(request);
	return 0;
}


static int request_ioctl(struct inode *inode, struct file *file, 
		       unsigned int cmd, unsigned long arg)
{
	int err;

	ENTRY;

	if (MINOR(inode->i_rdev) != REQUEST_MINOR) {
		EXIT;
		return -EINVAL;
	}

	if ( _IOC_TYPE(cmd) != IOC_REQUEST_TYPE || 
             _IOC_NR(cmd) < IOC_REQUEST_MIN_NR  || 
             _IOC_NR(cmd) > IOC_REQUEST_MAX_NR ) {
                CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
                                _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
                EXIT;
                return -EINVAL;
        }

	
	switch (cmd) {
	case IOC_REQUEST_GETATTR: { 
		printk("-- getting attr for ino 2\n"); 
		err = llight_getattr(2, NULL);
		printk("-- done err %d\n", err);
		break;
	}
	default:		
		err = -EINVAL;
		EXIT;
		break;
	}
	EXIT;
	return err;
}


static struct file_operations requestdev_fops = {
	ioctl: request_ioctl,
};


static struct miscdevice request_dev = {
	REQUEST_MINOR,
	"request",
	&requestdev_fops
};


int init_request_module(void)
{
	misc_register( &request_dev );
        return 0 ;
}

#ifdef MODULE
MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre MDS Request Tester v1.0");

#include <linux/module.h>

int init_module(void)
{
        return init_request_module();
}

void cleanup_module(void)
{
	misc_deregister(&request_dev);
	return;
}

#endif
