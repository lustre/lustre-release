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
#include <linux/module.h>

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

struct mds_request *mds_prep_req(int size, int opcode)
{
	struct mds_request *request;
	int rc;
	ENTRY; 

	request = (struct mds_request *)kmalloc(sizeof(*request), GFP_KERNEL); 
	if (!request) { 
		printk("mds_prep_req: request allocation out of memory\n");
		return NULL;
	}

	rc = mds_pack_req(NULL, 0, NULL, 0, 
			  &request->rq_reqhdr, &request->rq_req, 
			  &request->rq_reqlen, &request->rq_reqbuf);
	if (rc) { 
		printk("llight request: cannot pack request %d\n", rc); 
		return NULL;
	}
	request->rq_reqhdr->opc = opcode;

	EXIT;
	return request;
}




static int mds_queue_wait(struct mds_request *req)
{
	int rc;

	/* XXX fix the race here (wait_for_event?)*/
	/* hand the packet over to the server */
	rc = mds_queue_req(req); 
	if (rc) { 
		printk("osc_queue_wait: error %d, opcode %d\n", rc, 
		       req->rq_reqhdr->opc); 
		return -rc;
	}

	init_waitqueue_head(&req->rq_wait_for_rep);
	printk("-- sleeping\n");
	interruptible_sleep_on(&req->rq_wait_for_rep);
	printk("-- done\n");

	mds_unpack_rep(req->rq_repbuf, req->rq_replen, &req->rq_rephdr, 
		       &req->rq_rep); 
	printk("-->osc_queue_wait: buf %p len %d status %d\n", 
	       req->rq_repbuf, req->rq_replen, req->rq_rephdr->status); 

	EXIT;
	return req->rq_rephdr->status;
}

void mds_free_req(struct mds_request *request)
{
	kfree(request);
}

int mdc_getattr(ino_t ino, struct  mds_rep  **rep)
{
	struct mds_request *request;
	int rc; 

	request = mds_prep_req(sizeof(*request), MDS_GETATTR); 
	if (!request) { 
		printk("llight request: cannot pack\n");
		return -ENOMEM;
	}

	request->rq_req->fid1.id = ino;

	rc = mds_queue_wait(request);
	if (rc) { 
		printk("llight request: error in handling %d\n", rc); 
		goto out;
	}

	printk("mds_getattr: mode: %o\n", request->rq_rep->mode); 

	if (rep ) { 
		*rep = request->rq_rep;
	}

 out: 
	mds_free_req(request);
	return rc;
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
		err = mdc_getattr(2, NULL);
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


static int __init mds_request_init(void)
{
	misc_register(&request_dev);
        return 0 ;
}


static void __exit mds_request_exit(void)
{
	misc_deregister(&request_dev);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre MDS Request Tester v1.0");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(mdc_getattr); 


module_init(mds_request_init);
module_exit(mds_request_exit);
