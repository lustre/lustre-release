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
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>

extern int ost_queue_req(struct obd_device *obddev, struct ost_request *);



int osc_getattr(struct obd_conn *conn, struct obdo *oa)
{
	struct obd_device *obddev = conn->oc_dev;
	struct ost_request *request;
	int rc; 

	request = (struct ost_request *)kmalloc(sizeof(*request), 
						GFP_KERNEL); 
	if (!request) { 
		printk("osc_getattr: request allocation out of memory\n");
		return -ENOMEM;
	}

	rc = ost_pack_req(NULL, 0, NULL, 0, 
			  &request->rq_reqhdr, &request->rq_req, 
			  &request->rq_reqlen, &request->rq_reqbuf);
	if (rc) { 
		printk("llight request: cannot pack request %d\n", rc); 
		return rc;
	}
	
	memcpy(&request->rq_req->oa, oa, sizeof(*oa));
	request->rq_reqhdr->opc = OST_GETATTR;
	
	printk("osc_getattr ost tgt at %p\n", &obddev->u.osc.osc_tgt->u.ost);
	rc = ost_queue_req(obddev->u.osc.osc_tgt, request);
	if (rc) { 
		printk("ost_gettatr: error in handling %d\n", rc); 
		return rc;
	}

	printk("mode: %o\n", request->rq_rep->oa.o_mode); 
	if (oa) { 
		memcpy(oa, &request->rq_rep->oa, sizeof(*oa));
	}
	kfree(request->rq_repbuf);
	kfree(request);
	return 0;
}


/* mount the file system (secretly) */
static int osc_setup(struct obd_device *obddev, obd_count len,
			void *buf)
			
{
	struct obd_ioctl_data* data = buf;
	struct osc_obd *osc = &obddev->u.osc;
        ENTRY;

	if (data->ioc_dev  < 0 || data->ioc_dev > MAX_OBD_DEVICES) { 
		EXIT;
		return -ENODEV;
	}

        osc->osc_tgt = &obd_dev[data->ioc_dev];
	printk("OSC: tgt %d ost at %p\n", data->ioc_dev, &osc->osc_tgt->u.ost); 
        if ( ! (osc->osc_tgt->obd_flags & OBD_ATTACHED) || 
             ! (osc->osc_tgt->obd_flags & OBD_SET_UP) ){
                printk("device not attached or not set up (%d)\n", 
                       data->ioc_dev);
                EXIT;
		return -EINVAL;
        } 

        MOD_INC_USE_COUNT;
        EXIT; 
        return 0;
} 

static int osc_cleanup(struct obd_device * obddev)
{
        ENTRY;

        if ( !(obddev->obd_flags & OBD_SET_UP) ) {
                EXIT;
                return 0;
        }

        MOD_DEC_USE_COUNT;
        EXIT;
        return 0;
}


struct obd_ops osc_obd_ops = { 
	o_setup:   osc_setup,
	o_cleanup: osc_cleanup, 
	o_getattr: osc_getattr
};

static int __init osc_init(void)
{
        obd_register_type(&osc_obd_ops, LUSTRE_OSC_NAME);
	return 0;
}

static void __exit osc_exit(void)
{
	obd_unregister_type(LUSTRE_OSC_NAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC) v1.0");
MODULE_LICENSE("GPL"); 

module_init(osc_init);
module_exit(osc_exit);

