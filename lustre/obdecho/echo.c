/*
 *  linux/fs/ext2_obd/ext2_obd.c
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Peter Braam <braam@clusterfs.com>
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/ext2_fs.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_ECHO

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd_echo.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];
static struct obdo OA;
static obd_count GEN;

static int echo_getattr(struct obd_conn *conn, struct obdo *oa)
{
        memcpy(oa, &OA, sizeof(*oa));
        oa->o_mode = ++GEN;

        return 0;
}

int echo_preprw(int cmd, struct obd_conn *conn, int objcount,
                struct obd_ioobj *obj, int niocount, struct niobuf *nb, 
                struct niobuf *res)
{
        int rc = 0;
        int i;

        ENTRY;
        memset(res, 0, sizeof(*res) * niocount);

        for (i = 0; i < objcount; i++, obj++) { 
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, nb++, res++) { 
                        unsigned long address;

                        address = get_zeroed_page(GFP_KERNEL);
                        if (!address) { 
                                /* FIXME: cleanup old pages */
                                EXIT; 
                                rc = -ENOMEM; 
                        }
                        
                        /*
                        if (cmd == OBD_BRW_READ) {
                                __u64 *data = address;

                                data[0] = obj->ioo_id;
                                data[1] = j;
                                data[2] = nb->offset;
                                data[3] = nb->len;
                        }
                        */
                        
                        res->addr = address;
                        res->offset = nb->offset;
                        res->page = virt_to_page(address);
                        res->len = PAGE_SIZE;
                        // r->flags
                }
        }

        return rc;
}

int echo_commitrw(int cmd, struct obd_conn *conn, int objcount,
                  struct obd_ioobj *obj, int niocount, struct niobuf *res)
{
        int i; 
        int rc = 0;
        ENTRY;

        for (i = 0; i < objcount; i++, obj++) { 
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, res++) { 
                        struct page *page;

                        if (!res) {
                                /* FIXME: cleanup remaining pages */
                                CERROR("NULL buf, obj %Ld (%d), buf %d/%d\n",
                                        obj->ioo_id, i, j, obj->ioo_bufcnt);
                                rc = -EINVAL;
                        }

                        page = res->page;
                        if (page || !VALID_PAGE(page)) {
                                /* FIXME: cleanup remaining pages */
                                CERROR("bad page %p, obj %Ld (%d), buf %d/%d\n",
                                        page, obj->ioo_id, i, j, obj->ioo_bufcnt);
                                rc = -EINVAL;
                        }

                        page_cache_release(page);
                }
        }
        return rc;
}

struct obd_ops echo_obd_ops = {
        o_connect:     gen_connect,
        o_disconnect:  gen_disconnect,
        o_getattr:     echo_getattr,
        o_preprw:      echo_preprw,
        o_commitrw:    echo_commitrw,
};


static int __init obdecho_init(void)
{
        printk(KERN_INFO "Echo OBD driver  v0.001, braam@clusterfs.com\n");

        return obd_register_type(&echo_obd_ops, OBD_ECHO_DEVICENAME);
}

static void __exit obdecho_exit(void)
{
        obd_unregister_type(OBD_ECHO_DEVICENAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Testing Echo OBD driver v1.0");
MODULE_LICENSE("GPL"); 

module_init(obdecho_init);
module_exit(obdecho_exit);
