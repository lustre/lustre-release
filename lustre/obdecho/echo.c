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

/*
static int echo_setattr(struct obd_conn *conn, struct obdo *oa)
{
        memcpy(&OA, oa, sizeof(*oa));

        return 0;
}
*/

struct obd_ops echo_obd_ops = {
        o_connect:     gen_connect,
        o_disconnect:  gen_disconnect,
        o_getattr:     echo_getattr,
//        o_setattr:     echo_setattr,
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
