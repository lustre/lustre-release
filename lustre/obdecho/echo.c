/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/ext2_obd/ext2_obd.c
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Peter Braam <braam@clusterfs.com>
 */

static char rcsid[] __attribute ((unused)) = "$Id: echo.c,v 1.24 2002/08/19 23:45:00 adilger Exp $";
#define OBDECHO_VERSION "$Revision: 1.24 $"

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/ext2_fs.h>
#include <linux/quotaops.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_ECHO

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd_echo.h>
#include <linux/lustre_debug.h>
#include <linux/lustre_dlm.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];
static struct obdo OA;
static obd_count GEN;
static long echo_pages = 0;

static atomic_t echo_page_rws;
static atomic_t echo_getattrs;

#define ECHO_PROC_STAT "sys/obdecho"

int
echo_proc_read (char *page, char **start, off_t off, int count, int *eof, void *data)
{
	int                len;
        int                attrs = atomic_read (&echo_getattrs);
        int                pages = atomic_read (&echo_page_rws);

	*eof = 1;
	if (off != 0)
		return (0);

	len = sprintf (page, "%d %d\n", pages, attrs);

	*start = page;
	return (len);
}

int
echo_proc_write (struct file *file, const char *ubuffer, unsigned long count, void *data)
{
	/* Ignore what we've been asked to write, and just zero the stats counters */
        atomic_set (&echo_page_rws, 0);
        atomic_set (&echo_getattrs, 0);

	return (count);
}

void
echo_proc_init(void)
{
        struct proc_dir_entry *entry;

        entry = create_proc_entry(ECHO_PROC_STAT, S_IFREG|S_IRUGO|S_IWUSR,NULL);

        if (entry == NULL) {
                CERROR("couldn't create proc entry %s\n", ECHO_PROC_STAT);
                return;
        }

        entry->data = NULL;
        entry->read_proc = echo_proc_read;
	entry->write_proc = echo_proc_write;
}

void echo_proc_fini(void)
{
        remove_proc_entry(ECHO_PROC_STAT, 0);
}

static int echo_connect(struct lustre_handle *conn, struct obd_device *obd,
                        char *cluuid)
{
        int rc;

        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd, NULL);

        if (rc)
                MOD_DEC_USE_COUNT;

        return rc;
}

static int echo_disconnect(struct lustre_handle *conn)
{
        int rc;

        rc = class_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

        return rc;
}

static int echo_getattr(struct lustre_handle *conn, struct obdo *oa,
                        struct lov_stripe_md *md)
{
        memcpy(oa, &OA, sizeof(*oa));
        oa->o_mode = ++GEN;

        atomic_inc (&echo_getattrs);

        return 0;
}

#define DESC_PRIV 0x10293847

int echo_preprw(int cmd, struct lustre_handle *conn, int objcount,
                struct obd_ioobj *obj, int niocount, struct niobuf_remote *nb,
                struct niobuf_local *res, void **desc_private)
{
        struct niobuf_local *r = res;
        int rc = 0;
        int i;

        ENTRY;

        memset(res, 0, sizeof(*res) * niocount);

        CDEBUG(D_PAGE, "%s %d obdos with %d IOs\n",
               cmd == OBD_BRW_READ ? "reading" : "writing", objcount, niocount);

        *desc_private = (void *)DESC_PRIV;

        for (i = 0; i < objcount; i++, obj++) {
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, nb++, r++) {
                        r->page = alloc_pages(GFP_KERNEL, 0);
                        if (!r->page) {
                                CERROR("can't get page %d/%d for id "LPU64"\n",
                                       j, obj->ioo_bufcnt, obj->ioo_id);
                                GOTO(preprw_cleanup, rc = -ENOMEM);
                        }
                        echo_pages++;

                        r->offset = nb->offset;
                        r->addr = kmap(r->page);
                        r->len = nb->len;

                        CDEBUG(D_PAGE, "$$$$ get page %p, addr %p@"LPU64"\n",
                               r->page, r->addr, r->offset);
                        if (cmd & OBD_BRW_READ)
                                page_debug_setup(r->addr, r->len, r->offset,
                                                 obj->ioo_id);
                }
        }
        CDEBUG(D_PAGE, "%ld pages allocated after prep\n", echo_pages);

        RETURN(0);

preprw_cleanup:
        /* It is possible that we would rather handle errors by  allow
         * any already-set-up pages to complete, rather than tearing them
         * all down again.  I believe that this is what the in-kernel
         * prep/commit operations do.
         */
        CERROR("cleaning up %ld pages (%d obdos)\n", (long)(r - res), objcount);
        while (r-- > res) {
                kunmap(r->page);
                __free_pages(r->page, 0);
                echo_pages--;
        }
        memset(res, 0, sizeof(*res) * niocount);

        return rc;
}

int echo_commitrw(int cmd, struct lustre_handle *conn, int objcount,
                  struct obd_ioobj *obj, int niocount, struct niobuf_local *res,
                  void *desc_private)
{
        struct niobuf_local *r = res;
        int rc = 0;
        int i;
        ENTRY;

        CDEBUG(D_PAGE, "%s %d obdos with %d IOs\n",
               cmd == OBD_BRW_READ ? "reading" : "writing", objcount, niocount);

        if (niocount && !r) {
                CERROR("NULL res niobuf with niocount %d\n", niocount);
                RETURN(-EINVAL);
        }

        LASSERT(desc_private == (void *)DESC_PRIV);

        for (i = 0; i < objcount; i++, obj++) {
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, r++) {
                        struct page *page = r->page;
                        void *addr;

                        if (!page || !(addr = page_address(page)) ||
                            !kern_addr_valid(addr)) {

                                CERROR("bad page "LPU64":%p, buf %d/%d\n",
                                       obj->ioo_id, page, j, obj->ioo_bufcnt);
                                GOTO(commitrw_cleanup, rc = -EFAULT);
                        }

                        atomic_inc (&echo_page_rws);

                        CDEBUG(D_PAGE, "$$$$ use page %p, addr %p@"LPU64"\n",
                               r->page, addr, r->offset);
                        if (cmd & OBD_BRW_WRITE)
                                page_debug_check("echo", addr, r->len,
                                                 r->offset, obj->ioo_id);

                        kunmap(page);
                        __free_pages(page, 0);
                        echo_pages--;
                }
        }
        CDEBUG(D_PAGE, "%ld pages remain after commit\n", echo_pages);
        RETURN(0);

commitrw_cleanup:
        CERROR("cleaning up %ld pages (%d obdos)\n",
               niocount - (long)(r - res) - 1, objcount);
        while (++r < res + niocount) {
                struct page *page = r->page;

                kunmap(page);
                __free_pages(page, 0);
                echo_pages--;
        }
        return rc;
}

static int echo_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        ENTRY;

        obddev->obd_namespace =
                ldlm_namespace_new("echo-tgt", LDLM_NAMESPACE_SERVER);
        if (obddev->obd_namespace == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }

        RETURN(0);
}

static int echo_cleanup(struct obd_device *obddev)
{
        ENTRY;

        ldlm_namespace_free(obddev->obd_namespace);

        RETURN(0);
}

struct obd_ops echo_obd_ops = {
        o_connect:     echo_connect,
        o_disconnect:  echo_disconnect,
        o_getattr:     echo_getattr,
        o_preprw:      echo_preprw,
        o_commitrw:    echo_commitrw,
        o_setup:       echo_setup,
        o_cleanup:     echo_cleanup
};

static int __init obdecho_init(void)
{
        printk(KERN_INFO "Echo OBD driver " OBDECHO_VERSION " info@clusterfs.com\n");

        echo_proc_init();

        return class_register_type(&echo_obd_ops, OBD_ECHO_DEVICENAME);
}

static void __exit obdecho_exit(void)
{
        echo_proc_fini ();

        CERROR("%ld prep/commitrw pages leaked\n", echo_pages);
        class_unregister_type(OBD_ECHO_DEVICENAME);
}

MODULE_AUTHOR("Cluster Filesystems Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Testing Echo OBD driver " OBDECHO_VERSION);
MODULE_LICENSE("GPL");

module_init(obdecho_init);
module_exit(obdecho_exit);
