/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdecho/echo.c
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Peter Braam <braam@clusterfs.com>
 * and Andreas Dilger <adilger@clusterfs.com>
 */

static char rcsid[] __attribute ((unused)) = "$Id: echo.c,v 1.47 2002/11/13 02:46:41 thantry Exp $";
#define OBDECHO_VERSION "$Revision: 1.47 $"

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
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
#include <linux/lprocfs_status.h>

static atomic_t echo_page_rws;
static atomic_t echo_getattrs;

#define ECHO_PROC_STAT "sys/obdecho"
#define ECHO_INIT_OBJID 0x1000000000000000ULL

extern struct lprocfs_vars status_var_nm_1[];
extern struct lprocfs_vars status_class_var[];

int echo_proc_read(char *page, char **start, off_t off, int count, int *eof,
                   void *data)
{
        long long attrs = atomic_read(&echo_getattrs);
        long long pages = atomic_read(&echo_page_rws);
        int len;

        *eof = 1;
        if (off != 0)
                return (0);

        len = sprintf(page, "%Ld %Ld\n", attrs, pages);

        *start = page;
        return (len);
}

int echo_proc_write(struct file *file, const char *ubuffer,
                    unsigned long count, void *data)
{
        /* Ignore what we've been asked to write, and just zero the counters */
        atomic_set (&echo_page_rws, 0);
        atomic_set (&echo_getattrs, 0);

        return (count);
}

void echo_proc_init(void)
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
                        obd_uuid_t cluuid, struct recovd_obd *recovd,
                        ptlrpc_recovery_cb_t recover)
{
        int rc;

        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd, cluuid);

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

static __u64 echo_next_id(struct obd_device *obddev)
{
        obd_id id;

        spin_lock(&obddev->u.echo.eo_lock);
        id = ++obddev->u.echo.eo_lastino;
        spin_unlock(&obddev->u.echo.eo_lock);

        return id;
}

int echo_create(struct lustre_handle *conn, struct obdo *oa,
                struct lov_stripe_md **ea)
{
        struct obd_device *obd = class_conn2obd(conn);

        if (!obd) {
                CERROR("invalid client %Lx\n", conn->addr);
                return -EINVAL;
        }

        if (!(oa->o_mode && S_IFMT)) {
                CERROR("filter obd: no type!\n");
                return -ENOENT;
        }

        if (!(oa->o_valid & OBD_MD_FLTYPE)) {
                CERROR("invalid o_valid %08x\n", oa->o_valid);
                return -EINVAL;
        }

        oa->o_id = echo_next_id(obd);
        oa->o_valid = OBD_MD_FLID;
        atomic_inc(&obd->u.echo.eo_create);

        return 0;
}

int echo_destroy(struct lustre_handle *conn, struct obdo *oa,
                 struct lov_stripe_md *ea)
{
        struct obd_device *obd = class_conn2obd(conn);

        if (!obd) {
                CERROR("invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        if (!(oa->o_valid & OBD_MD_FLID)) {
                CERROR("obdo missing FLID valid flag: %08x\n", oa->o_valid);
                RETURN(-EINVAL);
        }

        if (oa->o_id > obd->u.echo.eo_lastino || oa->o_id < ECHO_INIT_OBJID) {
                CERROR("bad destroy objid: "LPX64"\n", oa->o_id);
                RETURN(-EINVAL);
        }

        atomic_inc(&obd->u.echo.eo_destroy);

        return 0;
}

static int echo_open(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *md)
{
        return 0;
}

static int echo_close(struct lustre_handle *conn, struct obdo *oa,
                      struct lov_stripe_md *md)
{
        return 0;
}

static int echo_getattr(struct lustre_handle *conn, struct obdo *oa,
                        struct lov_stripe_md *md)
{
        struct obd_device *obd = class_conn2obd(conn);
        obd_id id = oa->o_id;

        if (!obd) {
                CERROR("invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        if (!(oa->o_valid & OBD_MD_FLID)) {
                CERROR("obdo missing FLID valid flag: %08x\n", oa->o_valid);
                RETURN(-EINVAL);
        }

        memcpy(oa, &obd->u.echo.oa, sizeof(*oa));
        oa->o_id = id;
        oa->o_valid |= OBD_MD_FLID;

        atomic_inc(&echo_getattrs);

        return 0;
}

static int echo_setattr(struct lustre_handle *conn, struct obdo *oa,
                        struct lov_stripe_md *md)
{
        struct obd_device *obd = class_conn2obd(conn);

        if (!obd) {
                CERROR("invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        if (!(oa->o_valid & OBD_MD_FLID)) {
                CERROR("obdo missing FLID valid flag: %08x\n", oa->o_valid);
                RETURN(-EINVAL);
        }

        memcpy(&obd->u.echo.oa, oa, sizeof(*oa));

        atomic_inc(&obd->u.echo.eo_setattr);

        return 0;
}

/* This allows us to verify that desc_private is passed unmolested */
#define DESC_PRIV 0x10293847

int echo_preprw(int cmd, struct lustre_handle *conn, int objcount,
                struct obd_ioobj *obj, int niocount, struct niobuf_remote *nb,
                struct niobuf_local *res, void **desc_private)
{
        struct obd_device *obd;
        struct niobuf_local *r = res;
        int rc = 0;
        int i;

        ENTRY;

        obd = class_conn2obd(conn);
        if (!obd) {
                CERROR("invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        memset(res, 0, sizeof(*res) * niocount);

        CDEBUG(D_PAGE, "%s %d obdos with %d IOs\n",
               cmd == OBD_BRW_READ ? "reading" : "writing", objcount, niocount);

        *desc_private = (void *)DESC_PRIV;

        obd_kmap_get(niocount, 1);

        for (i = 0; i < objcount; i++, obj++) {
                int gfp_mask = (obj->ioo_id & 1) ? GFP_HIGHUSER : GFP_KERNEL;
                int verify = obj->ioo_id != 0;
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, nb++, r++) {
                        r->page = alloc_pages(gfp_mask, 0);
                        if (!r->page) {
                                CERROR("can't get page %d/%d for id "LPU64"\n",
                                       j, obj->ioo_bufcnt, obj->ioo_id);
                                GOTO(preprw_cleanup, rc = -ENOMEM);
                        }
                        atomic_inc(&obd->u.echo.eo_prep);

                        r->offset = nb->offset;
                        r->addr = kmap(r->page);
                        r->len = nb->len;

                        CDEBUG(D_PAGE, "$$$$ get page %p, addr %p@"LPU64"\n",
                               r->page, r->addr, r->offset);

                        if (verify && cmd == OBD_BRW_READ)
                                page_debug_setup(r->addr, r->len, r->offset,
                                                 obj->ioo_id);
                        else if (verify)
                                page_debug_setup(r->addr, r->len,
                                                 0xecc0ecc0ecc0ecc0,
                                                 0xecc0ecc0ecc0ecc0);
                }
        }
        CDEBUG(D_PAGE, "%d pages allocated after prep\n",
               atomic_read(&obd->u.echo.eo_prep));

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
                atomic_dec(&obd->u.echo.eo_prep);
        }
        obd_kmap_put(niocount);
        memset(res, 0, sizeof(*res) * niocount);

        return rc;
}

int echo_commitrw(int cmd, struct lustre_handle *conn, int objcount,
                  struct obd_ioobj *obj, int niocount, struct niobuf_local *res,
                  void *desc_private)
{
        struct obd_device *obd;
        struct niobuf_local *r = res;
        int rc = 0;
        int i;
        ENTRY;

        obd = class_conn2obd(conn);
        if (!obd) {
                CERROR("invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        if ((cmd & OBD_BRW_RWMASK) == OBD_BRW_READ) {
                CDEBUG(D_PAGE, "reading %d obdos with %d IOs\n",
                       objcount, niocount);
        } else {
                CDEBUG(D_PAGE, "writing %d obdos with %d IOs\n",
                       objcount, niocount);
        }

        if (niocount && !r) {
                CERROR("NULL res niobuf with niocount %d\n", niocount);
                RETURN(-EINVAL);
        }

        LASSERT(desc_private == (void *)DESC_PRIV);

        for (i = 0; i < objcount; i++, obj++) {
                int verify = obj->ioo_id != 0;
                int j;

                for (j = 0 ; j < obj->ioo_bufcnt ; j++, r++) {
                        struct page *page = r->page;
                        void *addr;

                        if (!page || !(addr = page_address(page)) ||
                            !kern_addr_valid(addr)) {

                                CERROR("bad page objid "LPU64":%p, buf %d/%d\n",
                                       obj->ioo_id, page, j, obj->ioo_bufcnt);
                                GOTO(commitrw_cleanup, rc = -EFAULT);
                        }

                        atomic_inc(&echo_page_rws);

                        CDEBUG(D_PAGE, "$$$$ use page %p, addr %p@"LPU64"\n",
                               r->page, addr, r->offset);

                        if (verify)
                                page_debug_check("echo", addr, r->len,
                                                 r->offset, obj->ioo_id);

                        kunmap(page);
                        obd_kmap_put(1);
                        __free_pages(page, 0);
                        atomic_dec(&obd->u.echo.eo_prep);
                }
        }
        CDEBUG(D_PAGE, "%d pages remain after commit\n",
               atomic_read(&obd->u.echo.eo_prep));
        RETURN(0);

commitrw_cleanup:
        CERROR("cleaning up %ld pages (%d obdos)\n",
               niocount - (long)(r - res) - 1, objcount);
        while (++r < res + niocount) {
                struct page *page = r->page;

                kunmap(page);
                obd_kmap_put(1);
                __free_pages(page, 0);
                atomic_dec(&obd->u.echo.eo_prep);
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
        spin_lock_init(&obddev->u.echo.eo_lock);
        obddev->u.echo.eo_lastino = ECHO_INIT_OBJID;

        RETURN(0);
}

static int echo_cleanup(struct obd_device *obddev)
{
        ENTRY;

        ldlm_namespace_free(obddev->obd_namespace);
        CERROR("%d prep/commitrw pages leaked\n",
               atomic_read(&obddev->u.echo.eo_prep));

        RETURN(0);
}

int echo_attach(struct obd_device *dev, 
                   obd_count len, void *data)
{
        return lprocfs_reg_obd(dev, status_var_nm_1, dev);
}

int echo_detach(struct obd_device *dev)
{
        return lprocfs_dereg_obd(dev);
}


struct obd_ops echo_obd_ops = {
        o_attach:       echo_attach,
        o_detach:       echo_detach,
        o_connect:      echo_connect,
        o_disconnect:   echo_disconnect,
        o_create:       echo_create,
        o_destroy:      echo_destroy,
        o_open:         echo_open,
        o_close:        echo_close,
        o_getattr:      echo_getattr,
        o_setattr:      echo_setattr,
        o_preprw:       echo_preprw,
        o_commitrw:     echo_commitrw,
        o_setup:        echo_setup,
        o_cleanup:      echo_cleanup
};

static int __init obdecho_init(void)
{
        int rc;
        

        printk(KERN_INFO "Echo OBD driver " OBDECHO_VERSION
               " info@clusterfs.com\n");

        echo_proc_init();
        rc = class_register_type(&echo_obd_ops, status_class_var, 
                                 OBD_ECHO_DEVICENAME);
        RETURN(rc);
        

}

static void __exit obdecho_exit(void)
{
                
        echo_proc_fini();
        class_unregister_type(OBD_ECHO_DEVICENAME);
}

MODULE_AUTHOR("Cluster Filesystems Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Testing Echo OBD driver " OBDECHO_VERSION);
MODULE_LICENSE("GPL");

module_init(obdecho_init);
module_exit(obdecho_exit);
