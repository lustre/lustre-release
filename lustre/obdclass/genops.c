/*
 *  linux/fs/ext2_obd/sim_obd.c
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * These are the only exported functions; they provide the simulated object-
 * oriented disk.
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_class.h>
#include <linux/random.h>
#include <linux/slab.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];
kmem_cache_t *obdo_cachep = NULL;
kmem_cache_t *export_cachep = NULL;
kmem_cache_t *import_cachep = NULL;

void obd_cleanup_caches(void)
{
        int rc;
        ENTRY;
        if (obdo_cachep) { 
                rc = kmem_cache_destroy(obdo_cachep);
                if (rc)
                        CERROR("Cannot destory obdo_cachep\n");
                obdo_cachep = NULL;
        }
        if (import_cachep) { 
                rc = kmem_cache_destroy(import_cachep);
                if (rc)
                        CERROR("Cannot destory import_cachep\n");
                import_cachep = NULL;
        }
        if (export_cachep) { 
                rc = kmem_cache_destroy(export_cachep);
                if (rc)
                        CERROR("Cannot destory import_cachep\n");
                export_cachep = NULL;
        }
        EXIT;
}

int obd_init_caches(void)
{
        ENTRY;
        if (obdo_cachep == NULL) {
                obdo_cachep = kmem_cache_create("obdo_cache",
                                                sizeof(struct obdo),
                                                0, SLAB_HWCACHE_ALIGN,
                                                NULL, NULL);
                if (obdo_cachep == NULL)
                        GOTO(out, -ENOMEM);
        }

        if (export_cachep == NULL) {
                export_cachep = kmem_cache_create("export_cache",
                                                sizeof(struct obd_export),
                                                0, SLAB_HWCACHE_ALIGN,
                                                NULL, NULL);
                if (export_cachep == NULL)
                        GOTO(out, -ENOMEM);
        }

        if (import_cachep == NULL) {
                import_cachep = kmem_cache_create("import_cache",
                                                sizeof(struct obd_import),
                                                0, SLAB_HWCACHE_ALIGN,
                                                NULL, NULL);
                if (import_cachep == NULL)
                        GOTO(out, -ENOMEM);
        }
        RETURN(0);
 out:
        obd_cleanup_caches();
        RETURN(-ENOMEM);

}


/* map connection to client */
struct obd_export *gen_client(struct obd_conn *conn)
{
        struct obd_export * export;

        if (!conn)
                RETURN(NULL);

        if (!conn->addr || conn->addr == -1 ) { 
                fixme();
                RETURN(NULL);
        }
              
        export = (struct obd_export *) (unsigned long)conn->addr;
        if (!kmem_cache_validate(export_cachep, (void *)export))
                RETURN(NULL);

        if (export->export_cookie != conn->cookie)
                return NULL;
        return export;
} /* gen_client */

struct obd_device *gen_conn2obd(struct obd_conn *conn)
{
        struct obd_export *export;
        export = gen_client(conn); 
        if (export) 
                return export->export_obd;
        fixme();
        return NULL;
}

/* a connection defines a context in which preallocation can be managed. */
int gen_connect (struct obd_conn *conn, struct obd_device *obd)
{
        struct obd_export * export;

        export = kmem_cache_alloc(export_cachep, GFP_KERNEL); 
        if ( !export ) {
                CERROR("no memory! (minor %d)\n", obd->obd_minor);
                return -ENOMEM;
        }

        memset(export, 0, sizeof(*export));
        get_random_bytes(&export->export_cookie, sizeof(__u64));
        /* XXX this should probably spinlocked? */
        export->export_id = ++obd->obd_gen_last_id;
        export->export_obd = obd; 
        export->export_import.addr = conn->addr;
        export->export_import.cookie = conn->cookie;
        
        list_add(&(export->export_chain), export->export_obd->obd_exports.prev);

        CDEBUG(D_INFO, "connect: new ID %u\n", export->export_id);
        conn->oc_id = export->export_id;
        conn->addr = (__u64) (unsigned long)export;
        conn->cookie = export->export_cookie;
        return 0;
} /* gen_connect */


int gen_disconnect(struct obd_conn *conn)
{
        struct obd_export * export;
        ENTRY;

        if (!(export = gen_client(conn))) {
                fixme();
                CDEBUG(D_IOCTL, "disconnect: attempting to free "
                       "nonexistent client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }
        list_del(&export->export_chain);
        kmem_cache_free(export_cachep, export);

        CDEBUG(D_INFO, "disconnect: ID %u\n", conn->oc_id);

        RETURN(0);
} /* gen_obd_disconnect */

/* FIXME: Data is a space- or comma-separated list of device IDs.  This will
 * have to change. */
int gen_multi_setup(struct obd_device *obddev, uint32_t len, void *data)
{
        int count, rc;
        char *p;
        ENTRY;

        for (p = data, count = 0; p < (char *)data + len; count++) {
                char *end;
                int tmp = simple_strtoul(p, &end, 0);

                if (p == end) {
                        CERROR("invalid device ID starting at: %s\n", p);
                        GOTO(err_disconnect, rc = -EINVAL);
                }
                
                if (tmp < 0 || tmp >= MAX_OBD_DEVICES) { 
                        CERROR("Trying to sub dev %d  - dev no too large\n", 
                               tmp);
                        GOTO(err_disconnect, rc); 
                }

                rc = obd_connect(&obddev->obd_multi_conn[count], &obd_dev[tmp]);
                if (rc) {
                        CERROR("cannot connect to device %d: rc = %d\n", tmp,
                               rc);
                        GOTO(err_disconnect, rc);
                }

                CDEBUG(D_INFO, "target OBD %d is of type %s\n", count,
                       obd_dev[tmp].obd_type->typ_name);

                p = end + 1;
        }

        obddev->obd_multi_count = count;

        RETURN(0);

 err_disconnect:
        for (count--; count >= 0; count--)
                obd_disconnect(&obddev->obd_multi_conn[count]);
        return rc;
}

/*
 *    remove all connections to this device
 *    close all connections to lower devices
 *    needed for forced unloads of OBD client drivers
 */
int gen_multi_cleanup(struct obd_device *obddev)
{
        int i;

        for (i = 0; i < obddev->obd_multi_count; i++) {
                int rc;
                struct obd_device *obd = gen_conn2obd(&obddev->obd_multi_conn[i]);

                if (!obd) { 
                        CERROR("no such device [i %d]\n", i); 
                        RETURN(-EINVAL);
                }

                rc = obd_disconnect(&obddev->obd_multi_conn[i]);
                if (rc)
                        CERROR("disconnect failure %d\n", obd->obd_minor);
        }
        return 0;
}


/*
 *    forced cleanup of the device:
 *    - remove connections from the device
 *    - cleanup the device afterwards
 */
int gen_cleanup(struct obd_device * obddev)
{
        struct list_head * lh, * tmp;
        struct obd_export * export;

        ENTRY;

        lh = tmp = &obddev->obd_exports;
        while ((tmp = tmp->next) != lh) {
                export = list_entry(tmp, struct obd_export, export_chain);
                CDEBUG(D_INFO, "Disconnecting obd_connection %d, at %p\n",
                       export->export_id, export);
        }
        return 0;
} /* sim_cleanup_device */

void lck_page(struct page *page)
{
        while (TryLockPage(page))
                ___wait_on_page(page);
}

int gen_copy_data(struct obd_conn *dst_conn, struct obdo *dst,
                  struct obd_conn *src_conn, struct obdo *src,
                  obd_size count, obd_off offset)
{
        struct page *page;
        unsigned long index = 0;
        int err = 0;

        ENTRY;
        CDEBUG(D_INFO, "src: ino %Ld blocks %Ld, size %Ld, dst: ino %Ld\n",
               (unsigned long long)src->o_id, (unsigned long long)src->o_blocks,
               (unsigned long long)src->o_size, (unsigned long long)dst->o_id);
        page = alloc_page(GFP_USER);
        if (page == NULL)
                RETURN(-ENOMEM);

        lck_page(page);

        /* XXX with brw vector I/O, we could batch up reads and writes here,
         *     all we need to do is allocate multiple pages to handle the I/Os
         *     and arrays to handle the request parameters.
         */
        while (index < ((src->o_size + PAGE_SIZE - 1) >> PAGE_SHIFT)) {
                obd_count        num_oa = 1;
                obd_count        num_buf = 1;
                obd_size         brw_count = PAGE_SIZE;
                obd_off          brw_offset = (page->index) << PAGE_SHIFT;
                obd_flag         flagr = 0;
                obd_flag         flagw = OBD_BRW_CREATE;

                page->index = index;
                err = obd_brw(OBD_BRW_READ, src_conn, num_oa, &src, &num_buf,
			      &page, &brw_count, &brw_offset, &flagr, NULL);

                if ( err ) {
                        EXIT;
                        break;
                }
                CDEBUG(D_INFO, "Read page %ld ...\n", page->index);

                err = obd_brw(OBD_BRW_WRITE, dst_conn, num_oa, &dst, &num_buf,
			      &page, &brw_count, &brw_offset, &flagw, NULL);

                /* XXX should handle dst->o_size, dst->o_blocks here */
                if ( err ) {
                        EXIT;
                        break;
                }

                CDEBUG(D_INFO, "Wrote page %ld ...\n", page->index);

                index++;
        }
        dst->o_size = src->o_size;
        dst->o_blocks = src->o_blocks;
        dst->o_valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);
        UnlockPage(page);
        __free_page(page);

        RETURN(err);
}
