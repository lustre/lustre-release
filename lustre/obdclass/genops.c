/*
 *  linux/fs/ext2_obd/sim_obd.c
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS
#include <linux/module.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#include <linux/slab.h>

extern struct list_head obd_types; 
extern struct obd_device obd_dev[MAX_OBD_DEVICES];
kmem_cache_t *obdo_cachep = NULL;
kmem_cache_t *export_cachep = NULL;
kmem_cache_t *import_cachep = NULL;

/*
 * support functions: we could use inter-module communication, but this
 * is more portable to other OS's
 */
static struct obd_type *class_search_type(char *nm)
{
        struct list_head *tmp;
        struct obd_type *type;
        CDEBUG(D_INFO, "SEARCH %s\n", nm);

        tmp = &obd_types;
        while ( (tmp = tmp->next) != &obd_types ) {
                type = list_entry(tmp, struct obd_type, typ_chain);
                CDEBUG(D_INFO, "TYP %s\n", type->typ_name);
                if (strlen(type->typ_name) == strlen(nm) &&
                    strcmp(type->typ_name, nm) == 0 ) {
                        return type;
                }
        }
        return NULL;
}

struct obd_type *class_nm_to_type(char *nm)
{
        struct obd_type *type = class_search_type(nm);

#ifdef CONFIG_KMOD
        if ( !type ) {
                if ( !request_module(nm) ) {
                        CDEBUG(D_INFO, "Loaded module '%s'\n", nm);
                        type = class_search_type(nm);
                } else {
                        CDEBUG(D_INFO, "Can't load module '%s'\n", nm);
                }
        }
#endif
        return type;
}

int class_register_type(struct obd_ops *ops, char *nm)
{
        struct obd_type *type;

        ENTRY;

        if (class_nm_to_type(nm)) {
                CDEBUG(D_IOCTL, "Type %s already registered\n", nm);
                RETURN(-EEXIST);
        }

        OBD_ALLOC(type, sizeof(*type));
        if (!type)
                RETURN(-ENOMEM);
        INIT_LIST_HEAD(&type->typ_chain);
        MOD_INC_USE_COUNT;
        list_add(&type->typ_chain, obd_types.next);
        type->typ_ops = ops;
        type->typ_name = nm;
        RETURN(0);
}

int class_unregister_type(char *nm)
{
        struct obd_type *type = class_nm_to_type(nm);

        ENTRY;

        if ( !type ) {
                MOD_DEC_USE_COUNT;
                CERROR("unknown obd type\n");
                RETURN(-EINVAL);
        }

        if ( type->typ_refcnt ) {
                MOD_DEC_USE_COUNT;
                CERROR("type %s has refcount (%d)\n", nm, type->typ_refcnt);
                RETURN(-EBUSY);
        }

        list_del(&type->typ_chain);
        OBD_FREE(type, sizeof(*type));
        MOD_DEC_USE_COUNT;
        RETURN(0);
} /* class_unregister_type */

int class_name2dev(char *name)
{
        int res = -1;
        int i;

        for (i=0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_name && strcmp(name, obd->obd_name) == 0) {
                        res = i;
                        return res;
                }
        }

        return res;
}

int class_uuid2dev(char *name)
{
        int res = -1;
        int i;

        for (i=0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_name && strncmp(name, obd->obd_uuid, 37) == 0) {
                        res = i;
                        return res;
                }
        }

        return res;
}

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
struct obd_export *class_conn2export(struct lustre_handle *conn)
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
} /* class_conn2export */

struct obd_device *class_conn2obd(struct lustre_handle *conn)
{
        struct obd_export *export;
        export = class_conn2export(conn); 
        if (export) 
                return export->export_obd;
        fixme();
        return NULL;
}

/* a connection defines an export context in which preallocation can
   be managed. */
int class_connect (struct lustre_handle *conn, struct obd_device *obd)
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
        conn->addr = (__u64) (unsigned long)export;
        conn->cookie = export->export_cookie;
        return 0;
} /* class_connect */

int class_disconnect(struct lustre_handle *conn)
{
        struct obd_export * export;
        ENTRY;

        if (!(export = class_conn2export(conn))) {
                fixme();
                CDEBUG(D_IOCTL, "disconnect: attempting to free "
                       "nonexistent client %Lx\n", conn->addr);
                RETURN(-EINVAL);
        }
        list_del(&export->export_chain);
        kmem_cache_free(export_cachep, export);

        RETURN(0);
} /* gen_obd_disconnect */

/* FIXME: Data is a space- or comma-separated list of device IDs.  This will
 * have to change. */
int class_multi_setup(struct obd_device *obddev, uint32_t len, void *data)
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
                        GOTO(err_disconnect, rc  = -EINVAL); 
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
int class_multi_cleanup(struct obd_device *obddev)
{
        int i;

        for (i = 0; i < obddev->obd_multi_count; i++) {
                int rc;
                struct obd_device *obd = class_conn2obd(&obddev->obd_multi_conn[i]);

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

