/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lustre/obdclass/genops.c
 * Copyright (C) 2001-2002  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS
#include <linux/kmod.h>   /* for request_module() */
#include <linux/module.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/lprocfs_status.h>

extern struct list_head obd_types;
kmem_cache_t *obdo_cachep = NULL;
kmem_cache_t *import_cachep = NULL;
kmem_cache_t *export_cachep = NULL;

int (*ptlrpc_put_connection_superhack)(struct ptlrpc_connection *c);

/* I would prefer if these next four functions were in ptlrpc, to be honest,
 * but obdclass uses them for the netregression ioctls. -phil */
static int sync_io_timeout(void *data)
{
        struct io_cb_data *cbd = data;
        struct ptlrpc_bulk_desc *desc;
        ENTRY;

        LASSERT(cbd);
        desc = cbd->desc;

        if (!desc) {
                CERROR("no desc for timed-out BRW, reopen Bugzilla 214!\n");
                RETURN(0); /* back to sleep -- someone had better wake us up! */
        }

        LASSERT(desc->bd_connection);

        CERROR("IO of %d pages to/from %s:%d (conn %p) timed out\n",
               desc->bd_page_count, desc->bd_connection->c_remote_uuid,
               desc->bd_portal, desc->bd_connection);
        desc->bd_connection->c_level = LUSTRE_CONN_RECOVD;
        desc->bd_flags |= PTL_RPC_FL_TIMEOUT;
        if (desc->bd_connection && class_signal_connection_failure) {
                class_signal_connection_failure(desc->bd_connection);

                /* We go back to sleep, until we're resumed or interrupted. */
                RETURN(0);
        }

        /* If we can't be recovered, just abort the syscall with -ETIMEDOUT. */
        RETURN(1);
}

static int sync_io_intr(void *data)
{
        struct io_cb_data *cbd = data;
        struct ptlrpc_bulk_desc *desc = cbd->desc;

        ENTRY;
        desc->bd_flags |= PTL_RPC_FL_INTR;
        RETURN(1); /* ignored, as of this writing */
}

int ll_sync_io_cb(struct io_cb_data *data, int err, int phase)
{
        int ret;
        ENTRY;

        if (phase == CB_PHASE_START) {
                struct l_wait_info lwi;
                lwi = LWI_TIMEOUT_INTR(obd_timeout * HZ, sync_io_timeout,
                                       sync_io_intr, data);
                ret = l_wait_event(data->waitq, data->complete, &lwi);
                if (atomic_dec_and_test(&data->refcount))
                        OBD_FREE(data, sizeof(*data));
                if (ret == -EINTR)
                        RETURN(ret);
        } else if (phase == CB_PHASE_FINISH) {
                data->err = err;
                data->complete = 1;
                wake_up(&data->waitq);
                if (atomic_dec_and_test(&data->refcount))
                        OBD_FREE(data, sizeof(*data));
                RETURN(err);
        } else                
                LBUG();
        EXIT;
        return 0;
}

struct io_cb_data *ll_init_cb(void)
{
        struct io_cb_data *d;

        OBD_ALLOC(d, sizeof(*d));
        if (d) {
                init_waitqueue_head(&d->waitq);
                atomic_set(&d->refcount, 2);
        }
        RETURN(d);
}

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
        list_for_each(tmp, &obd_types) {
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

int class_register_type(struct obd_ops *ops, struct lprocfs_vars* vars, char *nm)
{
        struct obd_type *type;
        int rc;

        ENTRY;

        if (class_search_type(nm)) {
                CDEBUG(D_IOCTL, "Type %s already registered\n", nm);
                RETURN(-EEXIST);
        }

        OBD_ALLOC(type, sizeof(*type));
        OBD_ALLOC(type->typ_ops, sizeof(*type->typ_ops));
        OBD_ALLOC(type->typ_name, strlen(nm) + 1);
        if (!type)
                RETURN(-ENOMEM);
        INIT_LIST_HEAD(&type->typ_chain);
        CDEBUG(D_INFO, "MOD_INC_USE for register_type: count = %d\n",
               atomic_read(&(THIS_MODULE)->uc.usecount));
        MOD_INC_USE_COUNT;
        list_add(&type->typ_chain, &obd_types);
        memcpy(type->typ_ops, ops, sizeof(*type->typ_ops));
        strcpy(type->typ_name, nm);
        rc = lprocfs_reg_class(type, (struct lprocfs_vars*)vars, (void*)type);
        if(rc)
                RETURN(rc);
        
        RETURN(0);
}

int class_unregister_type(char *nm)
{
        struct obd_type *type = class_nm_to_type(nm);

        ENTRY;

        if (!type) {
                CERROR("unknown obd type\n");
                RETURN(-EINVAL);
        }

        if (type->typ_refcnt) {
                CERROR("type %s has refcount (%d)\n", nm, type->typ_refcnt);
                /* This is a bad situation, let's make the best of it */
                /* Remove ops, but leave the name for debugging */
                OBD_FREE(type->typ_ops, sizeof(*type->typ_ops));
                RETURN(-EBUSY);
        }
        if(type->typ_procroot)
                lprocfs_dereg_class(type);

        list_del(&type->typ_chain);
        OBD_FREE(type->typ_name, strlen(nm) + 1);
        if (type->typ_ops != NULL)
                OBD_FREE(type->typ_ops, sizeof(*type->typ_ops));
        OBD_FREE(type, sizeof(*type));
        CDEBUG(D_INFO, "MOD_DEC_USE for register_type: count = %d\n",
               atomic_read(&(THIS_MODULE)->uc.usecount) - 1);
        MOD_DEC_USE_COUNT;
        RETURN(0);
} /* class_unregister_type */

int class_name2dev(char *name)
{
        int res = -1;
        int i;

        if (!name)
                return -1;

        for (i=0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_name && strcmp(name, obd->obd_name) == 0) {
                        res = i;
                        return res;
                }
        }

        return res;
}

int class_uuid2dev(char *uuid)
{
        int res = -1;
        int i;

        for (i=0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (strncmp(uuid, obd->obd_uuid, sizeof(obd->obd_uuid)) == 0) {
                        res = i;
                        return res;
                }
        }

        return res;
}


struct obd_device *class_uuid2obd(char *uuid)
{
        int i;

        for (i=0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (strncmp(uuid, obd->obd_uuid, sizeof(obd->obd_uuid)) == 0)
                        return obd;
        }

        return NULL;
}

void obd_cleanup_caches(void)
{
        int rc;
        ENTRY;
        if (obdo_cachep) {
                rc = kmem_cache_destroy(obdo_cachep);
                if (rc)
                        CERROR("Cannot destory ll_obdo_cache\n");
                obdo_cachep = NULL;
        }
        if (import_cachep) {
                rc = kmem_cache_destroy(import_cachep);
                if (rc)
                        CERROR("Cannot destory ll_import_cache\n");
                import_cachep = NULL;
        }
        if (export_cachep) {
                rc = kmem_cache_destroy(export_cachep);
                if (rc)
                        CERROR("Cannot destory ll_export_cache\n");
                export_cachep = NULL;
        }
        EXIT;
}

int obd_init_caches(void)
{
        ENTRY;
        LASSERT(obdo_cachep == NULL);
        obdo_cachep = kmem_cache_create("ll_obdo_cache", sizeof(struct obdo),
                                        0, 0, NULL, NULL);
        if (!obdo_cachep)
                GOTO(out, -ENOMEM);

        LASSERT(export_cachep == NULL);
        export_cachep = kmem_cache_create("ll_export_cache",
                                          sizeof(struct obd_export),
                                          0, 0, NULL, NULL);
        if (!export_cachep)
                GOTO(out, -ENOMEM);

        LASSERT(import_cachep == NULL);
        import_cachep = kmem_cache_create("ll_import_cache",
                                          sizeof(struct obd_import),
                                          0, 0, NULL, NULL);
        if (!import_cachep)
                GOTO(out, -ENOMEM);

        RETURN(0);
 out:
        obd_cleanup_caches();
        RETURN(-ENOMEM);

}

/* map connection to client */
struct obd_export *class_conn2export(struct lustre_handle *conn)
{
        struct obd_export *export;

        if (!conn) {
                CDEBUG(D_CACHE, "looking for null handle\n");
                RETURN(NULL);
        }

        if (conn->addr == -1) {  /* this means assign a new connection */
                CDEBUG(D_CACHE, "want a new connection\n");
                RETURN(NULL);
        }

        if (!conn->addr) {
                CDEBUG(D_CACHE, "looking for null addr\n");
                fixme();
                RETURN(NULL);
        }

        CDEBUG(D_IOCTL, "looking for export addr "LPX64" cookie "LPX64"\n",
               conn->addr, conn->cookie);
        export = (struct obd_export *) (unsigned long)conn->addr;
        if (!kmem_cache_validate(export_cachep, (void *)export))
                RETURN(NULL);

        if (export->exp_cookie != conn->cookie)
                RETURN(NULL);
        RETURN(export);
} /* class_conn2export */

struct obd_device *class_conn2obd(struct lustre_handle *conn)
{
        struct obd_export *export;
        export = class_conn2export(conn);
        if (export)
                return export->exp_obd;
        fixme();
        return NULL;
}

struct obd_import *class_conn2cliimp(struct lustre_handle *conn)
{
        return &class_conn2obd(conn)->u.cli.cl_import;
}

struct obd_import *class_conn2ldlmimp(struct lustre_handle *conn)
{
        return &class_conn2export(conn)->exp_ldlm_data.led_import;
}

struct obd_export *class_new_export(struct obd_device *obddev)
{
        struct obd_export * export;

        export = kmem_cache_alloc(export_cachep, GFP_KERNEL);
        if (!export) {
                CERROR("no memory! (minor %d)\n", obddev->obd_minor);
                return NULL;
        }

        memset(export, 0, sizeof(*export));
        get_random_bytes(&export->exp_cookie, sizeof(export->exp_cookie));
        export->exp_obd = obddev;
        /* XXX this should be in LDLM init */
        INIT_LIST_HEAD(&export->exp_ldlm_data.led_held_locks);
        INIT_LIST_HEAD(&export->exp_conn_chain);
        spin_lock(&obddev->obd_dev_lock);
        list_add(&export->exp_obd_chain, &export->exp_obd->obd_exports);
        spin_unlock(&obddev->obd_dev_lock);
        return export;
}

void class_destroy_export(struct obd_export *exp)
{
        ENTRY;

        LASSERT(exp->exp_cookie != DEAD_HANDLE_MAGIC);

        spin_lock(&exp->exp_obd->obd_dev_lock);
        list_del(&exp->exp_obd_chain);
        spin_unlock(&exp->exp_obd->obd_dev_lock);

        /* XXXshaver no connection here... */
        if (exp->exp_connection)
                spin_lock(&exp->exp_connection->c_lock);
        list_del(&exp->exp_conn_chain);
        if (exp->exp_connection) {
                spin_unlock(&exp->exp_connection->c_lock);
                ptlrpc_put_connection_superhack(exp->exp_connection);
        }

        exp->exp_cookie = DEAD_HANDLE_MAGIC;
        kmem_cache_free(export_cachep, exp);

        EXIT;
}

/* a connection defines an export context in which preallocation can
   be managed. */
int class_connect(struct lustre_handle *conn, struct obd_device *obd,
                  obd_uuid_t cluuid)
{
        struct obd_export * export;
        if (conn == NULL) {
                LBUG();
                return -EINVAL;
        }

        if (obd == NULL) {
                LBUG();
                return -EINVAL;
        }

        export = class_new_export(obd);
        if (!export)
                return -ENOMEM;

        conn->addr = (__u64) (unsigned long)export;
        conn->cookie = export->exp_cookie;

        CDEBUG(D_IOCTL, "connect: addr %Lx cookie %Lx\n",
               (long long)conn->addr, (long long)conn->cookie);
        return 0;
}

int class_disconnect(struct lustre_handle *conn)
{
        struct obd_export *export;
        ENTRY;

        if (!(export = class_conn2export(conn))) {
                fixme();
                CDEBUG(D_IOCTL, "disconnect: attempting to free "
                       "nonexistent client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        CDEBUG(D_IOCTL, "disconnect: addr %Lx cookie %Lx\n",
                       (long long)conn->addr, (long long)conn->cookie);

        class_destroy_export(export);

        RETURN(0);
}

void class_disconnect_all(struct obd_device *obddev)
{
        int again = 1;

        while (again) {
                spin_lock(&obddev->obd_dev_lock);
                if (!list_empty(&obddev->obd_exports)) {
                        struct obd_export *export;
                        struct lustre_handle conn;
                        int rc;

                        export = list_entry(obddev->obd_exports.next,
                                            struct obd_export,
                                            exp_obd_chain);
                        conn.addr = (__u64)(unsigned long)export;
                        conn.cookie = export->exp_cookie;
                        spin_unlock(&obddev->obd_dev_lock);
                        CERROR("force disconnecting export %p\n", export);
                        rc = obd_disconnect(&conn);
                        if (rc < 0) {
                                /* AED: not so sure about this...  We can't
                                 * loop here forever, yet we shouldn't leak
                                 * exports on a struct we will soon destroy.
                                 */
                                CERROR("destroy export %p with err: rc = %d\n",
                                       export, rc);
                                class_destroy_export(export);
                        }
                } else {
                        spin_unlock(&obddev->obd_dev_lock);
                        again = 0;
                }
        }
}

#if 0

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
                struct obd_device *obd =
                        class_conn2obd(&obddev->obd_multi_conn[i]);

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
#endif
