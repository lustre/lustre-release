/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifdef __KERNEL__
#include <linux/kmod.h>   /* for request_module() */
#include <linux/module.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#include <linux/slab.h>
#else 
#include <liblustre.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#endif
#include <linux/lprocfs_status.h>

extern struct list_head obd_types;
static spinlock_t obd_types_lock = SPIN_LOCK_UNLOCKED;
kmem_cache_t *obdo_cachep = NULL;
kmem_cache_t *import_cachep = NULL;

int (*ptlrpc_put_connection_superhack)(struct ptlrpc_connection *c);
void (*ptlrpc_abort_inflight_superhack)(struct obd_import *imp);

struct obd_uuid lctl_fake_uuid = { .uuid = "OBD_CLASS_UUID" };

/*
 * support functions: we could use inter-module communication, but this
 * is more portable to other OS's
 */
static struct obd_type *class_search_type(char *name)
{
        struct list_head *tmp;
        struct obd_type *type;

        spin_lock(&obd_types_lock);
        list_for_each(tmp, &obd_types) {
                type = list_entry(tmp, struct obd_type, typ_chain);
                if (strlen(type->typ_name) == strlen(name) &&
                    strcmp(type->typ_name, name) == 0) {
                        spin_unlock(&obd_types_lock);
                        return type;
                }
        }
        spin_unlock(&obd_types_lock);
        return NULL;
}

struct obd_type *class_get_type(char *name)
{
        struct obd_type *type = class_search_type(name);

#ifdef CONFIG_KMOD
        if (!type) {
                if (!request_module(name)) {
                        CDEBUG(D_INFO, "Loaded module '%s'\n", name);
                        type = class_search_type(name);
                } else
                        CDEBUG(D_INFO, "Can't load module '%s'\n", name);
        }
#endif
        if (type)
                __MOD_INC_USE_COUNT(type->typ_ops->o_owner);
        return type;
}

void class_put_type(struct obd_type *type)
{
        LASSERT(type);
        __MOD_DEC_USE_COUNT(type->typ_ops->o_owner);
}

int class_register_type(struct obd_ops *ops, struct lprocfs_vars *vars,
                        char *name)
{
        struct obd_type *type;
        int rc = 0;
        ENTRY;

        LASSERT(strnlen(name, 1024) < 1024);    /* sanity check */

        if (class_search_type(name)) {
                CDEBUG(D_IOCTL, "Type %s already registered\n", name);
                RETURN(-EEXIST);
        }

        rc = -ENOMEM;
        OBD_ALLOC(type, sizeof(*type));
        if (type == NULL)
                RETURN(rc);

        OBD_ALLOC(type->typ_ops, sizeof(*type->typ_ops));
        OBD_ALLOC(type->typ_name, strlen(name) + 1);
        if (type->typ_ops == NULL || type->typ_name == NULL)
                GOTO (failed, rc);

        *(type->typ_ops) = *ops;
        strcpy(type->typ_name, name);

        type->typ_procroot = lprocfs_register(type->typ_name, proc_lustre_root,
                                              vars, type);
        if (IS_ERR(type->typ_procroot)) {
                rc = PTR_ERR(type->typ_procroot);
                type->typ_procroot = NULL;
                GOTO (failed, rc);
        }

        spin_lock(&obd_types_lock);
        list_add(&type->typ_chain, &obd_types);
        spin_unlock(&obd_types_lock);

        RETURN (0);

 failed:
        if (type->typ_ops != NULL)
                OBD_FREE(type->typ_name, strlen(name) + 1);
        if (type->typ_ops != NULL)
                OBD_FREE (type->typ_ops, sizeof (*type->typ_ops));
        RETURN(rc);
}

int class_unregister_type(char *name)
{
        struct obd_type *type = class_search_type(name);
        ENTRY;

        if (!type) {
                CERROR("unknown obd type\n");
                RETURN(-EINVAL);
        }

        if (type->typ_refcnt) {
                CERROR("type %s has refcount (%d)\n", name, type->typ_refcnt);
                /* This is a bad situation, let's make the best of it */
                /* Remove ops, but leave the name for debugging */
                OBD_FREE(type->typ_ops, sizeof(*type->typ_ops));
                RETURN(-EBUSY);
        }

        if (type->typ_procroot) {
                lprocfs_remove(type->typ_procroot);
                type->typ_procroot = NULL;
        }

        spin_lock(&obd_types_lock);
        list_del(&type->typ_chain);
        spin_unlock(&obd_types_lock);
        OBD_FREE(type->typ_name, strlen(name) + 1);
        if (type->typ_ops != NULL)
                OBD_FREE(type->typ_ops, sizeof(*type->typ_ops));
        OBD_FREE(type, sizeof(*type));
        RETURN(0);
} /* class_unregister_type */

int class_name2dev(char *name)
{
        int i;

        if (!name)
                return -1;

        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_name && strcmp(name, obd->obd_name) == 0)
                        return i;
        }

        return -1;
}

struct obd_device *class_name2obd(char *name)
{
        int dev = class_name2dev(name);
        if (dev < 0)
                return NULL;
        return &obd_dev[dev];
}

int class_uuid2dev(struct obd_uuid *uuid)
{
        int i;

        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd_uuid_equals(uuid, &obd->obd_uuid))
                        return i;
        }

        return -1;
}

struct obd_device *class_uuid2obd(struct obd_uuid *uuid)
{
        int dev = class_uuid2dev(uuid);
        if (dev < 0)
                return NULL;
        return &obd_dev[dev];
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
        ENTRY;

        if (!conn) {
                CDEBUG(D_CACHE, "looking for null handle\n");
                RETURN(NULL);
        }

        if (conn->cookie == -1) {  /* this means assign a new connection */
                CDEBUG(D_CACHE, "want a new connection\n");
                RETURN(NULL);
        }

        CDEBUG(D_IOCTL, "looking for export cookie "LPX64"\n", conn->cookie);
        export = class_handle2object(conn->cookie);
        RETURN(export);
}

struct obd_device *class_conn2obd(struct lustre_handle *conn)
{
        struct obd_export *export;
        export = class_conn2export(conn);
        if (export) {
                struct obd_device *obd = export->exp_obd;
                class_export_put(export);
                return obd;
        }
        return NULL;
}

struct obd_import *class_conn2cliimp(struct lustre_handle *conn)
{
        return class_conn2obd(conn)->u.cli.cl_import;
}

struct obd_import *class_conn2ldlmimp(struct lustre_handle *conn)
{
        struct obd_export *export;
        export = class_conn2export(conn);
        if (export) {
                struct obd_import *imp = export->exp_ldlm_data.led_import;
                class_export_put(export);
                return imp;
        }
        fixme();
        return NULL;
}

/* Export management functions */
static void export_handle_addref(void *export)
{
        class_export_get(export);
}

struct obd_export *class_export_get(struct obd_export *exp)
{
        atomic_inc(&exp->exp_refcount);
        CDEBUG(D_INFO, "GETting export %p : new refcount %d\n", exp,
               atomic_read(&exp->exp_refcount));
        return exp;
}

void class_export_put(struct obd_export *exp)
{
        ENTRY;

        LASSERT(exp);
        CDEBUG(D_INFO, "PUTting export %p : new refcount %d\n", exp,
               atomic_read(&exp->exp_refcount) - 1);
        LASSERT(atomic_read(&exp->exp_refcount) > 0);
        LASSERT(atomic_read(&exp->exp_refcount) < 0x5a5a5a);
        if (atomic_dec_and_test(&exp->exp_refcount)) {
                struct obd_device *obd = exp->exp_obd;
                CDEBUG(D_IOCTL, "destroying export %p/%s\n", exp,
                       exp->exp_client_uuid.uuid);

                LASSERT(obd != NULL);

                /* "Local" exports (lctl, LOV->{mdc,osc}) have no connection. */
                if (exp->exp_connection)
                        ptlrpc_put_connection_superhack(exp->exp_connection);

                LASSERT(list_empty(&exp->exp_handle.h_link));

                obd_destroy_export(exp);

                OBD_FREE(exp, sizeof(*exp));
                atomic_dec(&obd->obd_refcount);
                wake_up(&obd->obd_refcount_waitq);
        }
        EXIT;
}

struct obd_export *class_new_export(struct obd_device *obddev)
{
        struct obd_export *export;

        OBD_ALLOC(export, sizeof(*export));
        if (!export) {
                CERROR("no memory! (minor %d)\n", obddev->obd_minor);
                return NULL;
        }

        atomic_set(&export->exp_refcount, 2);
        export->exp_obd = obddev;
        /* XXX this should be in LDLM init */
        INIT_LIST_HEAD(&export->exp_ldlm_data.led_held_locks);

        INIT_LIST_HEAD(&export->exp_handle.h_link);
        class_handle_hash(&export->exp_handle, export_handle_addref);
        spin_lock_init(&export->exp_lock);

        spin_lock(&obddev->obd_dev_lock);
        LASSERT(!obddev->obd_stopping); /* shouldn't happen, but might race */
        atomic_inc(&obddev->obd_refcount);
        list_add(&export->exp_obd_chain, &export->exp_obd->obd_exports);
        export->exp_obd->obd_num_exports++;
        spin_unlock(&obddev->obd_dev_lock);
        return export;
}

void class_unlink_export(struct obd_export *exp)
{
        class_handle_unhash(&exp->exp_handle);

        spin_lock(&exp->exp_obd->obd_dev_lock);
        list_del_init(&exp->exp_obd_chain);
        exp->exp_obd->obd_num_exports--;
        spin_unlock(&exp->exp_obd->obd_dev_lock);

        class_export_put(exp);
}

/* Import management functions */
static void import_handle_addref(void *import)
{
        class_import_get(import);
}

struct obd_import *class_import_get(struct obd_import *import)
{
        atomic_inc(&import->imp_refcount);
        CDEBUG(D_IOCTL, "import %p refcount=%d\n", import,
               atomic_read(&import->imp_refcount));
        return import;
}

void class_import_put(struct obd_import *import)
{
        ENTRY;

        CDEBUG(D_IOCTL, "import %p refcount=%d\n", import,
               atomic_read(&import->imp_refcount) - 1);

        LASSERT(atomic_read(&import->imp_refcount) > 0);
        LASSERT(atomic_read(&import->imp_refcount) < 0x5a5a5a);
        if (!atomic_dec_and_test(&import->imp_refcount)) {
                EXIT;
                return;
        }

        CDEBUG(D_IOCTL, "destroying import %p\n", import);

        ptlrpc_put_connection_superhack(import->imp_connection);

        LASSERT(list_empty(&import->imp_handle.h_link));
        OBD_FREE(import, sizeof(*import));
        EXIT;
}

struct obd_import *class_new_import(void)
{
        struct obd_import *imp;

        OBD_ALLOC(imp, sizeof(*imp));
        if (imp == NULL)
                return NULL;

        INIT_LIST_HEAD(&imp->imp_replay_list);
        INIT_LIST_HEAD(&imp->imp_sending_list);
        INIT_LIST_HEAD(&imp->imp_delayed_list);
        spin_lock_init(&imp->imp_lock);
        imp->imp_max_transno = 0;
        imp->imp_peer_committed_transno = 0;

        atomic_set(&imp->imp_refcount, 2);
        INIT_LIST_HEAD(&imp->imp_handle.h_link);
        class_handle_hash(&imp->imp_handle, import_handle_addref);

        return imp;
}

void class_destroy_import(struct obd_import *import)
{
        LASSERT(import != NULL);

        class_handle_unhash(&import->imp_handle);

        /* Abort any inflight DLM requests and NULL out their (about to be
         * freed) import. */
        /* Invalidate all requests on import, would be better to call
           ptlrpc_set_import_active(imp, 0); */
        import->imp_generation++;
        ptlrpc_abort_inflight_superhack(import);

        class_import_put(import);
}

/* a connection defines an export context in which preallocation can
   be managed. */
int class_connect(struct lustre_handle *exporth, struct obd_device *obd,
                  struct obd_uuid *cluuid)
{
        struct obd_export *export;
        LASSERT(exporth != NULL);
        LASSERT(obd != NULL);
        LASSERT(cluuid != NULL);

        export = class_new_export(obd);
        if (export == NULL)
                return -ENOMEM;

        exporth->cookie = export->exp_handle.h_cookie;
        memcpy(&export->exp_client_uuid, cluuid,
               sizeof(export->exp_client_uuid));
        class_export_put(export);

        CDEBUG(D_IOCTL, "connect: client %s, cookie "LPX64"\n",
               cluuid->uuid, exporth->cookie);
        return 0;
}

int class_disconnect(struct lustre_handle *conn, int failover)
{
        struct obd_export *export = class_conn2export(conn);
        ENTRY;

        if (export == NULL) {
                fixme();
                CDEBUG(D_IOCTL, "disconnect: attempting to free "
                       "nonexistent client "LPX64"\n", conn->cookie);
                RETURN(-EINVAL);
        }

        CDEBUG(D_IOCTL, "disconnect: cookie "LPX64"\n", conn->cookie);

        class_unlink_export(export);
        class_export_put(export);
        RETURN(0);
}

void class_disconnect_exports(struct obd_device *obd, int failover)
{
        int rc;
        struct list_head *tmp, *n, work_list;
        struct lustre_handle fake_conn;
        ENTRY;

        /* Move all of the exports from obd_exports to a work list, en masse. */
        spin_lock(&obd->obd_dev_lock);
        list_add(&work_list, &obd->obd_exports);
        list_del_init(&obd->obd_exports);
        spin_unlock(&obd->obd_dev_lock);

        CDEBUG(D_IOCTL, "OBD device %d (%p) has exports, "
               "disconnecting them\n", obd->obd_minor, obd);
        list_for_each_safe(tmp, n, &work_list) {
                struct obd_export *exp = list_entry(tmp, struct obd_export,
                                                    exp_obd_chain);

                class_export_get(exp);
                fake_conn.cookie = exp->exp_handle.h_cookie;
                rc = obd_disconnect(&fake_conn, failover);
                /* exports created from last_rcvd data, and "fake"
                   exports created by lctl don't have an import */
                if (exp->exp_ldlm_data.led_import != NULL)
                        class_destroy_import(exp->exp_ldlm_data.led_import);
                class_export_put(exp);

                if (rc) {
                        CDEBUG(D_IOCTL, "disconnecting export %p failed: %d\n",
                               exp, rc);
                } else {
                        CDEBUG(D_IOCTL, "export %p disconnected\n", exp);
                }
        }
        EXIT;
}
