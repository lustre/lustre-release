/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifdef __KERNEL__
#include <linux/kmod.h>   /* for request_module() */
#include <linux/module.h>
#else
#include <liblustre.h>
#endif
#include <linux/lustre_mds.h>
#include <linux/obd_ost.h>
#include <linux/obd_class.h>
#include <linux/lprocfs_status.h>

extern struct list_head obd_types;
static spinlock_t obd_types_lock = SPIN_LOCK_UNLOCKED;

kmem_cache_t *obdo_cachep = NULL;
EXPORT_SYMBOL(obdo_cachep);
kmem_cache_t *import_cachep = NULL;

int (*ptlrpc_put_connection_superhack)(struct ptlrpc_connection *c);
void (*ptlrpc_abort_inflight_superhack)(struct obd_import *imp);

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
                if (strcmp(type->typ_name, name) == 0) {
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
                try_module_get(type->typ_ops->o_owner);
        return type;
}

void class_put_type(struct obd_type *type)
{
        LASSERT(type);
        module_put(type->typ_ops->o_owner);
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

#ifdef LPROCFS
        type->typ_procroot = lprocfs_register(type->typ_name, proc_lustre_root,
                                              vars, type);
        if (IS_ERR(type->typ_procroot)) {
                rc = PTR_ERR(type->typ_procroot);
                type->typ_procroot = NULL;
                GOTO (failed, rc);
        }
#endif

        spin_lock(&obd_types_lock);
        list_add(&type->typ_chain, &obd_types);
        spin_unlock(&obd_types_lock);

        RETURN (0);

 failed:
        if (type->typ_name != NULL)
                OBD_FREE(type->typ_name, strlen(name) + 1);
        if (type->typ_ops != NULL)
                OBD_FREE (type->typ_ops, sizeof (*type->typ_ops));
        OBD_FREE(type, sizeof(*type));
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

struct obd_device *class_newdev(struct obd_type *type, char *name)
{
        struct obd_device *result = NULL;
        int i;

        spin_lock(&obd_dev_lock);
        for (i = 0 ; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_name && (strcmp(name, obd->obd_name) == 0)) {
                        CERROR("Device %s already exists, won't add\n", name);
                        if (result) {
                                result->obd_type = NULL;
                                result->obd_name = NULL;
                                result = NULL;
                        }
                        break;
                }
                if (!result && !obd->obd_type) {
                        LASSERT(obd->obd_minor == i);
                        memset(obd, 0, sizeof(*obd));
                        obd->obd_minor = i;
                        obd->obd_type = type;
                        obd->obd_name = name;
                        CDEBUG(D_IOCTL, "Adding new device %s\n",
                               obd->obd_name);
                        result = obd;
                }
        }
        spin_unlock(&obd_dev_lock);
        return result;
}

void class_release_dev(struct obd_device *obd)
{
        int minor = obd->obd_minor;

        spin_lock(&obd_dev_lock);
        memset(obd, 0x5a, sizeof(*obd));
        obd->obd_type = NULL;
        obd->obd_minor = minor;
        obd->obd_name = NULL;
        spin_unlock(&obd_dev_lock);
}

int class_name2dev(char *name)
{
        int i;

        if (!name)
                return -1;

        spin_lock(&obd_dev_lock);
        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_name && strcmp(name, obd->obd_name) == 0) {
                        /* Make sure we finished attaching before we give
                           out any references */
                        if (obd->obd_attached) {
                                spin_unlock(&obd_dev_lock);
                                return i;
                        }
                        break;
                }
        }
        spin_unlock(&obd_dev_lock);

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

        spin_lock(&obd_dev_lock);
        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd_uuid_equals(uuid, &obd->obd_uuid)) {
                        spin_unlock(&obd_dev_lock);
                        return i;
                }
        }
        spin_unlock(&obd_dev_lock);

        return -1;
}

struct obd_device *class_uuid2obd(struct obd_uuid *uuid)
{
        int dev = class_uuid2dev(uuid);
        if (dev < 0)
                return NULL;
        return &obd_dev[dev];
}

/* Search for a client OBD connected to tgt_uuid.  If grp_uuid is
   specified, then only the client with that uuid is returned,
   otherwise any client connected to the tgt is returned. */
struct obd_device * class_find_client_obd(struct obd_uuid *tgt_uuid,
                                          char * typ_name,
                                          struct obd_uuid *grp_uuid)
{
        int i;

        spin_lock(&obd_dev_lock);
        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_type == NULL)
                        continue;
                if ((strncmp(obd->obd_type->typ_name, typ_name,
                             strlen(typ_name)) == 0)) {
                        struct client_obd *cli = &obd->u.cli;
                        struct obd_import *imp = cli->cl_import;
                        if (obd_uuid_equals(tgt_uuid, &imp->imp_target_uuid) &&
                            ((grp_uuid)? obd_uuid_equals(grp_uuid,
                                                         &obd->obd_uuid) : 1)) {
                                spin_unlock(&obd_dev_lock);
                                return obd;
                        }
                }
        }
        spin_unlock(&obd_dev_lock);

        return NULL;
}

struct obd_device *class_find_client_notype(struct obd_uuid *tgt_uuid,
                                            struct obd_uuid *grp_uuid)
{
        struct obd_device *obd;

        obd = class_find_client_obd(tgt_uuid, LUSTRE_MDC_NAME, NULL);
        if (!obd)
                obd = class_find_client_obd(tgt_uuid, LUSTRE_OSC_NAME,
                                            grp_uuid);
        return obd;
}

/* Iterate the obd_device list looking devices have grp_uuid. Start
   searching at *next, and if a device is found, the next index to look
   at is saved in *next. If next is NULL, then the first matching device
   will always be returned. */
struct obd_device * class_devices_in_group(struct obd_uuid *grp_uuid, int *next)
{
        int i;

        if (next == NULL)
                i = 0;
        else if (*next >= 0 && *next < MAX_OBD_DEVICES)
                i = *next;
        else
                return NULL;

        spin_lock(&obd_dev_lock);
        for (; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_type == NULL)
                        continue;
                if (obd_uuid_equals(grp_uuid, &obd->obd_uuid)) {
                        if (next != NULL)
                                *next = i+1;
                        spin_unlock(&obd_dev_lock);
                        return obd;
                }
        }
        spin_unlock(&obd_dev_lock);

        return NULL;
}


void obd_cleanup_caches(void)
{
        ENTRY;
        if (obdo_cachep) {
                LASSERTF(kmem_cache_destroy(obdo_cachep) == 0,
                         "Cannot destory ll_obdo_cache\n");
                obdo_cachep = NULL;
        }
        if (import_cachep) {
                LASSERTF(kmem_cache_destroy(import_cachep) == 0,
                         "Cannot destory ll_import_cache\n");
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

        CDEBUG(D_INFO, "looking for export cookie "LPX64"\n", conn->cookie);
        export = class_handle2object(conn->cookie);
        RETURN(export);
}

struct obd_device *class_exp2obd(struct obd_export *exp)
{
        if (exp)
                return exp->exp_obd;
        return NULL;
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

struct obd_import *class_exp2cliimp(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        if (obd == NULL)
                return NULL;
        return obd->u.cli.cl_import;
}

struct obd_import *class_conn2cliimp(struct lustre_handle *conn)
{
        struct obd_device *obd = class_conn2obd(conn);
        if (obd == NULL)
                return NULL;
        return obd->u.cli.cl_import;
}

/* Export management functions */
static void export_handle_addref(void *export)
{
        class_export_get(export);
}

void __class_export_put(struct obd_export *exp)
{
        if (atomic_dec_and_test(&exp->exp_refcount)) {
                struct obd_device *obd = exp->exp_obd;
                CDEBUG(D_IOCTL, "destroying export %p/%s\n", exp,
                       exp->exp_client_uuid.uuid);

                LASSERT(obd != NULL);

                /* "Local" exports (lctl, LOV->{mdc,osc}) have no connection. */
                if (exp->exp_connection)
                        ptlrpc_put_connection_superhack(exp->exp_connection);

                LASSERT(list_empty(&exp->exp_outstanding_replies));
                LASSERT(list_empty(&exp->exp_handle.h_link));
                obd_destroy_export(exp);

                OBD_FREE(exp, sizeof(*exp));
                class_decref(obd);
        }
}
EXPORT_SYMBOL(__class_export_put);

/* Creates a new export, adds it to the hash table, and returns a
 * pointer to it. The refcount is 2: one for the hash reference, and
 * one for the pointer returned by this function. */
struct obd_export *class_new_export(struct obd_device *obd)
{
        struct obd_export *export;

        OBD_ALLOC(export, sizeof(*export));
        if (!export) {
                CERROR("no memory! (minor %d)\n", obd->obd_minor);
                return NULL;
        }

        export->exp_conn_cnt = 0;
        atomic_set(&export->exp_refcount, 2);
        export->exp_obd = obd;
        INIT_LIST_HEAD(&export->exp_outstanding_replies);
        /* XXX this should be in LDLM init */
        INIT_LIST_HEAD(&export->exp_ldlm_data.led_held_locks);

        INIT_LIST_HEAD(&export->exp_handle.h_link);
        class_handle_hash(&export->exp_handle, export_handle_addref);
        export->exp_last_request_time = CURRENT_SECONDS;
        spin_lock_init(&export->exp_lock);

        spin_lock(&obd->obd_dev_lock);
        LASSERT(!obd->obd_stopping); /* shouldn't happen, but might race */
        atomic_inc(&obd->obd_refcount);
        list_add(&export->exp_obd_chain, &export->exp_obd->obd_exports);
        list_add_tail(&export->exp_obd_chain_timed,
                      &export->exp_obd->obd_exports_timed);
        export->exp_obd->obd_num_exports++;
        spin_unlock(&obd->obd_dev_lock);

        obd_init_export(export);
        return export;
}
EXPORT_SYMBOL(class_new_export);

void class_unlink_export(struct obd_export *exp)
{
        class_handle_unhash(&exp->exp_handle);

        spin_lock(&exp->exp_obd->obd_dev_lock);
        list_del_init(&exp->exp_obd_chain);
        list_del_init(&exp->exp_obd_chain_timed);
        exp->exp_obd->obd_num_exports--;
        spin_unlock(&exp->exp_obd->obd_dev_lock);

        class_export_put(exp);
}
EXPORT_SYMBOL(class_unlink_export);

/* Import management functions */
static void import_handle_addref(void *import)
{
        class_import_get(import);
}

struct obd_import *class_import_get(struct obd_import *import)
{
        LASSERT(atomic_read(&import->imp_refcount) >= 0);
        LASSERT(atomic_read(&import->imp_refcount) < 0x5a5a5a);
        atomic_inc(&import->imp_refcount);
        CDEBUG(D_INFO, "import %p refcount=%d\n", import,
               atomic_read(&import->imp_refcount));
        return import;
}
EXPORT_SYMBOL(class_import_get);

void class_import_put(struct obd_import *import)
{
        ENTRY;

        CDEBUG(D_INFO, "import %p refcount=%d\n", import,
               atomic_read(&import->imp_refcount) - 1);

        LASSERT(atomic_read(&import->imp_refcount) > 0);
        LASSERT(atomic_read(&import->imp_refcount) < 0x5a5a5a);
        if (!atomic_dec_and_test(&import->imp_refcount)) {
                EXIT;
                return;
        }

        CDEBUG(D_IOCTL, "destroying import %p\n", import);

        ptlrpc_put_connection_superhack(import->imp_connection);

        while (!list_empty(&import->imp_conn_list)) {
                struct obd_import_conn *imp_conn;

                imp_conn = list_entry(import->imp_conn_list.next,
                                      struct obd_import_conn, oic_item);
                list_del(&imp_conn->oic_item);
                ptlrpc_put_connection_superhack(imp_conn->oic_conn);
                OBD_FREE(imp_conn, sizeof(*imp_conn));
        }

        LASSERT(list_empty(&import->imp_handle.h_link));
        OBD_FREE(import, sizeof(*import));
        EXIT;
}
EXPORT_SYMBOL(class_import_put);

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
        imp->imp_conn_cnt = 0;
        imp->imp_max_transno = 0;
        imp->imp_peer_committed_transno = 0;
        imp->imp_state = LUSTRE_IMP_NEW;
        init_waitqueue_head(&imp->imp_recovery_waitq);

        atomic_set(&imp->imp_refcount, 2);
        atomic_set(&imp->imp_inflight, 0);
        atomic_set(&imp->imp_replay_inflight, 0);
        INIT_LIST_HEAD(&imp->imp_conn_list);
        INIT_LIST_HEAD(&imp->imp_handle.h_link);
        class_handle_hash(&imp->imp_handle, import_handle_addref);

        return imp;
}
EXPORT_SYMBOL(class_new_import);

void class_destroy_import(struct obd_import *import)
{
        LASSERT(import != NULL);
        LASSERT(import != LP_POISON);

        class_handle_unhash(&import->imp_handle);

        /* Abort any inflight DLM requests and NULL out their (about to be
         * freed) import. */
        /* Invalidate all requests on import, would be better to call
           ptlrpc_set_import_active(imp, 0); */
        import->imp_generation++;
        ptlrpc_abort_inflight_superhack(import);

        class_import_put(import);
}
EXPORT_SYMBOL(class_destroy_import);

/* A connection defines an export context in which preallocation can
   be managed. This releases the export pointer reference, and returns
   the export handle, so the export refcount is 1 when this function
   returns. */
int class_connect(struct lustre_handle *conn, struct obd_device *obd,
                  struct obd_uuid *cluuid)
{
        struct obd_export *export;
        LASSERT(conn != NULL);
        LASSERT(obd != NULL);
        LASSERT(cluuid != NULL);
        ENTRY;

        export = class_new_export(obd);
        if (export == NULL)
                RETURN(-ENOMEM);

        conn->cookie = export->exp_handle.h_cookie;
        memcpy(&export->exp_client_uuid, cluuid,
               sizeof(export->exp_client_uuid));
        class_export_put(export);

        CDEBUG(D_IOCTL, "connect: client %s, cookie "LPX64"\n",
               cluuid->uuid, conn->cookie);
        RETURN(0);
}
EXPORT_SYMBOL(class_connect);

/* This function removes two references from the export: one for the
 * hash entry and one for the export pointer passed in.  The export
 * pointer passed to this function is destroyed should not be used
 * again. */
int class_disconnect(struct obd_export *export)
{
        int already_disconnected;
        ENTRY;

        if (export == NULL) {
                fixme();
                CDEBUG(D_IOCTL, "attempting to free NULL export %p\n", export);
                RETURN(-EINVAL);
        }

        spin_lock(&export->exp_lock);
        already_disconnected = export->exp_disconnected;
        export->exp_disconnected = 1;
        spin_unlock(&export->exp_lock);

        /* class_cleanup(), abort_recovery(), and class_fail_export()
         * all end up in here, and if any of them race we shouldn't
         * call extra class_export_puts(). */
        if (already_disconnected)
                RETURN(0);

        CDEBUG(D_IOCTL, "disconnect: cookie "LPX64"\n",
               export->exp_handle.h_cookie);

        class_unlink_export(export);
        class_export_put(export);
        RETURN(0);
}

static void class_disconnect_export_list(struct list_head *list, int flags)
{
        int rc;
        struct lustre_handle fake_conn;
        struct obd_export *fake_exp, *exp;
        ENTRY;

        /* It's possible that an export may disconnect itself, but
         * nothing else will be added to this list. */
        while(!list_empty(list)) {
                exp = list_entry(list->next, struct obd_export, exp_obd_chain);
                class_export_get(exp);
                exp->exp_flags = flags;

                if (obd_uuid_equals(&exp->exp_client_uuid,
                                    &exp->exp_obd->obd_uuid)) {
                        CDEBUG(D_HA,
                               "exp %p export uuid == obd uuid, don't discon\n",
                               exp);
                        /* Need to delete this now so we don't end up pointing
                         * to work_list later when this export is cleaned up. */
                        list_del_init(&exp->exp_obd_chain);
                        class_export_put(exp);
                        continue;
                }

                fake_conn.cookie = exp->exp_handle.h_cookie;
                fake_exp = class_conn2export(&fake_conn);
                if (!fake_exp) {
                        class_export_put(exp);
                        continue;
                }
                fake_exp->exp_flags = flags;
                rc = obd_disconnect(fake_exp);
                class_export_put(exp);
                if (rc) {
                        CDEBUG(D_HA, "disconnecting export %p failed: %d\n",
                               exp, rc);
                } else {
                        CDEBUG(D_HA, "export %p disconnected\n", exp);
                }
        }
        EXIT;
}

static inline int get_exp_flags_from_obd(struct obd_device *obd)
{
        return ((obd->obd_fail ? OBD_OPT_FAILOVER : 0) |
                (obd->obd_force ? OBD_OPT_FORCE : 0));
}

void class_disconnect_exports(struct obd_device *obd)
{
        struct list_head work_list;
        ENTRY;

        /* Move all of the exports from obd_exports to a work list, en masse. */
        spin_lock(&obd->obd_dev_lock);
        list_add(&work_list, &obd->obd_exports);
        list_del_init(&obd->obd_exports);
        spin_unlock(&obd->obd_dev_lock);

        CDEBUG(D_HA, "OBD device %d (%p) has exports, "
               "disconnecting them\n", obd->obd_minor, obd);
        class_disconnect_export_list(&work_list, get_exp_flags_from_obd(obd));
        EXIT;
}
EXPORT_SYMBOL(class_disconnect_exports);

/* Remove exports that have not completed recovery.
 */
void class_disconnect_stale_exports(struct obd_device *obd)
{
        struct list_head work_list;
        struct list_head *pos, *n;
        struct obd_export *exp;
        int cnt = 0;
        ENTRY;

        INIT_LIST_HEAD(&work_list);
        spin_lock(&obd->obd_dev_lock);
        list_for_each_safe(pos, n, &obd->obd_exports) {
                exp = list_entry(pos, struct obd_export, exp_obd_chain);
                if (exp->exp_replay_needed) {
                        list_del(&exp->exp_obd_chain);
                        list_add(&exp->exp_obd_chain, &work_list);
                        cnt++;
                }
        }
        spin_unlock(&obd->obd_dev_lock);

        CDEBUG(D_ERROR, "%s: disconnecting %d stale clients\n",
               obd->obd_name, cnt);
        class_disconnect_export_list(&work_list, get_exp_flags_from_obd(obd));
        EXIT;
}
EXPORT_SYMBOL(class_disconnect_stale_exports);

int oig_init(struct obd_io_group **oig_out)
{
        struct obd_io_group *oig;
        ENTRY;

        OBD_ALLOC(oig, sizeof(*oig));
        if (oig == NULL)
                RETURN(-ENOMEM);

        spin_lock_init(&oig->oig_lock);
        oig->oig_rc = 0;
        oig->oig_pending = 0;
        atomic_set(&oig->oig_refcount, 1);
        init_waitqueue_head(&oig->oig_waitq);
        INIT_LIST_HEAD(&oig->oig_occ_list);

        *oig_out = oig;
        RETURN(0);
};
EXPORT_SYMBOL(oig_init);

static inline void oig_grab(struct obd_io_group *oig)
{
        atomic_inc(&oig->oig_refcount);
}

void oig_release(struct obd_io_group *oig)
{
        if (atomic_dec_and_test(&oig->oig_refcount))
                OBD_FREE(oig, sizeof(*oig));
}
EXPORT_SYMBOL(oig_release);

void oig_add_one(struct obd_io_group *oig, struct oig_callback_context *occ)
{
        unsigned long flags;
        CDEBUG(D_CACHE, "oig %p ready to roll\n", oig);
        spin_lock_irqsave(&oig->oig_lock, flags);
        oig->oig_pending++;
        if (occ != NULL)
                list_add_tail(&occ->occ_oig_item, &oig->oig_occ_list);
        spin_unlock_irqrestore(&oig->oig_lock, flags);
        oig_grab(oig);
}
EXPORT_SYMBOL(oig_add_one);

void oig_complete_one(struct obd_io_group *oig,
                      struct oig_callback_context *occ, int rc)
{
        unsigned long flags;
        wait_queue_head_t *wake = NULL;
        int old_rc;

        spin_lock_irqsave(&oig->oig_lock, flags);

        if (occ != NULL)
                list_del_init(&occ->occ_oig_item);

        old_rc = oig->oig_rc;
        if (oig->oig_rc == 0 && rc != 0)
                oig->oig_rc = rc;

        if (--oig->oig_pending <= 0)
                wake = &oig->oig_waitq;

        spin_unlock_irqrestore(&oig->oig_lock, flags);

        CDEBUG(D_CACHE, "oig %p completed, rc %d -> %d via %d, %d now "
                        "pending (racey)\n", oig, old_rc, oig->oig_rc, rc,
                        oig->oig_pending);
        if (wake)
                wake_up(wake);
        oig_release(oig);
}
EXPORT_SYMBOL(oig_complete_one);

static int oig_done(struct obd_io_group *oig)
{
        unsigned long flags;
        int rc = 0;
        spin_lock_irqsave(&oig->oig_lock, flags);
        if (oig->oig_pending <= 0)
                rc = 1;
        spin_unlock_irqrestore(&oig->oig_lock, flags);
        return rc;
}

static void interrupted_oig(void *data)
{
        struct obd_io_group *oig = data;
        struct oig_callback_context *occ;
        unsigned long flags;

        spin_lock_irqsave(&oig->oig_lock, flags);
        /* We need to restart the processing each time we drop the lock, as
         * it is possible other threads called oig_complete_one() to remove
         * an entry elsewhere in the list while we dropped lock.  We need to
         * drop the lock because osc_ap_completion() calls oig_complete_one()
         * which re-gets this lock ;-) as well as a lock ordering issue. */
restart:
        list_for_each_entry(occ, &oig->oig_occ_list, occ_oig_item) {
                if (occ->interrupted)
                        continue;
                occ->interrupted = 1;
                spin_unlock_irqrestore(&oig->oig_lock, flags);
                occ->occ_interrupted(occ);
                spin_lock_irqsave(&oig->oig_lock, flags);
                goto restart;
        }
        spin_unlock_irqrestore(&oig->oig_lock, flags);
}

int oig_wait(struct obd_io_group *oig)
{
        struct l_wait_info lwi = LWI_INTR(interrupted_oig, oig);
        int rc;

        CDEBUG(D_CACHE, "waiting for oig %p\n", oig);

        do {
                rc = l_wait_event(oig->oig_waitq, oig_done(oig), &lwi);
                LASSERTF(rc == 0 || rc == -EINTR, "rc: %d\n", rc);
                /* we can't continue until the oig has emptied and stopped
                 * referencing state that the caller will free upon return */
                if (rc == -EINTR)
                        lwi = (struct l_wait_info){ 0, };
        } while (rc == -EINTR);

        LASSERTF(oig->oig_pending == 0,
                 "exiting oig_wait(oig = %p) with %d pending\n", oig,
                 oig->oig_pending);

        CDEBUG(D_CACHE, "done waiting on oig %p rc %d\n", oig, oig->oig_rc);
        return oig->oig_rc;
}
EXPORT_SYMBOL(oig_wait);

void class_fail_export(struct obd_export *exp)
{
        int rc, already_failed;
        unsigned long flags;

        spin_lock_irqsave(&exp->exp_lock, flags);
        already_failed = exp->exp_failed;
        exp->exp_failed = 1;
        spin_unlock_irqrestore(&exp->exp_lock, flags);

        if (already_failed) {
                CDEBUG(D_HA, "disconnecting dead export %p/%s; skipping\n",
                       exp, exp->exp_client_uuid.uuid);
                return;
        }

        CDEBUG(D_HA, "disconnecting export %p/%s\n",
               exp, exp->exp_client_uuid.uuid);

        if (obd_dump_on_timeout)
                libcfs_debug_dumplog();

        /* Most callers into obd_disconnect are removing their own reference
         * (request, for example) in addition to the one from the hash table.
         * We don't have such a reference here, so make one. */
        class_export_get(exp);
        rc = obd_disconnect(exp);
        if (rc)
                CERROR("disconnecting export %p failed: %d\n", exp, rc);
        else
                CDEBUG(D_HA, "disconnected export %p/%s\n",
                       exp, exp->exp_client_uuid.uuid);
}
EXPORT_SYMBOL(class_fail_export);

char *obd_export_nid2str(struct obd_export *exp)
{
        if (exp->exp_connection != NULL)
                return libcfs_nid2str(exp->exp_connection->c_peer.nid);
        
        return "(no nid)";
}
EXPORT_SYMBOL(obd_export_nid2str);

/* Ping evictor thread */
#ifdef __KERNEL__
#define PET_READY     1
#define PET_TERMINATE 2

static int               pet_refcount = 0;
static int               pet_state;
static wait_queue_head_t pet_waitq;
static struct obd_export *pet_exp = NULL;
static spinlock_t        pet_lock = SPIN_LOCK_UNLOCKED;

static int ping_evictor_wake(struct obd_export *exp)
{
        spin_lock(&pet_lock);
        if (pet_exp) {
                /* eventually the new obd will call here again. */
                spin_unlock(&pet_lock);
                return 1;
        }

        /* We have to make sure the obd isn't destroyed between now and when
         * the ping evictor runs.  We'll take a reference here, and drop it
         * when we finish in the evictor.  We don't really care about this
         * export in particular; we just need one to keep the obd alive. */
        pet_exp = class_export_get(exp);
        spin_unlock(&pet_lock);

        wake_up(&pet_waitq);
        return 0;
}

static int ping_evictor_main(void *arg)
{
        struct obd_device *obd;
        struct obd_export *exp;
        struct l_wait_info lwi = { 0 };
        time_t expire_time;
        unsigned long flags;
        ENTRY;

        lock_kernel();

        /* ptlrpc_daemonize() */
        exit_mm(current);
        lustre_daemonize_helper();
        set_fs_pwd(current->fs, init_task.fs->pwdmnt, init_task.fs->pwd);
        exit_files(current);
        reparent_to_init();
        THREAD_NAME(current->comm, sizeof(current->comm), "ping_evictor");

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
        unlock_kernel();

        CDEBUG(D_HA, "Starting Ping Evictor\n");
        pet_exp = NULL;
        pet_state = PET_READY;
        while (1) {
                l_wait_event(pet_waitq, pet_exp ||
                             (pet_state == PET_TERMINATE), &lwi);
                if (pet_state == PET_TERMINATE)
                        break;

                /* we only get here if pet_exp != NULL, and the end of this
                 * loop is the only place which sets it NULL again, so lock
                 * is not strictly necessary. */
                spin_lock(&pet_lock);
                obd = pet_exp->exp_obd;
                spin_unlock(&pet_lock);

                expire_time = CURRENT_SECONDS - (3 * obd_timeout / 2);

                CDEBUG(D_HA, "evicting all exports of obd %s older than %ld\n",
                       obd->obd_name, expire_time);

                /* Exports can't be deleted out of the list while we hold
                 * the obd lock (class_unlink_export), which means we can't
                 * lose the last ref on the export.  If they've already been
                 * removed from the list, we won't find them here. */
                spin_lock(&obd->obd_dev_lock);
                while (!list_empty(&obd->obd_exports_timed)) {
                        exp = list_entry(obd->obd_exports_timed.next,
                                         struct obd_export,exp_obd_chain_timed);

                        if (expire_time > exp->exp_last_request_time) {
                                class_export_get(exp);
                                spin_unlock(&obd->obd_dev_lock);
                                LCONSOLE_WARN("%s: haven't heard from %s in %ld"
                                              " seconds. Last request was at %ld. "
                                              "I think it's dead, and I am evicting "
                                              "it.\n", obd->obd_name,
                                              obd_export_nid2str(exp),
                                              (long)(CURRENT_SECONDS -
                                                     exp->exp_last_request_time),
                                              exp->exp_last_request_time);


                                class_fail_export(exp);
                                class_export_put(exp);

                                spin_lock(&obd->obd_dev_lock);
                        } else {
                                /* List is sorted, so everyone below is ok */
                                break;
                        }
                }
                spin_unlock(&obd->obd_dev_lock);

                class_export_put(pet_exp);

                spin_lock(&pet_lock);
                pet_exp = NULL;
                spin_unlock(&pet_lock);
        }
        CDEBUG(D_HA, "Exiting Ping Evictor\n");

        RETURN(0);
}

void ping_evictor_start(void)
{
        int rc;

        if (++pet_refcount > 1)
                return;

        init_waitqueue_head(&pet_waitq);

        rc = kernel_thread(ping_evictor_main, NULL, CLONE_VM | CLONE_FS);
        if (rc < 0) {
                pet_refcount--;
                CERROR("Cannot start ping evictor thread: %d\n", rc);
        }
}
EXPORT_SYMBOL(ping_evictor_start);

void ping_evictor_stop(void)
{
        if (--pet_refcount > 0)
                return;

        pet_state = PET_TERMINATE;
        wake_up(&pet_waitq);
}
EXPORT_SYMBOL(ping_evictor_stop);
#else /* !__KERNEL__ */
#define ping_evictor_wake(exp)     1
#endif

/* This function makes sure dead exports are evicted in a timely manner.
   This function is only called when some export receives a message (i.e.,
   the network is up.) */
void class_update_export_timer(struct obd_export *exp, time_t extra_delay)
{
        struct obd_export *oldest_exp;
        time_t oldest_time;

        ENTRY;

        LASSERT(exp);

        /* Compensate for slow machines, etc, by faking our request time
           into the future.  Although this can break the strict time-ordering
           of the list, we can be really lazy here - we don't have to evict
           at the exact right moment.  Eventually, all silent exports
           will make it to the top of the list. */
        exp->exp_last_request_time = max(exp->exp_last_request_time,
                                         (time_t)CURRENT_SECONDS + extra_delay);

        CDEBUG(D_INFO, "updating export %s at %ld\n",
               exp->exp_client_uuid.uuid,
               exp->exp_last_request_time);

        /* exports may get disconnected from the chain even though the
           export has references, so we must keep the spin lock while
           manipulating the lists */
        spin_lock(&exp->exp_obd->obd_dev_lock);

        if (list_empty(&exp->exp_obd_chain_timed)) {
                /* this one is not timed */
                spin_unlock(&exp->exp_obd->obd_dev_lock);
                EXIT;
                return;
        }

        list_move_tail(&exp->exp_obd_chain_timed,
                       &exp->exp_obd->obd_exports_timed);

        oldest_exp = list_entry(exp->exp_obd->obd_exports_timed.next,
                                struct obd_export, exp_obd_chain_timed);
        oldest_time = oldest_exp->exp_last_request_time;
        spin_unlock(&exp->exp_obd->obd_dev_lock);

        if (exp->exp_obd->obd_recovering) {
                /* be nice to everyone during recovery */
                EXIT;
                return;
        }

        /* Note - racing to start/reset the obd_eviction timer is safe */
        if (exp->exp_obd->obd_eviction_timer == 0) {
                /* Check if the oldest entry is expired. */
                if (CURRENT_SECONDS > (oldest_time +
                                       (3 * obd_timeout / 2) + extra_delay)) {
                        /* We need a second timer, in case the net was down and
                         * it just came back. Since the pinger may skip every
                         * other PING_INTERVAL (see note in ptlrpc_pinger_main),
                         * we better wait for 3. */
                        exp->exp_obd->obd_eviction_timer = CURRENT_SECONDS +
                                3 * PING_INTERVAL;
                        CDEBUG(D_HA, "%s: Think about evicting %s from %ld\n",
                               exp->exp_obd->obd_name, obd_export_nid2str(exp),
                               oldest_time);
                }
        } else {
                if (CURRENT_SECONDS > (exp->exp_obd->obd_eviction_timer +
                                       extra_delay)) {
                        /* The evictor won't evict anyone who we've heard from
                         * recently, so we don't have to check before we start
                         * it. */
                        if (!ping_evictor_wake(exp))
                                exp->exp_obd->obd_eviction_timer = 0;
                }
        }

        EXIT;
}
EXPORT_SYMBOL(class_update_export_timer);

#define EVICT_BATCH 32
int obd_export_evict_by_nid(struct obd_device *obd, char *nid)
{
        struct obd_export *doomed_exp[EVICT_BATCH] = { NULL };
        struct list_head *p;
        int exports_evicted = 0, num_to_evict = 0, i;

search_again:
        spin_lock(&obd->obd_dev_lock);
        list_for_each(p, &obd->obd_exports) {
                doomed_exp[num_to_evict] = list_entry(p, struct obd_export,
                                                      exp_obd_chain);
                if (strcmp(obd_export_nid2str(doomed_exp[num_to_evict]),
                           nid) == 0) {
                        class_export_get(doomed_exp[num_to_evict]);
                        if (++num_to_evict == EVICT_BATCH)
                                break;
                }
        }
        spin_unlock(&obd->obd_dev_lock);

        for (i = 0; i < num_to_evict; i++) {
                exports_evicted++;
                CWARN("%s: evict NID '%s' (%s) #%d at adminstrative request\n",
                       obd->obd_name, nid, doomed_exp[i]->exp_client_uuid.uuid,
                       exports_evicted);
                class_fail_export(doomed_exp[i]);
                class_export_put(doomed_exp[i]);
        }
        if (num_to_evict == EVICT_BATCH) {
                num_to_evict = 0;
                goto search_again;
        }

        if (!exports_evicted)
                CDEBUG(D_HA,"%s: can't disconnect NID '%s': no exports found\n",
                       obd->obd_name, nid);
        return exports_evicted;
}
EXPORT_SYMBOL(obd_export_evict_by_nid);

int obd_export_evict_by_uuid(struct obd_device *obd, char *uuid)
{
        struct obd_export *doomed_exp = NULL;
        struct list_head *p;
        struct obd_uuid doomed;
        int exports_evicted = 0;

        obd_str2uuid(&doomed, uuid);

        spin_lock(&obd->obd_dev_lock);
        list_for_each(p, &obd->obd_exports) {
                doomed_exp = list_entry(p, struct obd_export, exp_obd_chain);

                if (obd_uuid_equals(&doomed, &doomed_exp->exp_client_uuid)) {
                        class_export_get(doomed_exp);
                        break;
                }
                doomed_exp = NULL;
        }
        spin_unlock(&obd->obd_dev_lock);

        if (doomed_exp == NULL) {
                CERROR("%s: can't disconnect %s: no exports found\n",
                       obd->obd_name, uuid);
        } else {
                CWARN("%s: evicting %s at adminstrative request\n",
                       obd->obd_name, doomed_exp->exp_client_uuid.uuid);
                class_fail_export(doomed_exp);
                class_export_put(doomed_exp);
                exports_evicted++;
        }

        return exports_evicted;
}
EXPORT_SYMBOL(obd_export_evict_by_uuid);
