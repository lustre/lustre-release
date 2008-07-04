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
#ifndef __KERNEL__
#include <liblustre.h>
#endif
#include <obd_ost.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <class_hash.h>

extern struct list_head obd_types;
spinlock_t obd_types_lock;

cfs_mem_cache_t *obd_device_cachep;
cfs_mem_cache_t *obdo_cachep;
EXPORT_SYMBOL(obdo_cachep);
cfs_mem_cache_t *import_cachep;

struct list_head  obd_zombie_imports;
struct list_head  obd_zombie_exports;
spinlock_t        obd_zombie_impexp_lock;
void            (*obd_zombie_impexp_notify)(void) = NULL;
EXPORT_SYMBOL(obd_zombie_impexp_notify);


int (*ptlrpc_put_connection_superhack)(struct ptlrpc_connection *c);

/*
 * support functions: we could use inter-module communication, but this
 * is more portable to other OS's
 */
static struct obd_device *obd_device_alloc(void)
{
        struct obd_device *obd;

        OBD_SLAB_ALLOC_PTR(obd, obd_device_cachep);
        if (obd != NULL) {
                obd->obd_magic = OBD_DEVICE_MAGIC;
        }
        return obd;
}
EXPORT_SYMBOL(obd_device_alloc);

static void obd_device_free(struct obd_device *obd)
{
        LASSERT(obd != NULL);
        LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC, "obd %p obd_magic %08x != %08x\n", 
                 obd, obd->obd_magic, OBD_DEVICE_MAGIC);
        OBD_SLAB_FREE_PTR(obd, obd_device_cachep);
}
EXPORT_SYMBOL(obd_device_free);

struct obd_type *class_search_type(const char *name)
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

struct obd_type *class_get_type(const char *name)
{
        struct obd_type *type = class_search_type(name);

#ifdef CONFIG_KMOD
        if (!type) {
                const char *modname = name;
                if (strcmp(modname, LUSTRE_MDT_NAME) == 0) 
                        modname = LUSTRE_MDS_NAME;
                if (!request_module(modname)) {
                        CDEBUG(D_INFO, "Loaded module '%s'\n", modname);
                        type = class_search_type(name);
                } else {
                        LCONSOLE_ERROR_MSG(0x158, "Can't load module '%s'\n",
                                           modname);
                }
        }
#endif
        if (type) {
                spin_lock(&type->obd_type_lock);
                type->typ_refcnt++;
                try_module_get(type->typ_ops->o_owner);
                spin_unlock(&type->obd_type_lock);
        }
        return type;
}

void class_put_type(struct obd_type *type)
{
        LASSERT(type);
        spin_lock(&type->obd_type_lock);
        type->typ_refcnt--;
        module_put(type->typ_ops->o_owner);
        spin_unlock(&type->obd_type_lock);
}

int class_register_type(struct obd_ops *ops, struct lprocfs_vars *vars,
                        const char *name)
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
        spin_lock_init(&type->obd_type_lock);

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

int class_unregister_type(const char *name)
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

        if (type->typ_procroot) 
                lprocfs_remove(&type->typ_procroot);

        spin_lock(&obd_types_lock);
        list_del(&type->typ_chain);
        spin_unlock(&obd_types_lock);
        OBD_FREE(type->typ_name, strlen(name) + 1);
        if (type->typ_ops != NULL)
                OBD_FREE(type->typ_ops, sizeof(*type->typ_ops));
        OBD_FREE(type, sizeof(*type));
        RETURN(0);
} /* class_unregister_type */

struct obd_device *class_newdev(const char *type_name, const char *name)
{
        struct obd_device *result = NULL;
        struct obd_device *newdev;
        struct obd_type *type = NULL;
        int i;
        int new_obd_minor = 0;

        if (strlen(name) > MAX_OBD_NAME) {
                CERROR("name/uuid must be < %u bytes long\n", MAX_OBD_NAME);
                RETURN(ERR_PTR(-EINVAL));
        }

        type = class_get_type(type_name);
        if (type == NULL){
                CERROR("OBD: unknown type: %s\n", type_name);
                RETURN(ERR_PTR(-ENODEV));
        }

        newdev = obd_device_alloc();
        if (newdev == NULL) { 
                class_put_type(type);
                RETURN(ERR_PTR(-ENOMEM));
        }
        LASSERT(newdev->obd_magic == OBD_DEVICE_MAGIC);

        spin_lock(&obd_dev_lock);
        for (i = 0; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);
                if (obd && obd->obd_name && (strcmp(name, obd->obd_name) == 0)){
                        CERROR("Device %s already exists, won't add\n", name);
                        if (result) {
                                LASSERTF(result->obd_magic == OBD_DEVICE_MAGIC,
                                         "%p obd_magic %08x != %08x\n", result,
                                         result->obd_magic, OBD_DEVICE_MAGIC);
                                LASSERTF(result->obd_minor == new_obd_minor,
                                         "%p obd_minor %d != %d\n", result,
                                         result->obd_minor, new_obd_minor);

                                obd_devs[result->obd_minor] = NULL;
                                result->obd_name[0]='\0';
                        }
                        result = ERR_PTR(-EEXIST);
                        break;
                }
                if (!result && !obd) {
                        result = newdev;
                        result->obd_minor = i;
                        new_obd_minor = i;
                        result->obd_type = type;
                        memcpy(result->obd_name, name, strlen(name));
                        obd_devs[i] = result;
                }
        }
        spin_unlock(&obd_dev_lock);
        
        if (result == NULL && i >= class_devno_max()) {
                CERROR("all %u OBD devices used, increase MAX_OBD_DEVICES\n",
                       class_devno_max());
                result = ERR_PTR(-EOVERFLOW);
        }
        
        if (IS_ERR(result)) {
                obd_device_free(newdev);
                class_put_type(type);
        } else {
                CDEBUG(D_IOCTL, "Adding new device %s (%p)\n",
                       result->obd_name, result);
        }
        return result;
}

void class_release_dev(struct obd_device *obd)
{
        struct obd_type *obd_type = obd->obd_type;

        LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC, "%p obd_magic %08x != %08x\n",
                 obd, obd->obd_magic, OBD_DEVICE_MAGIC);
        LASSERTF(obd == obd_devs[obd->obd_minor], "obd %p != obd_devs[%d] %p\n",
                 obd, obd->obd_minor, obd_devs[obd->obd_minor]);
        LASSERT(obd_type != NULL);

        CDEBUG(D_INFO, "Release obd device %s obd_type name =%s\n",
               obd->obd_name,obd->obd_type->typ_name);

        spin_lock(&obd_dev_lock);
        obd_devs[obd->obd_minor] = NULL;
        spin_unlock(&obd_dev_lock);
        obd_device_free(obd);

        class_put_type(obd_type);
}

int class_name2dev(const char *name)
{
        int i;

        if (!name)
                return -1;

        spin_lock(&obd_dev_lock);
        for (i = 0; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);
                if (obd && obd->obd_name && strcmp(name, obd->obd_name) == 0) {
                        /* Make sure we finished attaching before we give
                           out any references */
                        LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
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

struct obd_device *class_name2obd(const char *name)
{
        int dev = class_name2dev(name);

        if (dev < 0 || dev > class_devno_max())
                return NULL;
        return class_num2obd(dev);
}

int class_uuid2dev(struct obd_uuid *uuid)
{
        int i;

        spin_lock(&obd_dev_lock);
        for (i = 0; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);
                if (obd && obd_uuid_equals(uuid, &obd->obd_uuid)) {
                        LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
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
        return class_num2obd(dev);
}

struct obd_device *class_num2obd(int num)
{
        struct obd_device *obd = NULL;

        if (num < class_devno_max()) {
                obd = obd_devs[num];
                if (obd == NULL) {
                        return NULL;
                }

                LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC,
                         "%p obd_magic %08x != %08x\n",
                         obd, obd->obd_magic, OBD_DEVICE_MAGIC);
                LASSERTF(obd->obd_minor == num,
                         "%p obd_minor %0d != %0d\n",
                         obd, obd->obd_minor, num);
        }

        return obd;
}

void class_obd_list(void)
{
        char *status;
        int i;

        spin_lock(&obd_dev_lock);
        for (i = 0; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);
                if (obd == NULL)
                        continue;
                if (obd->obd_stopping)
                        status = "ST";
                else if (obd->obd_set_up)
                        status = "UP";
                else if (obd->obd_attached)
                        status = "AT";
                else
                        status = "--";
                LCONSOLE(D_CONFIG, "%3d %s %s %s %s %d\n",
                         i, status, obd->obd_type->typ_name,
                         obd->obd_name, obd->obd_uuid.uuid,
                         atomic_read(&obd->obd_refcount));
        }
        spin_unlock(&obd_dev_lock);
        return;
}

/* Search for a client OBD connected to tgt_uuid.  If grp_uuid is
   specified, then only the client with that uuid is returned,
   otherwise any client connected to the tgt is returned. */
struct obd_device * class_find_client_obd(struct obd_uuid *tgt_uuid,
                                          const char * typ_name,
                                          struct obd_uuid *grp_uuid)
{
        int i;

        spin_lock(&obd_dev_lock);
        for (i = 0; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);
                if (obd == NULL)
                        continue;
                if ((strncmp(obd->obd_type->typ_name, typ_name,
                             strlen(typ_name)) == 0)) {
                        if (obd_uuid_equals(tgt_uuid,
                                            &obd->u.cli.cl_target_uuid) &&
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
        else if (*next >= 0 && *next < class_devno_max())
                i = *next;
        else
                return NULL;

        spin_lock(&obd_dev_lock);
        for (; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);
                if (obd == NULL)
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
        int rc;

        ENTRY;
        if (obd_device_cachep) {
                rc = cfs_mem_cache_destroy(obd_device_cachep);
                LASSERTF(rc == 0, "Cannot destropy ll_obd_device_cache: rc %d\n", rc);
                obd_device_cachep = NULL;
        }
        if (obdo_cachep) {
                rc = cfs_mem_cache_destroy(obdo_cachep);
                LASSERTF(rc == 0, "Cannot destory ll_obdo_cache\n");
                obdo_cachep = NULL;
        }
        if (import_cachep) {
                rc = cfs_mem_cache_destroy(import_cachep);
                LASSERTF(rc == 0, "Cannot destory ll_import_cache\n");
                import_cachep = NULL;
        }
        EXIT;
}

int obd_init_caches(void)
{
        ENTRY;

        LASSERT(obd_device_cachep == NULL);
        obd_device_cachep = cfs_mem_cache_create("ll_obd_dev_cache",
                                                 sizeof(struct obd_device), 
                                                 0, 0);
        if (!obd_device_cachep)
                GOTO(out, -ENOMEM);

        LASSERT(obdo_cachep == NULL);
        obdo_cachep = cfs_mem_cache_create("ll_obdo_cache", sizeof(struct obdo),
                                           0, 0);
        if (!obdo_cachep)
                GOTO(out, -ENOMEM);

        LASSERT(import_cachep == NULL);
        import_cachep = cfs_mem_cache_create("ll_import_cache",
                                             sizeof(struct obd_import),
                                             0, 0);
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
                LASSERT (list_empty(&exp->exp_obd_chain));

                CDEBUG(D_IOCTL, "final put %p/%s\n",
                       exp, exp->exp_client_uuid.uuid);
        
                spin_lock(&obd_zombie_impexp_lock);
                list_add(&exp->exp_obd_chain, &obd_zombie_exports);
                spin_unlock(&obd_zombie_impexp_lock);

                if (obd_zombie_impexp_notify != NULL)
                        obd_zombie_impexp_notify();
        }
}
EXPORT_SYMBOL(__class_export_put);

void class_export_destroy(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;

        LASSERT (atomic_read(&exp->exp_refcount) == 0);

        CDEBUG(D_IOCTL, "destroying export %p/%s\n", exp,
               exp->exp_client_uuid.uuid);

        LASSERT(obd != NULL);

        /* "Local" exports (lctl, LOV->{mdc,osc}) have no connection. */
        if (exp->exp_connection)
                ptlrpc_put_connection_superhack(exp->exp_connection);

        LASSERT(list_empty(&exp->exp_outstanding_replies));
        LASSERT(list_empty(&exp->exp_req_replay_queue));
        obd_destroy_export(exp);

        OBD_FREE_RCU(exp, sizeof(*exp), &exp->exp_handle);
        class_decref(obd);
}

/* Creates a new export, adds it to the hash table, and returns a
 * pointer to it. The refcount is 2: one for the hash reference, and
 * one for the pointer returned by this function. */
struct obd_export *class_new_export(struct obd_device *obd,
                                    struct obd_uuid *cluuid)
{
        struct obd_export *export;
        int rc = 0;

        OBD_ALLOC(export, sizeof(*export));
        if (!export)
                return ERR_PTR(-ENOMEM);

        export->exp_conn_cnt = 0;
        atomic_set(&export->exp_refcount, 2);
        atomic_set(&export->exp_rpc_count, 0);
        export->exp_obd = obd;
        CFS_INIT_LIST_HEAD(&export->exp_outstanding_replies);
        CFS_INIT_LIST_HEAD(&export->exp_req_replay_queue);
        /* XXX this should be in LDLM init */
        CFS_INIT_LIST_HEAD(&export->exp_ldlm_data.led_held_locks);
        spin_lock_init(&export->exp_ldlm_data.led_lock);

        CFS_INIT_LIST_HEAD(&export->exp_handle.h_link);
        class_handle_hash(&export->exp_handle, export_handle_addref);
        export->exp_last_request_time = cfs_time_current_sec();
        spin_lock_init(&export->exp_lock);
        INIT_HLIST_NODE(&export->exp_uuid_hash);
        INIT_HLIST_NODE(&export->exp_nid_hash);

        export->exp_client_uuid = *cluuid;
        obd_init_export(export);

        if (!obd_uuid_equals(cluuid, &obd->obd_uuid)) {
               rc = lustre_hash_additem_unique(obd->obd_uuid_hash_body, cluuid, 
                                               &export->exp_uuid_hash);
               if (rc != 0) {
                       CWARN("%s: denying duplicate export for %s\n",
                             obd->obd_name, cluuid->uuid);
                       class_handle_unhash(&export->exp_handle);
                       OBD_FREE_PTR(export);
                       return ERR_PTR(-EALREADY);
               }
        }

        spin_lock(&obd->obd_dev_lock);
        LASSERT(!obd->obd_stopping); /* shouldn't happen, but might race */
        class_incref(obd);
        list_add(&export->exp_obd_chain, &export->exp_obd->obd_exports);
        list_add_tail(&export->exp_obd_chain_timed,
                      &export->exp_obd->obd_exports_timed);
        export->exp_obd->obd_num_exports++;
        spin_unlock(&obd->obd_dev_lock);

        return export;
}
EXPORT_SYMBOL(class_new_export);

void class_unlink_export(struct obd_export *exp)
{
        class_handle_unhash(&exp->exp_handle);

        spin_lock(&exp->exp_obd->obd_dev_lock);
        /* delete an uuid-export hashitem from hashtables */
        if (!hlist_unhashed(&exp->exp_uuid_hash)) {
                lustre_hash_delitem(exp->exp_obd->obd_uuid_hash_body, 
                                    &exp->exp_client_uuid, &exp->exp_uuid_hash);
        }
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
        LASSERT(list_empty(&import->imp_zombie_chain));

        if (atomic_dec_and_test(&import->imp_refcount)) {

                CDEBUG(D_INFO, "final put import %p\n", import);
                
                spin_lock(&obd_zombie_impexp_lock);
                list_add(&import->imp_zombie_chain, &obd_zombie_imports);
                spin_unlock(&obd_zombie_impexp_lock);

                if (obd_zombie_impexp_notify != NULL)
                        obd_zombie_impexp_notify();
        }

        EXIT;
}

void class_import_destroy(struct obd_import *import)
{
        ENTRY;
        
        CDEBUG(D_IOCTL, "destroying import %p\n", import);

        LASSERT(atomic_read(&import->imp_refcount) == 0);

        ptlrpc_put_connection_superhack(import->imp_connection);

        while (!list_empty(&import->imp_conn_list)) {
                struct obd_import_conn *imp_conn;

                imp_conn = list_entry(import->imp_conn_list.next,
                                      struct obd_import_conn, oic_item);
                list_del(&imp_conn->oic_item);
                ptlrpc_put_connection_superhack(imp_conn->oic_conn);
                OBD_FREE(imp_conn, sizeof(*imp_conn));
        }

        class_decref(import->imp_obd);
        OBD_FREE_RCU(import, sizeof(*import), &import->imp_handle);
        EXIT;
}
EXPORT_SYMBOL(class_import_put);

static void init_imp_at(struct imp_at *at) {
        int i;
        at_init(&at->iat_net_latency, 0, 0);
        for (i = 0; i < IMP_AT_MAX_PORTALS; i++) {
                /* max service estimates are tracked on the server side, so
                   don't use the AT history here, just use the last reported
                   val. (But keep hist for proc histogram, worst_ever) */
                at_init(&at->iat_service_estimate[i], INITIAL_CONNECT_TIMEOUT,
                        AT_FLG_NOHIST);
        }
}

struct obd_import *class_new_import(struct obd_device *obd)
{
        struct obd_import *imp;

        OBD_ALLOC(imp, sizeof(*imp));
        if (imp == NULL)
                return NULL;

        CFS_INIT_LIST_HEAD(&imp->imp_zombie_chain);
        CFS_INIT_LIST_HEAD(&imp->imp_replay_list);
        CFS_INIT_LIST_HEAD(&imp->imp_sending_list);
        CFS_INIT_LIST_HEAD(&imp->imp_delayed_list);
        spin_lock_init(&imp->imp_lock);
        imp->imp_last_success_conn = 0;
        imp->imp_state = LUSTRE_IMP_NEW;
        imp->imp_obd = class_incref(obd);
        cfs_waitq_init(&imp->imp_recovery_waitq);

        atomic_set(&imp->imp_refcount, 2);
        atomic_set(&imp->imp_inflight, 0);
        atomic_set(&imp->imp_replay_inflight, 0);
        atomic_set(&imp->imp_inval_count, 0);
        CFS_INIT_LIST_HEAD(&imp->imp_conn_list);
        CFS_INIT_LIST_HEAD(&imp->imp_handle.h_link);
        class_handle_hash(&imp->imp_handle, import_handle_addref);
        init_imp_at(&imp->imp_at);

#ifdef HAVE_DEFAULT_V2_CONNECT
        /* the default magic is V2, will be used in connect RPC, and
         * then adjusted according to the flags in request/reply. */
        imp->imp_msg_magic = LUSTRE_MSG_MAGIC_V2;
#else
        /* the default magic is V1, will be used in connect RPC, and
         * then adjusted according to the flags in request/reply. */
        imp->imp_msg_magic = LUSTRE_MSG_MAGIC_V1;
#endif

        return imp;
}
EXPORT_SYMBOL(class_new_import);

void class_destroy_import(struct obd_import *import)
{
        LASSERT(import != NULL);
        LASSERT(import != LP_POISON);

        class_handle_unhash(&import->imp_handle);

        spin_lock(&import->imp_lock);
        import->imp_generation++;
        spin_unlock(&import->imp_lock);

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

        export = class_new_export(obd, cluuid);
        if (IS_ERR(export))
                RETURN(PTR_ERR(export));

        conn->cookie = export->exp_handle.h_cookie;
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

        if (!hlist_unhashed(&export->exp_nid_hash)) {
                lustre_hash_delitem(export->exp_obd->obd_nid_hash_body,
                                    &export->exp_connection->c_peer.nid, &export->exp_nid_hash);
        }
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
        while (!list_empty(list)) {
                exp = list_entry(list->next, struct obd_export, exp_obd_chain);
                class_export_get(exp);

                spin_lock(&exp->exp_lock);
                exp->exp_flags = flags;
                spin_unlock(&exp->exp_lock);

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

                spin_lock(&fake_exp->exp_lock);
                fake_exp->exp_flags = flags;
                spin_unlock(&fake_exp->exp_lock);

                CDEBUG(D_HA, "%s: disconnecting export at %s (%p), "
                       "last request at %ld\n",
                       exp->exp_obd->obd_name, obd_export_nid2str(exp),
                       exp, exp->exp_last_request_time);
                rc = obd_disconnect(fake_exp);
                class_export_put(exp);
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

        CFS_INIT_LIST_HEAD(&work_list);
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
        cfs_waitq_init(&oig->oig_waitq);
        CFS_INIT_LIST_HEAD(&oig->oig_occ_list);

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

int oig_add_one(struct obd_io_group *oig, struct oig_callback_context *occ)
{
        int rc = 0;
        CDEBUG(D_CACHE, "oig %p ready to roll\n", oig);
        spin_lock(&oig->oig_lock);
        if (oig->oig_rc) {
                rc = oig->oig_rc;
        } else {
                oig->oig_pending++;
                if (occ != NULL)
                        list_add_tail(&occ->occ_oig_item, &oig->oig_occ_list);
        }
        spin_unlock(&oig->oig_lock);
        oig_grab(oig);

        return rc;
}
EXPORT_SYMBOL(oig_add_one);

void oig_complete_one(struct obd_io_group *oig,
                      struct oig_callback_context *occ, int rc)
{
        cfs_waitq_t *wake = NULL;
        int old_rc;

        spin_lock(&oig->oig_lock);

        if (occ != NULL)
                list_del_init(&occ->occ_oig_item);

        old_rc = oig->oig_rc;
        if (oig->oig_rc == 0 && rc != 0)
                oig->oig_rc = rc;

        if (--oig->oig_pending <= 0)
                wake = &oig->oig_waitq;

        spin_unlock(&oig->oig_lock);

        CDEBUG(D_CACHE, "oig %p completed, rc %d -> %d via %d, %d now "
                        "pending (racey)\n", oig, old_rc, oig->oig_rc, rc,
                        oig->oig_pending);
        if (wake)
                cfs_waitq_signal(wake);
        oig_release(oig);
}
EXPORT_SYMBOL(oig_complete_one);

static int oig_done(struct obd_io_group *oig)
{
        int rc = 0;
        spin_lock(&oig->oig_lock);
        if (oig->oig_pending <= 0)
                rc = 1;
        spin_unlock(&oig->oig_lock);
        return rc;
}

static void interrupted_oig(void *data)
{
        struct obd_io_group *oig = data;
        struct oig_callback_context *occ;

        spin_lock(&oig->oig_lock);
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
                spin_unlock(&oig->oig_lock);
                occ->occ_interrupted(occ);
                spin_lock(&oig->oig_lock);
                goto restart;
        }
        spin_unlock(&oig->oig_lock);
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

        spin_lock(&exp->exp_lock);
        already_failed = exp->exp_failed;
        exp->exp_failed = 1;
        spin_unlock(&exp->exp_lock);

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

int obd_export_evict_by_nid(struct obd_device *obd, char *nid)
{
        struct obd_export *doomed_exp = NULL;
        int exports_evicted = 0;

        lnet_nid_t nid_key = libcfs_str2nid(nid);

        do {
                doomed_exp = lustre_hash_get_object_by_key(obd->obd_nid_hash_body,
                                                           &nid_key);

                if (doomed_exp == NULL)
                        break;

                LASSERTF(doomed_exp->exp_connection->c_peer.nid == nid_key,
                         "nid %s found, wanted nid %s, requested nid %s\n",
                         obd_export_nid2str(doomed_exp),
                         libcfs_nid2str(nid_key), nid);
        
                exports_evicted++;
                CDEBUG(D_HA, "%s: evict NID '%s' (%s) #%d at adminstrative request\n",
                       obd->obd_name, nid, doomed_exp->exp_client_uuid.uuid,
                       exports_evicted);
                class_fail_export(doomed_exp);
                class_export_put(doomed_exp);
        } while (1);

        if (!exports_evicted)
                CDEBUG(D_HA,"%s: can't disconnect NID '%s': no exports found\n",
                       obd->obd_name, nid);
        return exports_evicted;
}
EXPORT_SYMBOL(obd_export_evict_by_nid);

int obd_export_evict_by_uuid(struct obd_device *obd, char *uuid)
{
        struct obd_export *doomed_exp = NULL;
        struct obd_uuid doomed;
        int exports_evicted = 0;

        obd_str2uuid(&doomed, uuid);
        if(obd_uuid_equals(&doomed, &obd->obd_uuid)) {
                CERROR("%s: can't evict myself\n", obd->obd_name);
                return exports_evicted;
        }

        doomed_exp = lustre_hash_get_object_by_key(obd->obd_uuid_hash_body, 
                                                   &doomed);

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

void obd_zombie_impexp_cull(void) 
{
        struct obd_import *import;
        struct obd_export *export;
        
        do {
                spin_lock (&obd_zombie_impexp_lock);

                import = NULL;
                if (!list_empty(&obd_zombie_imports)) {
                        import = list_entry(obd_zombie_imports.next,
                                            struct obd_import,
                                            imp_zombie_chain);
                        list_del(&import->imp_zombie_chain);
                }
                
                export = NULL;
                if (!list_empty(&obd_zombie_exports)) {
                        export = list_entry(obd_zombie_exports.next,
                                            struct obd_export,
                                            exp_obd_chain);
                        list_del_init(&export->exp_obd_chain);
                }

                spin_unlock(&obd_zombie_impexp_lock);
                
                if (import != NULL)
                        class_import_destroy(import);

                if (export != NULL)
                        class_export_destroy(export);

        } while (import != NULL || export != NULL);
}
EXPORT_SYMBOL(obd_zombie_impexp_cull);

void obd_zombie_impexp_init(void)
{
        CFS_INIT_LIST_HEAD(&obd_zombie_imports);
        CFS_INIT_LIST_HEAD(&obd_zombie_exports);
        spin_lock_init(&obd_zombie_impexp_lock);
}
