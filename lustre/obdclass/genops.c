/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/genops.c
 *
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/pid_namespace.h>
#include <linux/workqueue.h>
#include <lustre_compat.h>
#include <obd_class.h>
#include <lustre_log.h>
#include <lprocfs_status.h>
#include <lustre_disk.h>
#include <lustre_kernelcomm.h>

DEFINE_RWLOCK(obd_dev_lock);
static struct obd_device *obd_devs[MAX_OBD_DEVICES];

static struct kmem_cache *obd_device_cachep;
static struct kobj_type class_ktype;
static struct workqueue_struct *zombie_wq;

static void obd_zombie_export_add(struct obd_export *exp);
static void obd_zombie_import_add(struct obd_import *imp);
static void print_export_data(struct obd_export *exp,
                              const char *status, int locks, int debug_level);

static LIST_HEAD(obd_stale_exports);
static DEFINE_SPINLOCK(obd_stale_export_lock);
static atomic_t obd_stale_export_num = ATOMIC_INIT(0);

/*
 * support functions: we could use inter-module communication, but this
 * is more portable to other OS's
 */
static struct obd_device *obd_device_alloc(void)
{
	struct obd_device *obd;

	OBD_SLAB_ALLOC_PTR_GFP(obd, obd_device_cachep, GFP_NOFS);
	if (obd != NULL) {
		obd->obd_magic = OBD_DEVICE_MAGIC;
	}
	return obd;
}

static void obd_device_free(struct obd_device *obd)
{
        LASSERT(obd != NULL);
        LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC, "obd %p obd_magic %08x != %08x\n",
                 obd, obd->obd_magic, OBD_DEVICE_MAGIC);
        if (obd->obd_namespace != NULL) {
                CERROR("obd %p: namespace %p was not properly cleaned up (obd_force=%d)!\n",
                       obd, obd->obd_namespace, obd->obd_force);
                LBUG();
        }
        lu_ref_fini(&obd->obd_reference);
        OBD_SLAB_FREE_PTR(obd, obd_device_cachep);
}

struct obd_type *class_search_type(const char *name)
{
	struct kobject *kobj = kset_find_obj(lustre_kset, name);

	if (kobj && kobj->ktype == &class_ktype)
		return container_of(kobj, struct obd_type, typ_kobj);

	kobject_put(kobj);
	return NULL;
}
EXPORT_SYMBOL(class_search_type);

struct obd_type *class_get_type(const char *name)
{
	struct obd_type *type;

	type = class_search_type(name);
#ifdef HAVE_MODULE_LOADING_SUPPORT
        if (!type) {
                const char *modname = name;

#ifdef HAVE_SERVER_SUPPORT
		if (strcmp(modname, "obdfilter") == 0)
			modname = "ofd";

		if (strcmp(modname, LUSTRE_LWP_NAME) == 0)
			modname = LUSTRE_OSP_NAME;

		if (!strncmp(modname, LUSTRE_MDS_NAME, strlen(LUSTRE_MDS_NAME)))
			modname = LUSTRE_MDT_NAME;
#endif /* HAVE_SERVER_SUPPORT */

		if (!request_module("%s", modname)) {
			CDEBUG(D_INFO, "Loaded module '%s'\n", modname);
			type = class_search_type(name);
                } else {
                        LCONSOLE_ERROR_MSG(0x158, "Can't load module '%s'\n",
                                           modname);
                }
        }
#endif
        if (type) {
		if (try_module_get(type->typ_dt_ops->o_owner)) {
			atomic_inc(&type->typ_refcnt);
			/* class_search_type() returned a counted reference,
			 * but we don't need that count any more as
			 * we have one through typ_refcnt.
			 */
			kobject_put(&type->typ_kobj);
		} else {
			kobject_put(&type->typ_kobj);
			type = NULL;
		}
	}
	return type;
}

void class_put_type(struct obd_type *type)
{
	LASSERT(type);
	module_put(type->typ_dt_ops->o_owner);
	atomic_dec(&type->typ_refcnt);
}

static void class_sysfs_release(struct kobject *kobj)
{
	struct obd_type *type = container_of(kobj, struct obd_type, typ_kobj);

	debugfs_remove_recursive(type->typ_debugfs_entry);
	type->typ_debugfs_entry = NULL;

	if (type->typ_lu)
		lu_device_type_fini(type->typ_lu);

#ifdef CONFIG_PROC_FS
	if (type->typ_name && type->typ_procroot)
		remove_proc_subtree(type->typ_name, proc_lustre_root);
#endif
	OBD_FREE(type, sizeof(*type));
}

static struct kobj_type class_ktype = {
	.sysfs_ops      = &lustre_sysfs_ops,
	.release        = class_sysfs_release,
};

#ifdef HAVE_SERVER_SUPPORT
struct obd_type *class_add_symlinks(const char *name, bool enable_proc)
{
	struct dentry *symlink;
	struct obd_type *type;
	int rc;

	type = class_search_type(name);
	if (type) {
		kobject_put(&type->typ_kobj);
		return ERR_PTR(-EEXIST);
	}

	OBD_ALLOC(type, sizeof(*type));
	if (!type)
		return ERR_PTR(-ENOMEM);

	type->typ_kobj.kset = lustre_kset;
	rc = kobject_init_and_add(&type->typ_kobj, &class_ktype,
				  &lustre_kset->kobj, "%s", name);
	if (rc)
		return ERR_PTR(rc);

	symlink = debugfs_create_dir(name, debugfs_lustre_root);
	type->typ_debugfs_entry = symlink;
	type->typ_sym_filter = true;

	if (enable_proc) {
		type->typ_procroot = lprocfs_register(name, proc_lustre_root,
						      NULL, NULL);
		if (IS_ERR(type->typ_procroot)) {
			CERROR("%s: can't create compat proc entry: %d\n",
			       name, (int)PTR_ERR(type->typ_procroot));
			type->typ_procroot = NULL;
		}
	}

	return type;
}
EXPORT_SYMBOL(class_add_symlinks);
#endif /* HAVE_SERVER_SUPPORT */

#define CLASS_MAX_NAME 1024

int class_register_type(const struct obd_ops *dt_ops,
			const struct md_ops *md_ops,
			bool enable_proc,
			const char *name, struct lu_device_type *ldt)
{
	struct obd_type *type;
	int rc;

	ENTRY;
	/* sanity check */
	LASSERT(strnlen(name, CLASS_MAX_NAME) < CLASS_MAX_NAME);

	type = class_search_type(name);
	if (type) {
#ifdef HAVE_SERVER_SUPPORT
		if (type->typ_sym_filter)
			goto dir_exist;
#endif /* HAVE_SERVER_SUPPORT */
		kobject_put(&type->typ_kobj);
                CDEBUG(D_IOCTL, "Type %s already registered\n", name);
                RETURN(-EEXIST);
        }

        OBD_ALLOC(type, sizeof(*type));
        if (type == NULL)
		RETURN(-ENOMEM);

	type->typ_lu = ldt ? OBD_LU_TYPE_SETUP : NULL;
	type->typ_kobj.kset = lustre_kset;
	kobject_init(&type->typ_kobj, &class_ktype);
#ifdef HAVE_SERVER_SUPPORT
dir_exist:
#endif /* HAVE_SERVER_SUPPORT */

	type->typ_dt_ops = dt_ops;
	type->typ_md_ops = md_ops;

#ifdef HAVE_SERVER_SUPPORT
	if (type->typ_sym_filter) {
		type->typ_sym_filter = false;
		kobject_put(&type->typ_kobj);
		goto setup_ldt;
	}
#endif
#ifdef CONFIG_PROC_FS
	if (enable_proc && !type->typ_procroot) {
		type->typ_procroot = lprocfs_register(name,
						      proc_lustre_root,
						      NULL, type);
		if (IS_ERR(type->typ_procroot)) {
			rc = PTR_ERR(type->typ_procroot);
			type->typ_procroot = NULL;
			GOTO(failed, rc);
		}
	}
#endif
	type->typ_debugfs_entry = debugfs_create_dir(name, debugfs_lustre_root);

	rc = kobject_add(&type->typ_kobj, &lustre_kset->kobj, "%s", name);
	if (rc)
		GOTO(failed, rc);
#ifdef HAVE_SERVER_SUPPORT
setup_ldt:
#endif
	if (ldt) {
		rc = lu_device_type_init(ldt);
		smp_store_release(&type->typ_lu, rc ? NULL : ldt);
		wake_up_var(&type->typ_lu);
		if (rc)
			GOTO(failed, rc);
	}

	RETURN(0);

failed:
	kobject_put(&type->typ_kobj);

	RETURN(rc);
}
EXPORT_SYMBOL(class_register_type);

int class_unregister_type(const char *name)
{
        struct obd_type *type = class_search_type(name);
	int rc = 0;
        ENTRY;

        if (!type) {
                CERROR("unknown obd type\n");
                RETURN(-EINVAL);
        }

	if (atomic_read(&type->typ_refcnt)) {
		CERROR("type %s has refcount (%d)\n", name,
		       atomic_read(&type->typ_refcnt));
                /* This is a bad situation, let's make the best of it */
                /* Remove ops, but leave the name for debugging */
		type->typ_dt_ops = NULL;
		type->typ_md_ops = NULL;
		GOTO(out_put, rc = -EBUSY);
        }

	/* Put the final ref */
	kobject_put(&type->typ_kobj);
out_put:
	/* Put the ref returned by class_search_type() */
	kobject_put(&type->typ_kobj);

	RETURN(rc);
} /* class_unregister_type */
EXPORT_SYMBOL(class_unregister_type);

/**
 * Create a new obd device.
 *
 * Allocate the new obd_device and initialize it.
 *
 * \param[in] type_name obd device type string.
 * \param[in] name      obd device name.
 * \param[in] uuid      obd device UUID
 *
 * \retval newdev         pointer to created obd_device
 * \retval ERR_PTR(errno) on error
 */
struct obd_device *class_newdev(const char *type_name, const char *name,
				const char *uuid)
{
        struct obd_device *newdev;
        struct obd_type *type = NULL;
        ENTRY;

        if (strlen(name) >= MAX_OBD_NAME) {
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
	strncpy(newdev->obd_name, name, sizeof(newdev->obd_name) - 1);
	newdev->obd_type = type;
	newdev->obd_minor = -1;

	rwlock_init(&newdev->obd_pool_lock);
	newdev->obd_pool_limit = 0;
	newdev->obd_pool_slv = 0;

	INIT_LIST_HEAD(&newdev->obd_exports);
	INIT_LIST_HEAD(&newdev->obd_unlinked_exports);
	INIT_LIST_HEAD(&newdev->obd_delayed_exports);
	INIT_LIST_HEAD(&newdev->obd_exports_timed);
	INIT_LIST_HEAD(&newdev->obd_nid_stats);
	spin_lock_init(&newdev->obd_nid_lock);
	spin_lock_init(&newdev->obd_dev_lock);
	mutex_init(&newdev->obd_dev_mutex);
	spin_lock_init(&newdev->obd_osfs_lock);
	/* newdev->obd_osfs_age must be set to a value in the distant
	 * past to guarantee a fresh statfs is fetched on mount. */
	newdev->obd_osfs_age = ktime_get_seconds() - 1000;

	/* XXX belongs in setup not attach  */
	init_rwsem(&newdev->obd_observer_link_sem);
	/* recovery data */
	spin_lock_init(&newdev->obd_recovery_task_lock);
	init_waitqueue_head(&newdev->obd_next_transno_waitq);
	init_waitqueue_head(&newdev->obd_evict_inprogress_waitq);
	INIT_LIST_HEAD(&newdev->obd_req_replay_queue);
	INIT_LIST_HEAD(&newdev->obd_lock_replay_queue);
	INIT_LIST_HEAD(&newdev->obd_final_req_queue);
	INIT_LIST_HEAD(&newdev->obd_evict_list);
	INIT_LIST_HEAD(&newdev->obd_lwp_list);

	llog_group_init(&newdev->obd_olg);
	/* Detach drops this */
	atomic_set(&newdev->obd_refcount, 1);
	lu_ref_init(&newdev->obd_reference);
	lu_ref_add(&newdev->obd_reference, "newdev", newdev);

	newdev->obd_conn_inprogress = 0;

	strncpy(newdev->obd_uuid.uuid, uuid, UUID_MAX);

	CDEBUG(D_IOCTL, "Allocate new device %s (%p)\n",
	       newdev->obd_name, newdev);

	return newdev;
}

/**
 * Free obd device.
 *
 * \param[in] obd obd_device to be freed
 *
 * \retval none
 */
void class_free_dev(struct obd_device *obd)
{
	struct obd_type *obd_type = obd->obd_type;

	LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC, "%p obd_magic %08x "
		 "!= %08x\n", obd, obd->obd_magic, OBD_DEVICE_MAGIC);
	LASSERTF(obd->obd_minor == -1 || obd_devs[obd->obd_minor] == obd,
		 "obd %p != obd_devs[%d] %p\n",
		 obd, obd->obd_minor, obd_devs[obd->obd_minor]);
	LASSERTF(atomic_read(&obd->obd_refcount) == 0,
		 "obd_refcount should be 0, not %d\n",
		 atomic_read(&obd->obd_refcount));
	LASSERT(obd_type != NULL);

	CDEBUG(D_INFO, "Release obd device %s obd_type name = %s\n",
	       obd->obd_name, obd->obd_type->typ_name);

	CDEBUG(D_CONFIG, "finishing cleanup of obd %s (%s)\n",
			 obd->obd_name, obd->obd_uuid.uuid);
	if (obd->obd_stopping) {
		int err;

		/* If we're not stopping, we were never set up */
		err = obd_cleanup(obd);
		if (err)
			CERROR("Cleanup %s returned %d\n",
				obd->obd_name, err);
	}

	obd_device_free(obd);

	class_put_type(obd_type);
}

/**
 * Unregister obd device.
 *
 * Free slot in obd_dev[] used by \a obd.
 *
 * \param[in] new_obd obd_device to be unregistered
 *
 * \retval none
 */
void class_unregister_device(struct obd_device *obd)
{
	write_lock(&obd_dev_lock);
	if (obd->obd_minor >= 0) {
		LASSERT(obd_devs[obd->obd_minor] == obd);
		obd_devs[obd->obd_minor] = NULL;
		obd->obd_minor = -1;
	}
	write_unlock(&obd_dev_lock);
}

/**
 * Register obd device.
 *
 * Find free slot in obd_devs[], fills it with \a new_obd.
 *
 * \param[in] new_obd obd_device to be registered
 *
 * \retval 0          success
 * \retval -EEXIST    device with this name is registered
 * \retval -EOVERFLOW obd_devs[] is full
 */
int class_register_device(struct obd_device *new_obd)
{
	int ret = 0;
	int i;
	int new_obd_minor = 0;
	bool minor_assign = false;
	bool retried = false;

again:
	write_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		struct obd_device *obd = class_num2obd(i);

		if (obd != NULL &&
		    (strcmp(new_obd->obd_name, obd->obd_name) == 0)) {

			if (!retried) {
				write_unlock(&obd_dev_lock);

				/* the obd_device could be waited to be
 				 * destroyed by the "obd_zombie_impexp_thread".
 				 */
				obd_zombie_barrier();
				retried = true;
				goto again;
			}

			CERROR("%s: already exists, won't add\n",
			       obd->obd_name);
			/* in case we found a free slot before duplicate */
			minor_assign = false;
			ret = -EEXIST;
			break;
		}
		if (!minor_assign && obd == NULL) {
			new_obd_minor = i;
			minor_assign = true;
		}
	}

	if (minor_assign) {
		new_obd->obd_minor = new_obd_minor;
		LASSERTF(obd_devs[new_obd_minor] == NULL, "obd_devs[%d] "
			 "%p\n", new_obd_minor, obd_devs[new_obd_minor]);
		obd_devs[new_obd_minor] = new_obd;
	} else {
		if (ret == 0) {
			ret = -EOVERFLOW;
			CERROR("%s: all %u/%u devices used, increase "
			       "MAX_OBD_DEVICES: rc = %d\n", new_obd->obd_name,
			       i, class_devno_max(), ret);
		}
	}
	write_unlock(&obd_dev_lock);

	RETURN(ret);
}

static int class_name2dev_nolock(const char *name)
{
        int i;

        if (!name)
                return -1;

        for (i = 0; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);

		if (obd && strcmp(name, obd->obd_name) == 0) {
                        /* Make sure we finished attaching before we give
                           out any references */
                        LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
                        if (obd->obd_attached) {
                                return i;
                        }
                        break;
                }
        }

        return -1;
}

int class_name2dev(const char *name)
{
	int i;

	if (!name)
		return -1;

	read_lock(&obd_dev_lock);
	i = class_name2dev_nolock(name);
	read_unlock(&obd_dev_lock);

	return i;
}
EXPORT_SYMBOL(class_name2dev);

struct obd_device *class_name2obd(const char *name)
{
        int dev = class_name2dev(name);

        if (dev < 0 || dev > class_devno_max())
                return NULL;
        return class_num2obd(dev);
}
EXPORT_SYMBOL(class_name2obd);

int class_uuid2dev_nolock(struct obd_uuid *uuid)
{
        int i;

        for (i = 0; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);

                if (obd && obd_uuid_equals(uuid, &obd->obd_uuid)) {
                        LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
                        return i;
                }
        }

        return -1;
}

int class_uuid2dev(struct obd_uuid *uuid)
{
	int i;

	read_lock(&obd_dev_lock);
	i = class_uuid2dev_nolock(uuid);
	read_unlock(&obd_dev_lock);

	return i;
}
EXPORT_SYMBOL(class_uuid2dev);

struct obd_device *class_uuid2obd(struct obd_uuid *uuid)
{
        int dev = class_uuid2dev(uuid);
        if (dev < 0)
                return NULL;
        return class_num2obd(dev);
}
EXPORT_SYMBOL(class_uuid2obd);

/**
 * Get obd device from ::obd_devs[]
 *
 * \param num [in] array index
 *
 * \retval NULL if ::obd_devs[\a num] does not contains an obd device
 *         otherwise return the obd device there.
 */
struct obd_device *class_num2obd(int num)
{
        struct obd_device *obd = NULL;

        if (num < class_devno_max()) {
                obd = obd_devs[num];
                if (obd == NULL)
                        return NULL;

                LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC,
                         "%p obd_magic %08x != %08x\n",
                         obd, obd->obd_magic, OBD_DEVICE_MAGIC);
                LASSERTF(obd->obd_minor == num,
                         "%p obd_minor %0d != %0d\n",
                         obd, obd->obd_minor, num);
        }

        return obd;
}
EXPORT_SYMBOL(class_num2obd);

/**
 * Find obd in obd_dev[] by name or uuid.
 *
 * Increment obd's refcount if found.
 *
 * \param[in] str obd name or uuid
 *
 * \retval NULL    if not found
 * \retval target  pointer to found obd_device
 */
struct obd_device *class_dev_by_str(const char *str)
{
	struct obd_device *target = NULL;
	struct obd_uuid tgtuuid;
	int rc;

	obd_str2uuid(&tgtuuid, str);

	read_lock(&obd_dev_lock);
	rc = class_uuid2dev_nolock(&tgtuuid);
	if (rc < 0)
		rc = class_name2dev_nolock(str);

	if (rc >= 0)
		target = class_num2obd(rc);

	if (target != NULL)
		class_incref(target, "find", current);
	read_unlock(&obd_dev_lock);

	RETURN(target);
}
EXPORT_SYMBOL(class_dev_by_str);

/**
 * Get obd devices count. Device in any
 *    state are counted
 * \retval obd device count
 */
int get_devices_count(void)
{
	int index, max_index = class_devno_max(), dev_count = 0;

	read_lock(&obd_dev_lock);
	for (index = 0; index <= max_index; index++) {
		struct obd_device *obd = class_num2obd(index);
		if (obd != NULL)
			dev_count++;
	}
	read_unlock(&obd_dev_lock);

	return dev_count;
}
EXPORT_SYMBOL(get_devices_count);

void class_obd_list(void)
{
        char *status;
        int i;

	read_lock(&obd_dev_lock);
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
	read_unlock(&obd_dev_lock);
}

/* Search for a client OBD connected to tgt_uuid.  If grp_uuid is
 * specified, then only the client with that uuid is returned,
 * otherwise any client connected to the tgt is returned.
 */
struct obd_device *class_find_client_obd(struct obd_uuid *tgt_uuid,
					 const char *type_name,
					 struct obd_uuid *grp_uuid)
{
        int i;

	read_lock(&obd_dev_lock);
        for (i = 0; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);

                if (obd == NULL)
                        continue;
		if ((strncmp(obd->obd_type->typ_name, type_name,
			     strlen(type_name)) == 0)) {
                        if (obd_uuid_equals(tgt_uuid,
                                            &obd->u.cli.cl_target_uuid) &&
                            ((grp_uuid)? obd_uuid_equals(grp_uuid,
                                                         &obd->obd_uuid) : 1)) {
				read_unlock(&obd_dev_lock);
                                return obd;
                        }
                }
        }
	read_unlock(&obd_dev_lock);

        return NULL;
}
EXPORT_SYMBOL(class_find_client_obd);

/* Iterate the obd_device list looking devices have grp_uuid. Start
 * searching at *next, and if a device is found, the next index to look
 * at is saved in *next. If next is NULL, then the first matching device
 * will always be returned.
 */
struct obd_device *class_devices_in_group(struct obd_uuid *grp_uuid, int *next)
{
        int i;

        if (next == NULL)
                i = 0;
        else if (*next >= 0 && *next < class_devno_max())
                i = *next;
        else
                return NULL;

	read_lock(&obd_dev_lock);
        for (; i < class_devno_max(); i++) {
                struct obd_device *obd = class_num2obd(i);

                if (obd == NULL)
                        continue;
                if (obd_uuid_equals(grp_uuid, &obd->obd_uuid)) {
                        if (next != NULL)
                                *next = i+1;
			read_unlock(&obd_dev_lock);
                        return obd;
                }
        }
	read_unlock(&obd_dev_lock);

        return NULL;
}
EXPORT_SYMBOL(class_devices_in_group);

/**
 * to notify sptlrpc log for \a fsname has changed, let every relevant OBD
 * adjust sptlrpc settings accordingly.
 */
int class_notify_sptlrpc_conf(const char *fsname, int namelen)
{
        struct obd_device  *obd;
        const char         *type;
        int                 i, rc = 0, rc2;

        LASSERT(namelen > 0);

	read_lock(&obd_dev_lock);
	for (i = 0; i < class_devno_max(); i++) {
		obd = class_num2obd(i);

		if (obd == NULL || obd->obd_set_up == 0 || obd->obd_stopping)
			continue;

		/* only notify mdc, osc, osp, lwp, mdt, ost
		 * because only these have a -sptlrpc llog */
		type = obd->obd_type->typ_name;
		if (strcmp(type, LUSTRE_MDC_NAME) != 0 &&
		    strcmp(type, LUSTRE_OSC_NAME) != 0 &&
		    strcmp(type, LUSTRE_OSP_NAME) != 0 &&
		    strcmp(type, LUSTRE_LWP_NAME) != 0 &&
		    strcmp(type, LUSTRE_MDT_NAME) != 0 &&
		    strcmp(type, LUSTRE_OST_NAME) != 0)
			continue;

                if (strncmp(obd->obd_name, fsname, namelen))
                        continue;

                class_incref(obd, __FUNCTION__, obd);
		read_unlock(&obd_dev_lock);
                rc2 = obd_set_info_async(NULL, obd->obd_self_export,
                                         sizeof(KEY_SPTLRPC_CONF),
                                         KEY_SPTLRPC_CONF, 0, NULL, NULL);
                rc = rc ? rc : rc2;
                class_decref(obd, __FUNCTION__, obd);
		read_lock(&obd_dev_lock);
        }
	read_unlock(&obd_dev_lock);
        return rc;
}
EXPORT_SYMBOL(class_notify_sptlrpc_conf);

void obd_cleanup_caches(void)
{
        ENTRY;
        if (obd_device_cachep) {
		kmem_cache_destroy(obd_device_cachep);
                obd_device_cachep = NULL;
        }

        EXIT;
}

int obd_init_caches(void)
{
	int rc;
	ENTRY;

	LASSERT(obd_device_cachep == NULL);
	obd_device_cachep = kmem_cache_create_usercopy("ll_obd_dev_cache",
				sizeof(struct obd_device),
				0, 0, 0, sizeof(struct obd_device), NULL);
	if (!obd_device_cachep)
		GOTO(out, rc = -ENOMEM);

	RETURN(0);
out:
	obd_cleanup_caches();
	RETURN(rc);
}

static const char export_handle_owner[] = "export";

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

	CDEBUG(D_INFO, "looking for export cookie %#llx\n", conn->cookie);
	export = class_handle2object(conn->cookie, export_handle_owner);
	RETURN(export);
}
EXPORT_SYMBOL(class_conn2export);

struct obd_device *class_exp2obd(struct obd_export *exp)
{
        if (exp)
                return exp->exp_obd;
        return NULL;
}
EXPORT_SYMBOL(class_exp2obd);

struct obd_import *class_exp2cliimp(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        if (obd == NULL)
                return NULL;
        return obd->u.cli.cl_import;
}
EXPORT_SYMBOL(class_exp2cliimp);

/* Export management functions */
static void class_export_destroy(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        ENTRY;

	LASSERT(refcount_read(&exp->exp_handle.h_ref) == 0);
	LASSERT(obd != NULL);

        CDEBUG(D_IOCTL, "destroying export %p/%s for %s\n", exp,
               exp->exp_client_uuid.uuid, obd->obd_name);

        /* "Local" exports (lctl, LOV->{mdc,osc}) have no connection. */
	ptlrpc_connection_put(exp->exp_connection);

	LASSERT(list_empty(&exp->exp_outstanding_replies));
	LASSERT(list_empty(&exp->exp_uncommitted_replies));
	LASSERT(list_empty(&exp->exp_req_replay_queue));
	LASSERT(list_empty(&exp->exp_hp_rpcs));
        obd_destroy_export(exp);
	/* self export doesn't hold a reference to an obd, although it
	 * exists until freeing of the obd */
	if (exp != obd->obd_self_export)
		class_decref(obd, "export", exp);

	OBD_FREE_PRE(exp, sizeof(*exp), "rcu");
	kfree_rcu(exp, exp_handle.h_rcu);
        EXIT;
}

struct obd_export *class_export_get(struct obd_export *exp)
{
	refcount_inc(&exp->exp_handle.h_ref);
	CDEBUG(D_INFO, "GET export %p refcount=%d\n", exp,
	       refcount_read(&exp->exp_handle.h_ref));
        return exp;
}
EXPORT_SYMBOL(class_export_get);

void class_export_put(struct obd_export *exp)
{
        LASSERT(exp != NULL);
	LASSERT(refcount_read(&exp->exp_handle.h_ref) >  0);
	LASSERT(refcount_read(&exp->exp_handle.h_ref) < LI_POISON);
        CDEBUG(D_INFO, "PUTting export %p : new refcount %d\n", exp,
	       refcount_read(&exp->exp_handle.h_ref) - 1);

	if (refcount_dec_and_test(&exp->exp_handle.h_ref)) {
		struct obd_device *obd = exp->exp_obd;

		CDEBUG(D_IOCTL, "final put %p/%s\n",
		       exp, exp->exp_client_uuid.uuid);

		/* release nid stat refererence */
		lprocfs_exp_cleanup(exp);

		if (exp == obd->obd_self_export) {
			/* self export should be destroyed without
			 * zombie thread as it doesn't hold a
			 * reference to obd and doesn't hold any
			 * resources */
			class_export_destroy(exp);
			/* self export is destroyed, no class
			 * references exist and it is safe to free
			 * obd */
			class_free_dev(obd);
		} else {
			LASSERT(!list_empty(&exp->exp_obd_chain));
			obd_zombie_export_add(exp);
		}

	}
}
EXPORT_SYMBOL(class_export_put);

static void obd_zombie_exp_cull(struct work_struct *ws)
{
	struct obd_export *export;

	export = container_of(ws, struct obd_export, exp_zombie_work);
	class_export_destroy(export);
}

/* Creates a new export, adds it to the hash table, and returns a
 * pointer to it. The refcount is 2: one for the hash reference, and
 * one for the pointer returned by this function. */
struct obd_export *__class_new_export(struct obd_device *obd,
				      struct obd_uuid *cluuid, bool is_self)
{
        struct obd_export *export;
        int rc = 0;
        ENTRY;

        OBD_ALLOC_PTR(export);
        if (!export)
                return ERR_PTR(-ENOMEM);

        export->exp_conn_cnt = 0;
        export->exp_lock_hash = NULL;
	export->exp_flock_hash = NULL;
	/* 2 = class_handle_hash + last */
	refcount_set(&export->exp_handle.h_ref, 2);
	atomic_set(&export->exp_rpc_count, 0);
	atomic_set(&export->exp_cb_count, 0);
	atomic_set(&export->exp_locks_count, 0);
#if LUSTRE_TRACKS_LOCK_EXP_REFS
	INIT_LIST_HEAD(&export->exp_locks_list);
	spin_lock_init(&export->exp_locks_list_guard);
#endif
	atomic_set(&export->exp_replay_count, 0);
	export->exp_obd = obd;
	INIT_LIST_HEAD(&export->exp_outstanding_replies);
	spin_lock_init(&export->exp_uncommitted_replies_lock);
	INIT_LIST_HEAD(&export->exp_uncommitted_replies);
	INIT_LIST_HEAD(&export->exp_req_replay_queue);
	INIT_HLIST_NODE(&export->exp_handle.h_link);
	INIT_LIST_HEAD(&export->exp_hp_rpcs);
	INIT_LIST_HEAD(&export->exp_reg_rpcs);
	class_handle_hash(&export->exp_handle, export_handle_owner);
	export->exp_last_request_time = ktime_get_real_seconds();
	spin_lock_init(&export->exp_lock);
	spin_lock_init(&export->exp_rpc_lock);
	INIT_HLIST_NODE(&export->exp_gen_hash);
	spin_lock_init(&export->exp_bl_list_lock);
	INIT_LIST_HEAD(&export->exp_bl_list);
	INIT_LIST_HEAD(&export->exp_stale_list);
	INIT_WORK(&export->exp_zombie_work, obd_zombie_exp_cull);

	export->exp_sp_peer = LUSTRE_SP_ANY;
	export->exp_flvr.sf_rpc = SPTLRPC_FLVR_INVALID;
	export->exp_client_uuid = *cluuid;
	obd_init_export(export);

	at_init(&export->exp_bl_lock_at, obd_timeout, 0);

	spin_lock(&obd->obd_dev_lock);
	if (!obd_uuid_equals(cluuid, &obd->obd_uuid)) {
		/* shouldn't happen, but might race */
		if (obd->obd_stopping)
			GOTO(exit_unlock, rc = -ENODEV);

		rc = obd_uuid_add(obd, export);
                if (rc != 0) {
			LCONSOLE_WARN("%s: denying duplicate export for %s: rc = %d\n",
                                      obd->obd_name, cluuid->uuid, rc);
			GOTO(exit_unlock, rc = -EALREADY);
                }
        }

	if (!is_self) {
		class_incref(obd, "export", export);
		list_add_tail(&export->exp_obd_chain_timed,
			      &obd->obd_exports_timed);
		list_add(&export->exp_obd_chain, &obd->obd_exports);
		obd->obd_num_exports++;
	} else {
		INIT_LIST_HEAD(&export->exp_obd_chain_timed);
		INIT_LIST_HEAD(&export->exp_obd_chain);
	}
	spin_unlock(&obd->obd_dev_lock);
	RETURN(export);

exit_unlock:
	spin_unlock(&obd->obd_dev_lock);
        class_handle_unhash(&export->exp_handle);
        obd_destroy_export(export);
        OBD_FREE_PTR(export);
        return ERR_PTR(rc);
}

struct obd_export *class_new_export(struct obd_device *obd,
				    struct obd_uuid *uuid)
{
	return __class_new_export(obd, uuid, false);
}
EXPORT_SYMBOL(class_new_export);

struct obd_export *class_new_export_self(struct obd_device *obd,
					 struct obd_uuid *uuid)
{
	return __class_new_export(obd, uuid, true);
}

void class_unlink_export(struct obd_export *exp)
{
	class_handle_unhash(&exp->exp_handle);

	if (exp->exp_obd->obd_self_export == exp) {
		class_export_put(exp);
		return;
	}

	spin_lock(&exp->exp_obd->obd_dev_lock);
	/* delete an uuid-export hashitem from hashtables */
	if (exp != exp->exp_obd->obd_self_export)
		obd_uuid_del(exp->exp_obd, exp);

#ifdef HAVE_SERVER_SUPPORT
	if (!hlist_unhashed(&exp->exp_gen_hash)) {
		struct tg_export_data	*ted = &exp->exp_target_data;
		struct cfs_hash		*hash;

		/* Because obd_gen_hash will not be released until
		 * class_cleanup(), so hash should never be NULL here */
		hash = cfs_hash_getref(exp->exp_obd->obd_gen_hash);
		LASSERT(hash != NULL);
		cfs_hash_del(hash, &ted->ted_lcd->lcd_generation,
			     &exp->exp_gen_hash);
		cfs_hash_putref(hash);
	}
#endif /* HAVE_SERVER_SUPPORT */

	list_move(&exp->exp_obd_chain, &exp->exp_obd->obd_unlinked_exports);
	list_del_init(&exp->exp_obd_chain_timed);
	exp->exp_obd->obd_num_exports--;
	spin_unlock(&exp->exp_obd->obd_dev_lock);
	atomic_inc(&obd_stale_export_num);

	/* A reference is kept by obd_stale_exports list */
	obd_stale_export_put(exp);
}
EXPORT_SYMBOL(class_unlink_export);

/* Import management functions */
static void obd_zombie_import_free(struct obd_import *imp)
{
	ENTRY;

	CDEBUG(D_IOCTL, "destroying import %p for %s\n", imp,
	       imp->imp_obd->obd_name);

	LASSERT(refcount_read(&imp->imp_refcount) == 0);

	ptlrpc_connection_put(imp->imp_connection);

	while (!list_empty(&imp->imp_conn_list)) {
		struct obd_import_conn *imp_conn;

		imp_conn = list_first_entry(&imp->imp_conn_list,
					    struct obd_import_conn, oic_item);
		list_del_init(&imp_conn->oic_item);
		ptlrpc_connection_put(imp_conn->oic_conn);
		OBD_FREE(imp_conn, sizeof(*imp_conn));
	}

	LASSERT(imp->imp_sec == NULL);
	LASSERTF(atomic_read(&imp->imp_reqs) == 0, "%s: imp_reqs = %d\n",
		 imp->imp_obd->obd_name, atomic_read(&imp->imp_reqs));
	class_decref(imp->imp_obd, "import", imp);
	OBD_FREE_PTR(imp);
	EXIT;
}

struct obd_import *class_import_get(struct obd_import *import)
{
	refcount_inc(&import->imp_refcount);
        CDEBUG(D_INFO, "import %p refcount=%d obd=%s\n", import,
	       refcount_read(&import->imp_refcount),
               import->imp_obd->obd_name);
        return import;
}
EXPORT_SYMBOL(class_import_get);

void class_import_put(struct obd_import *imp)
{
	ENTRY;

	LASSERT(refcount_read(&imp->imp_refcount) > 0);

        CDEBUG(D_INFO, "import %p refcount=%d obd=%s\n", imp,
	       refcount_read(&imp->imp_refcount) - 1,
               imp->imp_obd->obd_name);

	if (refcount_dec_and_test(&imp->imp_refcount)) {
                CDEBUG(D_INFO, "final put import %p\n", imp);
                obd_zombie_import_add(imp);
        }

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

static void obd_zombie_imp_cull(struct work_struct *ws)
{
	struct obd_import *import;

	import = container_of(ws, struct obd_import, imp_zombie_work);
	obd_zombie_import_free(import);
}

struct obd_import *class_new_import(struct obd_device *obd)
{
	struct obd_import *imp;
	struct pid_namespace *curr_pid_ns = ll_task_pid_ns(current);

	OBD_ALLOC(imp, sizeof(*imp));
	if (imp == NULL)
		return NULL;

	INIT_LIST_HEAD(&imp->imp_pinger_chain);
	INIT_LIST_HEAD(&imp->imp_replay_list);
	INIT_LIST_HEAD(&imp->imp_sending_list);
	INIT_LIST_HEAD(&imp->imp_delayed_list);
	INIT_LIST_HEAD(&imp->imp_committed_list);
	INIT_LIST_HEAD(&imp->imp_unreplied_list);
	imp->imp_known_replied_xid = 0;
	imp->imp_replay_cursor = &imp->imp_committed_list;
	spin_lock_init(&imp->imp_lock);
	imp->imp_last_success_conn = 0;
	imp->imp_state = LUSTRE_IMP_NEW;
	imp->imp_obd = class_incref(obd, "import", imp);
	rwlock_init(&imp->imp_sec_lock);
	init_waitqueue_head(&imp->imp_recovery_waitq);
	INIT_WORK(&imp->imp_zombie_work, obd_zombie_imp_cull);

	if (curr_pid_ns && curr_pid_ns->child_reaper)
		imp->imp_sec_refpid = curr_pid_ns->child_reaper->pid;
	else
		imp->imp_sec_refpid = 1;

	refcount_set(&imp->imp_refcount, 2);
	atomic_set(&imp->imp_unregistering, 0);
	atomic_set(&imp->imp_reqs, 0);
	atomic_set(&imp->imp_inflight, 0);
	atomic_set(&imp->imp_replay_inflight, 0);
	init_waitqueue_head(&imp->imp_replay_waitq);
	atomic_set(&imp->imp_inval_count, 0);
	INIT_LIST_HEAD(&imp->imp_conn_list);
	init_imp_at(&imp->imp_at);

	/* the default magic is V2, will be used in connect RPC, and
	 * then adjusted according to the flags in request/reply. */
	imp->imp_msg_magic = LUSTRE_MSG_MAGIC_V2;

	return imp;
}
EXPORT_SYMBOL(class_new_import);

void class_destroy_import(struct obd_import *import)
{
	LASSERT(import != NULL);
	LASSERT(import != LP_POISON);

	spin_lock(&import->imp_lock);
	import->imp_generation++;
	spin_unlock(&import->imp_lock);
	class_import_put(import);
}
EXPORT_SYMBOL(class_destroy_import);

#if LUSTRE_TRACKS_LOCK_EXP_REFS

void __class_export_add_lock_ref(struct obd_export *exp, struct ldlm_lock *lock)
{
	spin_lock(&exp->exp_locks_list_guard);

        LASSERT(lock->l_exp_refs_nr >= 0);

        if (lock->l_exp_refs_target != NULL &&
            lock->l_exp_refs_target != exp) {
                LCONSOLE_WARN("setting export %p for lock %p which already has export %p\n",
                              exp, lock, lock->l_exp_refs_target);
        }
        if ((lock->l_exp_refs_nr ++) == 0) {
		list_add(&lock->l_exp_refs_link, &exp->exp_locks_list);
                lock->l_exp_refs_target = exp;
        }
        CDEBUG(D_INFO, "lock = %p, export = %p, refs = %u\n",
               lock, exp, lock->l_exp_refs_nr);
	spin_unlock(&exp->exp_locks_list_guard);
}
EXPORT_SYMBOL(__class_export_add_lock_ref);

void __class_export_del_lock_ref(struct obd_export *exp, struct ldlm_lock *lock)
{
	spin_lock(&exp->exp_locks_list_guard);
        LASSERT(lock->l_exp_refs_nr > 0);
        if (lock->l_exp_refs_target != exp) {
                LCONSOLE_WARN("lock %p, "
                              "mismatching export pointers: %p, %p\n",
                              lock, lock->l_exp_refs_target, exp);
        }
        if (-- lock->l_exp_refs_nr == 0) {
		list_del_init(&lock->l_exp_refs_link);
                lock->l_exp_refs_target = NULL;
        }
        CDEBUG(D_INFO, "lock = %p, export = %p, refs = %u\n",
               lock, exp, lock->l_exp_refs_nr);
	spin_unlock(&exp->exp_locks_list_guard);
}
EXPORT_SYMBOL(__class_export_del_lock_ref);
#endif

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

	CDEBUG(D_IOCTL, "connect: client %s, cookie %#llx\n",
               cluuid->uuid, conn->cookie);
        RETURN(0);
}
EXPORT_SYMBOL(class_connect);

/* if export is involved in recovery then clean up related things */
static void class_export_recovery_cleanup(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;

	spin_lock(&obd->obd_recovery_task_lock);
	if (obd->obd_recovering) {
		if (exp->exp_in_recovery) {
			spin_lock(&exp->exp_lock);
			exp->exp_in_recovery = 0;
			spin_unlock(&exp->exp_lock);
			LASSERT_ATOMIC_POS(&obd->obd_connected_clients);
			atomic_dec(&obd->obd_connected_clients);
		}

		/* if called during recovery then should update
		 * obd_stale_clients counter,
		 * lightweight exports are not counted */
		if ((exp_connect_flags(exp) & OBD_CONNECT_LIGHTWEIGHT) == 0)
			exp->exp_obd->obd_stale_clients++;
	}
	spin_unlock(&obd->obd_recovery_task_lock);

	spin_lock(&exp->exp_lock);
	/** Cleanup req replay fields */
	if (exp->exp_req_replay_needed) {
		exp->exp_req_replay_needed = 0;

		LASSERT(atomic_read(&obd->obd_req_replay_clients));
		atomic_dec(&obd->obd_req_replay_clients);
	}

	/** Cleanup lock replay data */
	if (exp->exp_lock_replay_needed) {
		exp->exp_lock_replay_needed = 0;

		LASSERT(atomic_read(&obd->obd_lock_replay_clients));
		atomic_dec(&obd->obd_lock_replay_clients);
	}
	spin_unlock(&exp->exp_lock);
}

/* This function removes 1-3 references from the export:
 * 1 - for export pointer passed
 * and if disconnect really need
 * 2 - removing from hash
 * 3 - in client_unlink_export
 * The export pointer passed to this function can destroyed */
int class_disconnect(struct obd_export *export)
{
        int already_disconnected;
        ENTRY;

        if (export == NULL) {
                CWARN("attempting to free NULL export %p\n", export);
                RETURN(-EINVAL);
        }

	spin_lock(&export->exp_lock);
	already_disconnected = export->exp_disconnected;
	export->exp_disconnected = 1;
#ifdef HAVE_SERVER_SUPPORT
	/*  We hold references of export for uuid hash
	 *  and nid_hash and export link at least. So
	 *  it is safe to call rh*table_remove_fast in
	 *  there.
	 */
	obd_nid_del(export->exp_obd, export);
#endif /* HAVE_SERVER_SUPPORT */
	spin_unlock(&export->exp_lock);

        /* class_cleanup(), abort_recovery(), and class_fail_export()
         * all end up in here, and if any of them race we shouldn't
         * call extra class_export_puts(). */
	if (already_disconnected)
                GOTO(no_disconn, already_disconnected);

	CDEBUG(D_IOCTL, "disconnect: cookie %#llx\n",
               export->exp_handle.h_cookie);

        class_export_recovery_cleanup(export);
        class_unlink_export(export);
no_disconn:
        class_export_put(export);
        RETURN(0);
}
EXPORT_SYMBOL(class_disconnect);

/* Return non-zero for a fully connected export */
int class_connected_export(struct obd_export *exp)
{
	int connected = 0;

	if (exp) {
		spin_lock(&exp->exp_lock);
		connected = (exp->exp_conn_cnt > 0) && !exp->exp_failed;
		spin_unlock(&exp->exp_lock);
	}
	return connected;
}
EXPORT_SYMBOL(class_connected_export);

static void class_disconnect_export_list(struct list_head *list,
                                         enum obd_option flags)
{
        int rc;
        struct obd_export *exp;
        ENTRY;

        /* It's possible that an export may disconnect itself, but
         * nothing else will be added to this list. */
	while (!list_empty(list)) {
		exp = list_first_entry(list, struct obd_export,
				       exp_obd_chain);
		/* need for safe call CDEBUG after obd_disconnect */
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

                class_export_get(exp);
                CDEBUG(D_HA, "%s: disconnecting export at %s (%p), "
		       "last request at %lld\n",
                       exp->exp_obd->obd_name, obd_export_nid2str(exp),
                       exp, exp->exp_last_request_time);
                /* release one export reference anyway */
                rc = obd_disconnect(exp);

                CDEBUG(D_HA, "disconnected export at %s (%p): rc %d\n",
                       obd_export_nid2str(exp), exp, rc);
                class_export_put(exp);
        }
        EXIT;
}

void class_disconnect_exports(struct obd_device *obd)
{
	LIST_HEAD(work_list);
	ENTRY;

	/* Move all of the exports from obd_exports to a work list, en masse. */
	spin_lock(&obd->obd_dev_lock);
	list_splice_init(&obd->obd_exports, &work_list);
	list_splice_init(&obd->obd_delayed_exports, &work_list);
	spin_unlock(&obd->obd_dev_lock);

	if (!list_empty(&work_list)) {
                CDEBUG(D_HA, "OBD device %d (%p) has exports, "
                       "disconnecting them\n", obd->obd_minor, obd);
                class_disconnect_export_list(&work_list,
                                             exp_flags_from_obd(obd));
        } else
                CDEBUG(D_HA, "OBD device %d (%p) has no exports\n",
                       obd->obd_minor, obd);
        EXIT;
}
EXPORT_SYMBOL(class_disconnect_exports);

/* Remove exports that have not completed recovery.
 */
void class_disconnect_stale_exports(struct obd_device *obd,
                                    int (*test_export)(struct obd_export *))
{
	LIST_HEAD(work_list);
	struct obd_export *exp, *n;
	int evicted = 0;
	ENTRY;

	spin_lock(&obd->obd_dev_lock);
	list_for_each_entry_safe(exp, n, &obd->obd_exports,
				 exp_obd_chain) {
                /* don't count self-export as client */
                if (obd_uuid_equals(&exp->exp_client_uuid,
                                    &exp->exp_obd->obd_uuid))
                        continue;

		/* don't evict clients which have no slot in last_rcvd
		 * (e.g. lightweight connection) */
		if (exp->exp_target_data.ted_lr_idx == -1)
			continue;

		spin_lock(&exp->exp_lock);
		if (exp->exp_failed || test_export(exp)) {
			spin_unlock(&exp->exp_lock);
			continue;
		}
		exp->exp_failed = 1;
		spin_unlock(&exp->exp_lock);

		list_move(&exp->exp_obd_chain, &work_list);
		evicted++;
		CDEBUG(D_HA, "%s: disconnect stale client %s@%s\n",
		       obd->obd_name, exp->exp_client_uuid.uuid,
		       obd_export_nid2str(exp));
		print_export_data(exp, "EVICTING", 0, D_HA);
	}
	spin_unlock(&obd->obd_dev_lock);

	if (evicted)
		LCONSOLE_WARN("%s: disconnecting %d stale clients\n",
			      obd->obd_name, evicted);

	class_disconnect_export_list(&work_list, exp_flags_from_obd(obd) |
						 OBD_OPT_ABORT_RECOV);
	EXIT;
}
EXPORT_SYMBOL(class_disconnect_stale_exports);

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

	/* need for safe call CDEBUG after obd_disconnect */
	class_export_get(exp);

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
	class_export_put(exp);
}
EXPORT_SYMBOL(class_fail_export);

#ifdef HAVE_SERVER_SUPPORT

static int take_first(struct obd_export *exp, void *data)
{
	struct obd_export **expp = data;

	if (*expp)
		/* already have one */
		return 0;
	if (exp->exp_failed)
		/* Don't want this one */
		return 0;
	if (!refcount_inc_not_zero(&exp->exp_handle.h_ref))
		/* Cannot get a ref on this one */
		return 0;
	*expp = exp;
	return 1;
}

int obd_export_evict_by_nid(struct obd_device *obd, const char *nid)
{
	lnet_nid_t nid_key = libcfs_str2nid((char *)nid);
	struct obd_export *doomed_exp;
	int exports_evicted = 0;

	spin_lock(&obd->obd_dev_lock);
	/* umount has run already, so evict thread should leave
	 * its task to umount thread now */
	if (obd->obd_stopping) {
		spin_unlock(&obd->obd_dev_lock);
		return exports_evicted;
	}
	spin_unlock(&obd->obd_dev_lock);

	doomed_exp = NULL;
	while (obd_nid_export_for_each(obd, nid_key,
				       take_first, &doomed_exp) > 0) {

		LASSERTF(doomed_exp != obd->obd_self_export,
			 "self-export is hashed by NID?\n");

		LCONSOLE_WARN("%s: evicting %s (at %s) by administrative request\n",
			      obd->obd_name,
			      obd_uuid2str(&doomed_exp->exp_client_uuid),
			      obd_export_nid2str(doomed_exp));

		class_fail_export(doomed_exp);
		class_export_put(doomed_exp);
		exports_evicted++;
		doomed_exp = NULL;
	}

	if (!exports_evicted)
		CDEBUG(D_HA,
		       "%s: can't disconnect NID '%s': no exports found\n",
		       obd->obd_name, nid);
	return exports_evicted;
}
EXPORT_SYMBOL(obd_export_evict_by_nid);

int obd_export_evict_by_uuid(struct obd_device *obd, const char *uuid)
{
	struct obd_export *doomed_exp = NULL;
	struct obd_uuid doomed_uuid;
	int exports_evicted = 0;

	spin_lock(&obd->obd_dev_lock);
	if (obd->obd_stopping) {
		spin_unlock(&obd->obd_dev_lock);
		return exports_evicted;
	}
	spin_unlock(&obd->obd_dev_lock);

        obd_str2uuid(&doomed_uuid, uuid);
        if (obd_uuid_equals(&doomed_uuid, &obd->obd_uuid)) {
                CERROR("%s: can't evict myself\n", obd->obd_name);
                return exports_evicted;
        }

	doomed_exp = obd_uuid_lookup(obd, &doomed_uuid);
        if (doomed_exp == NULL) {
                CERROR("%s: can't disconnect %s: no exports found\n",
                       obd->obd_name, uuid);
        } else {
                CWARN("%s: evicting %s at adminstrative request\n",
                       obd->obd_name, doomed_exp->exp_client_uuid.uuid);
                class_fail_export(doomed_exp);
                class_export_put(doomed_exp);
		obd_uuid_del(obd, doomed_exp);
                exports_evicted++;
        }

        return exports_evicted;
}
#endif /* HAVE_SERVER_SUPPORT */

#if LUSTRE_TRACKS_LOCK_EXP_REFS
void (*class_export_dump_hook)(struct obd_export*) = NULL;
EXPORT_SYMBOL(class_export_dump_hook);
#endif

static void print_export_data(struct obd_export *exp, const char *status,
			      int locks, int debug_level)
{
	struct ptlrpc_reply_state *rs;
	struct ptlrpc_reply_state *first_reply = NULL;
	int nreplies = 0;

	spin_lock(&exp->exp_lock);
	list_for_each_entry(rs, &exp->exp_outstanding_replies,
			    rs_exp_list) {
		if (nreplies == 0)
			first_reply = rs;
		nreplies++;
	}
	spin_unlock(&exp->exp_lock);

	CDEBUG(debug_level, "%s: %s %p %s %s %d (%d %d %d) %d %d %d %d: "
	       "%p %s %llu stale:%d\n",
	       exp->exp_obd->obd_name, status, exp, exp->exp_client_uuid.uuid,
	       obd_export_nid2str(exp),
	       refcount_read(&exp->exp_handle.h_ref),
	       atomic_read(&exp->exp_rpc_count),
	       atomic_read(&exp->exp_cb_count),
	       atomic_read(&exp->exp_locks_count),
	       exp->exp_disconnected, exp->exp_delayed, exp->exp_failed,
	       nreplies, first_reply, nreplies > 3 ? "..." : "",
	       exp->exp_last_committed, !list_empty(&exp->exp_stale_list));
#if LUSTRE_TRACKS_LOCK_EXP_REFS
	if (locks && class_export_dump_hook != NULL)
		class_export_dump_hook(exp);
#endif
}

void dump_exports(struct obd_device *obd, int locks, int debug_level)
{
        struct obd_export *exp;

	spin_lock(&obd->obd_dev_lock);
	list_for_each_entry(exp, &obd->obd_exports, exp_obd_chain)
		print_export_data(exp, "ACTIVE", locks, debug_level);
	list_for_each_entry(exp, &obd->obd_unlinked_exports, exp_obd_chain)
		print_export_data(exp, "UNLINKED", locks, debug_level);
	list_for_each_entry(exp, &obd->obd_delayed_exports, exp_obd_chain)
		print_export_data(exp, "DELAYED", locks, debug_level);
	spin_unlock(&obd->obd_dev_lock);
}

void obd_exports_barrier(struct obd_device *obd)
{
	int waited = 2;
	LASSERT(list_empty(&obd->obd_exports));
	spin_lock(&obd->obd_dev_lock);
	while (!list_empty(&obd->obd_unlinked_exports)) {
		spin_unlock(&obd->obd_dev_lock);
		schedule_timeout_uninterruptible(cfs_time_seconds(waited));
		if (waited > 5 && is_power_of_2(waited)) {
			LCONSOLE_WARN("%s is waiting for obd_unlinked_exports "
				      "more than %d seconds. "
				      "The obd refcount = %d. Is it stuck?\n",
				      obd->obd_name, waited,
				      atomic_read(&obd->obd_refcount));
			dump_exports(obd, 1, D_CONSOLE | D_WARNING);
		}
		waited *= 2;
		spin_lock(&obd->obd_dev_lock);
	}
	spin_unlock(&obd->obd_dev_lock);
}
EXPORT_SYMBOL(obd_exports_barrier);

/**
 * Add export to the obd_zombe thread and notify it.
 */
static void obd_zombie_export_add(struct obd_export *exp) {
	atomic_dec(&obd_stale_export_num);
	spin_lock(&exp->exp_obd->obd_dev_lock);
	LASSERT(!list_empty(&exp->exp_obd_chain));
	list_del_init(&exp->exp_obd_chain);
	spin_unlock(&exp->exp_obd->obd_dev_lock);

	queue_work(zombie_wq, &exp->exp_zombie_work);
}

/**
 * Add import to the obd_zombe thread and notify it.
 */
static void obd_zombie_import_add(struct obd_import *imp) {
	LASSERT(imp->imp_sec == NULL);

	queue_work(zombie_wq, &imp->imp_zombie_work);
}

/**
 * wait when obd_zombie import/export queues become empty
 */
void obd_zombie_barrier(void)
{
	flush_workqueue(zombie_wq);
}
EXPORT_SYMBOL(obd_zombie_barrier);


struct obd_export *obd_stale_export_get(void)
{
	struct obd_export *exp = NULL;
	ENTRY;

	spin_lock(&obd_stale_export_lock);
	if (!list_empty(&obd_stale_exports)) {
		exp = list_first_entry(&obd_stale_exports,
				       struct obd_export, exp_stale_list);
		list_del_init(&exp->exp_stale_list);
	}
	spin_unlock(&obd_stale_export_lock);

	if (exp) {
		CDEBUG(D_DLMTRACE, "Get export %p: total %d\n", exp,
		       atomic_read(&obd_stale_export_num));
	}
	RETURN(exp);
}
EXPORT_SYMBOL(obd_stale_export_get);

void obd_stale_export_put(struct obd_export *exp)
{
	ENTRY;

	LASSERT(list_empty(&exp->exp_stale_list));
	if (exp->exp_lock_hash &&
	    atomic_read(&exp->exp_lock_hash->hs_count)) {
		CDEBUG(D_DLMTRACE, "Put export %p: total %d\n", exp,
		       atomic_read(&obd_stale_export_num));

		spin_lock_bh(&exp->exp_bl_list_lock);
		spin_lock(&obd_stale_export_lock);
		/* Add to the tail if there is no blocked locks,
		 * to the head otherwise. */
		if (list_empty(&exp->exp_bl_list))
			list_add_tail(&exp->exp_stale_list,
				      &obd_stale_exports);
		else
			list_add(&exp->exp_stale_list,
				 &obd_stale_exports);

		spin_unlock(&obd_stale_export_lock);
		spin_unlock_bh(&exp->exp_bl_list_lock);
	} else {
		class_export_put(exp);
	}
	EXIT;
}
EXPORT_SYMBOL(obd_stale_export_put);

/**
 * Adjust the position of the export in the stale list,
 * i.e. move to the head of the list if is needed.
 **/
void obd_stale_export_adjust(struct obd_export *exp)
{
	LASSERT(exp != NULL);
	spin_lock_bh(&exp->exp_bl_list_lock);
	spin_lock(&obd_stale_export_lock);

	if (!list_empty(&exp->exp_stale_list) &&
	    !list_empty(&exp->exp_bl_list))
		list_move(&exp->exp_stale_list, &obd_stale_exports);

	spin_unlock(&obd_stale_export_lock);
	spin_unlock_bh(&exp->exp_bl_list_lock);
}
EXPORT_SYMBOL(obd_stale_export_adjust);

/**
 * start destroy zombie import/export thread
 */
int obd_zombie_impexp_init(void)
{
	zombie_wq = cfs_cpt_bind_workqueue("obd_zombid", cfs_cpt_tab,
					   0, CFS_CPT_ANY,
					   cfs_cpt_number(cfs_cpt_tab));

	return IS_ERR(zombie_wq) ? PTR_ERR(zombie_wq) : 0;
}

/**
 * stop destroy zombie import/export thread
 */
void obd_zombie_impexp_stop(void)
{
	destroy_workqueue(zombie_wq);
	LASSERT(list_empty(&obd_stale_exports));
}

/***** Kernel-userspace comm helpers *******/

/* Get length of entire message, including header */
int kuc_len(int payload_len)
{
        return sizeof(struct kuc_hdr) + payload_len;
}
EXPORT_SYMBOL(kuc_len);

/* Get a pointer to kuc header, given a ptr to the payload
 * @param p Pointer to payload area
 * @returns Pointer to kuc header
 */
struct kuc_hdr * kuc_ptr(void *p)
{
        struct kuc_hdr *lh = ((struct kuc_hdr *)p) - 1;
        LASSERT(lh->kuc_magic == KUC_MAGIC);
        return lh;
}
EXPORT_SYMBOL(kuc_ptr);

/* Alloc space for a message, and fill in header
 * @return Pointer to payload area
 */
void *kuc_alloc(int payload_len, int transport, int type)
{
        struct kuc_hdr *lh;
        int len = kuc_len(payload_len);

        OBD_ALLOC(lh, len);
        if (lh == NULL)
                return ERR_PTR(-ENOMEM);

        lh->kuc_magic = KUC_MAGIC;
        lh->kuc_transport = transport;
        lh->kuc_msgtype = type;
        lh->kuc_msglen = len;

        return (void *)(lh + 1);
}
EXPORT_SYMBOL(kuc_alloc);

/* Takes pointer to payload area */
void kuc_free(void *p, int payload_len)
{
        struct kuc_hdr *lh = kuc_ptr(p);
        OBD_FREE(lh, kuc_len(payload_len));
}
EXPORT_SYMBOL(kuc_free);

struct obd_request_slot_waiter {
	struct list_head	orsw_entry;
	wait_queue_head_t	orsw_waitq;
	bool			orsw_signaled;
};

static bool obd_request_slot_avail(struct client_obd *cli,
				   struct obd_request_slot_waiter *orsw)
{
	bool avail;

	spin_lock(&cli->cl_loi_list_lock);
	avail = !!list_empty(&orsw->orsw_entry);
	spin_unlock(&cli->cl_loi_list_lock);

	return avail;
};

/*
 * For network flow control, the RPC sponsor needs to acquire a credit
 * before sending the RPC. The credits count for a connection is defined
 * by the "cl_max_rpcs_in_flight". If all the credits are occpuied, then
 * the subsequent RPC sponsors need to wait until others released their
 * credits, or the administrator increased the "cl_max_rpcs_in_flight".
 */
int obd_get_request_slot(struct client_obd *cli)
{
	struct obd_request_slot_waiter	 orsw;
	int				 rc;

	spin_lock(&cli->cl_loi_list_lock);
	if (cli->cl_rpcs_in_flight < cli->cl_max_rpcs_in_flight) {
		cli->cl_rpcs_in_flight++;
		spin_unlock(&cli->cl_loi_list_lock);
		return 0;
	}

	init_waitqueue_head(&orsw.orsw_waitq);
	list_add_tail(&orsw.orsw_entry, &cli->cl_flight_waiters);
	orsw.orsw_signaled = false;
	spin_unlock(&cli->cl_loi_list_lock);

	rc = l_wait_event_abortable(orsw.orsw_waitq,
				    obd_request_slot_avail(cli, &orsw) ||
				    orsw.orsw_signaled);

	/* Here, we must take the lock to avoid the on-stack 'orsw' to be
	 * freed but other (such as obd_put_request_slot) is using it. */
	spin_lock(&cli->cl_loi_list_lock);
	if (rc != 0) {
		if (!orsw.orsw_signaled) {
			if (list_empty(&orsw.orsw_entry))
				cli->cl_rpcs_in_flight--;
			else
				list_del(&orsw.orsw_entry);
		}
		rc = -EINTR;
	}

	if (orsw.orsw_signaled) {
		LASSERT(list_empty(&orsw.orsw_entry));

		rc = -EINTR;
	}
	spin_unlock(&cli->cl_loi_list_lock);

	return rc;
}
EXPORT_SYMBOL(obd_get_request_slot);

void obd_put_request_slot(struct client_obd *cli)
{
	struct obd_request_slot_waiter *orsw;

	spin_lock(&cli->cl_loi_list_lock);
	cli->cl_rpcs_in_flight--;

	/* If there is free slot, wakeup the first waiter. */
	if (!list_empty(&cli->cl_flight_waiters) &&
	    likely(cli->cl_rpcs_in_flight < cli->cl_max_rpcs_in_flight)) {
		orsw = list_first_entry(&cli->cl_flight_waiters,
					struct obd_request_slot_waiter,
					orsw_entry);
		list_del_init(&orsw->orsw_entry);
		cli->cl_rpcs_in_flight++;
		wake_up(&orsw->orsw_waitq);
	}
	spin_unlock(&cli->cl_loi_list_lock);
}
EXPORT_SYMBOL(obd_put_request_slot);

__u32 obd_get_max_rpcs_in_flight(struct client_obd *cli)
{
	return cli->cl_max_rpcs_in_flight;
}
EXPORT_SYMBOL(obd_get_max_rpcs_in_flight);

int obd_set_max_rpcs_in_flight(struct client_obd *cli, __u32 max)
{
	struct obd_request_slot_waiter *orsw;
	__u32				old;
	int				diff;
	int				i;
	int				rc;

	if (max > OBD_MAX_RIF_MAX || max < 1)
		return -ERANGE;

	CDEBUG(D_INFO, "%s: max = %hu max_mod = %u rif = %u\n",
	       cli->cl_import->imp_obd->obd_name, max,
	       cli->cl_max_mod_rpcs_in_flight, cli->cl_max_rpcs_in_flight);

	if (strcmp(cli->cl_import->imp_obd->obd_type->typ_name,
		   LUSTRE_MDC_NAME) == 0) {
		/* adjust max_mod_rpcs_in_flight to ensure it is always
		 * strictly lower that max_rpcs_in_flight */
		if (max < 2) {
			CERROR("%s: cannot set mdc.*.max_rpcs_in_flight=1\n",
			       cli->cl_import->imp_obd->obd_name);
			return -ERANGE;
		}
		if (max <= cli->cl_max_mod_rpcs_in_flight) {
			rc = obd_set_max_mod_rpcs_in_flight(cli, max - 1);
			if (rc != 0)
				return rc;
		}
	}

	spin_lock(&cli->cl_loi_list_lock);
	old = cli->cl_max_rpcs_in_flight;
	cli->cl_max_rpcs_in_flight = max;
	client_adjust_max_dirty(cli);

	diff = max - old;

	/* We increase the max_rpcs_in_flight, then wakeup some waiters. */
	for (i = 0; i < diff; i++) {
		if (list_empty(&cli->cl_flight_waiters))
			break;

		orsw = list_first_entry(&cli->cl_flight_waiters,
					struct obd_request_slot_waiter,
					orsw_entry);
		list_del_init(&orsw->orsw_entry);
		cli->cl_rpcs_in_flight++;
		wake_up(&orsw->orsw_waitq);
	}
	spin_unlock(&cli->cl_loi_list_lock);

	return 0;
}
EXPORT_SYMBOL(obd_set_max_rpcs_in_flight);

__u16 obd_get_max_mod_rpcs_in_flight(struct client_obd *cli)
{
	return cli->cl_max_mod_rpcs_in_flight;
}
EXPORT_SYMBOL(obd_get_max_mod_rpcs_in_flight);

int obd_set_max_mod_rpcs_in_flight(struct client_obd *cli, __u16 max)
{
	struct obd_connect_data *ocd;
	__u16 maxmodrpcs;
	__u16 prev;

	if (max > OBD_MAX_RIF_MAX || max < 1)
		return -ERANGE;

	ocd = &cli->cl_import->imp_connect_data;
	CDEBUG(D_INFO, "%s: max = %hu flags = %llx, max_mod = %u rif = %u\n",
	       cli->cl_import->imp_obd->obd_name, max, ocd->ocd_connect_flags,
	       ocd->ocd_maxmodrpcs, cli->cl_max_rpcs_in_flight);

	if (max == OBD_MAX_RIF_MAX)
		max = OBD_MAX_RIF_MAX - 1;

	/* Cannot exceed or equal max_rpcs_in_flight.  If we are asked to
	 * increase this value, also bump up max_rpcs_in_flight to match.
	 */
	if (max >= cli->cl_max_rpcs_in_flight) {
		CDEBUG(D_INFO,
		       "%s: increasing max_rpcs_in_flight=%hu to allow larger max_mod_rpcs_in_flight=%u\n",
		       cli->cl_import->imp_obd->obd_name, max + 1, max);
		obd_set_max_rpcs_in_flight(cli, max + 1);
	}

	/* cannot exceed max modify RPCs in flight supported by the server,
	 * but verify ocd_connect_flags is at least initialized first.  If
	 * not, allow it and fix value later in ptlrpc_connect_set_flags().
	 */
	if (!ocd->ocd_connect_flags) {
		maxmodrpcs = cli->cl_max_rpcs_in_flight - 1;
	} else if (ocd->ocd_connect_flags & OBD_CONNECT_MULTIMODRPCS) {
		maxmodrpcs = ocd->ocd_maxmodrpcs;
		if (maxmodrpcs == 0) { /* connection not finished yet */
			maxmodrpcs = cli->cl_max_rpcs_in_flight - 1;
			CDEBUG(D_INFO,
			       "%s: partial connect, assume maxmodrpcs=%hu\n",
			       cli->cl_import->imp_obd->obd_name, maxmodrpcs);
		}
	} else {
		maxmodrpcs = 1;
	}
	if (max > maxmodrpcs) {
		CERROR("%s: can't set max_mod_rpcs_in_flight=%hu higher than ocd_maxmodrpcs=%hu returned by the server at connection\n",
		       cli->cl_import->imp_obd->obd_name,
		       max, maxmodrpcs);
		return -ERANGE;
	}

	spin_lock(&cli->cl_mod_rpcs_lock);

	prev = cli->cl_max_mod_rpcs_in_flight;
	cli->cl_max_mod_rpcs_in_flight = max;

	/* wakeup waiters if limit has been increased */
	if (cli->cl_max_mod_rpcs_in_flight > prev)
		wake_up(&cli->cl_mod_rpcs_waitq);

	spin_unlock(&cli->cl_mod_rpcs_lock);

	return 0;
}
EXPORT_SYMBOL(obd_set_max_mod_rpcs_in_flight);

int obd_mod_rpc_stats_seq_show(struct client_obd *cli,
			       struct seq_file *seq)
{
	unsigned long mod_tot = 0, mod_cum;
	struct timespec64 now;
	int i;

	ktime_get_real_ts64(&now);

	spin_lock(&cli->cl_mod_rpcs_lock);

	seq_printf(seq, "snapshot_time:         %llu.%9lu (secs.nsecs)\n",
		   (s64)now.tv_sec, now.tv_nsec);
	seq_printf(seq, "modify_RPCs_in_flight:  %hu\n",
		   cli->cl_mod_rpcs_in_flight);

	seq_printf(seq, "\n\t\t\tmodify\n");
	seq_printf(seq, "rpcs in flight        rpcs   %% cum %%\n");

	mod_tot = lprocfs_oh_sum(&cli->cl_mod_rpcs_hist);

	mod_cum = 0;
	for (i = 0; i < OBD_HIST_MAX; i++) {
		unsigned long mod = cli->cl_mod_rpcs_hist.oh_buckets[i];
		mod_cum += mod;
		seq_printf(seq, "%d:\t\t%10lu %3u %3u\n",
			   i, mod, pct(mod, mod_tot),
			   pct(mod_cum, mod_tot));
		if (mod_cum == mod_tot)
			break;
	}

	spin_unlock(&cli->cl_mod_rpcs_lock);

	return 0;
}
EXPORT_SYMBOL(obd_mod_rpc_stats_seq_show);

/* The number of modify RPCs sent in parallel is limited
 * because the server has a finite number of slots per client to
 * store request result and ensure reply reconstruction when needed.
 * On the client, this limit is stored in cl_max_mod_rpcs_in_flight
 * that takes into account server limit and cl_max_rpcs_in_flight
 * value.
 * On the MDC client, to avoid a potential deadlock (see Bugzilla 3462),
 * one close request is allowed above the maximum.
 */
static inline bool obd_mod_rpc_slot_avail_locked(struct client_obd *cli,
						 bool close_req)
{
	bool avail;

	/* A slot is available if
	 * - number of modify RPCs in flight is less than the max
	 * - it's a close RPC and no other close request is in flight
	 */
	avail = cli->cl_mod_rpcs_in_flight < cli->cl_max_mod_rpcs_in_flight ||
		(close_req && cli->cl_close_rpcs_in_flight == 0);

	return avail;
}

static inline bool obd_mod_rpc_slot_avail(struct client_obd *cli,
					 bool close_req)
{
	bool avail;

	spin_lock(&cli->cl_mod_rpcs_lock);
	avail = obd_mod_rpc_slot_avail_locked(cli, close_req);
	spin_unlock(&cli->cl_mod_rpcs_lock);
	return avail;
}


/* Get a modify RPC slot from the obd client @cli according
 * to the kind of operation @opc that is going to be sent
 * and the intent @it of the operation if it applies.
 * If the maximum number of modify RPCs in flight is reached
 * the thread is put to sleep.
 * Returns the tag to be set in the request message. Tag 0
 * is reserved for non-modifying requests.
 */
__u16 obd_get_mod_rpc_slot(struct client_obd *cli, __u32 opc)
{
	bool			close_req = false;
	__u16			i, max;

	if (opc == MDS_CLOSE)
		close_req = true;

	do {
		spin_lock(&cli->cl_mod_rpcs_lock);
		max = cli->cl_max_mod_rpcs_in_flight;
		if (obd_mod_rpc_slot_avail_locked(cli, close_req)) {
			/* there is a slot available */
			cli->cl_mod_rpcs_in_flight++;
			if (close_req)
				cli->cl_close_rpcs_in_flight++;
			lprocfs_oh_tally(&cli->cl_mod_rpcs_hist,
					 cli->cl_mod_rpcs_in_flight);
			/* find a free tag */
			i = find_first_zero_bit(cli->cl_mod_tag_bitmap,
						max + 1);
			LASSERT(i < OBD_MAX_RIF_MAX);
			LASSERT(!test_and_set_bit(i, cli->cl_mod_tag_bitmap));
			spin_unlock(&cli->cl_mod_rpcs_lock);
			/* tag 0 is reserved for non-modify RPCs */

			CDEBUG(D_RPCTRACE,
			       "%s: modify RPC slot %u is allocated opc %u, max %hu\n",
			       cli->cl_import->imp_obd->obd_name,
			       i + 1, opc, max);

			return i + 1;
		}
		spin_unlock(&cli->cl_mod_rpcs_lock);

		CDEBUG(D_RPCTRACE, "%s: sleeping for a modify RPC slot "
		       "opc %u, max %hu\n",
		       cli->cl_import->imp_obd->obd_name, opc, max);

		wait_event_idle_exclusive(cli->cl_mod_rpcs_waitq,
					  obd_mod_rpc_slot_avail(cli,
								 close_req));
	} while (true);
}
EXPORT_SYMBOL(obd_get_mod_rpc_slot);

/* Put a modify RPC slot from the obd client @cli according
 * to the kind of operation @opc that has been sent.
 */
void obd_put_mod_rpc_slot(struct client_obd *cli, __u32 opc, __u16 tag)
{
	bool			close_req = false;

	if (tag == 0)
		return;

	if (opc == MDS_CLOSE)
		close_req = true;

	spin_lock(&cli->cl_mod_rpcs_lock);
	cli->cl_mod_rpcs_in_flight--;
	if (close_req)
		cli->cl_close_rpcs_in_flight--;
	/* release the tag in the bitmap */
	LASSERT(tag - 1 < OBD_MAX_RIF_MAX);
	LASSERT(test_and_clear_bit(tag - 1, cli->cl_mod_tag_bitmap) != 0);
	spin_unlock(&cli->cl_mod_rpcs_lock);
	wake_up(&cli->cl_mod_rpcs_waitq);
}
EXPORT_SYMBOL(obd_put_mod_rpc_slot);

