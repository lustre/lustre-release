/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Local storage for file/objects with fid generation. Works on top of OSD.
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#ifndef __LOCAL_STORAGE_H
#define __LOCAL_STORAGE_H

#include <dt_object.h>
#include <obd.h>
#include <lustre_fid.h>
#include <lustre_disk.h>

struct ls_device {
	struct dt_device	 ls_top_dev;
	/* all initialized ls_devices on this node linked by this */
	struct list_head	 ls_linkage;
	/* how many handle's reference this local storage */
	struct kref		 ls_refcount;
	/* underlaying OSD device */
	struct dt_device	*ls_osd;
	/* list of all local OID storages */
	struct list_head	 ls_los_list;
	struct mutex		 ls_los_mutex;
};

static inline struct ls_device *dt2ls_dev(struct dt_device *d)
{
	return container_of_safe(d, struct ls_device, ls_top_dev);
}

struct ls_object {
	struct lu_object_header	 ls_header;
	struct dt_object	 ls_obj;
};

static inline struct ls_object *lu2ls_obj(struct lu_object *o)
{
	return container_of_safe(o, struct ls_object, ls_obj.do_lu);
}

static inline struct dt_object *ls_locate(const struct lu_env *env,
					  struct ls_device *ls,
					  const struct lu_fid *fid,
					  const struct lu_object_conf *conf)
{
	return dt_locate_at(env, ls->ls_osd, fid,
			    &ls->ls_top_dev.dd_lu_dev, conf);
}

struct ls_device *ls_device_find_or_init(struct dt_device *dev);
void ls_device_put(const struct lu_env *env, struct ls_device *ls);
struct local_oid_storage *dt_los_find(struct ls_device *ls, __u64 seq);
void dt_los_put(struct local_oid_storage *los);

/* Lustre 2.3 on-disk structure describing local object OIDs storage
 * the structure to be used with any sequence managed by
 * local object library.
 * Obsoleted since 2.4 but is kept for compatibility reasons,
 * see lastid_compat_check() in obdclass/local_storage.c */
struct los_ondisk {
	__u32 lso_magic;
	__u32 lso_next_oid;
};

#define LOS_MAGIC	0xdecafbee

#endif
