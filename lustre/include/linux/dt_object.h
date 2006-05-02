/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
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
 */

#ifndef __LINUX_DT_OBJECT_H
#define __LINUX_DT_OBJECT_H

/*
 * Sub-class of lu_object with methods common for "data" objects in OST stack.
 *
 * Data objects behave like regular files: you can read/write them, get and
 * set their attributes. Implementation of dt interface is supposed to
 * implement some form of garbage collection, normally reference counting
 * (nlink) based one.
 *
 * Examples: osd (lustre/osd) is an implementation of dt interface.
 */


/*
 * super-class definitions.
 */
#include <linux/lu_object.h>

#include <libcfs/list.h>
#include <libcfs/kp30.h>

struct seq_file;
struct proc_dir_entry;
struct lustre_cfg;

struct thandle;
struct txn_param;
struct dt_device;
struct dt_object;

/*
 * Lock mode for DT objects.
 */
enum dt_lock_mode {
        DT_WRITE_LOCK = 1,
        DT_READ_LOCK  = 2,
};

/*
 * Operations on dt device.
 */
struct dt_device_operations {
        /*
         * Method for getting/setting device wide back stored config data,
         * like last used meta-sequence, etc.
         *
         * XXX this is ioctl()-like interface we want to get rid of.
         */
        int (*dt_config) (struct lu_context *ctx,
                          struct dt_device *dev, const char *name,
                          void *buf, int size, int mode);
        /*
         * Return device-wide statistics.
         */
        int   (*dt_statfs)(struct lu_context *ctx,
                           struct dt_device *dev, struct kstatfs *sfs);
        /*
         * Start transaction, described by @param.
         */
        struct thandle *(*dt_trans_start)(struct lu_context *ctx,
                                          struct dt_device *dev,
                                          struct txn_param *param);
        /*
         * Finish previously started transaction.
         */
        void  (*dt_trans_stop)(struct lu_context *ctx, struct thandle *th);
        /*
         * Return fid of root index object.
         */
        int   (*dt_root_get)(struct lu_context *ctx,
                             struct dt_device *dev, struct lu_fid *f);
        /*
         * Create new object on this device.
         *
         * postcondition: ergo(result == 0, lu_object_exists(ctxt, &dt->do_lu));
         */
        int   (*dt_object_create)(struct lu_context *ctxt, struct dt_object *dt,
                                  struct thandle *th);
        /*
         * Destroy existing object.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*dt_object_destroy)(struct lu_context *ctxt,
                                   struct dt_object *dt, struct thandle *th);
};

/*
 * Per-dt-object operations.
 */
struct dt_object_operations {
        void  (*do_object_lock)(struct lu_context *ctx,
                                struct dt_object *dt, enum dt_lock_mode mode);
        void  (*do_object_unlock)(struct lu_context *ctx,
                                  struct dt_object *dt, enum dt_lock_mode mode);
        /*
         * Note: following ->do_{x,}attr_{set,get}() operations are very
         * similar to ->moo_{x,}attr_{set,get}() operations in struct
         * md_object_operations (see md_object.h). These operations are not in
         * lu_object_operations, because ->do_{x,}attr_set() versions take
         * transaction handle as an argument (this transaction is started by
         * caller). We might factor ->do_{x,}attr_get() into
         * lu_object_operations, but that would break existing symmetry.
         */

        /*
         * Return standard attributes.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*do_attr_get)(struct lu_context *ctxt, struct dt_object *dt,
                             struct lu_attr *attr);
        /*
         * Set standard attributes.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*do_attr_set)(struct lu_context *ctxt, struct dt_object *dt,
                             struct lu_attr *attr, struct thandle *handle);
        /*
         * Return a value of an extended attribute.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*do_xattr_get)(struct lu_context *ctxt, struct dt_object *dt,
                              void *buf, int buf_len, const char *name);
        /*
         * Set value of an extended attribute.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*do_xattr_set)(struct lu_context *ctxt, struct dt_object *dt,
                              void *buf, int buf_len, const char *name,
                              struct thandle *handle);
};

/*
 * Per-dt-object operations on "file body".
 */
struct dt_body_operations {
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int (*dbo_read)(struct lu_context *ctxt, struct dt_object *dt, ...);
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int (*dbo_write)(struct lu_context *ctxt, struct dt_object *dt, ...);
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int (*dbo_truncate)(struct lu_context *ctxt, struct dt_object *dt, ...);
};

/*
 * Per-dt-object operations on object as index.
 */
struct dt_index_operations {
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*dio_index_insert)(struct lu_context *ctxt,
                                  struct dt_object *dt,
                                  struct lu_fid *fid, const char *name,
                                  struct thandle *handle);
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*dio_index_delete)(struct lu_context *ctxt,
                                  struct dt_object *dt,
                                  struct lu_fid *fid, const char *name,
                                  struct thandle *handle);
};

struct dt_device {
	struct lu_device             dd_lu_dev;
	struct dt_device_operations *dd_ops;
};

static inline int lu_device_is_dt(const struct lu_device *d)
{
        return ergo(d != NULL, d->ld_type->ldt_tags & LU_DEVICE_DT);
}

static inline struct dt_device * lu2dt_dev(struct lu_device *l)
{
        LASSERT(lu_device_is_dt(l));
        return container_of0(l, struct dt_device, dd_lu_dev);
}

struct dt_object {
        struct lu_object             do_lu;
	struct dt_object_operations *do_ops;
	struct dt_body_operations   *do_body_ops;
	struct dt_index_operations  *do_index_ops;
};

struct txn_param {
        unsigned int tp_credits;
};

#define TXN_PARAM_INIT(credits) {               \
        .tp_credits = (credits)                 \
}

#define TXN_PARAM(...) ((struct txn_param)TXN_PARAM_INIT(__VA_ARGS__))

#endif /* __LINUX_DT_OBJECT_H */
