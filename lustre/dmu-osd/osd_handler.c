/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_handler.c
 * Top-level entry points into osd module
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Alex Tomas <alex@clusterfs.com>
 * Author: Mike Pershin <tappro@sun.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>

//#include <lvfs.h>
#include <libcfs/libcfs.h>
#include <lustre_fsfilt.h>

#ifndef FALSE
#      define  FALSE   (0)
#endif

#ifndef TRUE
#      define  TRUE    (1)
#endif

/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd_support.h>
/* struct ptlrpc_thread */
#include <lustre_net.h>
/* LUSTRE_OSD_NAME */
#include <obd.h>
/* class_register_type(), class_unregister_type(), class_get_type() */
#include <obd_class.h>
#include <lustre_disk.h>

/* fid_is_local() */
#include <lustre_fid.h>

#include "udmu.h"
#include "udmu_util.h"

#include "osd_internal.h"

#define LUSTRE_ROOT_FID_SEQ     0

#define DMU_PROP_NAME_LABEL     "label"

struct osd_object {
        struct dt_object       oo_dt;
        /*
         * Inode for file system object represented by this osd_object. This
         * inode is pinned for the whole duration of lu_object life.
         *
         * Not modified concurrently (either setup early during object
         * creation, or assigned by osd_object_create() under write lock).
         */
        dmu_buf_t               *oo_db;

        /* protects inode attributes. */
        struct semaphore       oo_guard;
        struct rw_semaphore    oo_sem;

        uint64_t                oo_mode;
        uint64_t                oo_type;
        uint64_t                oo_exist;
};

enum {
        OSD_OI_FID_SMALL,
        OSD_OI_FID_OTHER,
        OSD_OI_FID_NR
};

struct osd_thandle {
        struct thandle          ot_super;
        dmu_tx_t               *ot_tx;
        __u32                   ot_sync:1,
                                ot_assigned:1;
};

static int   osd_root_get      (const struct lu_env *env,
                                struct dt_device *dev, struct lu_fid *f);

static int   lu_device_is_osd  (const struct lu_device *d);
static int   osd_type_init     (struct lu_device_type *t);
static void  osd_type_fini     (struct lu_device_type *t);
static int   osd_object_init   (const struct lu_env *env,
                                struct lu_object *l,
                                const struct lu_object_conf *conf);
static void  osd_object_release(const struct lu_env *env,
                                struct lu_object *l);
static int   osd_object_print  (const struct lu_env *env, void *cookie,
                                lu_printer_t p, const struct lu_object *o);
static struct lu_device *  osd_device_free   (const struct lu_env *env,
                                struct lu_device *m);
static void *osd_key_init      (const struct lu_context *ctx,
                                struct lu_context_key *key);
static void  osd_key_fini      (const struct lu_context *ctx,
                                struct lu_context_key *key, void *data);
static void  osd_key_exit      (const struct lu_context *ctx,
                                struct lu_context_key *key, void *data);
static void  osd_object_init0  (struct osd_object *obj);
static int   osd_device_init   (const struct lu_env *env,
                                struct lu_device *d, const char *,
                                struct lu_device *);
static int   osd_fid_lookup    (const struct lu_env *env,
                                struct osd_object *obj,
                                const struct lu_fid *fid);
static int   osd_index_try     (const struct lu_env *env,
                                struct dt_object *dt,
                                const struct dt_index_features *feat);
static void  osd_conf_get      (const struct lu_env *env,
                                const struct dt_device *dev,
                                struct dt_device_param *param);
static int   osd_trans_stop    (const struct lu_env *env,
                                struct thandle *th);
static int   osd_object_is_root(const struct osd_object *obj);

static struct thandle *osd_trans_create(const struct lu_env *env,
                                       struct dt_device *dt);
static int osd_trans_start(const struct lu_env *env, struct dt_device *d,
                           struct thandle *th);

static struct osd_object  *osd_obj          (const struct lu_object *o);
static struct osd_device  *osd_dev          (const struct lu_device *d);
static struct osd_device  *osd_dt_dev       (const struct dt_device *d);
static struct osd_object  *osd_dt_obj       (const struct dt_object *d);
static struct osd_device  *osd_obj2dev      (const struct osd_object *o);
static struct lu_device   *osd2lu_dev       (struct osd_device *osd);
static struct lu_device   *osd_device_fini  (const struct lu_env *env,
                                             struct lu_device *d);
static struct lu_device   *osd_device_alloc (const struct lu_env *env,
                                             struct lu_device_type *t,
                                             struct lustre_cfg *cfg);
static struct lu_object   *osd_object_alloc (const struct lu_env *env,
                                             const struct lu_object_header *hdr,
                                             struct lu_device *d);

static struct lu_device_type_operations osd_device_type_ops;
static struct lu_device_type            osd_device_type;
static struct lu_object_operations      osd_lu_obj_ops;
static struct obd_ops                   osd_obd_device_ops;
static struct lprocfs_vars              lprocfs_osd_module_vars[];
static struct lprocfs_vars              lprocfs_osd_obd_vars[];
static struct lu_device_operations      osd_lu_ops;
static struct lu_context_key            osd_key;
static struct dt_object_operations      osd_obj_ops;
static struct dt_body_operations        osd_body_ops;
const static struct dt_body_operations  osd_body_ops_new;

static char *osd_object_tag = "osd_object";
static char *root_tag = "osd_mount, rootdb";
static char *objdir_tag = "osd_mount, objdb";

static inline int lu_mode2vtype(__u32 mode)
{
        int vtype;

        if (S_ISREG(mode))
                vtype = VREG;
        else if (S_ISDIR(mode))
                vtype = VDIR;
        else if (S_ISCHR(mode))
                vtype = VCHR;
        else if (S_ISSOCK(mode))
                vtype = VSOCK;
        else if (S_ISFIFO(mode))
                vtype = VFIFO;
        else if (S_ISBLK(mode))
                vtype = VBLK;
        else if (S_ISLNK(mode))
                vtype = VLNK;
        else
                vtype = VNON;
        return vtype;
}

static void lu_attr2vnattr(struct lu_attr *la, vnattr_t *vap)
{
        ENTRY;

        vap->va_mask = 0;

        if (la->la_valid & LA_MODE) {
                /* get mode only */
                vap->va_mode = la->la_mode & ~S_IFMT;
                vap->va_mask |= DMU_AT_MODE;

                vap->va_type = lu_mode2vtype(la->la_mode);
                vap->va_mask |= DMU_AT_TYPE;

        }
        if (la->la_valid & LA_UID) {
                vap->va_uid = la->la_uid;
                vap->va_mask |= DMU_AT_UID;
        }
        if (la->la_valid & LA_GID) {
                vap->va_gid = la->la_gid;
                vap->va_mask |= DMU_AT_GID;
        }
        if (la->la_valid & LA_ATIME) {
                vap->va_atime.tv_sec = la->la_atime;
                vap->va_atime.tv_nsec = 0;
                vap->va_mask |= DMU_AT_ATIME;
        }
        if (la->la_valid & LA_MTIME) {
                vap->va_mtime.tv_sec = la->la_mtime;
                vap->va_mtime.tv_nsec = 0;
                vap->va_mask |= DMU_AT_MTIME;
        }
        if (la->la_valid & LA_CTIME) {
                vap->va_ctime.tv_sec = la->la_ctime;
                vap->va_ctime.tv_nsec = 0;
                vap->va_mask |= DMU_AT_CTIME;
        }

        if (la->la_valid & LA_SIZE) {
                vap->va_size = la->la_size;
                vap->va_mask |= DMU_AT_SIZE;
        }

        if (la->la_valid & LA_RDEV) {
                vap->va_rdev = la->la_rdev;
                vap->va_mask |= DMU_AT_RDEV;
        }

        if (la->la_valid & LA_NLINK) {
                vap->va_nlink = la->la_nlink ;
                vap->va_mask |= DMU_AT_NLINK;
        }

#if 0
        if (la->la_valid & LA_FLAGS) {
                vap->va_flags = (la->la_flags & 
                                 (LUSTRE_APPEND_FL | LUSTRE_IMMUTABLE_FL));
                vap->va_mask |= DMU_AT_FLAGS;
        }
#endif

        EXIT;
}

static inline __u32 vtype2lu_mode(vtype_t vt)
{
        if (vt == VREG)
                return S_IFREG;
        else if (vt == VDIR)
                return S_IFDIR;
        else if (vt == VBLK)
                return S_IFBLK;
        else if (vt == VCHR)
                return S_IFCHR;
        else if (vt == VLNK)
                return S_IFLNK;
        else if (vt == VFIFO)
                return S_IFIFO;
        else if (vt == VSOCK)
                return S_IFSOCK;
        else
                return 0;
}

static void vnattr2lu_attr(vnattr_t *vap, struct lu_attr *la)
{
        la->la_valid = 0;

        if (vap->va_mask & DMU_AT_SIZE) {
                la->la_size = (unsigned long long)vap->va_size;
                la->la_valid |= LA_SIZE;
        }
        if (vap->va_mask & DMU_AT_MTIME) {
                la->la_mtime = (unsigned long long)vap->va_mtime.tv_sec;
                la->la_valid |= LA_MTIME;
        }
        if (vap->va_mask & DMU_AT_CTIME) {
                la->la_ctime = (unsigned long long)vap->va_ctime.tv_sec;
                la->la_valid |= LA_CTIME;
        }
        if (vap->va_mask & DMU_AT_ATIME) {
                la->la_atime = (unsigned long long)vap->va_atime.tv_sec;
                la->la_valid |= LA_ATIME;
        }
        if (vap->va_mask & DMU_AT_MODE) {
                la->la_mode = (unsigned int)vap->va_mode;
                la->la_valid |= LA_MODE;
        }
        if (vap->va_mask & DMU_AT_TYPE) {
                la->la_mode |= vtype2lu_mode(vap->va_type);
                la->la_valid |= LA_TYPE;
        }
        if (vap->va_mask & DMU_AT_UID) {
                la->la_uid = vap->va_uid;
                la->la_valid |= LA_UID;
        }
        if (vap->va_mask & DMU_AT_GID) {
                la->la_gid = vap->va_gid;
                la->la_valid |= LA_GID;
        }
        if (vap->va_mask & DMU_AT_NLINK) {
                la->la_nlink = vap->va_nlink;
                la->la_valid |= LA_NLINK;
        }
        if (vap->va_mask & DMU_AT_BLKSIZE) {
                la->la_blksize = vap->va_blksize;
                /* XXX: if 0 then blksize != power of 2 */
                la->la_blkbits = vap->va_blkbits;
                la->la_valid |= LA_BLKSIZE;
        }
        if (vap->va_mask & DMU_AT_RDEV) {
                la->la_rdev = vap->va_rdev;
                la->la_valid |= LA_RDEV;
        }
        if (vap->va_mask & DMU_AT_NBLOCKS) {
                la->la_blocks = vap->va_nblocks;
                la->la_valid |= LA_BLOCKS;
        }
#if 0
        if (vap->va_mask & DMU_AT_FLAGS) {
                la->la_flags  = vap->va_flags;
                la->la_valid |= LA_FLAGS;
        }
#endif

}

/* XXX: f_ver is not counted, but may differ too */
static void osd_fid2str(char *buf, const struct lu_fid *fid)
{
        LASSERT(fid->f_seq != LUSTRE_ROOT_FID_SEQ);
        sprintf(buf, "%llx-%x", fid->f_seq, fid->f_oid);
}

/*
 * Invariants, assertions.
 */

static int osd_invariant(const struct osd_object *obj)
{
        return 1;
}

static inline struct osd_thread_info *osd_oti_get(const struct lu_env *env)
{
        return lu_context_key_get(&env->le_ctx, &osd_key);
}

/*
 * Concurrency: doesn't access mutable data
 */
static int osd_root_get(const struct lu_env *env,
                        struct dt_device *dev, struct lu_fid *f)
{
        f->f_seq = LUSTRE_ROOT_FID_SEQ;
        f->f_oid = udmu_object_get_id(osd_dt_dev(dev)->od_root_db);
        f->f_ver = 0;

        return 0;
}

/*
 * OSD object methods.
 */

/*
 * Concurrency: no concurrent access is possible that early in object
 * life-cycle.
 */
static struct lu_object *osd_object_alloc(const struct lu_env *env,
                                          const struct lu_object_header *hdr,
                                          struct lu_device *d)
{
        struct osd_object *mo;

        OBD_ALLOC_PTR(mo);
        if (mo != NULL) {
                struct lu_object *l;

                l = &mo->oo_dt.do_lu;
                dt_object_init(&mo->oo_dt, NULL, d);
                mo->oo_dt.do_ops = &osd_obj_ops;
                l->lo_ops = &osd_lu_obj_ops;
                init_rwsem(&mo->oo_sem);
                sema_init(&mo->oo_guard, 1);
                return l;
        } else
                return NULL;
}

/*
 * Concurrency: shouldn't matter.
 */
static void osd_object_init0(struct osd_object *obj)
{
        const struct lu_fid *fid  = lu_object_fid(&obj->oo_dt.do_lu);
        vnattr_t va;
        ENTRY;

        if (obj->oo_db != NULL) {
                /* object exist */
                udmu_object_getattr(obj->oo_db, &va);
                obj->oo_mode = va.va_mode;
                obj->oo_dt.do_body_ops = &osd_body_ops;
                obj->oo_dt.do_lu.lo_header->loh_attr |=
                        (LOHA_EXISTS | (obj->oo_mode & S_IFMT));
                /* add type infor to attr */
                obj->oo_dt.do_lu.lo_header->loh_attr |=
                        vtype2lu_mode(va.va_type);
        } else {
                CDEBUG(D_OTHER, "object %llu:%lu does not exist\n",
                        fid->f_seq, (unsigned long) fid->f_oid);
        }
}

/*
 * Concurrency: no concurrent access is possible that early in object
 * life-cycle.
 */
static int osd_object_init(const struct lu_env *env, struct lu_object *l,
                           const struct lu_object_conf *conf)
{
        struct osd_object *obj = osd_obj(l);
        int result;
        ENTRY;

        LASSERT(osd_invariant(obj));

        result = osd_fid_lookup(env, obj, lu_object_fid(l));
        if (result == 0)
                osd_object_init0(obj);
        else if (result == -ENOENT)
                result = 0;
        LASSERT(osd_invariant(obj));
        RETURN(result);
}

/*
 * Concurrency: no concurrent access is possible that late in object
 * life-cycle.
 */
static void osd_object_free(const struct lu_env *env, struct lu_object *l)
{
        struct osd_object *obj = osd_obj(l);

        LASSERT(osd_invariant(obj));

        dt_object_fini(&obj->oo_dt);
        OBD_FREE_PTR(obj);
}

enum {
        OSD_TXN_OI_DELETE_CREDITS    = 20,
        OSD_TXN_INODE_DELETE_CREDITS = 20
};

static void osd_declare_object_delete(const struct lu_env *env,
                                       struct osd_object *obj,
                                       struct thandle *handle)
{
        struct osd_device *osd = osd_obj2dev(obj);
        struct dt_object *dt = &obj->oo_dt;
        struct osd_thandle *oh;
        uint64_t zapid;
        char buf[32];
        ENTRY;

        LASSERT(handle != NULL);
        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_tx != NULL);

        udmu_declare_object_delete(&osd->od_objset, oh->ot_tx, obj->oo_db);

        /* declare that we'll remove object from fid-dnode mapping */
        osd_fid2str(buf, lu_object_fid(&obj->oo_dt.do_lu));
        zapid = udmu_object_get_id(osd->od_objdir_db);
        udmu_tx_hold_zap(oh->ot_tx, zapid, 0, buf);

        EXIT;
}

/*
 * Called just before object is freed. Releases all resources except for
 * object itself (that is released by osd_object_free()).
 *
 * Concurrency: no concurrent access is possible that late in object
 * life-cycle.
 */
static int osd_object_destroy(const struct lu_env *env, struct osd_object *obj)
{
        struct osd_device *osd = osd_obj2dev(obj);
        dmu_buf_t *zapdb = osd->od_objdir_db;
        struct dt_object *dt = &obj->oo_dt;
        struct osd_thandle *oh;
        uint64_t zapid, oid;
        char buf[32];
        vnattr_t va;
        int rc;
        struct thandle         *th;

        ENTRY;
        LASSERT(obj->oo_db != NULL);
        LASSERT(zapdb != NULL);

        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));

        zapid = udmu_object_get_id(zapdb);
        oid = udmu_object_get_id(obj->oo_db);
        osd_fid2str(buf, lu_object_fid(&obj->oo_dt.do_lu));

        udmu_object_getattr(obj->oo_db, &va);

        /* create tx */
        th = osd_trans_create(env, &osd->od_dt_dev);
        if (IS_ERR(th))
                RETURN (PTR_ERR(th));

        oh = container_of0(th, struct osd_thandle, ot_super);
        LASSERT(oh != NULL);
        LASSERT(oh->ot_tx != NULL);

        /* declare changes */
        osd_declare_object_delete(env, obj, th);

        /* start change */
        rc = osd_trans_start(env, &osd->od_dt_dev, th);
        if (rc) {
                CERROR("osd_trans_start() failed with error %d\n", rc);
                GOTO(out, rc);
        }

        /* remove obj ref from main obj. dir */
        rc = udmu_zap_delete(&osd->od_objset, zapdb, oh->ot_tx, buf);
        if (rc) {
                CERROR("udmu_zap_delete() failed with error %d\n", rc);
                GOTO(out, rc);
        }

        /* kill object */
        rc = udmu_object_delete(&osd->od_objset, &obj->oo_db,
                                oh->ot_tx, osd_object_tag);
        if (rc) {
                CERROR("udmu_object_delete() failed with error %d\n", rc);
                GOTO(out, rc);
        }

out:
        /* COMMIT changes */
        osd_trans_stop(env, th);
        
        udmu_object_put_dmu_buf(obj->oo_db, osd_object_tag);
        obj->oo_db = NULL;

        CDEBUG(D_OTHER, "destroy object %s (objid %llu)\n", buf, va.va_nodeid);
        RETURN (0);
}

static void osd_object_delete(const struct lu_env *env, struct lu_object *l)
{
        struct osd_object *obj    = osd_obj(l);
        int rc;

        if (obj->oo_db != NULL) {
                if (udmu_object_get_links(obj->oo_db) == 0) {
                        rc = osd_object_destroy(env, obj);
                        if (rc) {
                                CERROR("destroy error %d", rc);
                        }
                } else {
                        udmu_object_put_dmu_buf(obj->oo_db, osd_object_tag);
                        obj->oo_db = NULL;
                }
        }
}

/*
 * Concurrency: ->loo_object_release() is called under site spin-lock.
 */
static void osd_object_release(const struct lu_env *env,
                               struct lu_object *l)
{
        struct osd_object *obj = osd_obj(l);

        LASSERT(!lu_object_is_dying(l->lo_header));
        if (obj->oo_db && udmu_object_get_links(obj->oo_db) == 0)
                set_bit(LU_OBJECT_HEARD_BANSHEE, &l->lo_header->loh_flags);
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *l)
{
        struct osd_object *o = osd_obj(l);

        return (*p)(env, cookie, LUSTRE_ZFS_NAME"-object@%p", o);
}

/*
 * Concurrency: shouldn't matter.
 */
int osd_statfs(const struct lu_env *env, struct dt_device *d, struct kstatfs *sfs)
{
        struct osd_device *osd = osd_dt_dev(d);
        struct kstatfs *kfs = &osd->od_kstatfs;
        int rc = 0;

        spin_lock(&osd->od_osfs_lock);
        /* cache 1 second */
        if (cfs_time_before_64(osd->od_osfs_age, cfs_time_shift_64(-1))) {
                rc = udmu_objset_statfs(&osd->od_objset, (struct statfs64 *) kfs);

               /* Reserve 64MB for ZFS COW symantics so that grants won't
                * consume all available space. COW needs space to duplicate
                * the block tree even just to delete a file. If filesystem
                * size is  greater than 128MB, we reserve 64MB, if less than
                * 128MB but more than 64MB, we try to reserve 8MB,
                * otherwise we reserve 1MB. 
                */
                if ((kfs->f_blocks * kfs->f_frsize) >= (2*DMU_RESERVED_MAX)) {
                        kfs->f_blocks -= (DMU_RESERVED_MAX/kfs->f_bsize);
                } else if ((kfs->f_bsize * kfs->f_frsize) > DMU_RESERVED_MAX) {
                        kfs->f_blocks -= ((8 * DMU_RESERVED_MIN)/kfs->f_bsize);
                } else {
                        kfs->f_blocks -= (DMU_RESERVED_MIN/kfs->f_bsize);
                }
        }
        *sfs = *kfs;
        spin_unlock(&osd->od_osfs_lock);

        RETURN (rc);
}

/*
 * Concurrency: doesn't access mutable data.
 */
static void osd_conf_get(const struct lu_env *env,
                         const struct dt_device *dev,
                         struct dt_device_param *param)
{
        /*
         * XXX should be taken from not-yet-existing fs abstraction layer.
         */
        param->ddp_max_name_len  = 256;
        param->ddp_max_nlink     = 256;
        param->ddp_block_shift   = 12; /* XXX */
        /* XXX: remove when new llog/mountconf over osd are ready -bzzz */
        param->ddp_mnt           = NULL;
        param->ddp_mount_type    = LDD_MT_ZFS;
}

/*
 * Journal
 */

/*
 * Concurrency: shouldn't matter.
 */
static void osd_trans_commit_cb(void *cb_data, int error)
{
        struct osd_thandle *oh = cb_data;
        struct thandle     *th = &oh->ot_super;
        struct dt_device   *dev = th->th_dev;

        ENTRY;
        LASSERT(dev != NULL);

        if (error) {
                if (error == ECANCELED)
                        CWARN("transaction @0x%p was aborted\n", th);
                else
                        CERROR("transaction @0x%p commit error: %d\n",
                               th, error);
        } else {
                /*
                 * This od_env_for_commit is only for commit usage.  see
                 * "struct dt_device"
                 */
                lu_context_enter(&osd_dt_dev(dev)->od_env_for_commit.le_ctx);
                dt_txn_hook_commit(&osd_dt_dev(dev)->od_env_for_commit, th);
                lu_context_exit(&osd_dt_dev(dev)->od_env_for_commit.le_ctx);
        }

        lu_device_put(&th->th_dev->dd_lu_dev);
        th->th_dev = NULL;
        lu_context_exit(&th->th_ctx);
        lu_context_fini(&th->th_ctx);
        OBD_FREE_PTR(oh);

        EXIT;
}

static struct thandle *osd_trans_create(const struct lu_env *env,
                                       struct dt_device *dt)
{
        struct osd_device *osd = osd_dt_dev(dt);
        struct osd_thandle *oh;
        struct thandle *th;
        dmu_tx_t *tx;
        int hook_res;
        ENTRY;

        tx = udmu_tx_create(&osd->od_objset);
        if (tx == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        /* alloc callback data */
        OBD_ALLOC_PTR(oh);
        if (oh == NULL) {
                udmu_tx_abort(tx);
                RETURN(ERR_PTR(-ENOMEM));
        }

        oh->ot_tx = tx;
        th = &oh->ot_super;
        th->th_dev = dt;
        th->th_result = 0;
        lu_device_get(&dt->dd_lu_dev);
        lu_context_init(&th->th_ctx, LCT_TX_HANDLE);
        lu_context_enter(&th->th_ctx);

        hook_res = dt_txn_hook_start(env, dt, th);
        if (hook_res != 0)
                RETURN(ERR_PTR(hook_res));

        RETURN(th);
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_trans_start(const struct lu_env *env, struct dt_device *d,
                           struct thandle *th)
{
        struct osd_thandle *oh;
        int rc;
        ENTRY;

        oh = container_of0(th, struct osd_thandle, ot_super);

        /* TODO: hook_start shoud be here, so upper layers will be able to
         * declare own transaction usage */
        rc = udmu_tx_assign(oh->ot_tx, TXG_WAIT);
        if (rc != 0) {
                /* dmu will call commit callback with error code during abort */
                CERROR("can't assign tx: %d\n", rc);
                udmu_tx_abort(oh->ot_tx);
        } else {
                /* add commit callback */
                udmu_tx_cb_register(oh->ot_tx, osd_trans_commit_cb, (void *)oh);
                oh->ot_assigned = 1;
        }

        RETURN(-rc);
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_trans_stop(const struct lu_env *env, struct thandle *th)
{
        struct osd_device  *osd = osd_dt_dev(th->th_dev);
        struct osd_thandle *oh;
        uint64_t txg;
        int result;
        ENTRY;

        oh = container_of0(th, struct osd_thandle, ot_super);

        if (oh->ot_assigned == 0) {
                lu_device_put(&th->th_dev->dd_lu_dev);
                th->th_dev = NULL;
                lu_context_exit(&th->th_ctx);
                lu_context_fini(&th->th_ctx);
                OBD_FREE_PTR(oh);

                RETURN(0);
        }

        result = dt_txn_hook_stop(env, th);
        if (result != 0)
                CERROR("Failure in transaction hook: %d\n", result);

        txg = udmu_get_txg(&osd->od_objset, oh->ot_tx);
        
        udmu_tx_commit(oh->ot_tx);

        /* XXX FIXME XXX - the 'if' statement below seems to be disabled for
         * performance purposes, but this is not correct. We need to implement
         * a way to efficiently write synchronously, possibly using the ZIL.
         *
         * XXX: also note: oh->ot_sync appears not to be properly set at the
         * moment.
         */
        if (1 && oh->ot_sync)
                udmu_wait_txg_synced(&osd->od_objset, txg);

        RETURN(result);
}

/*
 * Concurrency: shouldn't matter.
 */
static int osd_sync(const struct lu_env *env, struct dt_device *d)
{
        struct osd_device  *osd = osd_dt_dev(d);
        CDEBUG(D_HA, "syncing OSD %s\n", LUSTRE_ZFS_NAME);
        udmu_wait_synced(&osd->od_objset, NULL);
        return 0;
}

static int osd_commit_async(const struct lu_env *env, struct dt_device *dev)
{
        CERROR("not implemented yet!\n");
        return 0;
}

/*
 * Concurrency: shouldn't matter.
 */
static void osd_ro(const struct lu_env *env, struct dt_device *d)
{
        struct osd_device  *osd = osd_dt_dev(d);
        ENTRY;

        CERROR("*** setting device %s read-only ***\n", LUSTRE_ZFS_NAME);
        osd->od_rdonly = 1;
        udmu_freeze(&osd->od_objset);

        EXIT;
}

/*
 * Concurrency: serialization provided by callers.
 */
static int osd_init_capa_ctxt(const struct lu_env *env, struct dt_device *d,
                              int mode, unsigned long timeout, __u32 alg,
                              struct lustre_capa_key *keys)
{
        struct osd_device *dev = osd_dt_dev(d);
        ENTRY;

        dev->od_fl_capa = mode;
        dev->od_capa_timeout = timeout;
        dev->od_capa_alg = alg;
        dev->od_capa_keys = keys;
        RETURN(0);
}

static char *osd_label_get(const struct lu_env *env, const struct dt_device *d)
{
        struct osd_device *dev = osd_dt_dev(d);
        int rc;
        ENTRY;

        rc = -udmu_userprop_get_str(&dev->od_objset, DMU_PROP_NAME_LABEL,
                                    dev->od_label, sizeof(dev->od_label));

        if (rc != 0) {
                CERROR("error getting ZFS label: %d\n", rc);
                RETURN(NULL);
        }

        RETURN(&dev->od_label[0]);
}

static int osd_label_set(const struct lu_env *env, const struct dt_device *d,
                         char *name)
{
        struct osd_device *dev = osd_dt_dev(d);
        int rc;
        ENTRY;

        rc = -udmu_userprop_set_str(&dev->od_objset, DMU_PROP_NAME_LABEL, name);

        if (rc == 0) {
                /* rename procfs entry (it's special on the first setup ) */
                osd_procfs_fini(dev);
                osd_procfs_init(dev, name);
        } else
                CERROR("error setting ZFS label to '%s': %d\n", name, rc);

        RETURN(rc);
}

static struct dt_device_operations osd_dt_ops = {
        .dt_root_get       = osd_root_get,
        .dt_statfs         = osd_statfs,
        .dt_trans_create   = osd_trans_create,
        .dt_trans_start    = osd_trans_start,
        .dt_trans_stop     = osd_trans_stop,
        .dt_conf_get       = osd_conf_get,
        .dt_sync           = osd_sync,
        .dt_commit_async   = osd_commit_async,
        .dt_ro             = osd_ro,
        .dt_init_capa_ctxt = osd_init_capa_ctxt,
        .dt_label_get      = osd_label_get,
        .dt_label_set      = osd_label_set
};

static void osd_object_read_lock(const struct lu_env *env,
                                 struct dt_object *dt, unsigned role)
{
        struct osd_object *obj = osd_dt_obj(dt);

        LASSERT(osd_invariant(obj));

        down_read(&obj->oo_sem);
}

static void osd_object_write_lock(const struct lu_env *env,
                                  struct dt_object *dt, unsigned role)
{
        struct osd_object *obj = osd_dt_obj(dt);

        LASSERT(osd_invariant(obj));

        down_write(&obj->oo_sem);
}

static void osd_object_read_unlock(const struct lu_env *env,
                                   struct dt_object *dt)
{
        struct osd_object *obj = osd_dt_obj(dt);

        LASSERT(osd_invariant(obj));
        up_read(&obj->oo_sem);
}

static void osd_object_write_unlock(const struct lu_env *env,
                                    struct dt_object *dt)
{
        struct osd_object *obj = osd_dt_obj(dt);

        LASSERT(osd_invariant(obj));
        up_write(&obj->oo_sem);
}

static int osd_object_write_locked(const struct lu_env *env,
                                   struct dt_object *dt)
{
        struct osd_object *obj = osd_dt_obj(dt);
        int rc = 1;

        LASSERT(osd_invariant(obj));
        
        if (down_write_trylock(&obj->oo_sem)) {
                rc = 0;
                up_write(&obj->oo_sem);
        }
        return rc;
}

static int osd_attr_get(const struct lu_env *env,
                        struct dt_object *dt,
                        struct lu_attr *attr,
                        struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);
        vnattr_t vap;

        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));
        LASSERT(obj->oo_db);

        down(&obj->oo_guard);
        udmu_object_getattr(obj->oo_db, &vap);
        up(&obj->oo_guard);
        vnattr2lu_attr(&vap, attr);

        return 0;
}

static int osd_declare_attr_set(const struct lu_env *env,
                                struct dt_object *dt,
                                const struct lu_attr *attr,
                                struct thandle *handle)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_thandle *oh;
        ENTRY;

        if (!dt_object_exists(dt)) {
                /* XXX: sanity check that object creation is declared */
                RETURN(0);
        }

        LASSERT(handle != NULL);
        LASSERT(osd_invariant(obj));

        oh = container_of0(handle, struct osd_thandle, ot_super);

        udmu_tx_hold_bonus(oh->ot_tx, udmu_object_get_id(obj->oo_db));

        RETURN(0);
}

static int osd_attr_set(const struct lu_env *env, struct dt_object *dt,
                        const struct lu_attr *attr, struct thandle *handle,
                        struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_thandle *oh;
        vnattr_t vap;
        int rc = 0;

        LASSERT(handle != NULL);
        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));
        LASSERT(obj->oo_db);

        oh = container_of0(handle, struct osd_thandle, ot_super);

        lu_attr2vnattr((struct lu_attr *)attr, &vap);
        down(&obj->oo_guard);
        udmu_object_setattr(obj->oo_db, oh->ot_tx, &vap);
        up(&obj->oo_guard);

        RETURN(rc);
}

static int osd_declare_punch(const struct lu_env *env, struct dt_object *dt,
                             __u64 start, __u64 end, struct thandle *handle)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_thandle *oh;
        ENTRY;
        
        oh = container_of0(handle, struct osd_thandle, ot_super);

        /* declare we'll free some blocks ... */
        udmu_tx_hold_free(oh->ot_tx, udmu_object_get_id(obj->oo_db), start, end);

        /* ... and we'll modify size attribute */
        udmu_tx_hold_bonus(oh->ot_tx, udmu_object_get_id(obj->oo_db));

        RETURN(0);
}

static int osd_punch(const struct lu_env *env, struct dt_object *dt,
                     __u64 start, __u64 end, struct thandle *th,
                     struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_device *osd = osd_obj2dev(obj);
        struct osd_thandle *oh;
        __u64 len = start - end;
        vnattr_t vap;
        int rc = 0;
        ENTRY;

        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));

        LASSERT(th != NULL);
        oh = container_of0(th, struct osd_thandle, ot_super);

        udmu_object_getattr(obj->oo_db, &vap);

        /* truncate */
        if (end == OBD_OBJECT_EOF)
                len = 0;

        /* XXX: explain this?
        if (start < vap.va_size)
                udmu_tx_hold_free(tx, udmu_object_get_id(obj->oo_db),
                                  start, len ? len : DMU_OBJECT_END);
         */

        rc = udmu_object_punch(&osd->od_objset, obj->oo_db, oh->ot_tx, start, len);

        /* set new size */
#if 0
        /* XXX: umdu_object_punch set the size already, why to set again? */
        if ((end == OBD_OBJECT_EOF) || (start + end > vap.va_size)) {
                vap.va_mask = DMU_AT_SIZE;
                vap.va_size = start;
                udmu_object_setattr(obj->oo_db, oh->ot_tx, &vap);
        }
#endif
        RETURN(rc);
}

/*
 * Object creation.
 *
 * XXX temporary solution.
 */

static int osd_create_post(struct osd_thread_info *info, struct osd_object *obj,
                           struct lu_attr *attr, struct thandle *th)
{
        obj->oo_exist = 1;
        osd_object_init0(obj);
        return 0;
}

static void osd_ah_init(const struct lu_env *env, struct dt_allocation_hint *ah,
                        struct dt_object *parent, umode_t child_mode)
{
        LASSERT(ah);

        memset(ah, 0, sizeof(*ah));
        ah->dah_parent = parent;
        ah->dah_mode = child_mode;
}

static int osd_declare_object_create(const struct lu_env *env,
                                     struct dt_object *dt,
                                     struct lu_attr *attr,
                                     struct dt_allocation_hint *hint,
                                     struct dt_object_format *dof,
                                     struct thandle *handle)
{
        const struct lu_fid *fid  = lu_object_fid(&dt->do_lu);
        struct osd_object *obj  = osd_dt_obj(dt);
        struct osd_device *osd = osd_obj2dev(obj);
        struct osd_thandle *oh;
        uint64_t zapid;
        char buf[64];
        ENTRY;

        LASSERT(!dt_object_exists(dt));
        LASSERT(dof);

        switch (dof->dof_type) {
                case DFT_REGULAR:
                case DFT_SYM:
                case DFT_NODE:
                        obj->oo_dt.do_body_ops = &osd_body_ops_new;
                        break;
                default:
                        break;
        }

        LASSERT(handle != NULL);
        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_tx != NULL);

        switch (dof->dof_type) {
                case DFT_DIR:
                case DFT_INDEX:
                        /* for zap create */
                        udmu_tx_hold_zap(oh->ot_tx, DMU_NEW_OBJECT, 1, NULL);
                        break;
                case DFT_REGULAR:
                case DFT_SYM:
                case DFT_NODE:
                        /* first, we'll create new object */
                        udmu_tx_hold_bonus(oh->ot_tx, DMU_NEW_OBJECT);
                        break;

                default:
                        LBUG();
                        break;
        }

        /* and we'll add it to fid-dnode mapping */
        osd_fid2str(buf, fid);
        zapid = udmu_object_get_id(osd->od_objdir_db);
        udmu_tx_hold_bonus(oh->ot_tx, zapid);
        udmu_tx_hold_zap(oh->ot_tx, zapid, TRUE, buf);

        RETURN(0);
}


static dmu_buf_t * osd_mkdir(struct osd_thread_info *info, struct osd_device  *osd,
                     struct lu_attr *attr,
                     struct osd_thandle *oh)
{
        dmu_buf_t *db;

        /* XXX: LASSERT(S_ISDIR(attr->la_mode)); */
        udmu_zap_create(&osd->od_objset, &db, oh->ot_tx, osd_object_tag);

        return db;
}

static dmu_buf_t* osd_mkreg(struct osd_thread_info *info, struct osd_device  *osd,
                     struct lu_attr *attr,
                     struct osd_thandle *oh)
{
        dmu_buf_t * db;
        LASSERT(S_ISREG(attr->la_mode));
        udmu_object_create(&osd->od_objset, &db, oh->ot_tx, osd_object_tag);
        return db;
}

static dmu_buf_t* osd_mksym(struct osd_thread_info *info, struct osd_device  *osd,
                     struct lu_attr *attr,
                     struct osd_thandle *oh)
{
        dmu_buf_t * db;

        LASSERT(S_ISLNK(attr->la_mode));
        udmu_object_create(&osd->od_objset, &db, oh->ot_tx, osd_object_tag);
        return db;
}

static dmu_buf_t* osd_mknod(struct osd_thread_info *info, struct osd_device *osd,
                            struct lu_attr *attr, struct osd_thandle *oh)
{
        umode_t    mode = attr->la_mode & (S_IFMT | S_IRWXUGO | S_ISVTX);
        dmu_buf_t *db;
        vnattr_t   vap;

        vap.va_mask = DMU_AT_MODE;
        if (S_ISCHR(mode)) {
                vap.va_type = VCHR;
                vap.va_mask |= DMU_AT_RDEV;
                vap.va_rdev = attr->la_rdev;
        } else if (S_ISBLK(mode)) {
                vap.va_type = VBLK;
                vap.va_mask |= DMU_AT_RDEV;
                vap.va_rdev = attr->la_rdev;
        } else if (S_ISFIFO(mode))
                vap.va_type = VFIFO;
        else if (S_ISSOCK(mode))
                vap.va_type = VSOCK;
        else
                LBUG();

        udmu_object_create(&osd->od_objset, &db, oh->ot_tx, osd_object_tag);

        udmu_object_setattr(db, oh->ot_tx, &vap);

        return db;
}

typedef dmu_buf_t* (*osd_obj_type_f)(struct osd_thread_info *info,
                                     struct osd_device  *osd,
                                     struct lu_attr *attr,
                                     struct osd_thandle *oh);

static osd_obj_type_f osd_create_type_f(enum dt_format_type type)
{
        osd_obj_type_f result;

        switch (type) {
        case DFT_DIR:
        case DFT_INDEX:
                result = osd_mkdir;
                break;
        case DFT_REGULAR:
                result = osd_mkreg;
                break;
        case DFT_SYM:
                result = osd_mksym;
                break;
        case DFT_NODE:
                result = osd_mknod;
                break;
        default:
                LBUG();
                break;
        }
        return result;
}


/*
 * Concurrency: @dt is write locked.
 */
static int osd_object_create(const struct lu_env *env, struct dt_object *dt,
                             struct lu_attr *attr, 
                             struct dt_allocation_hint *hint,
                             struct dt_object_format *dof,
                             struct thandle *th)
{
        const struct lu_fid    *fid  = lu_object_fid(&dt->do_lu);
        struct osd_object      *obj  = osd_dt_obj(dt);
        struct osd_thread_info *info = osd_oti_get(env);
        struct osd_device  *osd = osd_obj2dev(obj);
        dmu_buf_t *zapdb = osd->od_objdir_db;
        struct osd_thandle *oh;
        dmu_buf_t *db;
        uint64_t oid;
        vnattr_t vap;
        char buf[64];
        int rc;

        ENTRY;

        LASSERT(osd->od_objdir_db != NULL);
        LASSERT(osd_invariant(obj));
        LASSERT(!dt_object_exists(dt));
        LASSERT(dof != NULL);

        LASSERT(th != NULL);
        oh = container_of0(th, struct osd_thandle, ot_super);

        /*
         * XXX missing: Quote handling.
         */

        LASSERT(obj->oo_db == NULL);

        osd_fid2str(buf, fid);

        db = osd_create_type_f(dof->dof_type)(info, osd, attr, oh);

        if(IS_ERR(db))
                RETURN(PTR_ERR(th));

        oid = udmu_object_get_id(db);

        /* XXX: zapdb should be replaced with zap-mapping-fids-to-dnode */
        rc = udmu_zap_insert(&osd->od_objset, zapdb, oh->ot_tx, buf,
                             &oid, sizeof (oid));
        if (rc)
                GOTO(out, rc);

        obj->oo_db = db;

        lu_attr2vnattr(attr , &vap);
        udmu_object_setattr(db, oh->ot_tx, &vap);
        udmu_object_getattr(db, &vap);
        vnattr2lu_attr(&vap, attr);

        CDEBUG(D_OTHER, "create object "DFID" (dnode %llu)\n",
               PFID(fid), oid);

        rc = osd_create_post(info, obj, attr, th);

        LASSERT(ergo(rc == 0, dt_object_exists(dt)));
        LASSERT(osd_invariant(obj));
out:
        RETURN(-rc);
}

/**
 * Helper function to pack the fid
 */
void osd_fid_pack(struct osd_fid_pack *pack, const struct lu_fid *fid)
{
        struct lu_fid befider;
        fid_cpu_to_be(&befider, (struct lu_fid *)fid);
        memcpy(pack->fp_area, &befider, sizeof(befider));
        pack->fp_len = sizeof(befider) + 1;
}

int osd_fid_unpack(struct lu_fid *fid, const struct osd_fid_pack *pack)
{
        int result;

        result = 0;
        switch (pack->fp_len) {
        case sizeof *fid + 1:
                memcpy(fid, pack->fp_area, sizeof *fid);
                fid_be_to_cpu(fid, fid);
                break;
        default:
                CERROR("Unexpected packed fid size: %d\n", pack->fp_len);
                result = -EIO;
        }
        return result;
}

#define IT_REC_SIZE 256

struct osd_zap_it {
        zap_cursor_t            *ozi_zc;
        struct osd_object       *ozi_obj;
        struct lustre_capa      *ozi_capa;
        int                      ozi_reset;     /* 1 -- no need to advance */
        char                     ozi_name[NAME_MAX + 1];
        char                     ozi_rec[IT_REC_SIZE];
};

static struct dt_it *osd_zap_it_init(const struct lu_env *env,
                                     struct dt_object *dt,
                                     struct lustre_capa *capa)
{
        struct osd_zap_it       *it;
        struct osd_object       *obj = osd_dt_obj(dt);
        struct osd_device       *osd = osd_obj2dev(obj);
        struct lu_object        *lo  = &dt->do_lu;
        ENTRY;

        /* XXX: check capa ? */

        LASSERT(lu_object_exists(lo));
        LASSERT(obj->oo_db);
        LASSERT(udmu_object_is_zap(obj->oo_db));

        OBD_ALLOC_PTR(it);
        if (it != NULL) {
                if (udmu_zap_cursor_init(&it->ozi_zc, &osd->od_objset,
                                         udmu_object_get_id(obj->oo_db), 0))
                        RETURN(ERR_PTR(-ENOMEM));

                it->ozi_obj = obj;
                it->ozi_capa = capa;
                it->ozi_reset = 1;
                lu_object_get(lo);
                RETURN((struct dt_it *)it);
        }
        RETURN(ERR_PTR(-ENOMEM));
}

static void osd_zap_it_fini(const struct lu_env *env, struct dt_it *di)
{
        struct osd_zap_it *it = (struct osd_zap_it *)di;
        struct osd_object *obj;
        ENTRY;

        LASSERT(it);
        LASSERT(it->ozi_obj);

        obj = it->ozi_obj;

        udmu_zap_cursor_fini(it->ozi_zc);
        lu_object_put(env, &obj->oo_dt.do_lu);

        OBD_FREE_PTR(it);
        EXIT;
}

/**
 *  Move Iterator to record specified by \a key
 *
 *  \param  di      osd iterator
 *  \param  key     key for index
 *
 *  \retval +ve  di points to record with least key not larger than key
 *  \retval  0   di points to exact matched key
 *  \retval -ve  failure
 */

static int osd_zap_it_get(const struct lu_env *env,
                          struct dt_it *di, const struct dt_key *key)
{
        struct osd_zap_it *it = (struct osd_zap_it *)di;
        struct osd_object *obj = it->ozi_obj;
        struct osd_device *osd = osd_obj2dev(obj);
        ENTRY;

        LASSERT(it);
        LASSERT(it->ozi_zc);

        /* XXX: API is broken at the moment */
        LASSERT(((const char *)key)[0] == '\0');

        udmu_zap_cursor_fini(it->ozi_zc);
        if (udmu_zap_cursor_init(&it->ozi_zc, &osd->od_objset,
                                 udmu_object_get_id(obj->oo_db), 0))
                RETURN(-ENOMEM);

        it->ozi_reset = 1;

        RETURN(+1);
}

static void osd_zap_it_put(const struct lu_env *env, struct dt_it *di)
{
        /* PBS: do nothing : ref are incremented at retrive and decreamented
         *      next/finish. */
}


/**
 * to load a directory entry at a time and stored it in
 * iterator's in-memory data structure.
 *
 * \param di, struct osd_it_ea, iterator's in memory structure
 *
 * \retval +ve, iterator reached to end
 * \retval   0, iterator not reached to end
 * \retval -ve, on error
 */
static int osd_zap_it_next(const struct lu_env *env, struct dt_it *di)
{
        struct osd_zap_it *it = (struct osd_zap_it *)di;
        int                rc;
        ENTRY;

        if (it->ozi_reset == 0)
                udmu_zap_cursor_advance(it->ozi_zc);
        it->ozi_reset = 0;

        /* According to current API we need to return error if its last entry.
         * zap_cursor_advance() does return any value. So we need to call retrieve to
         * check if there is any record.
         * We shld make changes to Iterator API to not return status for this API
         * */

        rc = udmu_zap_cursor_retrieve_key(it->ozi_zc, NULL, NAME_MAX);
        if (rc == ENOENT) /* end of dir*/
                RETURN(+1);

        RETURN((-rc));
}

static struct dt_key *osd_zap_it_key(const struct lu_env *env,
                const struct dt_it *di)
{
        struct osd_zap_it *it = (struct osd_zap_it *)di;
        int                rc = 0;
        ENTRY;

        it->ozi_reset = 0;
        rc = udmu_zap_cursor_retrieve_key(it->ozi_zc, it->ozi_name, NAME_MAX + 1);
        if (!rc)
                RETURN((struct dt_key *)it->ozi_name);
        else
                RETURN(ERR_PTR(-rc));
}

static int osd_zap_it_key_size(const struct lu_env *env, const struct dt_it *di)
{
        struct osd_zap_it *it = (struct osd_zap_it *)di;
        int                rc;
        ENTRY;

        it->ozi_reset = 0;
        rc = udmu_zap_cursor_retrieve_key(it->ozi_zc, it->ozi_name, NAME_MAX+1);
        if (!rc)
                RETURN(strlen(it->ozi_name));
        else
                RETURN(-rc);
}

static int osd_zap_it_rec(const struct lu_env *env, const struct dt_it *di,
                          struct lu_dirent *lde, __u32 attr)
{
        struct osd_zap_it   *it = (struct osd_zap_it *)di;
        struct osd_fid_pack  pack;
        int                  bytes_read, rc, namelen;
        ENTRY;

        it->ozi_reset = 0;
        LASSERT(lde);

        lde->lde_attrs = LUDA_FID;
        lde->lde_hash = cpu_to_le64(udmu_zap_cursor_serialize(it->ozi_zc));

        rc = udmu_zap_cursor_retrieve_value(it->ozi_zc, (char *) &pack,
                                            IT_REC_SIZE, &bytes_read);
        if (rc)
                GOTO(out, rc);
        rc = osd_fid_unpack(&lde->lde_fid, &pack);
        LASSERT(rc == 0);
        
        rc = udmu_zap_cursor_retrieve_key(it->ozi_zc, lde->lde_name, NAME_MAX + 1);
        if (rc)
                GOTO(out, rc);

        namelen = strlen(lde->lde_name);
        lde->lde_namelen = cpu_to_le16(namelen);
        lde->lde_reclen = cpu_to_le16(lu_dirent_calc_size(namelen, attr));

out:
        RETURN(-rc);
}

static __u64 osd_zap_it_store(const struct lu_env *env, const struct dt_it *di)
{
        struct osd_zap_it *it = (struct osd_zap_it *)di;

        it->ozi_reset = 0;
        RETURN(udmu_zap_cursor_serialize(it->ozi_zc));
}
/*
 * return status :
 *  rc == 0 -> ok, proceed.
 *  rc >  0 -> end of directory.
 *  rc <  0 -> error.  ( EOVERFLOW  can be masked.)
 */

static int osd_zap_it_load(const struct lu_env *env,
                const struct dt_it *di, __u64 hash)
{
        struct osd_zap_it *it = (struct osd_zap_it *)di;
        struct osd_object *obj = it->ozi_obj;
        struct osd_device *osd = osd_obj2dev(obj);
        int                rc;
        ENTRY;

        udmu_zap_cursor_fini(it->ozi_zc);
        if (udmu_zap_cursor_init(&it->ozi_zc, &osd->od_objset,
                                 udmu_object_get_id(obj->oo_db), hash))
                RETURN(-ENOMEM);
        it->ozi_reset = 0;

        /* same as osd_zap_it_next()*/
        rc = udmu_zap_cursor_retrieve_key(it->ozi_zc, NULL, NAME_MAX + 1);
        if (rc == 0)
                RETURN(+1);

        if (rc == ENOENT) /* end of dir*/
                RETURN(0);

        RETURN(-rc);
}

static int osd_index_lookup(const struct lu_env *env, struct dt_object *dt,
                            struct dt_rec *rec, const struct dt_key *key,
                            struct lustre_capa *capa)
{
        struct osd_object  *obj = osd_dt_obj(dt);
        struct osd_device  *osd = osd_obj2dev(obj);
        struct lu_fid      *fid;
        dmu_buf_t          *zapdb = obj->oo_db;
        uint64_t            oid;
        int                 rc;
        ENTRY;

        LASSERT(udmu_object_is_zap(obj->oo_db));
        fid = (struct lu_fid *) rec;

        /* XXX: to decide on format of / yet */
        if (0 && osd_object_is_root(obj)) {
                rc = udmu_zap_lookup(&osd->od_objset, zapdb, (char *) key, &oid,
                                     sizeof(uint64_t), sizeof(uint64_t));
                if (rc) {
                        RETURN(-rc);
                }

                fid->f_seq = LUSTRE_FID_INIT_OID;
                fid->f_oid = oid; /* XXX: f_oid is 32bit, oid - 64bit */
        } else {
                struct osd_fid_pack pack;

                rc = udmu_zap_lookup(&osd->od_objset, zapdb, (char *) key,
                                     (void *) &pack, sizeof(pack), 1);

                if (rc == 0)
                        osd_fid_unpack(fid, &pack);

        }

        RETURN(rc == 0 ? 1 : -rc);
}

static int osd_declare_index_insert(const struct lu_env *env,
                                    struct dt_object *dt,
                                    const struct dt_rec *rec,
                                    const struct dt_key *key,
                                    struct thandle *th)
{
        struct osd_object *obj = osd_dt_obj(dt);
        uint64_t zapid;
        struct osd_thandle *oh;
        ENTRY;

        LASSERT(th != NULL);
        oh = container_of0(th, struct osd_thandle, ot_super);

        LASSERT(obj->oo_db);
        LASSERT(udmu_object_is_zap(obj->oo_db));

        zapid = udmu_object_get_id(obj->oo_db);

        udmu_tx_hold_bonus(oh->ot_tx, zapid);
        udmu_tx_hold_zap(oh->ot_tx, zapid, TRUE, (char *)key);

        RETURN(0);
}

static int osd_index_insert(const struct lu_env *env, struct dt_object *dt,
                            const struct dt_rec *rec, const struct dt_key *key,
                            struct thandle *th, struct lustre_capa *capa,
                            int ignore_quota)
{
        struct osd_object   *obj = osd_dt_obj(dt);
        struct osd_device   *osd = osd_obj2dev(obj);
        struct osd_thandle  *oh;
        struct osd_fid_pack  pack;
        dmu_buf_t           *zap_db = obj->oo_db;
        int                  rc;
        ENTRY;

        LASSERT(obj->oo_db);
        LASSERT(udmu_object_is_zap(obj->oo_db));

        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));

        LASSERT(th != NULL);
        oh = container_of0(th, struct osd_thandle, ot_super);

        /* XXX: Shouldn't rec be any data and not just a FID?
           If so, rec should have the size of the data and
           a pointer to the data - something like this:
           typedf struct {
                int dt_size;
                void * dt_data;
           } dt_data;
         */

        osd_fid_pack(&pack, (struct lu_fid *) rec);

        /* Insert (key,oid) into ZAP */
        rc = udmu_zap_insert(&osd->od_objset, zap_db, oh->ot_tx,
                             (char *) key, &pack, sizeof(pack));

        RETURN(-rc);
}

static int osd_declare_index_delete(const struct lu_env *env,
                                    struct dt_object *dt,
                                    const struct dt_key *key,
                                    struct thandle *th)
{
        struct osd_object *obj = osd_dt_obj(dt);
        uint64_t zapid;
        struct osd_thandle *oh;
        ENTRY;

        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));

        LASSERT(th != NULL);
        oh = container_of0(th, struct osd_thandle, ot_super);

        LASSERT(obj->oo_db);
        LASSERT(udmu_object_is_zap(obj->oo_db));

        zapid = udmu_object_get_id(obj->oo_db);

        udmu_tx_hold_zap(oh->ot_tx, zapid, TRUE, (char *)key);

        RETURN(0);

}

static int osd_index_delete(const struct lu_env *env, struct dt_object *dt,
                            const struct dt_key *key, struct thandle *th,
                            struct lustre_capa *capa)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_device *osd = osd_obj2dev(obj);
        struct osd_thandle *oh;
        dmu_buf_t *zap_db = obj->oo_db;
        int rc;
        ENTRY;

        LASSERT(obj->oo_db);
        LASSERT(udmu_object_is_zap(obj->oo_db));

        LASSERT(th != NULL);
        oh = container_of0(th, struct osd_thandle, ot_super);

        /* Remove key from the ZAP */
        rc = udmu_zap_delete(&osd->od_objset, zap_db, oh->ot_tx, (char *) key);

        if (rc && rc != ENOENT)
                CERROR("udmu_zap_delete() failed with error %d\n", rc);

        RETURN(-rc);
}

static struct dt_index_operations osd_index_ops = {
        .dio_lookup         = osd_index_lookup,
        .dio_declare_insert = osd_declare_index_insert,
        .dio_insert         = osd_index_insert,
        .dio_declare_delete = osd_declare_index_delete,
        .dio_delete         = osd_index_delete,
        .dio_it     = {
                .init     = osd_zap_it_init,
                .fini     = osd_zap_it_fini,
                .get      = osd_zap_it_get,
                .put      = osd_zap_it_put,
                .next     = osd_zap_it_next,
                .key      = osd_zap_it_key,
                .key_size = osd_zap_it_key_size,
                .rec      = osd_zap_it_rec,
                .store    = osd_zap_it_store,
                .load     = osd_zap_it_load
        }
};

static int osd_index_try(const struct lu_env *env, struct dt_object *dt,
                                const struct dt_index_features *feat)
{
        struct osd_object *obj  = osd_dt_obj(dt);
        LASSERT(obj->oo_db != NULL);
        ENTRY;
        /*
         * XXX: implement support for fixed-size keys sorted with natural
         *      numerical way (not using internal hash value)
         */
        if (udmu_object_is_zap(obj->oo_db))
                dt->do_index_ops = &osd_index_ops;
        RETURN(0);
}

static int osd_declare_object_ref_add(const struct lu_env *env,
                               struct dt_object *dt,
                               struct thandle *th)
{
        return osd_declare_attr_set(env, dt, NULL, th);
}

/*
 * Concurrency: @dt is write locked.
 */
static void osd_object_ref_add(const struct lu_env *env,
                               struct dt_object *dt,
                               struct thandle *handle)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_thandle *oh;
        ENTRY;

        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));

        oh = container_of0(handle, struct osd_thandle, ot_super);

        LASSERT(obj->oo_db != NULL);
        down(&obj->oo_guard);
        udmu_object_links_inc(obj->oo_db, oh->ot_tx);
        up(&obj->oo_guard);
}

static int osd_declare_object_ref_del(const struct lu_env *env,
                                       struct dt_object *dt,
                                       struct thandle *handle)
{
        return osd_declare_attr_set(env, dt, NULL, handle);
}

/*
 * Concurrency: @dt is write locked.
 */
static void osd_object_ref_del(const struct lu_env *env,
                               struct dt_object *dt,
                               struct thandle *handle)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_thandle *oh;
        ENTRY;

        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));

        oh = container_of0(handle, struct osd_thandle, ot_super);

        LASSERT(obj->oo_db != NULL);
        down(&obj->oo_guard);
        udmu_object_links_dec(obj->oo_db, oh->ot_tx);
        up(&obj->oo_guard);
}

int osd_xattr_get(const struct lu_env *env, struct dt_object *dt,
                struct lu_buf *buf, const char *name,
                struct lustre_capa *capa)
{
        struct osd_object  *obj  = osd_dt_obj(dt);
        struct osd_device  *osd = osd_obj2dev(obj);
        int                 rc, size;
        ENTRY;

        LASSERT(obj->oo_db != NULL);
        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));

        down(&obj->oo_guard);
        rc = -udmu_xattr_get(&osd->od_objset, obj->oo_db, buf->lb_buf,
                             buf->lb_len, name, &size);
        up(&obj->oo_guard);

        if (rc == -ENOENT)
                rc = -ENODATA;
        if (rc == 0)
                rc = size;
        
        RETURN(rc);
}

int osd_declare_xattr_set(const struct lu_env *env, struct dt_object *dt,
                          const int buflen, const char *name, int fl,
                          struct thandle *handle)
{
        struct osd_object  *obj = osd_dt_obj(dt);
        struct osd_device  *osd = osd_obj2dev(obj);
        struct osd_thandle *oh;
        ENTRY;

        LASSERT(handle != NULL);
        oh = container_of0(handle, struct osd_thandle, ot_super);

        if (!dt_object_exists(dt)) {
                udmu_tx_hold_bonus(oh->ot_tx, DMU_NEW_OBJECT);
                udmu_tx_hold_bonus(oh->ot_tx, DMU_NEW_OBJECT);
                RETURN(0);
        }

        LASSERT(obj->oo_db != NULL);
        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));

        down(&obj->oo_guard);
        udmu_xattr_declare_set(&osd->od_objset, obj->oo_db, buflen,
                               name, oh->ot_tx);
        up(&obj->oo_guard);

        RETURN(0);
}

int osd_xattr_set(const struct lu_env *env,
                struct dt_object *dt, const struct lu_buf *buf,
                const char *name, int fl, struct thandle *handle,
                struct lustre_capa *capa)
{
        struct osd_object  *obj = osd_dt_obj(dt);
        struct osd_device  *osd = osd_obj2dev(obj);
        struct osd_thandle *oh;
        int rc = 0;
        ENTRY;

        LASSERT(handle != NULL);
        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));
        LASSERT(obj->oo_db);
        
        oh = container_of0(handle, struct osd_thandle, ot_super);

        down(&obj->oo_guard);
        rc = -udmu_xattr_set(&osd->od_objset, obj->oo_db, buf->lb_buf,
                             buf->lb_len, name, oh->ot_tx);
        up(&obj->oo_guard);

        RETURN(rc);
}


int osd_declare_xattr_del(const struct lu_env *env, struct dt_object *dt,
                          const char *name, struct thandle *handle)
{
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_device *osd = osd_obj2dev(obj);
        struct osd_thandle *oh;
        ENTRY;

        LASSERT(handle != NULL);
        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));

        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_tx != NULL);
        LASSERT(obj->oo_db != NULL);

        down(&obj->oo_guard);
        udmu_xattr_declare_del(&osd->od_objset, obj->oo_db, name, oh->ot_tx);
        up(&obj->oo_guard);

        RETURN(0);
}

int osd_xattr_del(const struct lu_env *env, struct dt_object *dt,
                  const char *name, struct thandle *handle,
                  struct lustre_capa *capa)
{
        struct osd_object  *obj = osd_dt_obj(dt);
        struct osd_device  *osd = osd_obj2dev(obj);
        struct osd_thandle *oh;
        int                 rc;
        ENTRY;

        LASSERT(handle != NULL);
        LASSERT(obj->oo_db != NULL);
        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));
        oh = container_of0(handle, struct osd_thandle, ot_super);
        LASSERT(oh->ot_tx != NULL);

        down(&obj->oo_guard);
        rc = -udmu_xattr_del(&osd->od_objset, obj->oo_db, name, oh->ot_tx);
        up(&obj->oo_guard);

        RETURN(rc);
}

int osd_xattr_list(const struct lu_env *env,
                struct dt_object *dt, struct lu_buf *buf,
                struct lustre_capa *capa)
{
        struct osd_object  *obj = osd_dt_obj(dt);
        struct osd_device  *osd = osd_obj2dev(obj);
        int                 rc;
        ENTRY;

        LASSERT(obj->oo_db != NULL);
        LASSERT(osd_invariant(obj));
        LASSERT(dt_object_exists(dt));

        down(&obj->oo_guard);
        rc = udmu_xattr_list(&osd->od_objset, obj->oo_db,
                              buf->lb_buf, buf->lb_len);
        up(&obj->oo_guard);

        RETURN(rc);

}

static int capa_is_sane(const struct lu_env *env,
                        struct osd_device *dev,
                        struct lustre_capa *capa,
                        struct lustre_capa_key *keys)
{
        struct osd_thread_info *oti = osd_oti_get(env);
        struct obd_capa *oc;
        int i, rc = 0;
        ENTRY;

        oc = capa_lookup(dev->od_capa_hash, capa, 0);
        if (oc) {
                if (capa_is_expired(oc)) {
                        DEBUG_CAPA(D_ERROR, capa, "expired");
                        rc = -ESTALE;
                }
                capa_put(oc);
                RETURN(rc);
        }

        spin_lock(&capa_lock);
        for (i = 0; i < 2; i++) {
                if (keys[i].lk_keyid == capa->lc_keyid) {
                        oti->oti_capa_key = keys[i];
                        break;
                }
        }
        spin_unlock(&capa_lock);

        if (i == 2) {
                DEBUG_CAPA(D_ERROR, capa, "no matched capa key");
                RETURN(-ESTALE);
        }

        rc = capa_hmac(oti->oti_capa.lc_hmac, capa, oti->oti_capa_key.lk_key);
        if (rc)
                RETURN(rc);
        if (memcmp(oti->oti_capa.lc_hmac, capa->lc_hmac, sizeof(capa->lc_hmac)))
        {
                DEBUG_CAPA(D_ERROR, capa, "HMAC mismatch");
                LBUG();
                RETURN(-EACCES);
        }

        oc = capa_add(dev->od_capa_hash, capa);
        capa_put(oc);

        RETURN(0);
}

static int osd_object_auth(const struct lu_env *env, struct dt_object *dt,
                           struct lustre_capa *capa, __u64 opc)
{
        const struct lu_fid *fid = lu_object_fid(&dt->do_lu);
        struct osd_device *dev = osd_dev(dt->do_lu.lo_dev);
        int rc;

        if (!dev->od_fl_capa)
                return 0;

        if (capa == BYPASS_CAPA)
                return 0;

        if (!capa) {
                CERROR("no capability is provided for fid "DFID"\n", PFID(fid));
                return -EACCES;
        }

        if (!lu_fid_eq(fid, &capa->lc_fid)) {
                DEBUG_CAPA(D_ERROR, capa, "fid "DFID" mismatch with",
                           PFID(fid));
                return -EACCES;
        }

        if (!capa_opc_supported(capa, opc)) {
                DEBUG_CAPA(D_ERROR, capa, "opc "LPX64" not supported by", opc);
                return -EACCES;
        }

        if ((rc = capa_is_sane(env, dev, capa, dev->od_capa_keys))) {
                DEBUG_CAPA(D_ERROR, capa, "insane (rc %d)", rc);
                return -EACCES;
        }

        return 0;
}

static struct obd_capa *osd_capa_get(const struct lu_env *env,
                                     struct dt_object *dt,
                                     struct lustre_capa *old,
                                     __u64 opc)
{
        struct osd_thread_info *info = osd_oti_get(env);
        const struct lu_fid *fid = lu_object_fid(&dt->do_lu);
        struct osd_object *obj = osd_dt_obj(dt);
        struct osd_device *dev = osd_obj2dev(obj);
        struct lustre_capa_key *key = &info->oti_capa_key;
        struct lustre_capa *capa = &info->oti_capa;
        struct obd_capa *oc;
        int rc;
        ENTRY;

        if (!dev->od_fl_capa)
                RETURN(ERR_PTR(-ENOENT));

        LASSERT(dt_object_exists(dt));
        LASSERT(osd_invariant(obj));

        /* renewal sanity check */
        if (old && osd_object_auth(env, dt, old, opc))
                RETURN(ERR_PTR(-EACCES));

        capa->lc_fid = *fid;
        capa->lc_opc = opc;
        capa->lc_uid = 0;
        capa->lc_flags = dev->od_capa_alg << 24;
        capa->lc_timeout = dev->od_capa_timeout;
        capa->lc_expiry = 0;

        oc = capa_lookup(dev->od_capa_hash, capa, 1);
        if (oc) {
                LASSERT(!capa_is_expired(oc));
                RETURN(oc);
        }

        spin_lock(&capa_lock);
        *key = dev->od_capa_keys[1];
        spin_unlock(&capa_lock);

        capa->lc_keyid = key->lk_keyid;
        capa->lc_expiry = cfs_time_current_sec() + dev->od_capa_timeout;

        rc = capa_hmac(capa->lc_hmac, capa, key->lk_key);
        if (rc) {
                DEBUG_CAPA(D_ERROR, capa, "HMAC failed: %d for", rc);
                LBUG();
                RETURN(ERR_PTR(rc));
        }

        oc = capa_add(dev->od_capa_hash, capa);
        RETURN(oc);
}

static int osd_object_sync(const struct lu_env *env, struct dt_object *dt)
{
        ENTRY;

        /* XXX: not implemented yet, important for COS */

        RETURN(0);
}

static dt_obj_version_t osd_object_version_get(const struct lu_env *env,
                                               struct dt_object *dt)
{
        /* XXX: not implemented yet, important for VBR */
        return 0;
}

/*
 * Set the 64-bit version and return the old version.
 */
static void osd_object_version_set(const struct lu_env *env, struct dt_object *dt,
                                   dt_obj_version_t new_version)
{
        /* XXX: not implemented yet, important for VBR */
        return;
}

static int osd_data_get(const struct lu_env *env, struct dt_object *dt, void **data)
{
        ENTRY;

        /* XXX: not implemented yet, important for quota */
        *data = NULL;
        RETURN(0);
}

static struct dt_object_operations osd_obj_ops = {
        .do_read_lock         = osd_object_read_lock,
        .do_write_lock        = osd_object_write_lock,
        .do_read_unlock       = osd_object_read_unlock,
        .do_write_unlock      = osd_object_write_unlock,
        .do_write_locked      = osd_object_write_locked,
        .do_attr_get          = osd_attr_get,
        .do_declare_attr_set  = osd_declare_attr_set,
        .do_attr_set          = osd_attr_set,
        .do_declare_punch     = osd_declare_punch,
        .do_punch             = osd_punch,
        .do_ah_init           = osd_ah_init,
        .do_index_try         = osd_index_try,
        .do_declare_create    = osd_declare_object_create,
        .do_create            = osd_object_create,
        .do_declare_ref_add   = osd_declare_object_ref_add,
        .do_ref_add           = osd_object_ref_add,
        .do_declare_ref_del   = osd_declare_object_ref_del,
        .do_ref_del           = osd_object_ref_del,
        .do_xattr_get         = osd_xattr_get,
        .do_declare_xattr_set = osd_declare_xattr_set,
        .do_xattr_set         = osd_xattr_set,
        .do_declare_xattr_del = osd_declare_xattr_del,
        .do_xattr_del         = osd_xattr_del,
        .do_xattr_list        = osd_xattr_list,
        .do_capa_get          = osd_capa_get,
        .do_object_sync       = osd_object_sync,
        .do_version_get       = osd_object_version_get,
        .do_version_set       = osd_object_version_set,
        .do_data_get          = osd_data_get,
};

/*
 * Body operations.
 */

/*
 * XXX: Another layering violation for now.
 *
 * We don't want to use ->f_op->read methods, because generic file write
 *
 *         - serializes on ->i_sem, and
 *
 *         - does a lot of extra work like balance_dirty_pages(),
 *
 * which doesn't work for globally shared files like /last-received.
 */
static ssize_t osd_read(const struct lu_env *env, struct dt_object *dt,
                        struct lu_buf *buf, loff_t *pos,
                        struct lustre_capa *capa)
{
        struct osd_object *obj  = osd_dt_obj(dt);
        struct osd_device *osd = osd_obj2dev(obj);
        //loff_t offset = *pos;
        int rc;

        rc = udmu_object_read(&osd->od_objset, obj->oo_db, (uint64_t)(*pos),
                              (uint64_t)buf->lb_len, buf->lb_buf);
        if (rc > 0)
                *pos += rc;//buf->lb_len;

        /* XXX: workaround for bug in HEAD: fsfilt_ldiskfs_read() returns
         * requested number of bytes, not actually read ones */
        if (rc > 0 && S_ISLNK(obj->oo_dt.do_lu.lo_header->loh_attr))
                rc = buf->lb_len;

        return rc;
}

static int osd_declare_write(const struct lu_env *env, struct dt_object *dt,
                             const loff_t size, loff_t pos, struct thandle *th)
{
        struct osd_object *obj  = osd_dt_obj(dt);
        struct osd_thandle *oh;
        uint64_t oid;
        vnattr_t va;
        ENTRY;

        oh = container_of0(th, struct osd_thandle, ot_super);

        if (obj->oo_db) {
                oid = udmu_object_get_id(obj->oo_db);
                udmu_object_getattr(obj->oo_db, &va);
                if (va.va_size < pos + size)
                        udmu_tx_hold_bonus(oh->ot_tx, oid);
        } else {
                oid = DMU_NEW_OBJECT;
        }

        udmu_tx_hold_write(oh->ot_tx, oid, pos, size);

        RETURN(0);
}

static ssize_t osd_write(const struct lu_env *env, struct dt_object *dt,
                         const struct lu_buf *buf, loff_t *pos,
                         struct thandle *th, struct lustre_capa *capa,
                         int ignore_quota)
{
        struct osd_object *obj  = osd_dt_obj(dt);
        struct osd_device *osd = osd_obj2dev(obj);
        struct osd_thandle *oh;
        uint64_t offset = *pos;
        vnattr_t va;
        int rc;
        ENTRY;

        LASSERT(th != NULL);
        oh = container_of0(th, struct osd_thandle, ot_super);
        
        udmu_object_getattr(obj->oo_db, &va);

        udmu_object_write(&osd->od_objset, obj->oo_db, oh->ot_tx, offset,
                          (uint64_t)buf->lb_len, buf->lb_buf);
        if (va.va_size < offset + buf->lb_len) {
                va.va_size = offset + buf->lb_len;
                va.va_mask = DMU_AT_SIZE;
                udmu_object_setattr(obj->oo_db, oh->ot_tx, &va);
        }
        *pos += buf->lb_len;
        rc = buf->lb_len;

        RETURN(rc);
}

static int osd_get_bufs(const struct lu_env *env, struct dt_object *dt,
                        loff_t offset, ssize_t len, struct niobuf_local *_lb,
                        int rw, struct lustre_capa *capa)
{
        struct niobuf_local *lb = _lb;
        //long blocksize;
        //unsigned long tmp;
        int i, plen, npages = 0;

        while (len > 0) {
                plen = len;
                if (plen > CFS_PAGE_SIZE)
                        plen = CFS_PAGE_SIZE;

                lb->file_offset = offset;
                lb->page_offset = 0;
                lb->len = plen;
                lb->page = NULL;
                lb->rc = 0;
                lb->lnb_grant_used = 0;
                lb->obj = dt;

                offset += plen;
                len -= plen;
                lb++;
                npages++;
        }

        for (i = 0, lb = _lb; i< npages; i++, lb++) {
                lb->page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
                if (lb->page == NULL)
                        goto out_err;
                lu_object_get(&dt->do_lu);
        }


#if 0
        /* calcs for grants */
        udmu_get_blocksize(osd_dt_obj(dt)->oo_db, &blocksize);
        LASSERT(blocksize > 0);
        lb->bytes = len + (offset & (blocksize - 1));
        tmp = (len + offset) & (blocksize - 1);
        if (tmp)
                lb->bytes += blocksize - tmp;

        /* add overhead */
        udmu_indblk_overhead(osd_dt_obj(dt)->oo_db, &lb->bytes, &tmp);
        lb->bytes += tmp;
#endif

        lb->obj = dt;

        return npages;
out_err:
        lb = _lb;
        while (--i >= 0) {
                LASSERT(lb->page);
                lu_object_put(env, &dt->do_lu);
                __free_page(lb->page);
                lb->page = NULL;
        }
        return -ENOMEM;
}

static int osd_put_bufs(const struct lu_env *env, struct dt_object *dt,
                        struct niobuf_local *lb, int npages)
{
        int i;

        for (i = 0; i < npages; i++, lb++) {
                LASSERT(lb->obj == dt);
                if (lb->page == NULL)
                        continue;
                lu_object_put(env, &dt->do_lu);
                __free_page(lb->page);
                lb->page = NULL;
        }

        return 0;
}

static int osd_write_prep(const struct lu_env *env, struct dt_object *dt,
                          struct niobuf_local *lb, int nr,
                          unsigned long *used)
{
        return 0;
}

static int osd_declare_write_commit(const struct lu_env *env,
                                    struct dt_object *dt,
                                    struct niobuf_local *lb, int nr,
                                    struct thandle *th)
{
        struct osd_object  *obj = osd_dt_obj(dt);
        struct osd_thandle *oh;
        uint64_t            offset;
        uint32_t            size;
        uint64_t            oid;
        int                 i;
        ENTRY;

        LASSERT(lb);
        LASSERT(nr > 0);
        LASSERT(lb->obj == dt);

        oh = container_of0(th, struct osd_thandle, ot_super);

        oid = udmu_object_get_id(obj->oo_db);

        offset = lb->file_offset;
        size = lb->len;
        lb++;
        nr--;

        for (i = 0; i < nr; i++, lb++) {
                if (offset + size == lb->file_offset) {
                        size += lb->len;
                        continue;
                }

                udmu_tx_hold_write(oh->ot_tx, oid, offset, size);

                offset = lb->file_offset;
                size = lb->len;
        }

        if (size)
                udmu_tx_hold_write(oh->ot_tx, oid, offset, size);

        udmu_tx_hold_bonus(oh->ot_tx, udmu_object_get_id(obj->oo_db));

        RETURN(0);
}

static int osd_write_commit(const struct lu_env *env, struct dt_object *dt,
                            struct niobuf_local *lb, int nr, struct thandle *th)
{
        struct osd_object  *obj  = osd_dt_obj(dt);
        struct osd_device  *osd = osd_obj2dev(obj);
        struct osd_thandle *oh;
        vnattr_t            va;
        uint64_t            new_size = 0;
        int                 i;
        ENTRY;

        LASSERT(th != NULL);
        oh = container_of0(th, struct osd_thandle, ot_super);
        
        for (i = 0; i < nr; i++, lb++) {
                CDEBUG(D_OTHER, "write %u bytes at %u\n", (unsigned) lb->len,
                       (unsigned) lb->file_offset);

                udmu_object_write(&osd->od_objset, obj->oo_db, oh->ot_tx,
                                  lb->file_offset, lb->len, kmap(lb->page));
                kunmap(lb->page);
                if (new_size < lb->file_offset + lb->len)
                        new_size = lb->file_offset + lb->len;

                lb->rc = lb->len;
        }

        udmu_object_getattr(obj->oo_db, &va);
        if (va.va_size < new_size) {
                va.va_size = new_size;
                va.va_mask = DMU_AT_SIZE;
                udmu_object_setattr(obj->oo_db, oh->ot_tx, &va);
        }

        RETURN(0);
}

static int osd_read_prep(const struct lu_env *env, struct dt_object *dt,
                          struct niobuf_local *lb, int nr)
{
        struct lu_buf buf;
        loff_t offset;
        int i;

        for (i = 0; i < nr; i++, lb++) {
                buf.lb_buf = kmap(lb->page);
                buf.lb_len = lb->len;
                offset = lb->file_offset;

                CDEBUG(D_OTHER, "read %u bytes at %u\n", (unsigned) lb->len,
                       (unsigned) lb->file_offset);
                lb->rc = osd_read(env, dt, &buf, &offset, NULL);
                kunmap(lb->page);

                if (lb->rc < buf.lb_len) {
                        /* all subsequent rc should be 0 */
                        while (++i < nr) {
                                lb++;
                                lb->rc = 0;
                        }
                        break;
                }
        }

        return 0;
}

const static struct dt_body_operations osd_body_ops_new = {
        .dbo_declare_write = osd_declare_write,
};

static struct dt_body_operations osd_body_ops = {
        .dbo_read                 = osd_read,
        .dbo_declare_write        = osd_declare_write,
        .dbo_write                = osd_write,
        .dbo_get_bufs             = osd_get_bufs,
        .dbo_put_bufs             = osd_put_bufs,
        .dbo_write_prep           = osd_write_prep,
        .dbo_declare_write_commit = osd_declare_write_commit,
        .dbo_write_commit         = osd_write_commit,
        .dbo_read_prep            = osd_read_prep,
};

/*
 * Index operations.
 */

static int osd_object_is_root(const struct osd_object *obj)
{
        const struct lu_fid *fid = lu_object_fid(&obj->oo_dt.do_lu);
        struct osd_device       *dev = osd_obj2dev(obj);

        return (fid->f_seq == LUSTRE_ROOT_FID_SEQ &&
                fid->f_oid == udmu_object_get_id(dev->od_root_db) ? 1 : 0);
}

/*
 * DMU OSD device type methods
 */
static int osd_type_init(struct lu_device_type *t)
{
        LU_CONTEXT_KEY_INIT(&osd_key);
        return lu_context_key_register(&osd_key);
}

static void osd_type_fini(struct lu_device_type *t)
{
        lu_context_key_degister(&osd_key);
}

static struct lu_context_key osd_key = {
        .lct_tags = LCT_DT_THREAD | LCT_MD_THREAD,
        .lct_init = osd_key_init,
        .lct_fini = osd_key_fini,
        .lct_exit = osd_key_exit
};

static void *osd_key_init(const struct lu_context *ctx,
                          struct lu_context_key *key)
{
        struct osd_thread_info *info;

        OBD_ALLOC_PTR(info);
        if (info != NULL)
                info->oti_env = container_of(ctx, struct lu_env, le_ctx);
        else
                info = ERR_PTR(-ENOMEM);
        return info;
}

static void osd_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct osd_thread_info *info = data;
        OBD_FREE_PTR(info);
}

static void osd_key_exit(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct osd_thread_info *info = data;
        memset(info, 0, sizeof(*info));
}

static int osd_device_init(const struct lu_env *env, struct lu_device *d,
                           const char *name, struct lu_device *next)
{
        return lu_context_init(&osd_dev(d)->od_env_for_commit.le_ctx,
                               LCT_DT_THREAD|LCT_MD_THREAD);
}

static int osd_shutdown(const struct lu_env *env, struct osd_device *o)
{
        ENTRY;
        if (o->od_dt_dev.dd_lu_dev.ld_site)
                lu_site_purge(env, o->od_dt_dev.dd_lu_dev.ld_site, ~0);

        if (o->od_objdir_db)
                udmu_object_put_dmu_buf(o->od_objdir_db, objdir_tag);
        if (o->od_root_db)
                udmu_object_put_dmu_buf(o->od_root_db, root_tag);
        if (o->od_objset.os)
                udmu_objset_close(&o->od_objset);

        RETURN(0);
}

#define DMU_OSD_OI_NAME         "OBJ"

static int osd_oi_init(const struct lu_env *env, struct osd_device *o)
{
        dmu_buf_t         *objdb;
        uint64_t           objid;
        int                rc;
        ENTRY;
        
        rc = udmu_zap_lookup(&o->od_objset, o->od_root_db, DMU_OSD_OI_NAME, &objid,
                             sizeof(uint64_t), sizeof(uint64_t));
        if (rc == 0) {
                rc = udmu_object_get_dmu_buf(&o->od_objset, objid,
                                             &objdb, objdir_tag);
        } else {
                /* create fid-to-dnode index */
                dmu_tx_t *tx = udmu_tx_create(&o->od_objset);
                if (tx == NULL)
                        RETURN(-ENOMEM);

                udmu_tx_hold_zap(tx, DMU_NEW_OBJECT, 1, NULL);
                udmu_tx_hold_bonus(tx, udmu_object_get_id(o->od_root_db));
                udmu_tx_hold_zap(tx, udmu_object_get_id(o->od_root_db),
                                 TRUE, DMU_OSD_OI_NAME);

                rc = udmu_tx_assign(tx, TXG_WAIT);
                LASSERT(rc == 0);

                udmu_zap_create(&o->od_objset, &objdb, tx, osd_object_tag);
                objid = udmu_object_get_id(objdb);

                rc = udmu_zap_insert(&o->od_objset, o->od_root_db, tx,
                                     DMU_OSD_OI_NAME, &objid, sizeof(objid));
                LASSERT(rc == 0);

                udmu_tx_commit(tx);
        }

        o->od_objdir_db = objdb;

        RETURN(0);
}


static int osd_mount(const struct lu_env *env,
                     struct osd_device *o, struct lustre_cfg *cfg)
{
        char               *dev  = lustre_cfg_string(cfg, 0);
        dmu_buf_t          *rootdb;
        int                rc;

        ENTRY;

        if (o->od_objset.os != NULL)
                RETURN(0);

        rc = udmu_objset_open(dev, &o->od_objset); 
        if (rc) {
                CERROR("can't open objset %s: %d\n", dev, rc);
                RETURN(-rc);
        }

        rc = udmu_objset_root(&o->od_objset, &rootdb, root_tag);
        if (rc) {
                CERROR("udmu_objset_root() failed with error %d\n", rc);
                udmu_objset_close(&o->od_objset);
                RETURN(-rc);
        }
        o->od_root_db = rootdb;

        rc = osd_oi_init(env, o);
        LASSERT(rc == 0);

        rc = osd_procfs_init(o, osd_label_get(NULL, &o->od_dt_dev));

        RETURN(rc);
}

static struct lu_device *osd_device_fini(const struct lu_env *env,
                                         struct lu_device *d)
{
        struct osd_device *o = osd_dev(d);
        ENTRY;

        osd_procfs_fini(o);

        if (o->od_objset.os)
                osd_sync(env, lu2dt_dev(d));

        lu_context_fini(&o->od_env_for_commit.le_ctx);
        RETURN(NULL);
}

static struct lu_device *osd_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct osd_device *o;

        OBD_ALLOC_PTR(o);
        if (o != NULL) {
                int result;

                result = dt_device_init(&o->od_dt_dev, t);
                if (result == 0) {
                        l = osd2lu_dev(o);
                        l->ld_ops = &osd_lu_ops;
                        o->od_dt_dev.dd_ops = &osd_dt_ops;
                        spin_lock_init(&o->od_osfs_lock);
                        o->od_osfs_age = cfs_time_shift_64(-1000);
                } else
                        l = ERR_PTR(result);
        } else
                l = ERR_PTR(-ENOMEM);
        return l;
}

static struct lu_device * osd_device_free(const struct lu_env *env, struct lu_device *d)
{
        struct osd_device *o = osd_dev(d);

        dt_device_fini(&o->od_dt_dev);
        OBD_FREE_PTR(o);
        RETURN (NULL);
}

static int osd_process_config(const struct lu_env *env,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct osd_device *o = osd_dev(d);
        int err;
        ENTRY;

        switch(cfg->lcfg_command) {
        case LCFG_SETUP:
                err = osd_mount(env, o, cfg);
                break;
        case LCFG_CLEANUP:
                err = osd_shutdown(env, o);
                break;
        default:
                err = -ENOTTY;
        }

        RETURN(err);
}

static int osd_recovery_complete(const struct lu_env *env, struct lu_device *d)
{
        ENTRY;
        RETURN(0);
}

static int osd_fid_lookup(const struct lu_env *env,
                          struct osd_object *obj, const struct lu_fid *fid)
{
        struct osd_thread_info *info;
        struct lu_device       *ldev = obj->oo_dt.do_lu.lo_dev;
        struct osd_device      *dev;
        char                    buf[32];
        uint64_t                oid;
        int                     rc;
        ENTRY;

        LASSERT(osd_invariant(obj));

        info = osd_oti_get(env);
        dev  = osd_dev(ldev);

        if (OBD_FAIL_CHECK(OBD_FAIL_OST_ENOENT))
                RETURN(-ENOENT);

        LASSERT(obj->oo_db == NULL);

        if (fid->f_seq == LUSTRE_ROOT_FID_SEQ) {
                if (fid->f_oid == udmu_object_get_id(dev->od_root_db)) {
                        /* root */
                        oid = fid->f_oid;
                } else {
                        /* special fid found via ->index_lookup */
                        CDEBUG(D_OTHER, "lookup special %llu:%lu\n",
                               fid->f_seq, (unsigned long) fid->f_oid);
                        oid = fid->f_oid;
                }
        } else {
                osd_fid2str(buf, fid);

                rc = udmu_zap_lookup(&dev->od_objset, dev->od_objdir_db,
                                     buf, &oid, sizeof(uint64_t),
                                     sizeof(uint64_t));
                if (rc)
                        RETURN(-rc);
        }

        rc = udmu_object_get_dmu_buf(&dev->od_objset, oid, &obj->oo_db,
                                     osd_object_tag);
        if (rc == 0) {
                LASSERT(obj->oo_db != NULL);
        } else if (rc == ENOENT) {
                LASSERT(obj->oo_db == NULL);
        } else {
                CERROR("error during lookup %s: %d\n", buf, rc);
        }

        LASSERT(osd_invariant(obj));
        RETURN(0);
}

static int osd_prepare(const struct lu_env *env,
                       struct lu_device *pdev,
                       struct lu_device *dev)
{
        int rc = 0;
        ENTRY;

        if (lu_device_is_md(pdev)) {
                /* 2. setup local objects */
                rc = llo_local_objects_setup(env, lu2md_dev(pdev),
                                             lu2dt_dev(dev));
        }

        RETURN(rc);
}

/*
 * Helpers.
 */

static int lu_device_is_osd(const struct lu_device *d)
{
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &osd_lu_ops);
}

static struct osd_object *osd_obj(const struct lu_object *o)
{
        LASSERT(lu_device_is_osd(o->lo_dev));
        return container_of0(o, struct osd_object, oo_dt.do_lu);
}

static struct osd_device *osd_dt_dev(const struct dt_device *d)
{
        LASSERT(lu_device_is_osd(&d->dd_lu_dev));
        return container_of0(d, struct osd_device, od_dt_dev);
}

static struct osd_device *osd_dev(const struct lu_device *d)
{
        LASSERT(lu_device_is_osd(d));
        return osd_dt_dev(container_of0(d, struct dt_device, dd_lu_dev));
}

static struct osd_object *osd_dt_obj(const struct dt_object *d)
{
        return osd_obj(&d->do_lu);
}

static struct osd_device *osd_obj2dev(const struct osd_object *o)
{
        return osd_dev(o->oo_dt.do_lu.lo_dev);
}

static struct lu_device *osd2lu_dev(struct osd_device *osd)
{
        return &osd->od_dt_dev.dd_lu_dev;
}

static int osd_object_invariant(const struct lu_object *l)
{
        return osd_invariant(osd_obj(l));
}

static struct lu_object_operations osd_lu_obj_ops = {
        .loo_object_init      = osd_object_init,
        .loo_object_delete    = osd_object_delete,
        .loo_object_release   = osd_object_release,
        .loo_object_free      = osd_object_free,
        .loo_object_print     = osd_object_print,
        .loo_object_invariant = osd_object_invariant
};

static struct lu_device_operations osd_lu_ops = {
        .ldo_object_alloc      = osd_object_alloc,
        .ldo_process_config    = osd_process_config,
        .ldo_recovery_complete = osd_recovery_complete,
        .ldo_prepare           = osd_prepare
};

static void osd_type_start(struct lu_device_type *t)
{
}

static void osd_type_stop(struct lu_device_type *t)
{
}

static struct lu_device_type_operations osd_device_type_ops = {
        .ldto_init = osd_type_init,
        .ldto_fini = osd_type_fini,

        .ldto_start = osd_type_start,
        .ldto_stop  = osd_type_stop,

        .ldto_device_alloc = osd_device_alloc,
        .ldto_device_free  = osd_device_free,

        .ldto_device_init    = osd_device_init,
        .ldto_device_fini    = osd_device_fini
};

static struct lu_device_type osd_device_type = {
        .ldt_tags     = LU_DEVICE_DT,
        .ldt_name     = LUSTRE_ZFS_NAME,
        .ldt_ops      = &osd_device_type_ops,
        .ldt_ctx_tags = LCT_MD_THREAD|LCT_DT_THREAD
};


static struct obd_ops osd_obd_device_ops = {
        .o_owner = THIS_MODULE
};

int __init osd_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_osd_init_vars(&lvars);
        return class_register_type(&osd_obd_device_ops, NULL, lvars.module_vars,
                                   LUSTRE_ZFS_NAME, &osd_device_type);
        
}

#ifdef __KERNEL__
void __exit osd_exit(void)
{
        class_unregister_type(LUSTRE_ZFS_NAME);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Device over ZFS/DMU (no recovery) ("LUSTRE_ZFS_NAME")");
MODULE_LICENSE("GPL");

cfs_module(osd, "0.0.2", osd_init, osd_exit);
#endif

