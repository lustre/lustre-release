/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
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

#ifndef __LINUX_CLASS_OBD_H
#define __LINUX_CLASS_OBD_H

#ifndef __KERNEL__
# include <stdint.h>
# define __KERNEL__
# include <linux/list.h>
# undef __KERNEL__
#else 
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/time.h>

#include <linux/obd_support.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#endif


/*
 *  ======== OBD Device Declarations ===========
 */
#define MAX_OBD_DEVICES 128
extern struct obd_device obd_dev[MAX_OBD_DEVICES];

#define OBD_ATTACHED 0x1
#define OBD_SET_UP   0x2

extern struct proc_dir_entry *
proc_lustre_register_obd_device(struct obd_device *obd);
extern void proc_lustre_release_obd_device(struct obd_device *obd);
extern void proc_lustre_remove_obd_entry(const char* name,
                                         struct obd_device *obd);

/*
 *  ======== OBD Operations Declarations ===========
 */

#ifdef __KERNEL__
static inline int obd_check_conn(struct lustre_handle *conn) 
{
        struct obd_device *obd;
        if (!conn) {
                CERROR("NULL conn\n");
                RETURN(-ENOTCONN);
        }
        obd = class_conn2obd(conn);
        if (!obd) {
                CERROR("NULL obd\n");
                RETURN(-ENODEV);
        }

        if (!obd->obd_flags & OBD_ATTACHED ) {
                CERROR("obd %d not attached\n", obd->obd_minor);
                RETURN(-ENODEV);
        }

        if (!obd->obd_flags & OBD_SET_UP) {
                CERROR("obd %d not setup\n", obd->obd_minor); 
                RETURN(-ENODEV);
        }

        if (!obd->obd_type) {
                CERROR("obd %d not typed\n", obd->obd_minor);
                RETURN(-ENODEV);
        }

        if (!obd->obd_type->typ_ops) {
                CERROR("obd_check_conn: obd %d no operations\n",
                       obd->obd_minor);
                RETURN(-EOPNOTSUPP);
        }
        return 0;
}


#define OBT(dev)        (dev)->obd_type
#define OBP(dev,op)     (dev)->obd_type->typ_ops->o_ ## op

#define OBD_CHECK_SETUP(conn, export)                           \
do {                                                            \
        if (!(conn)) {                                          \
                CERROR("NULL connection\n");                    \
                RETURN(-EINVAL);                                \
        }                                                       \
                                                                \
        export = class_conn2export(conn);                       \
        if (!(export)) {                                        \
                CERROR("No export\n");                          \
                RETURN(-EINVAL);                                \
        }                                                       \
                                                                \
        if (!((export)->exp_obd->obd_flags & OBD_SET_UP)) {     \
                CERROR("Device %d not setup\n",                 \
                       (export)->exp_obd->obd_minor);           \
                RETURN(-EINVAL);                                \
        }                                                       \
} while (0)

#define OBD_CHECK_DEVSETUP(obd)                                 \
do {                                                            \
        if (!(obd)) {                                           \
                CERROR("NULL device\n");                        \
                RETURN(-EINVAL);                                \
        }                                                       \
                                                                \
        if ( !((obd)->obd_flags & OBD_SET_UP) ) {               \
                CERROR("Device %d not setup\n",                 \
                       (obd)->obd_minor);                       \
                RETURN(-EINVAL);                                \
        }                                                       \
} while (0)

#define OBD_CHECK_OP(obd,op)                                   \
do {                                                            \
        if (!OBP((obd),op)) {                                   \
                CERROR("obd_" #op ": dev %d no operation\n",    \
                       obd->obd_minor);                         \
                RETURN(-EOPNOTSUPP);                            \
        }                                                       \
} while (0)

static inline int obd_get_info(struct lustre_handle *conn, obd_count keylen,
                               void *key, obd_count *vallen, void **val)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,get_info);

        rc = OBP(export->exp_obd, get_info)(conn, keylen, key, vallen, val);
        RETURN(rc);
}

static inline int obd_set_info(struct lustre_handle *conn, obd_count keylen,
                               void *key, obd_count vallen, void *val)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,set_info);

        rc = OBP(export->exp_obd, set_info)(conn, keylen, key, vallen, val);
        RETURN(rc);
}

static inline int obd_setup(struct obd_device *obd, int datalen, void *data)
{
        int rc;

        OBD_CHECK_OP(obd,setup);

        rc = OBP(obd, setup)(obd, datalen, data);
        RETURN(rc);
}

static inline int obd_cleanup(struct obd_device *obd)
{
        int rc;

        OBD_CHECK_DEVSETUP(obd);
        OBD_CHECK_OP(obd,cleanup);

        rc = OBP(obd, cleanup)(obd);
        RETURN(rc);
}

static inline int obd_create(struct lustre_handle *conn, struct obdo *obdo, struct lov_stripe_md **ea)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,create);

#define OBD_MD_FLNEEDED (OBD_MD_FLID | OBD_MD_FLMODE)
        //if (obdo->o_valid & OBD_MD_FLNEEDED != OBD_MD_FLNEEDED)
        //        RETURN(-EINVAL);
#undef OBD_MD_FLNEEDED
        rc = OBP(export->exp_obd, create)(conn, obdo, ea);
        RETURN(rc);
}

static inline int obd_destroy(struct lustre_handle *conn, struct obdo *obdo, struct lov_stripe_md *ea)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,destroy);

        rc = OBP(export->exp_obd, destroy)(conn, obdo, ea);
        RETURN(rc);
}

static inline int obd_getattr(struct lustre_handle *conn, 
                              struct obdo *obdo,
                              struct lov_stripe_md *ea)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,getattr);

        rc = OBP(export->exp_obd, getattr)(conn, obdo, ea);
        RETURN(rc);
}

static inline int obd_close(struct lustre_handle *conn, struct obdo *obdo, struct lov_stripe_md *md)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,close);

        rc = OBP(export->exp_obd, close)(conn, obdo, md);
        RETURN(rc);
}
static inline int obd_open(struct lustre_handle *conn, struct obdo *obdo, 
                           struct lov_stripe_md *md)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,open);

        rc = OBP(export->exp_obd, open) (conn, obdo, md);
        RETURN(rc);
}

static inline int obd_setattr(struct lustre_handle *conn, 
                              struct obdo *obdo,
                              struct lov_stripe_md *ea)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,setattr);

        rc = OBP(export->exp_obd, setattr)(conn, obdo, ea);
        RETURN(rc);
}

static inline int obd_connect(struct lustre_handle *conn, struct obd_device *obd,
                              char *cluuid)
{
        int rc;
        OBD_CHECK_DEVSETUP(obd);
        OBD_CHECK_OP(obd,connect);

        rc = OBP(obd, connect)(conn, obd, cluuid);
        RETURN(rc);
}

static inline int obd_disconnect(struct lustre_handle *conn)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,disconnect);

        rc = OBP(export->exp_obd, disconnect)(conn);
        RETURN(rc);
}

static inline int obd_statfs(struct lustre_handle *conn, struct statfs *buf)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,statfs);

        rc = OBP(export->exp_obd, statfs)(conn, buf);
        RETURN(rc);
}

static inline int obd_punch(struct lustre_handle *conn, struct obdo *tgt,
                            struct lov_stripe_md *md, 
                            obd_size count, obd_off offset)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,punch);

        rc = OBP(export->exp_obd, punch)(conn, tgt, md, count, offset);
        RETURN(rc);
}

static inline int obd_brw(int cmd, struct lustre_handle *conn, 
                          struct lov_stripe_md *md, 
                          obd_count oa_bufs,
                          struct brw_page *pg, 
                          brw_callback_t callback, void *data)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,brw);

        if (!(cmd & OBD_BRW_RWMASK)) {
                CERROR("obd_brw: cmd must be OBD_BRW_READ or OBD_BRW_WRITE\n");
                LBUG();
        }

        rc = OBP(export->exp_obd, brw)(cmd, conn, md, oa_bufs, pg, callback, data);
        RETURN(rc);
}

static inline int obd_preprw(int cmd, struct lustre_handle *conn,
                             int objcount, struct obd_ioobj *obj,
                             int niocount, struct niobuf_remote *remote,
                             struct niobuf_local *local, void **desc_private)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,preprw);

        rc = OBP(export->exp_obd, preprw)(cmd, conn, objcount, obj, niocount,
                                       remote, local, desc_private);
        RETURN(rc);
}

static inline int obd_commitrw(int cmd, struct lustre_handle *conn,
                               int objcount, struct obd_ioobj *obj,
                               int niocount, struct niobuf_local *local,
                               void *desc_private)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,commitrw);

        rc = OBP(export->exp_obd, commitrw)(cmd, conn, objcount, obj, niocount,
                                         local, desc_private);
        RETURN(rc);
}

static inline int obd_iocontrol(int cmd, struct lustre_handle *conn,
                                int len, void *karg, void *uarg)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,iocontrol);

        rc = OBP(export->exp_obd, iocontrol)(cmd, conn, len, karg, uarg);
        RETURN(rc);
}

static inline int obd_enqueue(struct lustre_handle *conn,
                              struct lov_stripe_md *md,
                              struct lustre_handle *parent_lock, 
                              __u32 type, void *cookie, int cookielen,
                              __u32 mode, int *flags, void *cb, void *data,
                              int datalen, struct lustre_handle *lockh)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,enqueue);

        rc = OBP(export->exp_obd, enqueue)(conn, md, parent_lock, type,
                                        cookie, cookielen, mode, flags, cb,
                                        data, datalen, lockh);
        RETURN(rc);
}

static inline int obd_cancel(struct lustre_handle *conn, struct lov_stripe_md *md, __u32 mode,
                             struct lustre_handle *lockh)
{
        int rc;
        struct obd_export *export;
        OBD_CHECK_SETUP(conn, export);
        OBD_CHECK_OP(export->exp_obd,cancel);

        rc = OBP(export->exp_obd, cancel)(conn, md, mode, lockh);
        RETURN(rc);
}

#endif 

/*
 *  ======== OBD Metadata Support  ===========
 */

extern int obd_init_caches(void);
extern void obd_cleanup_caches(void);

static inline int obdo_has_inline(struct obdo *obdo)
{
        return (obdo->o_valid & OBD_MD_FLINLINE &&
                obdo->o_obdflags & OBD_FL_INLINEDATA);
};

#ifdef __KERNEL__
/* support routines */
extern kmem_cache_t *obdo_cachep;
static inline struct obdo *obdo_alloc(void)
{
        struct obdo *oa = NULL;

        oa = kmem_cache_alloc(obdo_cachep, SLAB_KERNEL);
        if (oa == NULL)
                LBUG();
        memset(oa, 0, sizeof (*oa));

        return oa;
}
static inline void obdo_free(struct obdo *oa)
{
        if (!oa)
                return;
        kmem_cache_free(obdo_cachep, oa);
}


static inline void obdo_from_iattr(struct obdo *oa, struct iattr *attr)
{
        unsigned int ia_valid = attr->ia_valid;

        if (ia_valid & ATTR_ATIME) {
                oa->o_atime = attr->ia_atime;
                oa->o_valid |= OBD_MD_FLATIME;
        }
        if (ia_valid & ATTR_MTIME) {
                oa->o_mtime = attr->ia_mtime;
                oa->o_valid |= OBD_MD_FLMTIME;
        }
        if (ia_valid & ATTR_CTIME) {
                oa->o_ctime = attr->ia_ctime;
                oa->o_valid |= OBD_MD_FLCTIME;
        }
        if (ia_valid & ATTR_SIZE) {
                oa->o_size = attr->ia_size;
                oa->o_valid |= OBD_MD_FLSIZE;
        }
        if (ia_valid & ATTR_MODE) {
                oa->o_mode = attr->ia_mode;
                oa->o_valid |= OBD_MD_FLMODE;
                if (!in_group_p(oa->o_gid) && !capable(CAP_FSETID))
                        oa->o_mode &= ~S_ISGID;
        }
        if (ia_valid & ATTR_UID)
        {
                oa->o_uid = attr->ia_uid;
                oa->o_valid |= OBD_MD_FLUID;
        }
        if (ia_valid & ATTR_GID) {
                oa->o_gid = attr->ia_gid;
                oa->o_valid |= OBD_MD_FLGID;
        }
}


static inline void iattr_from_obdo(struct iattr *attr, struct obdo *oa,
                                   obd_flag valid)
{
        memset(attr, 0, sizeof(*attr));
        if (valid & OBD_MD_FLATIME) {
                attr->ia_atime = oa->o_atime;
                attr->ia_valid |= ATTR_ATIME;
        }
        if (valid & OBD_MD_FLMTIME) {
                attr->ia_mtime = oa->o_mtime;
                attr->ia_valid |= ATTR_MTIME;
        }
        if (valid & OBD_MD_FLCTIME) {
                attr->ia_ctime = oa->o_ctime;
                attr->ia_valid |= ATTR_CTIME;
        }
        if (valid & OBD_MD_FLSIZE) {
                attr->ia_size = oa->o_size;
                attr->ia_valid |= ATTR_SIZE;
        }
        if (valid & OBD_MD_FLMODE) {
                attr->ia_mode = oa->o_mode;
                attr->ia_valid |= ATTR_MODE;
                if (!in_group_p(oa->o_gid) && !capable(CAP_FSETID))
                        attr->ia_mode &= ~S_ISGID;
        }
        if (valid & OBD_MD_FLUID)
        {
                attr->ia_uid = oa->o_uid;
                attr->ia_valid |= ATTR_UID;
        }
        if (valid & OBD_MD_FLGID) {
                attr->ia_gid = oa->o_gid;
                attr->ia_valid |= ATTR_GID;
        }
}


/* WARNING: the file systems must take care not to tinker with
   attributes they don't manage (such as blocks). */

static inline void obdo_from_inode(struct obdo *dst, struct inode *src,
                                   obd_flag valid)
{
//        if (valid & OBD_MD_FLID)
//                dst->o_id = src->i_ino;
        if (valid & OBD_MD_FLATIME)
                dst->o_atime = src->i_atime;
        if (valid & OBD_MD_FLMTIME)
                dst->o_mtime = src->i_mtime;
        if (valid & OBD_MD_FLCTIME)
                dst->o_ctime = src->i_ctime;
        if (valid & OBD_MD_FLSIZE)
                dst->o_size = src->i_size;
        if (valid & OBD_MD_FLBLOCKS)   /* allocation of space */
                dst->o_blocks = src->i_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                dst->o_blksize = src->i_blksize;
        if (valid & OBD_MD_FLMODE)
                dst->o_mode = src->i_mode;
        if (valid & OBD_MD_FLUID)
                dst->o_uid = src->i_uid;
        if (valid & OBD_MD_FLGID)
                dst->o_gid = src->i_gid;
        if (valid & OBD_MD_FLFLAGS)
                dst->o_flags = src->i_flags;
        if (valid & OBD_MD_FLNLINK)
                dst->o_nlink = src->i_nlink;
        if (valid & OBD_MD_FLGENER)
                dst->o_generation = src->i_generation;
        if (valid & OBD_MD_FLRDEV)
                dst->o_rdev = src->i_rdev;

        dst->o_valid |= (valid & ~OBD_MD_FLID);
}

static inline void obdo_to_inode(struct inode *dst, struct obdo *src,
                                 obd_flag valid)
{
//        if (valid & OBD_MD_FLID)
//                dst->i_ino = src->o_id;
        if (valid & OBD_MD_FLATIME)
                dst->i_atime = src->o_atime;
        if (valid & OBD_MD_FLMTIME)
                dst->i_mtime = src->o_mtime;
        if (valid & OBD_MD_FLCTIME)
                dst->i_ctime = src->o_ctime;
        if (valid & OBD_MD_FLSIZE)
                dst->i_size = src->o_size;
        if (valid & OBD_MD_FLBLOCKS) /* allocation of space */
                dst->i_blocks = src->o_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                dst->i_blksize = src->o_blksize;
        if (valid & OBD_MD_FLMODE)
                dst->i_mode = src->o_mode;
        if (valid & OBD_MD_FLUID)
                dst->i_uid = src->o_uid;
        if (valid & OBD_MD_FLGID)
                dst->i_gid = src->o_gid;
        if (valid & OBD_MD_FLFLAGS)
                dst->i_flags = src->o_flags;
        if (valid & OBD_MD_FLNLINK)
                dst->i_nlink = src->o_nlink;
        if (valid & OBD_MD_FLGENER)
                dst->i_generation = src->o_generation;
        if (valid & OBD_MD_FLRDEV)
                dst->i_rdev = src->o_rdev;
}
#endif

static inline void obdo_cpy_md(struct obdo *dst, struct obdo *src,
                               obd_flag valid)
{
#ifdef __KERNEL__
        CDEBUG(D_INODE, "src obdo %Ld valid 0x%x, dst obdo %Ld\n",
               (unsigned long long)src->o_id, src->o_valid,
               (unsigned long long)dst->o_id);
#endif
        if (valid & OBD_MD_FLATIME)
                dst->o_atime = src->o_atime;
        if (valid & OBD_MD_FLMTIME)
                dst->o_mtime = src->o_mtime;
        if (valid & OBD_MD_FLCTIME)
                dst->o_ctime = src->o_ctime;
        if (valid & OBD_MD_FLSIZE)
                dst->o_size = src->o_size;
        if (valid & OBD_MD_FLBLOCKS) /* allocation of space */
                dst->o_blocks = src->o_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                dst->o_blksize = src->o_blksize;
        if (valid & OBD_MD_FLMODE)
                dst->o_mode = src->o_mode;
        if (valid & OBD_MD_FLUID)
                dst->o_uid = src->o_uid;
        if (valid & OBD_MD_FLGID)
                dst->o_gid = src->o_gid;
        if (valid & OBD_MD_FLFLAGS)
                dst->o_flags = src->o_flags;
        /*
        if (valid & OBD_MD_FLOBDFLG)
                dst->o_obdflags = src->o_obdflags;
        */
        if (valid & OBD_MD_FLNLINK)
                dst->o_nlink = src->o_nlink;
        if (valid & OBD_MD_FLGENER)
                dst->o_generation = src->o_generation;
        if (valid & OBD_MD_FLRDEV)
                dst->o_rdev = src->o_rdev;
        if (valid & OBD_MD_FLINLINE &&
             src->o_obdflags & OBD_FL_INLINEDATA) {
                memcpy(dst->o_inline, src->o_inline, sizeof(src->o_inline));
                dst->o_obdflags |= OBD_FL_INLINEDATA;
        }

        dst->o_valid |= valid;
}


/* returns FALSE if comparison (by flags) is same, TRUE if changed */
static inline int obdo_cmp_md(struct obdo *dst, struct obdo *src,
                              obd_flag compare)
{
        int res = 0;

        if ( compare & OBD_MD_FLATIME )
                res = (res || (dst->o_atime != src->o_atime));
        if ( compare & OBD_MD_FLMTIME )
                res = (res || (dst->o_mtime != src->o_mtime));
        if ( compare & OBD_MD_FLCTIME )
                res = (res || (dst->o_ctime != src->o_ctime));
        if ( compare & OBD_MD_FLSIZE )
                res = (res || (dst->o_size != src->o_size));
        if ( compare & OBD_MD_FLBLOCKS ) /* allocation of space */
                res = (res || (dst->o_blocks != src->o_blocks));
        if ( compare & OBD_MD_FLBLKSZ )
                res = (res || (dst->o_blksize != src->o_blksize));
        if ( compare & OBD_MD_FLMODE )
                res = (res || (dst->o_mode != src->o_mode));
        if ( compare & OBD_MD_FLUID )
                res = (res || (dst->o_uid != src->o_uid));
        if ( compare & OBD_MD_FLGID )
                res = (res || (dst->o_gid != src->o_gid));
        if ( compare & OBD_MD_FLFLAGS ) 
                res = (res || (dst->o_flags != src->o_flags));
        if ( compare & OBD_MD_FLNLINK )
                res = (res || (dst->o_nlink != src->o_nlink));
        if ( compare & OBD_MD_FLGENER )
                res = (res || (dst->o_generation != src->o_generation));
        /* XXX Don't know if thses should be included here - wasn't previously
        if ( compare & OBD_MD_FLINLINE )
                res = (res || memcmp(dst->o_inline, src->o_inline));
        */
        return res;
}


#ifdef __KERNEL__
int class_register_type(struct obd_ops *ops, char *nm);
int class_unregister_type(char *nm);
int class_name2dev(char *name);
int class_uuid2dev(char *name);
struct obd_device *class_uuid2obd(char *name);
struct obd_export *class_new_export(struct obd_device *obddev);
void class_destroy_export(struct obd_export *exp);
int class_connect(struct lustre_handle *conn, struct obd_device *obd,
                  char *cluuid);
int class_disconnect(struct lustre_handle *conn);
void class_disconnect_all(struct obd_device *obddev);

/* generic operations shared by various OBD types */
int class_multi_setup(struct obd_device *obddev, uint32_t len, void *data);
int class_multi_cleanup(struct obd_device *obddev);

extern void (*class_signal_connection_failure)(struct ptlrpc_connection *);

/* == mds_client_free if MDS running here */
extern int (*mds_destroy_export)(struct obd_export *exp);
/* == ldlm_client_free if(?) DLM running here */
extern int (*ldlm_destroy_export)(struct obd_export *exp);

static inline struct ptlrpc_connection *class_rd2conn(struct recovd_data *rd)
{
        /* reuse list_entry's member-pointer offset stuff */
        return list_entry(rd, struct ptlrpc_connection, c_recovd_data);
}

#endif

/* sysctl.c */
extern void obd_sysctl_init (void);
extern void obd_sysctl_clean (void);

/* uuid.c  */
/* XXX - should use uuid_t here, but already defined as char[37] */
typedef unsigned char class_uuid_t[16];
int class_uuid_parse(char *in, class_uuid_t out);
void class_uuid_unparse(class_uuid_t in, char *out);
#endif /* __LINUX_CLASS_OBD_H */
