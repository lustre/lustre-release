/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
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
#endif 

#include <linux/obd_support.h>
#include <linux/lustre_import.h>
#include <linux/lustre_net.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/lprocfs_status.h>


/* OBD Device Declarations */
#define MAX_OBD_DEVICES 128
extern struct obd_device obd_dev[MAX_OBD_DEVICES];

#define OBD_ATTACHED       0x01
#define OBD_SET_UP         0x02
#define OBD_RECOVERING     0x04
#define OBD_ABORT_RECOVERY 0x08
#define OBD_REPLAYABLE     0x10
#define OBD_NO_TRANSNO     0x20 /* XXX needs better name */

/* OBD Operations Declarations */
extern struct obd_device *class_conn2obd(struct lustre_handle *);
extern struct obd_export *class_conn2export(struct lustre_handle *);

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
#define OBP(dev, op)    (dev)->obd_type->typ_ops->o_ ## op

#define OBD_CHECK_SETUP(conn, exp)                              \
do {                                                            \
        if (!(conn)) {                                          \
                CERROR("NULL connection\n");                    \
                RETURN(-EINVAL);                                \
        }                                                       \
                                                                \
        exp = class_conn2export(conn);                          \
        if (!(exp)) {                                           \
                CERROR("No export for conn "LPX64":"LPX64"\n",  \
                       conn->addr, conn->cookie);               \
                RETURN(-EINVAL);                                \
        }                                                       \
                                                                \
        if (!((exp)->exp_obd->obd_flags & OBD_SET_UP)) {        \
                CERROR("Device %d not setup\n",                 \
                       (exp)->exp_obd->obd_minor);              \
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
        if (!((obd)->obd_flags & OBD_SET_UP)) {                 \
                CERROR("Device %d not setup\n",                 \
                       (obd)->obd_minor);                       \
                RETURN(-EINVAL);                                \
        }                                                       \
} while (0)

#define OBD_CHECK_OP(obd, op)                                   \
do {                                                            \
        if (!OBP((obd), op)) {                                  \
                CERROR("obd_" #op ": dev %d no operation\n",    \
                       obd->obd_minor);                         \
                RETURN(-EOPNOTSUPP);                            \
        }                                                       \
} while (0)

static inline int obd_get_info(struct lustre_handle *conn, obd_count keylen,
                               void *key, obd_count *vallen, void **val)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, get_info);

        rc = OBP(exp->exp_obd, get_info)(conn, keylen, key, vallen, val);
        RETURN(rc);
}

static inline int obd_set_info(struct lustre_handle *conn, obd_count keylen,
                               void *key, obd_count vallen, void *val)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, set_info);

        rc = OBP(exp->exp_obd, set_info)(conn, keylen, key, vallen, val);
        RETURN(rc);
}

static inline int obd_setup(struct obd_device *obd, int datalen, void *data)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, setup);

        rc = OBP(obd, setup)(obd, datalen, data);
        RETURN(rc);
}

static inline int obd_cleanup(struct obd_device *obd)
{
        int rc;
        ENTRY;

        OBD_CHECK_DEVSETUP(obd);
        OBD_CHECK_OP(obd, cleanup);

        rc = OBP(obd, cleanup)(obd);
        RETURN(rc);
}

/* Pack an in-memory MD struct for sending to the MDS and/or disk.
 * Returns +ve size of packed MD (0 for free), or -ve error.
 *
 * If @wire_tgt == NULL, MD size is returned (max size if @mem_src == NULL).
 * If @*wire_tgt != NULL and @mem_src == NULL, @*wire_tgt will be freed.
 * If @*wire_tgt == NULL, it will be allocated
 */
static inline int obd_packmd(struct lustre_handle *conn,
                             struct lov_mds_md **wire_tgt,
                             struct lov_stripe_md *mem_src)
{
        struct obd_export *exp;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, packmd);

        RETURN(OBP(exp->exp_obd, packmd)(conn, wire_tgt, mem_src));
}

static inline int obd_size_wiremd(struct lustre_handle *conn,
                                  struct lov_stripe_md *mem_src)
{
        return obd_packmd(conn, NULL, mem_src);
}

/* helper functions */
static inline int obd_alloc_wiremd(struct lustre_handle *conn,
                                   struct lov_mds_md **wire_tgt)
{
        LASSERT(wire_tgt);
        LASSERT(*wire_tgt == NULL);
        return obd_packmd(conn, wire_tgt, NULL);
}

static inline int obd_free_wiremd(struct lustre_handle *conn,
                                  struct lov_mds_md **wire_tgt)
{
        LASSERT(wire_tgt);
        LASSERT(*wire_tgt);
        return obd_packmd(conn, wire_tgt, NULL);
}

/* Unpack an MD struct from the MDS and/or disk to in-memory format.
 * Returns +ve size of unpacked MD (0 for free), or -ve error.
 *
 * If @mem_tgt == NULL, MD size is returned (max size if @wire_src == NULL).
 * If @*mem_tgt != NULL and @wire_src == NULL, @*mem_tgt will be freed.
 * If @*mem_tgt == NULL, it will be allocated
 */
static inline int obd_unpackmd(struct lustre_handle *conn,
                               struct lov_stripe_md **mem_tgt,
                               struct lov_mds_md *wire_src)
{
        struct obd_export *exp;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, unpackmd);

        RETURN(OBP(exp->exp_obd, unpackmd)(conn, mem_tgt, wire_src));
}

static inline int obd_size_memmd(struct lustre_handle *conn,
                                 struct lov_mds_md *wire_src)
{
        return obd_unpackmd(conn, NULL, wire_src);
}

/* helper functions */
static inline int obd_alloc_memmd(struct lustre_handle *conn,
                                  struct lov_stripe_md **mem_tgt)
{
        LASSERT(mem_tgt);
        LASSERT(*mem_tgt == NULL);
        return obd_unpackmd(conn, mem_tgt, NULL);
}

static inline int obd_free_memmd(struct lustre_handle *conn,
                                 struct lov_stripe_md **mem_tgt)
{
        LASSERT(mem_tgt);
        LASSERT(*mem_tgt);
        return obd_unpackmd(conn, mem_tgt, NULL);
}

static inline int obd_create(struct lustre_handle *conn, struct obdo *obdo,
                             struct lov_stripe_md **ea,
                             struct obd_trans_info *oti)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, create);

        rc = OBP(exp->exp_obd, create)(conn, obdo, ea, oti);
        RETURN(rc);
}

static inline int obd_destroy(struct lustre_handle *conn, struct obdo *obdo,
                              struct lov_stripe_md *ea,
                              struct obd_trans_info *oti)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, destroy);

        rc = OBP(exp->exp_obd, destroy)(conn, obdo, ea, oti);
        RETURN(rc);
}

static inline int obd_getattr(struct lustre_handle *conn, struct obdo *obdo,
                              struct lov_stripe_md *ea)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, getattr);

        rc = OBP(exp->exp_obd, getattr)(conn, obdo, ea);
        RETURN(rc);
}

static inline int obd_close(struct lustre_handle *conn, struct obdo *obdo,
                            struct lov_stripe_md *ea,
                            struct obd_trans_info *oti)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, close);

        rc = OBP(exp->exp_obd, close)(conn, obdo, ea, oti);
        RETURN(rc);
}

static inline int obd_open(struct lustre_handle *conn, struct obdo *obdo,
                           struct lov_stripe_md *ea, struct obd_trans_info *oti)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, open);

        rc = OBP(exp->exp_obd, open)(conn, obdo, ea, oti);
        RETURN(rc);
}

static inline int obd_setattr(struct lustre_handle *conn, struct obdo *obdo,
                              struct lov_stripe_md *ea,
                              struct obd_trans_info *oti)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, setattr);

        rc = OBP(exp->exp_obd, setattr)(conn, obdo, ea, oti);
        RETURN(rc);
}

static inline int obd_connect(struct lustre_handle *conn,
                              struct obd_device *obd, struct obd_uuid *cluuid,
                              struct recovd_obd *recovd,
                              ptlrpc_recovery_cb_t recover)
{
        int rc;
        ENTRY;

        OBD_CHECK_DEVSETUP(obd);
        OBD_CHECK_OP(obd, connect);

        rc = OBP(obd, connect)(conn, obd, cluuid, recovd, recover);
        RETURN(rc);
}

static inline int obd_disconnect(struct lustre_handle *conn)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, disconnect);

        rc = OBP(exp->exp_obd, disconnect)(conn);
        RETURN(rc);
}

static inline int obd_statfs(struct lustre_handle *conn,struct obd_statfs *osfs)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, statfs);

        rc = OBP(exp->exp_obd, statfs)(conn, osfs);
        RETURN(rc);
}

static inline int obd_syncfs(struct lustre_handle *conn)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, syncfs);

        rc = OBP(exp->exp_obd, syncfs)(conn);
        RETURN(rc);
}

static inline int obd_punch(struct lustre_handle *conn, struct obdo *oa,
                            struct lov_stripe_md *ea, obd_size start,
                            obd_size end, struct obd_trans_info *oti)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, punch);

        rc = OBP(exp->exp_obd, punch)(conn, oa, ea, start, end, oti);
        RETURN(rc);
}

static inline int obd_brw(int cmd, struct lustre_handle *conn,
                          struct lov_stripe_md *ea, obd_count oa_bufs,
                          struct brw_page *pg, struct obd_brw_set *set,
                          struct obd_trans_info *oti)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, brw);

        if (!(cmd & OBD_BRW_RWMASK)) {
                CERROR("obd_brw: cmd must be OBD_BRW_READ or OBD_BRW_WRITE\n");
                LBUG();
        }

        rc = OBP(exp->exp_obd, brw)(cmd, conn, ea, oa_bufs, pg, set, oti);
        RETURN(rc);
}

static inline int obd_preprw(int cmd, struct lustre_handle *conn,
                             int objcount, struct obd_ioobj *obj,
                             int niocount, struct niobuf_remote *remote,
                             struct niobuf_local *local, void **desc_private,
                             struct obd_trans_info *oti)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, preprw);

        rc = OBP(exp->exp_obd, preprw)(cmd, conn, objcount, obj, niocount,
                                       remote, local, desc_private, oti);
        RETURN(rc);
}

static inline int obd_commitrw(int cmd, struct lustre_handle *conn,
                               int objcount, struct obd_ioobj *obj,
                               int niocount, struct niobuf_local *local,
                               void *desc_private, struct obd_trans_info *oti)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, commitrw);

        rc = OBP(exp->exp_obd, commitrw)(cmd, conn, objcount, obj, niocount,
                                         local, desc_private, oti);
        RETURN(rc);
}

static inline int obd_iocontrol(unsigned int cmd, struct lustre_handle *conn,
                                int len, void *karg, void *uarg)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, iocontrol);

        rc = OBP(exp->exp_obd, iocontrol)(cmd, conn, len, karg, uarg);
        RETURN(rc);
}

static inline int obd_enqueue(struct lustre_handle *conn,
                              struct lov_stripe_md *ea,
                              struct lustre_handle *parent_lock,
                              __u32 type, void *cookie, int cookielen,
                              __u32 mode, int *flags, void *cb, void *data,
                              int datalen, struct lustre_handle *lockh)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, enqueue);

        rc = OBP(exp->exp_obd, enqueue)(conn, ea, parent_lock, type,
                                        cookie, cookielen, mode, flags, cb,
                                        data, datalen, lockh);
        RETURN(rc);
}

static inline int obd_cancel(struct lustre_handle *conn,
                             struct lov_stripe_md *ea, __u32 mode,
                             struct lustre_handle *lockh)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, cancel);

        rc = OBP(exp->exp_obd, cancel)(conn, ea, mode, lockh);
        RETURN(rc);
}

static inline int obd_cancel_unused(struct lustre_handle *conn,
                                    struct lov_stripe_md *ea, int local)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, cancel_unused);

        rc = OBP(exp->exp_obd, cancel_unused)(conn, ea, local);
        RETURN(rc);
}

static inline int obd_san_preprw(int cmd, struct lustre_handle *conn,
                                 int objcount, struct obd_ioobj *obj,
                                 int niocount, struct niobuf_remote *remote)
{
        struct obd_export *exp;
        int rc;

        OBD_CHECK_SETUP(conn, exp);
        OBD_CHECK_OP(exp->exp_obd, preprw);

        rc = OBP(exp->exp_obd, san_preprw)(cmd, conn, objcount, obj,
                                           niocount, remote);
        RETURN(rc);
}


/* OBD Metadata Support */

extern int obd_init_caches(void);
extern void obd_cleanup_caches(void);

static inline struct lustre_handle *obdo_handle(struct obdo *oa)
{
        return (struct lustre_handle *)&oa->o_inline;
}

/* support routines */
extern kmem_cache_t *obdo_cachep;
static inline struct obdo *obdo_alloc(void)
{
        struct obdo *oa;

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

#ifdef __KERNEL__
static inline void obdo_from_iattr(struct obdo *oa, struct iattr *attr)
{
        unsigned int ia_valid = attr->ia_valid;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
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
#else
        if (ia_valid & ATTR_ATIME) {
                oa->o_atime = attr->ia_atime.tv_sec;
                oa->o_valid |= OBD_MD_FLATIME;
        }
        if (ia_valid & ATTR_MTIME) {
                oa->o_mtime = attr->ia_mtime.tv_sec;
                oa->o_valid |= OBD_MD_FLMTIME;
        }
        if (ia_valid & ATTR_CTIME) {
                oa->o_ctime = attr->ia_ctime.tv_sec;
                oa->o_valid |= OBD_MD_FLCTIME;
        }
#endif

        if (ia_valid & ATTR_SIZE) {
                oa->o_size = attr->ia_size;
                oa->o_valid |= OBD_MD_FLSIZE;
        }
        if (ia_valid & ATTR_MODE) {
                oa->o_mode = attr->ia_mode;
                oa->o_valid |= OBD_MD_FLTYPE | OBD_MD_FLMODE;
                if (!in_group_p(oa->o_gid) && !capable(CAP_FSETID))
                        oa->o_mode &= ~S_ISGID;
        }
        if (ia_valid & ATTR_UID) {
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
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
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
#else
        if (valid & OBD_MD_FLATIME) {
                attr->ia_atime.tv_sec = oa->o_atime;
                attr->ia_valid |= ATTR_ATIME;
        }
        if (valid & OBD_MD_FLMTIME) {
                attr->ia_mtime.tv_sec = oa->o_mtime;
                attr->ia_valid |= ATTR_MTIME;
        }
        if (valid & OBD_MD_FLCTIME) {
                attr->ia_ctime.tv_sec = oa->o_ctime;
                attr->ia_valid |= ATTR_CTIME;
        }
#endif
        if (valid & OBD_MD_FLSIZE) {
                attr->ia_size = oa->o_size;
                attr->ia_valid |= ATTR_SIZE;
        }
        if (valid & OBD_MD_FLTYPE) {
                attr->ia_mode = (attr->ia_mode & ~S_IFMT)|(oa->o_mode & S_IFMT);
                attr->ia_valid |= ATTR_MODE;
        }
        if (valid & OBD_MD_FLMODE) {
                attr->ia_mode = (attr->ia_mode & S_IFMT)|(oa->o_mode & ~S_IFMT);
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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define to_kdev_t(dev) dev
#define kdev_t_to_nr(dev) dev
#endif

static inline void obdo_from_inode(struct obdo *dst, struct inode *src,
                                   obd_flag valid)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (valid & OBD_MD_FLATIME)
                dst->o_atime = src->i_atime;
        if (valid & OBD_MD_FLMTIME)
                dst->o_mtime = src->i_mtime;
        if (valid & OBD_MD_FLCTIME)
                dst->o_ctime = src->i_ctime;
#else
        if (valid & OBD_MD_FLATIME)
                dst->o_atime = src->i_atime.tv_sec;
        if (valid & OBD_MD_FLMTIME)
                dst->o_mtime = src->i_mtime.tv_sec;
        if (valid & OBD_MD_FLCTIME)
                dst->o_ctime = src->i_ctime.tv_sec;
#endif
        if (valid & OBD_MD_FLSIZE)
                dst->o_size = src->i_size;
        if (valid & OBD_MD_FLBLOCKS)   /* allocation of space */
                dst->o_blocks = src->i_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                dst->o_blksize = src->i_blksize;
        if (valid & OBD_MD_FLTYPE)
                dst->o_mode = (dst->o_mode & ~S_IFMT) | (src->i_mode & S_IFMT);
        if (valid & OBD_MD_FLMODE)
                dst->o_mode = (dst->o_mode & S_IFMT) | (src->i_mode & ~S_IFMT);
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
                dst->o_rdev = (__u32)kdev_t_to_nr(src->i_rdev);

        dst->o_valid |= (valid & ~OBD_MD_FLID);
}

static inline void obdo_to_inode(struct inode *dst, struct obdo *src,
                                 obd_flag valid)
{
        valid &= src->o_valid;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (valid & OBD_MD_FLATIME)
                dst->i_atime = src->o_atime;
        if (valid & OBD_MD_FLMTIME)
                dst->i_mtime = src->o_mtime;
        if (valid & OBD_MD_FLCTIME && src->o_ctime > dst->i_ctime)
                dst->i_ctime = src->o_ctime;
#else
        if (valid & OBD_MD_FLATIME)
                dst->i_atime.tv_sec = src->o_atime;
        if (valid & OBD_MD_FLMTIME)
                dst->i_mtime.tv_sec = src->o_mtime;
        if (valid & OBD_MD_FLCTIME && src->o_ctime > dst->i_ctime.tv_sec)
                dst->i_ctime.tv_sec = src->o_ctime;
#endif
        if (valid & OBD_MD_FLSIZE)
                dst->i_size = src->o_size;
        if (valid & OBD_MD_FLBLOCKS) /* allocation of space */
                dst->i_blocks = src->o_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                dst->i_blksize = src->o_blksize;
        if (valid & OBD_MD_FLTYPE)
                dst->i_mode = (dst->i_mode & ~S_IFMT) | (src->o_mode & S_IFMT);
        if (valid & OBD_MD_FLMODE)
                dst->i_mode = (dst->i_mode & S_IFMT) | (src->o_mode & ~S_IFMT);
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
                dst->i_rdev = to_kdev_t(src->o_rdev);
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
        if (valid & OBD_MD_FLTYPE)
                dst->o_mode = (dst->o_mode & ~S_IFMT) | (src->o_mode & S_IFMT);
        if (valid & OBD_MD_FLMODE)
                dst->o_mode = (dst->o_mode & S_IFMT) | (src->o_mode & ~S_IFMT);
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
        if ( compare & OBD_MD_FLTYPE )
                res = (res || (((dst->o_mode ^ src->o_mode) & S_IFMT) != 0));
        if ( compare & OBD_MD_FLMODE )
                res = (res || (((dst->o_mode ^ src->o_mode) & ~S_IFMT) != 0));
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


/* I'm as embarrassed about this as you are.
 *
 * <shaver> // XXX do not look into _superhack with remaining eye
 * <shaver> // XXX if this were any uglier, I'd get my own show on MTV */
extern int (*ptlrpc_put_connection_superhack)(struct ptlrpc_connection *c);
extern void (*ptlrpc_abort_inflight_superhack)(struct obd_import *imp,
                                               int dying_import);

int class_register_type(struct obd_ops *ops, struct lprocfs_vars* vars,
                        char *nm);
int class_unregister_type(char *nm);
int class_name2dev(char *name);
int class_uuid2dev(struct obd_uuid *uuid);
struct obd_device *class_uuid2obd(struct obd_uuid *uuid);
struct obd_export *class_new_export(struct obd_device *obddev);
struct obd_type *class_get_type(char *name);
void class_put_type(struct obd_type *type);
void class_destroy_export(struct obd_export *exp);
int class_connect(struct lustre_handle *conn, struct obd_device *obd,
                  struct obd_uuid *cluuid);
int class_disconnect(struct lustre_handle *conn);
void class_disconnect_all(struct obd_device *obddev);

/* generic operations shared by various OBD types */
int class_multi_setup(struct obd_device *obddev, uint32_t len, void *data);
int class_multi_cleanup(struct obd_device *obddev);

extern void (*class_signal_connection_failure)(struct ptlrpc_connection *);

static inline struct ptlrpc_connection *class_rd2conn(struct recovd_data *rd)
{
        /* reuse list_entry's member-pointer offset stuff */
        return list_entry(rd, struct ptlrpc_connection, c_recovd_data);
}

struct obd_statfs;
struct statfs;
void statfs_pack(struct obd_statfs *osfs, struct statfs *sfs);
void statfs_unpack(struct statfs *sfs, struct obd_statfs *osfs);
void obd_statfs_pack(struct obd_statfs *tgt, struct obd_statfs *src);
void obd_statfs_unpack(struct obd_statfs *tgt, struct obd_statfs *src);


struct obd_class_user_state {
        struct obd_device     *ocus_current_obd;
        struct list_head       ocus_conns;
};

struct obd_class_user_conn {
        struct list_head       ocuc_chain;
        struct lustre_handle   ocuc_conn;
};


/* sysctl.c */
extern void obd_sysctl_init (void);
extern void obd_sysctl_clean (void);

/* uuid.c  */
typedef __u8 class_uuid_t[16];
//int class_uuid_parse(struct obd_uuid in, class_uuid_t out);
void class_uuid_unparse(class_uuid_t in, struct obd_uuid *out);

/* lustre_peer.c    */
int lustre_uuid_to_peer(char *uuid, struct lustre_peer *peer);
int class_add_uuid(char *uuid, __u64 nid, __u32 nal);
int class_del_uuid (char *uuid);
void class_init_uuidlist(void);
void class_exit_uuidlist(void);

#endif /* __LINUX_OBD_CLASS_H */
