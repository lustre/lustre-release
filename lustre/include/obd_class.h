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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __CLASS_OBD_H
#define __CLASS_OBD_H

#include <obd_support.h>
#include <lustre_import.h>
#include <lustre_net.h>
#include <obd.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lprocfs_status.h>

#if defined(__linux__)
#include <linux/obd_class.h>
#elif defined(__APPLE__)
#include <darwin/obd_class.h>
#elif defined(__WINNT__)
#include <winnt/obd_class.h>
#else
#error Unsupported operating system.
#endif

/* OBD Device Declarations */
extern struct obd_device *obd_devs[MAX_OBD_DEVICES];
extern spinlock_t obd_dev_lock;
extern cfs_mem_cache_t *obd_lvfs_ctxt_cache;

/* OBD Operations Declarations */
extern struct obd_device *class_conn2obd(struct lustre_handle *);
extern struct obd_device *class_exp2obd(struct obd_export *);
extern int class_handle_ioctl(unsigned int cmd, unsigned long arg);

/* genops.c */
struct obd_export *class_conn2export(struct lustre_handle *);
int class_register_type(struct obd_ops *ops, struct lprocfs_vars *,
                        const char *nm);
int class_unregister_type(const char *nm);

struct obd_device *class_newdev(const char *type_name, const char *name);
void class_release_dev(struct obd_device *obd);

int class_name2dev(const char *name);
struct obd_device *class_name2obd(const char *name);
int class_uuid2dev(struct obd_uuid *uuid);
struct obd_device *class_uuid2obd(struct obd_uuid *uuid);
void class_obd_list(void);
struct obd_device * class_find_client_obd(struct obd_uuid *tgt_uuid,
                                          const char * typ_name,
                                          struct obd_uuid *grp_uuid);
struct obd_device * class_find_client_notype(struct obd_uuid *tgt_uuid,
                                             struct obd_uuid *grp_uuid);
struct obd_device * class_devices_in_group(struct obd_uuid *grp_uuid,
                                           int *next);
struct obd_device * class_num2obd(int num);

int oig_init(struct obd_io_group **oig);
int oig_add_one(struct obd_io_group *oig, struct oig_callback_context *occ);
void oig_complete_one(struct obd_io_group *oig,
                      struct oig_callback_context *occ, int rc);
void oig_release(struct obd_io_group *oig);
int oig_wait(struct obd_io_group *oig);

char *obd_export_nid2str(struct obd_export *exp);

int obd_export_evict_by_nid(struct obd_device *obd, char *nid);
int obd_export_evict_by_uuid(struct obd_device *obd, char *uuid);

int obd_zombie_impexp_init(void);
void obd_zombie_impexp_stop(void);
void obd_zombie_impexp_cull(void);
void obd_zombie_barrier(void);

/* obd_config.c */
int class_process_config(struct lustre_cfg *lcfg);
int class_process_proc_param(char *prefix, struct lprocfs_vars *lvars,
                             struct lustre_cfg *lcfg, void *data);
int class_attach(struct lustre_cfg *lcfg);
int class_setup(struct obd_device *obd, struct lustre_cfg *lcfg);
int class_cleanup(struct obd_device *obd, struct lustre_cfg *lcfg);
int class_detach(struct obd_device *obd, struct lustre_cfg *lcfg);
struct obd_device *class_incref(struct obd_device *obd);
void class_decref(struct obd_device *obd);

/*obdecho*/
#ifdef LPROCFS
extern void lprocfs_echo_init_vars(struct lprocfs_static_vars *lvars);
#else
static inline void lprocfs_echo_init_vars(struct lprocfs_static_vars *lvars)
{
        memset(lvars, 0, sizeof(*lvars));
}
#endif

#define CFG_F_START     0x01   /* Set when we start updating from a log */
#define CFG_F_MARKER    0x02   /* We are within a maker */
#define CFG_F_SKIP      0x04   /* We should ignore this cfg command */
#define CFG_F_COMPAT146 0x08   /* Allow old-style logs */
#define CFG_F_EXCLUDE   0x10   /* OST exclusion list */

/* Passed as data param to class_config_parse_llog */
struct config_llog_instance {
        char *              cfg_instance;
        struct super_block *cfg_sb;
        struct obd_uuid     cfg_uuid;
        int                 cfg_last_idx; /* for partial llog processing */
        int                 cfg_flags;
};
int class_config_parse_llog(struct llog_ctxt *ctxt, char *name,
                            struct config_llog_instance *cfg);
int class_config_dump_llog(struct llog_ctxt *ctxt, char *name,
                           struct config_llog_instance *cfg);

/* list of active configuration logs  */
struct config_llog_data {
        char               *cld_logname;
        struct ldlm_res_id  cld_resid;
        struct config_llog_instance cld_cfg;
        struct list_head    cld_list_chain;
        atomic_t            cld_refcount;
        struct obd_export  *cld_mgcexp;
        unsigned int        cld_stopping:1; /* we were told to stop watching */
        unsigned int        cld_lostlock:1; /* lock not requeued */
        struct semaphore    cld_sem; /* for exclusive processing of the log */
};

struct lustre_profile {
        struct list_head lp_list;
        char * lp_profile;
        char * lp_osc;
        char * lp_mdc;
};

struct lustre_profile *class_get_profile(char * prof);
void class_del_profile(char *prof);
void class_del_profiles(void);

#define class_export_rpc_get(exp)                                       \
({                                                                      \
        atomic_inc(&(exp)->exp_rpc_count);                              \
        CDEBUG(D_INFO, "RPC GETting export %p : new rpc_count %d\n",    \
               (exp), atomic_read(&(exp)->exp_rpc_count));              \
        class_export_get(exp);                                          \
})

#define class_export_rpc_put(exp)                                       \
({                                                                      \
        atomic_dec(&(exp)->exp_rpc_count);                              \
        CDEBUG(D_INFO, "RPC PUTting export %p : new rpc_count %d\n",    \
               (exp), atomic_read(&(exp)->exp_rpc_count));              \
        class_export_put(exp);                                          \
})

/* genops.c */
#define class_export_get(exp)                                                  \
({                                                                             \
        struct obd_export *exp_ = exp;                                         \
        atomic_inc(&exp_->exp_refcount);                                       \
        CDEBUG(D_INFO, "GETting export %p : new refcount %d\n", exp_,          \
               atomic_read(&exp_->exp_refcount));                              \
        exp_;                                                                  \
})

/* class_export_put() is non-blocking */
#define class_export_put(exp)                                                  \
do {                                                                           \
        LASSERT((exp) != NULL);                                                \
        CDEBUG(D_INFO, "PUTting export %p : new refcount %d\n", (exp),         \
               atomic_read(&(exp)->exp_refcount) - 1);                         \
        LASSERT(atomic_read(&(exp)->exp_refcount) > 0);                        \
        LASSERT(atomic_read(&(exp)->exp_refcount) < LI_POISON);                \
        __class_export_put(exp);                                               \
} while (0)

void __class_export_put(struct obd_export *);
struct obd_export *class_new_export(struct obd_device *obddev,
                                    struct obd_uuid *cluuid);
void class_unlink_export(struct obd_export *exp);

struct obd_import *class_import_get(struct obd_import *);
void class_import_put(struct obd_import *);
struct obd_import *class_new_import(struct obd_device *obd);
void class_destroy_import(struct obd_import *exp);

struct obd_type *class_search_type(const char *name);
struct obd_type *class_get_type(const char *name);
void class_put_type(struct obd_type *type);
int class_connect(struct lustre_handle *conn, struct obd_device *obd,
                  struct obd_uuid *cluuid);
int class_disconnect(struct obd_export *exp);
void class_fail_export(struct obd_export *exp);
int class_connected_export(struct obd_export *exp);
void class_disconnect_exports(struct obd_device *obddev);
void class_set_export_delayed(struct obd_export *exp);
void class_handle_stale_exports(struct obd_device *obddev);
void class_disconnect_expired_exports(struct obd_device *obd);
void class_disconnect_stale_exports(struct obd_device *obddev,
                                    enum obd_option flags);
int class_stale_export_list(struct obd_device *obd, struct obd_ioctl_data *data);
int class_manual_cleanup(struct obd_device *obd);

static inline enum obd_option exp_flags_from_obd(struct obd_device *obd)
{
        return ((obd->obd_fail ? OBD_OPT_FAILOVER : 0) |
                (obd->obd_force ? OBD_OPT_FORCE : 0) |
                (obd->obd_abort_recovery ? OBD_OPT_ABORT_RECOV : 0) |
                0);
}

/* obdo.c */
void obdo_cpy_md(struct obdo *dst, struct obdo *src, obd_flag valid);
void obdo_to_ioobj(struct obdo *oa, struct obd_ioobj *ioobj);


#define OBT(dev)        (dev)->obd_type
#define OBP(dev, op)    (dev)->obd_type->typ_ops->o_ ## op
#define CTXTP(ctxt, op) (ctxt)->loc_logops->lop_##op

/* Ensure obd_setup: used for cleanup which must be called
   while obd is stopping */
#define OBD_CHECK_DEV(obd)                                      \
do {                                                            \
        if (!(obd)) {                                           \
                CERROR("NULL device\n");                        \
                RETURN(-ENODEV);                                \
        }                                                       \
} while (0)

/* ensure obd_setup and !obd_stopping */
#define OBD_CHECK_DEV_ACTIVE(obd)                               \
do {                                                            \
        OBD_CHECK_DEV(obd);                                     \
        if (!(obd)->obd_set_up || (obd)->obd_stopping) {        \
                CERROR("Device %d not setup\n",                 \
                       (obd)->obd_minor);                       \
                RETURN(-ENODEV);                                \
        }                                                       \
} while (0)


#ifdef LPROCFS
#define OBD_COUNTER_OFFSET(op)                                  \
        ((offsetof(struct obd_ops, o_ ## op) -                  \
          offsetof(struct obd_ops, o_iocontrol))                \
         / sizeof(((struct obd_ops *)(0))->o_iocontrol))

#define OBD_COUNTER_INCREMENT(obdx, op)                           \
        if ((obdx)->obd_stats != NULL) {                          \
                unsigned int coffset;                             \
                coffset = (unsigned int)((obdx)->obd_cntr_base) + \
                        OBD_COUNTER_OFFSET(op);                   \
                LASSERT(coffset < (obdx)->obd_stats->ls_num);     \
                lprocfs_counter_incr((obdx)->obd_stats, coffset); \
        }

#define EXP_COUNTER_INCREMENT(export, op)                                    \
        if ((export)->exp_obd->obd_stats != NULL) {                          \
                unsigned int coffset;                                        \
                coffset = (unsigned int)((export)->exp_obd->obd_cntr_base) + \
                        OBD_COUNTER_OFFSET(op);                              \
                LASSERT(coffset < (export)->exp_obd->obd_stats->ls_num);     \
                lprocfs_counter_incr((export)->exp_obd->obd_stats, coffset); \
                if ((export)->exp_nid_stats != NULL &&                       \
                    (export)->exp_nid_stats->nid_stats != NULL)              \
                        lprocfs_counter_incr(                                \
                                (export)->exp_nid_stats->nid_stats, coffset);\
        }

#else
#define OBD_COUNTER_OFFSET(op)
#define OBD_COUNTER_INCREMENT(obd, op)
#define EXP_COUNTER_INCREMENT(exp, op);
#endif

static inline int lprocfs_nid_ldlm_stats_init(struct nid_stat* tmp) {
        int rc;

        rc = lprocfs_register_stats(tmp->nid_proc, "stats",
                                    tmp->nid_stats);
        if (rc)
                return rc;

        /* Always add in ldlm_stats */
        tmp->nid_ldlm_stats = lprocfs_alloc_stats(LDLM_LAST_OPC - LDLM_FIRST_OPC
                                                  ,LPROCFS_STATS_FLAG_NOPERCPU);
        if (tmp->nid_ldlm_stats == NULL)
                return -ENOMEM;

        lprocfs_init_ldlm_stats(tmp->nid_ldlm_stats);

        return lprocfs_register_stats(tmp->nid_proc, "ldlm_stats",
                                      tmp->nid_ldlm_stats);
}

#define OBD_CHECK_OP(obd, op, err)                              \
do {                                                            \
        if (!OBT(obd) || !OBP((obd), op)) {\
                if (err)                                        \
                        CERROR("obd_" #op ": dev %d no operation\n",    \
                               obd->obd_minor);                         \
                RETURN(err);                                    \
        }                                                       \
} while (0)

#define EXP_CHECK_OP(exp, op)                                   \
do {                                                            \
        if ((exp) == NULL) {                                    \
                CERROR("obd_" #op ": NULL export\n");           \
                RETURN(-ENODEV);                                \
        }                                                       \
        if ((exp)->exp_obd == NULL || !OBT((exp)->exp_obd)) {   \
                CERROR("obd_" #op ": cleaned up obd\n");        \
                RETURN(-EOPNOTSUPP);                            \
        }                                                       \
        if (!OBT((exp)->exp_obd) || !OBP((exp)->exp_obd, op)) { \
                CERROR("obd_" #op ": dev %d no operation\n",    \
                       (exp)->exp_obd->obd_minor);              \
                RETURN(-EOPNOTSUPP);                            \
        }                                                       \
} while (0)

#define CTXT_CHECK_OP(ctxt, op, err)                                         \
do {                                                            \
        if (!OBT(ctxt->loc_obd) || !CTXTP((ctxt), op)) {                     \
                if (err)                                        \
                        CERROR("lop_" #op ": dev %d no operation\n",    \
                               ctxt->loc_obd->obd_minor);                         \
                RETURN(err);                                    \
        }                                                       \
} while (0)

static inline int class_devno_max(void)
{
        return MAX_OBD_DEVICES;
}

static inline int obd_get_info(struct obd_export *exp, __u32 keylen,
                               void *key, __u32 *vallen, void *val,
                               struct lov_stripe_md *lsm)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, get_info);
        EXP_COUNTER_INCREMENT(exp, get_info);

        rc = OBP(exp->exp_obd, get_info)(exp, keylen, key, vallen, val, lsm);
        RETURN(rc);
}

static inline int obd_set_info_async(struct obd_export *exp, obd_count keylen,
                                     void *key, obd_count vallen, void *val,
                                     struct ptlrpc_request_set *set)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, set_info_async);
        EXP_COUNTER_INCREMENT(exp, set_info_async);

        rc = OBP(exp->exp_obd, set_info_async)(exp, keylen, key, vallen, val,
                                               set);
        RETURN(rc);
}

static inline int obd_setup(struct obd_device *obd, int datalen, void *data)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, setup, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, setup);

        rc = OBP(obd, setup)(obd, datalen, data);
        RETURN(rc);
}

static inline int obd_precleanup(struct obd_device *obd,
                                 enum obd_cleanup_stage cleanup_stage)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, precleanup, 0);
        OBD_COUNTER_INCREMENT(obd, precleanup);

        rc = OBP(obd, precleanup)(obd, cleanup_stage);
        RETURN(rc);
}

static inline int obd_cleanup(struct obd_device *obd)
{
        int rc;
        ENTRY;

        OBD_CHECK_DEV(obd);
        OBD_CHECK_OP(obd, cleanup, 0);
        OBD_COUNTER_INCREMENT(obd, cleanup);

        rc = OBP(obd, cleanup)(obd);
        RETURN(rc);
}

static inline int
obd_process_config(struct obd_device *obd, int datalen, void *data)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, process_config, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, process_config);

        rc = OBP(obd, process_config)(obd, datalen, data);
        RETURN(rc);
}

/* Pack an in-memory MD struct for storage on disk.
 * Returns +ve size of packed MD (0 for free), or -ve error.
 *
 * If @disk_tgt == NULL, MD size is returned (max size if @mem_src == NULL).
 * If @*disk_tgt != NULL and @mem_src == NULL, @*disk_tgt will be freed.
 * If @*disk_tgt == NULL, it will be allocated
 */
static inline int obd_packmd(struct obd_export *exp,
                             struct lov_mds_md **disk_tgt,
                             struct lov_stripe_md *mem_src)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, packmd);
        EXP_COUNTER_INCREMENT(exp, packmd);

        rc = OBP(exp->exp_obd, packmd)(exp, disk_tgt, mem_src);
        RETURN(rc);
}

static inline int obd_size_diskmd(struct obd_export *exp,
                                  struct lov_stripe_md *mem_src)
{
        return obd_packmd(exp, NULL, mem_src);
}

/* helper functions */
static inline int obd_alloc_diskmd(struct obd_export *exp,
                                   struct lov_mds_md **disk_tgt)
{
        LASSERT(disk_tgt);
        LASSERT(*disk_tgt == NULL);
        return obd_packmd(exp, disk_tgt, NULL);
}

static inline int obd_free_diskmd(struct obd_export *exp,
                                  struct lov_mds_md **disk_tgt)
{
        LASSERT(disk_tgt);
        LASSERT(*disk_tgt);
        return obd_packmd(exp, disk_tgt, NULL);
}

/* Unpack an MD struct from disk to in-memory format.
 * Returns +ve size of unpacked MD (0 for free), or -ve error.
 *
 * If @mem_tgt == NULL, MD size is returned (max size if @disk_src == NULL).
 * If @*mem_tgt != NULL and @disk_src == NULL, @*mem_tgt will be freed.
 * If @*mem_tgt == NULL, it will be allocated
 */
static inline int obd_unpackmd(struct obd_export *exp,
                               struct lov_stripe_md **mem_tgt,
                               struct lov_mds_md *disk_src,
                               int disk_len)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, unpackmd);
        EXP_COUNTER_INCREMENT(exp, unpackmd);

        rc = OBP(exp->exp_obd, unpackmd)(exp, mem_tgt, disk_src, disk_len);
        RETURN(rc);
}

/* helper functions */
static inline int obd_alloc_memmd(struct obd_export *exp,
                                  struct lov_stripe_md **mem_tgt)
{
        LASSERT(mem_tgt);
        LASSERT(*mem_tgt == NULL);
        return obd_unpackmd(exp, mem_tgt, NULL, 0);
}

static inline int obd_free_memmd(struct obd_export *exp,
                                 struct lov_stripe_md **mem_tgt)
{
        LASSERT(mem_tgt);
        LASSERT(*mem_tgt);
        return obd_unpackmd(exp, mem_tgt, NULL, 0);
}

static inline int obd_checkmd(struct obd_export *exp,
                              struct obd_export *md_exp,
                              struct lov_stripe_md *mem_tgt)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, checkmd);
        EXP_COUNTER_INCREMENT(exp, checkmd);

        rc = OBP(exp->exp_obd, checkmd)(exp, md_exp, mem_tgt);
        RETURN(rc);
}

static inline int obd_precreate(struct obd_export *exp)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, precreate);
        OBD_COUNTER_INCREMENT(exp->exp_obd, precreate);

        rc = OBP(exp->exp_obd, precreate)(exp);
        RETURN(rc);
}

static inline int obd_create_async(struct obd_export *exp,
                                   struct obd_info *oinfo,
                                   struct lov_stripe_md **ea,
                                   struct obd_trans_info *oti)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, create_async);
        EXP_COUNTER_INCREMENT(exp, create_async);

        rc = OBP(exp->exp_obd, create_async)(exp, oinfo, ea, oti);
        RETURN(rc);
}

static inline int obd_create(struct obd_export *exp, struct obdo *obdo,
                             struct lov_stripe_md **ea,
                             struct obd_trans_info *oti)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, create);
        EXP_COUNTER_INCREMENT(exp, create);

        rc = OBP(exp->exp_obd, create)(exp, obdo, ea, oti);
        RETURN(rc);
}

static inline int obd_destroy(struct obd_export *exp, struct obdo *obdo,
                              struct lov_stripe_md *ea,
                              struct obd_trans_info *oti,
                              struct obd_export *md_exp)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, destroy);
        EXP_COUNTER_INCREMENT(exp, destroy);

        rc = OBP(exp->exp_obd, destroy)(exp, obdo, ea, oti, md_exp);
        RETURN(rc);
}

static inline int obd_getattr(struct obd_export *exp, struct obd_info *oinfo)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, getattr);
        EXP_COUNTER_INCREMENT(exp, getattr);

        rc = OBP(exp->exp_obd, getattr)(exp, oinfo);
        RETURN(rc);
}

static inline int obd_getattr_async(struct obd_export *exp,
                                    struct obd_info *oinfo,
                                    struct ptlrpc_request_set *set)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, getattr_async);
        EXP_COUNTER_INCREMENT(exp, getattr_async);

        rc = OBP(exp->exp_obd, getattr_async)(exp, oinfo, set);
        RETURN(rc);
}

static inline int obd_setattr(struct obd_export *exp, struct obd_info *oinfo,
                              struct obd_trans_info *oti)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, setattr);
        EXP_COUNTER_INCREMENT(exp, setattr);

        rc = OBP(exp->exp_obd, setattr)(exp, oinfo, oti);
        RETURN(rc);
}

/* This performs all the requests set init/wait/destroy actions. */
static inline int obd_setattr_rqset(struct obd_export *exp,
                                    struct obd_info *oinfo,
                                    struct obd_trans_info *oti)
{
        struct ptlrpc_request_set *set = NULL;
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, setattr_async);
        EXP_COUNTER_INCREMENT(exp, setattr_async);

        set =  ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        rc = OBP(exp->exp_obd, setattr_async)(exp, oinfo, oti, set);
        if (rc == 0)
                rc = ptlrpc_set_wait(set);
        ptlrpc_set_destroy(set);
        RETURN(rc);
}

/* This adds all the requests into @set if @set != NULL, otherwise
   all requests are sent asynchronously without waiting for response. */
static inline int obd_setattr_async(struct obd_export *exp,
                                    struct obd_info *oinfo,
                                    struct obd_trans_info *oti,
                                    struct ptlrpc_request_set *set)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, setattr_async);
        EXP_COUNTER_INCREMENT(exp, setattr_async);

        rc = OBP(exp->exp_obd, setattr_async)(exp, oinfo, oti, set);
        RETURN(rc);
}

static inline int obd_add_conn(struct obd_import *imp, struct obd_uuid *uuid,
                               int priority)
{
        struct obd_device *obd = imp->imp_obd;
        int rc;
        ENTRY;

        OBD_CHECK_DEV_ACTIVE(obd);
        OBD_CHECK_OP(obd, add_conn, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, add_conn);

        rc = OBP(obd, add_conn)(imp, uuid, priority);
        RETURN(rc);
}

static inline int obd_del_conn(struct obd_import *imp, struct obd_uuid *uuid)
{
        struct obd_device *obd = imp->imp_obd;
        int rc;
        ENTRY;

        OBD_CHECK_DEV_ACTIVE(obd);
        OBD_CHECK_OP(obd, del_conn, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, del_conn);

        rc = OBP(obd, del_conn)(imp, uuid);
        RETURN(rc);
}

static inline int obd_connect(struct lustre_handle *conn,struct obd_device *obd,
                              struct obd_uuid *cluuid,
                              struct obd_connect_data *d,
                              void *localdata)
{
        int rc;
        __u64 ocf = d ? d->ocd_connect_flags : 0; /* for post-condition check */
        ENTRY;

        OBD_CHECK_DEV_ACTIVE(obd);
        OBD_CHECK_OP(obd, connect, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, connect);

        rc = OBP(obd, connect)(conn, obd, cluuid, d, localdata);
        /* check that only subset is granted */
        LASSERT(ergo(d != NULL,
                     (d->ocd_connect_flags & ocf) == d->ocd_connect_flags));
        RETURN(rc);
}

static inline int obd_reconnect(struct obd_export *exp,
                                struct obd_device *obd,
                                struct obd_uuid *cluuid,
                                struct obd_connect_data *d,
                                void *localdata)
{
        int rc;
        __u64 ocf = d ? d->ocd_connect_flags : 0; /* for post-condition check */
        ENTRY;

        OBD_CHECK_DEV_ACTIVE(obd);
        OBD_CHECK_OP(obd, reconnect, 0);
        OBD_COUNTER_INCREMENT(obd, reconnect);

        rc = OBP(obd, reconnect)(exp, obd, cluuid, d, localdata);
        /* check that only subset is granted */
        LASSERT(ergo(d != NULL,
                     (d->ocd_connect_flags & ocf) == d->ocd_connect_flags));
        RETURN(rc);
}

static inline int obd_disconnect(struct obd_export *exp)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, disconnect);
        EXP_COUNTER_INCREMENT(exp, disconnect);

        rc = OBP(exp->exp_obd, disconnect)(exp);
        RETURN(rc);
}

static inline int obd_fid_init(struct obd_export *exp)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, fid_init, 0);
        EXP_COUNTER_INCREMENT(exp, fid_init);

        rc = OBP(exp->exp_obd, fid_init)(exp);
        RETURN(rc);
}

static inline int obd_fid_fini(struct obd_export *exp)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, fid_fini, 0);
        EXP_COUNTER_INCREMENT(exp, fid_fini);

        rc = OBP(exp->exp_obd, fid_fini)(exp);
        RETURN(rc);
}

static inline int obd_ping(struct obd_export *exp)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, ping, 0);
        EXP_COUNTER_INCREMENT(exp, ping);

        rc = OBP(exp->exp_obd, ping)(exp);
        RETURN(rc);
}

static inline int obd_pool_new(struct obd_device *obd, char *poolname)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, pool_new, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, pool_new);

        rc = OBP(obd, pool_new)(obd, poolname);
        RETURN(rc);
}

static inline int obd_pool_del(struct obd_device *obd, char *poolname)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, pool_del, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, pool_del);

        rc = OBP(obd, pool_del)(obd, poolname);
        RETURN(rc);
}

static inline int obd_pool_add(struct obd_device *obd, char *poolname, char *ostname)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, pool_add, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, pool_add);

        rc = OBP(obd, pool_add)(obd, poolname, ostname);
        RETURN(rc);
}

static inline int obd_pool_rem(struct obd_device *obd, char *poolname, char *ostname)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, pool_rem, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, pool_rem);

        rc = OBP(obd, pool_rem)(obd, poolname, ostname);
        RETURN(rc);
}

static inline void obd_getref(struct obd_device *obd)
{
        ENTRY;
        if (OBT(obd) && OBP(obd, getref)) {
                OBD_COUNTER_INCREMENT(obd, getref);
                OBP(obd, getref)(obd);
        }
        EXIT;
}

static inline void obd_putref(struct obd_device *obd)
{
        ENTRY;
        if (OBT(obd) && OBP(obd, putref)) {
                OBD_COUNTER_INCREMENT(obd, putref);
                OBP(obd, putref)(obd);
        }
        EXIT;
}

static inline int obd_init_export(struct obd_export *exp)
{
        int rc = 0;

        ENTRY;
        if ((exp)->exp_obd != NULL && OBT((exp)->exp_obd) &&
            OBP((exp)->exp_obd, init_export))
                rc = OBP(exp->exp_obd, init_export)(exp);
        RETURN(rc);
}

static inline int obd_destroy_export(struct obd_export *exp)
{
        ENTRY;
        if ((exp)->exp_obd != NULL && OBT((exp)->exp_obd) &&
            OBP((exp)->exp_obd, destroy_export))
                OBP(exp->exp_obd, destroy_export)(exp);
        RETURN(0);
}

static inline int obd_extent_calc(struct obd_export *exp,
                                  struct lov_stripe_md *md,
                                  int cmd, obd_off *offset)
{
        int rc;
        ENTRY;
        EXP_CHECK_OP(exp, extent_calc);
        rc = OBP(exp->exp_obd, extent_calc)(exp, md, cmd, offset);
        RETURN(rc);
}

static inline struct dentry *
obd_lvfs_fid2dentry(struct obd_export *exp, __u64 id_ino, __u32 gen, __u64 gr)
{
        LASSERT(exp->exp_obd);

        return lvfs_fid2dentry(&exp->exp_obd->obd_lvfs_ctxt, id_ino, gen, gr,
                               exp->exp_obd);
}

#ifndef time_before
#define time_before(t1, t2) ((long)t2 - (long)t1 > 0)
#endif

/* @max_age is the oldest time in jiffies that we accept using a cached data.
 * If the cache is older than @max_age we will get a new value from the
 * target.  Use a value of "cfs_time_current() + HZ" to guarantee freshness. */
static inline int obd_statfs_async(struct obd_device *obd,
                                   struct obd_info *oinfo,
                                   __u64 max_age,
                                   struct ptlrpc_request_set *rqset)
{
        int rc = 0;
        ENTRY;

        if (obd == NULL)
                RETURN(-EINVAL);

        OBD_CHECK_OP(obd, statfs, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, statfs);

        CDEBUG(D_SUPER, "%s: osfs %p age "LPU64", max_age "LPU64"\n",
               obd->obd_name, &obd->obd_osfs, obd->obd_osfs_age, max_age);
        if (cfs_time_before_64(obd->obd_osfs_age, max_age)) {
                rc = OBP(obd, statfs_async)(obd, oinfo, max_age, rqset);
        } else {
                CDEBUG(D_SUPER,"%s: use %p cache blocks "LPU64"/"LPU64
                       " objects "LPU64"/"LPU64"\n",
                       obd->obd_name, &obd->obd_osfs,
                       obd->obd_osfs.os_bavail, obd->obd_osfs.os_blocks,
                       obd->obd_osfs.os_ffree, obd->obd_osfs.os_files);
                spin_lock(&obd->obd_osfs_lock);
                memcpy(oinfo->oi_osfs, &obd->obd_osfs, sizeof(*oinfo->oi_osfs));
                spin_unlock(&obd->obd_osfs_lock);
                oinfo->oi_flags |= OBD_STATFS_FROM_CACHE;
                if (oinfo->oi_cb_up)
                        oinfo->oi_cb_up(oinfo, 0);
        }
        RETURN(rc);
}

static inline int obd_statfs_rqset(struct obd_device *obd,
                                   struct obd_statfs *osfs, __u64 max_age,
                                   __u32 flags)
{
        struct ptlrpc_request_set *set = NULL;
        struct obd_info oinfo = { { { 0 } } };
        int rc = 0;
        ENTRY;

        set = ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        oinfo.oi_osfs = osfs;
        oinfo.oi_flags = flags;
        rc = obd_statfs_async(obd, &oinfo, max_age, set);
        if (rc == 0)
                rc = ptlrpc_set_wait(set);
        ptlrpc_set_destroy(set);
        RETURN(rc);
}

/* @max_age is the oldest time in jiffies that we accept using a cached data.
 * If the cache is older than @max_age we will get a new value from the
 * target.  Use a value of "cfs_time_current() + HZ" to guarantee freshness. */
static inline int obd_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                             __u64 max_age, __u32 flags)
{
        int rc = 0;
        ENTRY;

        if (obd == NULL)
                RETURN(-EINVAL);

        OBD_CHECK_OP(obd, statfs, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, statfs);

        CDEBUG(D_SUPER, "osfs "LPU64", max_age "LPU64"\n",
               obd->obd_osfs_age, max_age);
        if (cfs_time_before_64(obd->obd_osfs_age, max_age)) {
                rc = OBP(obd, statfs)(obd, osfs, max_age, flags);
                if (rc == 0) {
                        spin_lock(&obd->obd_osfs_lock);
                        memcpy(&obd->obd_osfs, osfs, sizeof(obd->obd_osfs));
                        obd->obd_osfs_age = cfs_time_current_64();
                        spin_unlock(&obd->obd_osfs_lock);
                }
        } else {
                CDEBUG(D_SUPER,"%s: use %p cache blocks "LPU64"/"LPU64
                       " objects "LPU64"/"LPU64"\n",
                       obd->obd_name, &obd->obd_osfs,
                       obd->obd_osfs.os_bavail, obd->obd_osfs.os_blocks,
                       obd->obd_osfs.os_ffree, obd->obd_osfs.os_files);
                spin_lock(&obd->obd_osfs_lock);
                memcpy(osfs, &obd->obd_osfs, sizeof(*osfs));
                spin_unlock(&obd->obd_osfs_lock);
        }
        RETURN(rc);
}

static inline int obd_sync_rqset(struct obd_export *exp, struct obd_info *oinfo,
                                 obd_size start, obd_size end)
{
        struct ptlrpc_request_set *set = NULL;
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, sync, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, sync);

        set =  ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        rc = OBP(exp->exp_obd, sync)(exp, oinfo, start, end, set);
        if (rc == 0)
                rc = ptlrpc_set_wait(set);
        ptlrpc_set_destroy(set);
        RETURN(rc);
}

static inline int obd_sync(struct obd_export *exp, struct obd_info *oinfo,
                           obd_size start, obd_size end,
                           struct ptlrpc_request_set *set)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, sync, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, sync);

        rc = OBP(exp->exp_obd, sync)(exp, oinfo, start, end, set);
        RETURN(rc);
}

static inline int obd_punch_rqset(struct obd_export *exp,
                                  struct obd_info *oinfo,
                                  struct obd_trans_info *oti)
{
        struct ptlrpc_request_set *set = NULL;
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, punch);
        EXP_COUNTER_INCREMENT(exp, punch);

        set =  ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        rc = OBP(exp->exp_obd, punch)(exp, oinfo, oti, set);
        if (rc == 0)
                rc = ptlrpc_set_wait(set);
        ptlrpc_set_destroy(set);
        RETURN(rc);
}

static inline int obd_punch(struct obd_export *exp, struct obd_info *oinfo,
                            struct obd_trans_info *oti,
                            struct ptlrpc_request_set *rqset)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, punch);
        EXP_COUNTER_INCREMENT(exp, punch);

        rc = OBP(exp->exp_obd, punch)(exp, oinfo, oti, rqset);
        RETURN(rc);
}

static inline int obd_brw(int cmd, struct obd_export *exp,
                          struct obd_info *oinfo, obd_count oa_bufs,
                          struct brw_page *pg, struct obd_trans_info *oti)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, brw);
        EXP_COUNTER_INCREMENT(exp, brw);

        if (!(cmd & (OBD_BRW_RWMASK | OBD_BRW_CHECK))) {
                CERROR("obd_brw: cmd must be OBD_BRW_READ, OBD_BRW_WRITE, "
                       "or OBD_BRW_CHECK\n");
                LBUG();
        }

        rc = OBP(exp->exp_obd, brw)(cmd, exp, oinfo, oa_bufs, pg, oti);
        RETURN(rc);
}

static inline int obd_brw_async(int cmd, struct obd_export *exp,
                                struct obd_info *oinfo, obd_count oa_bufs,
                                struct brw_page *pg, struct obd_trans_info *oti,
                                struct ptlrpc_request_set *set, int pshift)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, brw_async);
        EXP_COUNTER_INCREMENT(exp, brw_async);

        if (!(cmd & OBD_BRW_RWMASK)) {
                CERROR("obd_brw: cmd must be OBD_BRW_READ or OBD_BRW_WRITE\n");
                LBUG();
        }

        rc = OBP(exp->exp_obd, brw_async)(cmd, exp, oinfo, oa_bufs,
                                          pg, oti,set, pshift);
        RETURN(rc);
}

static inline int obd_brw_rqset(int cmd, struct obd_export *exp,
                                struct obdo *oa, struct lov_stripe_md *lsm,
                                obd_count oa_bufs, struct brw_page *pg,
                                struct obd_trans_info *oti)
{
        struct ptlrpc_request_set *set = NULL;
        struct obd_info oinfo = { { { 0 } } };
        int rc = 0;
        ENTRY;

        set =  ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        oinfo.oi_oa = oa;
        oinfo.oi_md = lsm;
        rc = obd_brw_async(cmd, exp, &oinfo, oa_bufs, pg, oti, set, 0);
        if (rc == 0) {
                rc = ptlrpc_set_wait(set);
                if (rc)
                        CERROR("error from callback: rc = %d\n", rc);
        } else {
                CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR,
                       "error from obd_brw_async: rc = %d\n", rc);
        }
        ptlrpc_set_destroy(set);
        RETURN(rc);
}

/* flags used by obd_prep_async_page */
#define OBD_PAGE_NO_CACHE  0x00000001 /* don't add to cache */
#define OBD_FAST_LOCK 0x00000002 /* lockh refers to a "fast lock" */

static inline  int obd_prep_async_page(struct obd_export *exp,
                                       struct lov_stripe_md *lsm,
                                       struct lov_oinfo *loi,
                                       cfs_page_t *page, obd_off offset,
                                       struct obd_async_page_ops *ops,
                                       void *data, void **res, int flags,
                                       struct lustre_handle *lockh)
{
        int ret;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, prep_async_page, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, prep_async_page);

        ret = OBP(exp->exp_obd, prep_async_page)(exp, lsm, loi, page, offset,
                                                 ops, data, res, flags,
                                                 lockh);
        RETURN(ret);
}

static inline int obd_get_lock(struct obd_export *exp,
                               struct lov_stripe_md *lsm, void **res, int rw,
                               obd_off start, obd_off end,
                               struct lustre_handle *lockh, int flags)
{
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, get_lock, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, get_lock);

        RETURN(OBP(exp->exp_obd, get_lock)(exp, lsm, res, rw, start, end,
                                           lockh, flags));
}

static inline int obd_queue_async_io(struct obd_export *exp,
                                     struct lov_stripe_md *lsm,
                                     struct lov_oinfo *loi, void *cookie,
                                     int cmd, obd_off off, int count,
                                     obd_flag brw_flags, obd_flag async_flags)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, queue_async_io, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, queue_async_io);
        LASSERT(cmd & OBD_BRW_RWMASK);

        rc = OBP(exp->exp_obd, queue_async_io)(exp, lsm, loi, cookie, cmd, off,
                                               count, brw_flags, async_flags);
        RETURN(rc);
}

static inline int obd_set_async_flags(struct obd_export *exp,
                                      struct lov_stripe_md *lsm,
                                      struct lov_oinfo *loi, void *cookie,
                                      obd_flag async_flags)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, set_async_flags, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, set_async_flags);

        rc = OBP(exp->exp_obd, set_async_flags)(exp, lsm, loi, cookie,
                                                async_flags);
        RETURN(rc);
}

static inline int obd_queue_group_io(struct obd_export *exp,
                                     struct lov_stripe_md *lsm,
                                     struct lov_oinfo *loi,
                                     struct obd_io_group *oig,
                                     void *cookie, int cmd, obd_off off,
                                     int count, obd_flag brw_flags,
                                     obd_flag async_flags)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, queue_group_io, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, queue_group_io);
        LASSERT(cmd & OBD_BRW_RWMASK);

        rc = OBP(exp->exp_obd, queue_group_io)(exp, lsm, loi, oig, cookie,
                                               cmd, off, count, brw_flags,
                                               async_flags);
        RETURN(rc);
}

static inline int obd_trigger_group_io(struct obd_export *exp,
                                       struct lov_stripe_md *lsm,
                                       struct lov_oinfo *loi,
                                       struct obd_io_group *oig)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, trigger_group_io, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, trigger_group_io);

        rc = OBP(exp->exp_obd, trigger_group_io)(exp, lsm, loi, oig);
        RETURN(rc);
}

static inline int obd_teardown_async_page(struct obd_export *exp,
                                          struct lov_stripe_md *lsm,
                                          struct lov_oinfo *loi, void *cookie)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, teardown_async_page, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, teardown_async_page);

        rc = OBP(exp->exp_obd, teardown_async_page)(exp, lsm, loi, cookie);
        RETURN(rc);
}

static inline int obd_preprw(int cmd, struct obd_export *exp, struct obdo *oa,
                             int objcount, struct obd_ioobj *obj,
                             struct niobuf_remote *remote, int *pages,
                             struct niobuf_local *local,
                             struct obd_trans_info *oti)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, preprw, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, preprw);

        rc = OBP(exp->exp_obd, preprw)(cmd, exp, oa, objcount, obj, remote,
                                       pages, local, oti);
        RETURN(rc);
}

static inline int obd_commitrw(int cmd, struct obd_export *exp, struct obdo *oa,
                               int objcount, struct obd_ioobj *obj,
                               struct niobuf_remote *rnb, int pages,
                               struct niobuf_local *local,
                               struct obd_trans_info *oti, int rc)
{
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, commitrw, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, commitrw);

        rc = OBP(exp->exp_obd, commitrw)(cmd, exp, oa, objcount, obj,
                                         rnb, pages, local, oti, rc);
        RETURN(rc);
}

static inline int obd_merge_lvb(struct obd_export *exp,
                                struct lov_stripe_md *lsm,
                                struct ost_lvb *lvb, int kms_only)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, merge_lvb, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, merge_lvb);

        rc = OBP(exp->exp_obd, merge_lvb)(exp, lsm, lvb, kms_only);
        RETURN(rc);
}

static inline int obd_update_lvb(struct obd_export *exp,
                                 struct lov_stripe_md *lsm,
                                 struct ost_lvb *lvb, obd_flag valid)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, update_lvb, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, update_lvb);

        rc = OBP(exp->exp_obd, update_lvb)(exp, lsm, lvb, valid);
        RETURN(rc);
}

static inline int obd_adjust_kms(struct obd_export *exp,
                                 struct lov_stripe_md *lsm, obd_off size,
                                 int shrink)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, adjust_kms, -EOPNOTSUPP);
        EXP_COUNTER_INCREMENT(exp, adjust_kms);

        rc = OBP(exp->exp_obd, adjust_kms)(exp, lsm, size, shrink);
        RETURN(rc);
}

static inline int obd_iocontrol(unsigned int cmd, struct obd_export *exp,
                                int len, void *karg, void *uarg)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, iocontrol);
        EXP_COUNTER_INCREMENT(exp, iocontrol);

        rc = OBP(exp->exp_obd, iocontrol)(cmd, exp, len, karg, uarg);
        RETURN(rc);
}

static inline int obd_enqueue_rqset(struct obd_export *exp,
                                    struct obd_info *oinfo,
                                    struct ldlm_enqueue_info *einfo)
{
        struct ptlrpc_request_set *set = NULL;
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, enqueue);
        EXP_COUNTER_INCREMENT(exp, enqueue);

        set =  ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        rc = OBP(exp->exp_obd, enqueue)(exp, oinfo, einfo, set);
        if (rc == 0)
                rc = ptlrpc_set_wait(set);
        ptlrpc_set_destroy(set);
        RETURN(rc);
}

static inline int obd_enqueue(struct obd_export *exp,
                              struct obd_info *oinfo,
                              struct ldlm_enqueue_info *einfo,
                              struct ptlrpc_request_set *set)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, enqueue);
        EXP_COUNTER_INCREMENT(exp, enqueue);

        rc = OBP(exp->exp_obd, enqueue)(exp, oinfo, einfo, set);
        RETURN(rc);
}

static inline int obd_match(struct obd_export *exp, struct lov_stripe_md *ea,
                            __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                            int *flags, void *data, struct lustre_handle *lockh,
                            int *n_matches)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, match);
        EXP_COUNTER_INCREMENT(exp, match);

        rc = OBP(exp->exp_obd, match)(exp, ea, type, policy, mode, flags, data,
                                      lockh, n_matches);
        RETURN(rc);
}

static inline int obd_change_cbdata(struct obd_export *exp,
                                    struct lov_stripe_md *lsm,
                                    ldlm_iterator_t it, void *data)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, change_cbdata);
        EXP_COUNTER_INCREMENT(exp, change_cbdata);

        rc = OBP(exp->exp_obd, change_cbdata)(exp, lsm, it, data);
        RETURN(rc);
}

static inline int obd_find_cbdata(struct obd_export *exp,
                                  struct lov_stripe_md *lsm,
                                  ldlm_iterator_t it, void *data)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, find_cbdata);
        EXP_COUNTER_INCREMENT(exp, find_cbdata);

        rc = OBP(exp->exp_obd, find_cbdata)(exp, lsm, it, data);
        RETURN(rc);
}

static inline int obd_cancel(struct obd_export *exp, struct lov_stripe_md *ea,
                             __u32 mode, struct lustre_handle *lockh, int flags,
                             obd_off end)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, cancel);
        EXP_COUNTER_INCREMENT(exp, cancel);

        rc = OBP(exp->exp_obd, cancel)(exp, ea, mode, lockh, flags, end);
        RETURN(rc);
}

static inline int obd_cancel_unused(struct obd_export *exp,
                                    struct lov_stripe_md *ea, int flags,
                                    void *opaque)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, cancel_unused);
        EXP_COUNTER_INCREMENT(exp, cancel_unused);

        rc = OBP(exp->exp_obd, cancel_unused)(exp, ea, flags, opaque);
        RETURN(rc);
}

static inline int obd_join_lru(struct obd_export *exp,
                               struct lov_stripe_md *ea, int join)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, join_lru);
        EXP_COUNTER_INCREMENT(exp, join_lru);

        rc = OBP(exp->exp_obd, join_lru)(exp, ea, join);
        RETURN(rc);
}

static inline int obd_pin(struct obd_export *exp, struct ll_fid *fid,
                          struct obd_client_handle *handle, int flag)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, pin);
        EXP_COUNTER_INCREMENT(exp, pin);

        rc = OBP(exp->exp_obd, pin)(exp, fid, handle, flag);
        RETURN(rc);
}

static inline int obd_unpin(struct obd_export *exp,
                            struct obd_client_handle *handle, int flag)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, unpin);
        EXP_COUNTER_INCREMENT(exp, unpin);

        rc = OBP(exp->exp_obd, unpin)(exp, handle, flag);
        RETURN(rc);
}


static inline void obd_import_event(struct obd_device *obd,
                                    struct obd_import *imp,
                                    enum obd_import_event event)
{
        ENTRY;
        if (!obd) {
                CERROR("NULL device\n");
                EXIT;
                return;
        }
        if (obd->obd_set_up && OBP(obd, import_event)) {
                OBD_COUNTER_INCREMENT(obd, import_event);
                OBP(obd, import_event)(obd, imp, event);
        }
        EXIT;
}

static inline int obd_llog_connect(struct obd_export *exp,
                                   struct llogd_conn_body *body)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(exp->exp_obd, llog_connect, 0);
        EXP_COUNTER_INCREMENT(exp, llog_connect);

        rc = OBP(exp->exp_obd, llog_connect)(exp, body);
        RETURN(rc);
}

static inline int obd_notify(struct obd_device *obd,
                             struct obd_device *watched,
                             enum obd_notify_event ev, void *data)
{
        ENTRY;
        OBD_CHECK_DEV(obd);

        /* the check for async_recov is a complete hack - I'm hereby
           overloading the meaning to also mean "this was called from
           mds_postsetup".  I know that my mds is able to handle notifies
           by this point, and it needs to get them to execute mds_postrecov. */
        if (!obd->obd_set_up && !obd->obd_async_recov) {
                CDEBUG(D_HA, "obd %s not set up\n", obd->obd_name);
                RETURN(-EINVAL);
        }

        if (!OBP(obd, notify))
                RETURN(-ENOSYS);

        OBD_COUNTER_INCREMENT(obd, notify);
        RETURN(OBP(obd, notify)(obd, watched, ev, data));
}

static inline int obd_notify_observer(struct obd_device *observer,
                                      struct obd_device *observed,
                                      enum obd_notify_event ev, void *data)
{
        int rc1;
        int rc2;

        struct obd_notify_upcall *onu;

        if (observer->obd_observer)
                rc1 = obd_notify(observer->obd_observer, observed, ev, data);
        else
                rc1 = 0;
        /*
         * Also, call non-obd listener, if any
         */
        onu = &observer->obd_upcall;
        if (onu->onu_upcall != NULL)
                rc2 = onu->onu_upcall(observer, observed, ev, onu->onu_owner);
        else
                rc2 = 0;

        return rc1 ?: rc2;
 }

static inline int obd_quotacheck(struct obd_export *exp,
                                 struct obd_quotactl *oqctl)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, quotacheck);
        EXP_COUNTER_INCREMENT(exp, quotacheck);

        rc = OBP(exp->exp_obd, quotacheck)(exp, oqctl);
        RETURN(rc);
}

static inline int obd_quotactl(struct obd_export *exp,
                               struct obd_quotactl *oqctl)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, quotactl);
        EXP_COUNTER_INCREMENT(exp, quotactl);

        rc = OBP(exp->exp_obd, quotactl)(exp, oqctl);
        RETURN(rc);
}

static inline int obd_quota_adjust_qunit(struct obd_export *exp,
                                         struct quota_adjust_qunit *oqaq,
                                         struct lustre_quota_ctxt *qctxt)
{
#if defined(LPROCFS) && defined(HAVE_QUOTA_SUPPORT)
        struct timeval work_start;
        struct timeval work_end;
        long timediff;
#endif
        int rc;
        ENTRY;

#if defined(LPROCFS) && defined(HAVE_QUOTA_SUPPORT)
        if (qctxt)
                do_gettimeofday(&work_start);
#endif
        EXP_CHECK_OP(exp, quota_adjust_qunit);
        EXP_COUNTER_INCREMENT(exp, quota_adjust_qunit);

        rc = OBP(exp->exp_obd, quota_adjust_qunit)(exp, oqaq, qctxt);

#if defined(LPROCFS) && defined(HAVE_QUOTA_SUPPORT)
        if (qctxt) {
                do_gettimeofday(&work_end);
                timediff = cfs_timeval_sub(&work_end, &work_start, NULL);
                lprocfs_counter_add(qctxt->lqc_stats, LQUOTA_ADJUST_QUNIT,
                                    timediff);
        }
#endif
        RETURN(rc);
}

static inline int obd_health_check(struct obd_device *obd)
{
        /* returns: 0 on healthy
         *         >0 on unhealthy + reason code/flag
         *            however the only suppored reason == 1 right now
         *            We'll need to define some better reasons
         *            or flags in the future.
         *         <0 on error
         */
        int rc;
        ENTRY;

        /* don't use EXP_CHECK_OP, because NULL method is normal here */
        if (obd == NULL || !OBT(obd)) {
                CERROR("cleaned up obd\n");
                RETURN(-EOPNOTSUPP);
        }
        if (!obd->obd_set_up || obd->obd_stopping)
                RETURN(0);
        if (!OBP(obd, health_check))
                RETURN(0);

        rc = OBP(obd, health_check)(obd);
        RETURN(rc);
}

static inline int obd_register_observer(struct obd_device *obd,
                                        struct obd_device *observer)
{
        ENTRY;
        OBD_CHECK_DEV(obd);
        down_write(&obd->obd_observer_link_sem);
        if (obd->obd_observer && observer) {
                up_write(&obd->obd_observer_link_sem);
                RETURN(-EALREADY);
        }
        obd->obd_observer = observer;
        up_write(&obd->obd_observer_link_sem);
        RETURN(0);
}

static inline int obd_pin_observer(struct obd_device *obd,
                                   struct obd_device **observer)
{
        ENTRY;
        down_read(&obd->obd_observer_link_sem);
        if (!obd->obd_observer) {
                *observer = NULL;
                up_read(&obd->obd_observer_link_sem);
                RETURN(-ENOENT);
        }
        *observer = obd->obd_observer;
        RETURN(0);
}

static inline int obd_unpin_observer(struct obd_device *obd)
{
        ENTRY;
        up_read(&obd->obd_observer_link_sem);
        RETURN(0);
}

static inline int obd_register_page_removal_cb(struct obd_device *obd,
                                               obd_page_removal_cb_t cb,
                                               obd_pin_extent_cb pin_cb)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, register_page_removal_cb, 0);
        OBD_COUNTER_INCREMENT(obd, register_page_removal_cb);

        rc = OBP(obd, register_page_removal_cb)(obd, cb, pin_cb);
        RETURN(rc);
}

static inline int obd_unregister_page_removal_cb(struct obd_device *obd,
                                                 obd_page_removal_cb_t cb)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, unregister_page_removal_cb, 0);
        OBD_COUNTER_INCREMENT(obd, unregister_page_removal_cb);

        rc = OBP(obd, unregister_page_removal_cb)(obd, cb);
        RETURN(rc);
}

static inline int obd_register_lock_cancel_cb(struct obd_device *obd,
                                              obd_lock_cancel_cb cb)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, register_lock_cancel_cb, 0);
        OBD_COUNTER_INCREMENT(obd, register_lock_cancel_cb);

        rc = OBP(obd, register_lock_cancel_cb)(obd, cb);
        RETURN(rc);
}

static inline int obd_unregister_lock_cancel_cb(struct obd_device *obd,
                                                 obd_lock_cancel_cb cb)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, unregister_lock_cancel_cb, 0);
        OBD_COUNTER_INCREMENT(obd, unregister_lock_cancel_cb);

        rc = OBP(obd, unregister_lock_cancel_cb)(obd, cb);
        RETURN(rc);
}

/* OBD Metadata Support */

extern int obd_init_caches(void);
extern void obd_cleanup_caches(void);

/* support routines */
extern cfs_mem_cache_t *obdo_cachep;

#define OBDO_ALLOC(ptr)                                                       \
do {                                                                          \
        OBD_SLAB_ALLOC_PTR_GFP((ptr), obdo_cachep, CFS_ALLOC_IO);             \
} while(0)

#define OBDO_FREE(ptr)                                                        \
do {                                                                          \
        OBD_SLAB_FREE_PTR((ptr), obdo_cachep);                                \
} while(0)

/* I'm as embarrassed about this as you are.
 *
 * <shaver> // XXX do not look into _superhack with remaining eye
 * <shaver> // XXX if this were any uglier, I'd get my own show on MTV */
extern int (*ptlrpc_put_connection_superhack)(struct ptlrpc_connection *c);

/* sysctl.c */
extern void obd_sysctl_init (void);
extern void obd_sysctl_clean (void);

/* uuid.c  */
typedef __u8 class_uuid_t[16];
void class_uuid_unparse(class_uuid_t in, struct obd_uuid *out);

/* lustre_peer.c    */
int lustre_uuid_to_peer(char *uuid, lnet_nid_t *peer_nid, int index);
int class_add_uuid(char *uuid, __u64 nid);
int class_del_uuid (char *uuid);
void class_init_uuidlist(void);
void class_exit_uuidlist(void);

/* prng.c */
void ll_generate_random_uuid(class_uuid_t uuid_out);

#endif /* __LINUX_OBD_CLASS_H */
