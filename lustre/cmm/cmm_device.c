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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/cmm/cmm_device.c
 *
 * Lustre Cluster Metadata Manager (cmm)
 *
 * Author: Mike Pershin <tappro@clusterfs.com>
 */
/**
 * \addtogroup cmm
 * @{
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_ver.h>
#include "cmm_internal.h"
#include "mdc_internal.h"
#ifdef HAVE_QUOTA_SUPPORT
# include <lustre_quota.h>
#endif

struct obd_ops cmm_obd_device_ops = {
        .o_owner           = THIS_MODULE
};

static const struct lu_device_operations cmm_lu_ops;

static inline int lu_device_is_cmm(struct lu_device *d)
{
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &cmm_lu_ops);
}

int cmm_root_get(const struct lu_env *env, struct md_device *md,
                 struct lu_fid *fid)
{
        struct cmm_device *cmm_dev = md2cmm_dev(md);
        /* valid only on master MDS */
        if (cmm_dev->cmm_local_num == 0)
                return cmm_child_ops(cmm_dev)->mdo_root_get(env,
                                     cmm_dev->cmm_child, fid);
        else
                return -EINVAL;
}

static int cmm_statfs(const struct lu_env *env, struct md_device *md,
                      cfs_kstatfs_t *sfs)
{
        struct cmm_device *cmm_dev = md2cmm_dev(md);
        int rc;

        ENTRY;
        rc = cmm_child_ops(cmm_dev)->mdo_statfs(env,
                                                cmm_dev->cmm_child, sfs);
        RETURN (rc);
}

static int cmm_maxsize_get(const struct lu_env *env, struct md_device *md,
                           int *md_size, int *cookie_size)
{
        struct cmm_device *cmm_dev = md2cmm_dev(md);
        int rc;
        ENTRY;
        rc = cmm_child_ops(cmm_dev)->mdo_maxsize_get(env, cmm_dev->cmm_child,
                                                     md_size, cookie_size);
        RETURN(rc);
}

static int cmm_init_capa_ctxt(const struct lu_env *env, struct md_device *md,
                              int mode , unsigned long timeout, __u32 alg,
                              struct lustre_capa_key *keys)
{
        struct cmm_device *cmm_dev = md2cmm_dev(md);
        int rc;
        ENTRY;
        LASSERT(cmm_child_ops(cmm_dev)->mdo_init_capa_ctxt);
        rc = cmm_child_ops(cmm_dev)->mdo_init_capa_ctxt(env, cmm_dev->cmm_child,
                                                        mode, timeout, alg,
                                                        keys);
        RETURN(rc);
}

static int cmm_update_capa_key(const struct lu_env *env,
                               struct md_device *md,
                               struct lustre_capa_key *key)
{
        struct cmm_device *cmm_dev = md2cmm_dev(md);
        int rc;
        ENTRY;
        rc = cmm_child_ops(cmm_dev)->mdo_update_capa_key(env,
                                                         cmm_dev->cmm_child,
                                                         key);
        RETURN(rc);
}

static int cmm_llog_ctxt_get(const struct lu_env *env, struct md_device *m,
                             int idx, void **h)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        rc = cmm_child_ops(cmm_dev)->mdo_llog_ctxt_get(env, cmm_dev->cmm_child,
                                                       idx, h);
        RETURN(rc);
}

#ifdef HAVE_QUOTA_SUPPORT
/**
 * \name Quota functions
 * @{
 */
static int cmm_quota_notify(const struct lu_env *env, struct md_device *m)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_notify(env,
                                                          cmm_dev->cmm_child);
        RETURN(rc);
}

static int cmm_quota_setup(const struct lu_env *env, struct md_device *m,
                           void *data)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_setup(env,
                                                         cmm_dev->cmm_child,
                                                         data);
        RETURN(rc);
}

static int cmm_quota_cleanup(const struct lu_env *env, struct md_device *m)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_cleanup(env,
                                                           cmm_dev->cmm_child);
        RETURN(rc);
}

static int cmm_quota_recovery(const struct lu_env *env, struct md_device *m)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_recovery(env,
                                                            cmm_dev->cmm_child);
        RETURN(rc);
}

static int cmm_quota_check(const struct lu_env *env, struct md_device *m,
                           __u32 type)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_check(env,
                                                         cmm_dev->cmm_child,
                                                         type);
        RETURN(rc);
}

static int cmm_quota_on(const struct lu_env *env, struct md_device *m,
                        __u32 type)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_on(env,
                                                      cmm_dev->cmm_child,
                                                      type);
        RETURN(rc);
}

static int cmm_quota_off(const struct lu_env *env, struct md_device *m,
                         __u32 type)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_off(env,
                                                       cmm_dev->cmm_child,
                                                       type);
        RETURN(rc);
}

static int cmm_quota_setinfo(const struct lu_env *env, struct md_device *m,
                             __u32 type, __u32 id, struct obd_dqinfo *dqinfo)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_setinfo(env,
                                                           cmm_dev->cmm_child,
                                                           type, id, dqinfo);
        RETURN(rc);
}

static int cmm_quota_getinfo(const struct lu_env *env,
                             const struct md_device *m,
                             __u32 type, __u32 id, struct obd_dqinfo *dqinfo)
{
        struct cmm_device *cmm_dev = md2cmm_dev((struct md_device *)m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_getinfo(env,
                                                           cmm_dev->cmm_child,
                                                           type, id, dqinfo);
        RETURN(rc);
}

static int cmm_quota_setquota(const struct lu_env *env, struct md_device *m,
                              __u32 type, __u32 id, struct obd_dqblk *dqblk)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_setquota(env,
                                                            cmm_dev->cmm_child,
                                                            type, id, dqblk);
        RETURN(rc);
}

static int cmm_quota_getquota(const struct lu_env *env,
                              const struct md_device *m,
                              __u32 type, __u32 id, struct obd_dqblk *dqblk)
{
        struct cmm_device *cmm_dev = md2cmm_dev((struct md_device *)m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_getquota(env,
                                                            cmm_dev->cmm_child,
                                                            type, id, dqblk);
        RETURN(rc);
}

static int cmm_quota_getoinfo(const struct lu_env *env,
                              const struct md_device *m,
                              __u32 type, __u32 id, struct obd_dqinfo *dqinfo)
{
        struct cmm_device *cmm_dev = md2cmm_dev((struct md_device *)m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_getoinfo(env,
                                                            cmm_dev->cmm_child,
                                                            type, id, dqinfo);
        RETURN(rc);
}

static int cmm_quota_getoquota(const struct lu_env *env,
                               const struct md_device *m,
                               __u32 type, __u32 id, struct obd_dqblk *dqblk)
{
        struct cmm_device *cmm_dev = md2cmm_dev((struct md_device *)m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_getoquota(env,
                                                             cmm_dev->cmm_child,
                                                             type, id, dqblk);
        RETURN(rc);
}

static int cmm_quota_invalidate(const struct lu_env *env, struct md_device *m,
                                __u32 type)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_invalidate(env,
                                                              cmm_dev->cmm_child,
                                                              type);
        RETURN(rc);
}

static int cmm_quota_finvalidate(const struct lu_env *env, struct md_device *m,
                                 __u32 type)
{
        struct cmm_device *cmm_dev = md2cmm_dev(m);
        int rc;
        ENTRY;

        /* disable quota for CMD case temporary. */
        if (cmm_dev->cmm_tgt_count)
                RETURN(-EOPNOTSUPP);

        rc = cmm_child_ops(cmm_dev)->mdo_quota.mqo_finvalidate(env,
                                                               cmm_dev->cmm_child,
                                                               type);
        RETURN(rc);
}
/** @} */
#endif

int cmm_iocontrol(const struct lu_env *env, struct md_device *m,
                  unsigned int cmd, int len, void *data)
{
        struct md_device *next = md2cmm_dev(m)->cmm_child;
        int rc;

        ENTRY;
        rc = next->md_ops->mdo_iocontrol(env, next, cmd, len, data);
        RETURN(rc);
}


static const struct md_device_operations cmm_md_ops = {
        .mdo_statfs          = cmm_statfs,
        .mdo_root_get        = cmm_root_get,
        .mdo_maxsize_get     = cmm_maxsize_get,
        .mdo_init_capa_ctxt  = cmm_init_capa_ctxt,
        .mdo_update_capa_key = cmm_update_capa_key,
        .mdo_llog_ctxt_get   = cmm_llog_ctxt_get,
        .mdo_iocontrol       = cmm_iocontrol,
#ifdef HAVE_QUOTA_SUPPORT
        .mdo_quota           = {
                .mqo_notify      = cmm_quota_notify,
                .mqo_setup       = cmm_quota_setup,
                .mqo_cleanup     = cmm_quota_cleanup,
                .mqo_recovery    = cmm_quota_recovery,
                .mqo_check       = cmm_quota_check,
                .mqo_on          = cmm_quota_on,
                .mqo_off         = cmm_quota_off,
                .mqo_setinfo     = cmm_quota_setinfo,
                .mqo_getinfo     = cmm_quota_getinfo,
                .mqo_setquota    = cmm_quota_setquota,
                .mqo_getquota    = cmm_quota_getquota,
                .mqo_getoinfo    = cmm_quota_getoinfo,
                .mqo_getoquota   = cmm_quota_getoquota,
                .mqo_invalidate  = cmm_quota_invalidate,
                .mqo_finvalidate = cmm_quota_finvalidate
        }
#endif
};

extern struct lu_device_type mdc_device_type;
/**
 * Init MDC.
 */
static int cmm_post_init_mdc(const struct lu_env *env,
                             struct cmm_device *cmm)
{
        int max_mdsize, max_cookiesize, rc;
        struct mdc_device *mc, *tmp;

        /* get the max mdsize and cookiesize from lower layer */
        rc = cmm_maxsize_get(env, &cmm->cmm_md_dev, &max_mdsize,
                             &max_cookiesize);
        if (rc)
                RETURN(rc);

        cfs_spin_lock(&cmm->cmm_tgt_guard);
        cfs_list_for_each_entry_safe(mc, tmp, &cmm->cmm_targets,
                                     mc_linkage) {
                cmm_mdc_init_ea_size(env, mc, max_mdsize, max_cookiesize);
        }
        cfs_spin_unlock(&cmm->cmm_tgt_guard);
        RETURN(rc);
}

/* --- cmm_lu_operations --- */
/* add new MDC to the CMM, create MDC lu_device and connect it to mdc_obd */
static int cmm_add_mdc(const struct lu_env *env,
                       struct cmm_device *cm, struct lustre_cfg *cfg)
{
        struct lu_device_type *ldt = &mdc_device_type;
        char *p, *num = lustre_cfg_string(cfg, 2);
        struct mdc_device *mc, *tmp;
        struct lu_fld_target target;
        struct lu_device *ld;
        struct lu_device *cmm_lu = cmm2lu_dev(cm);
        mdsno_t mdc_num;
        struct lu_site *site = cmm2lu_dev(cm)->ld_site;
        int rc;
#ifdef HAVE_QUOTA_SUPPORT
        int first;
#endif
        ENTRY;

        /* find out that there is no such mdc */
        LASSERT(num);
        mdc_num = simple_strtol(num, &p, 10);
        if (*p) {
                CERROR("Invalid index in lustre_cgf, offset 2\n");
                RETURN(-EINVAL);
        }

        cfs_spin_lock(&cm->cmm_tgt_guard);
        cfs_list_for_each_entry_safe(mc, tmp, &cm->cmm_targets,
                                     mc_linkage) {
                if (mc->mc_num == mdc_num) {
                        cfs_spin_unlock(&cm->cmm_tgt_guard);
                        RETURN(-EEXIST);
                }
        }
        cfs_spin_unlock(&cm->cmm_tgt_guard);
        ld = ldt->ldt_ops->ldto_device_alloc(env, ldt, cfg);
        if (IS_ERR(ld))
                RETURN(PTR_ERR(ld));

        ld->ld_site = site;

        rc = ldt->ldt_ops->ldto_device_init(env, ld, NULL, NULL);
        if (rc) {
                ldt->ldt_ops->ldto_device_free(env, ld);
                RETURN(rc);
        }
        /* pass config to the just created MDC */
        rc = ld->ld_ops->ldo_process_config(env, ld, cfg);
        if (rc) {
                ldt->ldt_ops->ldto_device_fini(env, ld);
                ldt->ldt_ops->ldto_device_free(env, ld);
                RETURN(rc);
        }

        cfs_spin_lock(&cm->cmm_tgt_guard);
        cfs_list_for_each_entry_safe(mc, tmp, &cm->cmm_targets,
                                     mc_linkage) {
                if (mc->mc_num == mdc_num) {
                        cfs_spin_unlock(&cm->cmm_tgt_guard);
                        ldt->ldt_ops->ldto_device_fini(env, ld);
                        ldt->ldt_ops->ldto_device_free(env, ld);
                        RETURN(-EEXIST);
                }
        }
        mc = lu2mdc_dev(ld);
        cfs_list_add_tail(&mc->mc_linkage, &cm->cmm_targets);
        cm->cmm_tgt_count++;
#ifdef HAVE_QUOTA_SUPPORT
        first = cm->cmm_tgt_count;
#endif
        cfs_spin_unlock(&cm->cmm_tgt_guard);

        lu_device_get(cmm_lu);
        lu_ref_add(&cmm_lu->ld_reference, "mdc-child", ld);

        target.ft_srv = NULL;
        target.ft_idx = mc->mc_num;
        target.ft_exp = mc->mc_desc.cl_exp;
        fld_client_add_target(cm->cmm_fld, &target);

        if (mc->mc_num == 0) {
                /* this is mdt0 -> mc export, fld lookup need this export
                   to forward fld lookup request. */
                LASSERT(!lu_site2md(site)->ms_server_fld->lsf_control_exp);
                lu_site2md(site)->ms_server_fld->lsf_control_exp =
                                          mc->mc_desc.cl_exp;
        }
#ifdef HAVE_QUOTA_SUPPORT
        /* XXX: Disable quota for CMD case temporary. */
        if (first == 1) {
                CWARN("Disable quota for CMD case temporary!\n");
                cmm_child_ops(cm)->mdo_quota.mqo_off(env, cm->cmm_child, UGQUOTA);
        }
#endif
        /* Set max md size for the mdc. */
        rc = cmm_post_init_mdc(env, cm);
        RETURN(rc);
}

static void cmm_device_shutdown(const struct lu_env *env,
                                struct cmm_device *cm,
                                struct lustre_cfg *cfg)
{
        struct mdc_device *mc, *tmp;
        ENTRY;

        /* Remove local target from FLD. */
        fld_client_del_target(cm->cmm_fld, cm->cmm_local_num);

        /* Finish all mdc devices. */
        cfs_spin_lock(&cm->cmm_tgt_guard);
        cfs_list_for_each_entry_safe(mc, tmp, &cm->cmm_targets, mc_linkage) {
                struct lu_device *ld_m = mdc2lu_dev(mc);
                fld_client_del_target(cm->cmm_fld, mc->mc_num);
                ld_m->ld_ops->ldo_process_config(env, ld_m, cfg);
        }
        cfs_spin_unlock(&cm->cmm_tgt_guard);

        /* remove upcall device*/
        md_upcall_fini(&cm->cmm_md_dev);

        EXIT;
}

static int cmm_device_mount(const struct lu_env *env,
                            struct cmm_device *m, struct lustre_cfg *cfg)
{
        const char *index = lustre_cfg_string(cfg, 2);
        char *p;

        LASSERT(index != NULL);

        m->cmm_local_num = simple_strtol(index, &p, 10);
        if (*p) {
                CERROR("Invalid index in lustre_cgf\n");
                RETURN(-EINVAL);
        }

        RETURN(0);
}

static int cmm_process_config(const struct lu_env *env,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct cmm_device *m = lu2cmm_dev(d);
        struct lu_device *next = md2lu_dev(m->cmm_child);
        int err;
        ENTRY;

        switch(cfg->lcfg_command) {
        case LCFG_ADD_MDC:
                /* On first ADD_MDC add also local target. */
                if (!(m->cmm_flags & CMM_INITIALIZED)) {
                        struct lu_site *ls = cmm2lu_dev(m)->ld_site;
                        struct lu_fld_target target;

                        target.ft_srv = lu_site2md(ls)->ms_server_fld;
                        target.ft_idx = m->cmm_local_num;
                        target.ft_exp = NULL;

                        fld_client_add_target(m->cmm_fld, &target);
                }
                err = cmm_add_mdc(env, m, cfg);

                /* The first ADD_MDC can be counted as setup is finished. */
                if (!(m->cmm_flags & CMM_INITIALIZED))
                        m->cmm_flags |= CMM_INITIALIZED;

                break;
        case LCFG_SETUP:
        {
                /* lower layers should be set up at first */
                err = next->ld_ops->ldo_process_config(env, next, cfg);
                if (err == 0)
                        err = cmm_device_mount(env, m, cfg);
                break;
        }
        case LCFG_CLEANUP:
        {
                cmm_device_shutdown(env, m, cfg);
        }
        default:
                err = next->ld_ops->ldo_process_config(env, next, cfg);
        }
        RETURN(err);
}

static int cmm_recovery_complete(const struct lu_env *env,
                                 struct lu_device *d)
{
        struct cmm_device *m = lu2cmm_dev(d);
        struct lu_device *next = md2lu_dev(m->cmm_child);
        int rc;
        ENTRY;
        rc = next->ld_ops->ldo_recovery_complete(env, next);
        RETURN(rc);
}

static int cmm_prepare(const struct lu_env *env,
                       struct lu_device *pdev,
                       struct lu_device *dev)
{
        struct cmm_device *cmm = lu2cmm_dev(dev);
        struct lu_device *next = md2lu_dev(cmm->cmm_child);
        int rc;

        ENTRY;
        rc = next->ld_ops->ldo_prepare(env, dev, next);
        RETURN(rc);
}

static const struct lu_device_operations cmm_lu_ops = {
        .ldo_object_alloc      = cmm_object_alloc,
        .ldo_process_config    = cmm_process_config,
        .ldo_recovery_complete = cmm_recovery_complete,
        .ldo_prepare           = cmm_prepare,
};

/* --- lu_device_type operations --- */
int cmm_upcall(const struct lu_env *env, struct md_device *md,
               enum md_upcall_event ev, void *data)
{
        int rc;
        ENTRY;

        switch (ev) {
                case MD_LOV_SYNC:
                        rc = cmm_post_init_mdc(env, md2cmm_dev(md));
                        if (rc)
                                CERROR("can not init md size %d\n", rc);
                        /* fall through */
                default:
                        rc = md_do_upcall(env, md, ev, data);
        }
        RETURN(rc);
}

static struct lu_device *cmm_device_free(const struct lu_env *env,
                                         struct lu_device *d)
{
        struct cmm_device *m = lu2cmm_dev(d);
        struct lu_device  *next = md2lu_dev(m->cmm_child);
        ENTRY;

        LASSERT(m->cmm_tgt_count == 0);
        LASSERT(cfs_list_empty(&m->cmm_targets));
        if (m->cmm_fld != NULL) {
                OBD_FREE_PTR(m->cmm_fld);
                m->cmm_fld = NULL;
        }
        md_device_fini(&m->cmm_md_dev);
        OBD_FREE_PTR(m);
        RETURN(next);
}

static struct lu_device *cmm_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct cmm_device *m;
        ENTRY;

        OBD_ALLOC_PTR(m);
        if (m == NULL) {
                l = ERR_PTR(-ENOMEM);
        } else {
                md_device_init(&m->cmm_md_dev, t);
                m->cmm_md_dev.md_ops = &cmm_md_ops;
                md_upcall_init(&m->cmm_md_dev, cmm_upcall);
                l = cmm2lu_dev(m);
                l->ld_ops = &cmm_lu_ops;

                OBD_ALLOC_PTR(m->cmm_fld);
                if (!m->cmm_fld) {
                        cmm_device_free(env, l);
                        l = ERR_PTR(-ENOMEM);
                }
        }
        RETURN(l);
}

/* context key constructor/destructor: cmm_key_init, cmm_key_fini */
LU_KEY_INIT_FINI(cmm, struct cmm_thread_info);

/* context key: cmm_thread_key */
LU_CONTEXT_KEY_DEFINE(cmm, LCT_MD_THREAD);

struct cmm_thread_info *cmm_env_info(const struct lu_env *env)
{
        struct cmm_thread_info *info;

        info = lu_context_key_get(&env->le_ctx, &cmm_thread_key);
        LASSERT(info != NULL);
        return info;
}

/* type constructor/destructor: cmm_type_init/cmm_type_fini */
LU_TYPE_INIT_FINI(cmm, &cmm_thread_key);

/* 
 * Kludge code : it should be moved mdc_device.c if mdc_(mds)_device
 * is really stacked.
 */
static int __cmm_type_init(struct lu_device_type *t)
{
        int rc;
        rc = lu_device_type_init(&mdc_device_type);
        if (rc == 0) {
                rc = cmm_type_init(t);
                if (rc)
                        lu_device_type_fini(&mdc_device_type);
        }
        return rc;
}

static void __cmm_type_fini(struct lu_device_type *t)
{
        lu_device_type_fini(&mdc_device_type);
        cmm_type_fini(t);
}

static void __cmm_type_start(struct lu_device_type *t)
{
        mdc_device_type.ldt_ops->ldto_start(&mdc_device_type);
        cmm_type_start(t);
}

static void __cmm_type_stop(struct lu_device_type *t)
{
        mdc_device_type.ldt_ops->ldto_stop(&mdc_device_type);
        cmm_type_stop(t);
}

static int cmm_device_init(const struct lu_env *env, struct lu_device *d,
                           const char *name, struct lu_device *next)
{
        struct cmm_device *m = lu2cmm_dev(d);
        struct lu_site *ls;
        int err = 0;
        ENTRY;

        cfs_spin_lock_init(&m->cmm_tgt_guard);
        CFS_INIT_LIST_HEAD(&m->cmm_targets);
        m->cmm_tgt_count = 0;
        m->cmm_child = lu2md_dev(next);

        err = fld_client_init(m->cmm_fld, name,
                              LUSTRE_CLI_FLD_HASH_DHT);
        if (err) {
                CERROR("Can't init FLD, err %d\n", err);
                RETURN(err);
        }

        /* Assign site's fld client ref, needed for asserts in osd. */
        ls = cmm2lu_dev(m)->ld_site;
        lu_site2md(ls)->ms_client_fld = m->cmm_fld;
        err = cmm_procfs_init(m, name);

        RETURN(err);
}

static struct lu_device *cmm_device_fini(const struct lu_env *env,
                                         struct lu_device *ld)
{
        struct cmm_device *cm = lu2cmm_dev(ld);
        struct mdc_device *mc, *tmp;
        struct lu_site *ls;
        ENTRY;

        /* Finish all mdc devices */
        cfs_spin_lock(&cm->cmm_tgt_guard);
        cfs_list_for_each_entry_safe(mc, tmp, &cm->cmm_targets, mc_linkage) {
                struct lu_device *ld_m = mdc2lu_dev(mc);
                struct lu_device *ld_c = cmm2lu_dev(cm);

                cfs_list_del_init(&mc->mc_linkage);
                lu_ref_del(&ld_c->ld_reference, "mdc-child", ld_m);
                lu_device_put(ld_c);
                ld_m->ld_type->ldt_ops->ldto_device_fini(env, ld_m);
                ld_m->ld_type->ldt_ops->ldto_device_free(env, ld_m);
                cm->cmm_tgt_count--;
        }
        cfs_spin_unlock(&cm->cmm_tgt_guard);

        fld_client_fini(cm->cmm_fld);
        ls = cmm2lu_dev(cm)->ld_site;
        lu_site2md(ls)->ms_client_fld = NULL;
        cmm_procfs_fini(cm);

        RETURN (md2lu_dev(cm->cmm_child));
}

static struct lu_device_type_operations cmm_device_type_ops = {
        .ldto_init = __cmm_type_init,
        .ldto_fini = __cmm_type_fini,

        .ldto_start = __cmm_type_start,
        .ldto_stop  = __cmm_type_stop,

        .ldto_device_alloc = cmm_device_alloc,
        .ldto_device_free  = cmm_device_free,

        .ldto_device_init = cmm_device_init,
        .ldto_device_fini = cmm_device_fini
};

static struct lu_device_type cmm_device_type = {
        .ldt_tags     = LU_DEVICE_MD,
        .ldt_name     = LUSTRE_CMM_NAME,
        .ldt_ops      = &cmm_device_type_ops,
        .ldt_ctx_tags = LCT_MD_THREAD | LCT_DT_THREAD
};

struct lprocfs_vars lprocfs_cmm_obd_vars[] = {
        { 0 }
};

struct lprocfs_vars lprocfs_cmm_module_vars[] = {
        { 0 }
};

static void lprocfs_cmm_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars  = lprocfs_cmm_module_vars;
    lvars->obd_vars     = lprocfs_cmm_obd_vars;
}
/** @} */

static int __init cmm_mod_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_cmm_init_vars(&lvars);
        return class_register_type(&cmm_obd_device_ops, NULL, lvars.module_vars,
                                   LUSTRE_CMM_NAME, &cmm_device_type);
}

static void __exit cmm_mod_exit(void)
{
        class_unregister_type(LUSTRE_CMM_NAME);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Clustered Metadata Manager ("LUSTRE_CMM_NAME")");
MODULE_LICENSE("GPL");

cfs_module(cmm, "0.1.0", cmm_mod_init, cmm_mod_exit);
