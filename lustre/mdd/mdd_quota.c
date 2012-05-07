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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdd/mdd_quota.c
 *
 * Lustre Metadata Server (mdd) routines
 *
 * Author: Fan Yong <Yong.Fan@Sun.Com>
 */

#ifdef HAVE_QUOTA_SUPPORT

#include "mdd_internal.h"

int mdd_quota_notify(const struct lu_env *env, struct md_device *m)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        ENTRY;

        lquota_setinfo(mds_quota_interface_ref, obd, (void *)1);
        RETURN(0);
}

int mdd_quota_setup(const struct lu_env *env, struct md_device *m,
                    void *data)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct dt_device *dt = mdd->mdd_child;
        int rc;
        ENTRY;

	LASSERT(obd->obd_fsops != NULL);
        dt->dd_ops->dt_init_quota_ctxt(env, dt, (void *)obd, data);
        rc = lquota_setup(mds_quota_interface_ref, obd);
        RETURN(rc);
}

int mdd_quota_cleanup(const struct lu_env *env, struct md_device *m)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        int rc1, rc2;
        ENTRY;

        rc1 = lquota_cleanup(mds_quota_interface_ref, obd);
        rc2 = lquota_fs_cleanup(mds_quota_interface_ref, obd);
        RETURN(rc1 ? : rc2);
}

int mdd_quota_recovery(const struct lu_env *env, struct md_device *m)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        int rc;
        ENTRY;

        rc = lquota_recovery(mds_quota_interface_ref, obd);
        RETURN(rc);
}

int mdd_quota_check(const struct lu_env *env, struct md_device *m,
                    __u32 type)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_export *exp = md_quota(env)->mq_exp;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_type = type;
        rc = lquota_check(mds_quota_interface_ref, obd, exp, oqctl);
        RETURN(rc);
}

int mdd_quota_on(const struct lu_env *env, struct md_device *m,
                 __u32 type)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = Q_QUOTAON;
        oqctl->qc_type = type;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        RETURN(rc);
}

int mdd_quota_off(const struct lu_env *env, struct md_device *m,
                  __u32 type)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = Q_QUOTAOFF;
        oqctl->qc_type = type;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        RETURN(rc);
}

int mdd_quota_setinfo(const struct lu_env *env, struct md_device *m,
                      __u32 type, __u32 id, struct obd_dqinfo *dqinfo)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = Q_SETINFO;
        oqctl->qc_type = type;
        oqctl->qc_id = id;
        oqctl->qc_dqinfo = *dqinfo;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        RETURN(rc);
}

int mdd_quota_getinfo(const struct lu_env *env, const struct md_device *m,
                      __u32 type, __u32 id, struct obd_dqinfo *dqinfo)
{
        struct mdd_device *mdd = lu2mdd_dev(
                                 &((struct md_device *)m)->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = Q_GETINFO;
        oqctl->qc_type = type;
        oqctl->qc_id = id;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        *dqinfo = oqctl->qc_dqinfo;
        RETURN(rc);
}

int mdd_quota_setquota(const struct lu_env *env, struct md_device *m,
                       __u32 type, __u32 id, struct obd_dqblk *dqblk)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = Q_SETQUOTA;
        oqctl->qc_type = type;
        oqctl->qc_id = id;
        oqctl->qc_dqblk = *dqblk;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        RETURN(rc);
}

int mdd_quota_getquota(const struct lu_env *env, const struct md_device *m,
                       __u32 type, __u32 id, struct obd_dqblk *dqblk)
{
        struct mdd_device *mdd = lu2mdd_dev(
                                 &((struct md_device *)m)->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = Q_GETQUOTA;
        oqctl->qc_type = type;
        oqctl->qc_id = id;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        *dqblk = oqctl->qc_dqblk;
        RETURN(rc);
}

int mdd_quota_getoinfo(const struct lu_env *env, const struct md_device *m,
                       __u32 type, __u32 id, struct obd_dqinfo *dqinfo)
{
        struct mdd_device *mdd = lu2mdd_dev(
                                 &((struct md_device *)m)->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = Q_GETOINFO;
        oqctl->qc_type = type;
        oqctl->qc_id = id;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        *dqinfo = oqctl->qc_dqinfo;
        RETURN(rc);
}

int mdd_quota_getoquota(const struct lu_env *env, const struct md_device *m,
                        __u32 type, __u32 id, struct obd_dqblk *dqblk)
{
        struct mdd_device *mdd = lu2mdd_dev(
                                 &((struct md_device *)m)->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = Q_GETOQUOTA;
        oqctl->qc_type = type;
        oqctl->qc_id = id;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        *dqblk = oqctl->qc_dqblk;
        RETURN(rc);
}

int mdd_quota_invalidate(const struct lu_env *env, struct md_device *m,
                         __u32 type)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = LUSTRE_Q_INVALIDATE;
        oqctl->qc_type = type;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        RETURN(rc);
}

int mdd_quota_finvalidate(const struct lu_env *env, struct md_device *m,
                          __u32 type)
{
        struct mdd_device *mdd = lu2mdd_dev(&m->md_lu_dev);
        struct obd_device *obd = mdd->mdd_obd_dev;
        struct obd_quotactl *oqctl = &mdd_env_info(env)->mti_oqctl;
        int rc;
        ENTRY;

        oqctl->qc_cmd = LUSTRE_Q_FINVALIDATE;
        oqctl->qc_type = type;
        rc = lquota_ctl(mds_quota_interface_ref, obd, oqctl);
        RETURN(rc);
}
#endif
