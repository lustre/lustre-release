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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LMV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <asm/div64.h>
#include <linux/seq_file.h>
#include <linux/namei.h>
#else
#include <liblustre.h>
#endif

#include <lustre/lustre_idl.h>
#include <obd_support.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_lite.h>
#include <lustre_fid.h>
#include "lmv_internal.h"

/* object cache. */
cfs_mem_cache_t *lmv_object_cache;
cfs_atomic_t lmv_object_count = CFS_ATOMIC_INIT(0);

static void lmv_activate_target(struct lmv_obd *lmv,
                                struct lmv_tgt_desc *tgt,
                                int activate)
{
        if (tgt->ltd_active == activate)
                return;

        tgt->ltd_active = activate;
        lmv->desc.ld_active_tgt_count += (activate ? 1 : -1);
}

/**
 * Error codes:
 *
 *  -EINVAL  : UUID can't be found in the LMV's target list
 *  -ENOTCONN: The UUID is found, but the target connection is bad (!)
 *  -EBADF   : The UUID is found, but the OBD of the wrong type (!)
 */
static int lmv_set_mdc_active(struct lmv_obd *lmv, struct obd_uuid *uuid,
                              int activate)
{
        struct lmv_tgt_desc    *tgt;
        struct obd_device      *obd;
        int                     i;
        int                     rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "Searching in lmv %p for uuid %s (activate=%d)\n",
               lmv, uuid->uuid, activate);

	spin_lock(&lmv->lmv_lock);
        for (i = 0, tgt = lmv->tgts; i < lmv->desc.ld_tgt_count; i++, tgt++) {
                if (tgt->ltd_exp == NULL)
                        continue;

                CDEBUG(D_INFO, "Target idx %d is %s conn "LPX64"\n",
                       i, tgt->ltd_uuid.uuid, tgt->ltd_exp->exp_handle.h_cookie);

                if (obd_uuid_equals(uuid, &tgt->ltd_uuid))
                        break;
        }

        if (i == lmv->desc.ld_tgt_count)
                GOTO(out_lmv_lock, rc = -EINVAL);

        obd = class_exp2obd(tgt->ltd_exp);
        if (obd == NULL)
                GOTO(out_lmv_lock, rc = -ENOTCONN);

        CDEBUG(D_INFO, "Found OBD %s=%s device %d (%p) type %s at LMV idx %d\n",
               obd->obd_name, obd->obd_uuid.uuid, obd->obd_minor, obd,
               obd->obd_type->typ_name, i);
        LASSERT(strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) == 0);

        if (tgt->ltd_active == activate) {
                CDEBUG(D_INFO, "OBD %p already %sactive!\n", obd,
                       activate ? "" : "in");
                GOTO(out_lmv_lock, rc);
        }

        CDEBUG(D_INFO, "Marking OBD %p %sactive\n", obd,
               activate ? "" : "in");
        lmv_activate_target(lmv, tgt, activate);
        EXIT;

 out_lmv_lock:
	spin_unlock(&lmv->lmv_lock);
	return rc;
}

static int lmv_set_mdc_data(struct lmv_obd *lmv, struct obd_uuid *uuid,
			    struct obd_connect_data *data)
{
	struct lmv_tgt_desc    *tgt;
	int                     i;
	ENTRY;

	LASSERT(data != NULL);

	spin_lock(&lmv->lmv_lock);
	for (i = 0, tgt = lmv->tgts; i < lmv->desc.ld_tgt_count; i++, tgt++) {
		if (tgt->ltd_exp == NULL)
			continue;

		if (obd_uuid_equals(uuid, &tgt->ltd_uuid)) {
			lmv->datas[tgt->ltd_idx] = *data;
			break;
		}
	}
	spin_unlock(&lmv->lmv_lock);
	RETURN(0);
}

struct obd_uuid *lmv_get_uuid(struct obd_export *exp) {
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        return obd_get_uuid(lmv->tgts[0].ltd_exp);
}

static int lmv_notify(struct obd_device *obd, struct obd_device *watched,
                      enum obd_notify_event ev, void *data)
{
        struct obd_connect_data *conn_data;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct obd_uuid         *uuid;
        int                      rc = 0;
        ENTRY;

        if (strcmp(watched->obd_type->typ_name, LUSTRE_MDC_NAME)) {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name,
                       watched->obd_name);
                RETURN(-EINVAL);
        }

        uuid = &watched->u.cli.cl_target_uuid;
        if (ev == OBD_NOTIFY_ACTIVE || ev == OBD_NOTIFY_INACTIVE) {
                /*
                 * Set MDC as active before notifying the observer, so the
                 * observer can use the MDC normally.
                 */
                rc = lmv_set_mdc_active(lmv, uuid,
                                        ev == OBD_NOTIFY_ACTIVE);
                if (rc) {
                        CERROR("%sactivation of %s failed: %d\n",
                               ev == OBD_NOTIFY_ACTIVE ? "" : "de",
                               uuid->uuid, rc);
                        RETURN(rc);
                }
        } else if (ev == OBD_NOTIFY_OCD) {
                conn_data = &watched->u.cli.cl_import->imp_connect_data;

                /*
                 * Set connect data to desired target, update exp_connect_flags.
                 */
                rc = lmv_set_mdc_data(lmv, uuid, conn_data);
                if (rc) {
                        CERROR("can't set connect data to target %s, rc %d\n",
                               uuid->uuid, rc);
                        RETURN(rc);
                }

                /*
                 * XXX: Make sure that ocd_connect_flags from all targets are
                 * the same. Otherwise one of MDTs runs wrong version or
                 * something like this.  --umka
                 */
                obd->obd_self_export->exp_connect_flags =
                        conn_data->ocd_connect_flags;
        }
#if 0
        else if (ev == OBD_NOTIFY_DISCON) {
                /*
                 * For disconnect event, flush fld cache for failout MDS case.
                 */
                fld_client_flush(&lmv->lmv_fld);
        }
#endif
        /*
         * Pass the notification up the chain.
         */
        if (obd->obd_observer)
                rc = obd_notify(obd->obd_observer, watched, ev, data);

        RETURN(rc);
}

/**
 * This is fake connect function. Its purpose is to initialize lmv and say
 * caller that everything is okay. Real connection will be performed later.
 */
static int lmv_connect(const struct lu_env *env,
                       struct obd_export **exp, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data,
                       void *localdata)
{
#ifdef __KERNEL__
        struct proc_dir_entry *lmv_proc_dir;
#endif
        struct lmv_obd        *lmv = &obd->u.lmv;
        struct lustre_handle  conn = { 0 };
        int                    rc = 0;
        ENTRY;

        /*
         * We don't want to actually do the underlying connections more than
         * once, so keep track.
         */
        lmv->refcount++;
        if (lmv->refcount > 1) {
                *exp = NULL;
                RETURN(0);
        }

        rc = class_connect(&conn, obd, cluuid);
        if (rc) {
                CERROR("class_connection() returned %d\n", rc);
                RETURN(rc);
        }

        *exp = class_conn2export(&conn);
        class_export_get(*exp);

        lmv->exp = *exp;
        lmv->connected = 0;
        lmv->cluuid = *cluuid;

        if (data)
                lmv->conn_data = *data;

#ifdef __KERNEL__
        lmv_proc_dir = lprocfs_register("target_obds", obd->obd_proc_entry,
                                        NULL, NULL);
        if (IS_ERR(lmv_proc_dir)) {
                CERROR("could not register /proc/fs/lustre/%s/%s/target_obds.",
                       obd->obd_type->typ_name, obd->obd_name);
                lmv_proc_dir = NULL;
        }
#endif

        /*
         * All real clients should perform actual connection right away, because
         * it is possible, that LMV will not have opportunity to connect targets
         * and MDC stuff will be called directly, for instance while reading
         * ../mdc/../kbytesfree procfs file, etc.
         */
        if (data->ocd_connect_flags & OBD_CONNECT_REAL)
                rc = lmv_check_connect(obd);

#ifdef __KERNEL__
        if (rc) {
                if (lmv_proc_dir)
                        lprocfs_remove(&lmv_proc_dir);
        }
#endif

        RETURN(rc);
}

static void lmv_set_timeouts(struct obd_device *obd)
{
        struct lmv_tgt_desc   *tgts;
        struct lmv_obd        *lmv;
        int                    i;

        lmv = &obd->u.lmv;
        if (lmv->server_timeout == 0)
                return;

        if (lmv->connected == 0)
                return;

        for (i = 0, tgts = lmv->tgts; i < lmv->desc.ld_tgt_count; i++, tgts++) {
                if (tgts->ltd_exp == NULL)
                        continue;

                obd_set_info_async(NULL, tgts->ltd_exp, sizeof(KEY_INTERMDS),
                                   KEY_INTERMDS, 0, NULL, NULL);
        }
}

static int lmv_init_ea_size(struct obd_export *exp, int easize,
                            int def_easize, int cookiesize)
{
        struct obd_device   *obd = exp->exp_obd;
        struct lmv_obd      *lmv = &obd->u.lmv;
        int                  i;
        int                  rc = 0;
        int                  change = 0;
        ENTRY;

        if (lmv->max_easize < easize) {
                lmv->max_easize = easize;
                change = 1;
        }
        if (lmv->max_def_easize < def_easize) {
                lmv->max_def_easize = def_easize;
                change = 1;
        }
        if (lmv->max_cookiesize < cookiesize) {
                lmv->max_cookiesize = cookiesize;
                change = 1;
        }
        if (change == 0)
                RETURN(0);

        if (lmv->connected == 0)
                RETURN(0);

        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                if (lmv->tgts[i].ltd_exp == NULL) {
                        CWARN("%s: NULL export for %d\n", obd->obd_name, i);
                        continue;
                }

                rc = md_init_ea_size(lmv->tgts[i].ltd_exp, easize, def_easize,
                                     cookiesize);
                if (rc) {
                        CERROR("obd_init_ea_size() failed on MDT target %d, "
                               "error %d.\n", i, rc);
                        break;
                }
        }
        RETURN(rc);
}

#define MAX_STRING_SIZE 128

int lmv_connect_mdc(struct obd_device *obd, struct lmv_tgt_desc *tgt)
{
#ifdef __KERNEL__
        struct proc_dir_entry   *lmv_proc_dir;
#endif
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct obd_uuid         *cluuid = &lmv->cluuid;
        struct obd_connect_data *mdc_data = NULL;
        struct obd_uuid          lmv_mdc_uuid = { "LMV_MDC_UUID" };
        struct obd_device       *mdc_obd;
        struct obd_export       *mdc_exp;
        struct lu_fld_target     target;
        int                      rc;
        ENTRY;

        mdc_obd = class_find_client_obd(&tgt->ltd_uuid, LUSTRE_MDC_NAME,
                                        &obd->obd_uuid);
        if (!mdc_obd) {
                CERROR("target %s not attached\n", tgt->ltd_uuid.uuid);
                RETURN(-EINVAL);
        }

        CDEBUG(D_CONFIG, "connect to %s(%s) - %s, %s FOR %s\n",
                mdc_obd->obd_name, mdc_obd->obd_uuid.uuid,
                tgt->ltd_uuid.uuid, obd->obd_uuid.uuid,
                cluuid->uuid);

        if (!mdc_obd->obd_set_up) {
                CERROR("target %s is not set up\n", tgt->ltd_uuid.uuid);
                RETURN(-EINVAL);
        }

        rc = obd_connect(NULL, &mdc_exp, mdc_obd, &lmv_mdc_uuid,
                         &lmv->conn_data, NULL);
        if (rc) {
                CERROR("target %s connect error %d\n", tgt->ltd_uuid.uuid, rc);
                RETURN(rc);
        }

        /*
         * Init fid sequence client for this mdc and add new fld target.
         */
        rc = obd_fid_init(mdc_exp);
        if (rc)
                RETURN(rc);

        target.ft_srv = NULL;
        target.ft_exp = mdc_exp;
        target.ft_idx = tgt->ltd_idx;

        fld_client_add_target(&lmv->lmv_fld, &target);

        mdc_data = &class_exp2cliimp(mdc_exp)->imp_connect_data;

        rc = obd_register_observer(mdc_obd, obd);
        if (rc) {
                obd_disconnect(mdc_exp);
                CERROR("target %s register_observer error %d\n",
                       tgt->ltd_uuid.uuid, rc);
                RETURN(rc);
        }

        if (obd->obd_observer) {
                /*
                 * Tell the observer about the new target.
                 */
                rc = obd_notify(obd->obd_observer, mdc_exp->exp_obd,
                                OBD_NOTIFY_ACTIVE, (void *)(tgt - lmv->tgts));
                if (rc) {
                        obd_disconnect(mdc_exp);
                        RETURN(rc);
                }
        }

        tgt->ltd_active = 1;
        tgt->ltd_exp = mdc_exp;
        lmv->desc.ld_active_tgt_count++;

        /*
         * Copy connect data, it may be used later.
         */
        lmv->datas[tgt->ltd_idx] = *mdc_data;

        md_init_ea_size(tgt->ltd_exp, lmv->max_easize,
                        lmv->max_def_easize, lmv->max_cookiesize);

        CDEBUG(D_CONFIG, "Connected to %s(%s) successfully (%d)\n",
                mdc_obd->obd_name, mdc_obd->obd_uuid.uuid,
                cfs_atomic_read(&obd->obd_refcount));

#ifdef __KERNEL__
        lmv_proc_dir = lprocfs_srch(obd->obd_proc_entry, "target_obds");
        if (lmv_proc_dir) {
                struct proc_dir_entry *mdc_symlink;

                LASSERT(mdc_obd->obd_type != NULL);
                LASSERT(mdc_obd->obd_type->typ_name != NULL);
                mdc_symlink = lprocfs_add_symlink(mdc_obd->obd_name,
                                                  lmv_proc_dir,
                                                  "../../../%s/%s",
                                                  mdc_obd->obd_type->typ_name,
                                                  mdc_obd->obd_name);
                if (mdc_symlink == NULL) {
                        CERROR("Could not register LMV target "
                               "/proc/fs/lustre/%s/%s/target_obds/%s.",
                               obd->obd_type->typ_name, obd->obd_name,
                               mdc_obd->obd_name);
                        lprocfs_remove(&lmv_proc_dir);
                        lmv_proc_dir = NULL;
                }
        }
#endif
        RETURN(0);
}

int lmv_add_target(struct obd_device *obd, struct obd_uuid *tgt_uuid)
{
        struct lmv_obd      *lmv = &obd->u.lmv;
        struct lmv_tgt_desc *tgt;
        int                  rc = 0;
        ENTRY;

        CDEBUG(D_CONFIG, "Target uuid: %s.\n", tgt_uuid->uuid);

        lmv_init_lock(lmv);

        if (lmv->desc.ld_active_tgt_count >= LMV_MAX_TGT_COUNT) {
                lmv_init_unlock(lmv);
                CERROR("Can't add %s, LMV module compiled for %d MDCs. "
                       "That many MDCs already configured.\n",
                       tgt_uuid->uuid, LMV_MAX_TGT_COUNT);
                RETURN(-EINVAL);
        }
        if (lmv->desc.ld_tgt_count == 0) {
                struct obd_device *mdc_obd;

                mdc_obd = class_find_client_obd(tgt_uuid, LUSTRE_MDC_NAME,
                                                &obd->obd_uuid);
                if (!mdc_obd) {
                        lmv_init_unlock(lmv);
                        CERROR("Target %s not attached\n", tgt_uuid->uuid);
                        RETURN(-EINVAL);
                }
        }
	spin_lock(&lmv->lmv_lock);
	tgt = lmv->tgts + lmv->desc.ld_tgt_count++;
	tgt->ltd_uuid = *tgt_uuid;
	spin_unlock(&lmv->lmv_lock);

	if (lmv->connected) {
		rc = lmv_connect_mdc(obd, tgt);
		if (rc) {
			spin_lock(&lmv->lmv_lock);
			lmv->desc.ld_tgt_count--;
			memset(tgt, 0, sizeof(*tgt));
			spin_unlock(&lmv->lmv_lock);
                } else {
                        int easize = sizeof(struct lmv_stripe_md) +
                                     lmv->desc.ld_tgt_count *
                                     sizeof(struct lu_fid);
                        lmv_init_ea_size(obd->obd_self_export, easize, 0, 0);
                }
        }

        lmv_init_unlock(lmv);
        RETURN(rc);
}

int lmv_check_connect(struct obd_device *obd)
{
        struct lmv_obd       *lmv = &obd->u.lmv;
        struct lmv_tgt_desc  *tgt;
        int                   i;
        int                   rc;
        int                   easize;
        ENTRY;

        if (lmv->connected)
                RETURN(0);

        lmv_init_lock(lmv);
        if (lmv->connected) {
                lmv_init_unlock(lmv);
                RETURN(0);
        }

        if (lmv->desc.ld_tgt_count == 0) {
                lmv_init_unlock(lmv);
                CERROR("%s: no targets configured.\n", obd->obd_name);
                RETURN(-EINVAL);
        }

        CDEBUG(D_CONFIG, "Time to connect %s to %s\n",
               lmv->cluuid.uuid, obd->obd_name);

        LASSERT(lmv->tgts != NULL);

        for (i = 0, tgt = lmv->tgts; i < lmv->desc.ld_tgt_count; i++, tgt++) {
                rc = lmv_connect_mdc(obd, tgt);
                if (rc)
                        GOTO(out_disc, rc);
        }

        lmv_set_timeouts(obd);
        class_export_put(lmv->exp);
        lmv->connected = 1;
        easize = lmv_get_easize(lmv);
        lmv_init_ea_size(obd->obd_self_export, easize, 0, 0);
        lmv_init_unlock(lmv);
        RETURN(0);

 out_disc:
        while (i-- > 0) {
                int rc2;
                --tgt;
                tgt->ltd_active = 0;
                if (tgt->ltd_exp) {
                        --lmv->desc.ld_active_tgt_count;
                        rc2 = obd_disconnect(tgt->ltd_exp);
                        if (rc2) {
                                CERROR("LMV target %s disconnect on "
                                       "MDC idx %d: error %d\n",
                                       tgt->ltd_uuid.uuid, i, rc2);
                        }
                }
        }
        class_disconnect(lmv->exp);
        lmv_init_unlock(lmv);
        RETURN(rc);
}

static int lmv_disconnect_mdc(struct obd_device *obd, struct lmv_tgt_desc *tgt)
{
#ifdef __KERNEL__
        struct proc_dir_entry  *lmv_proc_dir;
#endif
        struct lmv_obd         *lmv = &obd->u.lmv;
        struct obd_device      *mdc_obd;
        int                     rc;
        ENTRY;

        LASSERT(tgt != NULL);
        LASSERT(obd != NULL);

        mdc_obd = class_exp2obd(tgt->ltd_exp);

        if (mdc_obd) {
                mdc_obd->obd_force = obd->obd_force;
                mdc_obd->obd_fail = obd->obd_fail;
                mdc_obd->obd_no_recov = obd->obd_no_recov;
        }

#ifdef __KERNEL__
        lmv_proc_dir = lprocfs_srch(obd->obd_proc_entry, "target_obds");
        if (lmv_proc_dir) {
                struct proc_dir_entry *mdc_symlink;

                mdc_symlink = lprocfs_srch(lmv_proc_dir, mdc_obd->obd_name);
                if (mdc_symlink) {
                        lprocfs_remove(&mdc_symlink);
                } else {
                        CERROR("/proc/fs/lustre/%s/%s/target_obds/%s missing\n",
                               obd->obd_type->typ_name, obd->obd_name,
                               mdc_obd->obd_name);
                }
        }
#endif
        rc = obd_fid_fini(tgt->ltd_exp);
        if (rc)
                CERROR("Can't finanize fids factory\n");

        CDEBUG(D_INFO, "Disconnected from %s(%s) successfully\n",
               tgt->ltd_exp->exp_obd->obd_name,
               tgt->ltd_exp->exp_obd->obd_uuid.uuid);

        obd_register_observer(tgt->ltd_exp->exp_obd, NULL);
        rc = obd_disconnect(tgt->ltd_exp);
        if (rc) {
                if (tgt->ltd_active) {
                        CERROR("Target %s disconnect error %d\n",
                               tgt->ltd_uuid.uuid, rc);
                }
        }

        lmv_activate_target(lmv, tgt, 0);
        tgt->ltd_exp = NULL;
        RETURN(0);
}

static int lmv_disconnect(struct obd_export *exp)
{
        struct obd_device     *obd = class_exp2obd(exp);
#ifdef __KERNEL__
        struct proc_dir_entry *lmv_proc_dir;
#endif
        struct lmv_obd        *lmv = &obd->u.lmv;
        int                    rc;
        int                    i;
        ENTRY;

        if (!lmv->tgts)
                goto out_local;

        /*
         * Only disconnect the underlying layers on the final disconnect.
         */
        lmv->refcount--;
        if (lmv->refcount != 0)
                goto out_local;

        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                if (lmv->tgts[i].ltd_exp == NULL)
                        continue;
                lmv_disconnect_mdc(obd, &lmv->tgts[i]);
        }

#ifdef __KERNEL__
        lmv_proc_dir = lprocfs_srch(obd->obd_proc_entry, "target_obds");
        if (lmv_proc_dir) {
                lprocfs_remove(&lmv_proc_dir);
        } else {
                CERROR("/proc/fs/lustre/%s/%s/target_obds missing\n",
                       obd->obd_type->typ_name, obd->obd_name);
        }
#endif

out_local:
        /*
         * This is the case when no real connection is established by
         * lmv_check_connect().
         */
        if (!lmv->connected)
                class_export_put(exp);
        rc = class_disconnect(exp);
        if (lmv->refcount == 0)
                lmv->connected = 0;
        RETURN(rc);
}

static int lmv_iocontrol(unsigned int cmd, struct obd_export *exp,
                         int len, void *karg, void *uarg)
{
        struct obd_device    *obddev = class_exp2obd(exp);
        struct lmv_obd       *lmv = &obddev->u.lmv;
        int                   i = 0;
        int                   rc = 0;
        int                   set = 0;
        int                   count = lmv->desc.ld_tgt_count;
        ENTRY;

        if (count == 0)
                RETURN(-ENOTTY);

        switch (cmd) {
        case IOC_OBD_STATFS: {
                struct obd_ioctl_data *data = karg;
                struct obd_device *mdc_obd;
                struct obd_statfs stat_buf = {0};
                __u32 index;

                memcpy(&index, data->ioc_inlbuf2, sizeof(__u32));
                if ((index >= count))
                        RETURN(-ENODEV);

                if (!lmv->tgts[index].ltd_active)
                        RETURN(-ENODATA);

                mdc_obd = class_exp2obd(lmv->tgts[index].ltd_exp);
                if (!mdc_obd)
                        RETURN(-EINVAL);

                /* copy UUID */
                if (cfs_copy_to_user(data->ioc_pbuf2, obd2cli_tgt(mdc_obd),
                                     min((int) data->ioc_plen2,
                                         (int) sizeof(struct obd_uuid))))
                        RETURN(-EFAULT);

                rc = obd_statfs(NULL, lmv->tgts[index].ltd_exp, &stat_buf,
                                cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
                                0);
                if (rc)
                        RETURN(rc);
                if (cfs_copy_to_user(data->ioc_pbuf1, &stat_buf,
                                     min((int) data->ioc_plen1,
                                         (int) sizeof(stat_buf))))
                        RETURN(-EFAULT);
                break;
        }
        case OBD_IOC_QUOTACTL: {
                struct if_quotactl *qctl = karg;
                struct lmv_tgt_desc *tgt = NULL;
                struct obd_quotactl *oqctl;

                if (qctl->qc_valid == QC_MDTIDX) {
                        if (qctl->qc_idx < 0 || count <= qctl->qc_idx)
                                RETURN(-EINVAL);

                        tgt = &lmv->tgts[qctl->qc_idx];
                        if (!tgt->ltd_exp)
                                RETURN(-EINVAL);
                } else if (qctl->qc_valid == QC_UUID) {
                        for (i = 0; i < count; i++) {
                                tgt = &lmv->tgts[i];
                                if (!obd_uuid_equals(&tgt->ltd_uuid,
                                                     &qctl->obd_uuid))
                                        continue;

                                if (tgt->ltd_exp == NULL)
                                        RETURN(-EINVAL);

                                break;
                        }
                } else {
                        RETURN(-EINVAL);
                }

                if (i >= count)
                        RETURN(-EAGAIN);

                LASSERT(tgt && tgt->ltd_exp);
                OBD_ALLOC_PTR(oqctl);
                if (!oqctl)
                        RETURN(-ENOMEM);

                QCTL_COPY(oqctl, qctl);
                rc = obd_quotactl(tgt->ltd_exp, oqctl);
                if (rc == 0) {
                        QCTL_COPY(qctl, oqctl);
                        qctl->qc_valid = QC_MDTIDX;
                        qctl->obd_uuid = tgt->ltd_uuid;
                }
                OBD_FREE_PTR(oqctl);
                break;
        }
        case OBD_IOC_CHANGELOG_SEND:
        case OBD_IOC_CHANGELOG_CLEAR: {
                struct ioc_changelog *icc = karg;

                if (icc->icc_mdtindex >= count)
                        RETURN(-ENODEV);

                rc = obd_iocontrol(cmd, lmv->tgts[icc->icc_mdtindex].ltd_exp,
                                   sizeof(*icc), icc, NULL);
                break;
        }
        case LL_IOC_GET_CONNECT_FLAGS: {
                rc = obd_iocontrol(cmd, lmv->tgts[0].ltd_exp, len, karg, uarg);
                break;
        }

        default : {
                for (i = 0; i < count; i++) {
                        int err;
                        struct obd_device *mdc_obd;

                        if (lmv->tgts[i].ltd_exp == NULL)
                                continue;
                        /* ll_umount_begin() sets force flag but for lmv, not
                         * mdc. Let's pass it through */
                        mdc_obd = class_exp2obd(lmv->tgts[i].ltd_exp);
                        mdc_obd->obd_force = obddev->obd_force;
                        err = obd_iocontrol(cmd, lmv->tgts[i].ltd_exp, len,
                                            karg, uarg);
                        if (err == -ENODATA && cmd == OBD_IOC_POLL_QUOTACHECK) {
                                RETURN(err);
                        } else if (err) {
                                if (lmv->tgts[i].ltd_active) {
                                        CERROR("error: iocontrol MDC %s on MDT"
                                               "idx %d cmd %x: err = %d\n",
                                                lmv->tgts[i].ltd_uuid.uuid,
                                                i, cmd, err);
                                        if (!rc)
                                                rc = err;
                                }
                        } else
                                set = 1;
                }
                if (!set && !rc)
                        rc = -EIO;
        }
        }
        RETURN(rc);
}

static int lmv_all_chars_policy(int count, const char *name,
                                int len)
{
        unsigned int c = 0;

        while (len > 0)
                c += name[--len];
        c = c % count;
        return c;
}

static int lmv_nid_policy(struct lmv_obd *lmv)
{
        struct obd_import *imp;
        __u32              id;

        /*
         * XXX: To get nid we assume that underlying obd device is mdc.
         */
        imp = class_exp2cliimp(lmv->tgts[0].ltd_exp);
        id = imp->imp_connection->c_self ^ (imp->imp_connection->c_self >> 32);
        return id % lmv->desc.ld_tgt_count;
}

static int lmv_choose_mds(struct lmv_obd *lmv, struct md_op_data *op_data,
                          placement_policy_t placement)
{
        switch (placement) {
        case PLACEMENT_CHAR_POLICY:
                return lmv_all_chars_policy(lmv->desc.ld_tgt_count,
                                            op_data->op_name,
                                            op_data->op_namelen);
        case PLACEMENT_NID_POLICY:
                return lmv_nid_policy(lmv);

        default:
                break;
        }

        CERROR("Unsupported placement policy %x\n", placement);
        return -EINVAL;
}

/**
 * This is _inode_ placement policy function (not name).
 */
static int lmv_placement_policy(struct obd_device *obd,
                                struct md_op_data *op_data,
                                mdsno_t *mds)
{
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_object       *obj;
        int                      rc;
        ENTRY;

        LASSERT(mds != NULL);

        if (lmv->desc.ld_tgt_count == 1) {
                *mds = 0;
                RETURN(0);
        }

        /*
         * Allocate new fid on target according to operation type and parent
         * home mds.
         */
        obj = lmv_object_find(obd, &op_data->op_fid1);
        if (obj != NULL || op_data->op_name == NULL ||
            op_data->op_opc != LUSTRE_OPC_MKDIR) {
                /*
                 * Allocate fid for non-dir or for null name or for case parent
                 * dir is split.
                 */
                if (obj) {
                        lmv_object_put(obj);

                        /*
                         * If we have this flag turned on, and we see that
                         * parent dir is split, this means, that caller did not
                         * notice split yet. This is race and we would like to
                         * let caller know that.
                         */
                        if (op_data->op_bias & MDS_CHECK_SPLIT)
                                RETURN(-ERESTART);
                }

                /*
                 * Allocate new fid on same mds where parent fid is located and
                 * where operation will be sent. In case of split dir, ->op_fid1
                 * and ->op_mds here will contain fid and mds of slave directory
                 * object (assigned by caller).
                 */
                *mds = op_data->op_mds;
                rc = 0;
        } else {
                /*
                 * Parent directory is not split and we want to create a
                 * directory in it. Let's calculate where to place it according
                 * to operation data @op_data.
                 */
                *mds = lmv_choose_mds(lmv, op_data, lmv->lmv_placement);
                rc = 0;
        }

        if (rc) {
                CERROR("Can't choose MDS, err = %d\n", rc);
        } else {
                LASSERT(*mds < lmv->desc.ld_tgt_count);
        }

        RETURN(rc);
}

int __lmv_fid_alloc(struct lmv_obd *lmv, struct lu_fid *fid,
                    mdsno_t mds)
{
        struct lmv_tgt_desc *tgt;
        int                  rc;
        ENTRY;

        tgt = lmv_get_target(lmv, mds);

        /*
         * New seq alloc and FLD setup should be atomic. Otherwise we may find
         * on server that seq in new allocated fid is not yet known.
         */
	mutex_lock(&tgt->ltd_fid_mutex);

        if (!tgt->ltd_active)
                GOTO(out, rc = -ENODEV);

        /*
         * Asking underlaying tgt layer to allocate new fid.
         */
        rc = obd_fid_alloc(tgt->ltd_exp, fid, NULL);
        if (rc > 0) {
                LASSERT(fid_is_sane(fid));
                rc = 0;
        }

        EXIT;
out:
	mutex_unlock(&tgt->ltd_fid_mutex);
        return rc;
}

int lmv_fid_alloc(struct obd_export *exp, struct lu_fid *fid,
                  struct md_op_data *op_data)
{
        struct obd_device     *obd = class_exp2obd(exp);
        struct lmv_obd        *lmv = &obd->u.lmv;
        mdsno_t                mds = 0;
        int                    rc;
        ENTRY;

        LASSERT(op_data != NULL);
        LASSERT(fid != NULL);

        rc = lmv_placement_policy(obd, op_data, &mds);
        if (rc) {
                CERROR("Can't get target for allocating fid, "
                       "rc %d\n", rc);
                RETURN(rc);
        }

        rc = __lmv_fid_alloc(lmv, fid, mds);
        if (rc) {
                CERROR("Can't alloc new fid, rc %d\n", rc);
                RETURN(rc);
        }

        RETURN(rc);
}

static int lmv_fid_delete(struct obd_export *exp, const struct lu_fid *fid)
{
        ENTRY;
        LASSERT(exp != NULL && fid != NULL);
        if (lmv_object_delete(exp, fid)) {
                CDEBUG(D_INODE, "Object "DFID" is destroyed.\n",
                       PFID(fid));
        }
        RETURN(0);
}

static int lmv_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct lmv_obd             *lmv = &obd->u.lmv;
        struct lprocfs_static_vars  lvars;
        struct lmv_desc            *desc;
        int                         rc;
        int                         i = 0;
        ENTRY;

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
                CERROR("LMV setup requires a descriptor\n");
                RETURN(-EINVAL);
        }

        desc = (struct lmv_desc *)lustre_cfg_buf(lcfg, 1);
        if (sizeof(*desc) > LUSTRE_CFG_BUFLEN(lcfg, 1)) {
                CERROR("Lmv descriptor size wrong: %d > %d\n",
                       (int)sizeof(*desc), LUSTRE_CFG_BUFLEN(lcfg, 1));
                RETURN(-EINVAL);
        }

        lmv->tgts_size = LMV_MAX_TGT_COUNT * sizeof(struct lmv_tgt_desc);

        OBD_ALLOC(lmv->tgts, lmv->tgts_size);
        if (lmv->tgts == NULL)
                RETURN(-ENOMEM);

        for (i = 0; i < LMV_MAX_TGT_COUNT; i++) {
		mutex_init(&lmv->tgts[i].ltd_fid_mutex);
                lmv->tgts[i].ltd_idx = i;
        }

        lmv->datas_size = LMV_MAX_TGT_COUNT * sizeof(struct obd_connect_data);

        OBD_ALLOC(lmv->datas, lmv->datas_size);
        if (lmv->datas == NULL)
                GOTO(out_free_tgts, rc = -ENOMEM);

        obd_str2uuid(&lmv->desc.ld_uuid, desc->ld_uuid.uuid);
        lmv->desc.ld_tgt_count = 0;
        lmv->desc.ld_active_tgt_count = 0;
        lmv->max_cookiesize = 0;
        lmv->max_def_easize = 0;
        lmv->max_easize = 0;
        lmv->lmv_placement = PLACEMENT_CHAR_POLICY;

	spin_lock_init(&lmv->lmv_lock);
	mutex_init(&lmv->init_mutex);

        rc = lmv_object_setup(obd);
        if (rc) {
                CERROR("Can't setup LMV object manager, error %d.\n", rc);
                GOTO(out_free_datas, rc);
        }

        lprocfs_lmv_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);
#ifdef LPROCFS
        {
                rc = lprocfs_seq_create(obd->obd_proc_entry, "target_obd",
                                        0444, &lmv_proc_target_fops, obd);
                if (rc)
                        CWARN("%s: error adding LMV target_obd file: rc = %d\n",
                               obd->obd_name, rc);
       }
#endif
        rc = fld_client_init(&lmv->lmv_fld, obd->obd_name,
                             LUSTRE_CLI_FLD_HASH_DHT);
        if (rc) {
                CERROR("Can't init FLD, err %d\n", rc);
                GOTO(out_free_datas, rc);
        }

        RETURN(0);

out_free_datas:
        OBD_FREE(lmv->datas, lmv->datas_size);
        lmv->datas = NULL;
out_free_tgts:
        OBD_FREE(lmv->tgts, lmv->tgts_size);
        lmv->tgts = NULL;
        return rc;
}

static int lmv_cleanup(struct obd_device *obd)
{
        struct lmv_obd   *lmv = &obd->u.lmv;
        ENTRY;

        fld_client_fini(&lmv->lmv_fld);
        lmv_object_cleanup(obd);
        OBD_FREE(lmv->datas, lmv->datas_size);
        OBD_FREE(lmv->tgts, lmv->tgts_size);

        RETURN(0);
}

static int lmv_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg     *lcfg = buf;
        struct obd_uuid        tgt_uuid;
        int                    rc;
        ENTRY;

        switch(lcfg->lcfg_command) {
        case LCFG_ADD_MDC:
                if (LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(tgt_uuid.uuid))
                        GOTO(out, rc = -EINVAL);

                obd_str2uuid(&tgt_uuid, lustre_cfg_string(lcfg, 1));
                rc = lmv_add_target(obd, &tgt_uuid);
                GOTO(out, rc);
        default: {
                CERROR("Unknown command: %d\n", lcfg->lcfg_command);
                GOTO(out, rc = -EINVAL);
        }
        }
out:
        RETURN(rc);
}

static int lmv_statfs(const struct lu_env *env, struct obd_export *exp,
                      struct obd_statfs *osfs, __u64 max_age, __u32 flags)
{
        struct obd_device     *obd = class_exp2obd(exp);
        struct lmv_obd        *lmv = &obd->u.lmv;
        struct obd_statfs     *temp;
        int                    rc = 0;
        int                    i;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        OBD_ALLOC(temp, sizeof(*temp));
        if (temp == NULL)
                RETURN(-ENOMEM);

        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                if (lmv->tgts[i].ltd_exp == NULL)
                        continue;

                rc = obd_statfs(env, lmv->tgts[i].ltd_exp, temp,
                                max_age, flags);
                if (rc) {
                        CERROR("can't stat MDS #%d (%s), error %d\n", i,
                               lmv->tgts[i].ltd_exp->exp_obd->obd_name,
                               rc);
                        GOTO(out_free_temp, rc);
                }
                if (i == 0) {
                        *osfs = *temp;
                } else {
                        osfs->os_bavail += temp->os_bavail;
                        osfs->os_blocks += temp->os_blocks;
                        osfs->os_ffree += temp->os_ffree;
                        osfs->os_files += temp->os_files;
                }
        }

        EXIT;
out_free_temp:
        OBD_FREE(temp, sizeof(*temp));
        return rc;
}

static int lmv_getstatus(struct obd_export *exp,
                         struct lu_fid *fid,
                         struct obd_capa **pc)
{
        struct obd_device    *obd = exp->exp_obd;
        struct lmv_obd       *lmv = &obd->u.lmv;
        int                   rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        rc = md_getstatus(lmv->tgts[0].ltd_exp, fid, pc);
        RETURN(rc);
}

static int lmv_getxattr(struct obd_export *exp, const struct lu_fid *fid,
                        struct obd_capa *oc, obd_valid valid, const char *name,
                        const char *input, int input_size, int output_size,
                        int flags, struct ptlrpc_request **request)
{
        struct obd_device      *obd = exp->exp_obd;
        struct lmv_obd         *lmv = &obd->u.lmv;
        struct lmv_tgt_desc    *tgt;
        int                     rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        tgt = lmv_find_target(lmv, fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = md_getxattr(tgt->ltd_exp, fid, oc, valid, name, input,
                         input_size, output_size, flags, request);

        RETURN(rc);
}

static int lmv_setxattr(struct obd_export *exp, const struct lu_fid *fid,
                        struct obd_capa *oc, obd_valid valid, const char *name,
                        const char *input, int input_size, int output_size,
                        int flags, __u32 suppgid,
                        struct ptlrpc_request **request)
{
        struct obd_device      *obd = exp->exp_obd;
        struct lmv_obd         *lmv = &obd->u.lmv;
        struct lmv_tgt_desc    *tgt;
        int                     rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        tgt = lmv_find_target(lmv, fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = md_setxattr(tgt->ltd_exp, fid, oc, valid, name, input,
                         input_size, output_size, flags, suppgid,
                         request);

        RETURN(rc);
}

static int lmv_getattr(struct obd_export *exp, struct md_op_data *op_data,
                       struct ptlrpc_request **request)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        struct lmv_object       *obj;
        int                      rc;
        int                      i;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        tgt = lmv_find_target(lmv, &op_data->op_fid1);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

	if (op_data->op_flags & MF_GET_MDT_IDX) {
		op_data->op_mds = tgt->ltd_idx;
		RETURN(0);
	}

        rc = md_getattr(tgt->ltd_exp, op_data, request);
        if (rc)
                RETURN(rc);

        obj = lmv_object_find_lock(obd, &op_data->op_fid1);

        CDEBUG(D_INODE, "GETATTR for "DFID" %s\n", PFID(&op_data->op_fid1),
               obj ? "(split)" : "");

        /*
         * If object is split, then we loop over all the slaves and gather size
         * attribute. In ideal world we would have to gather also mds field from
         * all slaves, as object is spread over the cluster and this is
         * definitely interesting information and it is not good to loss it,
         * but...
         */
        if (obj) {
                struct mdt_body *body;

                if (*request == NULL) {
                        lmv_object_put(obj);
                        RETURN(rc);
                }

                body = req_capsule_server_get(&(*request)->rq_pill,
                                              &RMF_MDT_BODY);
                LASSERT(body != NULL);

                for (i = 0; i < obj->lo_objcount; i++) {
                        if (lmv->tgts[i].ltd_exp == NULL) {
                                CWARN("%s: NULL export for %d\n",
                                      obd->obd_name, i);
                                continue;
                        }

                        /*
                         * Skip master object.
                         */
                        if (lu_fid_eq(&obj->lo_fid, &obj->lo_stripes[i].ls_fid))
                                continue;

                        body->size += obj->lo_stripes[i].ls_size;
                }

                lmv_object_put_unlock(obj);
        }

        RETURN(rc);
}

static int lmv_change_cbdata(struct obd_export *exp, const struct lu_fid *fid,
                             ldlm_iterator_t it, void *data)
{
        struct obd_device   *obd = exp->exp_obd;
        struct lmv_obd      *lmv = &obd->u.lmv;
        int                  i;
        int                  rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        CDEBUG(D_INODE, "CBDATA for "DFID"\n", PFID(fid));

        /*
         * With CMD every object can have two locks in different namespaces:
         * lookup lock in space of mds storing direntry and update/open lock in
         * space of mds storing inode.
         */
        for (i = 0; i < lmv->desc.ld_tgt_count; i++)
                md_change_cbdata(lmv->tgts[i].ltd_exp, fid, it, data);

        RETURN(0);
}

static int lmv_find_cbdata(struct obd_export *exp, const struct lu_fid *fid,
                           ldlm_iterator_t it, void *data)
{
        struct obd_device   *obd = exp->exp_obd;
        struct lmv_obd      *lmv = &obd->u.lmv;
        int                  i;
        int                  rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        CDEBUG(D_INODE, "CBDATA for "DFID"\n", PFID(fid));

        /*
         * With CMD every object can have two locks in different namespaces:
         * lookup lock in space of mds storing direntry and update/open lock in
         * space of mds storing inode.
         */
        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                rc = md_find_cbdata(lmv->tgts[i].ltd_exp, fid, it, data);
                if (rc)
                        RETURN(rc);
        }

        RETURN(rc);
}


static int lmv_close(struct obd_export *exp, struct md_op_data *op_data,
                     struct md_open_data *mod, struct ptlrpc_request **request)
{
        struct obd_device     *obd = exp->exp_obd;
        struct lmv_obd        *lmv = &obd->u.lmv;
        struct lmv_tgt_desc   *tgt;
        int                    rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        tgt = lmv_find_target(lmv, &op_data->op_fid1);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        CDEBUG(D_INODE, "CLOSE "DFID"\n", PFID(&op_data->op_fid1));
        rc = md_close(tgt->ltd_exp, op_data, mod, request);
        RETURN(rc);
}

/**
 * Called in the case MDS returns -ERESTART on create on open, what means that
 * directory is split and its LMV presentation object has to be updated.
 */
int lmv_handle_split(struct obd_export *exp, const struct lu_fid *fid)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct ptlrpc_request   *req = NULL;
        struct lmv_tgt_desc     *tgt;
        struct lmv_object       *obj;
        struct lustre_md         md;
        struct md_op_data       *op_data;
        int                      mealen;
        int                      rc;
        __u64                    valid;
        ENTRY;

        md.mea = NULL;
        mealen = lmv_get_easize(lmv);

        valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA | OBD_MD_MEA;

        tgt = lmv_find_target(lmv, fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        /*
         * Time to update mea of parent fid.
         */

        OBD_ALLOC_PTR(op_data);
        if (op_data == NULL) 
                RETURN(-ENOMEM);

        op_data->op_fid1 = *fid;
        op_data->op_mode = mealen;
        op_data->op_valid = valid;

        rc = md_getattr(tgt->ltd_exp, op_data, &req);
        OBD_FREE_PTR(op_data);
        if (rc) {
                CERROR("md_getattr() failed, error %d\n", rc);
                GOTO(cleanup, rc);
        }

        rc = md_get_lustre_md(tgt->ltd_exp, req, NULL, exp, &md);
        if (rc) {
                CERROR("md_get_lustre_md() failed, error %d\n", rc);
                GOTO(cleanup, rc);
        }

        if (md.mea == NULL)
                GOTO(cleanup, rc = -ENODATA);

        obj = lmv_object_create(exp, fid, md.mea);
        if (IS_ERR(obj))
                rc = PTR_ERR(obj);
        else
                lmv_object_put(obj);

        obd_free_memmd(exp, (void *)&md.mea);
        EXIT;
cleanup:
        if (req)
                ptlrpc_req_finished(req);
        return rc;
}

int lmv_create(struct obd_export *exp, struct md_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid,
               __u32 gid, cfs_cap_t cap_effective, __u64 rdev,
               struct ptlrpc_request **request)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        struct lmv_object       *obj;
        int                      rc;
        int                      loop = 0;
        int                      sidx;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        if (!lmv->desc.ld_active_tgt_count)
                RETURN(-EIO);
repeat:
        ++loop;
        LASSERT(loop <= 2);

        obj = lmv_object_find(obd, &op_data->op_fid1);
        if (obj) {
                sidx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                       op_data->op_name, op_data->op_namelen);
                op_data->op_fid1 = obj->lo_stripes[sidx].ls_fid;
                op_data->op_bias &= ~MDS_CHECK_SPLIT;
                op_data->op_mds = obj->lo_stripes[sidx].ls_mds;
                tgt = lmv_get_target(lmv, op_data->op_mds);
                lmv_object_put(obj);
        } else {
                tgt = lmv_find_target(lmv, &op_data->op_fid1);
                op_data->op_bias |= MDS_CHECK_SPLIT;
                op_data->op_mds = tgt->ltd_idx;
        }

        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = lmv_fid_alloc(exp, &op_data->op_fid2, op_data);
        if (rc == -ERESTART)
                goto repeat;
        else if (rc)
                RETURN(rc);

        CDEBUG(D_INODE, "CREATE '%*s' on "DFID" -> mds #%x\n",
               op_data->op_namelen, op_data->op_name, PFID(&op_data->op_fid1),
               op_data->op_mds);

        op_data->op_flags |= MF_MDC_CANCEL_FID1;
        rc = md_create(tgt->ltd_exp, op_data, data, datalen, mode, uid, gid,
                       cap_effective, rdev, request);
        if (rc == 0) {
                if (*request == NULL)
                        RETURN(rc);
                CDEBUG(D_INODE, "Created - "DFID"\n", PFID(&op_data->op_fid2));
        } else if (rc == -ERESTART) {
                LASSERT(*request != NULL);
                DEBUG_REQ(D_WARNING|D_RPCTRACE, *request,
                          "Got -ERESTART during create!\n");
                ptlrpc_req_finished(*request);
                *request = NULL;

                /*
                 * Directory got split. Time to update local object and repeat
                 * the request with proper MDS.
                 */
                rc = lmv_handle_split(exp, &op_data->op_fid1);
                if (rc == 0) {
                        rc = lmv_allocate_slaves(obd, &op_data->op_fid1,
                                                 op_data, &op_data->op_fid2);
                        if (rc)
                                RETURN(rc);
                        goto repeat;
                }
        }
        RETURN(rc);
}

static int lmv_done_writing(struct obd_export *exp,
                            struct md_op_data *op_data,
                            struct md_open_data *mod)
{
        struct obd_device     *obd = exp->exp_obd;
        struct lmv_obd        *lmv = &obd->u.lmv;
        struct lmv_tgt_desc   *tgt;
        int                    rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        tgt = lmv_find_target(lmv, &op_data->op_fid1);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = md_done_writing(tgt->ltd_exp, op_data, mod);
        RETURN(rc);
}

static int
lmv_enqueue_slaves(struct obd_export *exp, struct ldlm_enqueue_info *einfo,
                   struct lookup_intent *it, struct md_op_data *op_data,
                   struct lustre_handle *lockh, void *lmm, int lmmsize)
{
        struct obd_device     *obd = exp->exp_obd;
        struct lmv_obd        *lmv = &obd->u.lmv;
        struct lmv_stripe_md  *mea = op_data->op_mea1;
        struct md_op_data     *op_data2;
        struct lmv_tgt_desc   *tgt;
        int                    i;
        int                    rc = 0;
        ENTRY;

        OBD_ALLOC_PTR(op_data2);
        if (op_data2 == NULL)
                RETURN(-ENOMEM);

        LASSERT(mea != NULL);
        for (i = 0; i < mea->mea_count; i++) {
                memset(op_data2, 0, sizeof(*op_data2));
                op_data2->op_fid1 = mea->mea_ids[i];
                op_data2->op_bias = 0;

                tgt = lmv_find_target(lmv, &op_data2->op_fid1);
                if (IS_ERR(tgt))
                        GOTO(cleanup, rc = PTR_ERR(tgt));

                if (tgt->ltd_exp == NULL)
                        continue;

                rc = md_enqueue(tgt->ltd_exp, einfo, it, op_data2,
                                lockh + i, lmm, lmmsize, NULL, 0);

                CDEBUG(D_INODE, "Take lock on slave "DFID" -> %d/%d\n",
                       PFID(&mea->mea_ids[i]), rc, it->d.lustre.it_status);

                if (rc)
                        GOTO(cleanup, rc);

                if (it->d.lustre.it_data) {
                        struct ptlrpc_request *req;
                        req = (struct ptlrpc_request *)it->d.lustre.it_data;
                        ptlrpc_req_finished(req);
                }

                if (it->d.lustre.it_status)
                        GOTO(cleanup, rc = it->d.lustre.it_status);
        }

        EXIT;
cleanup:
        OBD_FREE_PTR(op_data2);

        if (rc != 0) {
                /*
                 * Drop all taken locks.
                 */
                while (--i >= 0) {
                        if (lockh[i].cookie)
                                ldlm_lock_decref(lockh + i, einfo->ei_mode);
                        lockh[i].cookie = 0;
                }
        }
        return rc;
}

static int
lmv_enqueue_remote(struct obd_export *exp, struct ldlm_enqueue_info *einfo,
                   struct lookup_intent *it, struct md_op_data *op_data,
                   struct lustre_handle *lockh, void *lmm, int lmmsize,
                   int extra_lock_flags)
{
        struct ptlrpc_request      *req = it->d.lustre.it_data;
        struct obd_device          *obd = exp->exp_obd;
        struct lmv_obd             *lmv = &obd->u.lmv;
        struct lustre_handle        plock;
        struct lmv_tgt_desc        *tgt;
        struct md_op_data          *rdata;
        struct lu_fid               fid1;
        struct mdt_body            *body;
        int                         rc = 0;
        int                         pmode;
        ENTRY;

        body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        if (!(body->valid & OBD_MD_MDS))
                RETURN(0);

        CDEBUG(D_INODE, "REMOTE_ENQUEUE '%s' on "DFID" -> "DFID"\n",
               LL_IT2STR(it), PFID(&op_data->op_fid1), PFID(&body->fid1));

        /*
         * We got LOOKUP lock, but we really need attrs.
         */
        pmode = it->d.lustre.it_lock_mode;
        LASSERT(pmode != 0);
        memcpy(&plock, lockh, sizeof(plock));
        it->d.lustre.it_lock_mode = 0;
        it->d.lustre.it_data = NULL;
        fid1 = body->fid1;

        it->d.lustre.it_disposition &= ~DISP_ENQ_COMPLETE;
        ptlrpc_req_finished(req);

        tgt = lmv_find_target(lmv, &fid1);
        if (IS_ERR(tgt))
                GOTO(out, rc = PTR_ERR(tgt));

        OBD_ALLOC_PTR(rdata);
        if (rdata == NULL)
                GOTO(out, rc = -ENOMEM);

        rdata->op_fid1 = fid1;
        rdata->op_bias = MDS_CROSS_REF;

        rc = md_enqueue(tgt->ltd_exp, einfo, it, rdata, lockh,
                        lmm, lmmsize, NULL, extra_lock_flags);
        OBD_FREE_PTR(rdata);
        EXIT;
out:
        ldlm_lock_decref(&plock, pmode);
        return rc;
}

static int
lmv_enqueue(struct obd_export *exp, struct ldlm_enqueue_info *einfo,
            struct lookup_intent *it, struct md_op_data *op_data,
            struct lustre_handle *lockh, void *lmm, int lmmsize,
	    struct ptlrpc_request **req, __u64 extra_lock_flags)
{
        struct obd_device        *obd = exp->exp_obd;
        struct lmv_obd           *lmv = &obd->u.lmv;
        struct lmv_tgt_desc      *tgt;
        struct lmv_object        *obj;
        int                       sidx;
        int                       rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        CDEBUG(D_INODE, "ENQUEUE '%s' on "DFID"\n",
               LL_IT2STR(it), PFID(&op_data->op_fid1));

        if (op_data->op_mea1 && it && it->it_op == IT_UNLINK) {
                rc = lmv_enqueue_slaves(exp, einfo, it, op_data,
                                        lockh, lmm, lmmsize);
                RETURN(rc);
        }

        obj = lmv_object_find(obd, &op_data->op_fid1);
        if (obj && op_data->op_namelen) {
                sidx = raw_name2idx(obj->lo_hashtype,
                                       obj->lo_objcount,
                                       (char *)op_data->op_name,
                                       op_data->op_namelen);
                op_data->op_fid1 = obj->lo_stripes[sidx].ls_fid;
                tgt = lmv_get_target(lmv, obj->lo_stripes[sidx].ls_mds);
        } else {
                tgt = lmv_find_target(lmv, &op_data->op_fid1);
        }
        if (obj)
                lmv_object_put(obj);

        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        CDEBUG(D_INODE, "ENQUEUE '%s' on "DFID" -> mds #%d\n",
               LL_IT2STR(it), PFID(&op_data->op_fid1), tgt->ltd_idx);

        rc = md_enqueue(tgt->ltd_exp, einfo, it, op_data, lockh,
                        lmm, lmmsize, req, extra_lock_flags);

        if (rc == 0 && it && it->it_op == IT_OPEN) {
                rc = lmv_enqueue_remote(exp, einfo, it, op_data, lockh,
                                        lmm, lmmsize, extra_lock_flags);
        }
        RETURN(rc);
}

static int
lmv_getattr_name(struct obd_export *exp,struct md_op_data *op_data,
                 struct ptlrpc_request **request)
{
        struct ptlrpc_request   *req = NULL;
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lu_fid            rid = op_data->op_fid1;
        struct lmv_tgt_desc     *tgt;
        struct mdt_body         *body;
        struct lmv_object       *obj;
        obd_valid                valid = op_data->op_valid;
        int                      rc;
        int                      loop = 0;
        int                      sidx;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

repeat:
        ++loop;
        LASSERT(loop <= 2);
        obj = lmv_object_find(obd, &rid);
        if (obj) {
                sidx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                    op_data->op_name, op_data->op_namelen);
                rid = obj->lo_stripes[sidx].ls_fid;
                tgt = lmv_get_target(lmv, obj->lo_stripes[sidx].ls_mds);
                op_data->op_mds = obj->lo_stripes[sidx].ls_mds;
                valid &= ~OBD_MD_FLCKSPLIT;
                lmv_object_put(obj);
        } else {
                tgt = lmv_find_target(lmv, &rid);
                valid |= OBD_MD_FLCKSPLIT;
                op_data->op_mds = tgt->ltd_idx;
        }
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        CDEBUG(D_INODE, "GETATTR_NAME for %*s on "DFID" - "DFID" -> mds #%d\n",
               op_data->op_namelen, op_data->op_name, PFID(&op_data->op_fid1),
               PFID(&rid), tgt->ltd_idx);

        op_data->op_valid = valid;
        op_data->op_fid1 = rid;
        rc = md_getattr_name(tgt->ltd_exp, op_data, request);
        if (rc == 0) {
                body = req_capsule_server_get(&(*request)->rq_pill,
                                              &RMF_MDT_BODY);
                LASSERT(body != NULL);

                if (body->valid & OBD_MD_MDS) {
                        rid = body->fid1;
                        CDEBUG(D_INODE, "Request attrs for "DFID"\n",
                               PFID(&rid));

                        tgt = lmv_find_target(lmv, &rid);
                        if (IS_ERR(tgt)) {
                                ptlrpc_req_finished(*request);
                                RETURN(PTR_ERR(tgt));
                        }

                        op_data->op_fid1 = rid;
                        op_data->op_valid |= OBD_MD_FLCROSSREF;
                        op_data->op_namelen = 0;
                        op_data->op_name = NULL;
                        rc = md_getattr_name(tgt->ltd_exp, op_data, &req);
                        ptlrpc_req_finished(*request);
                        *request = req;
                }
        } else if (rc == -ERESTART) {
                LASSERT(*request != NULL);
                DEBUG_REQ(D_WARNING|D_RPCTRACE, *request,
                          "Got -ERESTART during getattr!\n");
                ptlrpc_req_finished(*request);
                *request = NULL;

                /*
                 * Directory got split. Time to update local object and repeat
                 * the request with proper MDS.
                 */
                rc = lmv_handle_split(exp, &rid);
                if (rc == 0)
                        goto repeat;
        }
        RETURN(rc);
}

#define md_op_data_fid(op_data, fl)                     \
        (fl == MF_MDC_CANCEL_FID1 ? &op_data->op_fid1 : \
         fl == MF_MDC_CANCEL_FID2 ? &op_data->op_fid2 : \
         fl == MF_MDC_CANCEL_FID3 ? &op_data->op_fid3 : \
         fl == MF_MDC_CANCEL_FID4 ? &op_data->op_fid4 : \
         NULL)

static int lmv_early_cancel_slaves(struct obd_export *exp,
                                   struct md_op_data *op_data, int op_tgt,
                                   ldlm_mode_t mode, int bits, int flag)
{
        struct obd_device      *obd = exp->exp_obd;
        struct lmv_obd         *lmv = &obd->u.lmv;
        ldlm_policy_data_t      policy = {{0}};
        struct lu_fid          *op_fid;
        struct lu_fid          *st_fid;
        struct lmv_tgt_desc    *tgt;
        struct lmv_object      *obj;
        int                     rc = 0;
        int                     i;
        ENTRY;

        op_fid = md_op_data_fid(op_data, flag);
        if (!fid_is_sane(op_fid))
                RETURN(0);

        obj = lmv_object_find(obd, op_fid);
        if (obj == NULL)
                RETURN(-EALREADY);

        policy.l_inodebits.bits = bits;
        for (i = 0; i < obj->lo_objcount; i++) {
                tgt = lmv_get_target(lmv, obj->lo_stripes[i].ls_mds);
                st_fid = &obj->lo_stripes[i].ls_fid;
                if (op_tgt != tgt->ltd_idx) {
                        CDEBUG(D_INODE, "EARLY_CANCEL slave "DFID" -> mds #%d\n",
                               PFID(st_fid), tgt->ltd_idx);
                        rc = md_cancel_unused(tgt->ltd_exp, st_fid, &policy,
                                              mode, LCF_ASYNC, NULL);
                        if (rc)
                                GOTO(out_put_obj, rc);
                } else {
                        CDEBUG(D_INODE,
                               "EARLY_CANCEL skip operation target %d on "DFID"\n",
                               op_tgt, PFID(st_fid));
                        /*
                         * Do not cancel locks for operation target, they will
                         * be handled later in underlaying layer when calling
                         * function we run on behalf of.
                         */
                        *op_fid = *st_fid;
                        op_data->op_flags |= flag;
                }
        }
        EXIT;
out_put_obj:
        lmv_object_put(obj);
        return rc;
}

static int lmv_early_cancel(struct obd_export *exp, struct md_op_data *op_data,
                            int op_tgt, ldlm_mode_t mode, int bits, int flag)
{
        struct lu_fid          *fid = md_op_data_fid(op_data, flag);
        struct obd_device      *obd = exp->exp_obd;
        struct lmv_obd         *lmv = &obd->u.lmv;
        struct lmv_tgt_desc    *tgt;
        ldlm_policy_data_t      policy = {{0}};
        struct lmv_object      *obj;
        int                     rc = 0;
        ENTRY;

        if (!fid_is_sane(fid))
                RETURN(0);

        obj = lmv_object_find(obd, fid);
        if (obj) {
                rc = lmv_early_cancel_slaves(exp, op_data, op_tgt, mode,
                                             bits, flag);
                lmv_object_put(obj);
        } else {
                tgt = lmv_find_target(lmv, fid);
                if (IS_ERR(tgt))
                        RETURN(PTR_ERR(tgt));

                if (tgt->ltd_idx != op_tgt) {
                        CDEBUG(D_INODE, "EARLY_CANCEL on "DFID"\n", PFID(fid));
                        policy.l_inodebits.bits = bits;
                        rc = md_cancel_unused(tgt->ltd_exp, fid, &policy,
                                              mode, LCF_ASYNC, NULL);
                } else {
                        CDEBUG(D_INODE,
                               "EARLY_CANCEL skip operation target %d on "DFID"\n",
                               op_tgt, PFID(fid));
                        op_data->op_flags |= flag;
                        rc = 0;
                }

        }
        RETURN(rc);
}

/*
 * llite passes fid of an target inode in op_data->op_fid1 and id of directory in
 * op_data->op_fid2
 */
static int lmv_link(struct obd_export *exp, struct md_op_data *op_data,
                    struct ptlrpc_request **request)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        struct lmv_object       *obj;
        int                      rc;
        int                      loop = 0;
        mdsno_t                  mds;
        int                      sidx;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

repeat:
        ++loop;
        LASSERT(loop <= 2);
        LASSERT(op_data->op_namelen != 0);

        CDEBUG(D_INODE, "LINK "DFID":%*s to "DFID"\n",
               PFID(&op_data->op_fid2), op_data->op_namelen,
               op_data->op_name, PFID(&op_data->op_fid1));

        obj = lmv_object_find(obd, &op_data->op_fid2);
        if (obj) {
                sidx = raw_name2idx(obj->lo_hashtype,
                                    obj->lo_objcount,
                                    op_data->op_name,
                                    op_data->op_namelen);
                op_data->op_fid2 = obj->lo_stripes[sidx].ls_fid;
                mds = obj->lo_stripes[sidx].ls_mds;
                lmv_object_put(obj);
        } else {
                rc = lmv_fld_lookup(lmv, &op_data->op_fid2, &mds);
                if (rc)
                        RETURN(rc);
        }

        CDEBUG(D_INODE, "Forward to mds #%x ("DFID")\n",
               mds, PFID(&op_data->op_fid1));

        op_data->op_fsuid = cfs_curproc_fsuid();
        op_data->op_fsgid = cfs_curproc_fsgid();
        op_data->op_cap = cfs_curproc_cap_pack();
        tgt = lmv_get_target(lmv, mds);

        /*
         * Cancel UPDATE lock on child (fid1).
         */
        op_data->op_flags |= MF_MDC_CANCEL_FID2;
        rc = lmv_early_cancel(exp, op_data, tgt->ltd_idx, LCK_EX,
                              MDS_INODELOCK_UPDATE, MF_MDC_CANCEL_FID1);
        if (rc == 0)
                rc = md_link(tgt->ltd_exp, op_data, request);
        if (rc == -ERESTART) {
                LASSERT(*request != NULL);
                DEBUG_REQ(D_WARNING|D_RPCTRACE, *request,
                          "Got -ERESTART during link!\n");
                ptlrpc_req_finished(*request);
                *request = NULL;

                /*
                 * Directory got split. Time to update local object and repeat
                 * the request with proper MDS.
                 */
                rc = lmv_handle_split(exp, &op_data->op_fid2);
                if (rc == 0)
                        goto repeat;
        }

        RETURN(rc);
}

static int lmv_rename(struct obd_export *exp, struct md_op_data *op_data,
                      const char *old, int oldlen, const char *new, int newlen,
                      struct ptlrpc_request **request)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *src_tgt;
        int                      rc;
        int                      sidx;
        int                      loop = 0;
        struct lmv_object       *obj;
        mdsno_t                  mds1;
        mdsno_t                  mds2;
        ENTRY;

        LASSERT(oldlen != 0);

        CDEBUG(D_INODE, "RENAME %*s in "DFID" to %*s in "DFID"\n",
               oldlen, old, PFID(&op_data->op_fid1),
               newlen, new, PFID(&op_data->op_fid2));

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

repeat:
        ++loop;
        LASSERT(loop <= 2);
        obj = lmv_object_find(obd, &op_data->op_fid1);
        if (obj) {
                sidx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                    (char *)old, oldlen);
                op_data->op_fid1 = obj->lo_stripes[sidx].ls_fid;
                mds1 = obj->lo_stripes[sidx].ls_mds;
                CDEBUG(D_INODE, "Parent obj "DFID"\n", PFID(&op_data->op_fid1));
                lmv_object_put(obj);
        } else {
                rc = lmv_fld_lookup(lmv, &op_data->op_fid1, &mds1);
                if (rc)
                        RETURN(rc);
        }

        obj = lmv_object_find(obd, &op_data->op_fid2);
        if (obj) {
                /*
                 * Directory is already split, so we have to forward request to
                 * the right MDS.
                 */
                sidx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                       (char *)new, newlen);

                mds2 = obj->lo_stripes[sidx].ls_mds;
                op_data->op_fid2 = obj->lo_stripes[sidx].ls_fid;
                CDEBUG(D_INODE, "Parent obj "DFID"\n", PFID(&op_data->op_fid2));
                lmv_object_put(obj);
        } else {
                rc = lmv_fld_lookup(lmv, &op_data->op_fid2, &mds2);
                if (rc)
                        RETURN(rc);
        }

        op_data->op_fsuid = cfs_curproc_fsuid();
        op_data->op_fsgid = cfs_curproc_fsgid();
        op_data->op_cap = cfs_curproc_cap_pack();

        src_tgt = lmv_get_target(lmv, mds1);

        /*
         * LOOKUP lock on src child (fid3) should also be cancelled for
         * src_tgt in mdc_rename.
         */
        op_data->op_flags |= MF_MDC_CANCEL_FID1 | MF_MDC_CANCEL_FID3;

        /*
         * Cancel UPDATE locks on tgt parent (fid2), tgt_tgt is its
         * own target.
         */
        rc = lmv_early_cancel(exp, op_data, src_tgt->ltd_idx,
                              LCK_EX, MDS_INODELOCK_UPDATE,
                              MF_MDC_CANCEL_FID2);

        /*
         * Cancel LOOKUP locks on tgt child (fid4) for parent tgt_tgt.
         */
        if (rc == 0) {
                rc = lmv_early_cancel(exp, op_data, src_tgt->ltd_idx,
                                      LCK_EX, MDS_INODELOCK_LOOKUP,
                                      MF_MDC_CANCEL_FID4);
        }

        /*
         * Cancel all the locks on tgt child (fid4).
         */
        if (rc == 0)
                rc = lmv_early_cancel(exp, op_data, src_tgt->ltd_idx,
                                      LCK_EX, MDS_INODELOCK_FULL,
                                      MF_MDC_CANCEL_FID4);

        if (rc == 0)
                rc = md_rename(src_tgt->ltd_exp, op_data, old, oldlen,
                               new, newlen, request);

        if (rc == -ERESTART) {
                LASSERT(*request != NULL);
                DEBUG_REQ(D_WARNING|D_RPCTRACE, *request,
                          "Got -ERESTART during rename!\n");
                ptlrpc_req_finished(*request);
                *request = NULL;

                /*
                 * Directory got split. Time to update local object and repeat
                 * the request with proper MDS.
                 */
                rc = lmv_handle_split(exp, &op_data->op_fid1);
                if (rc == 0)
                        goto repeat;
        }
        RETURN(rc);
}

static int lmv_setattr(struct obd_export *exp, struct md_op_data *op_data,
                       void *ea, int ealen, void *ea2, int ea2len,
                       struct ptlrpc_request **request,
                       struct md_open_data **mod)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct ptlrpc_request   *req;
        struct lmv_tgt_desc     *tgt;
        struct lmv_object       *obj;
        int                      rc = 0;
        int                      i;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        obj = lmv_object_find(obd, &op_data->op_fid1);

        CDEBUG(D_INODE, "SETATTR for "DFID", valid 0x%x%s\n",
               PFID(&op_data->op_fid1), op_data->op_attr.ia_valid,
               obj ? ", split" : "");

        op_data->op_flags |= MF_MDC_CANCEL_FID1;
        if (obj) {
                for (i = 0; i < obj->lo_objcount; i++) {
                        op_data->op_fid1 = obj->lo_stripes[i].ls_fid;

                        tgt = lmv_get_target(lmv, obj->lo_stripes[i].ls_mds);
                        if (IS_ERR(tgt)) {
                                rc = PTR_ERR(tgt);
                                break;
                        }

                        rc = md_setattr(tgt->ltd_exp, op_data, ea, ealen,
                                        ea2, ea2len, &req, mod);

                        if (lu_fid_eq(&obj->lo_fid, &obj->lo_stripes[i].ls_fid)) {
                                /*
                                 * This is master object and this request should
                                 * be returned back to llite.
                                 */
                                *request = req;
                        } else {
                                ptlrpc_req_finished(req);
                        }

                        if (rc)
                                break;
                }
                lmv_object_put(obj);
        } else {
                tgt = lmv_find_target(lmv, &op_data->op_fid1);
                if (IS_ERR(tgt))
                        RETURN(PTR_ERR(tgt));

                rc = md_setattr(tgt->ltd_exp, op_data, ea, ealen, ea2,
                                ea2len, request, mod);
        }
        RETURN(rc);
}

static int lmv_sync(struct obd_export *exp, const struct lu_fid *fid,
                    struct obd_capa *oc, struct ptlrpc_request **request)
{
        struct obd_device         *obd = exp->exp_obd;
        struct lmv_obd            *lmv = &obd->u.lmv;
        struct lmv_tgt_desc       *tgt;
        int                        rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        tgt = lmv_find_target(lmv, fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = md_sync(tgt->ltd_exp, fid, oc, request);
        RETURN(rc);
}

/**
 * Main purpose of LMV blocking ast is to remove split directory LMV
 * presentation object (struct lmv_object) attached to the lock being revoked.
 */
int lmv_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                     void *data, int flag)
{
        struct lustre_handle    lockh;
        struct lmv_object      *obj;
        int                     rc;
        ENTRY;

        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0) {
                        CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
                        RETURN(rc);
                }
                break;
        case LDLM_CB_CANCELING:
                /*
                 * Time to drop cached attrs for split directory object
                 */
                obj = lock->l_ast_data;
                if (obj) {
                        CDEBUG(D_INODE, "Cancel %s on "LPU64"/"LPU64
                               ", master "DFID"\n",
                               lock->l_resource->lr_name.name[3] == 1 ?
                               "LOOKUP" : "UPDATE",
                               lock->l_resource->lr_name.name[0],
                               lock->l_resource->lr_name.name[1],
                               PFID(&obj->lo_fid));
                        lmv_object_put(obj);
                }
                break;
        default:
                LBUG();
        }
        RETURN(0);
}

static void lmv_hash_adjust(__u64 *hash, __u64 hash_adj)
{
        __u64         val;

        val = le64_to_cpu(*hash);
        if (val < hash_adj)
                val += MAX_HASH_SIZE;
        if (val != MDS_DIR_END_OFF)
                *hash = cpu_to_le64(val - hash_adj);
}

static __u32 lmv_node_rank(struct obd_export *exp, const struct lu_fid *fid)
{
        __u64              id;
        struct obd_import *imp;

        /*
         * XXX: to get nid we assume that underlying obd device is mdc.
         */
        imp  = class_exp2cliimp(exp);
        id   = imp->imp_connection->c_self + fid_flatten(fid);

        CDEBUG(D_INODE, "Readpage node rank: "LPX64" "DFID" "LPX64" "LPX64"\n",
               imp->imp_connection->c_self, PFID(fid), id, id ^ (id >> 32));

        return id ^ (id >> 32);
}

static int lmv_readpage(struct obd_export *exp, struct md_op_data *op_data,
                        struct page **pages, struct ptlrpc_request **request)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_object       *obj;
        struct lu_fid            rid = op_data->op_fid1;
        __u64                    offset = op_data->op_offset;
        __u64                    hash_adj = 0;
        __u32                    rank = 0;
        __u64                    seg_size = 0;
        __u64                    tgt_tmp = 0;
        int                      tgt_idx = 0;
        int                      tgt0_idx = 0;
        int                      rc;
        int                      nr = 0;
        int                      i;
        /* number of pages read, in CFS_PAGE_SIZE */
        int                      nrdpgs;
        /* number of pages transferred in LU_PAGE_SIZE */
        int                      nlupgs;
        struct lmv_stripe       *los;
        struct lmv_tgt_desc     *tgt;
        struct lu_dirpage       *dp;
        struct lu_dirent        *ent;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        CDEBUG(D_INODE, "READPAGE at "LPX64" from "DFID"\n", offset, PFID(&rid));

        /*
         * This case handle directory lookup in clustered metadata case (i.e.
         * split directory is located on multiple md servers.)
         * each server keeps directory entries for certain range of hashes.
         * E.g. we have N server and suppose hash range is 0 to MAX_HASH.
         * first server will keep records with hashes [ 0 ... MAX_HASH / N  - 1],
         * second one with hashes [MAX_HASH / N ... 2 * MAX_HASH / N] and
         * so on....
         *      readdir can simply start reading entries from 0 - N server in
         * order but that will not scale well as all client will request dir in
         * to server in same order.
         * Following algorithm does optimization:
         * Instead of doing readdir in 1, 2, ...., N order, client with a
         * rank R does readdir in R, R + 1, ..., N, 1, ... R - 1 order.
         * (every client has rank R)
         *      But ll_readdir() expect offset range [0 to MAX_HASH/N) but
         * since client ask dir from MDS{R} client has pages with offsets
         * [R*MAX_HASH/N ... (R + 1)*MAX_HASH/N] there for we do hash_adj
         * on hash  values that we get.
         */
        obj = lmv_object_find_lock(obd, &rid);
        if (obj) {
                nr       = obj->lo_objcount;
                LASSERT(nr > 0);
                seg_size = MAX_HASH_SIZE;
                do_div(seg_size, nr);
                los      = obj->lo_stripes;
                tgt      = lmv_get_target(lmv, los[0].ls_mds);
                rank     = lmv_node_rank(tgt->ltd_exp, &rid) % nr;
                tgt_tmp  = offset;
                do_div(tgt_tmp, seg_size);
                tgt0_idx = do_div(tgt_tmp,  nr);
                tgt_idx  = (tgt0_idx + rank) % nr;

                if (tgt_idx < tgt0_idx)
                        /*
                         * Wrap around.
                         *
                         * Last segment has unusual length due to division
                         * rounding.
                         */
                        hash_adj = MAX_HASH_SIZE - seg_size * nr;
                else
                        hash_adj = 0;

                hash_adj += rank * seg_size;

                CDEBUG(D_INODE, "Readpage hash adjustment: %x "LPX64" "
                       LPX64"/%x -> "LPX64"/%x\n", rank, hash_adj,
                       offset, tgt0_idx, offset + hash_adj, tgt_idx);

                offset = (offset + hash_adj) & MAX_HASH_SIZE;
                rid = obj->lo_stripes[tgt_idx].ls_fid;
                tgt = lmv_get_target(lmv, los[tgt_idx].ls_mds);

                CDEBUG(D_INODE, "Forward to "DFID" with offset %lu i %d\n",
                       PFID(&rid), (unsigned long)offset, tgt_idx);
        } else
                tgt = lmv_find_target(lmv, &rid);

        if (IS_ERR(tgt))
                GOTO(cleanup, rc = PTR_ERR(tgt));

        op_data->op_fid1 = rid;
        rc = md_readpage(tgt->ltd_exp, op_data, pages, request);
        if (rc)
                GOTO(cleanup, rc);

        nrdpgs = ((*request)->rq_bulk->bd_nob_transferred + CFS_PAGE_SIZE - 1)
                 >> CFS_PAGE_SHIFT;
        nlupgs = (*request)->rq_bulk->bd_nob_transferred >> LU_PAGE_SHIFT;
        LASSERT(!((*request)->rq_bulk->bd_nob_transferred & ~LU_PAGE_MASK));
        LASSERT(nrdpgs > 0 && nrdpgs <= op_data->op_npages);

        CDEBUG(D_INODE, "read %d(%d)/%d pages\n", nrdpgs, nlupgs,
               op_data->op_npages);

        for (i = 0; i < nrdpgs; i++) {
#if CFS_PAGE_SIZE > LU_PAGE_SIZE
                struct lu_dirpage *first;
                __u64 hash_end = 0;
                __u32 flags = 0;
#endif
                struct lu_dirent *tmp = NULL;

                dp = cfs_kmap(pages[i]);
                if (obj) {
                        lmv_hash_adjust(&dp->ldp_hash_start, hash_adj);
                        lmv_hash_adjust(&dp->ldp_hash_end,   hash_adj);
                        LASSERT(le64_to_cpu(dp->ldp_hash_start) <=
                                op_data->op_offset);

                        if ((tgt0_idx != nr - 1) &&
                            (le64_to_cpu(dp->ldp_hash_end) == MDS_DIR_END_OFF))
                        {
                                dp->ldp_hash_end = cpu_to_le32(seg_size *
                                                               (tgt0_idx + 1));
                                CDEBUG(D_INODE,
                                       ""DFID" reset end "LPX64" tgt %d\n",
                                       PFID(&rid),
                                       (__u64)le64_to_cpu(dp->ldp_hash_end),
                                       tgt_idx);
                        }
                }

                ent = lu_dirent_start(dp);
#if CFS_PAGE_SIZE > LU_PAGE_SIZE
                first = dp;
                hash_end = dp->ldp_hash_end;
repeat:
#endif
                nlupgs--;
                for (tmp = ent; ent != NULL;
                     tmp = ent, ent = lu_dirent_next(ent)) {
                        if (obj)
                                lmv_hash_adjust(&ent->lde_hash, hash_adj);
                }

#if CFS_PAGE_SIZE > LU_PAGE_SIZE
                dp = (struct lu_dirpage *)((char *)dp + LU_PAGE_SIZE);
                if (((unsigned long)dp & ~CFS_PAGE_MASK) && nlupgs > 0) {
                        ent = lu_dirent_start(dp);

                        if (obj) {
                                lmv_hash_adjust(&dp->ldp_hash_end, hash_adj);
                                if ((tgt0_idx != nr - 1) &&
                                    (le64_to_cpu(dp->ldp_hash_end) ==
                                     MDS_DIR_END_OFF)) {
                                        hash_end = cpu_to_le32(seg_size *
                                                               (tgt0_idx + 1));
                                        CDEBUG(D_INODE,
                                            ""DFID" reset end "LPX64" tgt %d\n",
                                            PFID(&rid),
                                            (__u64)le64_to_cpu(hash_end),
                                            tgt_idx);
                                }
                        }
                        hash_end = dp->ldp_hash_end;
                        flags = dp->ldp_flags;

                        if (tmp) {
                                /* enlarge the end entry lde_reclen from 0 to
                                 * first entry of next lu_dirpage, in this way
                                 * several lu_dirpages can be stored into one
                                 * client page on client. */
                                tmp = ((void *)tmp) +
                                      le16_to_cpu(tmp->lde_reclen);
                                tmp->lde_reclen =
                                        cpu_to_le16((char *)(dp->ldp_entries) -
                                                    (char *)tmp);
                                goto repeat;
                        }
                }
                first->ldp_hash_end = hash_end;
                first->ldp_flags &= ~cpu_to_le32(LDF_COLLIDE);
                first->ldp_flags |= flags & cpu_to_le32(LDF_COLLIDE);
#else
                SET_BUT_UNUSED(tmp);
#endif
                cfs_kunmap(pages[i]);
        }
        EXIT;
cleanup:
        if (obj)
                lmv_object_put_unlock(obj);
        return rc;
}

static int lmv_unlink(struct obd_export *exp, struct md_op_data *op_data,
                      struct ptlrpc_request **request)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt = NULL;
        struct lmv_object       *obj;
        int                      rc;
        int                      sidx;
        int                      loop = 0;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

repeat:
        ++loop;
        LASSERT(loop <= 2);
        LASSERT(op_data->op_namelen != 0);

        obj = lmv_object_find(obd, &op_data->op_fid1);
        if (obj) {
                sidx = raw_name2idx(obj->lo_hashtype,
                                    obj->lo_objcount,
                                    op_data->op_name,
                                    op_data->op_namelen);
                op_data->op_bias &= ~MDS_CHECK_SPLIT;
                op_data->op_fid1 = obj->lo_stripes[sidx].ls_fid;
                tgt = lmv_get_target(lmv,
                                     obj->lo_stripes[sidx].ls_mds);
                lmv_object_put(obj);
                CDEBUG(D_INODE, "UNLINK '%*s' in "DFID" -> %u\n",
                       op_data->op_namelen, op_data->op_name,
                       PFID(&op_data->op_fid1), sidx);
        }

        if (tgt == NULL) {
                tgt = lmv_find_target(lmv, &op_data->op_fid1);
                if (IS_ERR(tgt))
                        RETURN(PTR_ERR(tgt));
                op_data->op_bias |= MDS_CHECK_SPLIT;
        }

        op_data->op_fsuid = cfs_curproc_fsuid();
        op_data->op_fsgid = cfs_curproc_fsgid();
        op_data->op_cap = cfs_curproc_cap_pack();

        /*
         * If child's fid is given, cancel unused locks for it if it is from
         * another export than parent.
         *
         * LOOKUP lock for child (fid3) should also be cancelled on parent
         * tgt_tgt in mdc_unlink().
         */
        op_data->op_flags |= MF_MDC_CANCEL_FID1 | MF_MDC_CANCEL_FID3;

        /*
         * Cancel FULL locks on child (fid3).
         */
        rc = lmv_early_cancel(exp, op_data, tgt->ltd_idx, LCK_EX,
                              MDS_INODELOCK_FULL, MF_MDC_CANCEL_FID3);

        if (rc == 0)
                rc = md_unlink(tgt->ltd_exp, op_data, request);

        if (rc == -ERESTART) {
                LASSERT(*request != NULL);
                DEBUG_REQ(D_WARNING|D_RPCTRACE, *request,
                          "Got -ERESTART during unlink!\n");
                ptlrpc_req_finished(*request);
                *request = NULL;

                /*
                 * Directory got split. Time to update local object and repeat
                 * the request with proper MDS.
                 */
                rc = lmv_handle_split(exp, &op_data->op_fid1);
                if (rc == 0)
                        goto repeat;
        }
        RETURN(rc);
}

static int lmv_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc = 0;

        switch (stage) {
        case OBD_CLEANUP_EARLY:
                /* XXX: here should be calling obd_precleanup() down to
                 * stack. */
                break;
        case OBD_CLEANUP_EXPORTS:
                fld_client_proc_fini(&lmv->lmv_fld);
                lprocfs_obd_cleanup(obd);
                break;
        default:
                break;
        }
        RETURN(rc);
}

static int lmv_get_info(const struct lu_env *env, struct obd_export *exp,
                        __u32 keylen, void *key, __u32 *vallen, void *val,
                        struct lov_stripe_md *lsm)
{
        struct obd_device       *obd;
        struct lmv_obd          *lmv;
        int                      rc = 0;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "Invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }

        lmv = &obd->u.lmv;
        if (keylen >= strlen("remote_flag") && !strcmp(key, "remote_flag")) {
                struct lmv_tgt_desc *tgts;
                int i;

                rc = lmv_check_connect(obd);
                if (rc)
                        RETURN(rc);

                LASSERT(*vallen == sizeof(__u32));
                for (i = 0, tgts = lmv->tgts; i < lmv->desc.ld_tgt_count;
                     i++, tgts++) {

                        /*
                         * All tgts should be connected when this gets called.
                         */
                        if (!tgts || !tgts->ltd_exp) {
                                CERROR("target not setup?\n");
                                continue;
                        }

                        if (!obd_get_info(env, tgts->ltd_exp, keylen, key,
                                          vallen, val, NULL))
                                RETURN(0);
                }
                RETURN(-EINVAL);
        } else if (KEY_IS(KEY_MAX_EASIZE) || KEY_IS(KEY_CONN_DATA)) {
                rc = lmv_check_connect(obd);
                if (rc)
                        RETURN(rc);

                /*
                 * Forwarding this request to first MDS, it should know LOV
                 * desc.
                 */
                rc = obd_get_info(env, lmv->tgts[0].ltd_exp, keylen, key,
                                  vallen, val, NULL);
                if (!rc && KEY_IS(KEY_CONN_DATA)) {
                        exp->exp_connect_flags =
                        ((struct obd_connect_data *)val)->ocd_connect_flags;
                }
                RETURN(rc);
        } else if (KEY_IS(KEY_TGT_COUNT)) {
                *((int *)val) = lmv->desc.ld_tgt_count;
                RETURN(0);
        }

        CDEBUG(D_IOCTL, "Invalid key\n");
        RETURN(-EINVAL);
}

int lmv_set_info_async(const struct lu_env *env, struct obd_export *exp,
                       obd_count keylen, void *key, obd_count vallen,
                       void *val, struct ptlrpc_request_set *set)
{
        struct lmv_tgt_desc    *tgt;
        struct obd_device      *obd;
        struct lmv_obd         *lmv;
        int rc = 0;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "Invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }
        lmv = &obd->u.lmv;

        if (KEY_IS(KEY_READ_ONLY) || KEY_IS(KEY_FLUSH_CTX)) {
                int i, err = 0;

                for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                        tgt = &lmv->tgts[i];

                        if (!tgt->ltd_exp)
                                continue;

                        err = obd_set_info_async(env, tgt->ltd_exp,
                                                 keylen, key, vallen, val, set);
                        if (err && rc == 0)
                                rc = err;
                }

                RETURN(rc);
        }

        RETURN(-EINVAL);
}

int lmv_packmd(struct obd_export *exp, struct lov_mds_md **lmmp,
               struct lov_stripe_md *lsm)
{
        struct obd_device         *obd = class_exp2obd(exp);
        struct lmv_obd            *lmv = &obd->u.lmv;
        struct lmv_stripe_md      *meap;
        struct lmv_stripe_md      *lsmp;
        int                        mea_size;
        int                        i;
        ENTRY;

        mea_size = lmv_get_easize(lmv);
        if (!lmmp)
                RETURN(mea_size);

        if (*lmmp && !lsm) {
                OBD_FREE_LARGE(*lmmp, mea_size);
                *lmmp = NULL;
                RETURN(0);
        }

        if (*lmmp == NULL) {
                OBD_ALLOC_LARGE(*lmmp, mea_size);
                if (*lmmp == NULL)
                        RETURN(-ENOMEM);
        }

        if (!lsm)
                RETURN(mea_size);

        lsmp = (struct lmv_stripe_md *)lsm;
        meap = (struct lmv_stripe_md *)*lmmp;

        if (lsmp->mea_magic != MEA_MAGIC_LAST_CHAR &&
            lsmp->mea_magic != MEA_MAGIC_ALL_CHARS)
                RETURN(-EINVAL);

        meap->mea_magic = cpu_to_le32(lsmp->mea_magic);
        meap->mea_count = cpu_to_le32(lsmp->mea_count);
        meap->mea_master = cpu_to_le32(lsmp->mea_master);

        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                meap->mea_ids[i] = meap->mea_ids[i];
                fid_cpu_to_le(&meap->mea_ids[i], &meap->mea_ids[i]);
        }

        RETURN(mea_size);
}

int lmv_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsmp,
                 struct lov_mds_md *lmm, int lmm_size)
{
        struct obd_device          *obd = class_exp2obd(exp);
        struct lmv_stripe_md      **tmea = (struct lmv_stripe_md **)lsmp;
        struct lmv_stripe_md       *mea = (struct lmv_stripe_md *)lmm;
        struct lmv_obd             *lmv = &obd->u.lmv;
        int                         mea_size;
        int                         i;
        __u32                       magic;
        ENTRY;

        mea_size = lmv_get_easize(lmv);
        if (lsmp == NULL)
                return mea_size;

        if (*lsmp != NULL && lmm == NULL) {
                OBD_FREE_LARGE(*tmea, mea_size);
                *lsmp = NULL;
                RETURN(0);
        }

        LASSERT(mea_size == lmm_size);

        OBD_ALLOC_LARGE(*tmea, mea_size);
        if (*tmea == NULL)
                RETURN(-ENOMEM);

        if (!lmm)
                RETURN(mea_size);

        if (mea->mea_magic == MEA_MAGIC_LAST_CHAR ||
            mea->mea_magic == MEA_MAGIC_ALL_CHARS ||
            mea->mea_magic == MEA_MAGIC_HASH_SEGMENT)
        {
                magic = le32_to_cpu(mea->mea_magic);
        } else {
                /*
                 * Old mea is not handled here.
                 */
                CERROR("Old not supportable EA is found\n");
                LBUG();
        }

        (*tmea)->mea_magic = magic;
        (*tmea)->mea_count = le32_to_cpu(mea->mea_count);
        (*tmea)->mea_master = le32_to_cpu(mea->mea_master);

        for (i = 0; i < (*tmea)->mea_count; i++) {
                (*tmea)->mea_ids[i] = mea->mea_ids[i];
                fid_le_to_cpu(&(*tmea)->mea_ids[i], &(*tmea)->mea_ids[i]);
        }
        RETURN(mea_size);
}

static int lmv_cancel_unused(struct obd_export *exp, const struct lu_fid *fid,
                             ldlm_policy_data_t *policy, ldlm_mode_t mode,
                             ldlm_cancel_flags_t flags, void *opaque)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        int                      rc = 0;
        int                      err;
        int                      i;
        ENTRY;

        LASSERT(fid != NULL);

        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                if (!lmv->tgts[i].ltd_exp || !lmv->tgts[i].ltd_active)
                        continue;

                err = md_cancel_unused(lmv->tgts[i].ltd_exp, fid,
                                       policy, mode, flags, opaque);
                if (!rc)
                        rc = err;
        }
        RETURN(rc);
}

int lmv_set_lock_data(struct obd_export *exp, __u64 *lockh, void *data,
                      __u64 *bits)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        int                      rc;
        ENTRY;

        rc =  md_set_lock_data(lmv->tgts[0].ltd_exp, lockh, data, bits);
        RETURN(rc);
}

ldlm_mode_t lmv_lock_match(struct obd_export *exp, __u64 flags,
                           const struct lu_fid *fid, ldlm_type_t type,
                           ldlm_policy_data_t *policy, ldlm_mode_t mode,
                           struct lustre_handle *lockh)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        ldlm_mode_t              rc;
        int                      i;
        ENTRY;

        CDEBUG(D_INODE, "Lock match for "DFID"\n", PFID(fid));

        /*
         * With CMD every object can have two locks in different namespaces:
         * lookup lock in space of mds storing direntry and update/open lock in
         * space of mds storing inode. Thus we check all targets, not only that
         * one fid was created in.
         */
        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                rc = md_lock_match(lmv->tgts[i].ltd_exp, flags, fid,
                                   type, policy, mode, lockh);
                if (rc)
                        RETURN(rc);
        }

        RETURN(0);
}

int lmv_get_lustre_md(struct obd_export *exp, struct ptlrpc_request *req,
                      struct obd_export *dt_exp, struct obd_export *md_exp,
                      struct lustre_md *md)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        int                      rc;
        ENTRY;
        rc = md_get_lustre_md(lmv->tgts[0].ltd_exp, req, dt_exp, md_exp, md);
        RETURN(rc);
}

int lmv_free_lustre_md(struct obd_export *exp, struct lustre_md *md)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        ENTRY;

        if (md->mea)
                obd_free_memmd(exp, (void *)&md->mea);
        RETURN(md_free_lustre_md(lmv->tgts[0].ltd_exp, md));
}

int lmv_set_open_replay_data(struct obd_export *exp,
                             struct obd_client_handle *och,
                             struct ptlrpc_request *open_req)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        ENTRY;

        tgt = lmv_find_target(lmv, &och->och_fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        RETURN(md_set_open_replay_data(tgt->ltd_exp, och, open_req));
}

int lmv_clear_open_replay_data(struct obd_export *exp,
                               struct obd_client_handle *och)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        ENTRY;

        tgt = lmv_find_target(lmv, &och->och_fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        RETURN(md_clear_open_replay_data(tgt->ltd_exp, och));
}

static int lmv_get_remote_perm(struct obd_export *exp,
                               const struct lu_fid *fid,
                               struct obd_capa *oc, __u32 suppgid,
                               struct ptlrpc_request **request)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        int                      rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        tgt = lmv_find_target(lmv, fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = md_get_remote_perm(tgt->ltd_exp, fid, oc, suppgid, request);
        RETURN(rc);
}

static int lmv_renew_capa(struct obd_export *exp, struct obd_capa *oc,
                          renew_capa_cb_t cb)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        int                      rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        tgt = lmv_find_target(lmv, &oc->c_capa.lc_fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = md_renew_capa(tgt->ltd_exp, oc, cb);
        RETURN(rc);
}

int lmv_unpack_capa(struct obd_export *exp, struct ptlrpc_request *req,
                    const struct req_msg_field *field, struct obd_capa **oc)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc;

        ENTRY;
        rc = md_unpack_capa(lmv->tgts[0].ltd_exp, req, field, oc);
        RETURN(rc);
}

int lmv_intent_getattr_async(struct obd_export *exp,
                             struct md_enqueue_info *minfo,
                             struct ldlm_enqueue_info *einfo)
{
        struct md_op_data       *op_data = &minfo->mi_data;
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_object       *obj;
        struct lmv_tgt_desc     *tgt = NULL;
        int                      rc;
        int                      sidx;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        if (op_data->op_namelen) {
                obj = lmv_object_find(obd, &op_data->op_fid1);
                if (obj) {
                        sidx = raw_name2idx(obj->lo_hashtype, obj->lo_objcount,
                                            (char *)op_data->op_name,
                                            op_data->op_namelen);
                        op_data->op_fid1 = obj->lo_stripes[sidx].ls_fid;
                        tgt = lmv_get_target(lmv, obj->lo_stripes[sidx].ls_mds);
                        lmv_object_put(obj);
                }
        }

        if (tgt == NULL)
                tgt = lmv_find_target(lmv, &op_data->op_fid1);

        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = md_intent_getattr_async(tgt->ltd_exp, minfo, einfo);
        RETURN(rc);
}

int lmv_revalidate_lock(struct obd_export *exp, struct lookup_intent *it,
                        struct lu_fid *fid, __u64 *bits)
{
        struct obd_device       *obd = exp->exp_obd;
        struct lmv_obd          *lmv = &obd->u.lmv;
        struct lmv_tgt_desc     *tgt;
        int                      rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        tgt = lmv_find_target(lmv, fid);
        if (IS_ERR(tgt))
                RETURN(PTR_ERR(tgt));

        rc = md_revalidate_lock(tgt->ltd_exp, it, fid, bits);
        RETURN(rc);
}

/**
 * For lmv, only need to send request to master MDT, and the master MDT will
 * process with other slave MDTs. The only exception is Q_GETOQUOTA for which
 * we directly fetch data from the slave MDTs.
 */
int lmv_quotactl(struct obd_device *unused, struct obd_export *exp,
                 struct obd_quotactl *oqctl)
{
        struct obd_device   *obd = class_exp2obd(exp);
        struct lmv_obd      *lmv = &obd->u.lmv;
        struct lmv_tgt_desc *tgt = &lmv->tgts[0];
        int                  rc = 0, i;
        __u64                curspace, curinodes;
        ENTRY;

        if (!lmv->desc.ld_tgt_count || !tgt->ltd_active) {
                CERROR("master lmv inactive\n");
                RETURN(-EIO);
        }

        if (oqctl->qc_cmd != Q_GETOQUOTA) {
                rc = obd_quotactl(tgt->ltd_exp, oqctl);
                RETURN(rc);
        }

        curspace = curinodes = 0;
        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                int err;
                tgt = &lmv->tgts[i];

                if (tgt->ltd_exp == NULL)
                        continue;
                if (!tgt->ltd_active) {
                        CDEBUG(D_HA, "mdt %d is inactive.\n", i);
                        continue;
                }

                err = obd_quotactl(tgt->ltd_exp, oqctl);
                if (err) {
                        CERROR("getquota on mdt %d failed. %d\n", i, err);
                        if (!rc)
                                rc = err;
                } else {
                        curspace += oqctl->qc_dqblk.dqb_curspace;
                        curinodes += oqctl->qc_dqblk.dqb_curinodes;
                }
        }
        oqctl->qc_dqblk.dqb_curspace = curspace;
        oqctl->qc_dqblk.dqb_curinodes = curinodes;

        RETURN(rc);
}

int lmv_quotacheck(struct obd_device *unused, struct obd_export *exp,
                   struct obd_quotactl *oqctl)
{
        struct obd_device   *obd = class_exp2obd(exp);
        struct lmv_obd      *lmv = &obd->u.lmv;
        struct lmv_tgt_desc *tgt;
        int                  i, rc = 0;
        ENTRY;

        for (i = 0, tgt = lmv->tgts; i < lmv->desc.ld_tgt_count; i++, tgt++) {
                int err;

                if (!tgt->ltd_active) {
                        CERROR("lmv idx %d inactive\n", i);
                        RETURN(-EIO);
                }

                err = obd_quotacheck(tgt->ltd_exp, oqctl);
                if (err && !rc)
                        rc = err;
        }

        RETURN(rc);
}

struct obd_ops lmv_obd_ops = {
        .o_owner                = THIS_MODULE,
        .o_setup                = lmv_setup,
        .o_cleanup              = lmv_cleanup,
        .o_precleanup           = lmv_precleanup,
        .o_process_config       = lmv_process_config,
        .o_connect              = lmv_connect,
        .o_disconnect           = lmv_disconnect,
        .o_statfs               = lmv_statfs,
        .o_get_info             = lmv_get_info,
        .o_set_info_async       = lmv_set_info_async,
        .o_packmd               = lmv_packmd,
        .o_unpackmd             = lmv_unpackmd,
        .o_notify               = lmv_notify,
        .o_get_uuid             = lmv_get_uuid,
        .o_iocontrol            = lmv_iocontrol,
        .o_fid_delete           = lmv_fid_delete,
        .o_quotacheck           = lmv_quotacheck,
        .o_quotactl             = lmv_quotactl
};

struct md_ops lmv_md_ops = {
        .m_getstatus            = lmv_getstatus,
        .m_change_cbdata        = lmv_change_cbdata,
        .m_find_cbdata          = lmv_find_cbdata,
        .m_close                = lmv_close,
        .m_create               = lmv_create,
        .m_done_writing         = lmv_done_writing,
        .m_enqueue              = lmv_enqueue,
        .m_getattr              = lmv_getattr,
        .m_getxattr             = lmv_getxattr,
        .m_getattr_name         = lmv_getattr_name,
        .m_intent_lock          = lmv_intent_lock,
        .m_link                 = lmv_link,
        .m_rename               = lmv_rename,
        .m_setattr              = lmv_setattr,
        .m_setxattr             = lmv_setxattr,
        .m_sync                 = lmv_sync,
        .m_readpage             = lmv_readpage,
        .m_unlink               = lmv_unlink,
        .m_init_ea_size         = lmv_init_ea_size,
        .m_cancel_unused        = lmv_cancel_unused,
        .m_set_lock_data        = lmv_set_lock_data,
        .m_lock_match           = lmv_lock_match,
        .m_get_lustre_md        = lmv_get_lustre_md,
        .m_free_lustre_md       = lmv_free_lustre_md,
        .m_set_open_replay_data = lmv_set_open_replay_data,
        .m_clear_open_replay_data = lmv_clear_open_replay_data,
        .m_renew_capa           = lmv_renew_capa,
        .m_unpack_capa          = lmv_unpack_capa,
        .m_get_remote_perm      = lmv_get_remote_perm,
        .m_intent_getattr_async = lmv_intent_getattr_async,
        .m_revalidate_lock      = lmv_revalidate_lock
};

int __init lmv_init(void)
{
        struct lprocfs_static_vars lvars;
        int                        rc;

        lmv_object_cache = cfs_mem_cache_create("lmv_objects",
                                                sizeof(struct lmv_object),
                                                0, 0);
        if (!lmv_object_cache) {
                CERROR("Error allocating lmv objects cache\n");
                return -ENOMEM;
        }

        lprocfs_lmv_init_vars(&lvars);

        rc = class_register_type(&lmv_obd_ops, &lmv_md_ops,
                                 lvars.module_vars, LUSTRE_LMV_NAME, NULL);
        if (rc)
                cfs_mem_cache_destroy(lmv_object_cache);

        return rc;
}

#ifdef __KERNEL__
static void lmv_exit(void)
{
        class_unregister_type(LUSTRE_LMV_NAME);

        LASSERTF(cfs_atomic_read(&lmv_object_count) == 0,
                 "Can't free lmv objects cache, %d object(s) busy\n",
                 cfs_atomic_read(&lmv_object_count));
        cfs_mem_cache_destroy(lmv_object_cache);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Logical Metadata Volume OBD driver");
MODULE_LICENSE("GPL");

module_init(lmv_init);
module_exit(lmv_exit);
#endif
