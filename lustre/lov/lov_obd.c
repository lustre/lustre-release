/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002-2004 Cluster File Systems, Inc.
 * Author: Phil Schwan <phil@clusterfs.com>
 *         Peter Braam <braam@clusterfs.com>
 *         Mike Shaver <shaver@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LOV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <asm/div64.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_debug.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/obd_ost.h>
#include <linux/lprocfs_status.h>

#include "lov_internal.h"

/* obd methods */
#define MAX_STRING_SIZE 128
static int lov_connect_obd(struct obd_device *obd, struct lov_tgt_desc *tgt,
                           int activate, struct obd_connect_data *data)
{
        struct lov_obd *lov = &obd->u.lov;
        struct obd_uuid *tgt_uuid = &tgt->uuid;
        struct obd_device *tgt_obd;
        struct obd_uuid lov_osc_uuid = { "LOV_OSC_UUID" };
        struct lustre_handle conn = {0, };
        struct obd_import *imp;
#ifdef __KERNEL__
        struct proc_dir_entry *lov_proc_dir;
#endif
        int rc;
        ENTRY;

        tgt_obd = class_find_client_obd(tgt_uuid, LUSTRE_OSC_NAME,
                                        &obd->obd_uuid);

        if (!tgt_obd) {
                CERROR("Target %s not attached\n", tgt_uuid->uuid);
                RETURN(-EINVAL);
        }

        if (!tgt_obd->obd_set_up) {
                CERROR("Target %s not set up\n", tgt_uuid->uuid);
                RETURN(-EINVAL);
        }

        if (activate) {
                tgt_obd->obd_no_recov = 0;
                ptlrpc_activate_import(tgt_obd->u.cli.cl_import);
        }

        /*
         * Divine LOV knows that OBDs under it are OSCs.
         */
        imp = tgt_obd->u.cli.cl_import;

        if (imp->imp_invalid) {
                CERROR("not connecting OSC %s; administratively "
                       "disabled\n", tgt_uuid->uuid);
                rc = obd_register_observer(tgt_obd, obd);
                if (rc) {
                        CERROR("Target %s register_observer error %d; "
                               "will not be able to reactivate\n",
                               tgt_uuid->uuid, rc);
                }
                RETURN(0);
        }

        rc = obd_connect(&conn, tgt_obd, &lov_osc_uuid, data);
        if (rc) {
                CERROR("Target %s connect error %d\n", tgt_uuid->uuid, rc);
                RETURN(rc);
        }
        tgt->ltd_exp = class_conn2export(&conn);

        rc = obd_register_observer(tgt_obd, obd);
        if (rc) {
                CERROR("Target %s register_observer error %d\n",
                       tgt_uuid->uuid, rc);
                obd_disconnect(tgt->ltd_exp);
                tgt->ltd_exp = NULL;
                RETURN(rc);
        }

        tgt->active = 1;
        lov->desc.ld_active_tgt_count++;

#ifdef __KERNEL__
        lov_proc_dir = lprocfs_srch(obd->obd_proc_entry, "target_obds");
        if (lov_proc_dir) {
                struct obd_device *osc_obd = class_conn2obd(&conn);
                struct proc_dir_entry *osc_symlink;
                char name[MAX_STRING_SIZE];

                LASSERT(osc_obd != NULL);
                LASSERT(osc_obd->obd_type != NULL);
                LASSERT(osc_obd->obd_type->typ_name != NULL);
                snprintf(name, MAX_STRING_SIZE, "../../../%s/%s",
                         osc_obd->obd_type->typ_name,
                         osc_obd->obd_name);
                osc_symlink = proc_symlink(osc_obd->obd_name, lov_proc_dir,
                                           name);
                if (osc_symlink == NULL) {
                        CERROR("could not register LOV target "
                               "/proc/fs/lustre/%s/%s/target_obds/%s.",
                               obd->obd_type->typ_name, obd->obd_name,
                               osc_obd->obd_name);
                        lprocfs_remove(lov_proc_dir);
                        lov_proc_dir = NULL;
                }
        }
#endif

        RETURN(0);
}

static int lov_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_tgt_desc *tgt;
        struct obd_export *exp;
        __u64 connect_flags = data ? data->ocd_connect_flags : 0;
        int rc, rc2, i;
        ENTRY;

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        exp = class_conn2export(conn);

        /* We don't want to actually do the underlying connections more than
         * once, so keep track. */
        lov->refcount++;
        if (lov->refcount > 1) {
                class_export_put(exp);
                RETURN(0);
        }

        for (i = 0, tgt = lov->tgts; i < lov->desc.ld_tgt_count; i++, tgt++) {
                if (obd_uuid_empty(&tgt->uuid))
                        continue;
                rc = lov_connect_obd(obd, tgt, 0, data);
                if (rc)
                        GOTO(out_disc, rc);
                if (data)
                        connect_flags &= data->ocd_connect_flags;
        }

        if (data)
                data->ocd_connect_flags = connect_flags;

        class_export_put(exp);
        RETURN (0);

 out_disc:
        while (i-- > 0) {
                struct obd_uuid uuid;
                --tgt;
                --lov->desc.ld_active_tgt_count;
                tgt->active = 0;
                /* save for CERROR below; (we know it's terminated) */
                uuid = tgt->uuid;
                rc2 = obd_disconnect(tgt->ltd_exp);
                if (rc2)
                        CERROR("error: LOV target %s disconnect on OST idx %d: "
                               "rc = %d\n", uuid.uuid, i, rc2);
        }
        class_disconnect(exp);
        RETURN (rc);
}

static int lov_disconnect_obd(struct obd_device *obd, struct lov_tgt_desc *tgt)
{
        struct proc_dir_entry *lov_proc_dir;
        struct obd_device *osc_obd = class_exp2obd(tgt->ltd_exp);
        struct lov_obd *lov = &obd->u.lov;
        int rc;
        ENTRY;

        CDEBUG(D_CONFIG, "Disconnecting lov target %s\n", obd->obd_uuid.uuid);

        lov_proc_dir = lprocfs_srch(obd->obd_proc_entry, "target_obds");
        if (lov_proc_dir) {
                struct proc_dir_entry *osc_symlink;

                osc_symlink = lprocfs_srch(lov_proc_dir, osc_obd->obd_name);
                if (osc_symlink) {
                        lprocfs_remove(osc_symlink);
                } else {
                        CERROR("/proc/fs/lustre/%s/%s/target_obds/%s missing.",
                               obd->obd_type->typ_name, obd->obd_name,
                               osc_obd->obd_name);
                }
        }

        if (obd->obd_no_recov) {
                /* Pass it on to our clients.
                 * XXX This should be an argument to disconnect,
                 * XXX not a back-door flag on the OBD.  Ah well.
                 */
                if (osc_obd)
                        osc_obd->obd_no_recov = 1;
        }

        obd_register_observer(osc_obd, NULL);

        rc = obd_disconnect(tgt->ltd_exp);
        if (rc) {
                if (tgt->active) {
                        CERROR("Target %s disconnect error %d\n",
                               tgt->uuid.uuid, rc);
                }
                rc = 0;
        }

        if (tgt->active) {
                tgt->active = 0;
                lov->desc.ld_active_tgt_count--;
        }

        tgt->ltd_exp = NULL;
        RETURN(0);
}

static int
lov_del_obd(struct obd_device *obd, struct obd_uuid *uuidp, int index, int gen);

static int lov_disconnect(struct obd_export *exp)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_device *osc_obd;
        struct lov_obd *lov = &obd->u.lov;
        struct lov_tgt_desc *tgt;
        int rc, i;
        ENTRY;

        rc = class_disconnect(exp);

        if (!lov->tgts)
                RETURN(rc);

        /* Only disconnect the underlying layers on the final disconnect. */
        lov->refcount--;
        if (lov->refcount != 0)
                RETURN(rc);

        for (i = 0, tgt = lov->tgts; i < lov->desc.ld_tgt_count; i++, tgt++) {
                if (tgt->ltd_exp) {
                        osc_obd = class_exp2obd(tgt->ltd_exp);
                        /* Disconnect and delete from list */
                        lov_del_obd(obd, &tgt->uuid, i, tgt->ltd_gen);
                        /* Cleanup the osc now - can't do it from 
                           lov_cleanup because we just lost our only reference
                           to it. */ 
                        /* Use lov's force/fail flags. */
                        osc_obd->obd_force = obd->obd_force;
                        osc_obd->obd_fail = obd->obd_fail;
                        class_manual_cleanup(osc_obd);
                }
        }

        RETURN(rc);
}

/* Error codes:
 *
 *  -EINVAL  : UUID can't be found in the LOV's target list
 *  -ENOTCONN: The UUID is found, but the target connection is bad (!)
 *  -EBADF   : The UUID is found, but the OBD is the wrong type (!)
 */
static int lov_set_osc_active(struct lov_obd *lov, struct obd_uuid *uuid,
                              int activate)
{
        struct lov_tgt_desc *tgt;
        int i, rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "Searching in lov %p for uuid %s (activate=%d)\n",
               lov, uuid->uuid, activate);

        spin_lock(&lov->lov_lock);
        for (i = 0, tgt = lov->tgts; i < lov->desc.ld_tgt_count; i++, tgt++) {
                if (tgt->ltd_exp == NULL)
                        continue;

                CDEBUG(D_INFO, "lov idx %d is %s conn "LPX64"\n",
                       i, tgt->uuid.uuid, tgt->ltd_exp->exp_handle.h_cookie);
                if (strncmp(uuid->uuid, tgt->uuid.uuid, sizeof uuid->uuid) == 0)
                        break;
        }

        if (i == lov->desc.ld_tgt_count)
                GOTO(out, rc = -EINVAL);

        if (tgt->active == activate) {
                CDEBUG(D_INFO, "OSC %s already %sactive!\n", uuid->uuid,
                       activate ? "" : "in");
                GOTO(out, rc);
        }

        CDEBUG(D_INFO, "Marking OSC %s %sactive\n", uuid->uuid,
               activate ? "" : "in");

        tgt->active = activate;
        if (activate)
                lov->desc.ld_active_tgt_count++;
        else
                lov->desc.ld_active_tgt_count--;

        EXIT;
 out:
        spin_unlock(&lov->lov_lock);
        return rc;
}

static int lov_notify(struct obd_device *obd, struct obd_device *watched,
                       int active)
{
        int rc;
        struct obd_uuid *uuid;

        if (strcmp(watched->obd_type->typ_name, "osc")) {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name,
                       watched->obd_name);
                return -EINVAL;
        }
        uuid = &watched->u.cli.cl_import->imp_target_uuid;

        /* Set OSC as active before notifying the observer, so the
         * observer can use the OSC normally.
         */
        rc = lov_set_osc_active(&obd->u.lov, uuid, active);
        if (rc) {
                CERROR("%sactivation of %s failed: %d\n",
                       active ? "" : "de", uuid->uuid, rc);
                RETURN(rc);
        }

        if (obd->obd_observer)
                /* Pass the notification up the chain. */
                rc = obd_notify(obd->obd_observer, watched, active);

        RETURN(rc);
}

static int
lov_add_obd(struct obd_device *obd, struct obd_uuid *uuidp, int index, int gen)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_tgt_desc *tgt;
        struct obd_export *exp_observer;
        __u32 bufsize;
        __u32 size = 2;
        obd_id params[2];
        int rc, old_count;
        ENTRY;

        CDEBUG(D_CONFIG, "uuid: %s idx: %d gen: %d\n",
               uuidp->uuid, index, gen);

        if (index < 0) {
                CERROR("request to add OBD %s at invalid index: %d\n",
                       uuidp->uuid, index);
                RETURN(-EINVAL);
        }

        if (gen <= 0) {
                CERROR("request to add OBD %s with invalid generation: %d\n",
                       uuidp->uuid, gen);
                RETURN(-EINVAL);
        }

        bufsize = sizeof(struct lov_tgt_desc) * (index + 1);
        if (bufsize > lov->bufsize) {
                OBD_ALLOC(tgt, bufsize);
                if (tgt == NULL) {
                        CERROR("couldn't allocate %d bytes for new table.\n",
                               bufsize);
                        RETURN(-ENOMEM);
                }

                memset(tgt, 0, bufsize);
                if (lov->tgts) {
                        memcpy(tgt, lov->tgts, lov->bufsize);
                        OBD_FREE(lov->tgts, lov->bufsize);
                }

                lov->tgts = tgt;
                lov->bufsize = bufsize;
                CDEBUG(D_CONFIG, "tgts: %p bufsize: %d\n",
                       lov->tgts, lov->bufsize);
        }

        tgt = &lov->tgts[index];
        if (!obd_uuid_empty(&tgt->uuid)) {
                CERROR("OBD already assigned at LOV target index %d\n",
                       index);
                RETURN(-EEXIST);
        }

        tgt->uuid = *uuidp;
        /* XXX - add a sanity check on the generation number. */
        tgt->ltd_gen = gen;

        old_count = lov->desc.ld_tgt_count;
        if (index >= lov->desc.ld_tgt_count)
                lov->desc.ld_tgt_count = index + 1;

        CDEBUG(D_CONFIG, "idx=%d ltd_gen=%d ld_tgt_count=%d\n",
                index, tgt->ltd_gen, lov->desc.ld_tgt_count);

        if (lov->refcount == 0)
                /* lov_connect hasn't been called yet. So we'll do the
                   lov_connect_obd on this obd when that fn first runs. */
                RETURN(0);

        if (tgt->ltd_exp) {
                struct obd_device *osc_obd;

                osc_obd = class_exp2obd(tgt->ltd_exp);
                if (osc_obd)
                        osc_obd->obd_no_recov = 0;
        }

        /* NULL may need to change when we use flags for osc's */
        rc = lov_connect_obd(obd, tgt, 1, NULL);
        if (rc || !obd->obd_observer)
                RETURN(rc);

        /* tell the mds_lov about the new target */
        obd_llog_finish(obd->obd_observer, old_count);
        llog_cat_initialize(obd->obd_observer, lov->desc.ld_tgt_count);

        params[0] = index;
        rc = obd_get_info(tgt->ltd_exp, strlen("last_id"), "last_id", &size,
                          &params[1]);
        if (rc)
                GOTO(out, rc);

        exp_observer = obd->obd_observer->obd_self_export;
        rc = obd_set_info(exp_observer, strlen("next_id"),"next_id", 2, params);
        if (rc)
                GOTO(out, rc);

        rc = lov_notify(obd, tgt->ltd_exp->exp_obd, 1);
        GOTO(out, rc);
 out:
        if (rc && tgt->ltd_exp != NULL)
                lov_disconnect_obd(obd, tgt);
        return rc;
}

static int
lov_del_obd(struct obd_device *obd, struct obd_uuid *uuidp, int index, int gen)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_tgt_desc *tgt;
        int count = lov->desc.ld_tgt_count;
        int rc = 0;
        ENTRY;

        CDEBUG(D_CONFIG, "uuid: %s idx: %d gen: %d\n",
               uuidp->uuid, index, gen);

        if (index >= count) {
                CERROR("LOV target index %d >= number of LOV OBDs %d.\n",
                       index, count);
                RETURN(-EINVAL);
        }

        tgt = &lov->tgts[index];

        if (obd_uuid_empty(&tgt->uuid)) {
                CERROR("LOV target at index %d is not setup.\n", index);
                RETURN(-EINVAL);
        }

        if (strncmp(uuidp->uuid, tgt->uuid.uuid, sizeof uuidp->uuid) != 0) {
                CERROR("LOV target UUID %s at index %d doesn't match %s.\n",
                       tgt->uuid.uuid, index, uuidp->uuid);
                RETURN(-EINVAL);
        }

        if (tgt->ltd_exp)
                lov_disconnect_obd(obd, tgt);

        /* XXX - right now there is a dependency on ld_tgt_count being the
         * maximum tgt index for computing the mds_max_easize. So we can't
         * shrink it. */

        /* lt_gen = 0 will mean it will not match the gen of any valid loi */
        memset(tgt, 0, sizeof(*tgt));

        CDEBUG(D_CONFIG, "uuid: %s idx: %d gen: %d exp: %p active: %d\n",
               tgt->uuid.uuid, index, tgt->ltd_gen, tgt->ltd_exp, tgt->active);

        RETURN(rc);
}

static int lov_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        struct lustre_cfg *lcfg = buf;
        struct lov_desc *desc;
        struct lov_obd *lov = &obd->u.lov;
        int count;
        ENTRY;

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
                CERROR("LOV setup requires a descriptor\n");
                RETURN(-EINVAL);
        }

        desc = (struct lov_desc *)lustre_cfg_buf(lcfg, 1);

        if (sizeof(*desc) > LUSTRE_CFG_BUFLEN(lcfg, 1)) {
                CERROR("descriptor size wrong: %d > %d\n",
                       (int)sizeof(*desc), LUSTRE_CFG_BUFLEN(lcfg, 1));
                RETURN(-EINVAL);
        }

        if (desc->ld_magic != LOV_DESC_MAGIC) {
                if (desc->ld_magic == __swab32(LOV_DESC_MAGIC)) {
                            CDEBUG(D_OTHER, "%s: Swabbing lov desc %p\n",
                                   obd->obd_name, desc);
                            lustre_swab_lov_desc(desc);
                } else {
                        CERROR("%s: Bad lov desc magic: %#x\n",
                               obd->obd_name, desc->ld_magic);
                        RETURN(-EINVAL);
                }
        }

        if (desc->ld_default_stripe_size < PTLRPC_MAX_BRW_SIZE) {
                CWARN("Increasing default_stripe_size "LPU64" to %u\n",
                      desc->ld_default_stripe_size, PTLRPC_MAX_BRW_SIZE);
                CWARN("Please update config and run --write-conf on MDS\n");

                desc->ld_default_stripe_size = PTLRPC_MAX_BRW_SIZE;
        } else if (desc->ld_default_stripe_size & (LOV_MIN_STRIPE_SIZE - 1)) {
                CWARN("default_stripe_size "LPU64" isn't a multiple of %u\n",
                      desc->ld_default_stripe_size, LOV_MIN_STRIPE_SIZE);
                CWARN("Please update config and run --write-conf on MDS\n");

                desc->ld_default_stripe_size &= ~(LOV_MIN_STRIPE_SIZE - 1);
       }

        if (desc->ld_default_stripe_count == 0)
                desc->ld_default_stripe_count = 1;

        /* Because of 64-bit divide/mod operations only work with a 32-bit
         * divisor in a 32-bit kernel, we cannot support a stripe width
         * of 4GB or larger on 32-bit CPUs. */
        count = desc->ld_default_stripe_count;
        if ((count > 0 ? count : desc->ld_tgt_count) *
            desc->ld_default_stripe_size > ~0UL) {
                CERROR("LOV: stripe width "LPU64"x%u > %lu on 32-bit system\n",
                       desc->ld_default_stripe_size, count, ~0UL);
                RETURN(-EINVAL);
        }

        /* Allocate space for target list */
        if (desc->ld_tgt_count)
                count = desc->ld_tgt_count;
        lov->bufsize = sizeof(struct lov_tgt_desc) * max(count, 1);
        OBD_ALLOC(lov->tgts, lov->bufsize);
        if (lov->tgts == NULL) {
                CERROR("Out of memory\n");
                RETURN(-EINVAL);
        }
        memset(lov->tgts, 0, lov->bufsize);

        desc->ld_active_tgt_count = 0;
        lov->desc = *desc;
        spin_lock_init(&lov->lov_lock);

        lprocfs_init_vars(lov, &lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);
#ifdef LPROCFS
        {
                struct proc_dir_entry *entry;

                entry = create_proc_entry("target_obd", 0444,
                                          obd->obd_proc_entry);
                if (entry != NULL) {
                        entry->proc_fops = &lov_proc_target_fops;
                        entry->data = obd;
                }
        }
#endif

        RETURN(0);
}

static int lov_precleanup(struct obd_device *obd, int stage)
{
        int rc = 0;
        ENTRY;

        if (stage < 2)
                RETURN(0);

        rc = obd_llog_finish(obd, 0);
        if (rc != 0)
                CERROR("failed to cleanup llogging subsystems\n");

        RETURN(rc);
}

static int lov_cleanup(struct obd_device *obd)
{
        struct lov_obd *lov = &obd->u.lov;

        lprocfs_obd_cleanup(obd);
        if (lov->tgts) {
                int i;
                struct lov_tgt_desc *tgt;
                for (i = 0, tgt = lov->tgts;
                      i < lov->desc.ld_tgt_count; i++, tgt++) {
                        if (!obd_uuid_empty(&tgt->uuid))
                                lov_del_obd(obd, &tgt->uuid, i, 0);
                }
                OBD_FREE(lov->tgts, lov->bufsize);
        }
        RETURN(0);
}

static int lov_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct obd_uuid obd_uuid;
        int cmd;
        int index;
        int gen;
        int rc = 0;
        ENTRY;

        switch(cmd = lcfg->lcfg_command) {
        case LCFG_LOV_ADD_OBD:
        case LCFG_LOV_DEL_OBD: {
                if (LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(obd_uuid.uuid))
                        GOTO(out, rc = -EINVAL);

                obd_str2uuid(&obd_uuid,  lustre_cfg_buf(lcfg, 1));

                if (sscanf(lustre_cfg_buf(lcfg, 2), "%d", &index) != 1)
                        GOTO(out, rc = -EINVAL);
                if (sscanf(lustre_cfg_buf(lcfg, 3), "%d", &gen) != 1)
                        GOTO(out, rc = -EINVAL);
                if (cmd == LCFG_LOV_ADD_OBD)
                        rc = lov_add_obd(obd, &obd_uuid, index, gen);
                else
                        rc = lov_del_obd(obd, &obd_uuid, index, gen);
                GOTO(out, rc);
        }
        default: {
                CERROR("Unknown command: %d\n", lcfg->lcfg_command);
                GOTO(out, rc = -EINVAL);

        }
        }
out:
        RETURN(rc);
}

#ifndef log2
#define log2(n) ffz(~(n))
#endif

static int lov_clear_orphans(struct obd_export *export, struct obdo *src_oa,
                             struct lov_stripe_md **ea,
                             struct obd_trans_info *oti)
{
        struct lov_obd *lov;
        struct obdo *tmp_oa;
        struct obd_uuid *ost_uuid = NULL;
        int rc = 0, i;
        ENTRY;

        LASSERT(src_oa->o_valid & OBD_MD_FLFLAGS &&
                src_oa->o_flags == OBD_FL_DELORPHAN);

        lov = &export->exp_obd->u.lov;

        tmp_oa = obdo_alloc();
        if (tmp_oa == NULL)
                RETURN(-ENOMEM);

        if (src_oa->o_valid & OBD_MD_FLINLINE) {
                ost_uuid = (struct obd_uuid *)src_oa->o_inline;
                CDEBUG(D_HA, "clearing orphans only for %s\n",
                       ost_uuid->uuid);
        }

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                struct lov_stripe_md obj_md;
                struct lov_stripe_md *obj_mdp = &obj_md;
                int err;

                /* if called for a specific target, we don't
                   care if it is not active. */
                if (lov->tgts[i].active == 0 && ost_uuid == NULL) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", i);
                        continue;
                }

                if (ost_uuid && !obd_uuid_equals(ost_uuid, &lov->tgts[i].uuid))
                        continue;

                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));

                LASSERT(lov->tgts[i].ltd_exp);
                /* XXX: LOV STACKING: use real "obj_mdp" sub-data */
                err = obd_create(lov->tgts[i].ltd_exp, tmp_oa, &obj_mdp, oti);
                if (err)
                        /* This export will be disabled until it is recovered,
                           and then orphan recovery will be completed. */
                        CERROR("error in orphan recovery on OST idx %d/%d: "
                               "rc = %d\n", i, lov->desc.ld_tgt_count, err);

                if (ost_uuid)
                        break;
        }
        obdo_free(tmp_oa);
        RETURN(rc);
}

static int lov_recreate(struct obd_export *exp, struct obdo *src_oa,
                        struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct lov_stripe_md *obj_mdp, *lsm;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        unsigned ost_idx;
        int rc, i;
        ENTRY;

        LASSERT(src_oa->o_valid & OBD_MD_FLFLAGS &&
                src_oa->o_flags & OBD_FL_RECREATE_OBJS);

        OBD_ALLOC(obj_mdp, sizeof(*obj_mdp));
        if (obj_mdp == NULL)
                RETURN(-ENOMEM);

        ost_idx = src_oa->o_nlink;
        lsm = *ea;
        if (lsm == NULL)
                GOTO(out, rc = -EINVAL);
        if (ost_idx >= lov->desc.ld_tgt_count)
                GOTO(out, rc = -EINVAL);

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                if (lsm->lsm_oinfo[i].loi_ost_idx == ost_idx) {
                        if (lsm->lsm_oinfo[i].loi_id != src_oa->o_id)
                                GOTO(out, rc = -EINVAL);
                        break;
                }
        }
        if (i == lsm->lsm_stripe_count)
                GOTO(out, rc = -EINVAL);

        rc = obd_create(lov->tgts[ost_idx].ltd_exp, src_oa, &obj_mdp, oti);
out:
        OBD_FREE(obj_mdp, sizeof(*obj_mdp));
        RETURN(rc);
}

/* the LOV expects oa->o_id to be set to the LOV object id */
static int lov_create(struct obd_export *exp, struct obdo *src_oa,
                      struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct lov_obd *lov;
        struct lov_request_set *set = NULL;
        struct list_head *pos;
        int rc = 0;
        ENTRY;

        LASSERT(ea != NULL);
        if (exp == NULL)
                RETURN(-EINVAL);

        if ((src_oa->o_valid & OBD_MD_FLFLAGS) &&
            src_oa->o_flags == OBD_FL_DELORPHAN) {
                rc = lov_clear_orphans(exp, src_oa, ea, oti);
                RETURN(rc);
        }

        lov = &exp->exp_obd->u.lov;
        if (!lov->desc.ld_active_tgt_count)
                RETURN(-EIO);

        /* Recreate a specific object id at the given OST index */
        if ((src_oa->o_valid & OBD_MD_FLFLAGS) &&
            (src_oa->o_flags & OBD_FL_RECREATE_OBJS)) {
                 rc = lov_recreate(exp, src_oa, ea, oti);
                 RETURN(rc);
        }

        rc = lov_prep_create_set(exp, ea, src_oa, oti, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                struct lov_request *req =
                        list_entry(pos, struct lov_request, rq_link);

                /* XXX: LOV STACKING: use real "obj_mdp" sub-data */
                rc = obd_create(lov->tgts[req->rq_idx].ltd_exp,
                                req->rq_oa, &req->rq_md, oti);
                lov_update_create_set(set, req, rc);
        }
        rc = lov_fini_create_set(set, ea);
        RETURN(rc);
}

#define ASSERT_LSM_MAGIC(lsmp)                                          \
do {                                                                    \
        LASSERT((lsmp) != NULL);                                        \
        LASSERTF((lsmp)->lsm_magic == LOV_MAGIC, "%p->lsm_magic=%x\n",  \
                 (lsmp), (lsmp)->lsm_magic);                            \
} while (0)

static int lov_destroy(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov;
        int rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_destroy_set(exp, oa, lsm, oti, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                int err;
                req = list_entry(pos, struct lov_request, rq_link);

                /* XXX update the cookie position */
                oti->oti_logcookies = set->set_cookies + req->rq_stripe;
                rc = obd_destroy(lov->tgts[req->rq_idx].ltd_exp, req->rq_oa,
                                 NULL, oti);
                err = lov_update_common_set(set, req, rc);
                if (rc) {
                        CERROR("error: destroying objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               set->set_oa->o_id, req->rq_oa->o_id,
                               req->rq_idx, rc);
                        if (!rc)
                                rc = err;
                }
        }
        lov_fini_destroy_set(set);
        RETURN(rc);
}

static int lov_getattr(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *lsm)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov;
        int err = 0, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;

        rc = lov_prep_getattr_set(exp, oa, lsm, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                CDEBUG(D_INFO, "objid "LPX64"[%d] has subobj "LPX64" at idx "
                       "%u\n", oa->o_id, req->rq_stripe, req->rq_oa->o_id,
                       req->rq_idx);

                rc = obd_getattr(lov->tgts[req->rq_idx].ltd_exp,
                                 req->rq_oa, NULL);
                err = lov_update_common_set(set, req, rc);
                if (err) {
                        CERROR("error: getattr objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               set->set_oa->o_id, req->rq_oa->o_id,
                               req->rq_idx, err);
                        break;
                }
        }

        rc = lov_fini_getattr_set(set);
        if (err)
                rc = err;
        RETURN(rc);
}

static int lov_getattr_interpret(struct ptlrpc_request_set *rqset, void *data,
                                 int rc)
{
        struct lov_request_set *lovset = (struct lov_request_set *)data;
        ENTRY;

        /* don't do attribute merge if this aysnc op failed */
        if (rc) {
                lovset->set_completes = 0;
                lov_fini_getattr_set(lovset);
        } else {
                rc = lov_fini_getattr_set(lovset);
        }
        RETURN (rc);
}

static int lov_getattr_async(struct obd_export *exp, struct obdo *oa,
                              struct lov_stripe_md *lsm,
                              struct ptlrpc_request_set *rqset)
{
        struct lov_request_set *lovset;
        struct lov_obd *lov;
        struct list_head *pos;
        struct lov_request *req;
        int rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;

        rc = lov_prep_getattr_set(exp, oa, lsm, &lovset);
        if (rc)
                RETURN(rc);

        CDEBUG(D_INFO, "objid "LPX64": %ux%u byte stripes\n",
               lsm->lsm_object_id, lsm->lsm_stripe_count, lsm->lsm_stripe_size);

        list_for_each (pos, &lovset->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                CDEBUG(D_INFO, "objid "LPX64"[%d] has subobj "LPX64" at idx "
                       "%u\n", oa->o_id, req->rq_stripe, req->rq_oa->o_id,
                       req->rq_idx);
                rc = obd_getattr_async(lov->tgts[req->rq_idx].ltd_exp,
                                       req->rq_oa, NULL, rqset);
                if (rc) {
                        CERROR("error: getattr objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               lovset->set_oa->o_id, req->rq_oa->o_id,
                               req->rq_idx, rc);
                        GOTO(out, rc);
                }
                lov_update_common_set(lovset, req, rc);
        }

        LASSERT(rc == 0);
        LASSERT (rqset->set_interpret == NULL);
        rqset->set_interpret = lov_getattr_interpret;
        rqset->set_arg = (void *)lovset;
        RETURN(rc);
out:
        LASSERT(rc);
        lov_fini_getattr_set(lovset);
        RETURN(rc);
}

static int lov_setattr(struct obd_export *exp, struct obdo *src_oa,
                       struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct lov_request_set *set;
        struct lov_obd *lov;
        struct list_head *pos;
        struct lov_request *req;
        int err = 0, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        /* for now, we only expect time updates here */
        LASSERT(!(src_oa->o_valid & ~(OBD_MD_FLID|OBD_MD_FLTYPE | OBD_MD_FLMODE|
                                      OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                      OBD_MD_FLCTIME | OBD_MD_FLFLAGS |
                                      OBD_MD_FLSIZE)));
        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_setattr_set(exp, src_oa, lsm, NULL, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                rc = obd_setattr(lov->tgts[req->rq_idx].ltd_exp, req->rq_oa,
                                 NULL, NULL);
                err = lov_update_setattr_set(set, req, rc);
                if (err) {
                        CERROR("error: setattr objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               set->set_oa->o_id, req->rq_oa->o_id,
                               req->rq_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        err = lov_fini_setattr_set(set);
        if (!rc)
                rc = err;
        RETURN(rc);
}

static int lov_setattr_async(struct obd_export *exp, struct obdo *src_oa,
                       struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct lov_obd *lov;
        struct lov_oinfo *loi = NULL;
        int rc = 0, err;
        obd_id objid = src_oa->o_id;
        int i;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);
        LASSERT(oti);
        if (src_oa->o_valid & OBD_MD_FLCOOKIE)
                LASSERT(oti->oti_logcookies);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        /* support OBD_MD_FLUID, OBD_MD_FLGID and OBD_MD_FLCOOKIE now */
        LASSERT(!(src_oa->o_valid &  ~(OBD_MD_FLID | OBD_MD_FLUID |
                                       OBD_MD_FLGID| OBD_MD_FLCOOKIE)));
        lov = &exp->exp_obd->u.lov;

        loi = lsm->lsm_oinfo;
        for (i = 0; i < lsm->lsm_stripe_count; i++, loi++) {
                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        goto next;
                }

                src_oa->o_id = loi->loi_id;
                /* do chown/chgrp on OST asynchronously */
                err = obd_setattr_async(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                        src_oa, NULL, oti);
                if (err) {
                        CERROR("error: setattr objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               objid, src_oa->o_id, i, err);
                        if (!rc)
                                rc = err;
                }
        next:
                if (src_oa->o_valid & OBD_MD_FLCOOKIE)
                        oti->oti_logcookies++;
        }

        RETURN(rc);
}

/* FIXME: maybe we'll just make one node the authoritative attribute node, then
 * we can send this 'punch' to just the authoritative node and the nodes
 * that the punch will affect. */
static int lov_punch(struct obd_export *exp, struct obdo *oa,
                     struct lov_stripe_md *lsm,
                     obd_off start, obd_off end, struct obd_trans_info *oti)
{
        struct lov_request_set *set;
        struct lov_obd *lov;
        struct list_head *pos;
        struct lov_request *req;
        int err = 0, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_punch_set(exp, oa, lsm, start, end, oti, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                rc = obd_punch(lov->tgts[req->rq_idx].ltd_exp, req->rq_oa,
                               NULL, req->rq_extent.start,
                               req->rq_extent.end, NULL);
                err = lov_update_punch_set(set, req, rc);
                if (err) {
                        CERROR("error: punch objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", set->set_oa->o_id,
                               req->rq_oa->o_id, req->rq_idx, rc);
                        if (!rc)
                                rc = err;
                }
        }
        err = lov_fini_punch_set(set);
        if (!rc)
                rc = err;
        RETURN(rc);
}

static int lov_sync(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *lsm, obd_off start, obd_off end)
{
        struct lov_request_set *set;
        struct lov_obd *lov;
        struct list_head *pos;
        struct lov_request *req;
        int err = 0, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_sync_set(exp, oa, lsm, start, end, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                rc = obd_sync(lov->tgts[req->rq_idx].ltd_exp, req->rq_oa,
                              NULL, req->rq_extent.start, req->rq_extent.end);
                err = lov_update_common_set(set, req, rc);
                if (err) {
                        CERROR("error: fsync objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", set->set_oa->o_id,
                               req->rq_oa->o_id, req->rq_idx, rc);
                        if (!rc)
                                rc = err;
                }
        }
        err = lov_fini_sync_set(set);
        if (!rc)
                rc = err;
        RETURN(rc);
}

static int lov_brw_check(struct lov_obd *lov, struct obdo *oa,
                         struct lov_stripe_md *lsm,
                         obd_count oa_bufs, struct brw_page *pga)
{
        int i, rc = 0;

        /* The caller just wants to know if there's a chance that this
         * I/O can succeed */
        for (i = 0; i < oa_bufs; i++) {
                int stripe = lov_stripe_number(lsm, pga[i].off);
                int ost = lsm->lsm_oinfo[stripe].loi_ost_idx;
                obd_off start, end;

                if (!lov_stripe_intersects(lsm, i, pga[i].off,
                                           pga[i].off + pga[i].count,
                                           &start, &end))
                        continue;

                if (lov->tgts[ost].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost);
                        return -EIO;
                }
                rc = obd_brw(OBD_BRW_CHECK, lov->tgts[ost].ltd_exp, oa,
                             NULL, 1, &pga[i], NULL);
                if (rc)
                        break;
        }
        return rc;
}

static int lov_brw(int cmd, struct obd_export *exp, struct obdo *src_oa,
                   struct lov_stripe_md *lsm, obd_count oa_bufs,
                   struct brw_page *pga, struct obd_trans_info *oti)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int err, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (cmd == OBD_BRW_CHECK) {
                rc = lov_brw_check(lov, src_oa, lsm, oa_bufs, pga);
                RETURN(rc);
        }

        rc = lov_prep_brw_set(exp, src_oa, lsm, oa_bufs, pga, oti, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                struct obd_export *sub_exp;
                struct brw_page *sub_pga;
                req = list_entry(pos, struct lov_request, rq_link);

                sub_exp = lov->tgts[req->rq_idx].ltd_exp;
                sub_pga = set->set_pga + req->rq_pgaidx;
                rc = obd_brw(cmd, sub_exp, req->rq_oa, req->rq_md,
                             req->rq_oabufs, sub_pga, oti);
                if (rc)
                        break;
                lov_update_common_set(set, req, rc);
        }

        err = lov_fini_brw_set(set);
        if (!rc)
                rc = err;
        RETURN(rc);
}

static int lov_brw_interpret(struct ptlrpc_request_set *reqset, void *data,
                             int rc)
{
        struct lov_request_set *lovset = (struct lov_request_set *)data;
        ENTRY;

        if (rc) {
                lovset->set_completes = 0;
                lov_fini_brw_set(lovset);
        } else {
                rc = lov_fini_brw_set(lovset);
        }

        RETURN(rc);
}

static int lov_brw_async(int cmd, struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md *lsm, obd_count oa_bufs,
                         struct brw_page *pga, struct ptlrpc_request_set *set,
                         struct obd_trans_info *oti)
{
        struct lov_request_set *lovset;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (cmd == OBD_BRW_CHECK) {
                rc = lov_brw_check(lov, oa, lsm, oa_bufs, pga);
                RETURN(rc);
        }

        rc = lov_prep_brw_set(exp, oa, lsm, oa_bufs, pga, oti, &lovset);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &lovset->set_list) {
                struct obd_export *sub_exp;
                struct brw_page *sub_pga;
                req = list_entry(pos, struct lov_request, rq_link);

                sub_exp = lov->tgts[req->rq_idx].ltd_exp;
                sub_pga = lovset->set_pga + req->rq_pgaidx;
                rc = obd_brw_async(cmd, sub_exp, req->rq_oa, req->rq_md,
                                   req->rq_oabufs, sub_pga, set, oti);
                if (rc)
                        GOTO(out, rc);
                lov_update_common_set(lovset, req, rc);
        }
        LASSERT(rc == 0);
        LASSERT(set->set_interpret == NULL);
        set->set_interpret = (set_interpreter_func)lov_brw_interpret;
        set->set_arg = (void *)lovset;

        RETURN(rc);
out:
        lov_fini_brw_set(lovset);
        RETURN(rc);
}

static int lov_ap_make_ready(void *data, int cmd)
{
        struct lov_async_page *lap = LAP_FROM_COOKIE(data);

        return lap->lap_caller_ops->ap_make_ready(lap->lap_caller_data, cmd);
}
static int lov_ap_refresh_count(void *data, int cmd)
{
        struct lov_async_page *lap = LAP_FROM_COOKIE(data);

        return lap->lap_caller_ops->ap_refresh_count(lap->lap_caller_data,
                                                     cmd);
}
static void lov_ap_fill_obdo(void *data, int cmd, struct obdo *oa)
{
        struct lov_async_page *lap = LAP_FROM_COOKIE(data);

        lap->lap_caller_ops->ap_fill_obdo(lap->lap_caller_data, cmd, oa);
        /* XXX woah, shouldn't we be altering more here?  size? */
        oa->o_id = lap->lap_loi_id;
}

static void lov_ap_completion(void *data, int cmd, struct obdo *oa, int rc)
{
        struct lov_async_page *lap = LAP_FROM_COOKIE(data);

        /* in a raid1 regime this would down a count of many ios
         * in flight, onl calling the caller_ops completion when all
         * the raid1 ios are complete */
        lap->lap_caller_ops->ap_completion(lap->lap_caller_data, cmd, oa, rc);
}

static struct obd_async_page_ops lov_async_page_ops = {
        .ap_make_ready =        lov_ap_make_ready,
        .ap_refresh_count =     lov_ap_refresh_count,
        .ap_fill_obdo =         lov_ap_fill_obdo,
        .ap_completion =        lov_ap_completion,
};

int lov_prep_async_page(struct obd_export *exp, struct lov_stripe_md *lsm,
                           struct lov_oinfo *loi, struct page *page,
                           obd_off offset, struct obd_async_page_ops *ops,
                           void *data, void **res)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;
        ENTRY;

        if (!page)
                return size_round(sizeof(*lap)) +
                       obd_prep_async_page(lov->tgts[0].ltd_exp, NULL, NULL,
                                           NULL, 0, NULL, NULL, NULL);

        ASSERT_LSM_MAGIC(lsm);
        LASSERT(loi == NULL);

        lap = *res;
        lap->lap_magic = LAP_MAGIC;
        lap->lap_caller_ops = ops;
        lap->lap_caller_data = data;

        /* for now only raid 0 which passes through */
        lap->lap_stripe = lov_stripe_number(lsm, offset);
        lov_stripe_offset(lsm, offset, lap->lap_stripe, &lap->lap_sub_offset);
        loi = &lsm->lsm_oinfo[lap->lap_stripe];

        /* so the callback doesn't need the lsm */
        lap->lap_loi_id = loi->loi_id;

        lap->lap_sub_cookie = (void *)lap + size_round(sizeof(*lap));

        rc = obd_prep_async_page(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                 lsm, loi, page, lap->lap_sub_offset,
                                 &lov_async_page_ops, lap,
                                 &lap->lap_sub_cookie);
        if (rc)
                RETURN(rc);
        CDEBUG(D_CACHE, "lap %p page %p cookie %p off "LPU64"\n", lap, page,
               lap->lap_sub_cookie, offset);
        RETURN(0);
}

static int lov_queue_async_io(struct obd_export *exp,
                              struct lov_stripe_md *lsm,
                              struct lov_oinfo *loi, void *cookie,
                              int cmd, obd_off off, int count,
                              obd_flag brw_flags, obd_flag async_flags)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;

        LASSERT(loi == NULL);

        ASSERT_LSM_MAGIC(lsm);

        lap = LAP_FROM_COOKIE(cookie);

        loi = &lsm->lsm_oinfo[lap->lap_stripe];

        rc = obd_queue_async_io(lov->tgts[loi->loi_ost_idx].ltd_exp, lsm,
                                loi, lap->lap_sub_cookie, cmd, off, count,
                                brw_flags, async_flags);
        RETURN(rc);
}

static int lov_set_async_flags(struct obd_export *exp,
                               struct lov_stripe_md *lsm,
                               struct lov_oinfo *loi, void *cookie,
                               obd_flag async_flags)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;

        LASSERT(loi == NULL);

        ASSERT_LSM_MAGIC(lsm);

        lap = LAP_FROM_COOKIE(cookie);

        loi = &lsm->lsm_oinfo[lap->lap_stripe];

        rc = obd_set_async_flags(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                 lsm, loi, lap->lap_sub_cookie, async_flags);
        RETURN(rc);
}

static int lov_queue_group_io(struct obd_export *exp,
                              struct lov_stripe_md *lsm,
                              struct lov_oinfo *loi,
                              struct obd_io_group *oig, void *cookie,
                              int cmd, obd_off off, int count,
                              obd_flag brw_flags, obd_flag async_flags)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;

        LASSERT(loi == NULL);

        ASSERT_LSM_MAGIC(lsm);

        lap = LAP_FROM_COOKIE(cookie);

        loi = &lsm->lsm_oinfo[lap->lap_stripe];

        rc = obd_queue_group_io(lov->tgts[loi->loi_ost_idx].ltd_exp, lsm, loi,
                                oig, lap->lap_sub_cookie, cmd, off, count,
                                brw_flags, async_flags);
        RETURN(rc);
}

/* this isn't exactly optimal.  we may have queued sync io in oscs on
 * all stripes, but we don't record that fact at queue time.  so we
 * trigger sync io on all stripes. */
static int lov_trigger_group_io(struct obd_export *exp,
                                struct lov_stripe_md *lsm,
                                struct lov_oinfo *loi,
                                struct obd_io_group *oig)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0, i, err;

        LASSERT(loi == NULL);

        ASSERT_LSM_MAGIC(lsm);

        loi = lsm->lsm_oinfo;
        for (i = 0; i < lsm->lsm_stripe_count; i++, loi++) {
                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                err = obd_trigger_group_io(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                           lsm, loi, oig);
                if (rc == 0 && err != 0)
                        rc = err;
        };
        RETURN(rc);
}

static int lov_teardown_async_page(struct obd_export *exp,
                                   struct lov_stripe_md *lsm,
                                   struct lov_oinfo *loi, void *cookie)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;

        LASSERT(loi == NULL);

        ASSERT_LSM_MAGIC(lsm);

        lap = LAP_FROM_COOKIE(cookie);

        loi = &lsm->lsm_oinfo[lap->lap_stripe];

        rc = obd_teardown_async_page(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                     lsm, loi, lap->lap_sub_cookie);
        if (rc) {
                CERROR("unable to teardown sub cookie %p: %d\n",
                       lap->lap_sub_cookie, rc);
                RETURN(rc);
        }
        RETURN(rc);
}

static int lov_enqueue(struct obd_export *exp, struct lov_stripe_md *lsm,
                       __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                       int *flags, void *bl_cb, void *cp_cb, void *gl_cb,
                       void *data,__u32 lvb_len, void *lvb_swabber,
                       struct lustre_handle *lockh)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        ldlm_error_t rc;
        int save_flags = *flags;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        /* we should never be asked to replay a lock this way. */
        LASSERT((*flags & LDLM_FL_REPLAY) == 0);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_enqueue_set(exp, lsm, policy, mode, lockh, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                ldlm_policy_data_t sub_policy;
                req = list_entry(pos, struct lov_request, rq_link);
                lov_lockhp = set->set_lockh->llh_handles + req->rq_stripe;
                LASSERT(lov_lockhp);

                *flags = save_flags;
                sub_policy.l_extent = req->rq_extent;

                rc = obd_enqueue(lov->tgts[req->rq_idx].ltd_exp, req->rq_md,
                                 type, &sub_policy, mode, flags, bl_cb,
                                 cp_cb, gl_cb, data, lvb_len, lvb_swabber,
                                 lov_lockhp);
                rc = lov_update_enqueue_set(set, req, rc, save_flags);
                if (rc != ELDLM_OK)
                        break;
        }

        lov_fini_enqueue_set(set, mode);
        RETURN(rc);
}

static int lov_match(struct obd_export *exp, struct lov_stripe_md *lsm,
                     __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                     int *flags, void *data, struct lustre_handle *lockh)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lustre_handle *lov_lockhp;
        int lov_flags, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_match_set(exp, lsm, policy, mode, lockh, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                ldlm_policy_data_t sub_policy;
                req = list_entry(pos, struct lov_request, rq_link);
                lov_lockhp = set->set_lockh->llh_handles + req->rq_stripe;
                LASSERT(lov_lockhp);

                lov_flags = *flags;
                sub_policy.l_extent = req->rq_extent;

                rc = obd_match(lov->tgts[req->rq_idx].ltd_exp, req->rq_md,
                               type, &sub_policy, mode, &lov_flags, data,
                               lov_lockhp);
                rc = lov_update_match_set(set, req, rc);
                if (rc != 1)
                        break;
        }
        lov_fini_match_set(set, mode, *flags);
        RETURN(rc);
}

static int lov_change_cbdata(struct obd_export *exp,
                             struct lov_stripe_md *lsm, ldlm_iterator_t it,
                             void *data)
{
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct lov_stripe_md submd;

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                rc = obd_change_cbdata(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                       &submd, it, data);
        }
        RETURN(rc);
}

static int lov_cancel(struct obd_export *exp, struct lov_stripe_md *lsm,
                      __u32 mode, struct lustre_handle *lockh)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lustre_handle *lov_lockhp;
        int err = 0, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        LASSERT(lockh);
        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_cancel_set(exp, lsm, mode, lockh, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);
                lov_lockhp = set->set_lockh->llh_handles + req->rq_stripe;

                rc = obd_cancel(lov->tgts[req->rq_idx].ltd_exp, req->rq_md,
                                mode, lov_lockhp);
                rc = lov_update_common_set(set, req, rc);
                if (rc) {
                        CERROR("error: cancel objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               lsm->lsm_object_id,
                               req->rq_md->lsm_object_id, req->rq_idx, rc);
                        err = rc;
                }

        }
        lov_fini_cancel_set(set);
        RETURN(err);
}

static int lov_cancel_unused(struct obd_export *exp,
                             struct lov_stripe_md *lsm, int flags, void *opaque)
{
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        lov = &exp->exp_obd->u.lov;
        if (lsm == NULL) {
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        int err;
                        if (!lov->tgts[i].ltd_exp)
                                continue;

                        err = obd_cancel_unused(lov->tgts[i].ltd_exp, NULL,
                                                flags, opaque);
                        if (!rc)
                                rc = err;
                }
                RETURN(rc);
        }

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct lov_stripe_md submd;
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0)
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel_unused(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                        &submd, flags, opaque);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: cancel unused objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        RETURN(rc);
}

static int lov_join_lru(struct obd_export *exp,
                        struct lov_stripe_md *lsm, int join)
{
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int i, count = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);
        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct lov_stripe_md submd;
                int rc = 0;

                if (lov->tgts[loi->loi_ost_idx].active == 0)
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                rc = obd_join_lru(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                  &submd, join);
                if (rc < 0) {
                        CERROR("join lru failed. objid: "LPX64" subobj: "LPX64
                               " ostidx: %d rc: %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, rc);
                        return rc;
                } else {
                        count += rc;
                }
        }
        RETURN(count);
}

#define LOV_U64_MAX ((__u64)~0ULL)
#define LOV_SUM_MAX(tot, add)                                           \
        do {                                                            \
                if ((tot) + (add) < (tot))                              \
                        (tot) = LOV_U64_MAX;                            \
                else                                                    \
                        (tot) += (add);                                 \
        } while(0)

static int lov_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                      unsigned long max_age)
{
        struct lov_obd *lov = &obd->u.lov;
        struct obd_statfs lov_sfs;
        int set = 0;
        int rc = 0;
        int i;
        ENTRY;


        /* We only get block data from the OBD */
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                int err;
                if (!lov->tgts[i].active) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", i);
                        continue;
                }

                err = obd_statfs(class_exp2obd(lov->tgts[i].ltd_exp), &lov_sfs,
                                 max_age);
                if (err) {
                        if (lov->tgts[i].active && !rc)
                                rc = err;
                        continue;
                }

                if (!set) {
                        memcpy(osfs, &lov_sfs, sizeof(lov_sfs));
                        set = 1;
                } else {
                        osfs->os_bfree += lov_sfs.os_bfree;
                        osfs->os_bavail += lov_sfs.os_bavail;
                        osfs->os_blocks += lov_sfs.os_blocks;
                        /* XXX not sure about this one - depends on policy.
                         *   - could be minimum if we always stripe on all OBDs
                         *     (but that would be wrong for any other policy,
                         *     if one of the OBDs has no more objects left)
                         *   - could be sum if we stripe whole objects
                         *   - could be average, just to give a nice number
                         *
                         * To give a "reasonable" (if not wholly accurate)
                         * number, we divide the total number of free objects
                         * by expected stripe count (watch out for overflow).
                         */
                        LOV_SUM_MAX(osfs->os_files, lov_sfs.os_files);
                        LOV_SUM_MAX(osfs->os_ffree, lov_sfs.os_ffree);
                }
        }

        if (set) {
                __u32 expected_stripes = lov_get_stripecnt(lov, 0);

                if (osfs->os_files != LOV_U64_MAX)
                        do_div(osfs->os_files, expected_stripes);
                if (osfs->os_ffree != LOV_U64_MAX)
                        do_div(osfs->os_ffree, expected_stripes);
        } else if (!rc)
                rc = -EIO;

        RETURN(rc);
}

static int lov_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct lov_obd *lov = &obddev->u.lov;
        int i, rc, count = lov->desc.ld_tgt_count;
        struct obd_uuid *uuidp;
        ENTRY;

        switch (cmd) {
        case OBD_IOC_LOV_GET_CONFIG: {
                struct obd_ioctl_data *data = karg;
                struct lov_tgt_desc *tgtdesc;
                struct lov_desc *desc;
                char *buf = NULL;
                __u32 *genp;

                buf = NULL;
                len = 0;
                if (obd_ioctl_getdata(&buf, &len, (void *)uarg))
                        RETURN(-EINVAL);

                data = (struct obd_ioctl_data *)buf;

                if (sizeof(*desc) > data->ioc_inllen1) {
                        obd_ioctl_freedata(buf, len);
                        RETURN(-EINVAL);
                }

                if (sizeof(uuidp->uuid) * count > data->ioc_inllen2) {
                        obd_ioctl_freedata(buf, len);
                        RETURN(-EINVAL);
                }

                if (sizeof(__u32) * count > data->ioc_inllen3) {
                        obd_ioctl_freedata(buf, len);
                        RETURN(-EINVAL);
                }

                desc = (struct lov_desc *)data->ioc_inlbuf1;
                memcpy(desc, &(lov->desc), sizeof(*desc));

                uuidp = (struct obd_uuid *)data->ioc_inlbuf2;
                genp = (__u32 *)data->ioc_inlbuf3;
                tgtdesc = lov->tgts;
                /* the uuid will be empty for deleted OSTs */
                for (i = 0; i < count; i++, uuidp++, genp++, tgtdesc++) {
                        obd_str2uuid(uuidp, tgtdesc->uuid.uuid);
                        *genp = tgtdesc->ltd_gen;
                }

                rc = copy_to_user((void *)uarg, buf, len);
                if (rc)
                        rc = -EFAULT;
                obd_ioctl_freedata(buf, len);
                break;
        }
        case LL_IOC_LOV_SETSTRIPE:
                rc = lov_setstripe(exp, karg, uarg);
                break;
        case LL_IOC_LOV_GETSTRIPE:
                rc = lov_getstripe(exp, karg, uarg);
                break;
        case LL_IOC_LOV_SETEA:
                rc = lov_setea(exp, karg, uarg);
                break;
        default: {
                int set = 0;
                if (count == 0)
                        RETURN(-ENOTTY);
                rc = 0;
                for (i = 0; i < count; i++) {
                        int err;

                        /* OST was disconnected */
                        if (!lov->tgts[i].ltd_exp)
                                continue;

                        err = obd_iocontrol(cmd, lov->tgts[i].ltd_exp,
                                            len, karg, uarg);
                        if (err) {
                                if (lov->tgts[i].active) {
                                        CERROR("error: iocontrol OSC %s on OST "
                                               "idx %d cmd %x: err = %d\n",
                                               lov->tgts[i].uuid.uuid, i,
                                               cmd, err);
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

static int lov_get_info(struct obd_export *exp, __u32 keylen,
                        void *key, __u32 *vallen, void *val)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct lov_obd *lov = &obddev->u.lov;
        int i;
        ENTRY;

        if (!vallen || !val)
                RETURN(-EFAULT);

        if (keylen > strlen("lock_to_stripe") &&
            strcmp(key, "lock_to_stripe") == 0) {
                struct {
                        char name[16];
                        struct ldlm_lock *lock;
                        struct lov_stripe_md *lsm;
                } *data = key;
                struct lov_oinfo *loi;
                __u32 *stripe = val;

                if (*vallen < sizeof(*stripe))
                        RETURN(-EFAULT);
                *vallen = sizeof(*stripe);

                /* XXX This is another one of those bits that will need to
                 * change if we ever actually support nested LOVs.  It uses
                 * the lock's export to find out which stripe it is. */
                /* XXX - it's assumed all the locks for deleted OSTs have
                 * been cancelled. Also, the export for deleted OSTs will
                 * be NULL and won't match the lock's export. */
                for (i = 0, loi = data->lsm->lsm_oinfo;
                     i < data->lsm->lsm_stripe_count;
                     i++, loi++) {
                        if (lov->tgts[loi->loi_ost_idx].ltd_exp ==
                            data->lock->l_conn_export) {
                                *stripe = i;
                                RETURN(0);
                        }
                }
                LDLM_ERROR(data->lock, "lock on inode without such object\n");
                dump_lsm(D_ERROR, data->lsm);
                RETURN(-ENXIO);
        } else if (keylen >= strlen("size_to_stripe") &&
                   strcmp(key, "size_to_stripe") == 0) {
                struct {
                        int stripe_number;
                        __u64 size;
                        struct lov_stripe_md *lsm;
                } *data = val;

                if (*vallen < sizeof(*data))
                        RETURN(-EFAULT);

                data->size = lov_size_to_stripe(data->lsm, data->size,
                                                data->stripe_number);
                RETURN(0);
        } else if (keylen >= strlen("last_id") && strcmp(key, "last_id") == 0) {
                obd_id *ids = val;
                int rc, size = sizeof(obd_id);
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        if (!lov->tgts[i].active)
                                continue;
                        rc = obd_get_info(lov->tgts[i].ltd_exp,
                                          keylen, key, &size, &(ids[i]));
                        if (rc != 0)
                                RETURN(rc);
                }
                RETURN(0);
        } else if (keylen >= strlen("lovdesc") && strcmp(key, "lovdesc") == 0) {
                struct lov_desc *desc_ret = val;
                *desc_ret = lov->desc;

                RETURN(0);
        }

        RETURN(-EINVAL);
}

static int lov_set_info(struct obd_export *exp, obd_count keylen,
                        void *key, obd_count vallen, void *val)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct lov_obd *lov = &obddev->u.lov;
        int i, rc = 0, err;
        ENTRY;

        if (KEY_IS("next_id")) {
                if (vallen != lov->desc.ld_tgt_count)
                        RETURN(-EINVAL);
                vallen = sizeof(obd_id);
        }

        if (KEY_IS("next_id") || KEY_IS("checksum")) {
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        /* OST was disconnected */
                        if (!lov->tgts[i].ltd_exp)
                                continue;

                        /* hit all OSCs, even inactive ones */
                        err = obd_set_info(lov->tgts[i].ltd_exp, keylen, key,
                                           vallen, ((obd_id*)val) + i);
                        if (!rc)
                                rc = err;
                }
                RETURN(rc);
        }

        if (KEY_IS("evict_by_nid")) {
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        /* OST was disconnected or is inactive */
                        if (!lov->tgts[i].ltd_exp || !lov->tgts[i].active)
                                continue;

                        err = obd_set_info(lov->tgts[i].ltd_exp, keylen, key,
                                           vallen, val);
                        if (!rc)
                                rc = err;
                }
                RETURN(rc);
        }

        if (KEY_IS("mds_conn") || KEY_IS("unlinked")) {
                if (vallen != 0)
                        RETURN(-EINVAL);
        } else {
                RETURN(-EINVAL);
        }

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (val && !obd_uuid_equals(val, &lov->tgts[i].uuid))
                        continue;

                /* OST was disconnected */
                if (!lov->tgts[i].ltd_exp)
                        continue;

                if (!val && !lov->tgts[i].active)
                        continue;

                err = obd_set_info(lov->tgts[i].ltd_exp,
                                  keylen, key, vallen, val);
                if (!rc)
                        rc = err;
        }
        RETURN(rc);
}

int lov_test_and_clear_async_rc(struct lov_stripe_md *lsm)
{
        struct lov_oinfo *loi;
        int i, rc = 0;
        ENTRY;

        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++) {
                if (loi->loi_ar.ar_rc && !rc)
                        rc = loi->loi_ar.ar_rc;
                loi->loi_ar.ar_rc = 0;
        }
        RETURN(rc);
}
EXPORT_SYMBOL(lov_test_and_clear_async_rc);

#if 0
struct lov_multi_wait {
        struct ldlm_lock *lock;
        wait_queue_t      wait;
        int               completed;
        int               generation;
};

int lov_complete_many(struct obd_export *exp, struct lov_stripe_md *lsm,
                      struct lustre_handle *lockh)
{
        struct lov_lock_handles *lov_lockh = NULL;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_multi_wait *queues;
        int rc = 0, i;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        LASSERT(lockh != NULL);
        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_handle2llh(lockh);
                if (lov_lockh == NULL) {
                        CERROR("LOV: invalid lov lock handle %p\n", lockh);
                        RETURN(-EINVAL);
                }

                lov_lockhp = lov_lockh->llh_handles;
        } else {
                lov_lockhp = lockh;
        }

        OBD_ALLOC(queues, lsm->lsm_stripe_count * sizeof(*queues));
        if (queues == NULL)
                GOTO(out, rc = -ENOMEM);

        lov = &exp->exp_obd->u.lov;
        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++, lov_lockhp++) {
                struct ldlm_lock *lock;
                struct obd_device *obd;
                unsigned long irqflags;

                lock = ldlm_handle2lock(lov_lockhp);
                if (lock == NULL) {
                        CDEBUG(D_HA, "lov idx %d subobj "LPX64" no lock?\n",
                               loi->loi_ost_idx, loi->loi_id);
                        queues[i].completed = 1;
                        continue;
                }

                queues[i].lock = lock;
                init_waitqueue_entry(&(queues[i].wait), current);
                add_wait_queue(lock->l_waitq, &(queues[i].wait));

                obd = class_exp2obd(lock->l_conn_export);
                if (obd != NULL)
                        imp = obd->u.cli.cl_import;
                if (imp != NULL) {
                        spin_lock_irqsave(&imp->imp_lock, irqflags);
                        queues[i].generation = imp->imp_generation;
                        spin_unlock_irqrestore(&imp->imp_lock, irqflags);
                }
        }

        lwi = LWI_TIMEOUT_INTR(obd_timeout * HZ, ldlm_expired_completion_wait,
                               interrupted_completion_wait, &lwd);
        rc = l_wait_event_added(check_multi_complete(queues, lsm), &lwi);

        for (i = 0; i < lsm->lsm_stripe_count; i++)
                remove_wait_queue(lock->l_waitq, &(queues[i].wait));

        if (rc == -EINTR || rc == -ETIMEDOUT) {


        }

 out:
        if (lov_lockh != NULL)
                lov_llh_put(lov_lockh);
        RETURN(rc);
}
#endif


void lov_stripe_lock(struct lov_stripe_md *md)
{
        LASSERT(md->lsm_lock_owner != current);
        spin_lock(&md->lsm_lock);
        LASSERT(md->lsm_lock_owner == NULL);
        md->lsm_lock_owner = current;
}
EXPORT_SYMBOL(lov_stripe_lock);

void lov_stripe_unlock(struct lov_stripe_md *md)
{
        LASSERT(md->lsm_lock_owner == current);
        md->lsm_lock_owner = NULL;
        spin_unlock(&md->lsm_lock);
}
EXPORT_SYMBOL(lov_stripe_unlock);

struct obd_ops lov_obd_ops = {
        .o_owner               = THIS_MODULE,
        .o_setup               = lov_setup,
        .o_precleanup          = lov_precleanup,
        .o_cleanup             = lov_cleanup,
        .o_process_config      = lov_process_config,
        .o_connect             = lov_connect,
        .o_disconnect          = lov_disconnect,
        .o_statfs              = lov_statfs,
        .o_packmd              = lov_packmd,
        .o_unpackmd            = lov_unpackmd,
        .o_create              = lov_create,
        .o_destroy             = lov_destroy,
        .o_getattr             = lov_getattr,
        .o_getattr_async       = lov_getattr_async,
        .o_setattr             = lov_setattr,
        .o_setattr_async       = lov_setattr_async,
        .o_brw                 = lov_brw,
        .o_brw_async           = lov_brw_async,
        .o_prep_async_page     = lov_prep_async_page,
        .o_queue_async_io      = lov_queue_async_io,
        .o_set_async_flags     = lov_set_async_flags,
        .o_queue_group_io      = lov_queue_group_io,
        .o_trigger_group_io    = lov_trigger_group_io,
        .o_teardown_async_page = lov_teardown_async_page,
        .o_adjust_kms          = lov_adjust_kms,
        .o_punch               = lov_punch,
        .o_sync                = lov_sync,
        .o_enqueue             = lov_enqueue,
        .o_match               = lov_match,
        .o_change_cbdata       = lov_change_cbdata,
        .o_cancel              = lov_cancel,
        .o_cancel_unused       = lov_cancel_unused,
        .o_join_lru            = lov_join_lru,
        .o_iocontrol           = lov_iocontrol,
        .o_get_info            = lov_get_info,
        .o_set_info            = lov_set_info,
        .o_llog_init           = lov_llog_init,
        .o_llog_finish         = lov_llog_finish,
        .o_notify              = lov_notify,
#ifdef HAVE_QUOTA_SUPPORT
        .o_quotacheck          = lov_quotacheck,
        .o_quotactl            = lov_quotactl,
#endif
};

int __init lov_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        lprocfs_init_vars(lov, &lvars);
        rc = class_register_type(&lov_obd_ops, lvars.module_vars,
                                 OBD_LOV_DEVICENAME);
        RETURN(rc);
}

#ifdef __KERNEL__
static void /*__exit*/ lov_exit(void)
{
        class_unregister_type(OBD_LOV_DEVICENAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Logical Object Volume OBD driver");
MODULE_LICENSE("GPL");

module_init(lov_init);
module_exit(lov_exit);
#endif
