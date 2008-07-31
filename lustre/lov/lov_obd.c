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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 * lustre/lov/lov_obd.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Mike Shaver <shaver@clusterfs.com>
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LOV
#ifdef __KERNEL__
#include <libcfs/libcfs.h>
#else
#include <liblustre.h>
#endif

#include <obd_support.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre/lustre_idl.h>
#include <lustre_dlm.h>
#include <lustre_mds.h>
#include <lustre_debug.h>
#include <obd_class.h>
#include <obd_lov.h>
#include <obd_ost.h>
#include <lprocfs_status.h>
#include <lustre_param.h>
#include <lustre_cache.h>

#include "lov_internal.h"


/* Keep a refcount of lov->tgt usage to prevent racing with addition/deletion.
   Any function that expects lov_tgts to remain stationary must take a ref. */
void lov_getref(struct obd_device *obd)
{
        struct lov_obd *lov = &obd->u.lov;

        /* nobody gets through here until lov_putref is done */
        mutex_down(&lov->lov_lock);
        atomic_inc(&lov->lov_refcount);
        mutex_up(&lov->lov_lock);
        return;
}

static void __lov_del_obd(struct obd_device *obd, __u32 index);

void lov_putref(struct obd_device *obd)
{
        struct lov_obd *lov = &obd->u.lov;
        mutex_down(&lov->lov_lock);
        /* ok to dec to 0 more than once -- ltd_exp's will be null */
        if (atomic_dec_and_test(&lov->lov_refcount) && lov->lov_death_row) {
                int i;
                CDEBUG(D_CONFIG, "destroying %d lov targets\n", 
                       lov->lov_death_row);
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_reap)
                                continue;
                        /* Disconnect and delete from list */
                        __lov_del_obd(obd, i);
                        lov->lov_death_row--;
                }
        }
        mutex_up(&lov->lov_lock);
}

static int lov_register_page_removal_cb(struct obd_export *exp,
                                        obd_page_removal_cb_t func,
                                        obd_pin_extent_cb pin_cb)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int i, rc = 0;

        if (lov->lov_page_removal_cb && lov->lov_page_removal_cb != func)
                return -EBUSY;

        if (lov->lov_page_pin_cb && lov->lov_page_pin_cb != pin_cb)
                return -EBUSY;

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_exp)
                        continue;
                rc |= obd_register_page_removal_cb(lov->lov_tgts[i]->ltd_exp,
                                                   func, pin_cb);
        }

        lov->lov_page_removal_cb = func;
        lov->lov_page_pin_cb = pin_cb;

        return rc;
}

static int lov_unregister_page_removal_cb(struct obd_export *exp,
                                        obd_page_removal_cb_t func)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int i, rc = 0;

        if (lov->lov_page_removal_cb && lov->lov_page_removal_cb != func)
                return -EINVAL;

        lov->lov_page_removal_cb = NULL;
        lov->lov_page_pin_cb = NULL;

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_exp)
                        continue;
                rc |= obd_unregister_page_removal_cb(lov->lov_tgts[i]->ltd_exp,
                                                     func);
        }

        return rc;
}

static int lov_register_lock_cancel_cb(struct obd_export *exp,
                                         obd_lock_cancel_cb func)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int i, rc = 0;

        if (lov->lov_lock_cancel_cb && lov->lov_lock_cancel_cb != func)
                return -EBUSY;

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_exp)
                        continue;
                rc |= obd_register_lock_cancel_cb(lov->lov_tgts[i]->ltd_exp,
                                                  func);
        }

        lov->lov_lock_cancel_cb = func;

        return rc;
}

static int lov_unregister_lock_cancel_cb(struct obd_export *exp,
                                         obd_lock_cancel_cb func)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int i, rc = 0;

        if (lov->lov_lock_cancel_cb && lov->lov_lock_cancel_cb != func)
                return -EINVAL;

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_exp)
                        continue;
                rc |= obd_unregister_lock_cancel_cb(lov->lov_tgts[i]->ltd_exp,
                                                    func);
        }
        lov->lov_lock_cancel_cb = NULL;
        return rc;
}

#define MAX_STRING_SIZE 128
static int lov_connect_obd(struct obd_device *obd, __u32 index, int activate, 
                           struct obd_connect_data *data)
{
        struct lov_obd *lov = &obd->u.lov;
        struct obd_uuid tgt_uuid;
        struct obd_device *tgt_obd;
        struct obd_uuid lov_osc_uuid = { "LOV_OSC_UUID" };
        struct lustre_handle conn = {0, };
        struct obd_import *imp;

#ifdef __KERNEL__
        cfs_proc_dir_entry_t *lov_proc_dir;
#endif
        int rc;
        ENTRY;

        if (!lov->lov_tgts[index])
                RETURN(-EINVAL);

        tgt_uuid = lov->lov_tgts[index]->ltd_uuid;
        tgt_obd = class_find_client_obd(&tgt_uuid, LUSTRE_OSC_NAME,
                                        &obd->obd_uuid);

        if (!tgt_obd) {
                CERROR("Target %s not attached\n", obd_uuid2str(&tgt_uuid));
                RETURN(-EINVAL);
        }
        
        if (!tgt_obd->obd_set_up) {
                CERROR("Target %s not set up\n", obd_uuid2str(&tgt_uuid));
                RETURN(-EINVAL);
        }

        if (data && (data->ocd_connect_flags & OBD_CONNECT_INDEX))
                data->ocd_index = index;

        /*
         * Divine LOV knows that OBDs under it are OSCs.
         */
        imp = tgt_obd->u.cli.cl_import;

        if (activate) {
                tgt_obd->obd_no_recov = 0;
                /* FIXME this is probably supposed to be 
                   ptlrpc_set_import_active.  Horrible naming. */
                ptlrpc_activate_import(imp);
        }

        if (imp->imp_invalid) {
                CERROR("not connecting OSC %s; administratively "
                       "disabled\n", obd_uuid2str(&tgt_uuid));
                rc = obd_register_observer(tgt_obd, obd);
                if (rc) {
                        CERROR("Target %s register_observer error %d; "
                               "will not be able to reactivate\n",
                               obd_uuid2str(&tgt_uuid), rc);
                }
                RETURN(0);
        }

        rc = obd_connect(&conn, tgt_obd, &lov_osc_uuid, data, NULL);
        if (rc) {
                CERROR("Target %s connect error %d\n",
                       obd_uuid2str(&tgt_uuid), rc);
                RETURN(rc);
        }
        lov->lov_tgts[index]->ltd_exp = class_conn2export(&conn);
        if (!lov->lov_tgts[index]->ltd_exp) {
                CERROR("Target %s: null export!\n", obd_uuid2str(&tgt_uuid));
                RETURN(-ENODEV);
        }

        rc = obd_register_page_removal_cb(lov->lov_tgts[index]->ltd_exp,
                                          lov->lov_page_removal_cb,
                                          lov->lov_page_pin_cb);
        if (rc) {
                obd_disconnect(lov->lov_tgts[index]->ltd_exp);
                lov->lov_tgts[index]->ltd_exp = NULL;
                RETURN(rc);
        }

        rc = obd_register_lock_cancel_cb(lov->lov_tgts[index]->ltd_exp,
                                         lov->lov_lock_cancel_cb);
        if (rc) {
                obd_unregister_page_removal_cb(lov->lov_tgts[index]->ltd_exp,
                                               lov->lov_page_removal_cb);
                obd_disconnect(lov->lov_tgts[index]->ltd_exp);
                lov->lov_tgts[index]->ltd_exp = NULL;
                RETURN(rc);
        }

        rc = obd_register_observer(tgt_obd, obd);
        if (rc) {
                CERROR("Target %s register_observer error %d\n",
                       obd_uuid2str(&tgt_uuid), rc);
                obd_unregister_lock_cancel_cb(lov->lov_tgts[index]->ltd_exp,
                                              lov->lov_lock_cancel_cb);
                obd_unregister_page_removal_cb(lov->lov_tgts[index]->ltd_exp,
                                               lov->lov_page_removal_cb);
                obd_disconnect(lov->lov_tgts[index]->ltd_exp);
                lov->lov_tgts[index]->ltd_exp = NULL;
                RETURN(rc);
        }

        lov->lov_tgts[index]->ltd_reap = 0;
        if (activate) {
                lov->lov_tgts[index]->ltd_active = 1;
                lov->desc.ld_active_tgt_count++;
                lov->lov_tgts[index]->ltd_exp->exp_obd->obd_inactive = 0;
        }
        CDEBUG(D_CONFIG, "Connected tgt idx %d %s (%s) %sactive\n", index,
               obd_uuid2str(&tgt_uuid), tgt_obd->obd_name, activate ? "":"in");

#ifdef __KERNEL__
        lov_proc_dir = lprocfs_srch(obd->obd_proc_entry, "target_obds");
        if (lov_proc_dir) {
                struct obd_device *osc_obd = class_conn2obd(&conn);
                cfs_proc_dir_entry_t *osc_symlink;
                char name[MAX_STRING_SIZE];

                LASSERT(osc_obd != NULL);
                LASSERT(osc_obd->obd_magic == OBD_DEVICE_MAGIC);
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
                        lprocfs_remove(&lov_proc_dir);
                }
        }
#endif

        rc = qos_add_tgt(obd, index);
        if (rc) 
                CERROR("qos_add_tgt failed %d\n", rc);

        RETURN(0);
}

static int lov_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data,
                       void *localdata)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_tgt_desc *tgt;
        int i, rc;
        ENTRY;

        CDEBUG(D_CONFIG, "connect #%d\n", lov->lov_connects);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        /* Why should there ever be more than 1 connect? */
        lov->lov_connects++;
        LASSERT(lov->lov_connects == 1);
        
        memset(&lov->lov_ocd, 0, sizeof(lov->lov_ocd));
        if (data)
                lov->lov_ocd = *data;

        lov_getref(obd);
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                tgt = lov->lov_tgts[i];
                if (!tgt || obd_uuid_empty(&tgt->ltd_uuid))
                        continue;
                /* Flags will be lowest common denominator */
                rc = lov_connect_obd(obd, i, lov->lov_tgts[i]->ltd_activate,
                                     &lov->lov_ocd);
                if (rc) {
                        CERROR("%s: lov connect tgt %d failed: %d\n", 
                               obd->obd_name, i, rc);
                        continue;
                }
        }
        lov_putref(obd);
        
        RETURN(0);
}

static int lov_disconnect_obd(struct obd_device *obd, __u32 index)
{
        cfs_proc_dir_entry_t *lov_proc_dir;
        struct lov_obd *lov = &obd->u.lov;
        struct obd_device *osc_obd =
                class_exp2obd(lov->lov_tgts[index]->ltd_exp);
        int rc;

        ENTRY;

        CDEBUG(D_CONFIG, "%s: disconnecting target %s\n", 
               obd->obd_name, osc_obd->obd_name);

        obd_unregister_lock_cancel_cb(lov->lov_tgts[index]->ltd_exp,
                                      lov->lov_lock_cancel_cb);
        obd_unregister_page_removal_cb(lov->lov_tgts[index]->ltd_exp,
                                       lov->lov_page_removal_cb);
        if (lov->lov_tgts[index]->ltd_active) {
                lov->lov_tgts[index]->ltd_active = 0;
                lov->desc.ld_active_tgt_count--;
                lov->lov_tgts[index]->ltd_exp->exp_obd->obd_inactive = 1;
        }

        lov_proc_dir = lprocfs_srch(obd->obd_proc_entry, "target_obds");
        if (lov_proc_dir) {
                cfs_proc_dir_entry_t *osc_symlink;

                osc_symlink = lprocfs_srch(lov_proc_dir, osc_obd->obd_name);
                if (osc_symlink) {
                        lprocfs_remove(&osc_symlink);
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

        rc = obd_disconnect(lov->lov_tgts[index]->ltd_exp);
        if (rc) {
                CERROR("Target %s disconnect error %d\n",
                       lov_uuid2str(lov, index), rc);
                rc = 0;
        }

        qos_del_tgt(obd, index);

        lov->lov_tgts[index]->ltd_exp = NULL;
        RETURN(0);
}

static int lov_del_target(struct obd_device *obd, __u32 index, 
                          struct obd_uuid *uuidp, int gen);

static int lov_disconnect(struct obd_export *exp)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        int i, rc;
        ENTRY;

        if (!lov->lov_tgts)
                goto out;

        /* Only disconnect the underlying layers on the final disconnect. */
        lov->lov_connects--;
        if (lov->lov_connects != 0) {
                /* why should there be more than 1 connect? */
                CERROR("disconnect #%d\n", lov->lov_connects);
                goto out;
        }

        /* Let's hold another reference so lov_del_obd doesn't spin through
           putref every time */
        lov_getref(obd);
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (lov->lov_tgts[i] && lov->lov_tgts[i]->ltd_exp) {
                        /* Disconnection is the last we know about an obd */
                        lov_del_target(obd, i, 0, lov->lov_tgts[i]->ltd_gen);
                }
        }
        lov_putref(obd);

out:
        rc = class_disconnect(exp); /* bz 9811 */
        RETURN(rc);
}

/* Error codes:
 *
 *  -EINVAL  : UUID can't be found in the LOV's target list
 *  -ENOTCONN: The UUID is found, but the target connection is bad (!)
 *  -EBADF   : The UUID is found, but the OBD is the wrong type (!)
 */
static int lov_set_osc_active(struct obd_device *obd, struct obd_uuid *uuid,
                              int activate)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_tgt_desc *tgt;
        int i, rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "Searching in lov %p for uuid %s (activate=%d)\n",
               lov, uuid->uuid, activate);

        lov_getref(obd);
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                tgt = lov->lov_tgts[i];
                if (!tgt || !tgt->ltd_exp)
                        continue;

                CDEBUG(D_INFO, "lov idx %d is %s conn "LPX64"\n",
                       i, obd_uuid2str(&tgt->ltd_uuid),
                       tgt->ltd_exp->exp_handle.h_cookie);
                if (obd_uuid_equals(uuid, &tgt->ltd_uuid))
                        break;
        }

        if (i == lov->desc.ld_tgt_count)
                GOTO(out, rc = -EINVAL);

        if (lov->lov_tgts[i]->ltd_active == activate) {
                CDEBUG(D_INFO, "OSC %s already %sactive!\n", uuid->uuid,
                       activate ? "" : "in");
                GOTO(out, rc);
        }

        CDEBUG(D_CONFIG, "Marking OSC %s %sactive\n", obd_uuid2str(uuid),
               activate ? "" : "in");

        lov->lov_tgts[i]->ltd_active = activate;

        if (activate) {
                lov->desc.ld_active_tgt_count++;
                lov->lov_tgts[i]->ltd_exp->exp_obd->obd_inactive = 0;
        } else {
                lov->desc.ld_active_tgt_count--;
                lov->lov_tgts[i]->ltd_exp->exp_obd->obd_inactive = 1;
        }
        /* remove any old qos penalty */
        lov->lov_tgts[i]->ltd_qos.ltq_penalty = 0;

 out:
        lov_putref(obd);
        RETURN(rc);
}

static int lov_notify(struct obd_device *obd, struct obd_device *watched,
                      enum obd_notify_event ev, void *data)
{
        int rc = 0;
        ENTRY;

        if (ev == OBD_NOTIFY_ACTIVE || ev == OBD_NOTIFY_INACTIVE) {
                struct obd_uuid *uuid;

                LASSERT(watched);
                
                if (strcmp(watched->obd_type->typ_name, LUSTRE_OSC_NAME)) {
                        CERROR("unexpected notification of %s %s!\n",
                               watched->obd_type->typ_name,
                               watched->obd_name);
                        RETURN(-EINVAL);
                }
                uuid = &watched->u.cli.cl_target_uuid;

                /* Set OSC as active before notifying the observer, so the
                 * observer can use the OSC normally.
                 */
                rc = lov_set_osc_active(obd, uuid, ev == OBD_NOTIFY_ACTIVE);
                if (rc) {
                        CERROR("%sactivation of %s failed: %d\n",
                               (ev == OBD_NOTIFY_ACTIVE) ? "" : "de",
                               obd_uuid2str(uuid), rc);
                        RETURN(rc);
                }
        }

        /* Pass the notification up the chain. */
        if (watched) {
                rc = obd_notify_observer(obd, watched, ev, data);
        } else {
                /* NULL watched means all osc's in the lov (only for syncs) */
                struct lov_obd *lov = &obd->u.lov;
                struct obd_device *tgt_obd;
                int i;
                lov_getref(obd);
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        if (!lov->lov_tgts[i])
                                continue;
                        tgt_obd = class_exp2obd(lov->lov_tgts[i]->ltd_exp);
                        rc = obd_notify_observer(obd, tgt_obd, ev, data);
                        if (rc) {
                                CERROR("%s: notify %s of %s failed %d\n",
                                       obd->obd_name, 
                                       obd->obd_observer->obd_name,
                                       tgt_obd->obd_name, rc);
                                break;
                        }
                }
                lov_putref(obd);
        }

        RETURN(rc);
}

static int lov_add_target(struct obd_device *obd, struct obd_uuid *uuidp,
                          __u32 index, int gen, int active)
{
        struct lov_obd *lov = &obd->u.lov;
        struct lov_tgt_desc *tgt;
        int rc;
        ENTRY;

        CDEBUG(D_CONFIG, "uuid:%s idx:%d gen:%d active:%d\n",
               uuidp->uuid, index, gen, active);

        if (gen <= 0) {
                CERROR("request to add OBD %s with invalid generation: %d\n",
                       uuidp->uuid, gen);
                RETURN(-EINVAL);
        }

        mutex_down(&lov->lov_lock);

        if ((index < lov->lov_tgt_size) && (lov->lov_tgts[index] != NULL)) {
                tgt = lov->lov_tgts[index];
                CERROR("UUID %s already assigned at LOV target index %d\n",
                       obd_uuid2str(&tgt->ltd_uuid), index);
                mutex_up(&lov->lov_lock);
                RETURN(-EEXIST);
        }

        if (index >= lov->lov_tgt_size) {
                /* We need to reallocate the lov target array. */
                struct lov_tgt_desc **newtgts, **old = NULL;
                __u32 newsize, oldsize = 0;

                newsize = max(lov->lov_tgt_size, (__u32)2);
                while (newsize < index + 1) 
                        newsize = newsize << 1;
                OBD_ALLOC(newtgts, sizeof(*newtgts) * newsize);
                if (newtgts == NULL) {
                        mutex_up(&lov->lov_lock);
                        RETURN(-ENOMEM);
                }

                if (lov->lov_tgt_size) {
                        memcpy(newtgts, lov->lov_tgts, sizeof(*newtgts) * 
                               lov->lov_tgt_size);
                        old = lov->lov_tgts;
                        oldsize = lov->lov_tgt_size;
                }

                lov->lov_tgts = newtgts;
                lov->lov_tgt_size = newsize;
#ifdef __KERNEL__
                smp_rmb();
#endif
                if (old)
                        OBD_FREE(old, sizeof(*old) * oldsize);

                CDEBUG(D_CONFIG, "tgts: %p size: %d\n",
                       lov->lov_tgts, lov->lov_tgt_size);
        }


        OBD_ALLOC_PTR(tgt);
        if (!tgt) {
                mutex_up(&lov->lov_lock);
                RETURN(-ENOMEM);
        }

        memset(tgt, 0, sizeof(*tgt));
        tgt->ltd_uuid = *uuidp;
        /* XXX - add a sanity check on the generation number. */
        tgt->ltd_gen = gen;
        tgt->ltd_index = index;
        tgt->ltd_activate = active;
        lov->lov_tgts[index] = tgt;
        if (index >= lov->desc.ld_tgt_count)
                lov->desc.ld_tgt_count = index + 1;
        mutex_up(&lov->lov_lock);

        CDEBUG(D_CONFIG, "idx=%d ltd_gen=%d ld_tgt_count=%d\n",
                index, tgt->ltd_gen, lov->desc.ld_tgt_count);
        
        if (lov->lov_connects == 0) { 
                /* lov_connect hasn't been called yet. We'll do the
                   lov_connect_obd on this target when that fn first runs,
                   because we don't know the connect flags yet. */
                RETURN(0);
        }

        lov_getref(obd);

        rc = lov_connect_obd(obd, index, active, &lov->lov_ocd);
        if (rc)
                GOTO(out, rc);

        rc = lov_notify(obd, tgt->ltd_exp->exp_obd, 
                        active ? OBD_NOTIFY_ACTIVE : OBD_NOTIFY_INACTIVE,
                        (void *)&index);

out:
        if (rc) {
                CERROR("add failed (%d), deleting %s\n", rc, 
                       obd_uuid2str(&tgt->ltd_uuid));
                lov_del_target(obd, index, 0, 0);
        }
        lov_putref(obd);
        RETURN(rc);
}

/* Schedule a target for deletion */
static int lov_del_target(struct obd_device *obd, __u32 index, 
                          struct obd_uuid *uuidp, int gen)
{
        struct lov_obd *lov = &obd->u.lov;
        int count = lov->desc.ld_tgt_count;
        int rc = 0;
        ENTRY;

        if (index >= count) {
                CERROR("LOV target index %d >= number of LOV OBDs %d.\n",
                       index, count);
                RETURN(-EINVAL);
        }

        lov_getref(obd);

        if (!lov->lov_tgts[index]) {
                CERROR("LOV target at index %d is not setup.\n", index);
                GOTO(out, rc = -EINVAL);
        }

        if (uuidp && !obd_uuid_equals(uuidp, &lov->lov_tgts[index]->ltd_uuid)) {
                CERROR("LOV target UUID %s at index %d doesn't match %s.\n",
                       lov_uuid2str(lov, index), index,
                       obd_uuid2str(uuidp));
                GOTO(out, rc = -EINVAL);
        }

        CDEBUG(D_CONFIG, "uuid: %s idx: %d gen: %d exp: %p active: %d\n",
               lov_uuid2str(lov, index), index,
               lov->lov_tgts[index]->ltd_gen, lov->lov_tgts[index]->ltd_exp, 
               lov->lov_tgts[index]->ltd_active);

        lov->lov_tgts[index]->ltd_reap = 1;
        lov->lov_death_row++;
        /* we really delete it from lov_putref */
out:
        lov_putref(obd);

        RETURN(rc);
}

/* We are holding lov_lock */
static void __lov_del_obd(struct obd_device *obd, __u32 index)
{
        struct lov_obd *lov = &obd->u.lov;
        struct obd_device *osc_obd;
        struct lov_tgt_desc *tgt = lov->lov_tgts[index];

        LASSERT(tgt);
        LASSERT(tgt->ltd_reap);

        osc_obd = class_exp2obd(tgt->ltd_exp);

        CDEBUG(D_CONFIG, "Removing tgt %s : %s\n",
               lov_uuid2str(lov, index), 
               osc_obd ? osc_obd->obd_name : "<no obd>");

        if (tgt->ltd_exp)
                lov_disconnect_obd(obd, index);

        /* XXX - right now there is a dependency on ld_tgt_count being the
         * maximum tgt index for computing the mds_max_easize. So we can't
         * shrink it. */

        lov->lov_tgts[index] = NULL;
        OBD_FREE_PTR(tgt);        

        /* Manual cleanup - no cleanup logs to clean up the osc's.  We must
           do it ourselves. And we can't do it from lov_cleanup,
           because we just lost our only reference to it. */
        if (osc_obd) {
                /* Use lov's force/fail flags. */
                osc_obd->obd_force = obd->obd_force;
                osc_obd->obd_fail = obd->obd_fail;
                class_manual_cleanup(osc_obd);
        }
}

void lov_fix_desc_stripe_size(__u64 *val)
{
        if (*val < PTLRPC_MAX_BRW_SIZE) {
                LCONSOLE_WARN("Increasing default stripe size to min %u\n",
                              PTLRPC_MAX_BRW_SIZE);
                *val = PTLRPC_MAX_BRW_SIZE;
        } else if (*val & (LOV_MIN_STRIPE_SIZE - 1)) {
                *val &= ~(LOV_MIN_STRIPE_SIZE - 1);
                LCONSOLE_WARN("Changing default stripe size to "LPU64" (a "
                              "multiple of %u)\n",
                              *val, LOV_MIN_STRIPE_SIZE);
        }
}

void lov_fix_desc_stripe_count(__u32 *val)
{
        if (*val == 0)
                *val = 1;
}

void lov_fix_desc_pattern(__u32 *val)
{
        /* from lov_setstripe */
        if ((*val != 0) && (*val != LOV_PATTERN_RAID0)) {
                LCONSOLE_WARN("Unknown stripe pattern: %#x\n", *val);
                *val = 0;
        }
}

void lov_fix_desc_qos_maxage(__u32 *val)
{
        /* fix qos_maxage */
        if (*val == 0)
                *val = QOS_DEFAULT_MAXAGE;
}

void lov_fix_desc(struct lov_desc *desc)
{
        lov_fix_desc_stripe_size(&desc->ld_default_stripe_size);
        lov_fix_desc_stripe_count(&desc->ld_default_stripe_count);
        lov_fix_desc_pattern(&desc->ld_pattern);
        lov_fix_desc_qos_maxage(&desc->ld_qos_maxage);
}

static int lov_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars = { 0 };
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

        lov_fix_desc(desc);

        /* Because of 64-bit divide/mod operations only work with a 32-bit
         * divisor in a 32-bit kernel, we cannot support a stripe width
         * of 4GB or larger on 32-bit CPUs. */
        count = desc->ld_default_stripe_count;
        if ((count > 0 ? count : desc->ld_tgt_count) *
            desc->ld_default_stripe_size > 0xffffffff) {
                CERROR("LOV: stripe width "LPU64"x%u > 4294967295 bytes\n",
                       desc->ld_default_stripe_size, count);
                RETURN(-EINVAL);
        }

        desc->ld_active_tgt_count = 0;
        lov->desc = *desc;
        lov->lov_tgt_size = 0;
        sema_init(&lov->lov_lock, 1);
        atomic_set(&lov->lov_refcount, 0);
        CFS_INIT_LIST_HEAD(&lov->lov_qos.lq_oss_list);
        init_rwsem(&lov->lov_qos.lq_rw_sem);
        lov->lov_qos.lq_dirty = 1;
        lov->lov_qos.lq_dirty_rr = 1;
        lov->lov_qos.lq_reset = 1;
        /* Default priority is toward free space balance */
        lov->lov_qos.lq_prio_free = 232;

        lprocfs_lov_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);
#ifdef LPROCFS
        {
                cfs_proc_dir_entry_t *entry;

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

static int lov_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        int rc = 0;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_EARLY: {
                struct lov_obd *lov = &obd->u.lov;
                int i;
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_active)
                                continue;
                        obd_precleanup(class_exp2obd(lov->lov_tgts[i]->ltd_exp),
                                       OBD_CLEANUP_EARLY);
                }
                break;
        }
        case OBD_CLEANUP_EXPORTS:
                break;
        case OBD_CLEANUP_SELF_EXP:
                rc = obd_llog_finish(obd, 0);
                if (rc != 0)
                        CERROR("failed to cleanup llogging subsystems\n");
                break;
        case OBD_CLEANUP_OBD:
                break;
        }
        RETURN(rc);
}

static int lov_cleanup(struct obd_device *obd)
{
        struct lov_obd *lov = &obd->u.lov;

        lprocfs_obd_cleanup(obd);
        if (lov->lov_tgts) {
                int i;
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        if (lov->lov_tgts[i]) {
                                /* Inactive targets may never have connected */
                                if (lov->lov_tgts[i]->ltd_active ||
                                    atomic_read(&lov->lov_refcount)) 
                                        /* We should never get here - these 
                                           should have been removed in the 
                                           disconnect. */
                                        CERROR("lov tgt %d not cleaned!"
                                               " deathrow=%d, lovrc=%d\n",
                                               i, lov->lov_death_row, 
                                               atomic_read(&lov->lov_refcount));
                                lov_del_target(obd, i, 0, 0);
                        }
                }
                OBD_FREE(lov->lov_tgts, sizeof(*lov->lov_tgts) * 
                         lov->lov_tgt_size);
                lov->lov_tgt_size = 0;
        }
        
        if (lov->lov_qos.lq_rr_size) 
                OBD_FREE(lov->lov_qos.lq_rr_array, lov->lov_qos.lq_rr_size);

        RETURN(0);
}

static int lov_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct obd_uuid obd_uuid;
        int cmd;
        int rc = 0;
        ENTRY;

        switch(cmd = lcfg->lcfg_command) {
        case LCFG_LOV_ADD_OBD:
        case LCFG_LOV_ADD_INA:
        case LCFG_LOV_DEL_OBD: {
                __u32 index;
                int gen;
                /* lov_modify_tgts add  0:lov_mdsA  1:ost1_UUID  2:0  3:1 */
                if (LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(obd_uuid.uuid))
                        GOTO(out, rc = -EINVAL);

                obd_str2uuid(&obd_uuid,  lustre_cfg_buf(lcfg, 1));

                if (sscanf(lustre_cfg_buf(lcfg, 2), "%d", &index) != 1)
                        GOTO(out, rc = -EINVAL);
                if (sscanf(lustre_cfg_buf(lcfg, 3), "%d", &gen) != 1)
                        GOTO(out, rc = -EINVAL);
                if (cmd == LCFG_LOV_ADD_OBD)
                        rc = lov_add_target(obd, &obd_uuid, index, gen, 1);
                else if (cmd == LCFG_LOV_ADD_INA)
                        rc = lov_add_target(obd, &obd_uuid, index, gen, 0);
                else
                        rc = lov_del_target(obd, index, &obd_uuid, gen);
                GOTO(out, rc);
        }
        case LCFG_PARAM: {
                struct lprocfs_static_vars lvars = { 0 };
                struct lov_desc *desc = &(obd->u.lov.desc);
                
                if (!desc)
                        GOTO(out, rc = -EINVAL);
                
                lprocfs_lov_init_vars(&lvars);
                
                rc = class_process_proc_param(PARAM_LOV, lvars.obd_vars,
                                              lcfg, obd);
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

        OBDO_ALLOC(tmp_oa);
        if (tmp_oa == NULL)
                RETURN(-ENOMEM);

        if (oti->oti_ost_uuid) {
                ost_uuid = oti->oti_ost_uuid;
                CDEBUG(D_HA, "clearing orphans only for %s\n",
                       ost_uuid->uuid);
        }

        lov_getref(export->exp_obd);
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                struct lov_stripe_md obj_md;
                struct lov_stripe_md *obj_mdp = &obj_md;
                struct lov_tgt_desc *tgt;
                int err;

                tgt = lov->lov_tgts[i];
                if (!tgt)
                        continue;

                /* if called for a specific target, we don't
                   care if it is not active. */
                if (!lov->lov_tgts[i]->ltd_active && ost_uuid == NULL) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", i);
                        continue;
                }

                if (ost_uuid && !obd_uuid_equals(ost_uuid, &tgt->ltd_uuid))
                        continue;

                CDEBUG(D_CONFIG,"Clear orphans for %d:%s\n", i, 
                       obd_uuid2str(ost_uuid));

                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));

                LASSERT(lov->lov_tgts[i]->ltd_exp);
                /* XXX: LOV STACKING: use real "obj_mdp" sub-data */
                err = obd_create(lov->lov_tgts[i]->ltd_exp, 
                                 tmp_oa, &obj_mdp, oti);
                if (err)
                        /* This export will be disabled until it is recovered,
                           and then orphan recovery will be completed. */
                        CERROR("error in orphan recovery on OST idx %d/%d: "
                               "rc = %d\n", i, lov->desc.ld_tgt_count, err);

                if (ost_uuid)
                        break;
        }
        lov_putref(export->exp_obd);

        OBDO_FREE(tmp_oa);
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
        if (ost_idx >= lov->desc.ld_tgt_count ||
            !lov->lov_tgts[ost_idx])
                GOTO(out, rc = -EINVAL);

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                if (lsm->lsm_oinfo[i]->loi_ost_idx == ost_idx) {
                        if (lsm->lsm_oinfo[i]->loi_id != src_oa->o_id)
                                GOTO(out, rc = -EINVAL);
                        break;
                }
        }
        if (i == lsm->lsm_stripe_count)
                GOTO(out, rc = -EINVAL);

        rc = obd_create(lov->lov_tgts[ost_idx]->ltd_exp, src_oa, &obj_mdp, oti);
out:
        OBD_FREE(obj_mdp, sizeof(*obj_mdp));
        RETURN(rc);
}

/* the LOV expects oa->o_id to be set to the LOV object id */
static int lov_create(struct obd_export *exp, struct obdo *src_oa,
                      struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct lov_obd *lov;
        struct obd_info oinfo;
        struct lov_request_set *set = NULL;
        struct lov_request *req;
        struct obd_statfs osfs;
        __u64 maxage;
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

        maxage = cfs_time_shift_64(-lov->desc.ld_qos_maxage);
        obd_statfs_rqset(exp->exp_obd, &osfs, maxage, OBD_STATFS_NODELAY);

        rc = lov_prep_create_set(exp, &oinfo, ea, src_oa, oti, &set);
        if (rc)
                RETURN(rc);

        list_for_each_entry(req, &set->set_list, rq_link) {
                /* XXX: LOV STACKING: use real "obj_mdp" sub-data */
                rc = obd_create(lov->lov_tgts[req->rq_idx]->ltd_exp,
                                req->rq_oi.oi_oa, &req->rq_oi.oi_md, oti);
                lov_update_create_set(set, req, rc);
        }
        rc = lov_fini_create_set(set, ea);
        RETURN(rc);
}

#define ASSERT_LSM_MAGIC(lsmp)                                                  \
do {                                                                            \
        LASSERT((lsmp) != NULL);                                                \
        LASSERTF(((lsmp)->lsm_magic == LOV_MAGIC ||                             \
                 (lsmp)->lsm_magic == LOV_MAGIC_JOIN), "%p->lsm_magic=%x\n",    \
                 (lsmp), (lsmp)->lsm_magic);                                    \
} while (0)

static int lov_destroy(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *lsm, struct obd_trans_info *oti,
                       struct obd_export *md_exp)
{
        struct lov_request_set *set;
        struct obd_info oinfo;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov;
        int rc = 0, err;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        if (oa->o_valid & OBD_MD_FLCOOKIE) {
                LASSERT(oti);
                LASSERT(oti->oti_logcookies);
        }

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_destroy_set(exp, &oinfo, oa, lsm, oti, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                int err;
                req = list_entry(pos, struct lov_request, rq_link);

                if (oa->o_valid & OBD_MD_FLCOOKIE)
                        oti->oti_logcookies = set->set_cookies + req->rq_stripe;

                err = obd_destroy(lov->lov_tgts[req->rq_idx]->ltd_exp,
                                  req->rq_oi.oi_oa, NULL, oti, NULL);
                err = lov_update_common_set(set, req, err);
                if (err) {
                        CERROR("error: destroying objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               oa->o_id, req->rq_oi.oi_oa->o_id,
                               req->rq_idx, err);
                        if (!rc)
                                rc = err;
                }
        }

        if (rc == 0) {
                LASSERT(lsm_op_find(lsm->lsm_magic) != NULL);
                rc = lsm_op_find(lsm->lsm_magic)->lsm_destroy(lsm, oa, md_exp);
        }
        err = lov_fini_destroy_set(set);
        RETURN(rc ? rc : err);
}

static int lov_getattr(struct obd_export *exp, struct obd_info *oinfo)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov;
        int err = 0, rc = 0;
        ENTRY;

        LASSERT(oinfo);
        ASSERT_LSM_MAGIC(oinfo->oi_md);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;

        rc = lov_prep_getattr_set(exp, oinfo, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                CDEBUG(D_INFO, "objid "LPX64"[%d] has subobj "LPX64" at idx "
                       "%u\n", oinfo->oi_oa->o_id, req->rq_stripe, 
                       req->rq_oi.oi_oa->o_id, req->rq_idx);

                rc = obd_getattr(lov->lov_tgts[req->rq_idx]->ltd_exp,
                                 &req->rq_oi);
                err = lov_update_common_set(set, req, rc);
                if (err) {
                        CERROR("error: getattr objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               oinfo->oi_oa->o_id, req->rq_oi.oi_oa->o_id,
                               req->rq_idx, err);
                        break;
                }
        }

        rc = lov_fini_getattr_set(set);
        if (err)
                rc = err;
        RETURN(rc);
}

static int lov_getattr_interpret(struct ptlrpc_request_set *rqset, 
                                 void *data, int rc)
{
        struct lov_request_set *lovset = (struct lov_request_set *)data;
        int err;
        ENTRY;

        /* don't do attribute merge if this aysnc op failed */
        if (rc)
                lovset->set_completes = 0;
        err = lov_fini_getattr_set(lovset);
        RETURN(rc ? rc : err);
}

static int lov_getattr_async(struct obd_export *exp, struct obd_info *oinfo,
                              struct ptlrpc_request_set *rqset)
{
        struct lov_request_set *lovset;
        struct lov_obd *lov;
        struct list_head *pos;
        struct lov_request *req;
        int rc = 0, err;
        ENTRY;

        LASSERT(oinfo);
        ASSERT_LSM_MAGIC(oinfo->oi_md);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;

        rc = lov_prep_getattr_set(exp, oinfo, &lovset);
        if (rc)
                RETURN(rc);

        CDEBUG(D_INFO, "objid "LPX64": %ux%u byte stripes\n",
               oinfo->oi_md->lsm_object_id, oinfo->oi_md->lsm_stripe_count, 
               oinfo->oi_md->lsm_stripe_size);

        list_for_each (pos, &lovset->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                CDEBUG(D_INFO, "objid "LPX64"[%d] has subobj "LPX64" at idx "
                       "%u\n", oinfo->oi_oa->o_id, req->rq_stripe, 
                       req->rq_oi.oi_oa->o_id, req->rq_idx);
                rc = obd_getattr_async(lov->lov_tgts[req->rq_idx]->ltd_exp,
                                       &req->rq_oi, rqset);
                if (rc) {
                        CERROR("error: getattr objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               oinfo->oi_oa->o_id, req->rq_oi.oi_oa->o_id,
                               req->rq_idx, rc);
                        GOTO(out, rc);
                }
        }

        if (!list_empty(&rqset->set_requests)) {
                LASSERT(rc == 0);
                LASSERT (rqset->set_interpret == NULL);
                rqset->set_interpret = lov_getattr_interpret;
                rqset->set_arg = (void *)lovset;
                RETURN(rc);
        }
out:
        if (rc)
                lovset->set_completes = 0;
        err = lov_fini_getattr_set(lovset);
        RETURN(rc ? rc : err);
}

static int lov_setattr(struct obd_export *exp, struct obd_info *oinfo,
                       struct obd_trans_info *oti)
{
        struct lov_request_set *set;
        struct lov_obd *lov;
        struct list_head *pos;
        struct lov_request *req;
        int err = 0, rc = 0;
        ENTRY;

        LASSERT(oinfo);
        ASSERT_LSM_MAGIC(oinfo->oi_md);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        /* for now, we only expect the following updates here */
        LASSERT(!(oinfo->oi_oa->o_valid & ~(OBD_MD_FLID | OBD_MD_FLTYPE | 
                                            OBD_MD_FLMODE | OBD_MD_FLATIME | 
                                            OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                                            OBD_MD_FLFLAGS | OBD_MD_FLSIZE | 
                                            OBD_MD_FLGROUP | OBD_MD_FLUID | 
                                            OBD_MD_FLGID | OBD_MD_FLFID | 
                                            OBD_MD_FLGENER)));
        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_setattr_set(exp, oinfo, oti, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                rc = obd_setattr(lov->lov_tgts[req->rq_idx]->ltd_exp, 
                                 &req->rq_oi, NULL);
                err = lov_update_setattr_set(set, req, rc);
                if (err) {
                        CERROR("error: setattr objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               set->set_oi->oi_oa->o_id, 
                               req->rq_oi.oi_oa->o_id, req->rq_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        err = lov_fini_setattr_set(set);
        if (!rc)
                rc = err;
        RETURN(rc);
}

static int lov_setattr_interpret(struct ptlrpc_request_set *rqset,
                                 void *data, int rc)
{
        struct lov_request_set *lovset = (struct lov_request_set *)data;
        int err;
        ENTRY;

        if (rc)
                lovset->set_completes = 0;
        err = lov_fini_setattr_set(lovset);
        RETURN(rc ? rc : err);
}

/* If @oti is given, the request goes from MDS and responses from OSTs are not
   needed. Otherwise, a client is waiting for responses. */
static int lov_setattr_async(struct obd_export *exp, struct obd_info *oinfo,
                             struct obd_trans_info *oti,
                             struct ptlrpc_request_set *rqset)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov;
        int rc = 0;
        ENTRY;

        LASSERT(oinfo);
        ASSERT_LSM_MAGIC(oinfo->oi_md);
        if (oinfo->oi_oa->o_valid & OBD_MD_FLCOOKIE) {
                LASSERT(oti);
                LASSERT(oti->oti_logcookies);
        }

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_setattr_set(exp, oinfo, oti, &set);
        if (rc)
                RETURN(rc);

        CDEBUG(D_INFO, "objid "LPX64": %ux%u byte stripes\n",
               oinfo->oi_md->lsm_object_id, oinfo->oi_md->lsm_stripe_count,
               oinfo->oi_md->lsm_stripe_size);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                if (oinfo->oi_oa->o_valid & OBD_MD_FLCOOKIE)
                        oti->oti_logcookies = set->set_cookies + req->rq_stripe;

                CDEBUG(D_INFO, "objid "LPX64"[%d] has subobj "LPX64" at idx "
                       "%u\n", oinfo->oi_oa->o_id, req->rq_stripe,
                       req->rq_oi.oi_oa->o_id, req->rq_idx);

                rc = obd_setattr_async(lov->lov_tgts[req->rq_idx]->ltd_exp,
                                       &req->rq_oi, oti, rqset);
                if (rc) {
                        CERROR("error: setattr objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               set->set_oi->oi_oa->o_id,
                               req->rq_oi.oi_oa->o_id,
                               req->rq_idx, rc);
                        break;
                }
        }

        /* If we are not waiting for responses on async requests, return. */
        if (rc || !rqset || list_empty(&rqset->set_requests)) {
                int err;
                if (rc)
                        set->set_completes = 0;
                err = lov_fini_setattr_set(set);
                RETURN(rc ? rc : err);
        }

        LASSERT(rqset->set_interpret == NULL);
        rqset->set_interpret = lov_setattr_interpret;
        rqset->set_arg = (void *)set;

        RETURN(0);
}

static int lov_punch_interpret(struct ptlrpc_request_set *rqset,
                               void *data, int rc)
{
        struct lov_request_set *lovset = (struct lov_request_set *)data;
        int err;
        ENTRY;

        if (rc)
                lovset->set_completes = 0;
        err = lov_fini_punch_set(lovset);
        RETURN(rc ? rc : err);
}

/* FIXME: maybe we'll just make one node the authoritative attribute node, then
 * we can send this 'punch' to just the authoritative node and the nodes
 * that the punch will affect. */
static int lov_punch(struct obd_export *exp, struct obd_info *oinfo,
                     struct obd_trans_info *oti,
                     struct ptlrpc_request_set *rqset)
{
        struct lov_request_set *set;
        struct lov_obd *lov;
        struct list_head *pos;
        struct lov_request *req;
        int rc = 0;
        ENTRY;

        LASSERT(oinfo);
        ASSERT_LSM_MAGIC(oinfo->oi_md);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_punch_set(exp, oinfo, oti, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                rc = obd_punch(lov->lov_tgts[req->rq_idx]->ltd_exp,
                               &req->rq_oi, NULL, rqset);
                if (rc) {
                        CERROR("error: punch objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n",
                               set->set_oi->oi_oa->o_id,
                               req->rq_oi.oi_oa->o_id, req->rq_idx, rc);
                        break;
                }
        }

        if (rc || list_empty(&rqset->set_requests)) {
                int err;
                err = lov_fini_punch_set(set);
                RETURN(rc ? rc : err);
        }

        LASSERT(rqset->set_interpret == NULL);
        rqset->set_interpret = lov_punch_interpret;
        rqset->set_arg = (void *)set;

        RETURN(0);
}

static int lov_sync(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *lsm, obd_off start, obd_off end)
{
        struct lov_request_set *set;
        struct obd_info oinfo;
        struct lov_obd *lov;
        struct list_head *pos;
        struct lov_request *req;
        int err = 0, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_sync_set(exp, &oinfo, oa, lsm, start, end, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                rc = obd_sync(lov->lov_tgts[req->rq_idx]->ltd_exp, 
                              req->rq_oi.oi_oa, NULL, 
                              req->rq_oi.oi_policy.l_extent.start,
                              req->rq_oi.oi_policy.l_extent.end);
                err = lov_update_common_set(set, req, rc);
                if (err) {
                        CERROR("error: fsync objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n",
                               set->set_oi->oi_oa->o_id,
                               req->rq_oi.oi_oa->o_id, req->rq_idx, rc);
                        if (!rc)
                                rc = err;
                }
        }
        err = lov_fini_sync_set(set);
        if (!rc)
                rc = err;
        RETURN(rc);
}

static int lov_brw_check(struct lov_obd *lov, struct obd_info *lov_oinfo,
                         obd_count oa_bufs, struct brw_page *pga)
{
        struct obd_info oinfo = { { { 0 } } };
        int i, rc = 0;

        oinfo.oi_oa = lov_oinfo->oi_oa;

        /* The caller just wants to know if there's a chance that this
         * I/O can succeed */
        for (i = 0; i < oa_bufs; i++) {
                int stripe = lov_stripe_number(lov_oinfo->oi_md, pga[i].off);
                int ost = lov_oinfo->oi_md->lsm_oinfo[stripe]->loi_ost_idx;
                obd_off start, end;

                if (!lov_stripe_intersects(lov_oinfo->oi_md, i, pga[i].off,
                                           pga[i].off + pga[i].count,
                                           &start, &end))
                        continue;

                if (!lov->lov_tgts[ost] || !lov->lov_tgts[ost]->ltd_active) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost);
                        return -EIO;
                }

                rc = obd_brw(OBD_BRW_CHECK, lov->lov_tgts[ost]->ltd_exp, &oinfo,
                             1, &pga[i], NULL);
                if (rc)
                        break;
        }
        return rc;
}

static int lov_brw(int cmd, struct obd_export *exp, struct obd_info *oinfo,
                   obd_count oa_bufs, struct brw_page *pga,
                   struct obd_trans_info *oti)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int err, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(oinfo->oi_md);

        if (cmd == OBD_BRW_CHECK) {
                rc = lov_brw_check(lov, oinfo, oa_bufs, pga);
                RETURN(rc);
        }

        rc = lov_prep_brw_set(exp, oinfo, oa_bufs, pga, oti, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                struct obd_export *sub_exp;
                struct brw_page *sub_pga;
                req = list_entry(pos, struct lov_request, rq_link);

                sub_exp = lov->lov_tgts[req->rq_idx]->ltd_exp;
                sub_pga = set->set_pga + req->rq_pgaidx;
                rc = obd_brw(cmd, sub_exp, &req->rq_oi, req->rq_oabufs,
                             sub_pga, oti);
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

static int lov_brw_async(int cmd, struct obd_export *exp,
                         struct obd_info *oinfo, obd_count oa_bufs,
                         struct brw_page *pga, struct obd_trans_info *oti,
                         struct ptlrpc_request_set *set)
{
        struct lov_request_set *lovset;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0;
        ENTRY;

        LASSERT(oinfo);
        ASSERT_LSM_MAGIC(oinfo->oi_md);

        if (cmd == OBD_BRW_CHECK) {
                rc = lov_brw_check(lov, oinfo, oa_bufs, pga);
                RETURN(rc);
        }

        rc = lov_prep_brw_set(exp, oinfo, oa_bufs, pga, oti, &lovset);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &lovset->set_list) {
                struct obd_export *sub_exp;
                struct brw_page *sub_pga;
                req = list_entry(pos, struct lov_request, rq_link);

                sub_exp = lov->lov_tgts[req->rq_idx]->ltd_exp;
                sub_pga = lovset->set_pga + req->rq_pgaidx;
                rc = obd_brw_async(cmd, sub_exp, &req->rq_oi, req->rq_oabufs,
                                   sub_pga, oti, set);
                if (rc)
                        GOTO(out, rc);
                lov_update_common_set(lovset, req, rc);
        }
        LASSERT(rc == 0);
        LASSERT(set->set_interpret == NULL);
        LASSERT(set->set_arg == NULL);
        rc = ptlrpc_set_add_cb(set, lov_brw_interpret, lovset);
        if (rc)
                GOTO(out, rc);

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
        oa->o_stripe_idx = lap->lap_stripe;
}

static void lov_ap_update_obdo(void *data, int cmd, struct obdo *oa,
                               obd_valid valid)
{
        struct lov_async_page *lap = LAP_FROM_COOKIE(data);

        lap->lap_caller_ops->ap_update_obdo(lap->lap_caller_data, cmd,oa,valid);
}

static int lov_ap_completion(void *data, int cmd, struct obdo *oa, int rc)
{
        struct lov_async_page *lap = LAP_FROM_COOKIE(data);

        /* in a raid1 regime this would down a count of many ios
         * in flight, onl calling the caller_ops completion when all
         * the raid1 ios are complete */
        rc = lap->lap_caller_ops->ap_completion(lap->lap_caller_data,cmd,oa,rc);
        return rc;
}

static struct obd_async_page_ops lov_async_page_ops = {
        .ap_make_ready =        lov_ap_make_ready,
        .ap_refresh_count =     lov_ap_refresh_count,
        .ap_fill_obdo =         lov_ap_fill_obdo,
        .ap_update_obdo =       lov_ap_update_obdo,
        .ap_completion =        lov_ap_completion,
};

int lov_prep_async_page(struct obd_export *exp, struct lov_stripe_md *lsm,
                           struct lov_oinfo *loi, cfs_page_t *page,
                           obd_off offset, struct obd_async_page_ops *ops,
                           void *data, void **res, int nocache,
                           struct lustre_handle *lockh)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        struct lov_lock_handles *lov_lockh = NULL;
        int rc = 0;
        ENTRY;

        if (!page) {
                int i = 0;
                /* Find an existing osc so we can get it's stupid sizeof(*oap).
                   Only because of this layering limitation will a client 
                   mount with no osts fail */
                while (!lov->lov_tgts || !lov->lov_tgts[i] || 
                       !lov->lov_tgts[i]->ltd_exp) {
                        i++;
                        if (i >= lov->desc.ld_tgt_count) 
                                RETURN(-ENOMEDIUM);
                }
                rc = size_round(sizeof(*lap)) +
                        obd_prep_async_page(lov->lov_tgts[i]->ltd_exp, NULL,
                                            NULL, NULL, 0, NULL, NULL, NULL, 0,
                                            NULL);
                RETURN(rc);
        }
        ASSERT_LSM_MAGIC(lsm);
        LASSERT(loi == NULL);

        lap = *res;
        lap->lap_magic = LOV_AP_MAGIC;
        lap->lap_caller_ops = ops;
        lap->lap_caller_data = data;

        /* for now only raid 0 which passes through */
        lap->lap_stripe = lov_stripe_number(lsm, offset);
        lov_stripe_offset(lsm, offset, lap->lap_stripe, &lap->lap_sub_offset);
        loi = lsm->lsm_oinfo[lap->lap_stripe];

        /* so the callback doesn't need the lsm */
        lap->lap_loi_id = loi->loi_id;

        lap->lap_sub_cookie = (void *)lap + size_round(sizeof(*lap));

        if (lockh) {
                lov_lockh = lov_handle2llh(lockh);
                if (lov_lockh) {
                        lockh = lov_lockh->llh_handles + lap->lap_stripe;
                }
        }

        rc = obd_prep_async_page(lov->lov_tgts[loi->loi_ost_idx]->ltd_exp,
                                 lsm, loi, page, lap->lap_sub_offset,
                                 &lov_async_page_ops, lap,
                                 &lap->lap_sub_cookie, nocache, lockh);
        if (lov_lockh)
                lov_llh_put(lov_lockh);
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

        loi = lsm->lsm_oinfo[lap->lap_stripe];

        rc = obd_queue_async_io(lov->lov_tgts[loi->loi_ost_idx]->ltd_exp, lsm,
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

        loi = lsm->lsm_oinfo[lap->lap_stripe];

        rc = obd_set_async_flags(lov->lov_tgts[loi->loi_ost_idx]->ltd_exp,
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

        loi = lsm->lsm_oinfo[lap->lap_stripe];

        rc = obd_queue_group_io(lov->lov_tgts[loi->loi_ost_idx]->ltd_exp, lsm,
                                loi, oig, lap->lap_sub_cookie, cmd, off, count,
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

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                loi = lsm->lsm_oinfo[i];
                if (!lov->lov_tgts[loi->loi_ost_idx] || 
                    !lov->lov_tgts[loi->loi_ost_idx]->ltd_active) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                err = obd_trigger_group_io(lov->lov_tgts[loi->loi_ost_idx]->ltd_exp,
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

        loi = lsm->lsm_oinfo[lap->lap_stripe];

        rc = obd_teardown_async_page(lov->lov_tgts[loi->loi_ost_idx]->ltd_exp,
                                     lsm, loi, lap->lap_sub_cookie);
        if (rc) {
                CERROR("unable to teardown sub cookie %p: %d\n",
                       lap->lap_sub_cookie, rc);
                RETURN(rc);
        }
        RETURN(rc);
}

static int lov_enqueue_interpret(struct ptlrpc_request_set *rqset,
                                 void *data, int rc)
{
        struct lov_request_set *lovset = (struct lov_request_set *)data;
        ENTRY;
        rc = lov_fini_enqueue_set(lovset, lovset->set_ei->ei_mode, rc, rqset);
        RETURN(rc);
}

static int lov_enqueue(struct obd_export *exp, struct obd_info *oinfo,
                       struct ldlm_enqueue_info *einfo,
                       struct ptlrpc_request_set *rqset)
{
        ldlm_mode_t mode = einfo->ei_mode;
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov;
        ldlm_error_t rc;
        ENTRY;

        LASSERT(oinfo);
        ASSERT_LSM_MAGIC(oinfo->oi_md);
        LASSERT(mode == (mode & -mode));

        /* we should never be asked to replay a lock this way. */
        LASSERT((oinfo->oi_flags & LDLM_FL_REPLAY) == 0);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_enqueue_set(exp, oinfo, einfo, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);

                rc = obd_enqueue(lov->lov_tgts[req->rq_idx]->ltd_exp,
                                 &req->rq_oi, einfo, rqset);
                if (rc != ELDLM_OK)
                        GOTO(out, rc);
        }

        if (rqset && !list_empty(&rqset->set_requests)) {
                LASSERT(rc == 0);
                LASSERT(rqset->set_interpret == NULL);
                rqset->set_interpret = lov_enqueue_interpret;
                rqset->set_arg = (void *)set;
                RETURN(rc);
        }
out:
        rc = lov_fini_enqueue_set(set, mode, rc, rqset);
        RETURN(rc);
}

static int lov_match(struct obd_export *exp, struct lov_stripe_md *lsm,
                     __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                     int *flags, void *data, struct lustre_handle *lockh)
{
        struct lov_request_set *set;
        struct obd_info oinfo;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lustre_handle *lov_lockhp;
        int lov_flags, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);
        LASSERT((*flags & LDLM_FL_TEST_LOCK) || mode == (mode & -mode));

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_match_set(exp, &oinfo, lsm, policy, mode, lockh, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                ldlm_policy_data_t sub_policy;
                req = list_entry(pos, struct lov_request, rq_link);
                lov_lockhp = set->set_lockh->llh_handles + req->rq_stripe;
                LASSERT(lov_lockhp);

                lov_flags = *flags;
                sub_policy.l_extent = req->rq_oi.oi_policy.l_extent;

                rc = obd_match(lov->lov_tgts[req->rq_idx]->ltd_exp,
                               req->rq_oi.oi_md, type, &sub_policy,
                               mode, &lov_flags, data, lov_lockhp);
                rc = lov_update_match_set(set, req, rc);
                if (rc <= 0)
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
        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                struct lov_stripe_md submd;

                loi = lsm->lsm_oinfo[i];
                if (!lov->lov_tgts[loi->loi_ost_idx]) {
                        CDEBUG(D_HA, "lov idx %d NULL \n", loi->loi_ost_idx);
                        continue;
                }
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                rc = obd_change_cbdata(lov->lov_tgts[loi->loi_ost_idx]->ltd_exp,
                                       &submd, it, data);
        }
        RETURN(rc);
}

static int lov_cancel(struct obd_export *exp, struct lov_stripe_md *lsm,
                      __u32 mode, struct lustre_handle *lockh)
{
        struct lov_request_set *set;
        struct obd_info oinfo;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lustre_handle *lov_lockhp;
        ldlm_mode_t this_mode;
        int err = 0, rc = 0;
        ENTRY;

        ASSERT_LSM_MAGIC(lsm);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        LASSERT(lockh);
        lov = &exp->exp_obd->u.lov;
        rc = lov_prep_cancel_set(exp, &oinfo, lsm, mode, lockh, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                req = list_entry(pos, struct lov_request, rq_link);
                lov_lockhp = set->set_lockh->llh_handles + req->rq_stripe;

                /* If this lock was used for a write or truncate, the object
                 * will have been recreated by the OST, cancel the lock
                 * (setting LCK_GROUP incidentally causes immediate cancel). */
                if (OST_LVB_IS_ERR(lsm->lsm_oinfo[req->rq_stripe]->loi_lvb.lvb_blocks) &&
                    (mode == LCK_PW || mode == LCK_CW))
                        this_mode = LCK_GROUP;
                else
                        this_mode = mode;

                rc = obd_cancel(lov->lov_tgts[req->rq_idx]->ltd_exp,
                                req->rq_oi.oi_md, this_mode, lov_lockhp);
                rc = lov_update_common_set(set, req, rc);
                if (rc) {
                        CERROR("error: cancel objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               lsm->lsm_object_id,
                               req->rq_oi.oi_md->lsm_object_id,
                               req->rq_idx, rc);
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

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        if (lsm == NULL) {
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        int err;
                        if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_exp)
                                continue;

                        err = obd_cancel_unused(lov->lov_tgts[i]->ltd_exp, NULL,
                                                flags, opaque);
                        if (!rc)
                                rc = err;
                }
                RETURN(rc);
        }

        ASSERT_LSM_MAGIC(lsm);

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                struct lov_stripe_md submd;
                int err;

                loi = lsm->lsm_oinfo[i];
                if (!lov->lov_tgts[loi->loi_ost_idx]) {
                        CDEBUG(D_HA, "lov idx %d NULL\n", loi->loi_ost_idx);
                        continue;
                }

                if (!lov->lov_tgts[loi->loi_ost_idx]->ltd_active)
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel_unused(lov->lov_tgts[loi->loi_ost_idx]->ltd_exp,
                                        &submd, flags, opaque);
                if (err && lov->lov_tgts[loi->loi_ost_idx]->ltd_active) {
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
        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                struct lov_stripe_md submd;
                int rc = 0;

                loi = lsm->lsm_oinfo[i];
                if (!lov->lov_tgts[loi->loi_ost_idx]) {
                        CDEBUG(D_HA, "lov idx %d NULL\n", loi->loi_ost_idx);
                        continue;
                }

                if (!lov->lov_tgts[loi->loi_ost_idx]->ltd_active)
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                rc = obd_join_lru(lov->lov_tgts[loi->loi_ost_idx]->ltd_exp,
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

static int lov_statfs_interpret(struct ptlrpc_request_set *rqset,
                                void *data, int rc)
{
        struct lov_request_set *lovset = (struct lov_request_set *)data;
        int err;
        ENTRY;

        if (rc)
                lovset->set_completes = 0;

        err = lov_fini_statfs_set(lovset);
        RETURN(rc ? rc : err);
}

static int lov_statfs_async(struct obd_device *obd, struct obd_info *oinfo,
                            __u64 max_age, struct ptlrpc_request_set *rqset)
{
        struct lov_request_set *set;
        struct lov_request *req;
        struct list_head *pos;
        struct lov_obd *lov;
        int rc = 0;
        ENTRY;

        LASSERT(oinfo != NULL);
        LASSERT(oinfo->oi_osfs != NULL);

        lov = &obd->u.lov;
        rc = lov_prep_statfs_set(obd, oinfo, &set);
        if (rc)
                RETURN(rc);

        list_for_each (pos, &set->set_list) {
                struct obd_device *osc_obd;

                req = list_entry(pos, struct lov_request, rq_link);

                osc_obd = class_exp2obd(lov->lov_tgts[req->rq_idx]->ltd_exp);
                rc = obd_statfs_async(osc_obd, &req->rq_oi, max_age, rqset);
                if (rc)
                        break;
        }

        if (rc || list_empty(&rqset->set_requests)) {
                int err;
                if (rc)
                        set->set_completes = 0;
                err = lov_fini_statfs_set(set);
                RETURN(rc ? rc : err);
        }

        LASSERT(rqset->set_interpret == NULL);
        rqset->set_interpret = lov_statfs_interpret;
        rqset->set_arg = (void *)set;
        RETURN(0);
}

static int lov_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                      __u64 max_age, __u32 flags)
{
        struct ptlrpc_request_set *set = NULL;
        struct obd_info oinfo = { { { 0 } } };
        int rc = 0;
        ENTRY;

        /* for obdclass we forbid using obd_statfs_rqset, but prefer using async
         * statfs requests */
        set = ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        oinfo.oi_osfs = osfs;
        oinfo.oi_flags = flags;
        rc = lov_statfs_async(obd, &oinfo, max_age, set);
        if (rc == 0)
                rc = ptlrpc_set_wait(set);
        ptlrpc_set_destroy(set);

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
                struct obd_ioctl_data *data;
                struct lov_desc *desc;
                char *buf = NULL;
                __u32 *genp;

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
                /* the uuid will be empty for deleted OSTs */
                for (i = 0; i < count; i++, uuidp++, genp++) {
                        if (!lov->lov_tgts[i]) 
                                continue;
                        *uuidp = lov->lov_tgts[i]->ltd_uuid;
                        *genp = lov->lov_tgts[i]->ltd_gen;
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
                        if (!lov->lov_tgts[i] || !lov->lov_tgts[i]->ltd_exp)
                                continue;

                        err = obd_iocontrol(cmd, lov->lov_tgts[i]->ltd_exp,
                                            len, karg, uarg);
                        if (err == -ENODATA && cmd == OBD_IOC_POLL_QUOTACHECK) {
                                RETURN(err);
                        } else if (err) {
                                if (lov->lov_tgts[i]->ltd_active) {
                                        CDEBUG(err == -ENOTTY ?
                                               D_IOCTL : D_WARNING,
                                               "iocontrol OSC %s on OST "
                                               "idx %d cmd %x: err = %d\n",
                                               lov_uuid2str(lov, i),
                                               i, cmd, err);
                                        if (!rc)
                                                rc = err;
                                }
                        } else {
                                set = 1;
                        }
                }
                if (!set && !rc)
                        rc = -EIO;
        }
        }

        RETURN(rc);
}

static int lov_get_info(struct obd_export *exp, __u32 keylen,
                        void *key, __u32 *vallen, void *val,
                        struct lov_stripe_md *lsm)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct lov_obd *lov = &obddev->u.lov;
        int i, rc;
        ENTRY;

        if (!vallen || !val)
                RETURN(-EFAULT);

        lov_getref(obddev);

        if (KEY_IS(KEY_LOCK_TO_STRIPE)) {
                struct {
                        char name[16];
                        struct ldlm_lock *lock;
                } *data = key;
                struct ldlm_res_id *res_id = &data->lock->l_resource->lr_name;
                struct lov_oinfo *loi;
                __u32 *stripe = val;

                if (*vallen < sizeof(*stripe))
                        GOTO(out, rc = -EFAULT);
                *vallen = sizeof(*stripe);

                /* XXX This is another one of those bits that will need to
                 * change if we ever actually support nested LOVs.  It uses
                 * the lock's export to find out which stripe it is. */
                /* XXX - it's assumed all the locks for deleted OSTs have
                 * been cancelled. Also, the export for deleted OSTs will
                 * be NULL and won't match the lock's export. */
                for (i = 0; i < lsm->lsm_stripe_count; i++) {
                        loi = lsm->lsm_oinfo[i];
                        if (!lov->lov_tgts[loi->loi_ost_idx])
                                continue;
                        if (lov->lov_tgts[loi->loi_ost_idx]->ltd_exp ==
                            data->lock->l_conn_export &&
                            loi->loi_id == res_id->name[0] &&
                            loi->loi_gr == res_id->name[1]) {
                                *stripe = i;
                                GOTO(out, rc = 0);
                        }
                }
                LDLM_ERROR(data->lock, "lock on inode without such object");
                dump_lsm(D_ERROR, lsm);
                GOTO(out, rc = -ENXIO);
        } else if (KEY_IS(KEY_LAST_ID)) {
                struct obd_id_info *info = val;
                __u32 size = sizeof(obd_id);
                struct lov_tgt_desc *tgt;

                LASSERT(*vallen == sizeof(struct obd_id_info));
                tgt = lov->lov_tgts[info->idx];

                if (!tgt || !tgt->ltd_active)
                        GOTO(out, rc = -ESRCH);

                rc = obd_get_info(tgt->ltd_exp, keylen, key, &size, info->data, NULL);
                GOTO(out, rc = 0);
        } else if (KEY_IS(KEY_LOVDESC)) {
                struct lov_desc *desc_ret = val;
                *desc_ret = lov->desc;

                GOTO(out, rc = 0);
        } else if (KEY_IS(KEY_LOV_IDX)) {
                struct lov_tgt_desc *tgt;

                for(i = 0; i < lov->desc.ld_tgt_count; i++) {
                        tgt = lov->lov_tgts[i];
                        if (tgt && obd_uuid_equals(val, &tgt->ltd_uuid))
                                GOTO(out, rc = i);
                }
        }

        rc = -EINVAL;
out:
        lov_putref(obddev);
        RETURN(rc);
}

static int lov_set_info_async(struct obd_export *exp, obd_count keylen,
                              void *key, obd_count vallen, void *val,
                              struct ptlrpc_request_set *set)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct lov_obd *lov = &obddev->u.lov;
        obd_count count;
        int i, rc = 0, err, incr = 0, check_uuid = 0, do_inactive = 0;
        int no_set = !set;
        unsigned next_id = 0;
        struct lov_tgt_desc *tgt;
        void *data;
        ENTRY;

        if (no_set) {
                set = ptlrpc_prep_set();
                if (!set)
                        RETURN(-ENOMEM);
        }

        lov_getref(obddev);
        count = lov->desc.ld_tgt_count;

        if (KEY_IS(KEY_NEXT_ID)) {
                count = vallen / sizeof(struct obd_id_info);
                vallen = sizeof(obd_id);
                incr = sizeof(struct obd_id_info);
                do_inactive = 1;
                next_id = 1;
        } else if (KEY_IS(KEY_CHECKSUM)) {
                do_inactive = 1;
        } else if (KEY_IS(KEY_MDS_CONN) || KEY_IS(KEY_UNLINKED)) {
                check_uuid = val ? 1 : 0;
        } else if (KEY_IS(KEY_EVICT_BY_NID)) {
                /* use defaults:
                do_inactive = incr = 0;
                 */
        }

        for (i = 0; i < count; i++, val = (char *)val + incr) {
                if (next_id) {
                        tgt = lov->lov_tgts[((struct obd_id_info*)val)->idx];
                        data = ((struct obd_id_info*)val)->data;
                } else {
                        tgt = lov->lov_tgts[i];
                        data = val;
                }
                /* OST was disconnected */
                if (!tgt || !tgt->ltd_exp)
                        continue;

                /* OST is inactive and we don't want inactive OSCs */
                if (!tgt->ltd_active && !do_inactive)
                        continue;

                /* Only want a specific OSC */
                if (check_uuid &&
                    !obd_uuid_equals(val, &tgt->ltd_uuid))
                        continue;

                err = obd_set_info_async(tgt->ltd_exp,
                                         keylen, key, vallen, data, set);
                if (!rc)
                        rc = err;
        }
        lov_putref(obddev);
        if (no_set) {
                err = ptlrpc_set_wait(set);
                if (!rc)
                        rc = err;
                ptlrpc_set_destroy(set);
        }
        RETURN(rc);
}

static int lov_checkmd(struct obd_export *exp, struct obd_export *md_exp,
                       struct lov_stripe_md *lsm)
{
        int rc;
        ENTRY;

        if (!lsm)
                RETURN(0);
        LASSERT(md_exp);
        LASSERT(lsm_op_find(lsm->lsm_magic) != NULL);
        rc = lsm_op_find(lsm->lsm_magic)->lsm_revalidate(lsm, md_exp->exp_obd);

        RETURN(rc);
}

int lov_test_and_clear_async_rc(struct lov_stripe_md *lsm)
{
        struct lov_oinfo *loi;
        int i, rc = 0;
        ENTRY;

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                loi = lsm->lsm_oinfo[i];
                if (loi->loi_ar.ar_rc && !rc)
                        rc = loi->loi_ar.ar_rc;
                loi->loi_ar.ar_rc = 0;
        }
        RETURN(rc);
}
EXPORT_SYMBOL(lov_test_and_clear_async_rc);


static int lov_extent_calc(struct obd_export *exp, struct lov_stripe_md *lsm,
                           int cmd, __u64 *offset)
{
        __u64 start;
        __u32 ssize  = lsm->lsm_stripe_size;

        start = *offset;
        do_div(start, ssize);
        start = start * ssize;

        CDEBUG(D_DLMTRACE, "offset "LPU64", stripe %u, start "LPU64
               ", end "LPU64"\n", *offset, ssize, start, start + ssize - 1);
        if (cmd == OBD_CALC_STRIPE_END) {
                *offset = start + ssize - 1;
        } else if (cmd == OBD_CALC_STRIPE_START) {
                *offset = start;
        } else {
                LBUG();
        }

        RETURN(0);
}

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
                        spin_lock(&imp->imp_lock);
                        queues[i].generation = imp->imp_generation;
                        spin_unlock(&imp->imp_lock);
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
        LASSERT(md->lsm_lock_owner != cfs_current());
        spin_lock(&md->lsm_lock);
        LASSERT(md->lsm_lock_owner == NULL);
        md->lsm_lock_owner = cfs_current();
}
EXPORT_SYMBOL(lov_stripe_lock);

void lov_stripe_unlock(struct lov_stripe_md *md)
{
        LASSERT(md->lsm_lock_owner == cfs_current());
        md->lsm_lock_owner = NULL;
        spin_unlock(&md->lsm_lock);
}
EXPORT_SYMBOL(lov_stripe_unlock);

static int lov_reget_short_lock(struct obd_export *exp,
                                struct lov_stripe_md *lsm,
                                void **res, int rw,
                                obd_off start, obd_off end,
                                void **cookie)
{
        struct lov_async_page *l = *res;
        obd_off stripe_start, stripe_end = start;

        ENTRY;

        /* ensure we don't cross stripe boundaries */
        lov_extent_calc(exp, lsm, OBD_CALC_STRIPE_END, &stripe_end);
        if (stripe_end <= end)
                RETURN(0);

        /* map the region limits to the object limits */
        lov_stripe_offset(lsm, start, l->lap_stripe, &stripe_start);
        lov_stripe_offset(lsm, end, l->lap_stripe, &stripe_end);

        RETURN(obd_reget_short_lock(exp->exp_obd->u.lov.lov_tgts[lsm->
                                    lsm_oinfo[l->lap_stripe]->loi_ost_idx]->
                                    ltd_exp, NULL, &l->lap_sub_cookie,
                                    rw, stripe_start, stripe_end, cookie));
}

static int lov_release_short_lock(struct obd_export *exp,
                                  struct lov_stripe_md *lsm, obd_off end,
                                  void *cookie, int rw)
{
        int stripe;

        ENTRY;

        stripe = lov_stripe_number(lsm, end);

        RETURN(obd_release_short_lock(exp->exp_obd->u.lov.lov_tgts[lsm->
                                      lsm_oinfo[stripe]->loi_ost_idx]->
                                      ltd_exp, NULL, end, cookie, rw));
}

struct obd_ops lov_obd_ops = {
        .o_owner               = THIS_MODULE,
        .o_setup               = lov_setup,
        .o_precleanup          = lov_precleanup,
        .o_cleanup             = lov_cleanup,
        .o_process_config      = lov_process_config,
        .o_connect             = lov_connect,
        .o_disconnect          = lov_disconnect,
        .o_statfs              = lov_statfs,
        .o_statfs_async        = lov_statfs_async,
        .o_packmd              = lov_packmd,
        .o_unpackmd            = lov_unpackmd,
        .o_checkmd             = lov_checkmd,
        .o_create              = lov_create,
        .o_destroy             = lov_destroy,
        .o_getattr             = lov_getattr,
        .o_getattr_async       = lov_getattr_async,
        .o_setattr             = lov_setattr,
        .o_setattr_async       = lov_setattr_async,
        .o_brw                 = lov_brw,
        .o_brw_async           = lov_brw_async,
        .o_prep_async_page     = lov_prep_async_page,
        .o_reget_short_lock    = lov_reget_short_lock,
        .o_release_short_lock  = lov_release_short_lock,
        .o_queue_async_io      = lov_queue_async_io,
        .o_set_async_flags     = lov_set_async_flags,
        .o_queue_group_io      = lov_queue_group_io,
        .o_trigger_group_io    = lov_trigger_group_io,
        .o_teardown_async_page = lov_teardown_async_page,
        .o_merge_lvb           = lov_merge_lvb,
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
        .o_set_info_async      = lov_set_info_async,
        .o_extent_calc         = lov_extent_calc,
        .o_llog_init           = lov_llog_init,
        .o_llog_finish         = lov_llog_finish,
        .o_notify              = lov_notify,
        .o_register_page_removal_cb = lov_register_page_removal_cb,
        .o_unregister_page_removal_cb = lov_unregister_page_removal_cb,
        .o_register_lock_cancel_cb = lov_register_lock_cancel_cb,
        .o_unregister_lock_cancel_cb = lov_unregister_lock_cancel_cb,
};

static quota_interface_t *quota_interface;
extern quota_interface_t lov_quota_interface;

cfs_mem_cache_t *lov_oinfo_slab;

int __init lov_init(void)
{
        struct lprocfs_static_vars lvars = { 0 };
        int rc, rc2;
        ENTRY;

        lov_oinfo_slab = cfs_mem_cache_create("lov_oinfo",
                                              sizeof(struct lov_oinfo), 
                                              0, SLAB_HWCACHE_ALIGN);
        if (lov_oinfo_slab == NULL)
                return -ENOMEM;
        lprocfs_lov_init_vars(&lvars);

        request_module("lquota");
        quota_interface = PORTAL_SYMBOL_GET(lov_quota_interface);
        init_obd_quota_ops(quota_interface, &lov_obd_ops);

        rc = class_register_type(&lov_obd_ops, lvars.module_vars,
                                 LUSTRE_LOV_NAME);
        if (rc) {
                if (quota_interface)
                        PORTAL_SYMBOL_PUT(lov_quota_interface);
                rc2 = cfs_mem_cache_destroy(lov_oinfo_slab);
                LASSERT(rc2 == 0);
        }

        RETURN(rc);
}

#ifdef __KERNEL__
static void /*__exit*/ lov_exit(void)
{
        int rc;

        if (quota_interface)
                PORTAL_SYMBOL_PUT(lov_quota_interface);

        class_unregister_type(LUSTRE_LOV_NAME);
        rc = cfs_mem_cache_destroy(lov_oinfo_slab);
        LASSERT(rc == 0);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Logical Object Volume OBD driver");
MODULE_LICENSE("GPL");

cfs_module(lov, LUSTRE_VERSION_STRING, lov_init, lov_exit);
#endif
