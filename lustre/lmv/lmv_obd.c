/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LMV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <asm/div64.h>
#include <linux/seq_file.h>
#else
#include <liblustre.h>
#endif
#include <linux/ext2_fs.h>

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_ost.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd_lmv.h>
#include "lmv_internal.h"

static void lmv_activate_target(struct lmv_obd *lmv,
                                struct lmv_tgt_desc *tgt,
                                int activate)
{
        if (tgt->active == activate)
                return;
        
        tgt->active = activate;
        lmv->desc.ld_active_tgt_count += (activate ? 1 : -1);
}

/* Error codes:
 *
 *  -EINVAL  : UUID can't be found in the LMV's target list
 *  -ENOTCONN: The UUID is found, but the target connection is bad (!)
 *  -EBADF   : The UUID is found, but the OBD of the wrong type (!)
 */
static int lmv_set_mdc_active(struct lmv_obd *lmv, struct obd_uuid *uuid,
                              int activate)
{
        struct obd_device *obd;
        struct lmv_tgt_desc *tgt;
        int i, rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "Searching in lmv %p for uuid %s (activate=%d)\n",
               lmv, uuid->uuid, activate);

        spin_lock(&lmv->lmv_lock);
        for (i = 0, tgt = lmv->tgts; i < lmv->desc.ld_tgt_count; i++, tgt++) {
                if (tgt->ltd_exp == NULL)
                        continue;

                CDEBUG(D_INFO, "lmv idx %d is %s conn "LPX64"\n",
                       i, tgt->uuid.uuid, tgt->ltd_exp->exp_handle.h_cookie);

                if (strncmp(uuid->uuid, tgt->uuid.uuid, sizeof uuid->uuid) == 0)
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

        if (tgt->active == activate) {
                CDEBUG(D_INFO, "OBD %p already %sactive!\n", obd,
                       activate ? "" : "in");
                GOTO(out_lmv_lock, rc);
        }

        CDEBUG(D_INFO, "Marking OBD %p %sactive\n",
               obd, activate ? "" : "in");

        lmv_activate_target(lmv, tgt, activate);

        EXIT;
        
 out_lmv_lock:
        spin_unlock(&lmv->lmv_lock);
        return rc;
}

static int lmv_notify(struct obd_device *obd, struct obd_device *watched,
                      int active, void *data)
{
        int rc;
        struct obd_uuid *uuid;

        if (strcmp(watched->obd_type->typ_name, LUSTRE_MDC_NAME)) {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name,
                       watched->obd_name);
                return -EINVAL;
        }
        uuid = &watched->u.cli.cl_import->imp_target_uuid;

        /* Set MDC as active before notifying the observer, so the observer can
         * use the MDC normally.
         */
        rc = lmv_set_mdc_active(&obd->u.lmv, uuid, active);
        if (rc) {
                CERROR("%sactivation of %s failed: %d\n",
                       active ? "" : "de", uuid->uuid, rc);
                RETURN(rc);
        }

        if (obd->obd_observer)
                /* Pass the notification up the chain. */
                rc = obd_notify(obd->obd_observer, watched, active, data);

        RETURN(rc);
}

int lmv_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        lprocfs_init_vars(lmv, &lvars);
        rc = lprocfs_obd_attach(dev, lvars.obd_vars);
        if (rc == 0) {
#ifdef __KERNEL__
                struct proc_dir_entry *entry;
                
                entry = create_proc_entry("target_obd_status", 0444, 
                                           dev->obd_proc_entry);
                if (entry == NULL)
                        RETURN(-ENOMEM);
                entry->proc_fops = &lmv_proc_target_fops; 
                entry->data = dev;
#endif
       }
        RETURN (rc);
}

int lmv_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

/* this is fake connect function. Its purpose is to initialize lmv and say
 * caller that everything is okay. Real connection will be performed later. */
static int lmv_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, unsigned long flags)
{
#ifdef __KERNEL__
        struct proc_dir_entry *lmv_proc_dir;
#endif
        struct lmv_obd *lmv = &obd->u.lmv;
        struct obd_export *exp;
        int rc = 0;
        ENTRY;

        rc = class_connect(conn, obd, cluuid);
        if (rc) {
                CERROR("class_connection() returned %d\n", rc);
                RETURN(rc);
        }

        exp = class_conn2export(conn);
        
        /* we don't want to actually do the underlying connections more than
         * once, so keep track. */
        lmv->refcount++;
        if (lmv->refcount > 1) {
                class_export_put(exp);
                RETURN(0);
        }

        lmv->exp = exp;
        lmv->connected = 0;
        lmv->cluuid = *cluuid;
        lmv->connect_flags = flags;
        sema_init(&lmv->init_sem, 1);

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
         * all real clients shouls perform actual connection rightaway, because
         * it is possible, that LMV will not have opportunity to connect
         * targets, as MDC stuff will bit called directly, for instance while
         * reading ../mdc/../kbytesfree procfs file, etc.
         */
        if (flags & OBD_OPT_REAL_CLIENT)
                rc = lmv_check_connect(obd);

#ifdef __KERNEL__
        if (lmv_proc_dir)
                lprocfs_remove(lmv_proc_dir);
#endif

        RETURN(rc);
}

void lmv_set_timeouts(struct obd_device *obd)
{
        struct lmv_tgt_desc *tgts;
        struct lmv_obd *lmv;
        int i;

        lmv = &obd->u.lmv;
        if (lmv->server_timeout == 0)
                return;

        if (lmv->connected == 0)
                return;

        for (i = 0, tgts = lmv->tgts; i < lmv->desc.ld_tgt_count; i++, tgts++) {
                if (tgts->ltd_exp == NULL)
                        continue;
                
                obd_set_info(tgts->ltd_exp, strlen("inter_mds"),
                             "inter_mds", 0, NULL);
        }
}

#define MAX_STRING_SIZE 128

/* performs a check if passed obd is connected. If no - connect it. */
int lmv_check_connect(struct obd_device *obd)
{
#ifdef __KERNEL__
        struct proc_dir_entry *lmv_proc_dir;
#endif
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lmv_tgt_desc *tgts;
        struct obd_uuid *cluuid;
        struct obd_export *exp;
        int rc, rc2, i;

        if (lmv->connected)
                return 0;
        
        down(&lmv->init_sem);
        if (lmv->connected) {
                up(&lmv->init_sem);
                return 0;
        }

        cluuid = &lmv->cluuid;
        exp = lmv->exp;
        
        CDEBUG(D_OTHER, "time to connect %s to %s\n",
               cluuid->uuid, obd->obd_name);

        for (i = 0, tgts = lmv->tgts; i < lmv->desc.ld_tgt_count; i++, tgts++) {
                struct obd_device *tgt_obd;
                struct lustre_handle conn = {0, };
                struct obd_uuid lmv_mdc_uuid = { "LMV_MDC_UUID" };

                LASSERT(tgts != NULL);

                tgt_obd = class_find_client_obd(&tgts->uuid, LUSTRE_MDC_NAME, 
                                                &obd->obd_uuid);
                if (!tgt_obd) {
                        CERROR("Target %s not attached\n", tgts->uuid.uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }

                /* for MDS: don't connect to yourself */
                if (obd_uuid_equals(&tgts->uuid, cluuid)) {
                        CDEBUG(D_OTHER, "don't connect back to %s\n",
                               cluuid->uuid);
                        tgts->ltd_exp = NULL;
                        continue;
                }

                CDEBUG(D_OTHER, "connect to %s(%s) - %s, %s FOR %s\n",
                        tgt_obd->obd_name, tgt_obd->obd_uuid.uuid,
                        tgts->uuid.uuid, obd->obd_uuid.uuid,
                        cluuid->uuid);

                if (!tgt_obd->obd_set_up) {
                        CERROR("Target %s not set up\n", tgts->uuid.uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }
                
                rc = obd_connect(&conn, tgt_obd, &lmv_mdc_uuid,
                                 lmv->connect_flags);
                if (rc) {
                        CERROR("Target %s connect error %d\n",
                                tgts->uuid.uuid, rc);
                        GOTO(out_disc, rc);
                }
                tgts->ltd_exp = class_conn2export(&conn);

                obd_init_ea_size(tgts->ltd_exp, lmv->max_easize,
                                 lmv->max_cookiesize);

                rc = obd_register_observer(tgt_obd, obd);
                if (rc) {
                        CERROR("Target %s register_observer error %d\n",
                               tgts->uuid.uuid, rc);
                        obd_disconnect(tgts->ltd_exp, 0);
                        GOTO(out_disc, rc);
                }

                lmv->desc.ld_active_tgt_count++;
                tgts->active = 1;

                CDEBUG(D_OTHER, "connected to %s(%s) successfully (%d)\n",
                        tgt_obd->obd_name, tgt_obd->obd_uuid.uuid,
                        atomic_read(&obd->obd_refcount));

#ifdef __KERNEL__
                lmv_proc_dir = lprocfs_srch(obd->obd_proc_entry, "target_obds");
                if (lmv_proc_dir) {
                        struct obd_device *mdc_obd = class_conn2obd(&conn);
                        struct proc_dir_entry *mdc_symlink;
                        char name[MAX_STRING_SIZE + 1];

                        LASSERT(mdc_obd != NULL);
                        LASSERT(mdc_obd->obd_type != NULL);
                        LASSERT(mdc_obd->obd_type->typ_name != NULL);
                        name[MAX_STRING_SIZE] = '\0';
                        snprintf(name, MAX_STRING_SIZE, "../../../%s/%s",
                                 mdc_obd->obd_type->typ_name,
                                 mdc_obd->obd_name);
                        mdc_symlink = proc_symlink(mdc_obd->obd_name,
                                                   lmv_proc_dir, name);
                        if (mdc_symlink == NULL) {
                                CERROR("could not register LMV target "
                                       "/proc/fs/lustre/%s/%s/target_obds/%s.",
                                       obd->obd_type->typ_name, obd->obd_name,
                                       mdc_obd->obd_name);
                                lprocfs_remove(lmv_proc_dir);
                                lmv_proc_dir = NULL;
                        }
                }
#endif
        }

        lmv_set_timeouts(obd);
        class_export_put(exp);
        lmv->connected = 1;
        up(&lmv->init_sem);
        return 0;

 out_disc:
        while (i-- > 0) {
                struct obd_uuid uuid;
                --tgts;
                --lmv->desc.ld_active_tgt_count;
                tgts->active = 0;
                /* save for CERROR below; (we know it's terminated) */
                uuid = tgts->uuid;
                rc2 = obd_disconnect(tgts->ltd_exp, 0);
                if (rc2)
                        CERROR("error: LMV target %s disconnect on MDC idx %d: "
                               "error %d\n", uuid.uuid, i, rc2);
        }
        class_disconnect(exp, 0);
        up(&lmv->init_sem);
        RETURN (rc);
}

static int lmv_disconnect(struct obd_export *exp, int flags)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lmv_obd *lmv = &obd->u.lmv;

#ifdef __KERNEL__
        struct proc_dir_entry *lmv_proc_dir;
#endif
        int rc, i;
        ENTRY;

        if (!lmv->tgts)
                goto out_local;

        /* Only disconnect the underlying layers on the final disconnect. */
        lmv->refcount--;
        if (lmv->refcount != 0)
                goto out_local;

#ifdef __KERNEL__
        lmv_proc_dir = lprocfs_srch(obd->obd_proc_entry, "target_obds");
#endif

        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                struct obd_device *mdc_obd; 
                
                if (lmv->tgts[i].ltd_exp == NULL)
                        continue;

                mdc_obd = class_exp2obd(lmv->tgts[i].ltd_exp);

#ifdef __KERNEL__
                if (lmv_proc_dir) {
                        struct proc_dir_entry *mdc_symlink;

                        mdc_symlink = lprocfs_srch(lmv_proc_dir, mdc_obd->obd_name);
                        if (mdc_symlink) {
                                lprocfs_remove(mdc_symlink);
                        } else {
                                CERROR("/proc/fs/lustre/%s/%s/target_obds/%s missing\n",
                                       obd->obd_type->typ_name, obd->obd_name,
                                       mdc_obd->obd_name);
                        }
                }
#endif
                if (obd->obd_no_recov) {
                        if (mdc_obd)
                                mdc_obd->obd_no_recov = 1;
                }
                CDEBUG(D_OTHER, "disconnected from %s(%s) successfully\n",
                        lmv->tgts[i].ltd_exp->exp_obd->obd_name,
                        lmv->tgts[i].ltd_exp->exp_obd->obd_uuid.uuid);

                obd_register_observer(lmv->tgts[i].ltd_exp->exp_obd, NULL);
                rc = obd_disconnect(lmv->tgts[i].ltd_exp, flags);
                if (rc) {
                        if (lmv->tgts[i].active) {
                                CERROR("Target %s disconnect error %d\n",
                                       lmv->tgts[i].uuid.uuid, rc);
                        }
                        rc = 0;
                }
                
                lmv_activate_target(lmv, &lmv->tgts[i], 0);
                lmv->tgts[i].ltd_exp = NULL;
        }

#ifdef __KERNEL__
        if (lmv_proc_dir) {
                lprocfs_remove(lmv_proc_dir);
        } else {
                CERROR("/proc/fs/lustre/%s/%s/target_obds missing\n",
                       obd->obd_type->typ_name, obd->obd_name);
        }
#endif

out_local:
        /* this is the case when no real connection is established by
         * lmv_check_connect(). */
        if (!lmv->connected)
                class_export_put(exp);
        rc = class_disconnect(exp, 0);
        if (lmv->refcount == 0)
                lmv->connected = 0;
        RETURN(rc);
}

static int lmv_iocontrol(unsigned int cmd, struct obd_export *exp,
                         int len, void *karg, void *uarg)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct lmv_obd *lmv = &obddev->u.lmv;
        int i, rc = 0, set = 0;

        ENTRY;

        if (lmv->desc.ld_tgt_count == 0)
                RETURN(-ENOTTY);
        
        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                int err;

                if (lmv->tgts[i].ltd_exp == NULL)
                        continue;

                err = obd_iocontrol(cmd, lmv->tgts[i].ltd_exp, len, karg, uarg);
                if (err) {
                        if (lmv->tgts[i].active) {
                                CERROR("error: iocontrol MDC %s on MDT"
                                       "idx %d: err = %d\n",
                                       lmv->tgts[i].uuid.uuid, i, err);
                                if (!rc)
                                        rc = err;
                        }
                } else
                        set = 1;
        }
        if (!set && !rc)
                rc = -EIO;

        RETURN(rc);
}

static int lmv_setup(struct obd_device *obd, obd_count len, void *buf)
{
        int i, rc = 0;
        struct lmv_desc *desc;
        struct obd_uuid *uuids;
        struct lmv_tgt_desc *tgts;
        struct obd_device *tgt_obd;
        struct lustre_cfg *lcfg = buf;
        struct lmv_obd *lmv = &obd->u.lmv;
        ENTRY;

        if (lcfg->lcfg_inllen1 < 1) {
                CERROR("LMV setup requires a descriptor\n");
                RETURN(-EINVAL);
        }

        if (lcfg->lcfg_inllen2 < 1) {
                CERROR("LMV setup requires an OST UUID list\n");
                RETURN(-EINVAL);
        }

        desc = (struct lmv_desc *)lcfg->lcfg_inlbuf1;
        if (sizeof(*desc) > lcfg->lcfg_inllen1) {
                CERROR("descriptor size wrong: %d > %d\n",
                       (int)sizeof(*desc), lcfg->lcfg_inllen1);
                RETURN(-EINVAL);
        }

        uuids = (struct obd_uuid *)lcfg->lcfg_inlbuf2;
        if (sizeof(*uuids) * desc->ld_tgt_count != lcfg->lcfg_inllen2) {
                CERROR("UUID array size wrong: %u * %u != %u\n",
                       sizeof(*uuids), desc->ld_tgt_count, lcfg->lcfg_inllen2);
                RETURN(-EINVAL);
        }

        lmv->tgts_size = sizeof(struct lmv_tgt_desc) * desc->ld_tgt_count;
        OBD_ALLOC(lmv->tgts, lmv->tgts_size);
        if (lmv->tgts == NULL) {
                CERROR("Out of memory\n");
                RETURN(-ENOMEM);
        }

        lmv->desc = *desc;
        spin_lock_init(&lmv->lmv_lock);
        
        for (i = 0, tgts = lmv->tgts; i < desc->ld_tgt_count; i++, tgts++)
                tgts->uuid = uuids[i];
        
        lmv->max_cookiesize = 0;

        lmv->max_easize = sizeof(struct lustre_id) *
                desc->ld_tgt_count + sizeof(struct mea);
        
        rc = lmv_setup_mgr(obd);
        if (rc) {
                CERROR("Can't setup LMV object manager, "
                       "error %d.\n", rc);
                OBD_FREE(lmv->tgts, lmv->tgts_size);
        }

        tgt_obd = class_find_client_obd(&lmv->tgts->uuid, LUSTRE_MDC_NAME, 
                                        &obd->obd_uuid);
        if (!tgt_obd) {
                CERROR("Target %s not attached\n", lmv->tgts->uuid.uuid);
                RETURN(-EINVAL);
        }

        RETURN(rc);
}

static int lmv_cleanup(struct obd_device *obd, int flags) 
{
        struct lmv_obd *lmv = &obd->u.lmv;
        ENTRY;

        lmv_cleanup_mgr(obd);
        OBD_FREE(lmv->tgts, lmv->tgts_size);
        
        RETURN(0);
}

static int lmv_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                      unsigned long max_age)
{
        struct lmv_obd *lmv = &obd->u.lmv;
        struct obd_statfs temp;
        int rc = 0, i;
        ENTRY;
        
        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);
                
        for (i = 0; i < lmv->desc.ld_tgt_count; i++) {
                if (lmv->tgts[i].ltd_exp == NULL) {
                        CWARN("%s: NULL export for %d\n", obd->obd_name, i);
                        continue;
                }

                rc = obd_statfs(lmv->tgts[i].ltd_exp->exp_obd, &temp, max_age);
                if (rc) {
                        CERROR("can't stat MDS #%d (%s)\n", i,
                               lmv->tgts[i].ltd_exp->exp_obd->obd_name);
                        RETURN(rc);
                }
                if (i == 0) {
                        memcpy(osfs, &temp, sizeof(temp));
                } else {
                        osfs->os_bavail += temp.os_bavail;
                        osfs->os_blocks += temp.os_blocks;
                        osfs->os_ffree += temp.os_ffree;
                        osfs->os_files += temp.os_files;
                }
        }
        RETURN(rc);
}

static int lmv_getstatus(struct obd_export *exp, struct lustre_id *id)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        rc = md_getstatus(lmv->tgts[0].ltd_exp, id);
        id_group(id) = 0;
        
        RETURN(rc);
}

static int lmv_getattr(struct obd_export *exp, struct lustre_id *id,
                       unsigned long valid, unsigned int ea_size,
                       struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc, i = id_group(id);
        struct lmv_obj *obj;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        LASSERT(i < lmv->desc.ld_tgt_count);

        rc = md_getattr(lmv->tgts[i].ltd_exp, id, valid,
                        ea_size, request);
        if (rc)
                RETURN(rc);
        
        obj = lmv_grab_obj(obd, id);
        
        CDEBUG(D_OTHER, "GETATTR for "DLID4" %s\n",
               OLID4(id), obj ? "(splitted)" : "");

        /* if object is splitted, then we loop over all the slaves and gather
         * size attribute. In ideal world we would have to gather also mds field
         * from all slaves, as object is spread over the cluster and this is
         * definitely interesting information and it is not good to loss it,
         * but...*/
        if (obj) {
                struct mds_body *body;

                if (*request == NULL) {
                        lmv_put_obj(obj);
                        RETURN(rc);
                }
                        
                body = lustre_msg_buf((*request)->rq_repmsg, 0,
                                      sizeof(*body));
                LASSERT(body != NULL);

                lmv_lock_obj(obj);
        
                for (i = 0; i < obj->objcount; i++) {

                        if (lmv->tgts[i].ltd_exp == NULL) {
                                CWARN("%s: NULL export for %d\n",
                                      obd->obd_name, i);
                                continue;
                        }

                        /* skip master obj. */
                        if (id_equal_fid(&obj->id, &obj->objs[i].id))
                                continue;
                        
                        body->size += obj->objs[i].size;
                }

                lmv_unlock_obj(obj);
                lmv_put_obj(obj);
        }
        
        RETURN(rc);
}

static int lmv_change_cbdata(struct obd_export *exp,
                             struct lustre_id *id, 
                             ldlm_iterator_t it,
                             void *data)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc = 0;
        ENTRY;
        
        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);
        
        CDEBUG(D_OTHER, "CBDATA for "DLID4"\n", OLID4(id));
        LASSERT(id_group(id) < lmv->desc.ld_tgt_count);

        rc = md_change_cbdata(lmv->tgts[id_group(id)].ltd_exp,
                              id, it, data);
        
        RETURN(rc);
}

static int lmv_change_cbdata_name(struct obd_export *exp,
                                  struct lustre_id *pid,
                                  char *name, int len,
                                  struct lustre_id *cid,
                                  ldlm_iterator_t it,
                                  void *data)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lustre_id rcid = *cid;
        struct lmv_obj *obj;
        int rc = 0, mds;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        LASSERT(id_group(pid) < lmv->desc.ld_tgt_count);
        LASSERT(id_group(cid) < lmv->desc.ld_tgt_count);
        
        CDEBUG(D_OTHER, "CBDATA for "DLID4":%*s -> "DLID4"\n",
               OLID4(pid), len, name, OLID4(cid));

        /* this is default mds for directory name belongs to. */
        mds = id_group(pid);
        obj = lmv_grab_obj(obd, pid);
        if (obj) {
                /* directory is splitted. look for right mds for this name. */
                mds = raw_name2idx(obj->hashtype, obj->objcount, name, len);
                rcid = obj->objs[mds].id;
		mds = id_group(&rcid);
                lmv_put_obj(obj);
        }
        rc = md_change_cbdata(lmv->tgts[mds].ltd_exp, &rcid, it, data);
        RETURN(rc);
}

static int lmv_valid_attrs(struct obd_export *exp, struct lustre_id *id) 
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc = 0;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        CDEBUG(D_OTHER, "validate "DLID4"\n", OLID4(id));
        LASSERT(id_group(id) < lmv->desc.ld_tgt_count);
        rc = md_valid_attrs(lmv->tgts[id_group(id)].ltd_exp, id);
        RETURN(rc);
}

int lmv_close(struct obd_export *exp, struct obdo *obdo,
              struct obd_client_handle *och,
              struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc, i = obdo->o_mds;
        ENTRY;
        
        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        LASSERT(i < lmv->desc.ld_tgt_count);
        CDEBUG(D_OTHER, "CLOSE %lu/%lu/%lu\n", (unsigned long)obdo->o_mds,
               (unsigned long)obdo->o_id, (unsigned long)obdo->o_generation);
        rc = md_close(lmv->tgts[i].ltd_exp, obdo, och, request);
        RETURN(rc);
}

int lmv_get_mea_and_update_object(struct obd_export *exp, 
                                  struct lustre_id *id)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ptlrpc_request *req = NULL;
        struct lmv_obj *obj;
        struct lustre_md md;
        unsigned long valid;
        int mealen, rc;

        md.mea = NULL;
        mealen = MEA_SIZE_LMV(lmv);
        
        valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA;

        /* time to update mea of parent id */
        rc = md_getattr(lmv->tgts[id_group(id)].ltd_exp,
                        id, valid, mealen, &req);
        if (rc) {
                CERROR("md_getattr() failed, error %d\n", rc);
                GOTO(cleanup, rc);
        }

        rc = mdc_req2lustre_md(exp, req, 0, NULL, &md);
        if (rc) {
                CERROR("mdc_req2lustre_md() failed, error %d\n", rc);
                GOTO(cleanup, rc);
        }

        if (md.mea == NULL)
                GOTO(cleanup, rc = -ENODATA);

        obj = lmv_create_obj(exp, id, md.mea);
        if (IS_ERR(obj))
                rc = PTR_ERR(obj);
        
        lmv_put_obj(obj);
        obd_free_memmd(exp, (struct lov_stripe_md **)&md.mea);

cleanup:
        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

int lmv_create(struct obd_export *exp, struct mdc_op_data *op_data,
               const void *data, int datalen, int mode, __u32 uid,
               __u32 gid, __u64 rdev, struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mds_body *body;
        struct lmv_obj *obj;
        int rc, mds, loop = 0;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        if (!lmv->desc.ld_active_tgt_count)
                RETURN(-EIO);
repeat:
        LASSERT(++loop <= 2);
        obj = lmv_grab_obj(obd, &op_data->id1);
        if (obj) {
                mds = raw_name2idx(obj->hashtype, obj->objcount, 
                                   op_data->name, op_data->namelen);
                op_data->id1 = obj->objs[mds].id;
                lmv_put_obj(obj);
        }

        CDEBUG(D_OTHER, "CREATE '%*s' on "DLID4"\n", op_data->namelen,
               op_data->name, OLID4(&op_data->id1));
        
        rc = md_create(lmv->tgts[id_group(&op_data->id1)].ltd_exp, 
                       op_data, data, datalen, mode, uid, gid, rdev, request);
        if (rc == 0) {
                if (*request == NULL)
                        RETURN(rc);

                body = lustre_msg_buf((*request)->rq_repmsg, 0,
                                      sizeof(*body));
                LASSERT(body != NULL);
                
                CDEBUG(D_OTHER, "created. "DLID4"\n", OLID4(&op_data->id1));
                
/*                LASSERT(body->valid & OBD_MD_MDS ||
                        body->mds == id_group(&op_data->id1));*/
        } else if (rc == -ERESTART) {
                /* directory got splitted. time to update local object and
                 * repeat the request with proper MDS */
                rc = lmv_get_mea_and_update_object(exp, &op_data->id1);
                if (rc == 0) {
                        ptlrpc_req_finished(*request);
                        goto repeat;
                }
        }
        RETURN(rc);
}

int lmv_done_writing(struct obd_export *exp, struct obdo *obdo)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc;
        ENTRY;
        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        /* FIXME: choose right MDC here */
        CWARN("this method isn't implemented yet\n");
        rc = md_done_writing(lmv->tgts[0].ltd_exp, obdo);
        RETURN(rc);
}

int lmv_enqueue_slaves(struct obd_export *exp, int locktype,
                       struct lookup_intent *it, int lockmode,
                       struct mdc_op_data *data, struct lustre_handle *lockh,
                       void *lmm, int lmmsize, ldlm_completion_callback cb_compl,
                       ldlm_blocking_callback cb_blocking, void *cb_data)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mea *mea = data->mea1;
        struct mdc_op_data data2;
        int i, rc, mds;
        ENTRY;

        LASSERT(mea != NULL);
        for (i = 0; i < mea->mea_count; i++) {
                memset(&data2, 0, sizeof(data2));
                data2.id1 = mea->mea_ids[i];
                mds = id_group(&data2.id1);
                
                if (lmv->tgts[mds].ltd_exp == NULL)
                        continue;

                rc = md_enqueue(lmv->tgts[mds].ltd_exp, locktype, it, 
                                lockmode, &data2, lockh + i, lmm, lmmsize, 
                                cb_compl, cb_blocking, cb_data);
                
                CDEBUG(D_OTHER, "take lock on slave "DLID4" -> %d/%d\n",
                       OLID4(&mea->mea_ids[i]), rc, it->d.lustre.it_status);
                if (rc)
                        GOTO(cleanup, rc);
                if (it->d.lustre.it_data) {
                        struct ptlrpc_request *req;
                        req = (struct ptlrpc_request *) it->d.lustre.it_data;
                        ptlrpc_req_finished(req);
                }
                
                if (it->d.lustre.it_status)
                        GOTO(cleanup, rc = it->d.lustre.it_status);
        }
        RETURN(0);
        
cleanup:
        /* drop all taken locks */
        while (--i >= 0) {
                if (lockh[i].cookie)
                        ldlm_lock_decref(lockh + i, lockmode);
                lockh[i].cookie = 0;
        }
        RETURN(rc);
}

int lmv_enqueue(struct obd_export *exp, int lock_type,
                struct lookup_intent *it, int lock_mode,
                struct mdc_op_data *data, struct lustre_handle *lockh,
                void *lmm, int lmmsize, ldlm_completion_callback cb_compl,
                ldlm_blocking_callback cb_blocking, void *cb_data)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lmv_obj *obj;
        int rc, mds;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        if (data->mea1 && it->it_op == IT_UNLINK) {
                rc = lmv_enqueue_slaves(exp, lock_type, it, lock_mode,
                                        data, lockh, lmm, lmmsize,
                                        cb_compl, cb_blocking, cb_data);
                RETURN(rc);
        }

        if (data->namelen) {
                obj = lmv_grab_obj(obd, &data->id1);
                if (obj) {
                        /* directory is splitted. look for right mds for this
                         * name */
                        mds = raw_name2idx(obj->hashtype, obj->objcount,
                                           (char *)data->name, data->namelen);
                        data->id1 = obj->objs[mds].id;
                        lmv_put_obj(obj);
                }
        }
        CDEBUG(D_OTHER, "ENQUEUE '%s' on "DLID4"\n", LL_IT2STR(it),
               OLID4(&data->id1));
        
        rc = md_enqueue(lmv->tgts[id_group(&data->id1)].ltd_exp, 
                        lock_type, it, lock_mode, data, lockh, lmm, 
                        lmmsize, cb_compl, cb_blocking, cb_data);
        RETURN(rc);
}

int lmv_getattr_name(struct obd_export *exp, struct lustre_id *id,
                     char *filename, int namelen, unsigned long valid,
                     unsigned int ea_size, struct ptlrpc_request **request)
{
        int rc, mds = id_group(id), loop = 0;
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lustre_id rid = *id;
        struct mds_body *body;
        struct lmv_obj *obj;
        int fetch_fid_on;
        ENTRY;
        
        rc = lmv_check_connect(obd);
	if (rc)
		RETURN(rc);
repeat:
        LASSERT(++loop <= 2);
        obj = lmv_grab_obj(obd, id);
        if (obj) {
                /* directory is splitted. look for right mds for this name */
                mds = raw_name2idx(obj->hashtype, obj->objcount, 
                                   filename, namelen - 1);
                rid = obj->objs[mds].id;
                lmv_put_obj(obj);
        }
        
        CDEBUG(D_OTHER, "getattr_name for %*s on "DLID4" -> "DLID4"\n",
               namelen, filename, OLID4(id), OLID4(&rid));

        fetch_fid_on = (valid & OBD_MD_FID);

        /*
         * here should be applied OBD_MD_FID to ->valid, because otherwise,
         * mds_getattr_name() will not fetch fid component of lustre_id and
         * thus, next call to md_getattr_name() will be performed to wrong mds.
         */
        if (!fetch_fid_on)
                valid |= OBD_MD_FID;
        
        rc = md_getattr_name(lmv->tgts[id_group(&rid)].ltd_exp, 
                             &rid, filename, namelen, valid,
                             ea_size, request);
        if (rc == 0) {
                /*
                 * this could be cross-node reference. in this case all we have
                 * right now is lustre_id triple. we'd like to find other
                 * attributes.
                 */
                body = lustre_msg_buf((*request)->rq_repmsg, 0, sizeof(*body));
                LASSERT(body != NULL);
                if (body->valid & OBD_MD_MDS) {
                        struct ptlrpc_request *req = NULL;
                        
                        rid = body->id1;
                        CDEBUG(D_OTHER, "request attrs for "DLID4"\n", OLID4(&rid));

                        /* 
                         * turning OBD_MD_FID fetching off, as we already have
                         * full lustre_id and do need to fetch fid component
                         * again. This will help to make thing slightly faster.
                         */
                        if (!fetch_fid_on)
                                valid &= ~OBD_MD_FID;
                        
                        rc = md_getattr_name(lmv->tgts[id_group(&rid)].ltd_exp, 
                                             &rid, NULL, 1, valid, ea_size, &req);
                        ptlrpc_req_finished(*request);
                        *request = req;
                }
        } else if (rc == -ERESTART) {
                /* directory got splitted. time to update local object and
                 * repeat the request with proper MDS */
                rc = lmv_get_mea_and_update_object(exp, &rid);
                if (rc == 0) {
                        ptlrpc_req_finished(*request);
                        goto repeat;
                }
        }
        RETURN(rc);
}

/*
 * llite passes id of an target inode in data->id1 and id of directory in
 * data->id2
 */
int lmv_link(struct obd_export *exp, struct mdc_op_data *data,
             struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lmv_obj *obj;
        int rc;
        ENTRY;
        
        rc = lmv_check_connect(obd);
	if (rc)
		RETURN(rc);

        if (data->namelen != 0) {
                /* usual link request */
                obj = lmv_grab_obj(obd, &data->id1);
                if (obj) {
                        rc = raw_name2idx(obj->hashtype, obj->objcount, 
                                          data->name, data->namelen);
                        data->id1 = obj->objs[rc].id;
                        lmv_put_obj(obj);
                }
                
                CDEBUG(D_OTHER,"link "DLID4":%*s to "DLID4"\n",
                       OLID4(&data->id2), data->namelen, data->name,
                       OLID4(&data->id1));
        } else {
                /* request from MDS to acquire i_links for inode by id1 */
                CDEBUG(D_OTHER, "inc i_nlinks for "DLID4"\n",
                       OLID4(&data->id1));
        }
                        
        rc = md_link(lmv->tgts[id_group(&data->id1)].ltd_exp, 
                     data, request);
        RETURN(rc);
}

int lmv_rename(struct obd_export *exp, struct mdc_op_data *data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lmv_obj *obj;
        int rc, mds;
        ENTRY;

        CDEBUG(D_OTHER, "rename %*s in "DLID4" to %*s in "DLID4"\n",
               oldlen, old, OLID4(&data->id1), newlen, new, OLID4(&data->id2));

        rc = lmv_check_connect(obd);
	if (rc)
		RETURN(rc);

        if (oldlen == 0) {
                /*
                 * MDS with old dir entry is asking another MDS to create name
                 * there.
                 */
                CDEBUG(D_OTHER,
                       "create %*s(%d/%d) in "DLID4" pointing "
                       "to "DLID4"\n", newlen, new, oldlen, newlen,
                       OLID4(&data->id2), OLID4(&data->id1));

                mds = id_group(&data->id2);

                /* 
                 * target directory can be splitted, sowe should forward request
                 * to the right MDS.
                 */
                obj = lmv_grab_obj(obd, &data->id2);
                if (obj) {
                        mds = raw_name2idx(obj->hashtype, obj->objcount, 
                                           (char *)new, newlen);
                        data->id2 = obj->objs[mds].id;
                        CDEBUG(D_OTHER, "forward to MDS #%u ("DLID4")\n", mds,
                               OLID4(&data->id2));
                        lmv_put_obj(obj);
                }
                goto request;
        }

        obj = lmv_grab_obj(obd, &data->id1);
        if (obj) {
                /*
                 * directory is already splitted, so we have to forward request
                 * to the right MDS.
                 */
                mds = raw_name2idx(obj->hashtype, obj->objcount, 
                                   (char *)old, oldlen);
                data->id1 = obj->objs[mds].id;
                CDEBUG(D_OTHER, "forward to MDS #%u ("DLID4")\n", mds,
                       OLID4(&data->id1));
                lmv_put_obj(obj);
        }

        obj = lmv_grab_obj(obd, &data->id2);
        if (obj) {
                /*
                 * directory is already splitted, so we have to forward request
                 * to the right MDS.
                 */
                mds = raw_name2idx(obj->hashtype, obj->objcount, 
                                   (char *)new, newlen);
                
                data->id2 = obj->objs[mds].id;
                CDEBUG(D_OTHER, "forward to MDS #%u ("DLID4")\n", mds,
                       OLID4(&data->id2));
                lmv_put_obj(obj);
        }
        
        mds = id_group(&data->id1);

request:
        if (id_group(&data->id1) != id_group(&data->id2)) {
                CDEBUG(D_OTHER,"cross-node rename "DLID4"/%*s to "DLID4"/%*s\n",
                       OLID4(&data->id1), oldlen, old, OLID4(&data->id2),
                       newlen, new);
        }

        rc = md_rename(lmv->tgts[mds].ltd_exp, data, old, oldlen,
                       new, newlen, request); 
        RETURN(rc);
}

int lmv_setattr(struct obd_export *exp, struct mdc_op_data *data,
                struct iattr *iattr, void *ea, int ealen, void *ea2,
                int ea2len, struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ptlrpc_request *req;
        struct mds_body *body;
        struct lmv_obj *obj;
        int rc = 0, i;
        ENTRY;

        rc = lmv_check_connect(obd);
	if (rc)
		RETURN(rc);

        obj = lmv_grab_obj(obd, &data->id1);
        
        CDEBUG(D_OTHER, "SETATTR for "DLID4", valid 0x%x%s\n",
               OLID4(&data->id1), iattr->ia_valid, obj ? ", splitted" : "");
        
        if (obj) {
                for (i = 0; i < obj->objcount; i++) {
                        data->id1 = obj->objs[i].id;
                        
                        rc = md_setattr(lmv->tgts[id_group(&data->id1)].ltd_exp, 
                                        data, iattr, ea, ealen, ea2, ea2len, &req);

                        if (id_equal_fid(&obj->id, &obj->objs[i].id)) {
                                /*
                                 * this is master object and this request should
                                 * be returned back to llite.
                                 */
                                *request = req;
                        } else {
                                ptlrpc_req_finished(req);
                        }

                        if (rc)
                                break;
                }
                lmv_put_obj(obj);
        } else {
                LASSERT(id_group(&data->id1) < lmv->desc.ld_tgt_count);
                rc = md_setattr(lmv->tgts[id_group(&data->id1)].ltd_exp,
                                data, iattr, ea, ealen, ea2, ea2len, request); 
                if (rc == 0) {
                        body = lustre_msg_buf((*request)->rq_repmsg, 0,
                                              sizeof(*body));
                        LASSERT(body != NULL);
                        LASSERT(id_group(&body->id1) == id_group(&data->id1));
                }
        }
        RETURN(rc);
}

int lmv_sync(struct obd_export *exp, struct lustre_id *id,
             struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc;
        ENTRY;

        rc = lmv_check_connect(obd);
	if (rc)
		RETURN(rc);

        rc = md_sync(lmv->tgts[id_group(id)].ltd_exp, 
                     id, request);
        RETURN(rc);
}

int lmv_dirobj_blocking_ast(struct ldlm_lock *lock, 
                            struct ldlm_lock_desc *desc,
                            void *data, int flag)
{
        struct lustre_handle lockh;
        struct lmv_obj *obj;
        int rc;
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
                /* time to drop cached attrs for dirobj */
                obj = lock->l_ast_data;
                if (obj) {
                        CDEBUG(D_OTHER, "cancel %s on "LPU64"/"LPU64
                               ", master "DLID4"\n",
                               lock->l_resource->lr_name.name[3] == 1 ?
                               "LOOKUP" : "UPDATE",
                               lock->l_resource->lr_name.name[0],
                               lock->l_resource->lr_name.name[1], 
                               OLID4(&obj->id));
                        lmv_put_obj(obj);
                }
                break;
        default:
                LBUG();
        }
        RETURN(0);
}

void lmv_remove_dots(struct page *page)
{
        char *kaddr = page_address(page);
        unsigned limit = PAGE_CACHE_SIZE;
        unsigned offs, rec_len;
        struct ext2_dir_entry_2 *p;

        for (offs = 0; offs <= limit - EXT2_DIR_REC_LEN(1); offs += rec_len) {
                p = (struct ext2_dir_entry_2 *)(kaddr + offs);
                rec_len = le16_to_cpu(p->rec_len);

                if ((p->name_len == 1 && p->name[0] == '.') ||
                    (p->name_len == 2 && p->name[0] == '.' && p->name[1] == '.'))
                        p->inode = 0;
        }
}

int lmv_readpage(struct obd_export *exp, struct lustre_id *id,
                 __u64 offset, struct page *page,
                 struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lustre_id rid = *id;
        struct lmv_obj *obj;
        int rc, i;
        ENTRY;

#warning "we need well-desgined readdir() implementation"
        rc = lmv_check_connect(obd);
	if (rc)
		RETURN(rc);

        LASSERT(id_group(id) < lmv->desc.ld_tgt_count);
        CDEBUG(D_OTHER, "READPAGE at %llu from "DLID4"\n",
               offset, OLID4(&rid));

        obj = lmv_grab_obj(obd, id);
        if (obj) {
                lmv_lock_obj(obj);

                /* find dirobj containing page with requested offset. */
                for (i = 0; i < obj->objcount; i++) {
                        if (offset < obj->objs[i].size)
                                break;
                        offset -= obj->objs[i].size;
                }
                rid = obj->objs[i].id;
                
                lmv_unlock_obj(obj);
                lmv_put_obj(obj);
                
                CDEBUG(D_OTHER, "forward to "DLID4" with offset %lu\n",
                       OLID4(&rid), (unsigned long)offset);
        }
        rc = md_readpage(lmv->tgts[id_group(&rid)].ltd_exp, &rid, 
                         offset, page, request);
        
        if (rc == 0 && !id_equal_fid(&rid, id))
                /* this page isn't from master object. To avoid "." and ".." 
                 * duplication in directory, we have to remove them from all
                 * slave objects */
                lmv_remove_dots(page);
        
        RETURN(rc);
}

int lmv_unlink_slaves(struct obd_export *exp, struct mdc_op_data *data,
                      struct ptlrpc_request **req)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mea *mea = data->mea1;
        struct mdc_op_data data2;
        int i, rc = 0, mds;
        ENTRY;

        LASSERT(mea != NULL);
        for (i = 0; i < mea->mea_count; i++) {
                memset(&data2, 0, sizeof(data2));
                data2.id1 = mea->mea_ids[i];
                data2.create_mode = MDS_MODE_DONT_LOCK | S_IFDIR;
                
                mds = id_group(&data2.id1);

                if (lmv->tgts[mds].ltd_exp == NULL)
                        continue;

                rc = md_unlink(lmv->tgts[mds].ltd_exp, &data2, req);
                CDEBUG(D_OTHER, "unlink slave "DLID4" -> %d\n",
                       OLID4(&mea->mea_ids[i]), rc);
                if (*req) {
                        ptlrpc_req_finished(*req);
                        *req = NULL;
                }
                if (rc)
                        break;
        }
        RETURN(rc);
}

int lmv_delete_object(struct obd_export *exp, struct lustre_id *id)
{
        ENTRY;

        if (!lmv_delete_obj(exp, id)) {
                CDEBUG(D_OTHER, "object "DLID4" is not found.\n",
                       OLID4(id));
        }
        
        RETURN(0);
}

int lmv_unlink(struct obd_export *exp, struct mdc_op_data *data,
               struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc, i = 0;
        ENTRY;
        
	rc = lmv_check_connect(obd);
	if (rc)
		RETURN(rc);

        if (data->namelen == 0 && data->mea1 != NULL) {
                /* mds asks to remove slave objects */
                rc = lmv_unlink_slaves(exp, data, request);
                RETURN(rc);
        } else if (data->namelen != 0) {
                struct lmv_obj *obj;
                
                obj = lmv_grab_obj(obd, &data->id1);
                if (obj) {
                        i = raw_name2idx(obj->hashtype, obj->objcount,
                                         data->name, data->namelen);
                        data->id1 = obj->objs[i].id;
                        lmv_put_obj(obj);
                }
                CDEBUG(D_OTHER, "unlink '%*s' in "DLID4" -> %u\n",
                       data->namelen, data->name, OLID4(&data->id1),
                       i);
        } else {
                CDEBUG(D_OTHER, "drop i_nlink on "DLID4"\n",
                       OLID4(&data->id1));
        }
        rc = md_unlink(lmv->tgts[id_group(&data->id1)].ltd_exp, 
                       data, request); 
        RETURN(rc);
}

struct obd_device *lmv_get_real_obd(struct obd_export *exp,
                                    char *name, int len)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc;
        ENTRY;

        rc = lmv_check_connect(obd);
	if (rc)
		RETURN(ERR_PTR(rc));
        obd = lmv->tgts[0].ltd_exp->exp_obd;
        EXIT;
        return obd;
}

int lmv_init_ea_size(struct obd_export *exp, int easize, int cookiesize)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int i, rc = 0, change = 0;
        ENTRY;

        if (lmv->max_easize < easize) {
                lmv->max_easize = easize;
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

                rc = obd_init_ea_size(lmv->tgts[i].ltd_exp, easize, cookiesize);
                if (rc) {
                        CERROR("obd_init_ea_size() failed on MDT target %d, "
                               "error %d.\n", i, rc);
                        break;
                }
        }
        RETURN(rc);
}

int lmv_obd_create_single(struct obd_export *exp, struct obdo *oa,
                          struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lov_stripe_md obj_md;
        struct lov_stripe_md *obj_mdp = &obj_md;
        int rc = 0;
        ENTRY;

        LASSERT(ea == NULL);
        LASSERT(oa->o_mds < lmv->desc.ld_tgt_count);

        rc = obd_create(lmv->tgts[oa->o_mds].ltd_exp, oa, &obj_mdp, oti);

        RETURN(rc);
}

int lmv_getready(struct obd_export *exp)
{
        struct obd_device *obd = exp->exp_obd;
        int rc = 0;
        
        ENTRY;
        rc = lmv_check_connect(obd);
        RETURN(rc);
}

/*
 * to be called from MDS only.
 */
int lmv_obd_create(struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lustre_id mid;
        int i, c, rc = 0;
        struct mea *mea;
        int lcount;
        ENTRY;

        rc = lmv_check_connect(obd);
        if (rc)
                RETURN(rc);

        LASSERT(oa != NULL);
        
        if (ea == NULL) {
                rc = lmv_obd_create_single(exp, oa, NULL, oti);
                if (rc)
                        CERROR("Can't create object, rc = %d\n", rc);
                RETURN(rc);
        }

        if (*ea == NULL) {
                rc = obd_alloc_diskmd(exp, (struct lov_mds_md **)ea);
                if (rc < 0) {
                        CERROR("obd_alloc_diskmd() failed, error %d\n",
                               rc);
                        RETURN(rc);
                }
                
                if (*ea == NULL)
                        RETURN(-ENOMEM);
        }

        rc = 0;

        LASSERT(oa->o_id != 0);
        id_ino(&mid) = oa->o_id;
        id_fid(&mid) = oa->o_fid;
        id_gen(&mid) = oa->o_generation;

        mea = (struct mea *)*ea;
        if (!mea->mea_count || mea->mea_count > lmv->desc.ld_tgt_count)
                mea->mea_count = lmv->desc.ld_tgt_count;
        
        mea->mea_master = -1;
        mea->mea_magic = MEA_MAGIC_ALL_CHARS;

        lcount = lmv->desc.ld_tgt_count;
        for (i = 0, c = 0; c < mea->mea_count && i < lcount; i++) {
                struct lov_stripe_md obj_md;
                struct lov_stripe_md *obj_mdp = &obj_md;
               
                if (lmv->tgts[i].ltd_exp == NULL) {
                        /* this is master MDS */
                        mea->mea_master = i;
                        id_group(&mea->mea_ids[c]) = i;
                        id_ino(&mea->mea_ids[c]) = id_ino(&mid);
                        id_gen(&mea->mea_ids[c]) = id_gen(&mid);
                        id_fid(&mea->mea_ids[c]) = id_fid(&mid);
                        c++;
                        continue;
                }

                /* "master" MDS should always be part of stripped dir, so scan
                 * for it. */
                if (mea->mea_master == -1 && c == mea->mea_count - 1)
                        continue;

                oa->o_valid = OBD_MD_FLGENER | OBD_MD_FLTYPE | OBD_MD_FLMODE |
                        OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLID;

                rc = obd_create(lmv->tgts[c].ltd_exp, oa, &obj_mdp, oti);
                if (rc) {
                        CERROR("obd_create() failed on MDT target %d, "
                               "error %d\n", c, rc);
                        RETURN(rc);
                }

                CDEBUG(D_OTHER, "dirobj at mds %d: "LPU64"/%u\n",
                       i, oa->o_id, oa->o_generation);

                /* here after object is created on desired MDS we save its fid
                 * to local mea_ids. */
                LASSERT(oa->o_fid);
                
                id_group(&mea->mea_ids[c]) = i;
                id_ino(&mea->mea_ids[c]) = oa->o_id;
                id_fid(&mea->mea_ids[c]) = oa->o_fid;
                id_gen(&mea->mea_ids[c]) = oa->o_generation;
                c++;
        }
        LASSERT(c == mea->mea_count);
        CDEBUG(D_OTHER, "%d dirobjects created\n", (int) mea->mea_count);

        RETURN(rc);
}

static int lmv_llog_init(struct obd_device *obd, struct obd_llogs *llogs, 
                         struct obd_device *tgt, int count,
                         struct llog_catid *logid)
{
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        rc = obd_llog_setup(obd, llogs, LLOG_CONFIG_REPL_CTXT, tgt, 0, NULL,
                            &llog_client_ops);
        if (rc == 0) {
                ctxt = llog_get_context(llogs, LLOG_CONFIG_REPL_CTXT);
                ctxt->loc_imp = tgt->u.cli.cl_import;
        }

        RETURN(rc);
}

static int lmv_llog_finish(struct obd_device *obd,
                           struct obd_llogs *llogs, int count)
{
        int rc;
        ENTRY;

        rc = obd_llog_cleanup(llog_get_context(llogs, LLOG_CONFIG_REPL_CTXT));
        RETURN(rc);
}

static int lmv_get_info(struct obd_export *exp, __u32 keylen,
                        void *key, __u32 *vallen, void *val)
{
        struct obd_device *obd;
        struct lmv_obd *lmv;
        int rc = 0;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }

        lmv = &obd->u.lmv;
        if (keylen == 6 && memcmp(key, "mdsize", 6) == 0) {
                __u32 *mdsize = val;
                *vallen = sizeof(__u32);
                *mdsize = sizeof(struct lustre_id) * lmv->desc.ld_tgt_count
                        + sizeof(struct mea);
                RETURN(0);
        } else if (keylen == 6 && memcmp(key, "mdsnum", 6) == 0) {
                struct obd_uuid *cluuid = &lmv->cluuid;
                struct lmv_tgt_desc *tgts;
                __u32 *mdsnum = val;
                int i;

                for (i = 0, tgts = lmv->tgts; i < lmv->desc.ld_tgt_count; i++, tgts++) {
                        if (obd_uuid_equals(&tgts->uuid, cluuid)) {
                                *vallen = sizeof(__u32);
                                *mdsnum = i;
                                RETURN(0);
                        }
                }
                LASSERT(0);
        } else if (keylen == 6 && memcmp(key, "rootid", 6) == 0) {
                /* getting rootid from first MDS. */
                rc = obd_get_info(lmv->tgts[0].ltd_exp, keylen, key,
                                  vallen, val);
                RETURN(rc);
        } else if (keylen >= strlen("lmvdesc") && strcmp(key, "lmvdesc") == 0) {
                struct lmv_desc *desc_ret = val;
                *desc_ret = lmv->desc;
                RETURN(0);
        }

        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
}

int lmv_set_info(struct obd_export *exp, obd_count keylen,
                 void *key, obd_count vallen, void *val)
{
        struct obd_device *obd;
        struct lmv_obd *lmv;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }
        lmv = &obd->u.lmv;

        if (keylen >= strlen("inter_mds") && strcmp(key, "inter_mds") == 0) {
                lmv->server_timeout = 1;
                lmv_set_timeouts(obd);
                RETURN(0);
        }
        
        RETURN(-EINVAL);
}

int lmv_packmd(struct obd_export *exp, struct lov_mds_md **lmmp,
               struct lov_stripe_md *lsm)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lmv_obd *lmv = &obd->u.lmv;
        int mea_size;
        ENTRY;

	mea_size = sizeof(struct lustre_id) * 
                lmv->desc.ld_tgt_count + sizeof(struct mea);
        if (!lmmp)
                RETURN(mea_size);

        if (*lmmp && !lsm) {
                OBD_FREE(*lmmp, mea_size);
                *lmmp = NULL;
                RETURN(0);
        }

        if (*lmmp == NULL) {
                OBD_ALLOC(*lmmp, mea_size);
                if (*lmmp == NULL)
                        RETURN(-ENOMEM);
        }

        if (!lsm)
                RETURN(mea_size);

#warning "MEA packing/convertation must be here! -bzzz"
        memcpy(*lmmp, lsm, mea_size);
        RETURN(mea_size);
}

int lmv_unpackmd(struct obd_export *exp, struct lov_stripe_md **mem_tgt,
                 struct lov_mds_md *disk_src, int mdsize)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mea **tmea = (struct mea **) mem_tgt;
        struct mea *mea = (void *) disk_src;
        int mea_size;
        ENTRY;

	mea_size = sizeof(struct lustre_id) * 
                lmv->desc.ld_tgt_count + sizeof(struct mea);
        if (mem_tgt == NULL)
                return mea_size;

        if (*mem_tgt != NULL && disk_src == NULL) {
                OBD_FREE(*tmea, mea_size);
                RETURN(0);
        }

        LASSERT(mea_size == mdsize);

        OBD_ALLOC(*tmea, mea_size);
        if (*tmea == NULL)
                RETURN(-ENOMEM);

        if (!disk_src)
                RETURN(mea_size);

#warning "MEA unpacking/convertation must be here! -bzzz"
        memcpy(*tmea, mea, mdsize);
        RETURN(mea_size);
}

int lmv_brw(int rw, struct obd_export *exp, struct obdo *oa,
            struct lov_stripe_md *ea, obd_count oa_bufs,
            struct brw_page *pgarr, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mea *mea = (struct mea *) ea;
        int err;
      
        LASSERT(oa != NULL);
        LASSERT(ea != NULL);
        LASSERT(pgarr != NULL);
        LASSERT(oa->o_mds < lmv->desc.ld_tgt_count);

        oa->o_gr = id_gen(&mea->mea_ids[oa->o_mds]);
        oa->o_id = id_ino(&mea->mea_ids[oa->o_mds]);
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        
        err = obd_brw(rw, lmv->tgts[oa->o_mds].ltd_exp,
                      oa, NULL, oa_bufs, pgarr, oti);
        RETURN(err);
}

struct obd_ops lmv_obd_ops = {
        .o_owner                = THIS_MODULE,
        .o_attach               = lmv_attach,
        .o_detach               = lmv_detach,
        .o_setup                = lmv_setup,
        .o_cleanup              = lmv_cleanup,
        .o_connect              = lmv_connect,
        .o_disconnect           = lmv_disconnect,
        .o_statfs               = lmv_statfs,
        .o_llog_init            = lmv_llog_init,
        .o_llog_finish          = lmv_llog_finish,
        .o_get_info             = lmv_get_info,
        .o_set_info             = lmv_set_info,
        .o_create               = lmv_obd_create,
        .o_packmd               = lmv_packmd,
        .o_unpackmd             = lmv_unpackmd,
        .o_brw                  = lmv_brw,
        .o_init_ea_size         = lmv_init_ea_size,
        .o_notify               = lmv_notify,
        .o_iocontrol            = lmv_iocontrol,
        .o_getready             = lmv_getready,
};

struct md_ops lmv_md_ops = {
        .m_getstatus            = lmv_getstatus,
        .m_getattr              = lmv_getattr,
        .m_change_cbdata        = lmv_change_cbdata,
        .m_change_cbdata_name   = lmv_change_cbdata_name,
        .m_close                = lmv_close,
        .m_create               = lmv_create,
        .m_done_writing         = lmv_done_writing,
        .m_enqueue              = lmv_enqueue,
        .m_getattr_name         = lmv_getattr_name,
        .m_intent_lock          = lmv_intent_lock,
        .m_link                 = lmv_link,
        .m_rename               = lmv_rename,
        .m_setattr              = lmv_setattr,
        .m_sync                 = lmv_sync,
        .m_readpage             = lmv_readpage,
        .m_unlink               = lmv_unlink,
        .m_get_real_obd         = lmv_get_real_obd,
        .m_valid_attrs          = lmv_valid_attrs,
        .m_delete_object        = lmv_delete_object,
};

int __init lmv_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        lprocfs_init_vars(lmv, &lvars);
        rc = class_register_type(&lmv_obd_ops, &lmv_md_ops,
                                 lvars.module_vars, OBD_LMV_DEVICENAME);
        RETURN(rc);
}

#ifdef __KERNEL__
static void lmv_exit(void)
{
        class_unregister_type(OBD_LMV_DEVICENAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Logical Metadata Volume OBD driver");
MODULE_LICENSE("GPL");

module_init(lmv_init);
module_exit(lmv_exit);
#endif
