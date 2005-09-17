/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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
 * Config API
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifdef __KERNEL__
#include <linux/kmod.h>   /* for request_module() */
#include <linux/module.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#else
#include <liblustre.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#endif
#include <linux/lustre_log.h>
#include <linux/lprocfs_status.h>
#include <libcfs/list.h>


/* Create a new device and set the type, name and uuid.  If
 * successful, the new device can be accessed by either name or uuid.
 */
static int class_attach(struct lustre_cfg *lcfg)
{
        struct obd_type *type;
        struct obd_device *obd;
        char *typename, *name, *uuid;
        int rc, len, cleanup_phase = 0;

        if (!LUSTRE_CFG_BUFLEN(lcfg, 1)) {
                CERROR("No type passed!\n");
                RETURN(-EINVAL);
        }
        typename = lustre_cfg_string(lcfg, 1);

        if (!LUSTRE_CFG_BUFLEN(lcfg, 0)) {
                CERROR("No name passed!\n");
                RETURN(-EINVAL);
        }
        name = lustre_cfg_string(lcfg, 0);

        if (!LUSTRE_CFG_BUFLEN(lcfg, 2)) {
                CERROR("No UUID passed!\n");
                RETURN(-EINVAL);
        }
        uuid = lustre_cfg_string(lcfg, 2);

        CDEBUG(D_CONFIG, "attach type %s name: %s uuid: %s\n",
               MKSTR(typename), MKSTR(name), MKSTR(uuid));

        /* find the type */
        type = class_get_type(typename);
        if (!type) {
                CERROR("OBD: unknown type: %s\n", typename);
                RETURN(-EINVAL);
        }
        cleanup_phase = 1;  /* class_put_type */

        obd = class_name2obd(name);
        if (obd != NULL) {
                CERROR("obd %s already attached\n", name);
                GOTO(out, rc = -EEXIST);
        }

        obd = class_newdev(type);
        if (obd == NULL)
                GOTO(out, rc = -EINVAL);

        cleanup_phase = 2;  /* class_release_dev */
        
        INIT_LIST_HEAD(&obd->obd_exports);
        obd->obd_num_exports = 0;
        spin_lock_init(&obd->obd_dev_lock);
        spin_lock_init(&obd->obd_osfs_lock);
        obd->obd_osfs_age = jiffies - 1000 * HZ;
        init_waitqueue_head(&obd->obd_refcount_waitq);

        /* XXX belongs in setup not attach  */
        /* recovery data */
        init_timer(&obd->obd_recovery_timer);
        spin_lock_init(&obd->obd_processing_task_lock);
        init_waitqueue_head(&obd->obd_next_transno_waitq);
        INIT_LIST_HEAD(&obd->obd_req_replay_queue);
        INIT_LIST_HEAD(&obd->obd_lock_replay_queue);
        INIT_LIST_HEAD(&obd->obd_final_req_queue);

        spin_lock_init(&obd->obd_uncommitted_replies_lock);
        INIT_LIST_HEAD(&obd->obd_uncommitted_replies);

        len = strlen(name) + 1;
        OBD_ALLOC(obd->obd_name, len);
        if (!obd->obd_name)
                GOTO(out, rc = -ENOMEM);
        memcpy(obd->obd_name, name, len);
        
        cleanup_phase = 3; /* free obd_name */

        len = strlen(uuid);
        if (len >= sizeof(obd->obd_uuid)) {
                CERROR("uuid must be < "LPSZ" bytes long\n",
                       sizeof(obd->obd_uuid));
                GOTO(out, rc = -EINVAL);
        }
        memcpy(obd->obd_uuid.uuid, uuid, len);

        /* do the attach */
        if (OBP(obd, attach)) {
                rc = OBP(obd,attach)(obd, sizeof *lcfg, lcfg);
                if (rc)
                        GOTO(out, rc = -EINVAL);
        }

        obd->obd_attached = 1;
        type->typ_refcnt++;
        CDEBUG(D_IOCTL, "OBD: dev %d attached type %s\n",
               obd->obd_minor, typename);
        RETURN(0);
 out:
        switch (cleanup_phase) {
        case 3:
                OBD_FREE(obd->obd_name, strlen(obd->obd_name) + 1);
        case 2:
                class_release_dev(obd);
        case 1:
                class_put_type(type);
        }
        return rc;
}

static int class_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int err = 0;
        struct obd_export *exp;
        ENTRY;

        LASSERT(obd == (obd_dev + obd->obd_minor));

        /* have we attached a type to this device? */
        if (!obd->obd_attached) {
                CERROR("Device %d not attached\n", obd->obd_minor);
                RETURN(-ENODEV);
        }

        /* has this been done already? */
        if (obd->obd_set_up) {
                CERROR("Device %d already setup (type %s)\n",
                       obd->obd_minor, obd->obd_type->typ_name);
                RETURN(-EBUSY);
        }

        atomic_set(&obd->obd_refcount, 0);

        exp = class_new_export(obd);
        if (exp == NULL)
                RETURN(err);
        memcpy(&exp->exp_client_uuid, &obd->obd_uuid,
               sizeof(exp->exp_client_uuid));
        obd->obd_self_export = exp;
        class_export_put(exp);

        err = obd_setup(obd, sizeof(*lcfg), lcfg);
        if (err)
                GOTO(err_exp, err);

        obd->obd_type->typ_refcnt++;
        obd->obd_set_up = 1;

        RETURN(err);

err_exp:
        class_unlink_export(obd->obd_self_export);
        obd->obd_self_export = NULL;
        RETURN(err);
}

static int class_detach(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int err = 0;

        ENTRY;
        if (obd->obd_set_up) {
                CERROR("OBD device %d still set up\n", obd->obd_minor);
                RETURN(-EBUSY);
        }
        if (!obd->obd_attached) {
                CERROR("OBD device %d not attached\n", obd->obd_minor);
                RETURN(-ENODEV);
        }
        if (OBP(obd, detach))
                err = OBP(obd,detach)(obd);

        if (obd->obd_name) {
                OBD_FREE(obd->obd_name, strlen(obd->obd_name)+1);
                obd->obd_name = NULL;
        } else {
                CERROR("device %d: no name at detach\n", obd->obd_minor);
        }

        obd->obd_attached = 0;
        obd->obd_type->typ_refcnt--;
        class_put_type(obd->obd_type);
        class_release_dev(obd);
        RETURN(err);
}

static void dump_exports(struct obd_device *obd)
{
        struct obd_export *exp, *n;

        list_for_each_entry_safe(exp, n, &obd->obd_exports, exp_obd_chain) {
                struct ptlrpc_reply_state *rs;
                struct ptlrpc_reply_state *first_reply = NULL;
                int                        nreplies = 0;

                list_for_each_entry (rs, &exp->exp_outstanding_replies,
                                     rs_exp_list) {
                        if (nreplies == 0)
                                first_reply = rs;
                        nreplies++;
                }

                CERROR("%s: %p %s %d %d %d: %p %s\n",
                       obd->obd_name, exp, exp->exp_client_uuid.uuid,
                       atomic_read(&exp->exp_refcount),
                       exp->exp_failed, nreplies, first_reply,
                       nreplies > 3 ? "..." : "");
        }
}

static int class_cleanup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int flags = 0;
        int err = 0;
        char *flag;

        ENTRY;
        if (!obd->obd_set_up) {
                CERROR("Device %d not setup\n", obd->obd_minor);
                RETURN(-ENODEV);
        }
        if (LUSTRE_CFG_BUFLEN(lcfg, 1) > 0) {
                 for (flag = lustre_cfg_string(lcfg, 1); *flag != 0; flag++)
                        switch (*flag) {
                        case 'F':
                                flags |= OBD_OPT_FORCE;
                                break;
                        case 'A':
                                flags |= OBD_OPT_FAILOVER;
                                break;
                        default:
                                CERROR("unrecognised flag '%c'\n",
                                       *flag);
                        }
        }

        /* The one reference that should be remaining is the
         * obd_self_export */
        if (atomic_read(&obd->obd_refcount) <= 1 ||
            flags & OBD_OPT_FORCE) {
                /* this will stop new connections, and need to
                   do it before class_disconnect_exports() */
                obd->obd_stopping = 1;
        }

        if (atomic_read(&obd->obd_refcount) > 1) {
                struct l_wait_info lwi = LWI_TIMEOUT_INTR(1 * HZ, NULL,
                                                          NULL, NULL);
                int rc;

                if (!(flags & OBD_OPT_FORCE)) {
                        CERROR("OBD device %d (%p,%s) has refcount %d\n",
                               obd->obd_minor, obd, obd->obd_name,
                               atomic_read(&obd->obd_refcount));
                        portals_debug_dumplog();
                        dump_exports(obd);
                        GOTO(out, err = -EBUSY);
                }
                class_disconnect_exports(obd, flags);
                CDEBUG(D_IOCTL,
                       "%s: waiting for obd refs to go away: %d\n",
                       obd->obd_name, atomic_read(&obd->obd_refcount));

                rc = l_wait_event(obd->obd_refcount_waitq,
                                  atomic_read(&obd->obd_refcount) < 2, &lwi);
                if (rc == 0) {
                        LASSERT(atomic_read(&obd->obd_refcount) == 1);
                } else {
                        CERROR("wait cancelled cleaning anyway. "
                               "refcount: %d\n",
                               atomic_read(&obd->obd_refcount));
                        dump_exports(obd);
                }
                CDEBUG(D_IOCTL, "%s: awake, now finishing cleanup\n",
                       obd->obd_name);
        }

        if (obd->obd_self_export) {
                err = obd_precleanup(obd, flags);
                if (err)
                        GOTO(out, err);
                class_unlink_export(obd->obd_self_export);
                obd->obd_self_export = NULL;
        }

        err = obd_cleanup(obd, flags);
out:
        if (!err) {
                obd->obd_set_up = obd->obd_stopping = 0;
                obd->obd_type->typ_refcnt--;
                /* XXX this should be an LASSERT */
                if (atomic_read(&obd->obd_refcount) > 0) {
                        CERROR("%s (%p) still has refcount %d after "
                               "cleanup.\n", obd->obd_name, obd,
                               atomic_read(&obd->obd_refcount));
                        dump_exports(obd);
                }
        }

        RETURN(err);
}

int class_add_conn(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct obd_import *imp;
        struct obd_uuid uuid;
        int rc;
        ENTRY;

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
            LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(struct obd_uuid)) {
                CERROR("invalid conn_uuid\n");
                RETURN(-EINVAL);
        }

        if (strcmp(obd->obd_type->typ_name, OBD_MDC_DEVICENAME) &&
            strcmp(obd->obd_type->typ_name, OBD_OSC_DEVICENAME)) {
                CERROR("can't add connection on non-client dev\n");
                RETURN(-EINVAL);
        }

        imp = obd->u.cli.cl_import;
        if (!imp) {
                CERROR("try to add conn on immature client dev\n");
                RETURN(-EINVAL);
        }

        obd_str2uuid(&uuid, lustre_cfg_string(lcfg, 1));
        rc = obd_add_conn(imp, &uuid, lcfg->lcfg_num);

        RETURN(rc);
}

int class_del_conn(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct obd_import *imp;
        struct obd_uuid uuid;
        int rc;
        ENTRY;

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
            LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(struct obd_uuid)) {
                CERROR("invalid conn_uuid\n");
                RETURN(-EINVAL);
        }

        if (strcmp(obd->obd_type->typ_name, OBD_MDC_DEVICENAME) &&
            strcmp(obd->obd_type->typ_name, OBD_OSC_DEVICENAME)) {
                CERROR("can't add connection on non-client dev\n");
                RETURN(-EINVAL);
        }

        imp = obd->u.cli.cl_import;
        if (!imp) {
                CERROR("try to del conn on immature client dev\n");
                RETURN(-EINVAL);
        }

        obd_str2uuid(&uuid, lustre_cfg_string(lcfg, 1));
        rc = obd_del_conn(imp, &uuid);

        RETURN(rc);
}

LIST_HEAD(lustre_profile_list);

struct lustre_profile *class_get_profile(char * prof)
{
        struct lustre_profile *lprof;

        list_for_each_entry(lprof, &lustre_profile_list, lp_list) {
                if (!strcmp(lprof->lp_profile, prof)) {
                        RETURN(lprof);
                }
        }
        RETURN(NULL);
}

int class_add_profile(int proflen, char *prof,
                      int lovlen, char *lov,
                      int lmvlen, char *lmv,
                      int gkclen, char *gkc)
{
        struct lustre_profile *lprof;
        int err = 0;

        OBD_ALLOC(lprof, sizeof(*lprof));
        if (lprof == NULL)
                GOTO(out, err = -ENOMEM);
        INIT_LIST_HEAD(&lprof->lp_list);

        LASSERT(proflen == (strlen(prof) + 1));
        OBD_ALLOC(lprof->lp_profile, proflen);
        if (lprof->lp_profile == NULL)
                GOTO(out, err = -ENOMEM);
        memcpy(lprof->lp_profile, prof, proflen);

        LASSERT(lovlen == (strlen(lov) + 1));
        OBD_ALLOC(lprof->lp_lov, lovlen);
        if (lprof->lp_profile == NULL)
                GOTO(out, err = -ENOMEM);
        memcpy(lprof->lp_lov, lov, lovlen);

        if (lmvlen > 0) {
                LASSERT(lmvlen == (strlen(lmv) + 1));
                OBD_ALLOC(lprof->lp_lmv, lmvlen);
                if (lprof->lp_lmv == NULL)
                        GOTO(out, err = -ENOMEM);
                memcpy(lprof->lp_lmv, lmv, lmvlen);
        }
        if (gkclen > 0 ) {
                LASSERT(gkclen == (strlen(gkc) + 1));
                OBD_ALLOC(lprof->lp_gkc, gkclen);
                if (lprof->lp_gkc == NULL)
                        GOTO(out, err = -ENOMEM);
                memcpy(lprof->lp_gkc, gkc, gkclen);
        }
        
        list_add(&lprof->lp_list, &lustre_profile_list);
out:
        RETURN(err);
}

void class_del_profile(char *prof)
{
        struct lustre_profile *lprof;

        lprof = class_get_profile(prof);
        if (lprof) {
                list_del(&lprof->lp_list);
                OBD_FREE(lprof->lp_profile, strlen(lprof->lp_profile) + 1);
                OBD_FREE(lprof->lp_lov, strlen(lprof->lp_lov) + 1);
                if (lprof->lp_lmv)
                        OBD_FREE(lprof->lp_lmv, strlen(lprof->lp_lmv) + 1);
                if (lprof->lp_gkc)
                        OBD_FREE(lprof->lp_gkc, strlen(lprof->lp_gkc) + 1);
                OBD_FREE(lprof, sizeof *lprof);
        }
}

int class_process_config(struct lustre_cfg *lcfg)
{
        struct obd_device *obd;
        char str[PTL_NALFMT_SIZE];
        int err;
        ENTRY;

        LASSERT(lcfg && !IS_ERR(lcfg));

        CDEBUG(D_CONFIG, "processing cmd: %x\n", lcfg->lcfg_command);

        /* Commands that don't need a device */
        switch(lcfg->lcfg_command) {
        case LCFG_ATTACH: {
                err = class_attach(lcfg);
                GOTO(out, err);
        }
        case LCFG_ADD_UUID: {
                CDEBUG(D_CONFIG, "adding mapping from uuid %s to nid "LPX64
                       " (%s), nal %x\n", lustre_cfg_string(lcfg, 1),
                       lcfg->lcfg_nid,
                       portals_nid2str(lcfg->lcfg_nal, lcfg->lcfg_nid, str),
                       lcfg->lcfg_nal);

               err = class_add_uuid(lustre_cfg_string(lcfg, 1), lcfg->lcfg_nid,
                                    lcfg->lcfg_nal);
               GOTO(out, err);
        }
        case LCFG_DEL_UUID: {
                CDEBUG(D_CONFIG, "removing mappings for uuid %s\n",
                       (lcfg->lcfg_bufcount < 2 || LUSTRE_CFG_BUFLEN(lcfg, 1) == 0)
                       ? "<all uuids>" : lustre_cfg_string(lcfg, 1));

                err = class_del_uuid(lustre_cfg_string(lcfg, 1));
                GOTO(out, err);
        }
        case LCFG_MOUNTOPT: {
                CDEBUG(D_CONFIG, "mountopt: profile %s osc %s mdc %s gkc %s \n",
                       lustre_cfg_string(lcfg, 1),
                       lustre_cfg_string(lcfg, 2),
                       lustre_cfg_string(lcfg, 3),
                       lustre_cfg_string(lcfg, 4));
                /* set these mount options somewhere, so ll_fill_super
                 * can find them. */
                err = class_add_profile(LUSTRE_CFG_BUFLEN(lcfg, 1),
                                        lustre_cfg_string(lcfg, 1),
                                        LUSTRE_CFG_BUFLEN(lcfg, 2),
                                        lustre_cfg_string(lcfg, 2),
                                        LUSTRE_CFG_BUFLEN(lcfg, 3),
                                        lustre_cfg_string(lcfg, 3),
                                        LUSTRE_CFG_BUFLEN(lcfg, 4),
                                        lustre_cfg_string(lcfg, 4));
                GOTO(out, err);
        }
        case LCFG_DEL_MOUNTOPT: {
                CDEBUG(D_CONFIG, "mountopt: profile %s\n",
                       lustre_cfg_string(lcfg, 1));
                /* set these mount options somewhere, so ll_fill_super
                 * can find them. */
                class_del_profile(lustre_cfg_string(lcfg, 1));
                GOTO(out, err = 0);
        }
        case LCFG_SET_TIMEOUT: {
                CDEBUG(D_CONFIG, "changing lustre timeout from %d to %d\n",
                       obd_timeout,
                       lcfg->lcfg_num);
                obd_timeout = lcfg->lcfg_num;
                GOTO(out, err = 0);
        }
        case LCFG_SET_UPCALL: {
                CDEBUG(D_CONFIG, "setting lustre ucpall to: %s\n",
                       lustre_cfg_string(lcfg, 1));
                if (LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof obd_lustre_upcall)
                        GOTO(out, err = -EINVAL);
                strncpy(obd_lustre_upcall, lustre_cfg_string(lcfg, 1),
                        sizeof (obd_lustre_upcall));
                GOTO(out, err = 0);
        }
        }
        
        /* Commands that require a device */
        obd = class_name2obd(lustre_cfg_string(lcfg, 0));
        if (obd == NULL) {
                if (!LUSTRE_CFG_BUFLEN(lcfg, 0))
                        CERROR("this lcfg command %d requires a device name\n", 
                               lcfg->lcfg_command);
                else
                        CERROR("no device for: %s\n",
                               lustre_cfg_string(lcfg, 0));

                GOTO(out, err = -EINVAL);
        }

        switch(lcfg->lcfg_command) {
        case LCFG_SETUP: {
                err = class_setup(obd, lcfg);
                GOTO(out, err);
        }
        case LCFG_DETACH: {
                err = class_detach(obd, lcfg);
                GOTO(out, err = 0);
        }
        case LCFG_CLEANUP: {
                err = class_cleanup(obd, lcfg);
                GOTO(out, err = 0);
        }
        case LCFG_ADD_CONN: {
                err = class_add_conn(obd, lcfg);
                GOTO(out, err = 0);
        }
        case LCFG_DEL_CONN: {
                err = class_del_conn(obd, lcfg);
                GOTO(out, err = 0);
        }
        default: {
                err = obd_process_config(obd, sizeof(*lcfg), lcfg);
                GOTO(out, err);

        }
        }
out:
        return err;
}

static int class_config_parse_handler(struct llog_handle * handle,
                                      struct llog_rec_hdr *rec, void *data)
{
        struct config_llog_instance *cfg = data;
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        int rc = 0;
        ENTRY;

        if (rec->lrh_type == OBD_CFG_REC) {
                struct lustre_cfg *lcfg, *lcfg_new;
                struct lustre_cfg_bufs bufs;
                char *inst_name = NULL;
                int inst_len = 0;

                lcfg = (struct lustre_cfg *)cfg_buf;
                if (lcfg->lcfg_version == __swab32(LUSTRE_CFG_VERSION))
                        lustre_swab_lustre_cfg(lcfg);

                rc = lustre_cfg_sanity_check(cfg_buf, cfg_len);
                if (rc)
                        GOTO(out, rc);

                lustre_cfg_bufs_init(&bufs, lcfg);
                if (cfg && cfg->cfg_instance) {
                        if (LUSTRE_CFG_BUFLEN(lcfg, 0) > 0) {
                                inst_len = LUSTRE_CFG_BUFLEN(lcfg, 0) +
                                        strlen(cfg->cfg_instance) + 1;
                                OBD_ALLOC(inst_name, inst_len);
                                if (inst_name == NULL)
                                        GOTO(out, rc = -ENOMEM);
                                sprintf(inst_name, "%s-%s",
                                        lustre_cfg_string(lcfg, 0),
                                        cfg->cfg_instance);
                                lustre_cfg_bufs_set_string(&bufs, 0, inst_name);
                        }
                        if (lcfg->lcfg_command == LCFG_SETUP) {
                                /*add cfg_instance to the end of lcfg buffers*/
                                lustre_cfg_bufs_set_string(&bufs,
                                                           bufs.lcfg_bufcount, 
                                                           cfg->cfg_instance); 
                        }
                }

                if (cfg && (lcfg->lcfg_command == LCFG_ATTACH)){
                        /*Very Dirty Hack fix here, for mds add, 
                         *the mdc in mds should not 
                         *change uuid FIXME: Wangdi
                         */
                         if (memcmp(lustre_cfg_string(lcfg, 1), OBD_MDC_DEVICENAME, 
                                    strlen(OBD_MDC_DEVICENAME)) || 
                             (cfg->cfg_flags & CFG_MODIFY_UUID_FL))
                                lustre_cfg_bufs_set_string(&bufs, 2,
                                                   (char *)cfg->cfg_uuid.uuid);
                }
                lcfg_new = lustre_cfg_new(lcfg->lcfg_command, &bufs);

                lcfg_new->lcfg_num   = lcfg->lcfg_num;
                lcfg_new->lcfg_flags = lcfg->lcfg_flags;
                lcfg_new->lcfg_nid   = lcfg->lcfg_nid;
                lcfg_new->lcfg_nal   = lcfg->lcfg_nal;

                rc = class_process_config(lcfg_new);
                lustre_cfg_free(lcfg_new);

                if (inst_name)
                        OBD_FREE(inst_name, inst_len);
        } else if (rec->lrh_type == PTL_CFG_REC) {
                struct portals_cfg *pcfg = (struct portals_cfg *)cfg_buf;
                if (pcfg->pcfg_command == NAL_CMD_REGISTER_MYNID &&
                    cfg->cfg_local_nid != PTL_NID_ANY) {
                        pcfg->pcfg_nid = cfg->cfg_local_nid;
                }

                rc = libcfs_nal_cmd(pcfg);
        } else {
                CERROR("unrecognized record type: 0x%x\n", rec->lrh_type);
        }
out:
        RETURN(rc);
}

int class_config_process_llog(struct llog_ctxt *ctxt, char *name,
                              struct config_llog_instance *cfg)
{
        struct llog_handle *llh;
        int rc, rc2;
        ENTRY;

        rc = llog_open(ctxt, &llh, NULL, name, 0);
        if (rc)
                RETURN(rc);

        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc == 0)
                rc = llog_process(llh, class_config_parse_handler, cfg, NULL);

        rc2 = llog_close(llh);
        if (rc == 0)
                rc = rc2;

        RETURN(rc);
}

int class_config_dump_handler(struct llog_handle * handle,
                              struct llog_rec_hdr *rec, void *data)
{
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        int rc = 0;
        ENTRY;
        if (rec->lrh_type == OBD_CFG_REC) {
                struct lustre_cfg *lcfg;
                int i;

                rc = lustre_cfg_sanity_check(cfg_buf, cfg_len);
                if (rc)
                        GOTO(out, rc);
                lcfg = (struct lustre_cfg *)cfg_buf;

                CDEBUG(D_INFO, "lcfg command: %x\n", lcfg->lcfg_command);
                if (LUSTRE_CFG_BUFLEN(lcfg, 0) > 0)
                        CDEBUG(D_INFO, "     devname: %s\n",
                               lustre_cfg_string(lcfg, 0));
                if (lcfg->lcfg_flags)
                        CDEBUG(D_INFO, "       flags: %x\n", lcfg->lcfg_flags);
                if (lcfg->lcfg_nid)
                        CDEBUG(D_INFO, "         nid: "LPX64"\n",
                               lcfg->lcfg_nid);
                if (lcfg->lcfg_nal)
                        CDEBUG(D_INFO, "         nal: %x\n", lcfg->lcfg_nal);
                if (lcfg->lcfg_num)
                        CDEBUG(D_INFO, "         nal: %x\n", lcfg->lcfg_num);
                for (i = 1; i < lcfg->lcfg_bufcount; i++)
                        if (LUSTRE_CFG_BUFLEN(lcfg, i) > 0)
                                CDEBUG(D_INFO, "     inlbuf%d: %s\n", i,
                                       lustre_cfg_string(lcfg, i));
        } else if (rec->lrh_type == PTL_CFG_REC) {
                struct portals_cfg *pcfg = (struct portals_cfg *)cfg_buf;
                CDEBUG(D_INFO, "pcfg command: %d\n", pcfg->pcfg_command);
                if (pcfg->pcfg_nal)
                        CDEBUG(D_INFO, "         nal: %x\n",
                               pcfg->pcfg_nal);
                if (pcfg->pcfg_gw_nal)
                        CDEBUG(D_INFO, "      gw_nal: %x\n",
                               pcfg->pcfg_gw_nal);
                if (pcfg->pcfg_nid)
                        CDEBUG(D_INFO, "         nid: "LPX64"\n",
                               pcfg->pcfg_nid);
                if (pcfg->pcfg_nid2)
                        CDEBUG(D_INFO, "         nid: "LPX64"\n",
                               pcfg->pcfg_nid2);
                if (pcfg->pcfg_nid3)
                        CDEBUG(D_INFO, "         nid: "LPX64"\n",
                               pcfg->pcfg_nid3);
                if (pcfg->pcfg_misc)
                        CDEBUG(D_INFO, "         nid: %d\n",
                               pcfg->pcfg_misc);
                if (pcfg->pcfg_id)
                        CDEBUG(D_INFO, "          id: %x\n",
                               pcfg->pcfg_id);
                if (pcfg->pcfg_flags)
                        CDEBUG(D_INFO, "       flags: %x\n",
                               pcfg->pcfg_flags);
        } else {
                CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
                rc = -EINVAL;
        }
out:
        RETURN(rc);
}

int class_config_dump_llog(struct llog_ctxt *ctxt, char *name,
                           struct config_llog_instance *cfg)
{
        struct llog_handle *llh;
        int rc, rc2;
        ENTRY;

        rc = llog_open(ctxt, &llh, NULL, name, 0);
        if (rc)
                RETURN(rc);

        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc == 0)
                rc = llog_process(llh, class_config_dump_handler, cfg, NULL);

        rc2 = llog_close(llh);
        if (rc == 0)
                rc = rc2;

        RETURN(rc);
}
