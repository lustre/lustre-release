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
int class_attach(struct lustre_cfg *lcfg)
{
        struct obd_type *type;
        struct obd_device *obd = NULL;
        char *typename, *name, *namecopy, *uuid;
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

        CDEBUG(D_IOCTL, "attach type %s name: %s uuid: %s\n",
               MKSTR(typename), MKSTR(name), MKSTR(uuid));

        /* find the type */
        type = class_get_type(typename);
        if (!type) {
                CERROR("OBD: unknown type: %s\n", typename);
                RETURN(-ENODEV);
        }
        cleanup_phase = 1;  /* class_put_type */

        len = strlen(name) + 1;
        OBD_ALLOC(namecopy, len);
        if (!namecopy)
                GOTO(out, rc = -ENOMEM);
        memcpy(namecopy, name, len);
        cleanup_phase = 2; /* free obd_name */

        obd = class_newdev(type, namecopy);
        if (obd == NULL) {
                /* Already exists or out of obds */
                CERROR("Can't create device %s\n", name);
                GOTO(out, rc = -EEXIST);
        }
        cleanup_phase = 3;  /* class_release_dev */

        INIT_LIST_HEAD(&obd->obd_exports);
        INIT_LIST_HEAD(&obd->obd_exports_timed);
        obd->obd_num_exports = 0;
        spin_lock_init(&obd->obd_dev_lock);
        spin_lock_init(&obd->obd_osfs_lock);
        obd->obd_osfs_age = jiffies - 1000 * HZ;

        /* XXX belongs in setup not attach  */
        /* recovery data */
        init_timer(&obd->obd_recovery_timer);
        spin_lock_init(&obd->obd_processing_task_lock);
        init_waitqueue_head(&obd->obd_next_transno_waitq);
        INIT_LIST_HEAD(&obd->obd_recovery_queue);
        INIT_LIST_HEAD(&obd->obd_delayed_reply_queue);

        spin_lock_init(&obd->obd_uncommitted_replies_lock);
        INIT_LIST_HEAD(&obd->obd_uncommitted_replies);

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

        /* Detach drops this */
        atomic_set(&obd->obd_refcount, 1);

        obd->obd_attached = 1;
        type->typ_refcnt++;
        CDEBUG(D_IOCTL, "OBD: dev %d attached type %s\n",
               obd->obd_minor, typename);
        RETURN(0);
 out:
        switch (cleanup_phase) {
        case 3:
                class_release_dev(obd);
        case 2:
                OBD_FREE(namecopy, strlen(namecopy) + 1);
        case 1:
                class_put_type(type);
        }
        return rc;
}

int class_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
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

        if (obd->obd_set_up) {
                CERROR("Device %d already setup (type %s)\n",
                       obd->obd_minor, obd->obd_type->typ_name);
                RETURN(-EEXIST);
        }

        /* is someone else setting us up right now? (attach inits spinlock) */
        spin_lock(&obd->obd_dev_lock);
        if (obd->obd_starting) {
                spin_unlock(&obd->obd_dev_lock);
                CERROR("Device %d setup in progress (type %s)\n",
                       obd->obd_minor, obd->obd_type->typ_name);
                RETURN(-EEXIST);
        }
        /* just leave this on forever.  I can't use obd_set_up here because
           other fns check that status, and we're not actually set up yet. */
        obd->obd_starting = 1;
        spin_unlock(&obd->obd_dev_lock);

        exp = class_new_export(obd);
        if (exp == NULL)
                RETURN(err);
        memcpy(&exp->exp_client_uuid, &obd->obd_uuid,
               sizeof(exp->exp_client_uuid));
        obd->obd_self_export = exp;
        list_del_init(&exp->exp_obd_chain_timed);
        class_export_put(exp);

        err = obd_setup(obd, sizeof(*lcfg), lcfg);
        if (err)
                GOTO(err_exp, err);

        obd->obd_type->typ_refcnt++;
        obd->obd_set_up = 1;
        spin_lock(&obd->obd_dev_lock);
        /* cleanup drops this */
        atomic_inc(&obd->obd_refcount);
        spin_unlock(&obd->obd_dev_lock);

        CDEBUG(D_IOCTL, "finished setup of obd %s (uuid %s)\n",
               obd->obd_name, obd->obd_uuid.uuid);

        RETURN(0);

err_exp:
        class_unlink_export(obd->obd_self_export);
        obd->obd_self_export = NULL;
        obd->obd_starting = 0;
        RETURN(err);
}

static int __class_detach(struct obd_device *obd)
{
        int err = 0;
        ENTRY;

        CDEBUG(D_CONFIG, "destroying obd %d (%s)\n",
               obd->obd_minor, obd->obd_name);

        if (OBP(obd, detach))
                err = OBP(obd,detach)(obd);

        if (obd->obd_name) {
                OBD_FREE(obd->obd_name, strlen(obd->obd_name)+1);
                obd->obd_name = NULL;
        } else {
                CERROR("device %d: no name at detach\n", obd->obd_minor);
        }

        LASSERT(OBT(obd));
        /* Attach took type refcount */
        obd->obd_type->typ_refcnt--;
        class_put_type(obd->obd_type);
        class_release_dev(obd);
        RETURN(err);
}

int class_detach(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        ENTRY;

        if (obd->obd_set_up) {
                CERROR("OBD device %d still set up\n", obd->obd_minor);
                RETURN(-EBUSY);
        }

        spin_lock(&obd->obd_dev_lock);
        if (!obd->obd_attached) {
                spin_unlock(&obd->obd_dev_lock);
                CERROR("OBD device %d not attached\n", obd->obd_minor);
                RETURN(-ENODEV);
        }
        obd->obd_attached = 0;
        spin_unlock(&obd->obd_dev_lock);

        CDEBUG(D_IOCTL, "detach on obd %s (uuid %s)\n",
               obd->obd_name, obd->obd_uuid.uuid);

        class_decref(obd);
        RETURN(0);
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

                CDEBUG(D_IOCTL, "%s: %p %s %s %d %d %d: %p %s\n",
                       obd->obd_name, exp, exp->exp_client_uuid.uuid,
                       obd_export_nid2str(exp),
                       atomic_read(&exp->exp_refcount),
                       exp->exp_failed, nreplies, first_reply,
                       nreplies > 3 ? "..." : "");
        }
}

int class_cleanup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int err = 0;
        char *flag;
        ENTRY;

        OBD_RACE(OBD_FAIL_LDLM_RECOV_CLIENTS);

        if (!obd->obd_set_up) {
                CERROR("Device %d not setup\n", obd->obd_minor);
                RETURN(-ENODEV);
        }

        spin_lock(&obd->obd_dev_lock);
        if (obd->obd_stopping) {
                spin_unlock(&obd->obd_dev_lock);
                CERROR("OBD %d already stopping\n", obd->obd_minor);
                RETURN(-ENODEV);
        }
        /* Leave this on forever */
        obd->obd_stopping = 1;
        spin_unlock(&obd->obd_dev_lock);

        if (lcfg->lcfg_bufcount >= 2 && LUSTRE_CFG_BUFLEN(lcfg, 1) > 0) {
                for (flag = lustre_cfg_string(lcfg, 1); *flag != 0; flag++)
                        switch (*flag) {
                        case 'F':
                                obd->obd_force = 1;
                                break;
                        case 'A':
                                LCONSOLE_WARN("Failing %s by user command\n",
                                       obd->obd_name);
                                obd->obd_fail = 1;
                                obd->obd_no_transno = 1;
                                obd->obd_no_recov = 1;
                                /* Set the obd readonly if we can */
                                if (OBP(obd, iocontrol))
                                        obd_iocontrol(OBD_IOC_SET_READONLY,
                                                      obd->obd_self_export,
                                                      0, NULL, NULL);
                                break;
                        default:
                                CERROR("unrecognised flag '%c'\n",
                                       *flag);
                        }
        }

        /* The three references that should be remaining are the
         * obd_self_export and the attach and setup references. */
        if (atomic_read(&obd->obd_refcount) > 3) {
                if (!(obd->obd_fail || obd->obd_force)) {
                        CERROR("OBD %s is still busy with %d references\n"
                               "You should stop active file system users,"
                               " or use the --force option to cleanup.\n",
                               obd->obd_name, atomic_read(&obd->obd_refcount));
                        dump_exports(obd);
                        GOTO(out, err = -EBUSY);
                }
                CDEBUG(D_IOCTL, "%s: forcing exports to disconnect: %d\n",
                       obd->obd_name, atomic_read(&obd->obd_refcount) - 1);
                dump_exports(obd);
                class_disconnect_exports(obd);
        }

        LASSERT(obd->obd_self_export);

        /* Precleanup stage 1, we must make sure all exports (other than the
           self-export) get destroyed. */
        err = obd_precleanup(obd, 1);
        if (err)
                CERROR("Precleanup %s returned %d\n",
                       obd->obd_name, err);

        class_decref(obd);
        obd->obd_set_up = 0;
        obd->obd_type->typ_refcnt--;

        RETURN(0);
out:
        /* Allow a failed cleanup to try again. */
        obd->obd_stopping = 0;
        RETURN(err);
}

void class_decref(struct obd_device *obd)
{
        int err;
        int refs;

        spin_lock(&obd->obd_dev_lock);
        atomic_dec(&obd->obd_refcount);
        refs = atomic_read(&obd->obd_refcount);
        spin_unlock(&obd->obd_dev_lock);

        CDEBUG(D_INFO, "Decref %s now %d\n", obd->obd_name, refs);

        if ((refs == 1) && obd->obd_stopping) {
                /* All exports (other than the self-export) have been
                   destroyed; there should be no more in-progress ops
                   by this point.*/
                /* if we're not stopping, we didn't finish setup */
                /* Precleanup stage 2,  do other type-specific
                   cleanup requiring the self-export. */
                err = obd_precleanup(obd, 2);
                if (err)
                        CERROR("Precleanup %s returned %d\n",
                               obd->obd_name, err);
                obd->obd_self_export->exp_flags |=
                        (obd->obd_fail ? OBD_OPT_FAILOVER : 0) |
                        (obd->obd_force ? OBD_OPT_FORCE : 0);
                /* note that we'll recurse into class_decref again */
                class_unlink_export(obd->obd_self_export);
                return;
        }

        if (refs == 0) {
                CDEBUG(D_CONFIG, "finishing cleanup of obd %s (%s)\n",
                       obd->obd_name, obd->obd_uuid.uuid);
                LASSERT(!obd->obd_attached);
                if (obd->obd_stopping) {
                        /* If we're not stopping, we were never set up */
                        err = obd_cleanup(obd);
                        if (err)
                                CERROR("Cleanup %s returned %d\n",
                                       obd->obd_name, err);
                }
                err = __class_detach(obd);
                if (err)
                        CERROR("Detach returned %d\n", err);
        }
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
        if (strcmp(obd->obd_type->typ_name, "mdc") &&
            strcmp(obd->obd_type->typ_name, "osc")) {
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
        if (strcmp(obd->obd_type->typ_name, "mdc") &&
            strcmp(obd->obd_type->typ_name, "osc")) {
                CERROR("can't del connection on non-client dev\n");
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

int class_add_profile(int proflen, char *prof, int osclen, char *osc,
                      int mdclen, char *mdc)
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

        LASSERT(osclen == (strlen(osc) + 1));
        OBD_ALLOC(lprof->lp_osc, osclen);
        if (lprof->lp_profile == NULL)
                GOTO(out, err = -ENOMEM);
        memcpy(lprof->lp_osc, osc, osclen);

        if (mdclen > 0) {
                LASSERT(mdclen == (strlen(mdc) + 1));
                OBD_ALLOC(lprof->lp_mdc, mdclen);
                if (lprof->lp_mdc == NULL)
                        GOTO(out, err = -ENOMEM);
                memcpy(lprof->lp_mdc, mdc, mdclen);
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
                OBD_FREE(lprof->lp_osc, strlen(lprof->lp_osc) + 1);
                if (lprof->lp_mdc)
                        OBD_FREE(lprof->lp_mdc, strlen(lprof->lp_mdc) + 1);
                OBD_FREE(lprof, sizeof *lprof);
        }
}

int class_process_config(struct lustre_cfg *lcfg)
{
        struct obd_device *obd;
        int err;

        LASSERT(lcfg && !IS_ERR(lcfg));
        CDEBUG(D_IOCTL, "processing cmd: %x\n", lcfg->lcfg_command);

        /* Commands that don't need a device */
        switch(lcfg->lcfg_command) {
        case LCFG_ATTACH: {
                err = class_attach(lcfg);
                GOTO(out, err);
        }
        case LCFG_ADD_UUID: {
                CDEBUG(D_IOCTL, "adding mapping from uuid %s to nid "LPX64
                       " (%s)\n", lustre_cfg_string(lcfg, 1),
                       lcfg->lcfg_nid, libcfs_nid2str(lcfg->lcfg_nid));

                err = class_add_uuid(lustre_cfg_string(lcfg, 1), lcfg->lcfg_nid);
                GOTO(out, err);
        }
        case LCFG_DEL_UUID: {
                CDEBUG(D_IOCTL, "removing mappings for uuid %s\n",
                       (lcfg->lcfg_bufcount < 2 || LUSTRE_CFG_BUFLEN(lcfg, 1) == 0)
                       ? "<all uuids>" : lustre_cfg_string(lcfg, 1));

                err = class_del_uuid(lustre_cfg_string(lcfg, 1));
                GOTO(out, err);
        }
        case LCFG_MOUNTOPT: {
                CDEBUG(D_IOCTL, "mountopt: profile %s osc %s mdc %s\n",
                       lustre_cfg_string(lcfg, 1),
                       lustre_cfg_string(lcfg, 2),
                       lustre_cfg_string(lcfg, 3));
                /* set these mount options somewhere, so ll_fill_super
                 * can find them. */
                err = class_add_profile(LUSTRE_CFG_BUFLEN(lcfg, 1),
                                        lustre_cfg_string(lcfg, 1),
                                        LUSTRE_CFG_BUFLEN(lcfg, 2),
                                        lustre_cfg_string(lcfg, 2),
                                        LUSTRE_CFG_BUFLEN(lcfg, 3),
                                        lustre_cfg_string(lcfg, 3));
                GOTO(out, err);
        }
        case LCFG_DEL_MOUNTOPT: {
                CDEBUG(D_IOCTL, "mountopt: profile %s\n",
                       lustre_cfg_string(lcfg, 1));
                /* set these mount options somewhere, so ll_fill_super
                 * can find them. */
                class_del_profile(lustre_cfg_string(lcfg, 1));
                GOTO(out, err = 0);
        }
        case LCFG_SET_TIMEOUT: {
                CDEBUG(D_IOCTL, "changing lustre timeout from %d to %d\n",
                       obd_timeout, lcfg->lcfg_num);
                obd_timeout = max(lcfg->lcfg_num, 1U);
                if (ldlm_timeout >= obd_timeout)
                        ldlm_timeout = max(obd_timeout / 3, 1U);
                else if (ldlm_timeout < 10 && obd_timeout >= ldlm_timeout * 4)
                        ldlm_timeout = min(obd_timeout / 3, 30U);
                GOTO(out, err = 0);
        }
        case LCFG_SET_UPCALL: {
                CDEBUG(D_IOCTL, "setting lustre ucpall to: %s\n",
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
                        CERROR("this lcfg command requires a device name\n");
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

static int class_config_llog_handler(struct llog_handle * handle,
                                     struct llog_rec_hdr *rec, void *data)
{
        struct config_llog_instance *cfg = data;
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        int rc = 0;
        ENTRY;
        switch (rec->lrh_type) {
        case OBD_CFG_REC: {
                struct lustre_cfg *lcfg, *lcfg_new;
                struct lustre_cfg_bufs bufs;
                char *inst_name = NULL;
                int inst_len = 0;
                int inst = 0;

                lcfg = (struct lustre_cfg *)cfg_buf;
                if (lcfg->lcfg_version == __swab32(LUSTRE_CFG_VERSION))
                        lustre_swab_lustre_cfg(lcfg);

                rc = lustre_cfg_sanity_check(cfg_buf, cfg_len);
                if (rc)
                        GOTO(out, rc);

                lustre_cfg_bufs_init(&bufs, lcfg);

                if (cfg && cfg->cfg_instance && LUSTRE_CFG_BUFLEN(lcfg, 0) > 0) {
                        inst = 1;
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

                if (cfg && lcfg->lcfg_command == LCFG_ATTACH) {
                        lustre_cfg_bufs_set_string(&bufs, 2, cfg->cfg_uuid.uuid);
                }

                lcfg_new = lustre_cfg_new(lcfg->lcfg_command, &bufs);

                lcfg_new->lcfg_num   = lcfg->lcfg_num;
                lcfg_new->lcfg_flags = lcfg->lcfg_flags;

                /* XXX Hack to try to remain binary compatible with
                 * pre-newconfig logs */
                if (lcfg->lcfg_nal != 0 &&      /* pre-newconfig log? */
                    (lcfg->lcfg_nid >> 32) == 0) {
                        __u32 addr = (__u32)(lcfg->lcfg_nid & 0xffffffff);

                        lcfg_new->lcfg_nid =
                                PTL_MKNID(PTL_MKNET(lcfg->lcfg_nal, 0), addr);
                        CWARN("Converted pre-newconfig NAL %d NID %x to %s\n",
                              lcfg->lcfg_nal, addr,
                              libcfs_nid2str(lcfg_new->lcfg_nid));
                } else {
                        lcfg_new->lcfg_nid = lcfg->lcfg_nid;
                }

                lcfg_new->lcfg_nal = 0; /* illegal value for obsolete field */

                rc = class_process_config(lcfg_new);
                lustre_cfg_free(lcfg_new);

                if (inst)
                        OBD_FREE(inst_name, inst_len);
                break;
        }
        case PTL_CFG_REC: {
                CWARN("Ignoring obsolete portals config\n");
                break;
        }
        default:
                CERROR("Unknown llog record type %#x encountered\n",
                       rec->lrh_type);
                break;
        }
out:
        RETURN(rc);
}

int class_config_parse_llog(struct llog_ctxt *ctxt, char *name,
                            struct config_llog_instance *cfg)
{
        struct llog_handle *llh;
        int rc, rc2;
        ENTRY;

        CDEBUG(D_INFO, "looking up llog %s\n", name);
        rc = llog_create(ctxt, &llh, NULL, name);
        if (rc)
                RETURN(rc);

        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(parse_out, rc);

        rc = llog_process(llh, class_config_llog_handler, cfg, NULL);
parse_out:
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
                        CDEBUG(D_INFO, "         nal: %x (obsolete)\n", lcfg->lcfg_nal);
                if (lcfg->lcfg_num)
                        CDEBUG(D_INFO, "         num: %x\n", lcfg->lcfg_num);
                for (i = 1; i < lcfg->lcfg_bufcount; i++)
                        if (LUSTRE_CFG_BUFLEN(lcfg, i) > 0)
                                CDEBUG(D_INFO, "     inlbuf%d: %s\n", i,
                                       lustre_cfg_string(lcfg, i));
        } else if (rec->lrh_type == PTL_CFG_REC) {
                CDEBUG(D_INFO, "Obsolete pcfg command\n");
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

        rc = llog_create(ctxt, &llh, NULL, name);
        if (rc)
                RETURN(rc);

        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(parse_out, rc);

        rc = llog_process(llh, class_config_dump_handler, cfg, NULL);
parse_out:
        rc2 = llog_close(llh);
        if (rc == 0)
                rc = rc2;

        RETURN(rc);

}
