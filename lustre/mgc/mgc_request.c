/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mgc/mgc_request.c
 *  Lustre Management Client
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Nathan Rutman <nathan@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MGC
#define D_MGC D_CONFIG /*|D_WARNING*/

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
# include <linux/miscdevice.h>
# include <linux/init.h>
#else
# include <liblustre.h>
#endif

#include <obd_class.h>
#include <lustre_dlm.h>
#include <lustre_log.h>
#include <lustre_fsfilt.h>
#include <lustre_disk.h>

int mgc_logname2resid(char *logname, struct ldlm_res_id *res_id)
{
        char *name_end;
        int len;
        __u64 resname = 0;

        /* fsname is at most 8 chars long at the beginning of the logname
           e.g. "lustre-MDT0001" or "lustre" */
        name_end = strrchr(logname, '-');
        if (name_end)
                len = name_end - logname;
        else
                len = strlen(logname);
        if (len > 8) {
                CERROR("fsname too long: %s\n", logname);
                return -EINVAL;
        }
        if (len <= 0) {
                CERROR("missing fsname: %s\n", logname);
                return -EINVAL;
        }
        memcpy(&resname, logname, len);

        memset(res_id, 0, sizeof(*res_id));

        /* Always use the same endianness for the resid */
        res_id->name[0] = cpu_to_le64(resname);
        CDEBUG(D_MGC, "log %s to resid "LPX64"/"LPX64" (%.8s)\n", logname,
               res_id->name[0], res_id->name[1], (char *)&res_id->name[0]);
        return 0;
}
EXPORT_SYMBOL(mgc_logname2resid);

/********************** config llog list **********************/
static struct list_head config_llog_list = LIST_HEAD_INIT(config_llog_list);
static spinlock_t       config_list_lock = SPIN_LOCK_UNLOCKED;

/* Take a reference to a config log */
static int config_log_get(struct config_llog_data *cld)
{
        ENTRY;
        CDEBUG(D_INFO, "log %s refs %d\n", cld->cld_logname,
               atomic_read(&cld->cld_refcount));
        if (cld->cld_stopping)
                RETURN(1);
        atomic_inc(&cld->cld_refcount);
        RETURN(0);
}

/* Drop a reference to a config log.  When no longer referenced,
   we can free the config log data */
static void config_log_put(struct config_llog_data *cld)
{
        ENTRY;
        CDEBUG(D_INFO, "log %s refs %d\n", cld->cld_logname,
               atomic_read(&cld->cld_refcount));
        if (atomic_dec_and_test(&cld->cld_refcount)) {
                CDEBUG(D_MGC, "dropping config log %s\n", cld->cld_logname);
                class_export_put(cld->cld_mgcexp);
                OBD_FREE(cld->cld_logname, strlen(cld->cld_logname) + 1);
                if (cld->cld_cfg.cfg_instance != NULL)
                        OBD_FREE(cld->cld_cfg.cfg_instance,
                                 strlen(cld->cld_cfg.cfg_instance) + 1);
                OBD_FREE(cld, sizeof(*cld));
        }
        EXIT;
}

/* Find a config log by name */
static struct config_llog_data *config_log_find(char *logname,
                                                struct config_llog_instance *cfg)
{
        struct list_head *tmp;
        struct config_llog_data *cld;
        char *logid = logname;
        int match_instance = 0;
        ENTRY;

        if (cfg && cfg->cfg_instance) {
                match_instance++;
                logid = cfg->cfg_instance;
        }
        if (!logid) {
                CERROR("No log specified\n");
                RETURN(ERR_PTR(-EINVAL));
        }

        spin_lock(&config_list_lock);
        list_for_each(tmp, &config_llog_list) {
                cld = list_entry(tmp, struct config_llog_data, cld_list_chain);
                if (match_instance && cld->cld_cfg.cfg_instance &&
                    strcmp(logid, cld->cld_cfg.cfg_instance) == 0)
                        goto out_found;
                if (!match_instance &&
                    strcmp(logid, cld->cld_logname) == 0)
                        goto out_found;
        }
        spin_unlock(&config_list_lock);

        CERROR("can't get log %s\n", logid);
        RETURN(ERR_PTR(-ENOENT));
out_found:
        atomic_inc(&cld->cld_refcount);
        spin_unlock(&config_list_lock);
        RETURN(cld);
}

/* Add this log to our list of active logs.
   We have one active log per "mount" - client instance or servername.
   Each instance may be at a different point in the log. */
static int config_log_add(char *logname, struct config_llog_instance *cfg,
                          struct super_block *sb)
{
        struct config_llog_data *cld;
        struct lustre_sb_info *lsi = s2lsi(sb);
        int rc;
        ENTRY;

        CDEBUG(D_MGC, "adding config log %s:%s\n", logname, cfg->cfg_instance);

        OBD_ALLOC(cld, sizeof(*cld));
        if (!cld)
                RETURN(-ENOMEM);
        OBD_ALLOC(cld->cld_logname, strlen(logname) + 1);
        if (!cld->cld_logname) {
                OBD_FREE(cld, sizeof(*cld));
                RETURN(-ENOMEM);
        }
        strcpy(cld->cld_logname, logname);
        cld->cld_cfg = *cfg;
        cld->cld_cfg.cfg_last_idx = 0;
        cld->cld_cfg.cfg_flags = 0;
        cld->cld_cfg.cfg_sb = sb;
        atomic_set(&cld->cld_refcount, 1);

        /* Keep the mgc around until we are done */
        cld->cld_mgcexp = class_export_get(lsi->lsi_mgc->obd_self_export);

        if (cfg->cfg_instance != NULL) {
                OBD_ALLOC(cld->cld_cfg.cfg_instance,
                          strlen(cfg->cfg_instance) + 1);
                strcpy(cld->cld_cfg.cfg_instance, cfg->cfg_instance);
        }
        rc = mgc_logname2resid(logname, &cld->cld_resid);
        if (rc) {
                config_log_put(cld);
                RETURN(rc);
        }
        spin_lock(&config_list_lock);
        list_add(&cld->cld_list_chain, &config_llog_list);
        spin_unlock(&config_list_lock);

        RETURN(rc);
}

/* Stop watching for updates on this log. */
static int config_log_end(char *logname, struct config_llog_instance *cfg)
{
        struct config_llog_data *cld;
        int rc = 0;
        ENTRY;

        cld = config_log_find(logname, cfg);
        if (IS_ERR(cld))
                RETURN(PTR_ERR(cld));
        /* drop the ref from the find */
        config_log_put(cld);

        cld->cld_stopping = 1;
        spin_lock(&config_list_lock);
        list_del(&cld->cld_list_chain);
        spin_unlock(&config_list_lock);
        /* drop the start ref */
        config_log_put(cld);
        CDEBUG(D_MGC, "end config log %s (%d)\n", logname ? logname : "client",
               rc);
        RETURN(rc);
}

#if 0
/* Failsafe FIXME remove this */
static void config_log_end_all(void)
{
        struct list_head *tmp, *n;
        struct config_llog_data *cld;
        ENTRY;

        spin_lock(&config_list_lock);
        list_for_each_safe(tmp, n, &config_llog_list) {
                cld = list_entry(tmp, struct config_llog_data, cld_list_chain);
                CERROR("\n\nconflog failsafe %s\n\n\n", cld->cld_logname);
                list_del(&cld->cld_list_chain);
                config_log_put(cld);
        }
        spin_unlock(&config_list_lock);
        EXIT;
}
#endif

/********************** class fns **********************/

static int mgc_fs_setup(struct obd_device *obd, struct super_block *sb,
                        struct vfsmount *mnt)
{
        struct lvfs_run_ctxt saved;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct client_obd *cli = &obd->u.cli;
        struct dentry *dentry;
        char *label;
        int err = 0;
        ENTRY;

        LASSERT(lsi);
        LASSERT(lsi->lsi_srv_mnt == mnt);

        /* The mgc fs exclusion sem. Only one fs can be setup at a time. */
        down(&cli->cl_mgc_sem);

        cleanup_group_info();

        obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        if (IS_ERR(obd->obd_fsops)) {
                up(&cli->cl_mgc_sem);
                CERROR("No fstype %s rc=%ld\n", MT_STR(lsi->lsi_ldd),
                       PTR_ERR(obd->obd_fsops));
                RETURN(PTR_ERR(obd->obd_fsops));
        }

        cli->cl_mgc_vfsmnt = mnt;
        fsfilt_setup(obd, mnt->mnt_sb);

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        dentry = lookup_one_len(MOUNT_CONFIGS_DIR, current->fs->pwd,
                                strlen(MOUNT_CONFIGS_DIR));
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (IS_ERR(dentry)) {
                err = PTR_ERR(dentry);
                CERROR("cannot lookup %s directory: rc = %d\n",
                       MOUNT_CONFIGS_DIR, err);
                GOTO(err_ops, err);
        }
        cli->cl_mgc_configs_dir = dentry;

        /* We take an obd ref to insure that we can't get to mgc_cleanup
           without calling mgc_fs_cleanup first. */
        class_incref(obd);

        label = fsfilt_get_label(obd, mnt->mnt_sb);
        if (label)
                CDEBUG(D_MGC, "MGC using disk labelled=%s\n", label);

        /* We keep the cl_mgc_sem until mgc_fs_cleanup */
        RETURN(0);

err_ops:
        fsfilt_put_ops(obd->obd_fsops);
        obd->obd_fsops = NULL;
        cli->cl_mgc_vfsmnt = NULL;
        up(&cli->cl_mgc_sem);
        RETURN(err);
}

static int mgc_fs_cleanup(struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;
        int rc = 0;
        ENTRY;

        LASSERT(cli->cl_mgc_vfsmnt != NULL);

        if (cli->cl_mgc_configs_dir != NULL) {
                struct lvfs_run_ctxt saved;
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                l_dput(cli->cl_mgc_configs_dir);
                cli->cl_mgc_configs_dir = NULL;
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                class_decref(obd);
        }

        cli->cl_mgc_vfsmnt = NULL;
        if (obd->obd_fsops)
                fsfilt_put_ops(obd->obd_fsops);

        up(&cli->cl_mgc_sem);

        RETURN(rc);
}

static int mgc_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        int rc = 0;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_EARLY:
                break;
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

static int mgc_cleanup(struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;
        int rc;
        ENTRY;

        LASSERT(cli->cl_mgc_vfsmnt == NULL);

        /* COMPAT_146 - old config logs may have added profiles we don't
           know about */
        if (obd->obd_type->typ_refcnt <= 1)
                /* Only for the last mgc */
                class_del_profiles();

        ptlrpcd_decref();

        rc = client_obd_cleanup(obd);
        RETURN(rc);
}

static int mgc_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int rc;
        ENTRY;

        ptlrpcd_addref();

        rc = client_obd_setup(obd, lcfg);
        if (rc)
                GOTO(err_decref, rc);

        rc = obd_llog_init(obd, NULL, obd, 0, NULL, NULL);
        if (rc) {
                CERROR("failed to setup llogging subsystems\n");
                GOTO(err_cleanup, rc);
        }

        RETURN(rc);

err_cleanup:
        client_obd_cleanup(obd);
err_decref:
        ptlrpcd_decref();
        RETURN(rc);
}

static int mgc_process_log(struct obd_device *mgc,
                           struct config_llog_data *cld);

/* FIXME I don't want a thread for every cld; make a list of cld's to requeue
   and use only 1 thread. */
/* reenqueue the lock, reparse the log */
static int mgc_async_requeue(void *data)
{
        wait_queue_head_t   waitq;
        struct l_wait_info  lwi;
        struct config_llog_data *cld = (struct config_llog_data *)data;
        char name[24];
        int rc = 0;
        ENTRY;

        if (!data)
                RETURN(-EINVAL);
        if (cld->cld_stopping)
                GOTO(out, rc = 0);

        snprintf(name, sizeof(name), "ll_log_%s", cld->cld_logname);
        name[sizeof(name)-1] = '\0';
        ptlrpc_daemonize(name);

        CDEBUG(D_MGC, "requeue "LPX64" %s:%s\n",
               cld->cld_resid.name[0], cld->cld_logname,
               cld->cld_cfg.cfg_instance);

        /* Sleep a few seconds to allow the server who caused
           the lock revocation to finish its setup, plus some random
           so everyone doesn't try to reconnect at once. */
        init_waitqueue_head(&waitq);
        lwi = LWI_TIMEOUT(3 * HZ + (ll_rand() & 0xff), NULL, NULL);
        l_wait_event(waitq, 0, &lwi);

#if 0
        /* Re-send server info every time, in case MGS needs to regen its
           logs (for write_conf).  Do we need this?  It's extra RPCs for
           every server at every update.  Turning it off until I'm sure
           it's needed. */
        /* Unsafe - we don't know that the lsi hasn't been destroyed */
        server_register_target(cld->cld_cfg.cfg_sb);
#endif

        rc = mgc_process_log(cld->cld_mgcexp->exp_obd, cld);
out:
        /* Whether we enqueued again or not in mgc_process_log,
           we're done with the ref from the old mgc_blocking_ast */
        config_log_put(cld);

        RETURN(rc);
}

/* based on ll_mdc_blocking_ast */
static int mgc_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                            void *data, int flag)
{
        struct lustre_handle lockh;
        struct config_llog_data *cld = (struct config_llog_data *)data;
        int rc = 0;
        ENTRY;

        switch (flag) {
        case LDLM_CB_BLOCKING:
                /* mgs wants the lock, give it up... */
                LDLM_DEBUG(lock, "MGC blocking CB");
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                break;
        case LDLM_CB_CANCELING: {
                /* We've given up the lock, prepare ourselves to update. */
                LDLM_DEBUG(lock, "MGC cancel CB");

                CDEBUG(D_MGC, "Lock res "LPX64" (%.8s)\n",
                       lock->l_resource->lr_name.name[0],
                       (char *)&lock->l_resource->lr_name.name[0]);

                /* Make sure not to re-enqueue when the mgc is stopping
                   (we get called from client_disconnect_export) */
                if (!lock->l_conn_export ||
                    !lock->l_conn_export->exp_obd->u.cli.cl_conn_count) {
                        CDEBUG(D_MGC, "Disconnecting, don't requeue\n");
                        goto out_drop;
                }
                if (lock->l_req_mode != lock->l_granted_mode) {
                        CERROR("original grant failed, won't requeue\n");
                        goto out_drop;
                }
                if (!data) {
                        CERROR("missing data, won't requeue\n");
                        goto out_drop;
                }
                if (cld->cld_stopping) {
                        CERROR("stopping, won't requeue\n");
                        goto out_drop;
                }

                /* Re-enqueue the lock in a separate thread, because we must
                   return from this fn before that lock can be taken. */
                rc = cfs_kernel_thread(mgc_async_requeue, data,
                                       CLONE_VM | CLONE_FILES);
                if (rc < 0) {
                        CERROR("Cannot re-enqueue thread: %d\n", rc);
                } else {
                        rc = 0;
                        break;
                }
out_drop:
                /* Drop this here or in mgc_async_requeue,
                   in either case, we're done with the reference
                   after this. */
                config_log_put(cld);
                break;
        }
        default:
                LBUG();
        }


        if (rc) {
                CERROR("%s CB failed %d:\n", flag == LDLM_CB_BLOCKING ?
                       "blocking" : "cancel", rc);
                LDLM_ERROR(lock, "MGC ast");
        }
        RETURN(rc);
}

/* Take a config lock so we can get cancel notifications */
static int mgc_enqueue(struct obd_export *exp, struct lov_stripe_md *lsm,
                       __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                       int *flags, void *bl_cb, void *cp_cb, void *gl_cb,
                       void *data, __u32 lvb_len, void *lvb_swabber,
                       struct lustre_handle *lockh)
{
        struct config_llog_data *cld = (struct config_llog_data *)data;
        int rc;
        ENTRY;

        CDEBUG(D_MGC, "Enqueue for %s (res "LPX64")\n", cld->cld_logname,
               cld->cld_resid.name[0]);

        /* We can only drop this config log ref when we drop the lock */
        if (config_log_get(cld))
                RETURN(ELDLM_LOCK_ABORTED);

        /* We need a callback for every lockholder, so don't try to
           ldlm_lock_match (see rev 1.1.2.11.2.47) */

        rc = ldlm_cli_enqueue(exp, NULL, &cld->cld_resid,
                              type, NULL, mode, flags,
                              mgc_blocking_ast, ldlm_completion_ast, NULL,
                              data, NULL, 0, NULL, lockh, 0);

        RETURN(rc);
}

static int mgc_cancel(struct obd_export *exp, struct lov_stripe_md *md,
                      __u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

#if 0
static int mgc_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_ioctl_data *data = karg;
        struct llog_ctxt *ctxt;
        struct lvfs_run_ctxt saved;
        int rc;
        ENTRY;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        MOD_INC_USE_COUNT;
#else
        if (!try_module_get(THIS_MODULE)) {
                CERROR("Can't get module. Is it alive?");
                return -EINVAL;
        }
#endif
        switch (cmd) {
        /* REPLicator context */
        case OBD_IOC_PARSE: {
                CERROR("MGC parsing llog %s\n", data->ioc_inlbuf1);
                ctxt = llog_get_context(exp->exp_obd, LLOG_CONFIG_REPL_CTXT);
                rc = class_config_parse_llog(ctxt, data->ioc_inlbuf1, NULL);
                GOTO(out, rc);
        }
#ifdef __KERNEL__
        case OBD_IOC_LLOG_INFO:
        case OBD_IOC_LLOG_PRINT: {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                rc = llog_ioctl(ctxt, cmd, data);

                GOTO(out, rc);
        }
#endif
        /* ORIGinator context */
        case OBD_IOC_DUMP_LOG: {
                ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = class_config_dump_llog(ctxt, data->ioc_inlbuf1, NULL);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        RETURN(rc);

                GOTO(out, rc);
        }
        default:
                CERROR("mgc_ioctl(): unrecognised ioctl %#x\n", cmd);
                GOTO(out, rc = -ENOTTY);
        }
out:
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        MOD_DEC_USE_COUNT;
#else
        module_put(THIS_MODULE);
#endif

        return rc;
}
#endif

/* Send target_reg message to MGS */
static int mgc_target_register(struct obd_export *exp,
                               struct mgs_target_info *mti)
{
        struct ptlrpc_request *req;
        struct mgs_target_info *req_mti, *rep_mti;
        int size[] = { sizeof(struct ptlrpc_body), sizeof(*req_mti) };
        int rep_size[] = { sizeof(struct ptlrpc_body), sizeof(*mti) };
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_MGS_VERSION,
                              MGS_TARGET_REG, 2, size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        req_mti = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, sizeof(*req_mti));
        if (!req_mti)
                RETURN(-ENOMEM);
        memcpy(req_mti, mti, sizeof(*req_mti));

        ptlrpc_req_set_repsize(req, 2, rep_size);

        CDEBUG(D_MGC, "register %s\n", mti->mti_svname);

        rc = ptlrpc_queue_wait(req);
        if (!rc) {
                rep_mti = lustre_swab_repbuf(req, REPLY_REC_OFF,
                                             sizeof(*rep_mti),
                                             lustre_swab_mgs_target_info);
                memcpy(mti, rep_mti, sizeof(*rep_mti));
                CDEBUG(D_MGC, "register %s got index = %d\n",
                       mti->mti_svname, mti->mti_stripe_index);
        } else {
                CERROR("register failed. rc=%d\n", rc);
        }
        ptlrpc_req_finished(req);

        RETURN(rc);
}

int mgc_set_info_async(struct obd_export *exp, obd_count keylen,
                       void *key, obd_count vallen, void *val,
                       struct ptlrpc_request_set *set)
{
        struct obd_import *imp = class_exp2cliimp(exp);
        int rc = -EINVAL;
        ENTRY;

        /* Try to "recover" the initial connection; i.e. retry */
        if (KEY_IS(KEY_INIT_RECOV)) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                imp->imp_initial_recov = *(int *)val;
                CDEBUG(D_HA, "%s: set imp_initial_recov = %d\n",
                       exp->exp_obd->obd_name, imp->imp_initial_recov);
                RETURN(0);
        }
        /* Turn off initial_recov after we try all backup servers once */
        if (KEY_IS(KEY_INIT_RECOV_BACKUP)) {
                int value;
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                value = *(int *)val;
                imp->imp_initial_recov_bk = value > 0;
                /* Even after the initial connection, give up all comms if
                   nobody answers the first time. */
                imp->imp_recon_bk = 1;
                CDEBUG(D_MGC, "InitRecov %s %d/%d:d%d:i%d:r%d:or%d:%s\n",
                       imp->imp_obd->obd_name, value, imp->imp_initial_recov,
                       imp->imp_deactive, imp->imp_invalid,
                       imp->imp_replayable, imp->imp_obd->obd_replayable,
                       ptlrpc_import_state_name(imp->imp_state));
                /* Resurrect if we previously died */
                if (imp->imp_invalid || value > 1) {
                        /* Allow reconnect attempts */
                        imp->imp_obd->obd_no_recov = 0;
                        /* Force a new connect attempt */
                        /* (can't put these in obdclass, module loop) */
                        ptlrpc_invalidate_import(imp);
                        /* Remove 'invalid' flag */
                        ptlrpc_activate_import(imp);
                        /* Attempt a new connect */
                        ptlrpc_recover_import(imp, NULL);
                }
                RETURN(0);
        }
        /* FIXME move this to mgc_process_config */
        if (KEY_IS("register_target")) {
                struct mgs_target_info *mti;
                if (vallen != sizeof(struct mgs_target_info))
                        RETURN(-EINVAL);
                mti = (struct mgs_target_info *)val;
                CDEBUG(D_MGC, "register_target %s %#x\n",
                       mti->mti_svname, mti->mti_flags);
                rc =  mgc_target_register(exp, mti);
                RETURN(rc);
        }
        if (KEY_IS("set_fs")) {
                struct super_block *sb = (struct super_block *)val;
                struct lustre_sb_info *lsi;
                if (vallen != sizeof(struct super_block))
                        RETURN(-EINVAL);
                lsi = s2lsi(sb);
                rc = mgc_fs_setup(exp->exp_obd, sb, lsi->lsi_srv_mnt);
                if (rc) {
                        CERROR("set_fs got %d\n", rc);
                }
                RETURN(rc);
        }
        if (KEY_IS("clear_fs")) {
                if (vallen != 0)
                        RETURN(-EINVAL);
                rc = mgc_fs_cleanup(exp->exp_obd);
                if (rc) {
                        CERROR("clear_fs got %d\n", rc);
                }
                RETURN(rc);
        }

        RETURN(rc);
}

static int mgc_import_event(struct obd_device *obd,
                            struct obd_import *imp,
                            enum obd_import_event event)
{
        int rc = 0;

        LASSERT(imp->imp_obd == obd);
        CDEBUG(D_MGC, "import event %#x\n", event);

        switch (event) {
        case IMP_EVENT_DISCON:
                /* MGC imports should not wait for recovery */
                ptlrpc_invalidate_import(imp);
                break;
        case IMP_EVENT_INACTIVE:
                break;
        case IMP_EVENT_INVALIDATE: {
                struct ldlm_namespace *ns = obd->obd_namespace;
                ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);
                break;
        }
        case IMP_EVENT_ACTIVE:
        case IMP_EVENT_OCD:
                break;
        default:
                CERROR("Unknown import event %#x\n", event);
                LBUG();
        }
        RETURN(rc);
}

static int mgc_llog_init(struct obd_device *obd, struct obd_llogs *llogs,
                         struct obd_device *tgt, int count,
                         struct llog_catid *logid, struct obd_uuid *uuid)
{
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        rc = llog_setup(obd, llogs, LLOG_CONFIG_ORIG_CTXT, tgt, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                RETURN(rc);

        rc = llog_setup(obd, llogs, LLOG_CONFIG_REPL_CTXT, tgt, 0, NULL,
                        &llog_client_ops);
        if (rc == 0) {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                ctxt->loc_imp = obd->u.cli.cl_import;
        }

        RETURN(rc);
}

static int mgc_llog_finish(struct obd_device *obd, int count)
{
        int rc;
        ENTRY;

        rc = llog_cleanup(llog_get_context(obd, LLOG_CONFIG_REPL_CTXT));
        rc = llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));

        RETURN(rc);
}

/* identical to mgs_log_is_empty */
static int mgc_llog_is_empty(struct obd_device *obd, struct llog_ctxt *ctxt,
                            char *name)
{
        struct lvfs_run_ctxt saved;
        struct llog_handle *llh;
        int rc = 0;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_create(ctxt, &llh, NULL, name);
        if (rc == 0) {
                llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
                rc = llog_get_size(llh);
                llog_close(llh);
        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        /* header is record 1 */
        return(rc <= 1);
}

static int mgc_copy_handler(struct llog_handle *llh, struct llog_rec_hdr *rec,
                            void *data)
{
        struct llog_rec_hdr local_rec = *rec;
        struct llog_handle *local_llh = (struct llog_handle *)data;
        char *cfg_buf = (char*) (rec + 1);
        struct lustre_cfg *lcfg;
        int rc = 0;
        ENTRY;

        lcfg = (struct lustre_cfg *)cfg_buf;

        /* append new records */
        if (rec->lrh_index >= llog_get_size(local_llh)) {
                rc = llog_write_rec(local_llh, &local_rec, NULL, 0,
                                    (void *)cfg_buf, -1);

                CDEBUG(D_INFO, "idx=%d, rc=%d, len=%d, cmd %x %s %s\n",
                       rec->lrh_index, rc, rec->lrh_len, lcfg->lcfg_command,
                       lustre_cfg_string(lcfg, 0), lustre_cfg_string(lcfg, 1));
        } else {
                CDEBUG(D_INFO, "skip idx=%d\n",  rec->lrh_index);
        }

        RETURN(rc);
}

static int mgc_copy_llog(struct obd_device *obd, struct llog_ctxt *rctxt,
                         struct llog_ctxt *lctxt, char *logname)
{
        struct llog_handle *local_llh, *remote_llh;
        struct obd_uuid *uuid;
        int rc, rc2;
        ENTRY;

        /* open local log */
        rc = llog_create(lctxt, &local_llh, NULL, logname);
        if (rc)
                RETURN(rc);
        /* set the log header uuid for fun */
        OBD_ALLOC_PTR(uuid);
        obd_str2uuid(uuid, logname);
        rc = llog_init_handle(local_llh, LLOG_F_IS_PLAIN, uuid);
        OBD_FREE_PTR(uuid);
        if (rc)
                GOTO(out_closel, rc);

        /* FIXME write new log to a temp name, then vfs_rename over logname
           upon successful completion. */

        /* open remote log */
        rc = llog_create(rctxt, &remote_llh, NULL, logname);
        if (rc)
                GOTO(out_closel, rc);
        rc = llog_init_handle(remote_llh, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out_closer, rc);

        rc = llog_process(remote_llh, mgc_copy_handler,(void *)local_llh, NULL);

out_closer:
        rc2 = llog_close(remote_llh);
        if (!rc)
                rc = rc2;
out_closel:
        rc2 = llog_close(local_llh);
        if (!rc)
                rc = rc2;

        CDEBUG(D_MGC, "Copied remote log %s (%d)\n", logname, rc);
        RETURN(rc);
}

DECLARE_MUTEX(llog_process_lock);

/* Get a config log from the MGS and process it.
   This func is called for both clients and servers. */
static int mgc_process_log(struct obd_device *mgc,
                           struct config_llog_data *cld)
{
        struct llog_ctxt *ctxt, *lctxt;
        struct lustre_handle lockh;
        struct client_obd *cli = &mgc->u.cli;
        struct lvfs_run_ctxt saved;
        struct lustre_sb_info *lsi;
        int rc = 0, rcl, flags = 0, must_pop = 0;
        ENTRY;

        if (!cld || !cld->cld_cfg.cfg_sb) {
                /* This should never happen */
                CERROR("Missing cld, aborting log update\n");
                RETURN(-EINVAL);
        }
        if (cld->cld_stopping)
                RETURN(0);

        OBD_FAIL_TIMEOUT(OBD_FAIL_MGC_PROCESS_LOG, 20);

        lsi = s2lsi(cld->cld_cfg.cfg_sb);

        CDEBUG(D_MGC, "Process log %s:%s from %d\n", cld->cld_logname,
               cld->cld_cfg.cfg_instance, cld->cld_cfg.cfg_last_idx + 1);

        ctxt = llog_get_context(mgc, LLOG_CONFIG_REPL_CTXT);
        if (!ctxt) {
                CERROR("missing llog context\n");
                RETURN(-EINVAL);
        }

        /* I don't want mutliple processes running process_log at once --
           sounds like badness.  It actually might be fine, as long as
           we're not trying to update from the same log
           simultaneously (in which case we should use a per-log sem.) */
        down(&llog_process_lock);

        /* Get the cfg lock on the llog */
        rcl = mgc_enqueue(mgc->u.cli.cl_mgc_mgsexp, NULL, LDLM_PLAIN, NULL,
                          LCK_CR, &flags, NULL, NULL, NULL,
                          cld, 0, NULL, &lockh);
        if (rcl)
                CERROR("Can't get cfg lock: %d\n", rcl);

        lctxt = llog_get_context(mgc, LLOG_CONFIG_ORIG_CTXT);

        /* Copy the setup log locally if we can. Don't mess around if we're
           running an MGS though (logs are already local). */
        if (lctxt && lsi && (lsi->lsi_flags & LSI_SERVER) &&
            (lsi->lsi_srv_mnt == cli->cl_mgc_vfsmnt) &&
            !IS_MGS(lsi->lsi_ldd)) {
                push_ctxt(&saved, &mgc->obd_lvfs_ctxt, NULL);
                must_pop++;
                if (rcl == 0)
                        /* Only try to copy log if we have the lock. */
                        rc = mgc_copy_llog(mgc, ctxt, lctxt, cld->cld_logname);
                if (rcl || rc) {
                        if (mgc_llog_is_empty(mgc, lctxt, cld->cld_logname)) {
                                LCONSOLE_ERROR("Failed to get MGS log %s "
                                               "and no local copy.\n",
                                               cld->cld_logname);
                                GOTO(out_pop, rc = -ENOTCONN);
                        }
                        LCONSOLE_WARN("Failed to get MGS log %s, using "
                                      "local copy.\n", cld->cld_logname);
                }
                /* Now, whether we copied or not, start using the local llog.
                   If we failed to copy, we'll start using whatever the old
                   log has. */
                ctxt = lctxt;
        }

        /* logname and instance info should be the same, so use our
           copy of the instance for the update.  The cfg_last_idx will
           be updated here. */
        rc = class_config_parse_llog(ctxt, cld->cld_logname, &cld->cld_cfg);

 out_pop:
        if (must_pop)
                pop_ctxt(&saved, &mgc->obd_lvfs_ctxt, NULL);

        /* Now drop the lock so MGS can revoke it */
        if (!rcl) {
                rcl = mgc_cancel(mgc->u.cli.cl_mgc_mgsexp, NULL,
                                 LCK_CR, &lockh);
                if (rcl)
                        CERROR("Can't drop cfg lock: %d\n", rcl);
        }

        if (rc) {
                CERROR("%s: the configuration '%s' could not be read "
                       "(%d) from the MGS.\n",
                       mgc->obd_name, cld->cld_logname, rc);
        }

        up(&llog_process_lock);

        RETURN(rc);
}

static int mgc_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        int cmd;
        int rc = 0;
        ENTRY;

        switch(cmd = lcfg->lcfg_command) {
        case LCFG_LOV_ADD_OBD: {
                /* Add any new target, not just osts */
                struct mgs_target_info *mti;

                if (LUSTRE_CFG_BUFLEN(lcfg, 1) !=
                    sizeof(struct mgs_target_info))
                        GOTO(out, rc = -EINVAL);

                mti = (struct mgs_target_info *)lustre_cfg_buf(lcfg, 1);
                CDEBUG(D_MGC, "add_target %s %#x\n",
                       mti->mti_svname, mti->mti_flags);
                rc = mgc_target_register(obd->u.cli.cl_mgc_mgsexp, mti);
                break;
        }
        case LCFG_LOV_DEL_OBD:
                /* Remove target from the fs? */
                /* FIXME */
                CERROR("lov_del_obd unimplemented\n");
                rc = -ENOSYS;
                break;
        case LCFG_LOG_START: {
                struct config_llog_data *cld;
                struct config_llog_instance *cfg;
                struct super_block *sb;
                char *logname = lustre_cfg_string(lcfg, 1);
                cfg = (struct config_llog_instance *)lustre_cfg_buf(lcfg, 2);
                sb = *(struct super_block **)lustre_cfg_buf(lcfg, 3);

                CDEBUG(D_MGC, "parse_log %s from %d\n", logname,
                       cfg->cfg_last_idx);

                /* We're only called through here on the initial mount */
                rc = config_log_add(logname, cfg, sb);
                if (rc)
                        break;
                cld = config_log_find(logname, cfg);
                if (IS_ERR(cld)) {
                        rc = PTR_ERR(cld);
                        break;
                }

                /* COMPAT_146 */
                /* FIXME only set this for old logs!  Right now this forces
                   us to always skip the "inside markers" check */
                cld->cld_cfg.cfg_flags |= CFG_F_COMPAT146;

                rc = mgc_process_log(obd, cld);
                config_log_put(cld);

                break;
        }
        case LCFG_LOG_END: {
                struct config_llog_instance *cfg = NULL;
                char *logname = lustre_cfg_string(lcfg, 1);
                if (lcfg->lcfg_bufcount >= 2)
                        cfg = (struct config_llog_instance *)lustre_cfg_buf(
                                lcfg, 2);
                rc = config_log_end(logname, cfg);
                break;
        }
        default: {
                CERROR("Unknown command: %d\n", lcfg->lcfg_command);
                GOTO(out, rc = -EINVAL);

        }
        }
out:
        RETURN(rc);
}

struct obd_ops mgc_obd_ops = {
        .o_owner        = THIS_MODULE,
        .o_setup        = mgc_setup,
        .o_precleanup   = mgc_precleanup,
        .o_cleanup      = mgc_cleanup,
        .o_add_conn     = client_import_add_conn,
        .o_del_conn     = client_import_del_conn,
        .o_connect      = client_connect_import,
        .o_disconnect   = client_disconnect_export,
        //.o_enqueue      = mgc_enqueue,
        .o_cancel       = mgc_cancel,
        //.o_iocontrol    = mgc_iocontrol,
        .o_set_info_async = mgc_set_info_async,
        .o_import_event = mgc_import_event,
        .o_llog_init    = mgc_llog_init,
        .o_llog_finish  = mgc_llog_finish,
        .o_process_config = mgc_process_config,
};

int __init mgc_init(void)
{
        return class_register_type(&mgc_obd_ops, NULL, NULL,
                                   LUSTRE_MGC_NAME, NULL);
}

#ifdef __KERNEL__
static void /*__exit*/ mgc_exit(void)
{
        class_unregister_type(LUSTRE_MGC_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Management Client");
MODULE_LICENSE("GPL");

module_init(mgc_init);
module_exit(mgc_exit);
#endif
