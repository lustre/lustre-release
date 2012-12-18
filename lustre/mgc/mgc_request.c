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
 *
 * Copyright (c) 2011, Intel Corporation.
 *
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mgc/mgc_request.c
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
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
#include <lprocfs_status.h>
#include <lustre_log.h>
#include <lustre_fsfilt.h>
#include <lustre_disk.h>
#include "mgc_internal.h"

static int mgc_name2resid(char *name, int len, struct ldlm_res_id *res_id)
{
        __u64 resname = 0;

        if (len > 8) {
                CERROR("name too long: %s\n", name);
                return -EINVAL;
        }
        if (len <= 0) {
                CERROR("missing name: %s\n", name);
                return -EINVAL;
        }
        memcpy(&resname, name, len);

        memset(res_id, 0, sizeof(*res_id));

        /* Always use the same endianness for the resid */
        res_id->name[0] = cpu_to_le64(resname);
        CDEBUG(D_MGC, "log %s to resid "LPX64"/"LPX64" (%.8s)\n", name,
               res_id->name[0], res_id->name[1], (char *)&res_id->name[0]);
        return 0;
}

int mgc_fsname2resid(char *fsname, struct ldlm_res_id *res_id)
{
        /* fsname is at most 8 chars long, maybe contain "-".
         * e.g. "lustre", "SUN-000" */
        return mgc_name2resid(fsname, strlen(fsname), res_id);
}
EXPORT_SYMBOL(mgc_fsname2resid);

int mgc_logname2resid(char *logname, struct ldlm_res_id *res_id)
{
        char *name_end;
        int len;

        /* logname consists of "fsname-nodetype".
         * e.g. "lustre-MDT0001", "SUN-000-client" */
        name_end = strrchr(logname, '-');
        LASSERT(name_end);
        len = name_end - logname;
        return mgc_name2resid(logname, len, res_id);
}

/********************** config llog list **********************/
static CFS_LIST_HEAD(config_llog_list);
static cfs_spinlock_t       config_list_lock = CFS_SPIN_LOCK_UNLOCKED;

/* Take a reference to a config log */
static int config_log_get(struct config_llog_data *cld)
{
        ENTRY;
        if (cld->cld_stopping)
                RETURN(1);
        cfs_atomic_inc(&cld->cld_refcount);
        CDEBUG(D_INFO, "log %s refs %d\n", cld->cld_logname,
               cfs_atomic_read(&cld->cld_refcount));
        RETURN(0);
}

/* Drop a reference to a config log.  When no longer referenced,
   we can free the config log data */
static void config_log_put(struct config_llog_data *cld)
{
        ENTRY;

        CDEBUG(D_INFO, "log %s refs %d\n", cld->cld_logname,
               cfs_atomic_read(&cld->cld_refcount));
        LASSERT(cfs_atomic_read(&cld->cld_refcount) > 0);

        /* spinlock to make sure no item with 0 refcount in the list */
        cfs_spin_lock(&config_list_lock);
        if (unlikely(cfs_atomic_dec_and_test(&cld->cld_refcount))) {
                cfs_list_del(&cld->cld_list_chain);
                cfs_spin_unlock(&config_list_lock);

                CDEBUG(D_MGC, "dropping config log %s\n", cld->cld_logname);

                if (cld->cld_sptlrpc)
                        config_log_put(cld->cld_sptlrpc);
                if (cld->cld_is_sptlrpc)
                        sptlrpc_conf_log_stop(cld->cld_logname);

                class_export_put(cld->cld_mgcexp);
                OBD_FREE(cld->cld_logname, strlen(cld->cld_logname) + 1);
                OBD_FREE(cld, sizeof(*cld));
        } else {
                cfs_spin_unlock(&config_list_lock);
        }

        EXIT;
}

/* Find a config log by name */
static
struct config_llog_data *config_log_find(char *logname,
                                         struct config_llog_instance *cfg)
{
        struct config_llog_data *cld;
        struct config_llog_data *found = NULL;
        void *                   instance;
        ENTRY;

        LASSERT(logname != NULL);

        instance = cfg ? cfg->cfg_instance : NULL;
        cfs_spin_lock(&config_list_lock);
        cfs_list_for_each_entry(cld, &config_llog_list, cld_list_chain) {
                /* check if instance equals */
                if (instance != cld->cld_cfg.cfg_instance)
                        continue;

                /* instance may be NULL, should check name */
                if (strcmp(logname, cld->cld_logname) == 0) {
                        found = cld;
                        break;
                }
        }
        if (found) {
                cfs_atomic_inc(&found->cld_refcount);
                LASSERT(found->cld_stopping == 0 || found->cld_is_sptlrpc == 0);
        }
        cfs_spin_unlock(&config_list_lock);
        RETURN(found);
}

static
struct config_llog_data *do_config_log_add(struct obd_device *obd,
                                           char *logname,
                                           unsigned int is_sptlrpc,
                                           struct config_llog_instance *cfg,
                                           struct super_block *sb)
{
        struct config_llog_data *cld;
        int                      rc;
        ENTRY;

        CDEBUG(D_MGC, "do adding config log %s:%p\n", logname,
               cfg ? cfg->cfg_instance : 0);

        OBD_ALLOC(cld, sizeof(*cld));
        if (!cld)
                RETURN(ERR_PTR(-ENOMEM));
        OBD_ALLOC(cld->cld_logname, strlen(logname) + 1);
        if (!cld->cld_logname) {
                OBD_FREE(cld, sizeof(*cld));
                RETURN(ERR_PTR(-ENOMEM));
        }
        strcpy(cld->cld_logname, logname);
        if (cfg)
                cld->cld_cfg = *cfg;
        cfs_mutex_init(&cld->cld_lock);
        cld->cld_cfg.cfg_last_idx = 0;
        cld->cld_cfg.cfg_flags = 0;
        cld->cld_cfg.cfg_sb = sb;
        cld->cld_is_sptlrpc = is_sptlrpc;
        cfs_atomic_set(&cld->cld_refcount, 1);

        /* Keep the mgc around until we are done */
        cld->cld_mgcexp = class_export_get(obd->obd_self_export);

        if (is_sptlrpc) {
                sptlrpc_conf_log_start(logname);
                cld->cld_cfg.cfg_obdname = obd->obd_name;
        }

        rc = mgc_logname2resid(logname, &cld->cld_resid);

        cfs_spin_lock(&config_list_lock);
        cfs_list_add(&cld->cld_list_chain, &config_llog_list);
        cfs_spin_unlock(&config_list_lock);

        if (rc) {
                config_log_put(cld);
                RETURN(ERR_PTR(rc));
        }

        if (is_sptlrpc) {
                rc = mgc_process_log(obd, cld);
                if (rc)
                        CERROR("failed processing sptlrpc log: %d\n", rc);
        }

        RETURN(cld);
}

/** Add this log to the list of active logs watched by an MGC.
 * Active means we're watching for updates.
 * We have one active log per "mount" - client instance or servername.
 * Each instance may be at a different point in the log.
 */
static int config_log_add(struct obd_device *obd, char *logname,
                          struct config_llog_instance *cfg,
                          struct super_block *sb)
{
        struct config_llog_data *cld, *sptlrpc_cld;
        char                     seclogname[20];
        char                    *ptr;
        ENTRY;

        CDEBUG(D_MGC, "adding config log %s:%p\n", logname, cfg->cfg_instance);

        /*
         * for each regular log, the depended sptlrpc log name is
         * <fsname>-sptlrpc. multiple regular logs may share one sptlrpc log.
         */
        ptr = strrchr(logname, '-');
        if (ptr == NULL || ptr - logname > 8) {
                CERROR("logname %s is too long\n", logname);
                RETURN(-EINVAL);
        }

        memcpy(seclogname, logname, ptr - logname);
        strcpy(seclogname + (ptr - logname), "-sptlrpc");

        sptlrpc_cld = config_log_find(seclogname, NULL);
        if (sptlrpc_cld == NULL) {
                sptlrpc_cld = do_config_log_add(obd, seclogname, 1, NULL, NULL);
                if (IS_ERR(sptlrpc_cld)) {
                        CERROR("can't create sptlrpc log: %s\n", seclogname);
                        RETURN(PTR_ERR(sptlrpc_cld));
                }
        }

        cld = do_config_log_add(obd, logname, 0, cfg, sb);
        if (IS_ERR(cld)) {
                CERROR("can't create log: %s\n", logname);
                config_log_put(sptlrpc_cld);
                RETURN(PTR_ERR(cld));
        }

        cld->cld_sptlrpc = sptlrpc_cld;

        RETURN(0);
}

CFS_DECLARE_MUTEX(llog_process_lock);

/** Stop watching for updates on this log.
 */
static int config_log_end(char *logname, struct config_llog_instance *cfg)
{
        struct config_llog_data *cld, *cld_sptlrpc = NULL;
        int rc = 0;
        ENTRY;

        cld = config_log_find(logname, cfg);
        if (cld == NULL)
                RETURN(-ENOENT);

        cfs_mutex_lock(&cld->cld_lock);
        /*
         * if cld_stopping is set, it means we didn't start the log thus
         * not owning the start ref. this can happen after previous umount:
         * the cld still hanging there waiting for lock cancel, and we
         * remount again but failed in the middle and call log_end without
         * calling start_log.
         */
        if (unlikely(cld->cld_stopping)) {
                cfs_mutex_unlock(&cld->cld_lock);
                /* drop the ref from the find */
                config_log_put(cld);
                RETURN(rc);
        }

        cld->cld_stopping = 1;
        cfs_mutex_unlock(&cld->cld_lock);

        cfs_spin_lock(&config_list_lock);
        cld_sptlrpc = cld->cld_sptlrpc;
        cld->cld_sptlrpc = NULL;
        cfs_spin_unlock(&config_list_lock);

        if (cld_sptlrpc)
                config_log_put(cld_sptlrpc);

        /* drop the ref from the find */
        config_log_put(cld);
        /* drop the start ref */
        config_log_put(cld);

        CDEBUG(D_MGC, "end config log %s (%d)\n", logname ? logname : "client",
               rc);
        RETURN(rc);
}

/* reenqueue any lost locks */
#define RQ_RUNNING 0x1
#define RQ_NOW     0x2
#define RQ_LATER   0x4
#define RQ_STOP    0x8
static int rq_state = 0;
static cfs_waitq_t rq_waitq;

static int mgc_requeue_add(struct config_llog_data *cld, int later);

static void do_requeue(struct config_llog_data *cld)
{
        LASSERT(cfs_atomic_read(&cld->cld_refcount) > 0);

        /* Do not run mgc_process_log on a disconnected export or an
           export which is being disconnected. Take the client
           semaphore to make the check non-racy. */
        cfs_down_read(&cld->cld_mgcexp->exp_obd->u.cli.cl_sem);
        if (cld->cld_mgcexp->exp_obd->u.cli.cl_conn_count != 0) {
                CDEBUG(D_MGC, "updating log %s\n", cld->cld_logname);
                mgc_process_log(cld->cld_mgcexp->exp_obd, cld);
        } else {
                CDEBUG(D_MGC, "disconnecting, won't update log %s\n",
                       cld->cld_logname);
        }
        cfs_up_read(&cld->cld_mgcexp->exp_obd->u.cli.cl_sem);

        /* Whether we enqueued again or not in mgc_process_log, we're done
         * with the ref from the old enqueue */
        config_log_put(cld);
}

static int mgc_requeue_thread(void *data)
{
        struct l_wait_info lwi_now, lwi_later;
        struct config_llog_data *cld, *cld_next, *cld_prev;
        char name[] = "ll_cfg_requeue";
        int rc = 0;
        ENTRY;

        cfs_daemonize(name);

        CDEBUG(D_MGC, "Starting requeue thread\n");

        lwi_later = LWI_TIMEOUT(60 * CFS_HZ, NULL, NULL);
        l_wait_event(rq_waitq, rq_state & (RQ_NOW | RQ_STOP), &lwi_later);

        /* Keep trying failed locks periodically */
        cfs_spin_lock(&config_list_lock);
        while (rq_state & (RQ_NOW | RQ_LATER)) {
                /* Any new or requeued lostlocks will change the state */
                rq_state &= ~(RQ_NOW | RQ_LATER);
                cfs_spin_unlock(&config_list_lock);

                /* Always wait a few seconds to allow the server who
                   caused the lock revocation to finish its setup, plus some
                   random so everyone doesn't try to reconnect at once. */
                lwi_now = LWI_TIMEOUT(3 * CFS_HZ + (cfs_rand() & 0xff) * \
                                      (CFS_HZ / 100),
                                      NULL, NULL);
                l_wait_event(rq_waitq, rq_state & RQ_STOP, &lwi_now);

                /*
                 * iterate & processing through the list. for each cld, process
                 * its depending sptlrpc cld firstly (if any) and then itself.
                 *
                 * it's guaranteed any item in the list must have
                 * reference > 0; and if cld_lostlock is set, at
                 * least one reference is taken by the previous enqueue.
                 *
                 * Note: releasing a cld might lead to itself and its depended
                 * sptlrpc cld be unlinked from the list. to safely iterate
                 * we need to take a reference on next cld before processing.
                 */
                cld_prev = NULL;

                cfs_spin_lock(&config_list_lock);
                cfs_list_for_each_entry_safe(cld, cld_next, &config_llog_list,
                                             cld_list_chain) {
                        if (cld->cld_list_chain.next != &config_llog_list)
                                cfs_atomic_inc(&cld_next->cld_refcount);

                        if (cld->cld_lostlock) {
                                if (cld->cld_sptlrpc &&
                                    cld->cld_sptlrpc->cld_lostlock) {
                                        cld->cld_sptlrpc->cld_lostlock = 0;

                                        cfs_spin_unlock(&config_list_lock);
                                        do_requeue(cld->cld_sptlrpc);
                                        cfs_spin_lock(&config_list_lock);
                                        LASSERT(cld->cld_lostlock);
                                }

                                cld->cld_lostlock = 0;

                                cfs_spin_unlock(&config_list_lock);
                                do_requeue(cld);
                                cfs_spin_lock(&config_list_lock);
                        }


                        if (cld_prev) {
                                cfs_spin_unlock(&config_list_lock);
                                config_log_put(cld_prev);
                                cfs_spin_lock(&config_list_lock);
                        }

                        cld_prev = cld_next;
                }
                cfs_spin_unlock(&config_list_lock);

                /* Wait a bit to see if anyone else needs a requeue */
                l_wait_event(rq_waitq, rq_state & (RQ_NOW | RQ_STOP),
                             &lwi_later);
                cfs_spin_lock(&config_list_lock);
        }
        /* spinlock and while guarantee RQ_NOW and RQ_LATER are not set */
        rq_state &= ~RQ_RUNNING;
        cfs_spin_unlock(&config_list_lock);

        CDEBUG(D_MGC, "Ending requeue thread\n");
        RETURN(rc);
}

/* Add a cld to the list to requeue.  Start the requeue thread if needed.
   We are responsible for dropping the config log reference from here on out. */
static int mgc_requeue_add(struct config_llog_data *cld, int later)
{
        int rc = 0;

        CDEBUG(D_INFO, "log %s: requeue (l=%d r=%d sp=%d st=%x)\n",
               cld->cld_logname, later, cfs_atomic_read(&cld->cld_refcount),
               cld->cld_stopping, rq_state);
        LASSERT(cfs_atomic_read(&cld->cld_refcount) > 0);

        /* Hold lock for rq_state */
        cfs_spin_lock(&config_list_lock);

        if (cld->cld_stopping || (rq_state & RQ_STOP)) {
                cld->cld_lostlock = 0;
                cfs_spin_unlock(&config_list_lock);
                config_log_put(cld);
                RETURN(0);
        }

        cld->cld_lostlock = 1;

        if (!(rq_state & RQ_RUNNING)) {
                LASSERT(rq_state == 0);
                rq_state = RQ_RUNNING | (later ? RQ_LATER : RQ_NOW);
                cfs_spin_unlock(&config_list_lock);
                rc = cfs_create_thread(mgc_requeue_thread, NULL,
                                       CFS_DAEMON_FLAGS);
                if (rc < 0) {
                        CERROR("log %s: cannot start requeue thread (%d),"
                               "no more log updates!\n", cld->cld_logname, rc);
                        /* Drop the ref, since the rq thread won't */
                        cld->cld_lostlock = 0;
                        config_log_put(cld);
                        rq_state = 0;
                        RETURN(rc);
                }
        } else {
                rq_state |= later ? RQ_LATER : RQ_NOW;
                cfs_spin_unlock(&config_list_lock);
                cfs_waitq_signal(&rq_waitq);
        }

        RETURN(0);
}

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
        cfs_down(&cli->cl_mgc_sem);

        cfs_cleanup_group_info();

        obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        if (IS_ERR(obd->obd_fsops)) {
                cfs_up(&cli->cl_mgc_sem);
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
        dentry = ll_lookup_one_len(MOUNT_CONFIGS_DIR, cfs_fs_pwd(current->fs),
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
        class_incref(obd, "mgc_fs", obd);

        label = fsfilt_get_label(obd, mnt->mnt_sb);
        if (label)
                CDEBUG(D_MGC, "MGC using disk labelled=%s\n", label);

        /* We keep the cl_mgc_sem until mgc_fs_cleanup */
        RETURN(0);

err_ops:
        fsfilt_put_ops(obd->obd_fsops);
        obd->obd_fsops = NULL;
        cli->cl_mgc_vfsmnt = NULL;
        cfs_up(&cli->cl_mgc_sem);
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
                class_decref(obd, "mgc_fs", obd);
        }

        cli->cl_mgc_vfsmnt = NULL;
        if (obd->obd_fsops)
                fsfilt_put_ops(obd->obd_fsops);

        cfs_up(&cli->cl_mgc_sem);

        RETURN(rc);
}

static cfs_atomic_t mgc_count = CFS_ATOMIC_INIT(0);
static int mgc_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        int rc = 0;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_EARLY:
                break;
        case OBD_CLEANUP_EXPORTS:
                if (cfs_atomic_dec_and_test(&mgc_count)) {
                        /* Kick the requeue waitq - cld's should all be
                           stopping */
                        cfs_spin_lock(&config_list_lock);
                        rq_state |= RQ_STOP;
                        cfs_spin_unlock(&config_list_lock);
                        cfs_waitq_signal(&rq_waitq);
                }
                obd_cleanup_client_import(obd);
                rc = obd_llog_finish(obd, 0);
                if (rc != 0)
                        CERROR("failed to cleanup llogging subsystems\n");
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

        lprocfs_obd_cleanup(obd);
        ptlrpcd_decref();

        rc = client_obd_cleanup(obd);
        RETURN(rc);
}

static int mgc_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        ptlrpcd_addref();

        rc = client_obd_setup(obd, lcfg);
        if (rc)
                GOTO(err_decref, rc);

        rc = obd_llog_init(obd, &obd->obd_olg, obd, NULL);
        if (rc) {
                CERROR("failed to setup llogging subsystems\n");
                GOTO(err_cleanup, rc);
        }

        lprocfs_mgc_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);
        sptlrpc_lprocfs_cliobd_attach(obd);

        cfs_spin_lock(&config_list_lock);
        cfs_atomic_inc(&mgc_count);
        if (cfs_atomic_read(&mgc_count) == 1) {
                rq_state &= ~RQ_STOP;
                cfs_waitq_init(&rq_waitq);
        }
        cfs_spin_unlock(&config_list_lock);

        RETURN(rc);

err_cleanup:
        client_obd_cleanup(obd);
err_decref:
        ptlrpcd_decref();
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

                if (!cld) {
                        CERROR("missing data, won't requeue\n");
                        break;
                }
                /* Are we done with this log? */
                if (cld->cld_stopping) {
                        CDEBUG(D_MGC, "log %s: stopping, won't requeue\n",
                               cld->cld_logname);
                        config_log_put(cld);
                        break;
                }
                /* Make sure not to re-enqueue when the mgc is stopping
                   (we get called from client_disconnect_export) */
                if (!lock->l_conn_export ||
                    !lock->l_conn_export->exp_obd->u.cli.cl_conn_count) {
                        CDEBUG(D_MGC, "log %s: disconnecting, won't requeue\n",
                               cld->cld_logname);
                        config_log_put(cld);
                        break;
                }
                /* Did we fail to get the lock? */
                if (lock->l_req_mode != lock->l_granted_mode &&
                    !cld->cld_is_sptlrpc) {
                        CDEBUG(D_MGC, "log %s: original grant failed, will "
                               "requeue later\n", cld->cld_logname);
                        /* Try to re-enqueue later */
                        rc = mgc_requeue_add(cld, 1);
                        break;
                }
                /* Re-enqueue now */
                rc = mgc_requeue_add(cld, 0);
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

/* Not sure where this should go... */
#define  MGC_ENQUEUE_LIMIT 50
#define  MGC_TARGET_REG_LIMIT 10
#define  MGC_SEND_PARAM_LIMIT 10

/* Send parameter to MGS*/
static int mgc_set_mgs_param(struct obd_export *exp,
                             struct mgs_send_param *msp)
{
        struct ptlrpc_request *req;
        struct mgs_send_param *req_msp, *rep_msp;
        int rc;
        ENTRY;

        req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
                                        &RQF_MGS_SET_INFO, LUSTRE_MGS_VERSION,
                                        MGS_SET_INFO);
        if (!req)
                RETURN(-ENOMEM);

        req_msp = req_capsule_client_get(&req->rq_pill, &RMF_MGS_SEND_PARAM);
        if (!req_msp) {
                ptlrpc_req_finished(req);
                RETURN(-ENOMEM);
        }

        memcpy(req_msp, msp, sizeof(*req_msp));
        ptlrpc_request_set_replen(req);

        /* Limit how long we will wait for the enqueue to complete */
        req->rq_delay_limit = MGC_SEND_PARAM_LIMIT;
        rc = ptlrpc_queue_wait(req);
        if (!rc) {
                rep_msp = req_capsule_server_get(&req->rq_pill, &RMF_MGS_SEND_PARAM);
                memcpy(msp, rep_msp, sizeof(*rep_msp));
        }

        ptlrpc_req_finished(req);

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
        struct ldlm_enqueue_info einfo = { type, mode, mgc_blocking_ast,
                         ldlm_completion_ast, NULL, NULL, data};
        struct ptlrpc_request *req;
        int short_limit = cld->cld_is_sptlrpc;
        int rc;
        ENTRY;

        CDEBUG(D_MGC, "Enqueue for %s (res "LPX64")\n", cld->cld_logname,
               cld->cld_resid.name[0]);

        /* We can only drop this config log ref when we drop the lock */
        if (config_log_get(cld))
                RETURN(ELDLM_LOCK_ABORTED);

        /* We need a callback for every lockholder, so don't try to
           ldlm_lock_match (see rev 1.1.2.11.2.47) */
        req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
                                        &RQF_LDLM_ENQUEUE, LUSTRE_DLM_VERSION,
                                        LDLM_ENQUEUE);
        if (req == NULL)
                RETURN(-ENOMEM);
        ptlrpc_request_set_replen(req);
        /* check if this is server or client */
        if (cld->cld_cfg.cfg_sb) {
                struct lustre_sb_info *lsi = s2lsi(cld->cld_cfg.cfg_sb);
                if (lsi && (lsi->lsi_flags & LSI_SERVER))
                        short_limit = 1;
        }
        /* Limit how long we will wait for the enqueue to complete */
        req->rq_delay_limit = short_limit ? 5 : MGC_ENQUEUE_LIMIT;
        rc = ldlm_cli_enqueue(exp, &req, &einfo, &cld->cld_resid, NULL, flags,
                              NULL, 0, lockh, 0);
        /* A failed enqueue should still call the mgc_blocking_ast,
           where it will be requeued if needed ("grant failed"). */
        ptlrpc_req_finished(req);
        RETURN(rc);
}

static int mgc_cancel(struct obd_export *exp, struct lov_stripe_md *md,
                      __u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

/* Send target_reg message to MGS */
static int mgc_target_register(struct obd_export *exp,
                               struct mgs_target_info *mti)
{
        struct ptlrpc_request  *req;
        struct mgs_target_info *req_mti, *rep_mti;
        int                     rc;
        ENTRY;

        req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
                                        &RQF_MGS_TARGET_REG, LUSTRE_MGS_VERSION,
                                        MGS_TARGET_REG);
        if (req == NULL)
                RETURN(-ENOMEM);

        req_mti = req_capsule_client_get(&req->rq_pill, &RMF_MGS_TARGET_INFO);
        if (!req_mti) {
                ptlrpc_req_finished(req);
                RETURN(-ENOMEM);
        }

        memcpy(req_mti, mti, sizeof(*req_mti));
        ptlrpc_request_set_replen(req);
        CDEBUG(D_MGC, "register %s\n", mti->mti_svname);
        /* Limit how long we will wait for the enqueue to complete */
        req->rq_delay_limit = MGC_TARGET_REG_LIMIT;

        rc = ptlrpc_queue_wait(req);
        if (!rc) {
                rep_mti = req_capsule_server_get(&req->rq_pill,
                                                 &RMF_MGS_TARGET_INFO);
                memcpy(mti, rep_mti, sizeof(*rep_mti));
                CDEBUG(D_MGC, "register %s got index = %d\n",
                       mti->mti_svname, mti->mti_stripe_index);
        }
        ptlrpc_req_finished(req);

        RETURN(rc);
}

int mgc_set_info_async(struct obd_export *exp, obd_count keylen,
                       void *key, obd_count vallen, void *val,
                       struct ptlrpc_request_set *set)
{
        int rc = -EINVAL;
        ENTRY;

        /* Turn off initial_recov after we try all backup servers once */
        if (KEY_IS(KEY_INIT_RECOV_BACKUP)) {
                struct obd_import *imp = class_exp2cliimp(exp);
                int value;
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                value = *(int *)val;
                CDEBUG(D_MGC, "InitRecov %s %d/d%d:i%d:r%d:or%d:%s\n",
                       imp->imp_obd->obd_name, value,
                       imp->imp_deactive, imp->imp_invalid,
                       imp->imp_replayable, imp->imp_obd->obd_replayable,
                       ptlrpc_import_state_name(imp->imp_state));
                /* Resurrect if we previously died */
                if ((imp->imp_state != LUSTRE_IMP_FULL &&
                     imp->imp_state != LUSTRE_IMP_NEW) || value > 1)
                        ptlrpc_reconnect_import(imp);
                RETURN(0);
        }
        /* FIXME move this to mgc_process_config */
        if (KEY_IS(KEY_REGISTER_TARGET)) {
                struct mgs_target_info *mti;
                if (vallen != sizeof(struct mgs_target_info))
                        RETURN(-EINVAL);
                mti = (struct mgs_target_info *)val;
                CDEBUG(D_MGC, "register_target %s %#x\n",
                       mti->mti_svname, mti->mti_flags);
                rc =  mgc_target_register(exp, mti);
                RETURN(rc);
        }
        if (KEY_IS(KEY_SET_FS)) {
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
        if (KEY_IS(KEY_CLEAR_FS)) {
                if (vallen != 0)
                        RETURN(-EINVAL);
                rc = mgc_fs_cleanup(exp->exp_obd);
                if (rc) {
                        CERROR("clear_fs got %d\n", rc);
                }
                RETURN(rc);
        }
        if (KEY_IS(KEY_SET_INFO)) {
                struct mgs_send_param *msp;

                msp = (struct mgs_send_param *)val;
                rc =  mgc_set_mgs_param(exp, msp);
                RETURN(rc);
        }
        if (KEY_IS(KEY_MGSSEC)) {
                struct client_obd     *cli = &exp->exp_obd->u.cli;
                struct sptlrpc_flavor  flvr;

                /*
                 * empty string means using current flavor, if which haven't
                 * been set yet, set it as null.
                 *
                 * if flavor has been set previously, check the asking flavor
                 * must match the existing one.
                 */
                if (vallen == 0) {
                        if (cli->cl_flvr_mgc.sf_rpc != SPTLRPC_FLVR_INVALID)
                                RETURN(0);
                        val = "null";
                        vallen = 4;
                }

                rc = sptlrpc_parse_flavor(val, &flvr);
                if (rc) {
                        CERROR("invalid sptlrpc flavor %s to MGS\n",
                               (char *) val);
                        RETURN(rc);
                }

                /*
                 * caller already hold a mutex
                 */
                if (cli->cl_flvr_mgc.sf_rpc == SPTLRPC_FLVR_INVALID) {
                        cli->cl_flvr_mgc = flvr;
                } else if (memcmp(&cli->cl_flvr_mgc, &flvr,
                                  sizeof(flvr)) != 0) {
                        char    str[20];

                        sptlrpc_flavor2name(&cli->cl_flvr_mgc,
                                            str, sizeof(str));
                        LCONSOLE_ERROR("asking sptlrpc flavor %s to MGS but "
                                       "currently %s is in use\n",
                                       (char *) val, str);
                        rc = -EPERM;
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
                break;
        case IMP_EVENT_INACTIVE:
                break;
        case IMP_EVENT_INVALIDATE: {
                struct ldlm_namespace *ns = obd->obd_namespace;
                ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);
                break;
        }
        case IMP_EVENT_ACTIVE:
                LCONSOLE_WARN("%s: Reactivating import\n", obd->obd_name);
                /* Clearing obd_no_recov allows us to continue pinging */
                obd->obd_no_recov = 0;
                break;
        case IMP_EVENT_OCD:
                break;
        case IMP_EVENT_DEACTIVATE:
        case IMP_EVENT_ACTIVATE:
                break;
        default:
                CERROR("Unknown import event %#x\n", event);
                LBUG();
        }
        RETURN(rc);
}

static int mgc_llog_init(struct obd_device *obd, struct obd_llog_group *olg,
                         struct obd_device *tgt, int *index)
{
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        LASSERT(olg == &obd->obd_olg);

        rc = llog_setup(obd, olg, LLOG_CONFIG_ORIG_CTXT, tgt, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                RETURN(rc);

        rc = llog_setup(obd, olg, LLOG_CONFIG_REPL_CTXT, tgt, 0, NULL,
                        &llog_client_ops);
        if (rc == 0) {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                if (!ctxt) {
                        ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                        if (ctxt)
                                llog_cleanup(ctxt);
                        RETURN(-ENODEV);
                }
                llog_initiator_connect(ctxt);
                llog_ctxt_put(ctxt);
        } else {
                ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                if (ctxt)
                        llog_cleanup(ctxt);
        }

        RETURN(rc);
}

static int mgc_llog_finish(struct obd_device *obd, int count)
{
        struct llog_ctxt *ctxt;
        int rc = 0, rc2 = 0;
        ENTRY;

        ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
        if (ctxt)
                rc = llog_cleanup(ctxt);

        ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
        if (ctxt)
                rc2 = llog_cleanup(ctxt);

        if (!rc)
                rc = rc2;

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

        /* Append all records */
        local_rec.lrh_len -= sizeof(*rec) + sizeof(struct llog_rec_tail);
        rc = llog_write_rec(local_llh, &local_rec, NULL, 0,
                            (void *)cfg_buf, -1);

        lcfg = (struct lustre_cfg *)cfg_buf;
        CDEBUG(D_INFO, "idx=%d, rc=%d, len=%d, cmd %x %s %s\n",
               rec->lrh_index, rc, rec->lrh_len, lcfg->lcfg_command,
               lustre_cfg_string(lcfg, 0), lustre_cfg_string(lcfg, 1));

        RETURN(rc);
}

/* Copy a remote log locally */
static int mgc_copy_llog(struct obd_device *obd, struct llog_ctxt *rctxt,
                         struct llog_ctxt *lctxt, char *logname)
{
        struct llog_handle *local_llh, *remote_llh;
        struct obd_uuid *uuid;
        char *temp_log;
        int rc, rc2;
        ENTRY;

        /* Write new log to a temp name, then vfs_rename over logname
           upon successful completion. */

        OBD_ALLOC(temp_log, strlen(logname) + 1);
        if (!temp_log)
                RETURN(-ENOMEM);
        sprintf(temp_log, "%sT", logname);

        /* Make sure there's no old temp log */
        rc = llog_create(lctxt, &local_llh, NULL, temp_log);
        if (rc)
                GOTO(out, rc);
        rc = llog_init_handle(local_llh, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out, rc);
        rc = llog_destroy(local_llh);
        llog_free_handle(local_llh);
        if (rc)
                GOTO(out, rc);

        /* open local log */
        rc = llog_create(lctxt, &local_llh, NULL, temp_log);
        if (rc)
                GOTO(out, rc);

        /* set the log header uuid for fun */
        OBD_ALLOC_PTR(uuid);
        obd_str2uuid(uuid, logname);
        rc = llog_init_handle(local_llh, LLOG_F_IS_PLAIN, uuid);
        OBD_FREE_PTR(uuid);
        if (rc)
                GOTO(out_closel, rc);

        /* open remote log */
        rc = llog_create(rctxt, &remote_llh, NULL, logname);
        if (rc)
                GOTO(out_closel, rc);
        rc = llog_init_handle(remote_llh, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out_closer, rc);

        /* Copy remote log */
        rc = llog_process(remote_llh, mgc_copy_handler,(void *)local_llh, NULL);

out_closer:
        rc2 = llog_close(remote_llh);
        if (!rc)
                rc = rc2;
out_closel:
        rc2 = llog_close(local_llh);
        if (!rc)
                rc = rc2;

        /* We've copied the remote log to the local temp log, now
           replace the old local log with the temp log. */
        if (!rc) {
                struct client_obd *cli = &obd->u.cli;
                LASSERT(cli);
                LASSERT(cli->cl_mgc_configs_dir);
                rc = lustre_rename(cli->cl_mgc_configs_dir, cli->cl_mgc_vfsmnt,
                                   temp_log, logname);
        }
        CDEBUG(D_MGC, "Copied remote log %s (%d)\n", logname, rc);
out:
        if (rc)
                CERROR("Failed to copy remote log %s (%d)\n", logname, rc);
        OBD_FREE(temp_log, strlen(logname) + 1);
        RETURN(rc);
}

/** Get a config log from the MGS and process it.
 * This func is called for both clients and servers.
 * Copy the log locally before parsing it if appropriate (non-MGS server)
 */
int mgc_process_log(struct obd_device *mgc,
                    struct config_llog_data *cld)
{
        struct llog_ctxt *ctxt, *lctxt;
        struct lustre_handle lockh;
        struct client_obd *cli = &mgc->u.cli;
        struct lvfs_run_ctxt *saved_ctxt;
        struct lustre_sb_info *lsi = NULL;
        int rc = 0, rcl, flags = 0, must_pop = 0;
        ENTRY;

        LASSERT(cld);

        /* I don't want multiple processes running process_log at once --
           sounds like badness.  It actually might be fine, as long as
           we're not trying to update from the same log
           simultaneously (in which case we should use a per-log sem.) */
        cfs_mutex_lock(&cld->cld_lock);

        if (cld->cld_stopping) {
                cfs_mutex_unlock(&cld->cld_lock);
                RETURN(0);
        }

        OBD_FAIL_TIMEOUT(OBD_FAIL_MGC_PAUSE_PROCESS_LOG, 20);

        if (cld->cld_cfg.cfg_sb)
                lsi = s2lsi(cld->cld_cfg.cfg_sb);

        CDEBUG(D_MGC, "Process log %s:%p from %d\n", cld->cld_logname,
               cld->cld_cfg.cfg_instance, cld->cld_cfg.cfg_last_idx + 1);

        ctxt = llog_get_context(mgc, LLOG_CONFIG_REPL_CTXT);
        if (!ctxt) {
                CERROR("missing llog context\n");
                cfs_mutex_unlock(&cld->cld_lock);
                RETURN(-EINVAL);
        }

        OBD_ALLOC_PTR(saved_ctxt);
        if (saved_ctxt == NULL) {
                cfs_mutex_unlock(&cld->cld_lock);
                RETURN(-ENOMEM);
        }

        /* Get the cfg lock on the llog */
        rcl = mgc_enqueue(mgc->u.cli.cl_mgc_mgsexp, NULL, LDLM_PLAIN, NULL,
                          LCK_CR, &flags, NULL, NULL, NULL,
                          cld, 0, NULL, &lockh);
        if (rcl)
                CDEBUG(D_MGC, "Can't get cfg lock: %d\n", rcl);

        lctxt = llog_get_context(mgc, LLOG_CONFIG_ORIG_CTXT);

        /*
         * local copy of sptlrpc log is controlled elsewhere, don't try to
         * read it up here.
         */
        if (rcl && cld->cld_is_sptlrpc)
                GOTO(out_pop, rc);

        /* Copy the setup log locally if we can. Don't mess around if we're
           running an MGS though (logs are already local). */
        if (lctxt && lsi && (lsi->lsi_flags & LSI_SERVER) &&
            (lsi->lsi_srv_mnt == cli->cl_mgc_vfsmnt) &&
            !IS_MGS(lsi->lsi_ldd)) {
                push_ctxt(saved_ctxt, &mgc->obd_lvfs_ctxt, NULL);
                must_pop++;
                if (rcl == 0)
                        /* Only try to copy log if we have the lock. */
                        rc = mgc_copy_llog(mgc, ctxt, lctxt, cld->cld_logname);
                if (rcl || rc) {
                        if (mgc_llog_is_empty(mgc, lctxt, cld->cld_logname)) {
                                LCONSOLE_ERROR_MSG(0x13a, "Failed to get MGS "
                                                   "log %s and no local copy."
                                                   "\n", cld->cld_logname);
                                GOTO(out_pop, rc = -ENOTCONN);
                        }
                        CDEBUG(D_MGC, "Failed to get MGS log %s, using local "
                               "copy for now, will try to update later.\n",
                               cld->cld_logname);
                }
                /* Now, whether we copied or not, start using the local llog.
                   If we failed to copy, we'll start using whatever the old
                   log has. */
                llog_ctxt_put(ctxt);
                ctxt = lctxt;
        }

        if (cld->cld_is_sptlrpc)
                sptlrpc_conf_log_update_begin(cld->cld_logname);

        /* logname and instance info should be the same, so use our
           copy of the instance for the update.  The cfg_last_idx will
           be updated here. */
        if (rcl == 0 || lctxt == ctxt)
                rc = class_config_parse_llog(ctxt, cld->cld_logname, &cld->cld_cfg);
out_pop:
        llog_ctxt_put(ctxt);
        if (ctxt != lctxt)
                llog_ctxt_put(lctxt);
        if (must_pop)
                pop_ctxt(saved_ctxt, &mgc->obd_lvfs_ctxt, NULL);

        OBD_FREE_PTR(saved_ctxt);
        /*
         * update settings on existing OBDs. doing it inside
         * of llog_process_lock so no device is attaching/detaching
         * in parallel.
         * the logname must be <fsname>-sptlrpc
         */
        if (cld->cld_is_sptlrpc && rcl == 0) {
                sptlrpc_conf_log_update_end(cld->cld_logname);
                class_notify_sptlrpc_conf(cld->cld_logname,
                                          strlen(cld->cld_logname) -
                                          strlen("-sptlrpc"));
        }

        /* Now drop the lock so MGS can revoke it */
        if (!rcl) {
                rcl = mgc_cancel(mgc->u.cli.cl_mgc_mgsexp, NULL,
                                 LCK_CR, &lockh);
                if (rcl)
                        CERROR("Can't drop cfg lock: %d\n", rcl);
        }

        CDEBUG(D_MGC, "%s: configuration from log '%s' %sed (%d).\n",
               mgc->obd_name, cld->cld_logname, rc ? "fail" : "succeed", rc);

        cfs_mutex_unlock(&cld->cld_lock);

        RETURN(rc);
}

/** Called from lustre_process_log.
 * LCFG_LOG_START gets the config log from the MGS, processes it to start
 * any services, and adds it to the list logs to watch (follow).
 */
static int mgc_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct config_llog_instance *cfg = NULL;
        char *logname;
        int rc = 0;
        ENTRY;

        switch(lcfg->lcfg_command) {
        case LCFG_LOV_ADD_OBD: {
                /* Overloading this cfg command: register a new target */
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
                /* Unregister has no meaning at the moment. */
                CERROR("lov_del_obd unimplemented\n");
                rc = -ENOSYS;
                break;
        case LCFG_SPTLRPC_CONF: {
                rc = sptlrpc_process_config(lcfg);
                break;
        }
        case LCFG_LOG_START: {
                struct config_llog_data *cld;
                struct super_block *sb;

                logname = lustre_cfg_string(lcfg, 1);
                cfg = (struct config_llog_instance *)lustre_cfg_buf(lcfg, 2);
                sb = *(struct super_block **)lustre_cfg_buf(lcfg, 3);

                CDEBUG(D_MGC, "parse_log %s from %d\n", logname,
                       cfg->cfg_last_idx);

                /* We're only called through here on the initial mount */
                rc = config_log_add(obd, logname, cfg, sb);
                if (rc)
                        break;
                cld = config_log_find(logname, cfg);
                if (cld == NULL) {
                        rc = -ENOENT;
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
                logname = lustre_cfg_string(lcfg, 1);

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

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Management Client");
MODULE_LICENSE("GPL");

module_init(mgc_init);
module_exit(mgc_exit);
#endif
