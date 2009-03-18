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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/obd_mount.c
 *
 * Client/server mount routines
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */


#define DEBUG_SUBSYSTEM S_CLASS
#define D_MOUNT D_SUPER|D_CONFIG /*|D_WARNING */
#define PRINT_CMD CDEBUG
#define PRINT_MASK D_SUPER|D_CONFIG

#include <obd.h>
#include <lvfs.h>
#include <lustre_fsfilt.h>
#include <obd_class.h>
#include <lustre/lustre_user.h>
#include <linux/version.h>
#include <lustre_log.h>
#include <lustre_disk.h>
#include <lustre_param.h>

static int (*client_fill_super)(struct super_block *sb) = NULL;
static void (*kill_super_cb)(struct super_block *sb) = NULL;

struct mconf_device {
        struct lu_device  mcf_lu_dev;
        struct lu_device *mcf_bottom;
};

struct mconf_object {
        struct lu_object_header mco_header;
        struct lu_object        mco_obj;
};

static inline struct mconf_device *mconf_dev(struct lu_device *d)
{
        return container_of0(d, struct mconf_device, mcf_lu_dev);
}

static struct mconf_object *mconf_obj(struct lu_object *o)
{
        return container_of0(o, struct mconf_object, mco_obj);
}

static char *mconf_get_label(struct dt_device *dt);
static int mconf_set_label(struct dt_device *dt, char *label);


/*********** mount lookup *********/

DECLARE_MUTEX(lustre_mount_info_lock);
static CFS_LIST_HEAD(server_mount_info_list);

static struct lustre_mount_info *server_find_mount(const char *name)
{
        struct list_head *tmp;
        struct lustre_mount_info *lmi;
        ENTRY;

        list_for_each(tmp, &server_mount_info_list) {
                lmi = list_entry(tmp, struct lustre_mount_info, lmi_list_chain);
                if (strcmp(name, lmi->lmi_name) == 0)
                        RETURN(lmi);
        }
        RETURN(NULL);
}

/* we must register an obd for a mount before we call the setup routine.
   *_setup will call lustre_get_mount to get the mnt struct
   by obd_name, since we can't pass the pointer to setup. */
static int server_register_mount(const char *name, struct super_block *sb,
                          struct dt_device *dt)
{
        struct lustre_mount_info *lmi;
        char *name_cp;
        ENTRY;

        LASSERT(dt);
        LASSERT(sb);

        OBD_ALLOC(lmi, sizeof(*lmi));
        if (!lmi)
                RETURN(-ENOMEM);
        OBD_ALLOC(name_cp, strlen(name) + 1);
        if (!name_cp) {
                OBD_FREE(lmi, sizeof(*lmi));
                RETURN(-ENOMEM);
        }
        strcpy(name_cp, name);

        down(&lustre_mount_info_lock);

        if (server_find_mount(name)) {
                up(&lustre_mount_info_lock);
                OBD_FREE(lmi, sizeof(*lmi));
                OBD_FREE(name_cp, strlen(name) + 1);
                CERROR("Already registered %s\n", name);
                RETURN(-EEXIST);
        }
        lmi->lmi_name = name_cp;
        lmi->lmi_sb = sb;
        lmi->lmi_dt = dt;
        list_add(&lmi->lmi_list_chain, &server_mount_info_list);

        up(&lustre_mount_info_lock);

        CDEBUG(D_MOUNT, "reg_dt %p from %s\n", lmi->lmi_dt, name);

        RETURN(0);
}

/* when an obd no longer needs a mount */
static int server_deregister_mount(const char *name)
{
        struct lustre_mount_info *lmi;
        ENTRY;

        down(&lustre_mount_info_lock);
        lmi = server_find_mount(name);
        if (!lmi) {
                up(&lustre_mount_info_lock);
                CERROR("%s not registered\n", name);
                RETURN(-ENOENT);
        }

        CDEBUG(D_MOUNT, "dereg_dt %p from %s\n", lmi->lmi_dt, name);

        OBD_FREE(lmi->lmi_name, strlen(lmi->lmi_name) + 1);
        list_del(&lmi->lmi_list_chain);
        OBD_FREE(lmi, sizeof(*lmi));
        up(&lustre_mount_info_lock);

        RETURN(0);
}

/* obd's look up a registered mount using their obdname. This is just
   for initial obd setup to find the mount struct.  It should not be
   called every time you want to mntget. */
struct lustre_mount_info *server_get_mount(const char *name)
{
        struct lustre_mount_info *lmi;
        struct lustre_sb_info *lsi;
        ENTRY;

        down(&lustre_mount_info_lock);
        lmi = server_find_mount(name);
        up(&lustre_mount_info_lock);
        if (!lmi) {
                CERROR("Can't find mount for %s\n", name);
                RETURN(NULL);
        }
        lsi = s2lsi(lmi->lmi_sb);
        atomic_inc(&lsi->lsi_mounts);

        CDEBUG(D_MOUNT, "%p/%p from %s, refs=%d\n",
               lmi->lmi_sb, lsi, name, atomic_read(&lsi->lsi_mounts));

        RETURN(lmi);
}

/*
 * Used by mdt to get mount_info from obdname.
 * There are no blocking when using the mount_info.
 * Do not use server_get_mount for this purpose.
 */
struct lustre_mount_info *server_get_mount_2(const char *name)
{
        struct lustre_mount_info *lmi;
        ENTRY;

        down(&lustre_mount_info_lock);
        lmi = server_find_mount(name);
        up(&lustre_mount_info_lock);
        if (!lmi)
                CERROR("Can't find mount for %s\n", name);

        RETURN(lmi);
}

static void unlock_mntput(struct vfsmount *mnt)
{
        if (kernel_locked()) {
                unlock_kernel();
                mntput(mnt);
                lock_kernel();
        } else {
                mntput(mnt);
        }
}

static int lustre_put_lsi(struct super_block *sb);

/* to be called from obd_cleanup methods */
int server_put_mount(const char *name)
{
        struct lustre_mount_info *lmi;
        struct lustre_sb_info *lsi;
        ENTRY;

        down(&lustre_mount_info_lock);
        lmi = server_find_mount(name);
        up(&lustre_mount_info_lock);
        if (!lmi) {
                CERROR("Can't find mount for %s\n", name);
                RETURN(-ENOENT);
        }
        lsi = s2lsi(lmi->lmi_sb);

        CDEBUG(D_MOUNT, "%p/%p from %s, refs=%d\n",
               lmi->lmi_sb, lsi, name, atomic_read(&lsi->lsi_mounts));

        if (lustre_put_lsi(lmi->lmi_sb)) {
                CDEBUG(D_MOUNT, "Last put from %s\n", name);
#if 0
                /* last mount is the One True Mount */
                if (count > 1)
                        CERROR("%s: mount busy, vfscount=%d!\n", name, count);
#endif
        }

        /* this obd should never need the mount again */
        server_deregister_mount(name);
        RETURN(0);
}

/* Corresponding to server_get_mount_2 */
int server_put_mount_2(const char *name)
{
        ENTRY;
        RETURN(0);
}

/******* mount helper utilities *********/

#if 0
static void ldd_print(struct lustre_disk_data *ldd)
{
        PRINT_CMD(PRINT_MASK, "  disk data:\n");
        PRINT_CMD(PRINT_MASK, "server:  %s\n", ldd->ldd_svname);
        PRINT_CMD(PRINT_MASK, "uuid:    %s\n", (char *)ldd->ldd_uuid);
        PRINT_CMD(PRINT_MASK, "fs:      %s\n", ldd->ldd_fsname);
        PRINT_CMD(PRINT_MASK, "index:   %04x\n", ldd->ldd_svindex);
        PRINT_CMD(PRINT_MASK, "config:  %d\n", ldd->ldd_config_ver);
        PRINT_CMD(PRINT_MASK, "flags:   %#x\n", ldd->ldd_flags);
        PRINT_CMD(PRINT_MASK, "diskfs:  %s\n", MT_STR(ldd));
        PRINT_CMD(PRINT_MASK, "options: %s\n", ldd->ldd_mount_opts);
        PRINT_CMD(PRINT_MASK, "params:  %s\n", ldd->ldd_params);
        PRINT_CMD(PRINT_MASK, "comment: %s\n", ldd->ldd_userdata);
}
#endif

static int ldd_write(struct dt_device *dt, struct lustre_disk_data *ldd)
{
        struct lu_env          env;
        int                    rc;
        struct dt_object      *file;
        struct lu_fid          fid;
        struct lu_buf          buf;
        loff_t                 pos;
        struct thandle        *th;

        if (dt->dd_lu_dev.ld_site == NULL) {
                /* no configuration file */
                return 0;
        }

        rc = lu_env_init(&env, dt->dd_lu_dev.ld_type->ldt_ctx_tags);
        LASSERT(rc == 0);

        file = dt_store_open(&env, dt, MOUNT_CONFIGS_DIR, CONFIGS_FILE, &fid);
        LASSERT(!IS_ERR(file));

        buf.lb_buf = ldd;
        buf.lb_len = sizeof(*ldd);
        pos = 0;

        th = dt->dd_ops->dt_trans_create(&env, dt);
        LASSERT(!IS_ERR(th));
        rc = dt_declare_record_write(&env, file, buf.lb_len, pos, th);
        LASSERT(rc == 0);
        rc = dt->dd_ops->dt_trans_start(&env, dt, th);
        LASSERT(rc == 0);

        rc = dt_record_write(&env, file, &buf, &pos, th, BYPASS_CAPA, 1);

        dt->dd_ops->dt_trans_stop(&env, th);

        lu_object_put(&env, &file->do_lu);
        lu_env_fini(&env);
        RETURN(0);
}


/**************** config llog ********************/

/* Get a config log from the MGS and process it.
   This func is called for both clients and servers.
   Continue to process new statements appended to the logs
   (whenever the config lock is revoked) until lustre_end_log
   is called. */
int lustre_process_log(struct super_block *sb, char *logname,
                     struct config_llog_instance *cfg)
{
        struct lustre_cfg *lcfg;
        struct lustre_cfg_bufs bufs;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        int rc;
        ENTRY;

        LASSERT(mgc);
        LASSERT(cfg);

        /* mgc_process_config */
        lustre_cfg_bufs_reset(&bufs, mgc->obd_name);
        lustre_cfg_bufs_set_string(&bufs, 1, logname);
        lustre_cfg_bufs_set(&bufs, 2, cfg, sizeof(*cfg));
        lustre_cfg_bufs_set(&bufs, 3, &sb, sizeof(sb));
        lcfg = lustre_cfg_new(LCFG_LOG_START, &bufs);
        rc = obd_process_config(mgc, sizeof(*lcfg), lcfg);
        lustre_cfg_free(lcfg);

        if (rc == -EINVAL)
                LCONSOLE_ERROR_MSG(0x15b, "%s: The configuration from log '%s'"
                                   "failed from the MGS (%d).  Make sure this "
                                   "client and the MGS are running compatible "
                                   "versions of Lustre.\n",
                                   mgc->obd_name, logname, rc);

        if (rc)
                LCONSOLE_ERROR_MSG(0x15c, "%s: The configuration from log '%s' "
                                   "failed (%d). This may be the result of "
                                   "communication errors between this node and "
                                   "the MGS, a bad configuration, or other "
                                   "errors. See the syslog for more "
                                   "information.\n", mgc->obd_name, logname,
                                   rc);

        /* class_obd_list(); */
        RETURN(rc);
}

/* Stop watching this config log for updates */
int lustre_end_log(struct super_block *sb, char *logname,
                       struct config_llog_instance *cfg)
{
        struct lustre_cfg *lcfg;
        struct lustre_cfg_bufs bufs;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        int rc;
        ENTRY;

        if (!mgc)
                RETURN(-ENOENT);

        /* mgc_process_config */
        lustre_cfg_bufs_reset(&bufs, mgc->obd_name);
        lustre_cfg_bufs_set_string(&bufs, 1, logname);
        if (cfg)
                lustre_cfg_bufs_set(&bufs, 2, cfg, sizeof(*cfg));
        lcfg = lustre_cfg_new(LCFG_LOG_END, &bufs);
        rc = obd_process_config(mgc, sizeof(*lcfg), lcfg);
        lustre_cfg_free(lcfg);
        RETURN(rc);
}

/**************** obd start *******************/

int do_lcfg(char *cfgname, lnet_nid_t nid, int cmd,
            char *s1, char *s2, char *s3, char *s4)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg    * lcfg = NULL;
        int rc;

        CDEBUG(D_TRACE, "lcfg %s %#x %s %s %s %s\n", cfgname,
               cmd, s1, s2, s3, s4);

        lustre_cfg_bufs_reset(&bufs, cfgname);
        if (s1)
                lustre_cfg_bufs_set_string(&bufs, 1, s1);
        if (s2)
                lustre_cfg_bufs_set_string(&bufs, 2, s2);
        if (s3)
                lustre_cfg_bufs_set_string(&bufs, 3, s3);
        if (s4)
                lustre_cfg_bufs_set_string(&bufs, 4, s4);

        lcfg = lustre_cfg_new(cmd, &bufs);
        lcfg->lcfg_nid = nid;
        rc = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        return(rc);
}

static int lustre_start_simple(char *obdname, char *type, char *uuid,
                               char *s1, char *s2)
{
        int rc;
        CDEBUG(D_MOUNT, "Starting obd %s (typ=%s)\n", obdname, type);

        rc = do_lcfg(obdname, 0, LCFG_ATTACH, type, uuid, 0, 0);
        if (rc) {
                CERROR("%s attach error %d\n", obdname, rc);
                return(rc);
        }
        rc = do_lcfg(obdname, 0, LCFG_SETUP, s1, s2, 0, 0);
        if (rc) {
                CERROR("%s setup error %d\n", obdname, rc);
                do_lcfg(obdname, 0, LCFG_DETACH, 0, 0, 0, 0);
        }
        return rc;
}

/* Set up a MGS to serve startup logs */
static int server_start_mgs(struct super_block *sb)
{
        struct lustre_sb_info    *lsi = s2lsi(sb);
        struct lustre_mount_info *lmi;
        int    rc = 0;
        ENTRY;
        LASSERT(lsi->lsi_dt_dev);

        /* It is impossible to have more than 1 MGS per node, since
           MGC wouldn't know which to connect to */
        lmi = server_find_mount(LUSTRE_MGS_OBDNAME);
        if (lmi) {
                LASSERT(lmi->lmi_sb);
                lsi = s2lsi(lmi->lmi_sb);
                LCONSOLE_ERROR_MSG(0x15d, "The MGS service was already started"
                                   " from server %s\n",
                                   lsi->lsi_ldd->ldd_svname);
                RETURN(-EALREADY);
        }

        CDEBUG(D_CONFIG, "Start MGS service %s\n", LUSTRE_MGS_OBDNAME);

        rc = server_register_mount(LUSTRE_MGS_OBDNAME, sb, lsi->lsi_dt_dev);

        if (!rc) {
                rc = lustre_start_simple(LUSTRE_MGS_OBDNAME, LUSTRE_MGS_NAME,
                                         LUSTRE_MGS_OBDNAME, 0, 0);
                /* Do NOT call server_deregister_mount() here. This leads to
                 * inability cleanup cleanly and free lsi and other stuff when
                 * mgs calls server_put_mount() in error handling case. -umka */
        }

        if (rc)
                LCONSOLE_ERROR_MSG(0x15e, "Failed to start MGS '%s' (%d). "
                                   "Is the 'mgs' module loaded?\n",
                                   LUSTRE_MGS_OBDNAME, rc);
        RETURN(rc);
}

static int server_stop_mgs(struct super_block *sb)
{
        struct obd_device *obd;
        int rc;
        ENTRY;

        CDEBUG(D_MOUNT, "Stop MGS service %s\n", LUSTRE_MGS_OBDNAME);

        /* There better be only one MGS */
        obd = class_name2obd(LUSTRE_MGS_OBDNAME);
        if (!obd) {
                CDEBUG(D_CONFIG, "mgs %s not running\n", LUSTRE_MGS_OBDNAME);
                RETURN(-EALREADY);
        }

        /* The MGS should always stop when we say so */
        obd->obd_force = 1;
        rc = class_manual_cleanup(obd);
        RETURN(rc);
}

DECLARE_MUTEX(mgc_start_lock);

/** Set up a mgc obd to process startup logs
 *
 * \param sb [in] super block of the mgc obd
 *
 * \retval 0 success, otherwise error code
 */
static int lustre_start_mgc(struct super_block *sb)
{
        struct obd_connect_data *data = NULL;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *obd;
        struct obd_export *exp;
        struct obd_uuid *uuid;
        class_uuid_t uuidc;
        lnet_nid_t nid;
        char *mgcname, *niduuid, *mgssec;
        char *ptr;
        int recov_bk;
        int rc = 0, i = 0, j, len;
        ENTRY;

        LASSERT(lsi->lsi_lmd);

        /* Find the first non-lo MGS nid for our MGC name */
        if (lsi->lsi_flags & LSI_SERVER) {
                ptr = lsi->lsi_ldd->ldd_params;
                /* Use mgsnode= nids */
                if ((class_find_param(ptr, PARAM_MGSNODE, &ptr) == 0) &&
                    (class_parse_nid(ptr, &nid, &ptr) == 0)) {
                        i++;
                } else if (lsi->lsi_lmd->lmd_mgs &&
                    (class_parse_nid(lsi->lsi_lmd->lmd_mgs, &nid, NULL) == 0)) {
                        i++;
                } else if (IS_MGS(lsi->lsi_ldd)) {
                        lnet_process_id_t id;
                        while ((rc = LNetGetId(i++, &id)) != -ENOENT) {
                                if (LNET_NETTYP(LNET_NIDNET(id.nid)) == LOLND)
                                        continue;
                                nid = id.nid;
                                i++;
                                break;
                        }
                }
        } else { /* client */
                /* Use nids from mount line: uml1,1@elan:uml2,2@elan:/lustre */
                ptr = lsi->lsi_lmd->lmd_dev;
                if (class_parse_nid(ptr, &nid, &ptr) == 0)
                        i++;
        }
        if (i == 0) {
                CERROR("No valid MGS nids found.\n");
                RETURN(-EINVAL);
        }

        len = strlen(LUSTRE_MGC_OBDNAME) + strlen(libcfs_nid2str(nid)) + 1;
        OBD_ALLOC(mgcname, len);
        OBD_ALLOC(niduuid, len + 2);
        if (!mgcname || !niduuid)
                GOTO(out_free, rc = -ENOMEM);
        sprintf(mgcname, "%s%s", LUSTRE_MGC_OBDNAME, libcfs_nid2str(nid));

        mgssec = lsi->lsi_lmd->lmd_mgssec ? lsi->lsi_lmd->lmd_mgssec : "";

        mutex_down(&mgc_start_lock);

        obd = class_name2obd(mgcname);
        if (obd && !obd->obd_stopping) {
                rc = obd_set_info_async(obd->obd_self_export,
                                        strlen(KEY_MGSSEC), KEY_MGSSEC,
                                        strlen(mgssec), mgssec, NULL);
                if (rc)
                        GOTO(out_free, rc);

                /* Re-using an existing MGC */
                atomic_inc(&obd->u.cli.cl_mgc_refcount);

                recov_bk = 0;
                /* If we are restarting the MGS, don't try to keep the MGC's
                   old connection, or registration will fail. */
                if ((lsi->lsi_flags & LSI_SERVER) && IS_MGS(lsi->lsi_ldd)) {
                        CDEBUG(D_MOUNT, "New MGS with live MGC\n");
                        recov_bk = 1;
                }

                /* Try all connections, but only once (again).
                   We don't want to block another target from starting
                   (using its local copy of the log), but we do want to connect
                   if at all possible. */
                recov_bk++;
                CDEBUG(D_MOUNT, "%s: Set MGC reconnect %d\n", mgcname,recov_bk);
                rc = obd_set_info_async(obd->obd_self_export,
                                        sizeof(KEY_INIT_RECOV_BACKUP),
                                        KEY_INIT_RECOV_BACKUP,
                                        sizeof(recov_bk), &recov_bk, NULL);
                GOTO(out, rc = 0);
        }

        CDEBUG(D_MOUNT, "Start MGC '%s'\n", mgcname);

        /* Add the primary nids for the MGS */
        i = 0;
        sprintf(niduuid, "%s_%x", mgcname, i);
        if (lsi->lsi_flags & LSI_SERVER) {
                ptr = lsi->lsi_ldd->ldd_params;
                if (IS_MGS(lsi->lsi_ldd)) {
                        /* Use local nids (including LO) */
                        lnet_process_id_t id;
                        while ((rc = LNetGetId(i++, &id)) != -ENOENT) {
                                rc = do_lcfg(mgcname, id.nid,
                                             LCFG_ADD_UUID, niduuid, 0,0,0);
                        }
                } else {
                        /* Use mgsnode= nids */
                        if (class_find_param(ptr, PARAM_MGSNODE, &ptr) != 0) {
                                CERROR("No MGS nids given.\n");
                                GOTO(out_free, rc = -EINVAL);
                        }
                        while (class_parse_nid(ptr, &nid, &ptr) == 0) {
                                rc = do_lcfg(mgcname, nid,
                                             LCFG_ADD_UUID, niduuid, 0,0,0);
                                i++;
                        }
                }
        } else { /* client */
                /* Use nids from mount line: uml1,1@elan:uml2,2@elan:/lustre */
                ptr = lsi->lsi_lmd->lmd_dev;
                while (class_parse_nid(ptr, &nid, &ptr) == 0) {
                        rc = do_lcfg(mgcname, nid,
                                     LCFG_ADD_UUID, niduuid, 0,0,0);
                        i++;
                        /* Stop at the first failover nid */
                        if (*ptr == ':')
                                break;
                }
        }
        if (i == 0) {
                CERROR("No valid MGS nids found.\n");
                GOTO(out_free, rc = -EINVAL);
        }
        lsi->lsi_lmd->lmd_mgs_failnodes = 1;

        /* Random uuid for MGC allows easier reconnects */
        OBD_ALLOC_PTR(uuid);
        ll_generate_random_uuid(uuidc);
        class_uuid_unparse(uuidc, uuid);

        /* Start the MGC */
        rc = lustre_start_simple(mgcname, LUSTRE_MGC_NAME,
                                 (char *)uuid->uuid, LUSTRE_MGS_OBDNAME,
                                 niduuid);
        OBD_FREE_PTR(uuid);
        if (rc)
                GOTO(out_free, rc);

        /* Add any failover MGS nids */
        i = 1;
        while ((*ptr == ':' ||
                class_find_param(ptr, PARAM_MGSNODE, &ptr) == 0)) {
                /* New failover node */
                sprintf(niduuid, "%s_%x", mgcname, i);
                j = 0;
                while (class_parse_nid(ptr, &nid, &ptr) == 0) {
                        j++;
                        rc = do_lcfg(mgcname, nid,
                                     LCFG_ADD_UUID, niduuid, 0,0,0);
                        if (*ptr == ':')
                                break;
                }
                if (j > 0) {
                        rc = do_lcfg(mgcname, 0, LCFG_ADD_CONN,
                                     niduuid, 0, 0, 0);
                        i++;
                } else {
                        /* at ":/fsname" */
                        break;
                }
        }
        lsi->lsi_lmd->lmd_mgs_failnodes = i;

        obd = class_name2obd(mgcname);
        if (!obd) {
                CERROR("Can't find mgcobd %s\n", mgcname);
                GOTO(out_free, rc = -ENOTCONN);
        }

        rc = obd_set_info_async(obd->obd_self_export,
                                strlen(KEY_MGSSEC), KEY_MGSSEC,
                                strlen(mgssec), mgssec, NULL);
        if (rc)
                GOTO(out_free, rc);

        /* Keep a refcount of servers/clients who started with "mount",
           so we know when we can get rid of the mgc. */
        atomic_set(&obd->u.cli.cl_mgc_refcount, 1);

        /* Try all connections, but only once. */
        recov_bk = 1;
        rc = obd_set_info_async(obd->obd_self_export,
                                sizeof(KEY_INIT_RECOV_BACKUP),
                                KEY_INIT_RECOV_BACKUP,
                                sizeof(recov_bk), &recov_bk, NULL);
        if (rc)
                /* nonfatal */
                CWARN("can't set %s %d\n", KEY_INIT_RECOV_BACKUP, rc);
        /* We connect to the MGS at setup, and don't disconnect until cleanup */
        OBD_ALLOC_PTR(data);
        if (data == NULL)
                GOTO(out, rc = -ENOMEM);
        data->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_FID |
                                  OBD_CONNECT_AT;
        data->ocd_version = LUSTRE_VERSION_CODE;
        rc = obd_connect(NULL, &exp, obd, &(obd->obd_uuid), data, NULL);
        OBD_FREE_PTR(data);
        if (rc) {
                CERROR("connect failed %d\n", rc);
                GOTO(out, rc);
        }

        obd->u.cli.cl_mgc_mgsexp = exp;

out:
        /* Keep the mgc info in the sb. Note that many lsi's can point
           to the same mgc.*/
        lsi->lsi_mgc = obd;
out_free:
        mutex_up(&mgc_start_lock);

        if (mgcname)
                OBD_FREE(mgcname, len);
        if (niduuid)
                OBD_FREE(niduuid, len + 2);
        RETURN(rc);
}

static int lustre_stop_mgc(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *obd;
        char *niduuid = 0, *ptr = 0;
        int i, rc = 0, len = 0;
        ENTRY;

        if (!lsi)
                RETURN(-ENOENT);
        obd = lsi->lsi_mgc;
        if (!obd)
                RETURN(-ENOENT);
        lsi->lsi_mgc = NULL;

        mutex_down(&mgc_start_lock);
        LASSERT(atomic_read(&obd->u.cli.cl_mgc_refcount) > 0);
        if (!atomic_dec_and_test(&obd->u.cli.cl_mgc_refcount)) {
                /* This is not fatal, every client that stops
                   will call in here. */
                CDEBUG(D_MOUNT, "mgc still has %d references.\n",
                       atomic_read(&obd->u.cli.cl_mgc_refcount));
                GOTO(out, rc = -EBUSY);
        }

        /* The MGC has no recoverable data in any case.
         * force shotdown set in umount_begin */
        obd->obd_no_recov = 1;

        if (obd->u.cli.cl_mgc_mgsexp) {
                /* An error is not fatal, if we are unable to send the
                   disconnect mgs ping evictor cleans up the export */
                rc = obd_disconnect(obd->u.cli.cl_mgc_mgsexp);
                if (rc)
                        CDEBUG(D_MOUNT, "disconnect failed %d\n", rc);
        }

        /* Save the obdname for cleaning the nid uuids, which are
           obdname_XX */
        len = strlen(obd->obd_name) + 6;
        OBD_ALLOC(niduuid, len);
        if (niduuid) {
                strcpy(niduuid, obd->obd_name);
                ptr = niduuid + strlen(niduuid);
        }

        rc = class_manual_cleanup(obd);
        if (rc)
                GOTO(out, rc);

        /* Clean the nid uuids */
        if (!niduuid)
                GOTO(out, rc = -ENOMEM);

        for (i = 0; i < lsi->lsi_lmd->lmd_mgs_failnodes; i++) {
                sprintf(ptr, "_%x", i);
                rc = do_lcfg(LUSTRE_MGC_OBDNAME, 0, LCFG_DEL_UUID,
                             niduuid, 0, 0, 0);
                if (rc)
                        CERROR("del MDC UUID %s failed: rc = %d\n",
                               niduuid, rc);
        }
out:
        if (niduuid)
                OBD_FREE(niduuid, len);

        /* class_import_put will get rid of the additional connections */
        mutex_up(&mgc_start_lock);
        RETURN(rc);
}

/* Since there's only one mgc per node, we have to change it's fs to get
   access to the right disk. */
static int server_mgc_set_fs(struct obd_device *mgc, struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        int rc;
        ENTRY;

        CDEBUG(D_MOUNT, "Set mgc disk for %s\n", lsi->lsi_lmd->lmd_dev);

        /* cl_mgc_sem in mgc insures we sleep if the mgc_fs is busy */
        rc = obd_set_info_async(mgc->obd_self_export,
                                sizeof(KEY_SET_FS), KEY_SET_FS,
                                sizeof(*sb), sb, NULL);
        if (rc) {
                CERROR("can't set_fs %d\n", rc);
        }

        RETURN(rc);
}

static int server_mgc_clear_fs(struct obd_device *mgc)
{
        int rc;
        ENTRY;

        CDEBUG(D_MOUNT, "Unassign mgc disk\n");

        rc = obd_set_info_async(mgc->obd_self_export,
                                sizeof(KEY_CLEAR_FS), KEY_CLEAR_FS,
                                0, NULL, NULL);
        RETURN(rc);
}

DECLARE_MUTEX(server_start_lock);

/* Stop MDS/OSS if nobody is using them */
static int server_stop_servers(int lddflags, int lsiflags)
{
        struct obd_device *obd = NULL;
        struct obd_type *type = NULL;
        int rc = 0;
        ENTRY;

        mutex_down(&server_start_lock);

        /* Either an MDT or an OST or neither  */
        /* if this was an MDT, and there are no more MDT's, clean up the MDS */
        if ((lddflags & LDD_F_SV_TYPE_MDT) &&
            (obd = class_name2obd(LUSTRE_MDS_OBDNAME))) {
                /*FIXME pre-rename, should eventually be LUSTRE_MDT_NAME*/
                type = class_search_type(LUSTRE_MDS_NAME);
        }
        /* if this was an OST, and there are no more OST's, clean up the OSS */
        if ((lddflags & LDD_F_SV_TYPE_OST) &&
            (obd = class_name2obd(LUSTRE_OSS_OBDNAME))) {
                type = class_search_type(LUSTRE_OST_NAME);
        }

        if (obd && (!type || !type->typ_refcnt)) {
                int err;
                obd->obd_force = 1;
                /* obd_fail doesn't mean much on a server obd */
                err = class_manual_cleanup(obd);
                if (!rc)
                        rc = err;
        }

        mutex_up(&server_start_lock);

        RETURN(rc);
}

int server_mti_print(char *title, struct mgs_target_info *mti)
{
        PRINT_CMD(PRINT_MASK, "mti %s\n", title);
        PRINT_CMD(PRINT_MASK, "server: %s\n", mti->mti_svname);
        PRINT_CMD(PRINT_MASK, "fs:     %s\n", mti->mti_fsname);
        PRINT_CMD(PRINT_MASK, "uuid:   %s\n", mti->mti_uuid);
        PRINT_CMD(PRINT_MASK, "ver: %d  flags: %#x\n",
                  mti->mti_config_ver, mti->mti_flags);
        return(0);
}

static int server_label2mti(struct super_block *sb, struct mgs_target_info *mti)
{
        struct                 dt_device_param dt_param;
        struct lustre_sb_info *lsi = s2lsi(sb);
        char *label;

        LASSERT(lsi);
        LASSERT(lsi->lsi_dt_dev);

        /* first, retrieve label */
        label = mconf_get_label(lsi->lsi_dt_dev);
        if (label == NULL)
                return -EINVAL;

        lsi->lsi_dt_dev->dd_ops->dt_conf_get(NULL, lsi->lsi_dt_dev, &dt_param);
        lsi->lsi_ldd->ldd_mount_type = dt_param.ddp_mount_type;

        mti->mti_flags = 0;
        strncpy(mti->mti_svname, label, sizeof(mti->mti_svname));
        mti->mti_svname[sizeof(mti->mti_svname) - 1] = '\0';

        return 0;
}

static int server_sb2mti(struct super_block *sb, struct mgs_target_info *mti)
{
        struct lustre_sb_info    *lsi = s2lsi(sb);
        struct lustre_disk_data  *ldd = lsi->lsi_ldd;
        lnet_process_id_t         id;
        int i = 0;
        ENTRY;

        if (!(lsi->lsi_flags & LSI_SERVER))
                RETURN(-EINVAL);

        mti->mti_nid_count = 0;
        while (LNetGetId(i++, &id) != -ENOENT) {
                if (LNET_NETTYP(LNET_NIDNET(id.nid)) == LOLND)
                        continue;
                mti->mti_nids[mti->mti_nid_count] = id.nid;
                mti->mti_nid_count++;
                if (mti->mti_nid_count >= MTI_NIDS_MAX) {
                        CWARN("Only using first %d nids for %s\n",
                              mti->mti_nid_count, mti->mti_svname);
                        break;
                }
        }

        mti->mti_lustre_ver = LUSTRE_VERSION_CODE;
        mti->mti_config_ver = 0;

        if (ldd->ldd_magic == 0) {
                /* no config, generate data for registration */
                RETURN(server_label2mti(sb, mti));
        }

        strncpy(mti->mti_fsname, ldd->ldd_fsname,
                sizeof(mti->mti_fsname));
        strncpy(mti->mti_svname, ldd->ldd_svname,
                sizeof(mti->mti_svname));

        mti->mti_flags = ldd->ldd_flags;
        mti->mti_stripe_index = ldd->ldd_svindex;
        memcpy(mti->mti_uuid, ldd->ldd_uuid, sizeof(mti->mti_uuid));
        if (strlen(ldd->ldd_params) > sizeof(mti->mti_params)) {
                CERROR("params too big for mti\n");
                RETURN(-ENOMEM);
        }
        memcpy(mti->mti_params, ldd->ldd_params, sizeof(mti->mti_params));
        RETURN(0);
}

static int mconf_set_label(struct dt_device *dt, char *label)
{
        struct lu_env          env;
        int                    rc;

        lu_env_init(&env, dt->dd_lu_dev.ld_type->ldt_ctx_tags);
        rc = dt->dd_ops->dt_label_set(&env, dt, label);
        lu_env_fini(&env);
        return rc;
}

static char *mconf_get_label(struct dt_device *dt)
{
        struct lu_env          env;
        char                  *label;

        lu_env_init(&env, dt->dd_lu_dev.ld_type->ldt_ctx_tags);
        label = dt->dd_ops->dt_label_get(&env, dt);
        lu_env_fini(&env);

        return label;
}

static int mconf_sync_dev(struct dt_device *dt)
{
        return 0;
}


/* Register an old or new target with the MGS. If needed MGS will construct
   startup logs and assign index */
int server_register_target(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        struct lustre_disk_data *ldd = lsi->lsi_ldd;
        struct mgs_target_info *mti = NULL;
        int rc;
        ENTRY;

        LASSERT(mgc);

        if (!(lsi->lsi_flags & LSI_SERVER))
                RETURN(-EINVAL);

        OBD_ALLOC_PTR(mti);
        if (!mti)
                RETURN(-ENOMEM);
        rc = server_sb2mti(sb, mti);
        if (rc)
                GOTO(out, rc);

        CDEBUG(D_MOUNT, "Registration %s, fs=%s, %s, index=%04x, flags=%#x\n",
               mti->mti_svname, mti->mti_fsname,
               libcfs_nid2str(mti->mti_nids[0]), mti->mti_stripe_index,
               mti->mti_flags);

        /* Register the target */
        /* FIXME use mgc_process_config instead */
        rc = obd_set_info_async(mgc->u.cli.cl_mgc_mgsexp,
                                sizeof(KEY_REGISTER_TARGET), KEY_REGISTER_TARGET,
                                sizeof(*mti), mti, NULL);
        if (rc)
                GOTO(out, rc);

        /* we don't have persistent ldd probably,
         * but MGS * supplies us withservice name */
        ldd->ldd_svindex = mti->mti_stripe_index;
        strncpy(ldd->ldd_svname, mti->mti_svname,
                        sizeof(ldd->ldd_svname));

        /* Always update our flags */
        ldd->ldd_flags = mti->mti_flags & ~LDD_F_REWRITE_LDD;

        /* If this flag is set, it means the MGS wants us to change our
           on-disk data. (So far this means just the index.) */
        if (mti->mti_flags & LDD_F_REWRITE_LDD) {
                char *label;
                int err;
                CDEBUG(D_MOUNT, "Changing on-disk index from %#x to %#x "
                       "for %s\n", ldd->ldd_svindex, mti->mti_stripe_index,
                       mti->mti_svname);
                /* or ldd_make_sv_name(ldd); */
                ldd_write(lsi->lsi_dt_dev, ldd);
                err = mconf_set_label(lsi->lsi_dt_dev, mti->mti_svname);
                if (err)
                        CERROR("Label set error %d\n", err);
                label = mconf_get_label(lsi->lsi_dt_dev);
                if (label)
                        CDEBUG(D_MOUNT, "Disk label changed to %s\n", label);

                /* Flush the new ldd to disk */
                mconf_sync_dev(lsi->lsi_dt_dev);
        }

out:
        if (mti)
                OBD_FREE_PTR(mti);
        RETURN(rc);
}

static void stop_temp_site(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct lu_env          env;
        struct mconf_device   *mdev;
        int                    rc;
        struct lu_site        *site;

        LASSERT(lsi);
        LASSERT(lsi->lsi_dt_dev);

        site = lsi->lsi_dt_dev->dd_lu_dev.ld_site;
        if (site == NULL)
                return;

        mdev = mconf_dev(site->ls_top_dev);
        LASSERT(mdev);

        rc = lu_env_init(&env, mdev->mcf_lu_dev.ld_type->ldt_ctx_tags);
        LASSERT(rc == 0);
        lu_site_purge(&env, site, ~0);
        lu_site_fini(site);
        lu_env_fini(&env);

        lsi->lsi_dt_dev->dd_lu_dev.ld_site = NULL;

        OBD_FREE_PTR(site);
        OBD_FREE_PTR(mdev);
}

/* Start targets */
static int server_start_targets(struct super_block *sb, struct dt_device *dt)
{
        struct obd_device *obd;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct config_llog_instance cfg;
        int rc;
        ENTRY;

        CDEBUG(D_MOUNT, "starting target %s\n", lsi->lsi_ldd->ldd_svname);

#if 0
        /* If we're an MDT, make sure the global MDS is running */
        if (lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_MDT) {
                /* make sure the MDS is started */
                mutex_down(&server_start_lock);
                obd = class_name2obd(LUSTRE_MDS_OBDNAME);
                if (!obd) {
                        rc = lustre_start_simple(LUSTRE_MDS_OBDNAME,
                    /* FIXME pre-rename, should eventually be LUSTRE_MDS_NAME */
                                                 LUSTRE_MDT_NAME,
                                                 LUSTRE_MDS_OBDNAME"_uuid",
                                                 0, 0);
                        if (rc) {
                                mutex_up(&server_start_lock);
                                CERROR("failed to start MDS: %d\n", rc);
                                RETURN(rc);
                        }
                }
                mutex_up(&server_start_lock);
        }
#endif

        /* Register with MGS */
        rc = server_register_target(sb);

        /* destroy temporary site */
        stop_temp_site(sb);

        /* If we're an OST, make sure the global OSS is running */
        if (lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_OST) {
                /* make sure OSS is started */
                mutex_down(&server_start_lock);
                obd = class_name2obd(LUSTRE_OSS_OBDNAME);
                if (!obd) {
                        rc = lustre_start_simple(LUSTRE_OSS_OBDNAME,
                                                 LUSTRE_OSS_NAME,
                                                 LUSTRE_OSS_OBDNAME"_uuid",
                                                 0, 0);
                        if (rc) {
                                mutex_up(&server_start_lock);
                                CERROR("failed to start OSS: %d\n", rc);
                                RETURN(rc);
                        }
                }
                mutex_up(&server_start_lock);
        }

        /* Set the mgc fs to our server disk.  This allows the MGC
           to read and write configs locally. */
        rc = server_mgc_set_fs(lsi->lsi_mgc, sb);
        if (rc)
                RETURN(rc);

        if (rc && (lsi->lsi_ldd->ldd_flags &
                   (LDD_F_NEED_INDEX | LDD_F_UPDATE | LDD_F_UPGRADE14))){
                CERROR("Required registration failed for %s: %d\n",
                       lsi->lsi_ldd->ldd_svname, rc);
                if (rc == -EIO) {
                        LCONSOLE_ERROR_MSG(0x15f, "Communication error with "
                                           "the MGS.  Is the MGS running?\n");
                }
                GOTO(out_mgc, rc);
        }
        if (rc == -EINVAL) {
                LCONSOLE_ERROR_MSG(0x160, "The MGS is refusing to allow this "
                                   "server (%s) to start. Please see messages"
                                   " on the MGS node.\n",
                                   lsi->lsi_ldd->ldd_svname);
                GOTO(out_mgc, rc);
        }
        /* non-fatal error of registeration with MGS */
        if (rc)
                CDEBUG(D_MOUNT, "Cannot register with MGS: %d\n", rc);

        /* Let the target look up the mount using the target's name
           (we can't pass the sb or dt through class_process_config.) */
        rc = server_register_mount(lsi->lsi_ldd->ldd_svname, sb, dt);
        if (rc)
                GOTO(out_mgc, rc);

        /* Start targets using the llog named for the target */
        memset(&cfg, 0, sizeof(cfg));
        rc = lustre_process_log(sb, lsi->lsi_ldd->ldd_svname, &cfg);
        if (rc) {
                CERROR("failed to start server %s: %d\n",
                       lsi->lsi_ldd->ldd_svname, rc);
                /* Do NOT call server_deregister_mount() here. This makes it
                 * impossible to find mount later in cleanup time and leaves
                 * @lsi and othder stuff leaked. -umka */
                GOTO(out_mgc, rc);
        }

out_mgc:
        /* Release the mgc fs for others to use */
        server_mgc_clear_fs(lsi->lsi_mgc);

        if (!rc) {
                obd = class_name2obd(lsi->lsi_ldd->ldd_svname);
                if (!obd) {
                        CERROR("no server named %s was started\n",
                               lsi->lsi_ldd->ldd_svname);
                        RETURN(-ENXIO);
                }

                if ((lsi->lsi_lmd->lmd_flags & LMD_FLG_ABORT_RECOV) &&
                    (OBP(obd, iocontrol))) {
                        obd_iocontrol(OBD_IOC_ABORT_RECOVERY,
                                      obd->obd_self_export, 0, NULL, NULL);
                }

                /* log has been fully processed */
                obd_notify(obd, NULL, OBD_NOTIFY_CONFIG, (void *)CONFIG_LOG);
        }

        RETURN(rc);
}

/***************** lustre superblock **************/

struct lustre_sb_info *lustre_init_lsi(struct super_block *sb)
{
        struct lustre_sb_info *lsi;
        ENTRY;

        OBD_ALLOC_PTR(lsi);
        if (!lsi)
                RETURN(NULL);
        OBD_ALLOC_PTR(lsi->lsi_lmd);
        if (!lsi->lsi_lmd) {
                OBD_FREE_PTR(lsi);
                RETURN(NULL);
        }

        lsi->lsi_lmd->lmd_exclude_count = 0;
        s2lsi_nocast(sb) = lsi;
        /* we take 1 extra ref for our setup */
        atomic_set(&lsi->lsi_mounts, 1);

        /* Default umount style */
        lsi->lsi_flags = LSI_UMOUNT_FAILOVER;

        RETURN(lsi);
}

static int lustre_free_lsi(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        ENTRY;

        LASSERT(lsi != NULL);
        CDEBUG(D_MOUNT, "Freeing lsi %p\n", lsi);

        /* someone didn't call server_put_mount. */
        LASSERT(atomic_read(&lsi->lsi_mounts) == 0);

        if (lsi->lsi_ldd != NULL)
                OBD_FREE(lsi->lsi_ldd, sizeof(*lsi->lsi_ldd));

        if (lsi->lsi_lmd != NULL) {
                if (lsi->lsi_lmd->lmd_dev != NULL)
                        OBD_FREE(lsi->lsi_lmd->lmd_dev,
                                 strlen(lsi->lsi_lmd->lmd_dev) + 1);
                if (lsi->lsi_lmd->lmd_profile != NULL)
                        OBD_FREE(lsi->lsi_lmd->lmd_profile,
                                 strlen(lsi->lsi_lmd->lmd_profile) + 1);
                if (lsi->lsi_lmd->lmd_mgssec != NULL)
                        OBD_FREE(lsi->lsi_lmd->lmd_mgssec,
                                 strlen(lsi->lsi_lmd->lmd_mgssec) + 1);
                if (lsi->lsi_lmd->lmd_opts != NULL)
                        OBD_FREE(lsi->lsi_lmd->lmd_opts,
                                 strlen(lsi->lsi_lmd->lmd_opts) + 1);
                if (lsi->lsi_lmd->lmd_exclude_count)
                        OBD_FREE(lsi->lsi_lmd->lmd_exclude,
                                 sizeof(lsi->lsi_lmd->lmd_exclude[0]) *
                                 lsi->lsi_lmd->lmd_exclude_count);
                if (lsi->lsi_lmd->lmd_mgs)
                        OBD_FREE(lsi->lsi_lmd->lmd_mgs,
                                        strlen(lsi->lsi_lmd->lmd_mgs) + 1);
                OBD_FREE(lsi->lsi_lmd, sizeof(*lsi->lsi_lmd));
        }

        LASSERT(lsi->lsi_llsbi == NULL);
        OBD_FREE(lsi, sizeof(*lsi));
        s2lsi_nocast(sb) = NULL;

        RETURN(0);
}

/* The lsi has one reference for every server that is using the disk -
   e.g. MDT, MGS, and potentially MGC */
static int lustre_put_lsi(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        ENTRY;

        LASSERT(lsi != NULL);

        CDEBUG(D_MOUNT, "put %p/%p %d\n", sb, lsi, atomic_read(&lsi->lsi_mounts));
        if (atomic_dec_and_test(&lsi->lsi_mounts)) {
                lustre_free_lsi(sb);
                RETURN(1);
        }
        RETURN(0);
}

/*************** server mount ******************/

static int mconf_object_init(const struct lu_env *env, struct lu_object *o,
                             const struct lu_object_conf *_)
{
        struct mconf_device *d = mconf_dev(o->lo_dev);
        struct lu_device  *under;
        struct lu_object  *below;
        int                rc = 0;
        ENTRY;

        under = d->mcf_bottom;
        below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
        if (below != NULL) {
                lu_object_add(o, below);
        } else
                rc = -ENOMEM;

        RETURN(rc);
}

static void mconf_object_free(const struct lu_env *env, struct lu_object *o)
{
        struct mconf_object *mo = mconf_obj(o);
        struct lu_object_header *h;
        ENTRY;

        h = o->lo_header;
        CDEBUG(D_INFO, "object free, fid = "DFID"\n",
               PFID(lu_object_fid(o)));

        lu_object_fini(o);
        lu_object_header_fini(h);
        OBD_FREE_PTR(mo);
        EXIT;
}


static const struct lu_object_operations mconf_obj_ops = {
        .loo_object_init    = mconf_object_init,
        .loo_object_free    = mconf_object_free
};

static struct lu_object *
mconf_object_alloc(const struct lu_env *env,
                   const struct lu_object_header *hdr,
                   struct lu_device *d)
{
        struct mconf_object *mo;
        
        ENTRY;

        OBD_ALLOC_PTR(mo);
        if (mo != NULL) {
                struct lu_object *o;
                struct lu_object_header *h;

                o = &mo->mco_obj;
                h = &mo->mco_header;
                lu_object_header_init(h);
                lu_object_init(o, h, d);
                lu_object_add_top(h, o);
                o->lo_ops = &mconf_obj_ops;
                RETURN(o);
        } else
                RETURN(NULL);
}

static const struct lu_device_operations mconf_lu_ops = {
        .ldo_object_alloc   = mconf_object_alloc,
};

static struct lu_device_type_operations mconf_device_type_ops = {
};

static struct lu_device_type mconf_device_type = {
        .ldt_tags     = LU_DEVICE_MC,
        .ldt_name     = LUSTRE_MCF_NAME,
        .ldt_ops      = &mconf_device_type_ops,
        .ldt_ctx_tags = LCT_DT_THREAD
};


static struct lu_device *try_start_osd(struct lustre_mount_data *lmd,
                                       char *typename,
                                       unsigned long s_flags)
{
        struct obd_type       *type = NULL;
        struct lu_device_type *ldt = NULL;
        struct lu_device      *d = NULL;
        struct dt_device      *dt;
        struct lu_env          env;
        int                    rc = 0;
        struct                 lustre_cfg *lcfg;
        struct                 lustre_cfg_bufs bufs;


        /* find the type */
        type = class_get_type(typename);
        if (!type) {
                CERROR("Unknown type: '%s'\n", typename);
                GOTO(out_env, rc = -ENODEV);
        }

        ldt = type->typ_lu;
        if (ldt == NULL) {
                CERROR("type: '%s'\n", typename);
                GOTO(out_type, rc = -EINVAL);
        }

        rc = lu_env_init(&env, ldt->ldt_ctx_tags);
        LASSERT(rc == 0);

        ldt->ldt_obd_type = type;
        d = ldt->ldt_ops->ldto_device_alloc(&env, ldt, NULL);
        if (IS_ERR(d)) {
                CERROR("Cannot allocate device: '%s'\n", typename);
                GOTO(out_type, rc = -ENODEV);
        }

        type->typ_refcnt++;
        rc = ldt->ldt_ops->ldto_device_init(&env, d, NULL, NULL);
        if (rc) {
                CERROR("can't init device '%s', rc %d\n", typename, rc);
                GOTO(out_alloc, rc);
        }

        /* ask osd to mount underlying disk filesystem */
        lustre_cfg_bufs_reset(&bufs, lmd->lmd_dev);
        lustre_cfg_bufs_set(&bufs, 1, &s_flags, sizeof(s_flags));
        lcfg = lustre_cfg_new(LCFG_SETUP, &bufs);
        dt = lu2dt_dev(d);
        rc = dt->dd_lu_dev.ld_ops->ldo_process_config(&env, d, lcfg);
        lustre_cfg_free(lcfg);

        if (rc)
                GOTO(out, rc);

        lu_device_get(d);
        lu_ref_add(&d->ld_reference, "lu-stack", &lu_site_init);
out_type:
out_alloc:
out:
        if (rc) {
                if (d) {
                        LASSERT(ldt);
                        type->typ_refcnt--;
                        ldt->ldt_ops->ldto_device_fini(&env, d);
                        ldt->ldt_ops->ldto_device_free(&env, d);
                }
                if (type)
                        class_put_type(type);
        }
        lu_env_fini(&env);
out_env:
        if (rc)
                d = ERR_PTR(rc);

        RETURN(d);
}

static struct lu_device *start_osd(struct lustre_mount_data *lmd,
                                   unsigned long s_flags)
{
        struct lu_device *d;
        ENTRY;

        d = try_start_osd(lmd, LUSTRE_OSD_NAME, s_flags);
        if (IS_ERR(d))
                d = try_start_osd(lmd, LUSTRE_ZFS_NAME, s_flags);
        RETURN(d);
}

static int ldd_parse(struct mconf_device *mdev, struct lustre_disk_data *ldd)
{
        struct dt_device      *dev = lu2dt_dev(mdev->mcf_bottom);
        struct lu_env          env;
        int                    rc;
        struct dt_object      *file;
        struct lu_fid          fid;
        struct lu_buf          buf;
        loff_t                 pos;

        rc = lu_env_init(&env, mdev->mcf_lu_dev.ld_type->ldt_ctx_tags);
        LASSERT(rc == 0);

        file = dt_store_open(&env, dev, MOUNT_CONFIGS_DIR, CONFIGS_FILE, &fid);
        if (IS_ERR(file))
                GOTO(out, rc = PTR_ERR(file));

        buf.lb_buf = ldd;
        buf.lb_len = sizeof(*ldd);
        pos = 0;
        rc = file->do_body_ops->dbo_read(&env, file, &buf, &pos, BYPASS_CAPA);
        if (rc == buf.lb_len) {
                if (ldd->ldd_magic != LDD_MAGIC) {
                        /* FIXME add swabbing support */
                        CERROR("Bad magic in %s: %x!=%x\n", MOUNT_DATA_FILE,
                                        ldd->ldd_magic, LDD_MAGIC);
                        GOTO(out, rc = -EINVAL);
                }

                if (ldd->ldd_feature_incompat & ~LDD_INCOMPAT_SUPP) {
                        CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
                               ldd->ldd_svname,
                               ldd->ldd_feature_incompat & ~LDD_INCOMPAT_SUPP);
                        GOTO(out, rc = -EINVAL);
                }
                if (ldd->ldd_feature_rocompat & ~LDD_ROCOMPAT_SUPP) {
                        CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
                               ldd->ldd_svname,
                               ldd->ldd_feature_rocompat & ~LDD_ROCOMPAT_SUPP);
                        /* Do something like remount filesystem read-only */
                        GOTO(out, rc = -EINVAL);
                }
                rc = 0;
        } else if (rc >= 0)
                rc = -EIO;
        lu_object_put(&env, &file->do_lu);
out:
        lu_env_fini(&env);
        RETURN(rc);
}


/* Kernel mount using mount options in MOUNT_DATA_FILE */
static struct dt_device *server_kernel_mount(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct lustre_disk_data *ldd;
        struct lustre_mount_data *lmd = lsi->lsi_lmd;
        struct lu_device *dev;
        struct mconf_device *mdev;
        struct lu_site *site;
        int rc;

        ENTRY;

        OBD_ALLOC(ldd, sizeof(*ldd));
        if (!ldd)
                RETURN(ERR_PTR(-ENOMEM));
        lsi->lsi_ldd = ldd;

        /* start OSD on given device */
        dev = start_osd(lmd, sb->s_flags);
        if (IS_ERR(dev)) {
                OBD_FREE(ldd, sizeof(*ldd));
                lsi->lsi_ldd = NULL;
                RETURN((void *) dev);
        }
        
        lsi->lsi_dt_dev = lu2dt_dev(dev);

        /* create temporary site to access ldd */
        OBD_ALLOC_PTR(site);
        LASSERT(site);

        /* create temporary top-device to access ldd */
        OBD_ALLOC_PTR(mdev);
        LASSERT(mdev != NULL);
        lu_device_init(&mdev->mcf_lu_dev, &mconf_device_type);
        mdev->mcf_lu_dev.ld_ops = &mconf_lu_ops;
        mdev->mcf_bottom = dev;

        rc = lu_site_init(site, &mdev->mcf_lu_dev);
        LASSERT(rc == 0);
        dev->ld_site = site;
        rc = lu_site_init_finish(site);
        LASSERT(rc == 0);

        rc = ldd_parse(mdev, ldd);
        if (rc == -ENOENT) {
                /* no configuration found, use disk label */
                stop_temp_site(sb);
        } else {
                LASSERT(rc == 0);
        }

        RETURN(lu2dt_dev(dev));
}

static void server_wait_finished(struct vfsmount *mnt)
{
        wait_queue_head_t   waitq;
        struct l_wait_info  lwi;
        int                 retries = 330;

        return;
        init_waitqueue_head(&waitq);

        while ((atomic_read(&mnt->mnt_count) > 1) && (retries > 0)) {
                LCONSOLE_WARN("%s: Mount still busy with %d refs, waiting for "
                              "%d secs...\n", mnt->mnt_devname,
                              atomic_read(&mnt->mnt_count), retries);

                /* Wait for a bit */
                retries -= 5;
                lwi = LWI_TIMEOUT(5 * HZ, NULL, NULL);
                l_wait_event(waitq, 0, &lwi);
        }
        if (atomic_read(&mnt->mnt_count) > 1) {
                CERROR("%s: Mount still busy (%d refs), giving up.\n",
                       mnt->mnt_devname, atomic_read(&mnt->mnt_count));
        }
}

static void server_put_super(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device     *obd;
        struct vfsmount       *mnt = NULL; /* XXX: */
        char *tmpname, *extraname = NULL;
        int tmpname_sz;
        int lddflags = lsi->lsi_ldd->ldd_flags;
        int lsiflags = lsi->lsi_flags;
        ENTRY;

        LASSERT(lsiflags & LSI_SERVER);

        tmpname_sz = strlen(lsi->lsi_ldd->ldd_svname) + 1;
        OBD_ALLOC(tmpname, tmpname_sz);
        memcpy(tmpname, lsi->lsi_ldd->ldd_svname, tmpname_sz);
        CDEBUG(D_MOUNT, "server put_super %s\n", tmpname);

        /* Stop the target */
        if (!(lsi->lsi_lmd->lmd_flags & LMD_FLG_NOSVC) &&
            (IS_MDT(lsi->lsi_ldd) || IS_OST(lsi->lsi_ldd))) {
                struct lustre_profile *lprof = NULL;

                /* tell the mgc to drop the config log */
                lustre_end_log(sb, lsi->lsi_ldd->ldd_svname, NULL);

                /* COMPAT_146 - profile may get deleted in mgc_cleanup.
                   If there are any setup/cleanup errors, save the lov
                   name for safety cleanup later. */
                lprof = class_get_profile(lsi->lsi_ldd->ldd_svname);
                if (lprof && lprof->lp_dt) {
                        OBD_ALLOC(extraname, strlen(lprof->lp_dt) + 1);
                        strcpy(extraname, lprof->lp_dt);
                }

                obd = class_name2obd(lsi->lsi_ldd->ldd_svname);
                if (obd) {
                        CDEBUG(D_MOUNT, "stopping %s\n", obd->obd_name);
                        if (lsi->lsi_flags & LSI_UMOUNT_FAILOVER)
                                obd->obd_fail = 1;
                        /* We can't seem to give an error return code
                         * to .put_super, so we better make sure we clean up! */
                        obd->obd_force = 1;
                        class_manual_cleanup(obd);
                } else {
                        CERROR("no obd %s\n", lsi->lsi_ldd->ldd_svname);
                        server_deregister_mount(lsi->lsi_ldd->ldd_svname);
                }
        }

        /* If they wanted the mgs to stop separately from the mdt, they
           should have put it on a different device. */
        if (IS_MGS(lsi->lsi_ldd)) {
                /* if MDS start with --nomgs, don't stop MGS then */
                if (!(lsi->lsi_lmd->lmd_flags & LMD_FLG_NOMGS))
                        server_stop_mgs(sb);
        }

        /* Clean the mgc and sb */
        lustre_common_put_super(sb);

        /* Wait for the targets to really clean up - can't exit (and let the
           sb get destroyed) while the mount is still in use */
        server_wait_finished(mnt);

        /* drop the One True Mount */
        unlock_mntput(mnt);

        /* Stop the servers (MDS, OSS) if no longer needed.  We must wait
           until the target is really gone so that our type refcount check
           is right. */
        server_stop_servers(lddflags, lsiflags);

        /* In case of startup or cleanup err, stop related obds */
        if (extraname) {
                obd = class_name2obd(extraname);
                if (obd) {
                        CWARN("Cleaning orphaned obd %s\n", extraname);
                        obd->obd_force = 1;
                        class_manual_cleanup(obd);
                }
                OBD_FREE(extraname, strlen(extraname) + 1);
        }

        LCONSOLE_WARN("server umount %s complete\n", tmpname);
        OBD_FREE(tmpname, tmpname_sz);
        EXIT;
}

#ifdef HAVE_UMOUNTBEGIN_VFSMOUNT
static void server_umount_begin(struct vfsmount *vfsmnt, int flags)
{
        struct super_block *sb = vfsmnt->mnt_sb;
#else
static void server_umount_begin(struct super_block *sb)
{
#endif
        struct lustre_sb_info *lsi = s2lsi(sb);
        ENTRY;

#ifdef HAVE_UMOUNTBEGIN_VFSMOUNT
        if (!(flags & MNT_FORCE)) {
                EXIT;
                return;
        }
#endif

        CDEBUG(D_MOUNT, "umount -f\n");
        /* umount = failover
           umount -f = force
           no third way to do non-force, non-failover */
        lsi->lsi_flags &= ~LSI_UMOUNT_FAILOVER;
        lsi->lsi_flags |= LSI_UMOUNT_FORCE;
        EXIT;
}

#ifndef HAVE_STATFS_DENTRY_PARAM
static int server_statfs (struct super_block *sb, struct kstatfs *buf)
{
#else
static int server_statfs (struct dentry *dentry, struct kstatfs *buf)
{
        struct super_block *sb = dentry->d_sb;
#endif
        struct vfsmount *mnt = NULL;
        ENTRY;

        if (mnt && mnt->mnt_sb && mnt->mnt_sb->s_op->statfs) {
#ifdef HAVE_STATFS_DENTRY_PARAM
                int rc = mnt->mnt_sb->s_op->statfs(mnt->mnt_root, buf);
#else
                int rc = mnt->mnt_sb->s_op->statfs(mnt->mnt_sb, buf);
#endif
                if (!rc) {
                        buf->f_type = sb->s_magic;
                        RETURN(0);
                }
        }

        /* just return 0 */
        buf->f_type = sb->s_magic;
        buf->f_bsize = sb->s_blocksize;
        buf->f_blocks = 1;
        buf->f_bfree = 0;
        buf->f_bavail = 0;
        buf->f_files = 1;
        buf->f_ffree = 0;
        buf->f_namelen = NAME_MAX;
        RETURN(0);
}

static struct super_operations server_ops =
{
        .put_super      = server_put_super,
        .umount_begin   = server_umount_begin, /* umount -f */
        .statfs         = server_statfs,
};

#define log2(n) ffz(~(n))
#define LUSTRE_SUPER_MAGIC 0x0BD00BD1

static int server_fill_super_common(struct super_block *sb)
{
        struct inode *root = 0;
        ENTRY;

        CDEBUG(D_MOUNT, "Server sb, dev=%d\n", (int)sb->s_dev);

        sb->s_blocksize = 4096;
        sb->s_blocksize_bits = log2(sb->s_blocksize);
        sb->s_magic = LUSTRE_SUPER_MAGIC;
        sb->s_maxbytes = 0; //PAGE_CACHE_MAXBYTES;
        sb->s_flags |= MS_RDONLY;
        sb->s_op = &server_ops;

        root = new_inode(sb);
        if (!root) {
                CERROR("Can't make root inode\n");
                RETURN(-EIO);
        }

        /* returns -EIO for every operation */
        /* make_bad_inode(root); -- badness - can't umount */
        /* apparently we need to be a directory for the mount to finish */
        root->i_mode = S_IFDIR;

        sb->s_root = d_alloc_root(root);
        if (!sb->s_root) {
                CERROR("Can't make root dentry\n");
                iput(root);
                RETURN(-EIO);
        }

        RETURN(0);
}

static int server_fill_super(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct dt_device *dt;
        int rc;
        ENTRY;

        /* the One True Mount */
        dt = server_kernel_mount(sb);
        if (IS_ERR(dt)) {
                rc = PTR_ERR(dt);
                CERROR("Unable to mount device %s: %d\n",
                       lsi->lsi_lmd->lmd_dev, rc);
                lustre_put_lsi(sb);
                RETURN(rc);
        }

        LASSERT(lsi->lsi_ldd);
        CDEBUG(D_MOUNT, "Found service %s for fs '%s' on device %s\n",
               lsi->lsi_ldd->ldd_svname, lsi->lsi_ldd->ldd_fsname,
               lsi->lsi_lmd->lmd_dev);

        if (class_name2obd(lsi->lsi_ldd->ldd_svname)) {
                LCONSOLE_ERROR_MSG(0x161, "The target named %s is already "
                                   "running. Double-mount may have compromised"
                                   " the disk journal.\n",
                                   lsi->lsi_ldd->ldd_svname);
                lustre_put_lsi(sb);
                /* XXX: cleanup osd */
                LBUG();
                RETURN(-EALREADY);
        }

        /* Start MGS before MGC */
        if (IS_MGS(lsi->lsi_ldd) && !(lsi->lsi_lmd->lmd_flags & LMD_FLG_NOMGS)){
                rc = server_start_mgs(sb);
                if (rc)
                        GOTO(out_mnt, rc);
        }

        rc = lustre_start_mgc(sb);
        if (rc)
                GOTO(out_mnt, rc);

        /* Set up all obd devices for service */
        if (lsi->lsi_ldd->ldd_magic == 0) {
                /* no configuration found, try to register on MGS and get conf */
                rc = server_start_targets(sb, dt);
                if (rc < 0) {
                        CERROR("Unable to start targets: %d\n", rc);
                        GOTO(out_mnt, rc);
                }
        } else if (!(lsi->lsi_lmd->lmd_flags & LMD_FLG_NOSVC) &&
                (IS_OST(lsi->lsi_ldd) || IS_MDT(lsi->lsi_ldd))) {
                rc = server_start_targets(sb, dt);
                if (rc < 0) {
                        CERROR("Unable to start targets: %d\n", rc);
                        GOTO(out_mnt, rc);
                }
        /* FIXME overmount client here,
           or can we just start a client log and client_fill_super on this sb?
           We need to make sure server_put_super gets called too - ll_put_super
           calls lustre_common_put_super; check there for LSI_SERVER flag,
           call s_p_s if so.
           Probably should start client from new thread so we can return.
           Client will not finish until all servers are connected.
           Note - MGS-only server does NOT get a client, since there is no
           lustre fs associated - the MGS is for all lustre fs's */
        }

        rc = server_fill_super_common(sb);
        if (rc)
                GOTO(out_mnt, rc);

        LCONSOLE_WARN("Server %s on device %s has started\n",
                      lsi->lsi_ldd->ldd_svname, lsi->lsi_lmd->lmd_dev);

        RETURN(0);
out_mnt:
        /* We jump here in case of failure while starting targets or MGS.
         * In this case we can't just put @mnt and have to do real cleanup
         * with stoping targets, etc. */
        server_put_super(sb);
        return rc;
}

/* Get the index from the obd name.
   rc = server type, or
   rc < 0  on error
   if endptr isn't NULL it is set to end of name */
int server_name2index(char *svname, __u32 *idx, char **endptr)
{
        unsigned long index;
        int rc;
        char *dash = strrchr(svname, '-');
        if (!dash) {
                dash = strrchr(svname, ':');
                if (!dash)
                        return(-EINVAL);
        }

        /* intepret <fsname>-MDTXXXXX-mdc as mdt, the better way is to pass
         * in the fsname, then determine the server index */
        if (!strcmp(LUSTRE_MDC_NAME, dash + 1)) {
                dash--;
                for (; dash > svname && *dash != '-' && *dash != ':'; dash--);
                if (dash == svname)
                        return(-EINVAL);
        }

        if (strncmp(dash + 1, "MDT", 3) == 0)
                rc = LDD_F_SV_TYPE_MDT;
        else if (strncmp(dash + 1, "OST", 3) == 0)
                rc = LDD_F_SV_TYPE_OST;
        else
                return(-EINVAL);

        dash += 4;

        if (strcmp(dash, "all") == 0)
                return rc | LDD_F_SV_ALL;

        if (*dash == 'u') {
                rc |= LDD_F_NEED_INDEX;
                dash++;
        }

        index = simple_strtoul(dash, endptr, 16);
        *idx = index;
        return rc;
}

/*************** mount common betweeen server and client ***************/

/* Common umount */
int lustre_common_put_super(struct super_block *sb)
{
        int rc;
        ENTRY;

        CDEBUG(D_MOUNT, "dropping sb %p\n", sb);

        /* Drop a ref to the MGC */
        rc = lustre_stop_mgc(sb);
        if (rc && (rc != -ENOENT)) {
                if (rc != -EBUSY) {
                        CERROR("Can't stop MGC: %d\n", rc);
                        RETURN(rc);
                }
                /* BUSY just means that there's some other obd that
                   needs the mgc.  Let him clean it up. */
                CDEBUG(D_MOUNT, "MGC still in use\n");
        }
        /* Drop a ref to the mounted disk */
        lustre_put_lsi(sb);
        lu_types_stop();
        RETURN(rc);
}

#if 0
static void lmd_print(struct lustre_mount_data *lmd)
{
        int i;

        PRINT_CMD(PRINT_MASK, "  mount data:\n");
        if (lmd_is_client(lmd))
                PRINT_CMD(PRINT_MASK, "profile: %s\n", lmd->lmd_profile);
        PRINT_CMD(PRINT_MASK, "device:  %s\n", lmd->lmd_dev);
        PRINT_CMD(PRINT_MASK, "flags:   %x\n", lmd->lmd_flags);
        if (lmd->lmd_opts)
                PRINT_CMD(PRINT_MASK, "options: %s\n", lmd->lmd_opts);
        for (i = 0; i < lmd->lmd_exclude_count; i++) {
                PRINT_CMD(PRINT_MASK, "exclude %d:  OST%04x\n", i,
                          lmd->lmd_exclude[i]);
        }
}
#endif

/* Is this server on the exclusion list */
int lustre_check_exclusion(struct super_block *sb, char *svname)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct lustre_mount_data *lmd = lsi->lsi_lmd;
        __u32 index;
        int i, rc;
        ENTRY;

        rc = server_name2index(svname, &index, NULL);
        if (rc != LDD_F_SV_TYPE_OST)
                /* Only exclude OSTs */
                RETURN(0);

        CDEBUG(D_MOUNT, "Check exclusion %s (%d) in %d of %s\n", svname,
               index, lmd->lmd_exclude_count, lmd->lmd_dev);

        for(i = 0; i < lmd->lmd_exclude_count; i++) {
                if (index == lmd->lmd_exclude[i]) {
                        CWARN("Excluding %s (on exclusion list)\n", svname);
                        RETURN(1);
                }
        }
        RETURN(0);
}

/* mount -v  -o exclude=lustre-OST0001:lustre-OST0002 -t lustre ... */
static int lmd_make_exclusion(struct lustre_mount_data *lmd, char *ptr)
{
        char *s1 = ptr, *s2;
        __u32 index, *exclude_list;
        int rc = 0, devmax;
        ENTRY;

        /* The shortest an ost name can be is 8 chars: -OST0000.
           We don't actually know the fsname at this time, so in fact
           a user could specify any fsname. */
        devmax = strlen(ptr) / 8 + 1;

        /* temp storage until we figure out how many we have */
        OBD_ALLOC(exclude_list, sizeof(index) * devmax);
        if (!exclude_list)
                RETURN(-ENOMEM);

        /* we enter this fn pointing at the '=' */
        while (*s1 && *s1 != ' ' && *s1 != ',') {
                s1++;
                rc = server_name2index(s1, &index, &s2);
                if (rc < 0) {
                        CERROR("Can't parse server name '%s'\n", s1);
                        break;
                }
                if (rc == LDD_F_SV_TYPE_OST)
                        exclude_list[lmd->lmd_exclude_count++] = index;
                else
                        CDEBUG(D_MOUNT, "ignoring exclude %.7s\n", s1);
                s1 = s2;
                /* now we are pointing at ':' (next exclude)
                   or ',' (end of excludes) */
                if (lmd->lmd_exclude_count >= devmax)
                        break;
        }
        if (rc >= 0) /* non-err */
                rc = 0;

        if (lmd->lmd_exclude_count) {
                /* permanent, freed in lustre_free_lsi */
                OBD_ALLOC(lmd->lmd_exclude, sizeof(index) *
                          lmd->lmd_exclude_count);
                if (lmd->lmd_exclude) {
                        memcpy(lmd->lmd_exclude, exclude_list,
                               sizeof(index) * lmd->lmd_exclude_count);
                } else {
                        rc = -ENOMEM;
                        lmd->lmd_exclude_count = 0;
                }
        }
        OBD_FREE(exclude_list, sizeof(index) * devmax);
        RETURN(rc);
}

static int lmd_parse_mgssec(struct lustre_mount_data *lmd, char *ptr)
{
        char   *tail;
        int     length;

        if (lmd->lmd_mgssec != NULL) {
                OBD_FREE(lmd->lmd_mgssec, strlen(lmd->lmd_mgssec) + 1);
                lmd->lmd_mgssec = NULL;
        }

        tail = strchr(ptr, ',');
        if (tail == NULL)
                length = strlen(ptr);
        else
                length = tail - ptr;

        OBD_ALLOC(lmd->lmd_mgssec, length + 1);
        if (lmd->lmd_mgssec == NULL)
                return -ENOMEM;

        memcpy(lmd->lmd_mgssec, ptr, length);
        lmd->lmd_mgssec[length] = '\0';
        return 0;
}

static int lmd_parse_mgs(struct lustre_mount_data *lmd, char *ptr)
{
        char   *tail;
        int     length;

        if (lmd->lmd_mgs != NULL) {
                OBD_FREE(lmd->lmd_mgs, strlen(lmd->lmd_mgs) + 1);
                lmd->lmd_mgs = NULL;
        }

        tail = strchr(ptr, ',');
        if (tail == NULL)
                length = strlen(ptr);
        else
                length = tail - ptr;

        OBD_ALLOC(lmd->lmd_mgs, length + 1);
        if (lmd->lmd_mgs == NULL)
                return -ENOMEM;

        memcpy(lmd->lmd_mgs, ptr, length);
        lmd->lmd_mgs[length] = '\0';
        return 0;
}

/* mount -v -t lustre uml1:uml2:/lustre-client /mnt/lustre */
static int lmd_parse(char *options, struct lustre_mount_data *lmd)
{
        char *s1, *s2, *devname = NULL;
        struct lustre_mount_data *raw = (struct lustre_mount_data *)options;
        int rc = 0;
        ENTRY;

        LASSERT(lmd);
        if (!options) {
                LCONSOLE_ERROR_MSG(0x162, "Missing mount data: check that "
                                   "/sbin/mount.lustre is installed.\n");
                RETURN(-EINVAL);
        }

        /* Options should be a string - try to detect old lmd data */
        if ((raw->lmd_magic & 0xffffff00) == (LMD_MAGIC & 0xffffff00)) {
                LCONSOLE_ERROR_MSG(0x163, "You're using an old version of "
                                   "/sbin/mount.lustre.  Please install "
                                   "version %s\n", LUSTRE_VERSION_STRING);
                RETURN(-EINVAL);
        }
        lmd->lmd_magic = LMD_MAGIC;

        /* Set default flags here */

        s1 = options;
        while (*s1) {
                int clear = 0;
                /* Skip whitespace and extra commas */
                while (*s1 == ' ' || *s1 == ',')
                        s1++;

                /* Client options are parsed in ll_options: eg. flock,
                   user_xattr, acl */

                /* Parse non-ldiskfs options here. Rather than modifying
                   ldiskfs, we just zero these out here */
                if (strncmp(s1, "abort_recov", 11) == 0) {
                        lmd->lmd_flags |= LMD_FLG_ABORT_RECOV;
                        clear++;
                } else if (strncmp(s1, "nosvc", 5) == 0) {
                        lmd->lmd_flags |= LMD_FLG_NOSVC;
                        clear++;
                } else if (strncmp(s1, "nomgs", 5) == 0) {
                        lmd->lmd_flags |= LMD_FLG_NOMGS;
                        clear++;
                } else if (strncmp(s1, "mgssec=", 7) == 0) {
                        rc = lmd_parse_mgssec(lmd, s1 + 7);
                        if (rc)
                                goto invalid;
                        clear++;
                /* ost exclusion list */
                } else if (strncmp(s1, "exclude=", 8) == 0) {
                        rc = lmd_make_exclusion(lmd, s1 + 7);
                        if (rc)
                                goto invalid;
                        clear++;
                } else if (strncmp(s1, "mgs=", 4) == 0) {
                        rc = lmd_parse_mgs(lmd, s1 + 4);
                        if (rc)
                                goto invalid;
                        clear++;
                }
                /* Linux 2.4 doesn't pass the device, so we stuck it at the
                   end of the options. */
                else if (strncmp(s1, "device=", 7) == 0) {
                        devname = s1 + 7;
                        /* terminate options right before device.  device
                           must be the last one. */
                        *s1 = '\0';
                        break;
                }

                /* Find next opt */
                s2 = strchr(s1, ',');
                if (s2 == NULL) {
                        if (clear)
                                *s1 = '\0';
                        break;
                }
                s2++;
                if (clear)
                        memmove(s1, s2, strlen(s2) + 1);
                else
                        s1 = s2;
        }

        if (!devname) {
                LCONSOLE_ERROR_MSG(0x164, "Can't find the device name "
                                   "(need mount option 'device=...')\n");
                goto invalid;
        }

        s1 = strstr(devname, ":/");
        if (s1) {
                ++s1;
                lmd->lmd_flags = LMD_FLG_CLIENT;
                /* Remove leading /s from fsname */
                while (*++s1 == '/') ;
                /* Freed in lustre_free_lsi */
                OBD_ALLOC(lmd->lmd_profile, strlen(s1) + 8);
                if (!lmd->lmd_profile)
                        RETURN(-ENOMEM);
                sprintf(lmd->lmd_profile, "%s-client", s1);
        }

        /* Freed in lustre_free_lsi */
        OBD_ALLOC(lmd->lmd_dev, strlen(devname) + 1);
        if (!lmd->lmd_dev)
                RETURN(-ENOMEM);
        strcpy(lmd->lmd_dev, devname);

        /* Save mount options */
        s1 = options + strlen(options) - 1;
        while (s1 >= options && (*s1 == ',' || *s1 == ' '))
                *s1-- = 0;
        if (*options != 0) {
                /* Freed in lustre_free_lsi */
                OBD_ALLOC(lmd->lmd_opts, strlen(options) + 1);
                if (!lmd->lmd_opts)
                        RETURN(-ENOMEM);
                strcpy(lmd->lmd_opts, options);
        }

        lmd->lmd_magic = LMD_MAGIC;

        RETURN(rc);

invalid:
        CERROR("Bad mount options %s\n", options);
        RETURN(-EINVAL);
}


/* Common mount */
int lustre_fill_super(struct super_block *sb, void *data, int silent)
{
        struct lustre_mount_data *lmd;
        struct lustre_sb_info *lsi;
        int rc;
        ENTRY;

        CDEBUG(D_MOUNT|D_VFSTRACE, "VFS Op: sb %p\n", sb);

        lsi = lustre_init_lsi(sb);
        if (!lsi)
                RETURN(-ENOMEM);
        lmd = lsi->lsi_lmd;

        /*
         * Disable lockdep during mount, because mount locking patterns are
         * `special'.
         */
        lockdep_off();

        /* Figure out the lmd from the mount options */
        if (lmd_parse((char *)data, lmd)) {
                lustre_put_lsi(sb);
                GOTO(out, rc = -EINVAL);
        }

        if (lmd_is_client(lmd)) {
                CDEBUG(D_MOUNT, "Mounting client %s\n", lmd->lmd_profile);
                if (!client_fill_super) {
                        LCONSOLE_ERROR_MSG(0x165, "Nothing registered for "
                                           "client mount! Is the 'lustre' "
                                           "module loaded?\n");
                        lustre_put_lsi(sb);
                        rc = -ENODEV;
                } else {
                        rc = lustre_start_mgc(sb);
                        if (rc) {
                                lustre_put_lsi(sb);
                                GOTO(out, rc);
                        }
                        /* Connect and start */
                        /* (should always be ll_fill_super) */
                        rc = (*client_fill_super)(sb);
                        /* c_f_s will call lustre_common_put_super on failure */
                }
        } else {
                CDEBUG(D_MOUNT, "Mounting server from %s\n", lmd->lmd_dev);
                lsi->lsi_flags |= LSI_SERVER;
                rc = server_fill_super(sb);
                /* s_f_s calls lustre_start_mgc after the mount because we need
                   the MGS nids which are stored on disk.  Plus, we may
                   need to start the MGS first. */
                /* s_f_s will call server_put_super on failure */
        }

        /* If error happens in fill_super() call, @lsi will be killed there.
         * This is why we do not put it here. */
        GOTO(out, rc);
out:
        if (rc) {
                CERROR("Unable to mount %s (%d)\n",
                       s2lsi(sb) ? lmd->lmd_dev : "", rc);
        } else {
                CDEBUG(D_SUPER, "Mount %s complete\n",
                       lmd->lmd_dev);
        }
        lockdep_on();
        return rc;
}


/* We can't call ll_fill_super by name because it lives in a module that
   must be loaded after this one. */
void lustre_register_client_fill_super(int (*cfs)(struct super_block *sb))
{
        client_fill_super = cfs;
}

void lustre_register_kill_super_cb(void (*cfs)(struct super_block *sb))
{
        kill_super_cb = cfs;
}

/***************** FS registration ******************/

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))
struct super_block * lustre_get_sb(struct file_system_type *fs_type,
                               int flags, const char *devname, void * data)
{
        return get_sb_nodev(fs_type, flags, data, lustre_fill_super);
}
#else
int lustre_get_sb(struct file_system_type *fs_type,
                               int flags, const char *devname, void * data,
                               struct vfsmount *mnt)
{
        return get_sb_nodev(fs_type, flags, data, lustre_fill_super, mnt);
}
#endif

void lustre_kill_super(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);

        if (kill_super_cb && lsi && !(lsi->lsi_flags & LSI_SERVER))
                (*kill_super_cb)(sb);

        kill_anon_super(sb);
}

struct file_system_type lustre_fs_type = {
        .owner        = THIS_MODULE,
        .name         = "lustre",
        .get_sb       = lustre_get_sb,
        .kill_sb      = lustre_kill_super,
        .fs_flags     = FS_BINARY_MOUNTDATA | FS_REQUIRES_DEV |
                        LL_RENAME_DOES_D_MOVE,
};

int lustre_register_fs(void)
{
        return register_filesystem(&lustre_fs_type);
}

int lustre_unregister_fs(void)
{
        return unregister_filesystem(&lustre_fs_type);
}

EXPORT_SYMBOL(lustre_register_client_fill_super);
EXPORT_SYMBOL(lustre_register_kill_super_cb);
EXPORT_SYMBOL(lustre_common_put_super);
EXPORT_SYMBOL(lustre_process_log);
EXPORT_SYMBOL(lustre_end_log);
EXPORT_SYMBOL(server_get_mount);
EXPORT_SYMBOL(server_get_mount_2);
EXPORT_SYMBOL(server_put_mount);
EXPORT_SYMBOL(server_put_mount_2);
EXPORT_SYMBOL(server_register_target);
EXPORT_SYMBOL(server_name2index);
EXPORT_SYMBOL(server_mti_print);
EXPORT_SYMBOL(do_lcfg);
