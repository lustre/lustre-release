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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
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
#ifdef HAVE_KERNEL_LOCKED
#include <linux/smp_lock.h>
#endif

static int (*client_fill_super)(struct super_block *sb,
                                struct vfsmount *mnt) = NULL;
static void (*kill_super_cb)(struct super_block *sb) = NULL;

/*********** mount lookup *********/

CFS_DEFINE_MUTEX(lustre_mount_info_lock);
static CFS_LIST_HEAD(server_mount_info_list);

static struct lustre_mount_info *server_find_mount(const char *name)
{
        cfs_list_t *tmp;
        struct lustre_mount_info *lmi;
        ENTRY;

        cfs_list_for_each(tmp, &server_mount_info_list) {
                lmi = cfs_list_entry(tmp, struct lustre_mount_info,
                                     lmi_list_chain);
                if (strcmp(name, lmi->lmi_name) == 0)
                        RETURN(lmi);
        }
        RETURN(NULL);
}

/* we must register an obd for a mount before we call the setup routine.
   *_setup will call lustre_get_mount to get the mnt struct
   by obd_name, since we can't pass the pointer to setup. */
static int server_register_mount(const char *name, struct super_block *sb,
                          struct vfsmount *mnt)
{
        struct lustre_mount_info *lmi;
        char *name_cp;
        ENTRY;

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

        cfs_mutex_lock(&lustre_mount_info_lock);

        if (server_find_mount(name)) {
                cfs_mutex_unlock(&lustre_mount_info_lock);
                OBD_FREE(lmi, sizeof(*lmi));
                OBD_FREE(name_cp, strlen(name) + 1);
                CERROR("Already registered %s\n", name);
                RETURN(-EEXIST);
        }
        lmi->lmi_name = name_cp;
        lmi->lmi_sb = sb;
        lmi->lmi_mnt = mnt;
        cfs_list_add(&lmi->lmi_list_chain, &server_mount_info_list);

        cfs_mutex_unlock(&lustre_mount_info_lock);

	CDEBUG(D_MOUNT, "reg_mnt %p from %s\n", lmi->lmi_mnt, name);

        RETURN(0);
}

/* when an obd no longer needs a mount */
static int server_deregister_mount(const char *name)
{
        struct lustre_mount_info *lmi;
        ENTRY;

        cfs_mutex_lock(&lustre_mount_info_lock);
        lmi = server_find_mount(name);
        if (!lmi) {
                cfs_mutex_unlock(&lustre_mount_info_lock);
                CERROR("%s not registered\n", name);
                RETURN(-ENOENT);
        }

	CDEBUG(D_MOUNT, "dereg_mnt %p from %s\n", lmi->lmi_mnt, name);

        OBD_FREE(lmi->lmi_name, strlen(lmi->lmi_name) + 1);
        cfs_list_del(&lmi->lmi_list_chain);
        OBD_FREE(lmi, sizeof(*lmi));
        cfs_mutex_unlock(&lustre_mount_info_lock);

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

        cfs_mutex_lock(&lustre_mount_info_lock);
        lmi = server_find_mount(name);
        cfs_mutex_unlock(&lustre_mount_info_lock);
        if (!lmi) {
                CERROR("Can't find mount for %s\n", name);
                RETURN(NULL);
        }
        lsi = s2lsi(lmi->lmi_sb);

        cfs_atomic_inc(&lsi->lsi_mounts);

	CDEBUG(D_MOUNT, "get_mnt %p from %s, refs=%d\n", lmi->lmi_mnt,
	       name, cfs_atomic_read(&lsi->lsi_mounts));

        RETURN(lmi);
}
EXPORT_SYMBOL(server_get_mount);

/*
 * Used by mdt to get mount_info from obdname.
 * There are no blocking when using the mount_info.
 * Do not use server_get_mount for this purpose.
 */
struct lustre_mount_info *server_get_mount_2(const char *name)
{
        struct lustre_mount_info *lmi;
        ENTRY;

        cfs_mutex_lock(&lustre_mount_info_lock);
        lmi = server_find_mount(name);
        cfs_mutex_unlock(&lustre_mount_info_lock);
        if (!lmi)
                CERROR("Can't find mount for %s\n", name);

        RETURN(lmi);
}
EXPORT_SYMBOL(server_get_mount_2);

static int lustre_put_lsi(struct super_block *sb);

/* to be called from obd_cleanup methods */
int server_put_mount(const char *name, struct vfsmount *mnt)
{
        struct lustre_mount_info *lmi;
        struct lustre_sb_info *lsi;
        ENTRY;

        cfs_mutex_lock(&lustre_mount_info_lock);
        lmi = server_find_mount(name);
        cfs_mutex_unlock(&lustre_mount_info_lock);
        if (!lmi) {
                CERROR("Can't find mount for %s\n", name);
                RETURN(-ENOENT);
        }
        lsi = s2lsi(lmi->lmi_sb);

	CDEBUG(D_MOUNT, "put_mnt %p from %s, refs=%d\n",
	       lmi->lmi_mnt, name, cfs_atomic_read(&lsi->lsi_mounts));

	if (lustre_put_lsi(lmi->lmi_sb))
		CDEBUG(D_MOUNT, "Last put of mnt %p from %s\n",
		       lmi->lmi_mnt, name);

        /* this obd should never need the mount again */
        server_deregister_mount(name);

        RETURN(0);
}
EXPORT_SYMBOL(server_put_mount);

/* Corresponding to server_get_mount_2 */
int server_put_mount_2(const char *name, struct vfsmount *mnt)
{
        ENTRY;
        RETURN(0);
}
EXPORT_SYMBOL(server_put_mount_2);

/**************** config llog ********************/

/** Get a config log from the MGS and process it.
 * This func is called for both clients and servers.
 * Continue to process new statements appended to the logs
 * (whenever the config lock is revoked) until lustre_end_log
 * is called.
 * @param sb The superblock is used by the MGC to write to the local copy of
 *   the config log
 * @param logname The name of the llog to replicate from the MGS
 * @param cfg Since the same mgc may be used to follow multiple config logs
 *   (e.g. ost1, ost2, client), the config_llog_instance keeps the state for
 *   this log, and is added to the mgc's list of logs to follow.
 */
int lustre_process_log(struct super_block *sb, char *logname,
                     struct config_llog_instance *cfg)
{
        struct lustre_cfg *lcfg;
        struct lustre_cfg_bufs *bufs;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        int rc;
        ENTRY;

        LASSERT(mgc);
        LASSERT(cfg);

        OBD_ALLOC_PTR(bufs);
        if (bufs == NULL)
                RETURN(-ENOMEM);

        /* mgc_process_config */
        lustre_cfg_bufs_reset(bufs, mgc->obd_name);
        lustre_cfg_bufs_set_string(bufs, 1, logname);
        lustre_cfg_bufs_set(bufs, 2, cfg, sizeof(*cfg));
        lustre_cfg_bufs_set(bufs, 3, &sb, sizeof(sb));
        lcfg = lustre_cfg_new(LCFG_LOG_START, bufs);
        rc = obd_process_config(mgc, sizeof(*lcfg), lcfg);
        lustre_cfg_free(lcfg);

        OBD_FREE_PTR(bufs);

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
EXPORT_SYMBOL(lustre_process_log);

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
EXPORT_SYMBOL(lustre_end_log);

/**************** obd start *******************/

/** lustre_cfg_bufs are a holdover from 1.4; we can still set these up from
 * lctl (and do for echo cli/srv.
 */
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
EXPORT_SYMBOL(do_lcfg);

/** Call class_attach and class_setup.  These methods in turn call
 * obd type-specific methods.
 */
static int lustre_start_simple(char *obdname, char *type, char *uuid,
			       char *s1, char *s2, char *s3, char *s4)
{
	int rc;
	CDEBUG(D_MOUNT, "Starting obd %s (typ=%s)\n", obdname, type);

	rc = do_lcfg(obdname, 0, LCFG_ATTACH, type, uuid, 0, 0);
	if (rc) {
		CERROR("%s attach error %d\n", obdname, rc);
		return(rc);
	}
	rc = do_lcfg(obdname, 0, LCFG_SETUP, s1, s2, s3, s4);
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
        struct vfsmount          *mnt = lsi->lsi_srv_mnt;
        struct lustre_mount_info *lmi;
        int    rc = 0;
        ENTRY;
        LASSERT(mnt);

        /* It is impossible to have more than 1 MGS per node, since
           MGC wouldn't know which to connect to */
        lmi = server_find_mount(LUSTRE_MGS_OBDNAME);
        if (lmi) {
                lsi = s2lsi(lmi->lmi_sb);
                LCONSOLE_ERROR_MSG(0x15d, "The MGS service was already started"
				   " from server\n");
                RETURN(-EALREADY);
        }

        CDEBUG(D_CONFIG, "Start MGS service %s\n", LUSTRE_MGS_OBDNAME);

        rc = server_register_mount(LUSTRE_MGS_OBDNAME, sb, mnt);

        if (!rc) {
                rc = lustre_start_simple(LUSTRE_MGS_OBDNAME, LUSTRE_MGS_NAME,
					 LUSTRE_MGS_OBDNAME, 0, 0, 0, 0);
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

CFS_DEFINE_MUTEX(mgc_start_lock);

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
        char *mgcname = NULL, *niduuid = NULL, *mgssec = NULL;
        char *ptr;
        int recov_bk;
        int rc = 0, i = 0, j, len;
        ENTRY;

        LASSERT(lsi->lsi_lmd);

        /* Find the first non-lo MGS nid for our MGC name */
	if (IS_SERVER(lsi)) {
		/* mount -o mgsnode=nid */
		ptr = lsi->lsi_lmd->lmd_mgs;
		if (lsi->lsi_lmd->lmd_mgs &&
		    (class_parse_nid(lsi->lsi_lmd->lmd_mgs, &nid, &ptr) == 0)) {
			i++;
		} else if (IS_MGS(lsi)) {
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

        cfs_mutex_lock(&mgc_start_lock);

        len = strlen(LUSTRE_MGC_OBDNAME) + strlen(libcfs_nid2str(nid)) + 1;
        OBD_ALLOC(mgcname, len);
        OBD_ALLOC(niduuid, len + 2);
        if (!mgcname || !niduuid)
                GOTO(out_free, rc = -ENOMEM);
        sprintf(mgcname, "%s%s", LUSTRE_MGC_OBDNAME, libcfs_nid2str(nid));

        mgssec = lsi->lsi_lmd->lmd_mgssec ? lsi->lsi_lmd->lmd_mgssec : "";

        OBD_ALLOC_PTR(data);
        if (data == NULL)
                GOTO(out_free, rc = -ENOMEM);

        obd = class_name2obd(mgcname);
        if (obd && !obd->obd_stopping) {
                rc = obd_set_info_async(NULL, obd->obd_self_export,
                                        strlen(KEY_MGSSEC), KEY_MGSSEC,
                                        strlen(mgssec), mgssec, NULL);
                if (rc)
                        GOTO(out_free, rc);

                /* Re-using an existing MGC */
                cfs_atomic_inc(&obd->u.cli.cl_mgc_refcount);

                /* IR compatibility check, only for clients */
                if (lmd_is_client(lsi->lsi_lmd)) {
                        int has_ir;
                        int vallen = sizeof(*data);
                        __u32 *flags = &lsi->lsi_lmd->lmd_flags;

                        rc = obd_get_info(NULL, obd->obd_self_export,
                                          strlen(KEY_CONN_DATA), KEY_CONN_DATA,
                                          &vallen, data, NULL);
                        LASSERT(rc == 0);
                        has_ir = OCD_HAS_FLAG(data, IMP_RECOV);
                        if (has_ir ^ !(*flags & LMD_FLG_NOIR)) {
                                /* LMD_FLG_NOIR is for test purpose only */
                                LCONSOLE_WARN(
                                    "Trying to mount a client with IR setting "
                                    "not compatible with current mgc. "
                                    "Force to use current mgc setting that is "
                                    "IR %s.\n",
                                    has_ir ? "enabled" : "disabled");
                                if (has_ir)
                                        *flags &= ~LMD_FLG_NOIR;
                                else
                                        *flags |= LMD_FLG_NOIR;
                        }
                }

                recov_bk = 0;
                /* If we are restarting the MGS, don't try to keep the MGC's
                   old connection, or registration will fail. */
		if (IS_MGS(lsi)) {
                        CDEBUG(D_MOUNT, "New MGS with live MGC\n");
                        recov_bk = 1;
                }

                /* Try all connections, but only once (again).
                   We don't want to block another target from starting
                   (using its local copy of the log), but we do want to connect
                   if at all possible. */
                recov_bk++;
                CDEBUG(D_MOUNT, "%s: Set MGC reconnect %d\n", mgcname,recov_bk);
                rc = obd_set_info_async(NULL, obd->obd_self_export,
                                        sizeof(KEY_INIT_RECOV_BACKUP),
                                        KEY_INIT_RECOV_BACKUP,
                                        sizeof(recov_bk), &recov_bk, NULL);
                GOTO(out, rc = 0);
        }

        CDEBUG(D_MOUNT, "Start MGC '%s'\n", mgcname);

        /* Add the primary nids for the MGS */
        i = 0;
        sprintf(niduuid, "%s_%x", mgcname, i);
	if (IS_SERVER(lsi)) {
		ptr = lsi->lsi_lmd->lmd_mgs;
		if (IS_MGS(lsi)) {
                        /* Use local nids (including LO) */
                        lnet_process_id_t id;
                        while ((rc = LNetGetId(i++, &id)) != -ENOENT) {
                                rc = do_lcfg(mgcname, id.nid,
                                             LCFG_ADD_UUID, niduuid, 0,0,0);
                        }
                } else {
                        /* Use mgsnode= nids */
			/* mount -o mgsnode=nid */
			if (lsi->lsi_lmd->lmd_mgs) {
				ptr = lsi->lsi_lmd->lmd_mgs;
			} else if (class_find_param(ptr, PARAM_MGSNODE,
						    &ptr) != 0) {
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
				 niduuid, 0, 0);
        OBD_FREE_PTR(uuid);
        if (rc)
                GOTO(out_free, rc);

        /* Add any failover MGS nids */
        i = 1;
	while (ptr && ((*ptr == ':' ||
	       class_find_param(ptr, PARAM_MGSNODE, &ptr) == 0))) {
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

        rc = obd_set_info_async(NULL, obd->obd_self_export,
                                strlen(KEY_MGSSEC), KEY_MGSSEC,
                                strlen(mgssec), mgssec, NULL);
        if (rc)
                GOTO(out_free, rc);

        /* Keep a refcount of servers/clients who started with "mount",
           so we know when we can get rid of the mgc. */
        cfs_atomic_set(&obd->u.cli.cl_mgc_refcount, 1);

        /* Try all connections, but only once. */
        recov_bk = 1;
        rc = obd_set_info_async(NULL, obd->obd_self_export,
                                sizeof(KEY_INIT_RECOV_BACKUP),
                                KEY_INIT_RECOV_BACKUP,
                                sizeof(recov_bk), &recov_bk, NULL);
        if (rc)
                /* nonfatal */
                CWARN("can't set %s %d\n", KEY_INIT_RECOV_BACKUP, rc);

	/* We connect to the MGS at setup, and don't disconnect until cleanup */
	data->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_AT |
				  OBD_CONNECT_FULL20 | OBD_CONNECT_IMP_RECOV;

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 2, 50, 0)
	data->ocd_connect_flags |= OBD_CONNECT_MNE_SWAB;
#else
#warning "LU-1644: Remove old OBD_CONNECT_MNE_SWAB fixup and imp_need_mne_swab"
#endif

        if (lmd_is_client(lsi->lsi_lmd) &&
            lsi->lsi_lmd->lmd_flags & LMD_FLG_NOIR)
                data->ocd_connect_flags &= ~OBD_CONNECT_IMP_RECOV;
        data->ocd_version = LUSTRE_VERSION_CODE;
        rc = obd_connect(NULL, &exp, obd, &(obd->obd_uuid), data, NULL);
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
        cfs_mutex_unlock(&mgc_start_lock);

        if (data)
                OBD_FREE_PTR(data);
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

        cfs_mutex_lock(&mgc_start_lock);
        LASSERT(cfs_atomic_read(&obd->u.cli.cl_mgc_refcount) > 0);
        if (!cfs_atomic_dec_and_test(&obd->u.cli.cl_mgc_refcount)) {
                /* This is not fatal, every client that stops
                   will call in here. */
                CDEBUG(D_MOUNT, "mgc still has %d references.\n",
                       cfs_atomic_read(&obd->u.cli.cl_mgc_refcount));
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
        cfs_mutex_unlock(&mgc_start_lock);
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
        rc = obd_set_info_async(NULL, mgc->obd_self_export,
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

        rc = obd_set_info_async(NULL, mgc->obd_self_export,
                                sizeof(KEY_CLEAR_FS), KEY_CLEAR_FS,
                                0, NULL, NULL);
        RETURN(rc);
}

CFS_DEFINE_MUTEX(server_start_lock);

/* Stop MDS/OSS if nobody is using them */
static int server_stop_servers(int lsiflags)
{
        struct obd_device *obd = NULL;
        struct obd_type *type = NULL;
        int rc = 0;
        ENTRY;

        cfs_mutex_lock(&server_start_lock);

        /* Either an MDT or an OST or neither  */
        /* if this was an MDT, and there are no more MDT's, clean up the MDS */
	if ((lsiflags & LDD_F_SV_TYPE_MDT) &&
            (obd = class_name2obd(LUSTRE_MDS_OBDNAME))) {
                /*FIXME pre-rename, should eventually be LUSTRE_MDT_NAME*/
                type = class_search_type(LUSTRE_MDS_NAME);
        }
        /* if this was an OST, and there are no more OST's, clean up the OSS */
	if ((lsiflags & LDD_F_SV_TYPE_OST) &&
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

        cfs_mutex_unlock(&server_start_lock);

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

/** Get the fsname ("lustre") from the server name ("lustre-OST003F").
 * @param [in] svname server name including type and index
 * @param [out] fsname Buffer to copy filesystem name prefix into.
 *  Must have at least 'strlen(fsname) + 1' chars.
 * @param [out] endptr if endptr isn't NULL it is set to end of fsname
 * rc < 0  on error
 */
static int server_name2fsname(char *svname, char *fsname, char **endptr)
{
	char *p;

	p = strstr(svname, "-OST");
	if (p == NULL)
		p = strstr(svname, "-MDT");
	if (p == NULL)
		return -1;

	if (fsname) {
		strncpy(fsname, svname, p - svname);
		fsname[p - svname] = '\0';
	}

	if (endptr != NULL)
		*endptr = p;

	return 0;
}

/**
 * Get service name (svname) from string
 * rc < 0 on error
 * if endptr isn't NULL it is set to end of fsname *
 */
int server_name2svname(char *label, char *svname, char **endptr)
{
	int rc;
	char *dash;

	/* We use server_name2fsname() just for parsing */
	rc = server_name2fsname(label, NULL, &dash);
	if (rc != 0)
		return rc;

	if (*dash != '-')
		return -1;

	strncpy(svname, dash + 1, MTI_NAME_MAXLEN);

	return 0;
}
EXPORT_SYMBOL(server_name2svname);


/* Get the index from the obd name.
   rc = server type, or
   rc < 0  on error
   if endptr isn't NULL it is set to end of name */
int server_name2index(char *svname, __u32 *idx, char **endptr)
{
	unsigned long index;
	int rc;
	char *dash;

	/* We use server_name2fsname() just for parsing */
	rc = server_name2fsname(svname, NULL, &dash);
	if (rc != 0)
		return rc;

	if (*dash != '-')
		return -EINVAL;

	dash++;

	if (strncmp(dash, "MDT", 3) == 0)
		rc = LDD_F_SV_TYPE_MDT;
	else if (strncmp(dash, "OST", 3) == 0)
		rc = LDD_F_SV_TYPE_OST;
	else
		return -EINVAL;

	dash += 3;

	if (strcmp(dash, "all") == 0)
		return rc | LDD_F_SV_ALL;

	index = simple_strtoul(dash, endptr, 16);
	*idx = index;

	return rc;
}
EXPORT_SYMBOL(server_name2index);

/* Generate data for registration */
static int server_lsi2mti(struct lustre_sb_info *lsi,
			  struct mgs_target_info *mti)
{
	lnet_process_id_t id;
	int rc, i = 0;
        ENTRY;

	if (!IS_SERVER(lsi))
                RETURN(-EINVAL);

	strncpy(mti->mti_svname, lsi->lsi_svname, sizeof(mti->mti_svname));

        mti->mti_nid_count = 0;
        while (LNetGetId(i++, &id) != -ENOENT) {
                if (LNET_NETTYP(LNET_NIDNET(id.nid)) == LOLND)
                        continue;

                /* server use --servicenode param, only allow specified
                 * nids be registered */
		if ((lsi->lsi_lmd->lmd_flags & LMD_FLG_NO_PRIMNODE) != 0 &&
		    class_match_nid(lsi->lsi_lmd->lmd_params,
                                    PARAM_FAILNODE, id.nid) < 1)
                        continue;

                /* match specified network */
		if (!class_match_net(lsi->lsi_lmd->lmd_params,
                                     PARAM_NETWORK, LNET_NIDNET(id.nid)))
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

	rc = server_name2fsname(lsi->lsi_svname, mti->mti_fsname, NULL);
	if (rc != 0)
		return rc;

	rc = server_name2index(lsi->lsi_svname, &mti->mti_stripe_index, NULL);
	if (rc < 0)
		return rc;
	/* Orion requires index to be set */
	LASSERT(!(rc & LDD_F_NEED_INDEX));
	/* keep only LDD flags */
	mti->mti_flags = lsi->lsi_flags & LDD_F_MASK;
	mti->mti_flags |= LDD_F_UPDATE;
	strncpy(mti->mti_params, lsi->lsi_lmd->lmd_params,
		sizeof(mti->mti_params));
	return 0;
}

/* Register an old or new target with the MGS. If needed MGS will construct
   startup logs and assign index */
static int server_register_target(struct lustre_sb_info *lsi)
{
        struct obd_device *mgc = lsi->lsi_mgc;
        struct mgs_target_info *mti = NULL;
        bool writeconf;
        int rc;
        ENTRY;

        LASSERT(mgc);

	if (!IS_SERVER(lsi))
                RETURN(-EINVAL);

        OBD_ALLOC_PTR(mti);
        if (!mti)
                RETURN(-ENOMEM);

	rc = server_lsi2mti(lsi, mti);
        if (rc)
                GOTO(out, rc);

        CDEBUG(D_MOUNT, "Registration %s, fs=%s, %s, index=%04x, flags=%#x\n",
               mti->mti_svname, mti->mti_fsname,
               libcfs_nid2str(mti->mti_nids[0]), mti->mti_stripe_index,
               mti->mti_flags);

        /* if write_conf is true, the registration must succeed */
	writeconf = !!(lsi->lsi_flags & (LDD_F_NEED_INDEX | LDD_F_UPDATE));
        mti->mti_flags |= LDD_F_OPC_REG;

        /* Register the target */
        /* FIXME use mgc_process_config instead */
        rc = obd_set_info_async(NULL, mgc->u.cli.cl_mgc_mgsexp,
                                sizeof(KEY_REGISTER_TARGET), KEY_REGISTER_TARGET,
                                sizeof(*mti), mti, NULL);
        if (rc) {
                if (mti->mti_flags & LDD_F_ERROR) {
                        LCONSOLE_ERROR_MSG(0x160,
                                "The MGS is refusing to allow this "
                                "server (%s) to start. Please see messages"
				" on the MGS node.\n", lsi->lsi_svname);
                } else if (writeconf) {
                        LCONSOLE_ERROR_MSG(0x15f,
                                "Communication to the MGS return error %d. "
                                "Is the MGS running?\n", rc);
                } else {
                        CERROR("Cannot talk to the MGS: %d, not fatal\n", rc);
                        /* reset the error code for non-fatal error. */
                        rc = 0;
                }
                GOTO(out, rc);
        }

out:
        if (mti)
                OBD_FREE_PTR(mti);
        RETURN(rc);
}

/**
 * Notify the MGS that this target is ready.
 * Used by IR - if the MGS receives this message, it will notify clients.
 */
static int server_notify_target(struct super_block *sb, struct obd_device *obd)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        struct mgs_target_info *mti = NULL;
        int rc;
        ENTRY;

        LASSERT(mgc);

	if (!(IS_SERVER(lsi)))
                RETURN(-EINVAL);

        OBD_ALLOC_PTR(mti);
        if (!mti)
                RETURN(-ENOMEM);
	rc = server_lsi2mti(lsi, mti);
        if (rc)
                GOTO(out, rc);

        mti->mti_instance = obd->u.obt.obt_instance;
        mti->mti_flags |= LDD_F_OPC_READY;

        /* FIXME use mgc_process_config instead */
        rc = obd_set_info_async(NULL, mgc->u.cli.cl_mgc_mgsexp,
                                sizeof(KEY_REGISTER_TARGET),
                                KEY_REGISTER_TARGET,
                                sizeof(*mti), mti, NULL);

        /* Imperative recovery: if the mgs informs us to use IR? */
        if (!rc && !(mti->mti_flags & LDD_F_ERROR) &&
            (mti->mti_flags & LDD_F_IR_CAPABLE))
		lsi->lsi_flags |= LDD_F_IR_CAPABLE;

out:
        if (mti)
                OBD_FREE_PTR(mti);
        RETURN(rc);

}

/** Start server targets: MDTs and OSTs
 */
static int server_start_targets(struct super_block *sb, struct vfsmount *mnt)
{
        struct obd_device *obd;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct config_llog_instance cfg;
        int rc;
        ENTRY;

	CDEBUG(D_MOUNT, "starting target %s\n", lsi->lsi_svname);

#if 0
        /* If we're an MDT, make sure the global MDS is running */
        if (lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_MDT) {
                /* make sure the MDS is started */
                cfs_mutex_lock(&server_start_lock);
                obd = class_name2obd(LUSTRE_MDS_OBDNAME);
                if (!obd) {
                        rc = lustre_start_simple(LUSTRE_MDS_OBDNAME,
                    /* FIXME pre-rename, should eventually be LUSTRE_MDS_NAME */
                                                 LUSTRE_MDT_NAME,
                                                 LUSTRE_MDS_OBDNAME"_uuid",
                                                 0, 0);
                        if (rc) {
                                cfs_mutex_unlock(&server_start_lock);
                                CERROR("failed to start MDS: %d\n", rc);
                                RETURN(rc);
                        }
                }
                cfs_mutex_unlock(&server_start_lock);
        }
#endif

        /* If we're an OST, make sure the global OSS is running */
	if (IS_OST(lsi)) {
                /* make sure OSS is started */
                cfs_mutex_lock(&server_start_lock);
                obd = class_name2obd(LUSTRE_OSS_OBDNAME);
                if (!obd) {
                        rc = lustre_start_simple(LUSTRE_OSS_OBDNAME,
                                                 LUSTRE_OSS_NAME,
                                                 LUSTRE_OSS_OBDNAME"_uuid",
						 0, 0, 0, 0);
                        if (rc) {
                                cfs_mutex_unlock(&server_start_lock);
                                CERROR("failed to start OSS: %d\n", rc);
                                RETURN(rc);
                        }
                }
                cfs_mutex_unlock(&server_start_lock);
        }

        /* Set the mgc fs to our server disk.  This allows the MGC to
         * read and write configs locally, in case it can't talk to the MGS. */
	if (lsi->lsi_srv_mnt) {
		rc = server_mgc_set_fs(lsi->lsi_mgc, sb);
		if (rc)
			RETURN(rc);
	}

        /* Register with MGS */
	rc = server_register_target(lsi);
        if (rc)
                GOTO(out_mgc, rc);

        /* Let the target look up the mount using the target's name
           (we can't pass the sb or mnt through class_process_config.) */
	rc = server_register_mount(lsi->lsi_svname, sb, mnt);
        if (rc)
                GOTO(out_mgc, rc);

	/* Start targets using the llog named for the target */
	memset(&cfg, 0, sizeof(cfg));
	rc = lustre_process_log(sb, lsi->lsi_svname, &cfg);
	if (rc) {
		CERROR("failed to start server %s: %d\n",
		       lsi->lsi_svname, rc);
		/* Do NOT call server_deregister_mount() here. This makes it
		 * impossible to find mount later in cleanup time and leaves
		 * @lsi and othder stuff leaked. -umka */
		GOTO(out_mgc, rc);
	}

out_mgc:
        /* Release the mgc fs for others to use */
	if (lsi->lsi_srv_mnt)
		server_mgc_clear_fs(lsi->lsi_mgc);

        if (!rc) {
		obd = class_name2obd(lsi->lsi_svname);
                if (!obd) {
                        CERROR("no server named %s was started\n",
			       lsi->lsi_svname);
                        RETURN(-ENXIO);
                }

                if ((lsi->lsi_lmd->lmd_flags & LMD_FLG_ABORT_RECOV) &&
                    (OBP(obd, iocontrol))) {
                        obd_iocontrol(OBD_IOC_ABORT_RECOVERY,
                                      obd->obd_self_export, 0, NULL, NULL);
                }

                server_notify_target(sb, obd);

                /* calculate recovery timeout, do it after lustre_process_log */
                server_calc_timeout(lsi, obd);

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
        lsi->lsi_lmd->lmd_recovery_time_soft = 0;
        lsi->lsi_lmd->lmd_recovery_time_hard = 0;
        s2lsi_nocast(sb) = lsi;
        /* we take 1 extra ref for our setup */
        cfs_atomic_set(&lsi->lsi_mounts, 1);

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
        LASSERT(cfs_atomic_read(&lsi->lsi_mounts) == 0);

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
		if (lsi->lsi_lmd->lmd_mgs != NULL)
			OBD_FREE(lsi->lsi_lmd->lmd_mgs,
				 strlen(lsi->lsi_lmd->lmd_mgs) + 1);
		if (lsi->lsi_lmd->lmd_osd_type != NULL)
			OBD_FREE(lsi->lsi_lmd->lmd_osd_type,
				 strlen(lsi->lsi_lmd->lmd_osd_type) + 1);
		if (lsi->lsi_lmd->lmd_params != NULL)
			OBD_FREE(lsi->lsi_lmd->lmd_params, 4096);

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

        CDEBUG(D_MOUNT, "put %p %d\n", sb, cfs_atomic_read(&lsi->lsi_mounts));
        if (cfs_atomic_dec_and_test(&lsi->lsi_mounts)) {
		if (IS_SERVER(lsi) && lsi->lsi_osd_exp) {
			obd_disconnect(lsi->lsi_osd_exp);
			/* wait till OSD is gone */
			obd_zombie_barrier();
		}
                lustre_free_lsi(sb);
                RETURN(1);
        }
        RETURN(0);
}

static int lsi_prepare(struct lustre_sb_info *lsi)
{
	__u32 index;
	int rc;
	ENTRY;

	LASSERT(lsi);
	LASSERT(lsi->lsi_lmd);

	/* The server name is given as a mount line option */
	if (lsi->lsi_lmd->lmd_profile == NULL) {
		LCONSOLE_ERROR("Can't determine server name\n");
		RETURN(-EINVAL);
	}

	if (strlen(lsi->lsi_lmd->lmd_profile) >= sizeof(lsi->lsi_svname))
		RETURN(-ENAMETOOLONG);

	strcpy(lsi->lsi_svname, lsi->lsi_lmd->lmd_profile);

	/* Determine osd type */
	if (lsi->lsi_lmd->lmd_osd_type != NULL) {
		if (strlen(lsi->lsi_lmd->lmd_osd_type) >=
			   sizeof(lsi->lsi_osd_type))
			RETURN(-ENAMETOOLONG);

		strcpy(lsi->lsi_osd_type, lsi->lsi_lmd->lmd_osd_type);
	} else {
		strcpy(lsi->lsi_osd_type, LUSTRE_OSD_LDISKFS_NAME);
	}

	/* XXX: a temp. solution for components using fsfilt
	 *      to be removed in one of the subsequent patches */
	if (!strcmp(lsi->lsi_lmd->lmd_osd_type, "osd-ldiskfs")) {
		strcpy(lsi->lsi_fstype, "ldiskfs");
	} else {
		strcpy(lsi->lsi_fstype, lsi->lsi_lmd->lmd_osd_type);
	}

	/* Determine server type */
	rc = server_name2index(lsi->lsi_svname, &index, NULL);
	if (rc < 0) {
		if (lsi->lsi_lmd->lmd_flags & LMD_FLG_MGS) {
			/* Assume we're a bare MGS */
			rc = 0;
			lsi->lsi_lmd->lmd_flags |= LMD_FLG_NOSVC;
		} else {
			LCONSOLE_ERROR("Can't determine server type of '%s'\n",
				       lsi->lsi_svname);
			RETURN(rc);
		}
	}
	lsi->lsi_flags |= rc;

	/* Add mount line flags that used to be in ldd:
	 * writeconf, mgs, iam, anything else?
	 */
	lsi->lsi_flags |= (lsi->lsi_lmd->lmd_flags & LMD_FLG_WRITECONF) ?
		LDD_F_WRITECONF : 0;
	lsi->lsi_flags |= (lsi->lsi_lmd->lmd_flags & LMD_FLG_VIRGIN) ?
		LDD_F_VIRGIN : 0;
	lsi->lsi_flags |= (lsi->lsi_lmd->lmd_flags & LMD_FLG_MGS) ?
		LDD_F_SV_TYPE_MGS : 0;
	lsi->lsi_flags |= (lsi->lsi_lmd->lmd_flags & LMD_FLG_IAM) ?
		LDD_F_IAM_DIR : 0;
	lsi->lsi_flags |= (lsi->lsi_lmd->lmd_flags & LMD_FLG_NO_PRIMNODE) ?
		LDD_F_NO_PRIMNODE : 0;

	RETURN(0);
}

/*************** server mount ******************/

/** Start the shutdown of servers at umount.
 */
static void server_put_super(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device     *obd;
        char *tmpname, *extraname = NULL;
        int tmpname_sz;
        int lsiflags = lsi->lsi_flags;
        ENTRY;

	LASSERT(IS_SERVER(lsi));

	tmpname_sz = strlen(lsi->lsi_svname) + 1;
        OBD_ALLOC(tmpname, tmpname_sz);
	memcpy(tmpname, lsi->lsi_svname, tmpname_sz);
        CDEBUG(D_MOUNT, "server put_super %s\n", tmpname);
	if (IS_MDT(lsi) && (lsi->lsi_lmd->lmd_flags & LMD_FLG_NOSVC))
                snprintf(tmpname, tmpname_sz, "MGS");

        /* Stop the target */
        if (!(lsi->lsi_lmd->lmd_flags & LMD_FLG_NOSVC) &&
	    (IS_MDT(lsi) || IS_OST(lsi))) {
                struct lustre_profile *lprof = NULL;

                /* tell the mgc to drop the config log */
		lustre_end_log(sb, lsi->lsi_svname, NULL);

                /* COMPAT_146 - profile may get deleted in mgc_cleanup.
                   If there are any setup/cleanup errors, save the lov
                   name for safety cleanup later. */
		lprof = class_get_profile(lsi->lsi_svname);
                if (lprof && lprof->lp_dt) {
                        OBD_ALLOC(extraname, strlen(lprof->lp_dt) + 1);
                        strcpy(extraname, lprof->lp_dt);
                }

		obd = class_name2obd(lsi->lsi_svname);
                if (obd) {
                        CDEBUG(D_MOUNT, "stopping %s\n", obd->obd_name);
                        if (lsi->lsi_flags & LSI_UMOUNT_FAILOVER)
                                obd->obd_fail = 1;
                        /* We can't seem to give an error return code
                         * to .put_super, so we better make sure we clean up! */
                        obd->obd_force = 1;
                        class_manual_cleanup(obd);
                } else {
			CERROR("no obd %s\n", lsi->lsi_svname);
			server_deregister_mount(lsi->lsi_svname);
                }
        }

        /* If they wanted the mgs to stop separately from the mdt, they
           should have put it on a different device. */
	if (IS_MGS(lsi)) {
                /* if MDS start with --nomgs, don't stop MGS then */
                if (!(lsi->lsi_lmd->lmd_flags & LMD_FLG_NOMGS))
                        server_stop_mgs(sb);
        }

        /* Clean the mgc and sb */
        lustre_common_put_super(sb);

	/* wait till all in-progress cleanups are done
	 * specifically we're interested in ofd cleanup
	 * as it pins OSS */
	obd_zombie_barrier();

	/* Stop the servers (MDS, OSS) if no longer needed.  We must wait
	   until the target is really gone so that our type refcount check
	   is right. */
	server_stop_servers(lsiflags);

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

/** Called only for 'umount -f'
 */
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
        EXIT;
}

static int server_statfs (struct dentry *dentry, cfs_kstatfs_t *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_statfs statfs;
	int rc;
	ENTRY;

	if (lsi->lsi_dt_dev) {
		rc = dt_statfs(NULL, lsi->lsi_dt_dev, &statfs);
		if (rc == 0) {
			statfs_unpack(buf, &statfs);
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

/** The operations we support directly on the superblock:
 * mount, umount, and df.
 */
static struct super_operations server_ops =
{
        .put_super      = server_put_super,
        .umount_begin   = server_umount_begin, /* umount -f */
        .statfs         = server_statfs,
};

#define log2(n) cfs_ffz(~(n))
#define LUSTRE_SUPER_MAGIC 0x0BD00BD1

static int server_fill_super_common(struct super_block *sb)
{
        struct inode *root = 0;
        ENTRY;

        CDEBUG(D_MOUNT, "Server sb, dev=%d\n", (int)sb->s_dev);

        sb->s_blocksize = 4096;
        sb->s_blocksize_bits = log2(sb->s_blocksize);
        sb->s_magic = LUSTRE_SUPER_MAGIC;
        sb->s_maxbytes = 0; /* we don't allow file IO on server mountpoints */
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

static int osd_start(struct lustre_sb_info *lsi, unsigned long mflags)
{
	struct lustre_mount_data *lmd = lsi->lsi_lmd;
	struct obd_device	 *obd;
	struct dt_device_param    p;
	char			  flagstr[16];
	int			  rc;
	ENTRY;

	CDEBUG(D_MOUNT,
	       "Attempting to start %s, type=%s, lsifl=%x, mountfl=%lx\n",
	       lsi->lsi_svname, lsi->lsi_osd_type, lsi->lsi_flags, mflags);

	sprintf(lsi->lsi_osd_obdname, "%s-osd", lsi->lsi_svname);
	strcpy(lsi->lsi_osd_uuid, lsi->lsi_osd_obdname);
	strcat(lsi->lsi_osd_uuid, "_UUID");
	sprintf(flagstr, "%lu:%lu", mflags, (unsigned long) lmd->lmd_flags);

	obd = class_name2obd(lsi->lsi_osd_obdname);
	if (obd == NULL) {
		rc = lustre_start_simple(lsi->lsi_osd_obdname,
				lsi->lsi_osd_type,
				lsi->lsi_osd_uuid, lmd->lmd_dev,
				flagstr, lsi->lsi_lmd->lmd_opts,
				lsi->lsi_svname);
		if (rc)
			GOTO(out, rc);
		obd = class_name2obd(lsi->lsi_osd_obdname);
		LASSERT(obd);
	}

	rc = obd_connect(NULL, &lsi->lsi_osd_exp, obd, &obd->obd_uuid, NULL, NULL);
	if (rc) {
		obd->obd_force = 1;
		class_manual_cleanup(obd);
		lsi->lsi_dt_dev = NULL;
	}

	/* XXX: to keep support old components relying on lsi_srv_mnt
	 *	we get this info from OSD just started */
	LASSERT(obd->obd_lu_dev);
	lsi->lsi_dt_dev = lu2dt_dev(obd->obd_lu_dev);
	LASSERT(lsi->lsi_dt_dev);

	dt_conf_get(NULL, lsi->lsi_dt_dev, &p);

	lsi->lsi_srv_mnt = p.ddp_mnt;

out:
	RETURN(rc);
}

/** Fill in the superblock info for a Lustre server.
 * Mount the device with the correct options.
 * Read the on-disk config file.
 * Start the services.
 */
static int server_fill_super(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        int rc;
        ENTRY;

	rc = lsi_prepare(lsi);
	if (rc)
		RETURN(rc);

	/* Start low level OSD */
	rc = osd_start(lsi, sb->s_flags);
	if (rc) {
		CERROR("Unable to start osd on %s: %d\n",
		       lsi->lsi_lmd->lmd_dev, rc);
                lustre_put_lsi(sb);
                RETURN(rc);
	}

	CDEBUG(D_MOUNT, "Found service %s on device %s\n",
	       lsi->lsi_svname, lsi->lsi_lmd->lmd_dev);

	if (class_name2obd(lsi->lsi_svname)) {
                LCONSOLE_ERROR_MSG(0x161, "The target named %s is already "
                                   "running. Double-mount may have compromised"
                                   " the disk journal.\n",
				   lsi->lsi_svname);
                lustre_put_lsi(sb);
                RETURN(-EALREADY);
        }

        /* Start MGS before MGC */
	if (IS_MGS(lsi) && !(lsi->lsi_lmd->lmd_flags & LMD_FLG_NOMGS)){
                rc = server_start_mgs(sb);
                if (rc)
                        GOTO(out_mnt, rc);
        }

        /* Start MGC before servers */
        rc = lustre_start_mgc(sb);
        if (rc)
                GOTO(out_mnt, rc);

        /* Set up all obd devices for service */
        if (!(lsi->lsi_lmd->lmd_flags & LMD_FLG_NOSVC) &&
			(IS_OST(lsi) || IS_MDT(lsi))) {
		rc = server_start_targets(sb, lsi->lsi_srv_mnt);
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

        RETURN(0);
out_mnt:
        /* We jump here in case of failure while starting targets or MGS.
         * In this case we can't just put @mnt and have to do real cleanup
         * with stoping targets, etc. */
        server_put_super(sb);
        return rc;
}

/*
 * Calculate timeout value for a target.
 */
void server_calc_timeout(struct lustre_sb_info *lsi, struct obd_device *obd)
{
        struct lustre_mount_data *lmd;
        int soft = 0;
        int hard = 0;
        int factor = 0;
	bool has_ir = !!(lsi->lsi_flags & LDD_F_IR_CAPABLE);
        int min = OBD_RECOVERY_TIME_MIN;

	LASSERT(IS_SERVER(lsi));

        lmd = lsi->lsi_lmd;
        if (lmd) {
                soft   = lmd->lmd_recovery_time_soft;
                hard   = lmd->lmd_recovery_time_hard;
                has_ir = has_ir && !(lmd->lmd_flags & LMD_FLG_NOIR);
                obd->obd_no_ir = !has_ir;
        }

        if (soft == 0)
                soft = OBD_RECOVERY_TIME_SOFT;
        if (hard == 0)
                hard = OBD_RECOVERY_TIME_HARD;

        /* target may have ir_factor configured. */
        factor = OBD_IR_FACTOR_DEFAULT;
        if (obd->obd_recovery_ir_factor)
                factor = obd->obd_recovery_ir_factor;

        if (has_ir) {
                int new_soft = soft;
                int new_hard = hard;

                /* adjust timeout value by imperative recovery */

                new_soft = (soft * factor) / OBD_IR_FACTOR_MAX;
                new_hard = (hard * factor) / OBD_IR_FACTOR_MAX;

                /* make sure the timeout is not too short */
                new_soft = max(min, new_soft);
                new_hard = max(new_soft, new_hard);

                LCONSOLE_INFO("%s: Imperative Recovery enabled, recovery "
                              "window shrunk from %d-%d down to %d-%d\n",
                              obd->obd_name, soft, hard, new_soft, new_hard);

                soft = new_soft;
                hard = new_hard;
        }

        /* we're done */
        obd->obd_recovery_timeout   = max(obd->obd_recovery_timeout, soft);
        obd->obd_recovery_time_hard = hard;
        obd->obd_recovery_ir_factor = factor;
}
EXPORT_SYMBOL(server_calc_timeout);

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
EXPORT_SYMBOL(lustre_common_put_super);

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

        if (lmd->lmd_recovery_time_soft)
                PRINT_CMD(PRINT_MASK, "recovery time soft: %d\n",
                          lmd->lmd_recovery_time_soft);

        if (lmd->lmd_recovery_time_hard)
                PRINT_CMD(PRINT_MASK, "recovery time hard: %d\n",
                          lmd->lmd_recovery_time_hard);

        for (i = 0; i < lmd->lmd_exclude_count; i++) {
                PRINT_CMD(PRINT_MASK, "exclude %d:  OST%04x\n", i,
                          lmd->lmd_exclude[i]);
        }
}

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

static int lmd_parse_string(char **handle, char *ptr)
{
	char   *tail;
	int     length;

	if ((handle == NULL) || (ptr == NULL))
		return -EINVAL;

	if (*handle != NULL) {
		OBD_FREE(*handle, strlen(*handle) + 1);
		*handle = NULL;
	}

	tail = strchr(ptr, ',');
	if (tail == NULL)
		length = strlen(ptr);
	else
		length = tail - ptr;

	OBD_ALLOC(*handle, length + 1);
	if (*handle == NULL)
		return -ENOMEM;

	memcpy(*handle, ptr, length);
	(*handle)[length] = '\0';

	return 0;
}

/* Collect multiple values for mgsnid specifiers */
static int lmd_parse_mgs(struct lustre_mount_data *lmd, char **ptr)
{
	lnet_nid_t nid;
	char *tail = *ptr;
	char *mgsnid;
	int   length;
	int   oldlen = 0;

	/* Find end of nidlist */
	while (class_parse_nid(tail, &nid, &tail) == 0) {}
	length = tail - *ptr;
	if (length == 0) {
		LCONSOLE_ERROR_MSG(0x159, "Can't parse NID '%s'\n", *ptr);
		return -EINVAL;
	}

	if (lmd->lmd_mgs != NULL)
		oldlen = strlen(lmd->lmd_mgs) + 1;

	OBD_ALLOC(mgsnid, oldlen + length + 1);
	if (mgsnid == NULL)
		return -ENOMEM;

	if (lmd->lmd_mgs != NULL) {
		/* Multiple mgsnid= are taken to mean failover locations */
		memcpy(mgsnid, lmd->lmd_mgs, oldlen);
		mgsnid[oldlen - 1] = ':';
		OBD_FREE(lmd->lmd_mgs, oldlen);
	}
	memcpy(mgsnid + oldlen, *ptr, length);
	mgsnid[oldlen + length] = '\0';
	lmd->lmd_mgs = mgsnid;
	*ptr = tail;

	return 0;
}

/** Parse mount line options
 * e.g. mount -v -t lustre -o abort_recov uml1:uml2:/lustre-client /mnt/lustre
 * dev is passed as device=uml1:/lustre by mount.lustre
 */
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

	OBD_ALLOC(lmd->lmd_params, 4096);
	if (lmd->lmd_params == NULL)
		RETURN(-ENOMEM);
	lmd->lmd_params[0] = '\0';

        /* Set default flags here */

        s1 = options;
        while (*s1) {
                int clear = 0;
                int time_min = OBD_RECOVERY_TIME_MIN;

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
                } else if (strncmp(s1, "recovery_time_soft=", 19) == 0) {
                        lmd->lmd_recovery_time_soft = max_t(int,
                                simple_strtoul(s1 + 19, NULL, 10), time_min);
                        clear++;
                } else if (strncmp(s1, "recovery_time_hard=", 19) == 0) {
                        lmd->lmd_recovery_time_hard = max_t(int,
                                simple_strtoul(s1 + 19, NULL, 10), time_min);
                        clear++;
                } else if (strncmp(s1, "noir", 4) == 0) {
                        lmd->lmd_flags |= LMD_FLG_NOIR; /* test purpose only. */
                        clear++;
                } else if (strncmp(s1, "nosvc", 5) == 0) {
                        lmd->lmd_flags |= LMD_FLG_NOSVC;
                        clear++;
                } else if (strncmp(s1, "nomgs", 5) == 0) {
                        lmd->lmd_flags |= LMD_FLG_NOMGS;
                        clear++;
		} else if (strncmp(s1, "noscrub", 7) == 0) {
			lmd->lmd_flags |= LMD_FLG_NOSCRUB;
			clear++;
		} else if (strncmp(s1, PARAM_MGSNODE,
				   sizeof(PARAM_MGSNODE) - 1) == 0) {
			s2 = s1 + sizeof(PARAM_MGSNODE) - 1;
			/* Assume the next mount opt is the first
			   invalid nid we get to. */
			rc = lmd_parse_mgs(lmd, &s2);
			if (rc)
				goto invalid;
			clear++;
                } else if (strncmp(s1, "writeconf", 9) == 0) {
                        lmd->lmd_flags |= LMD_FLG_WRITECONF;
                        clear++;
		} else if (strncmp(s1, "virgin", 6) == 0) {
			lmd->lmd_flags |= LMD_FLG_VIRGIN;
			clear++;
		} else if (strncmp(s1, "noprimnode", 10) == 0) {
			lmd->lmd_flags |= LMD_FLG_NO_PRIMNODE;
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
		} else if (strncmp(s1, "mgs", 3) == 0) {
			/* We are an MGS */
			lmd->lmd_flags |= LMD_FLG_MGS;
			clear++;
		} else if (strncmp(s1, "svname=", 7) == 0) {
			rc = lmd_parse_string(&lmd->lmd_profile, s1 + 7);
			if (rc)
				goto invalid;
			clear++;
		} else if (strncmp(s1, "param=", 6) == 0) {
			int length;
			char *tail = strchr(s1 + 6, ',');
			if (tail == NULL)
				length = strlen(s1);
			else
				length = tail - s1;
			length -= 6;
			strncat(lmd->lmd_params, s1 + 6, length);
			strcat(lmd->lmd_params, " ");
			clear++;
		} else if (strncmp(s1, "osd=", 4) == 0) {
			rc = lmd_parse_string(&lmd->lmd_osd_type, s1 + 4);
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
                lmd->lmd_flags |= LMD_FLG_CLIENT;
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

        lmd_print(lmd);
        lmd->lmd_magic = LMD_MAGIC;

        RETURN(rc);

invalid:
        CERROR("Bad mount options %s\n", options);
        RETURN(-EINVAL);
}

struct lustre_mount_data2 {
        void *lmd2_data;
        struct vfsmount *lmd2_mnt;
};

/** This is the entry point for the mount call into Lustre.
 * This is called when a server or client is mounted,
 * and this is where we start setting things up.
 * @param data Mount options (e.g. -o flock,abort_recov)
 */
int lustre_fill_super(struct super_block *sb, void *data, int silent)
{
        struct lustre_mount_data *lmd;
        struct lustre_mount_data2 *lmd2 = data;
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
        cfs_lockdep_off();

        /*
         * LU-639: the obd cleanup of last mount may not finish yet, wait here.
         */
        obd_zombie_barrier();

        /* Figure out the lmd from the mount options */
        if (lmd_parse((char *)(lmd2->lmd2_data), lmd)) {
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
                        rc = (*client_fill_super)(sb, lmd2->lmd2_mnt);
                        /* c_f_s will call lustre_common_put_super on failure */
                }
        } else {
                CDEBUG(D_MOUNT, "Mounting server from %s\n", lmd->lmd_dev);
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
        cfs_lockdep_on();
        return rc;
}


/* We can't call ll_fill_super by name because it lives in a module that
   must be loaded after this one. */
void lustre_register_client_fill_super(int (*cfs)(struct super_block *sb,
                                                  struct vfsmount *mnt))
{
        client_fill_super = cfs;
}
EXPORT_SYMBOL(lustre_register_client_fill_super);

void lustre_register_kill_super_cb(void (*cfs)(struct super_block *sb))
{
        kill_super_cb = cfs;
}
EXPORT_SYMBOL(lustre_register_kill_super_cb);

/***************** FS registration ******************/
#ifdef HAVE_FSTYPE_MOUNT
struct dentry *lustre_mount(struct file_system_type *fs_type, int flags,
				const char *devname, void *data)
{
	struct lustre_mount_data2 lmd2 = { data, NULL };

	return mount_nodev(fs_type, flags, &lmd2, lustre_fill_super);
}
#else
int lustre_get_sb(struct file_system_type *fs_type, int flags,
                  const char *devname, void * data, struct vfsmount *mnt)
{
	struct lustre_mount_data2 lmd2 = { data, mnt };

	return get_sb_nodev(fs_type, flags, &lmd2, lustre_fill_super, mnt);
}
#endif

void lustre_kill_super(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);

	if (kill_super_cb && lsi && !IS_SERVER(lsi))
                (*kill_super_cb)(sb);

        kill_anon_super(sb);
}

/** Register the "lustre" fs type
 */
struct file_system_type lustre_fs_type = {
        .owner        = THIS_MODULE,
        .name         = "lustre",
#ifdef HAVE_FSTYPE_MOUNT
	.mount        = lustre_mount,
#else
        .get_sb       = lustre_get_sb,
#endif
        .kill_sb      = lustre_kill_super,
        .fs_flags     = FS_BINARY_MOUNTDATA | FS_REQUIRES_DEV |
#ifdef FS_HAS_FIEMAP
                        FS_HAS_FIEMAP |
#endif
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

EXPORT_SYMBOL(server_mti_print);
