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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/obd_mount.c
 *
 * Client mount routines
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */


#define DEBUG_SUBSYSTEM S_CLASS
#define D_MOUNT (D_SUPER|D_CONFIG/*|D_WARNING */)
#define PRINT_CMD CDEBUG

#include <linux/types.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <linux/uuid.h>
#include <linux/version.h>

#include <obd.h>
#include <obd_class.h>
#include <lustre_crypto.h>
#include <lustre_log.h>
#include <lustre_disk.h>
#include <uapi/linux/lustre/lustre_param.h>

/**************** config llog ********************/

/**
 * Get a config log from the MGS and process it.
 * This func is called for both clients and servers.
 * Continue to process new statements appended to the logs
 * (whenever the config lock is revoked) until lustre_end_log
 * is called.
 *
 * @param sb The superblock is used by the MGC to write to the local copy of
 *   the config log
 * @param logname The name of the llog to replicate from the MGS
 * @param cfg Since the same MGC may be used to follow multiple config logs
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
	OBD_ALLOC(lcfg, lustre_cfg_len(bufs->lcfg_bufcount, bufs->lcfg_buflen));
	if (!lcfg)
		GOTO(out, rc = -ENOMEM);
	lustre_cfg_init(lcfg, LCFG_LOG_START, bufs);

	rc = obd_process_config(mgc, sizeof(*lcfg), lcfg);
	OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount, lcfg->lcfg_buflens));
out:
	OBD_FREE_PTR(bufs);

	if (rc == -EINVAL)
		LCONSOLE_ERROR("%s: Configuration from log %s failed from MGS %d. Check client and MGS are on compatible version.\n",
			       mgc->obd_name, logname, rc);
	else if (rc != 0)
		LCONSOLE_ERROR("%s: Confguration from log %s failed from MGS %d. Communication error between node & MGS, a bad configuration, or other errors. See syslog for more info\n",
			       mgc->obd_name, logname, rc);

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
	OBD_ALLOC(lcfg, lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (!lcfg)
		RETURN(-ENOMEM);
	lustre_cfg_init(lcfg, LCFG_LOG_END, &bufs);
	rc = obd_process_config(mgc, sizeof(*lcfg), lcfg);
	OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount, lcfg->lcfg_buflens));
	RETURN(rc);
}
EXPORT_SYMBOL(lustre_end_log);

/**************** OBD start *******************/

/**
 * lustre_cfg_bufs are a holdover from 1.4; we can still set these up from
 * lctl (and do for echo cli/srv.
 */
static int do_lcfg(char *cfgname, lnet_nid_t nid, int cmd,
		   char *s1, char *s2, char *s3, char *s4)
{
	struct lustre_cfg_bufs bufs;
	struct lustre_cfg *lcfg = NULL;
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

	OBD_ALLOC(lcfg, lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (!lcfg)
		return -ENOMEM;
	lustre_cfg_init(lcfg, cmd, &bufs);
	lcfg->lcfg_nid = nid;
	rc = class_process_config(lcfg);
	OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount, lcfg->lcfg_buflens));
	return rc;
}

static int do_lcfg_nid(char *cfgname, struct lnet_nid *nid, int cmd,
		       char *s1)
{
	lnet_nid_t nid4 = 0;
	char *nidstr = NULL;

	if (nid_is_nid4(nid))
		nid4 = lnet_nid_to_nid4(nid);
	else
		nidstr = libcfs_nidstr(nid);
	return do_lcfg(cfgname, nid4, cmd, s1, nidstr, NULL, NULL);
}

/**
 * Call class_attach and class_setup.  These methods in turn call
 * OBD type-specific methods.
 */
SERVER_ONLY
int lustre_start_simple(char *obdname, char *type, char *uuid,
			char *s1, char *s2, char *s3, char *s4)
{
	int rc;

	CDEBUG(D_MOUNT, "Starting OBD %s (typ=%s)\n", obdname, type);

	rc = do_lcfg(obdname, 0, LCFG_ATTACH, type, uuid, NULL, NULL);
	if (rc) {
		CERROR("%s attach error %d\n", obdname, rc);
		return rc;
	}
	rc = do_lcfg(obdname, 0, LCFG_SETUP, s1, s2, s3, s4);
	if (rc) {
		CERROR("%s setup error %d\n", obdname, rc);
		do_lcfg(obdname, 0, LCFG_DETACH, NULL, NULL, NULL, NULL);
	}
	return rc;
}
SERVER_ONLY_EXPORT_SYMBOL(lustre_start_simple);

static DEFINE_MUTEX(mgc_start_lock);

/* 9 for '_%x' (INT_MAX as hex is 8 chars - '7FFFFFFF') and 1 for '\0' */
#define NIDUUID_SUFFIX_MAX_LEN 10
static inline int mgc_niduuid_create(char **niduuid, char *nidstr)
{
	size_t niduuid_len = strlen(nidstr) + strlen(LUSTRE_MGC_OBDNAME) +
			     NIDUUID_SUFFIX_MAX_LEN;

	LASSERT(niduuid);

	/* See comment in niduuid_create() */
	if (niduuid_len > UUID_MAX) {
		nidstr += niduuid_len - UUID_MAX;
		niduuid_len = strlen(LUSTRE_MGC_OBDNAME) +
			      strlen(nidstr) + NIDUUID_SUFFIX_MAX_LEN;
	}

	OBD_ALLOC(*niduuid, niduuid_len);
	if (!*niduuid)
		return -ENOMEM;

	snprintf(*niduuid, niduuid_len, "%s%s", LUSTRE_MGC_OBDNAME, nidstr);
	return 0;
}

static inline void mgc_niduuid_destroy(char **niduuid)
{
	if (*niduuid) {
		char *tmp = strchr(*niduuid, '_');

		/* If the "_%x" suffix hasn't been added yet then the size
		 * calculation below should still be correct
		 */
		if (tmp)
			*tmp = '\0';

		OBD_FREE(*niduuid, strlen(*niduuid) + NIDUUID_SUFFIX_MAX_LEN);
	}
	*niduuid = NULL;
}

/**
 * Set up a MGC OBD to process startup logs
 *
 * \param sb [in] super block of the MGC OBD
 *
 * \retval 0 success, otherwise error code
 */
int lustre_start_mgc(struct super_block *sb)
{
	struct obd_connect_data *data = NULL;
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *obd;
	struct obd_export *exp;
	struct obd_uuid *uuid = NULL;
	uuid_t uuidc;
	struct lnet_nid nid;
	char nidstr[LNET_NIDSTR_SIZE];
	char *mgcname = NULL, *niduuid = NULL, *mgssec = NULL;
	bool large_nids = false;
	char *ptr, *niduuid_suffix;
	int rc = 0, i = 0, j;
	size_t len;

	ENTRY;

	LASSERT(lsi->lsi_lmd);

	/* Find the first non-lo MGS NID for our MGC name */
	if (IS_SERVER(lsi)) {
		/* mount -o mgsnode=nid */
		ptr = lsi->lsi_lmd->lmd_mgs;
		if (lsi->lsi_lmd->lmd_mgs &&
		    (class_parse_nid(lsi->lsi_lmd->lmd_mgs, &nid, &ptr) == 0)) {
			if (!nid_is_nid4(&nid))
				large_nids = true;
			i++;
		} else if (IS_MGS(lsi)) {
			struct lnet_processid id;

			large_nids = true;
			while ((rc = LNetGetId(i++, &id, true)) != -ENOENT) {
				if (nid_is_lo0(&id.nid))
					continue;
				nid = id.nid;
				i++;
				break;
			}
		}
	} else { /* client */
		/* Use NIDs from mount line: uml1,1@elan:uml2,2@elan:/lustre */
		ptr = lsi->lsi_lmd->lmd_dev;
		if (class_parse_nid(ptr, &nid, &ptr) == 0) {
			if (!nid_is_nid4(&nid))
				large_nids = true;
			i++;
		}
	}
	if (i == 0) {
		CERROR("No valid MGS NIDs found.\n");
		RETURN(-EINVAL);
	}

	mutex_lock(&mgc_start_lock);

	libcfs_nidstr_r(&nid, nidstr, sizeof(nidstr));
	len = strlen(LUSTRE_MGC_OBDNAME) + strlen(nidstr) + 1;
	OBD_ALLOC(mgcname, len);
	rc = mgc_niduuid_create(&niduuid, nidstr);
	if (rc || mgcname == NULL)
		GOTO(out_free, rc = -ENOMEM);

	snprintf(mgcname, len, "%s%s", LUSTRE_MGC_OBDNAME, nidstr);

	mgssec = lsi->lsi_lmd->lmd_mgssec ? lsi->lsi_lmd->lmd_mgssec : "";

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		GOTO(out_free, rc = -ENOMEM);

	obd = class_name2obd(mgcname);
	if (obd && !obd->obd_stopping) {
		int recov_bk;

		rc = obd_set_info_async(NULL, obd->obd_self_export,
					strlen(KEY_MGSSEC), KEY_MGSSEC,
					strlen(mgssec), mgssec, NULL);
		if (rc)
			GOTO(out_free, rc);

		/* Re-using an existing MGC */
		atomic_inc(&obd->u.cli.cl_mgc_refcount);

		/* IR compatibility check, only for clients */
		if (lmd_is_client(lsi->lsi_lmd)) {
			int has_ir;
			int vallen = sizeof(*data);

			rc = obd_get_info(NULL, obd->obd_self_export,
					  strlen(KEY_CONN_DATA), KEY_CONN_DATA,
					  &vallen, data);
			LASSERT(rc == 0);
			has_ir = OCD_HAS_FLAG(data, IMP_RECOV);
			if (has_ir ^ !test_bit(LMD_FLG_NOIR,
					       lsi->lsi_lmd->lmd_flags)) {
				/* LMD_FLG_NOIR is for test purpose only */
				LCONSOLE_WARN(
					      "Mounting client with IR setting not compatible with current MGC. Using MGC setting that is IR %s",
					      has_ir ? "enabled" : "disabled");
				if (has_ir) {
					clear_bit(LMD_FLG_NOIR,
						  lsi->lsi_lmd->lmd_flags);
				} else {
					set_bit(LMD_FLG_NOIR,
						lsi->lsi_lmd->lmd_flags);
				}
			}
		}

		recov_bk = 0;
		/*
		 * If we are restarting the MGS, don't try to keep the MGC's
		 * old connection, or registration will fail.
		 */
		if (IS_MGS(lsi)) {
			CDEBUG(D_MOUNT, "New MGS with live MGC\n");
			recov_bk = 1;
		}

		/*
		 * Try all connections, but only once (again).
		 * We don't want to block another target from starting
		 * (using its local copy of the log), but we do want to connect
		 * if at all possible.
		 */
		recov_bk++;
		CDEBUG(D_MOUNT, "%s:Set MGC reconnect %d\n", mgcname, recov_bk);
		rc = obd_set_info_async(NULL, obd->obd_self_export,
					sizeof(KEY_INIT_RECOV_BACKUP),
					KEY_INIT_RECOV_BACKUP,
					sizeof(recov_bk), &recov_bk, NULL);
		GOTO(out, rc = 0);
	}

	CDEBUG(D_MOUNT, "Start MGC '%s'\n", mgcname);

	/* Add the primary NIDs for the MGS */
	i = 0;
	niduuid_suffix = niduuid + strlen(niduuid);
	snprintf(niduuid_suffix, NIDUUID_SUFFIX_MAX_LEN, "_%x", i);
	if (IS_SERVER(lsi)) {
		ptr = lsi->lsi_lmd->lmd_mgs;
		CDEBUG(D_MOUNT, "mgs NIDs %s.\n", ptr);
		if (IS_MGS(lsi)) {
			/* Use local NIDs (including LO) */
			struct lnet_processid id;

			while ((rc = LNetGetId(i++, &id, true)) != -ENOENT) {
				rc = do_lcfg_nid(mgcname, &id.nid,
						 LCFG_ADD_UUID,
						 niduuid);
			}
		} else {
			/* Use mgsnode= nids */
			/* mount -o mgsnode=nid */
			if (lsi->lsi_lmd->lmd_mgs) {
				ptr = lsi->lsi_lmd->lmd_mgs;
			} else if (class_find_param(ptr, PARAM_MGSNODE,
						    &ptr) != 0) {
				CERROR("No MGS NIDs given.\n");
				GOTO(out_free, rc = -EINVAL);
			}
			/*
			 * Add primary MGS NID(s).
			 * Multiple NIDs on one MGS node are separated
			 * by commas.
			 */
			while (class_parse_nid(ptr, &nid, &ptr) == 0) {
				rc = do_lcfg_nid(mgcname, &nid,
						 LCFG_ADD_UUID,
						 niduuid);
				if (rc == 0)
					++i;
				/* Stop at the first failover NID */
				if (*ptr == ':')
					break;
			}
		}
	} else { /* client */
		/* Use NIDs from mount line: uml1,1@elan:uml2,2@elan:/lustre */
		ptr = lsi->lsi_lmd->lmd_dev;
		while (class_parse_nid(ptr, &nid, &ptr) == 0) {
			rc = do_lcfg_nid(mgcname, &nid, LCFG_ADD_UUID,
					 niduuid);
			if (rc == 0)
				++i;
			/* Stop at the first failover NID */
			if (*ptr == ':')
				break;
		}
	}
	if (i == 0) {
		CERROR("No valid MGS NIDs found.\n");
		GOTO(out_free, rc = -EINVAL);
	}
	lsi->lsi_lmd->lmd_mgs_failnodes = 1;

	/* Random uuid for MGC allows easier reconnects */
	OBD_ALLOC_PTR(uuid);
	if (uuid == NULL)
		GOTO(out_free, rc = -ENOMEM);

	generate_random_uuid(uuidc.b);
	snprintf(uuid->uuid, sizeof(*uuid), "%pU", uuidc.b);

	/* Start the MGC */
	rc = lustre_start_simple(mgcname, LUSTRE_MGC_NAME,
				 (char *)uuid->uuid, LUSTRE_MGS_OBDNAME,
				 niduuid, NULL, NULL);
	if (rc)
		GOTO(out_free, rc);

	/* Add any failover MGS NIDs */
	i = 1;
	while (ptr && ((*ptr == ':' ||
	       class_find_param(ptr, PARAM_MGSNODE, &ptr) == 0))) {
		/* New failover node */
		snprintf(niduuid_suffix, NIDUUID_SUFFIX_MAX_LEN, "_%x", i);
		j = 0;
		while (class_parse_nid_quiet(ptr, &nid, &ptr) == 0) {
			if (!nid_is_nid4(&nid))
				large_nids = true;

			rc = do_lcfg_nid(mgcname, &nid, LCFG_ADD_UUID,
					 niduuid);
			if (rc == 0)
				++j;
			if (*ptr == ':')
				break;
		}
		if (j > 0) {
			rc = do_lcfg(mgcname, 0, LCFG_ADD_CONN,
				     niduuid, NULL, NULL, NULL);
			if (rc == 0)
				++i;
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

	/*
	 * Keep a refcount of servers/clients who started with "mount",
	 * so we know when we can get rid of the mgc.
	 */
	atomic_set(&obd->u.cli.cl_mgc_refcount, 1);

	/* We connect to the MGS at setup, and don't disconnect until cleanup */
	data->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_AT |
				  OBD_CONNECT_FULL20 | OBD_CONNECT_IMP_RECOV |
				  OBD_CONNECT_LVB_TYPE |
				  OBD_CONNECT_BULK_MBITS | OBD_CONNECT_BARRIER |
				  OBD_CONNECT_FLAGS2;
	data->ocd_connect_flags2 = OBD_CONNECT2_REP_MBITS |
				   OBD_CONNECT2_LARGE_NID;

	if (lmd_is_client(lsi->lsi_lmd) &&
	    test_bit(LMD_FLG_NOIR, lsi->lsi_lmd->lmd_flags))
		data->ocd_connect_flags &= ~OBD_CONNECT_IMP_RECOV;
	data->ocd_version = LUSTRE_VERSION_CODE;
	rc = obd_connect(NULL, &exp, obd, uuid, data, NULL);
	if (rc) {
		CERROR("connect failed %d\n", rc);
		GOTO(out, rc);
	}

	/* Having a MGS export setup does not mean we can reach it. When this
	 * is the case check the connect flags which will be zero since we
	 * couldn't reach the MGS. If the mgsnode= contains a large NID we
	 * should enable large NID support so we can mount on servers when
	 * the MGS is down.
	 */
	if (exp_connect_flags(exp) == 0 && large_nids) {
		exp->exp_connect_data.ocd_connect_flags = OBD_CONNECT_FLAGS2;
		exp->exp_connect_data.ocd_connect_flags2 = OBD_CONNECT2_LARGE_NID;
	}
	obd->u.cli.cl_mgc_mgsexp = exp;
out:
	/*
	 * Keep the MGC info in the sb. Note that many lsi's can point
	 * to the same mgc.
	 */
	lsi->lsi_mgc = obd;
out_free:
	mutex_unlock(&mgc_start_lock);

	OBD_FREE_PTR(uuid);
	OBD_FREE_PTR(data);
	OBD_FREE(mgcname, len);
	mgc_niduuid_destroy(&niduuid);

	RETURN(rc);
}
EXPORT_SYMBOL(lustre_start_mgc);

SERVER_ONLY int lustre_stop_mgc(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct obd_device *obd;
	char *niduuid = NULL, *niduuid_suffix;
	char nidstr[LNET_NIDSTR_SIZE];
	int i, rc = 0;

	ENTRY;

	if (!lsi)
		RETURN(-ENOENT);
	obd = lsi->lsi_mgc;
	if (!obd)
		RETURN(-ENOENT);
	lsi->lsi_mgc = NULL;

	/* Reconstruct the NID uuid from the obd_name */
	strscpy(nidstr, &obd->obd_name[0] + strlen(LUSTRE_MGC_OBDNAME),
		sizeof(nidstr));

	rc = mgc_niduuid_create(&niduuid, nidstr);
	if (rc)
		RETURN(-ENOMEM);

	niduuid_suffix = niduuid + strlen(niduuid);

	mutex_lock(&mgc_start_lock);
	LASSERT(atomic_read(&obd->u.cli.cl_mgc_refcount) > 0);
	if (!atomic_dec_and_test(&obd->u.cli.cl_mgc_refcount)) {
		/*
		 * This is not fatal, every client that stops
		 * will call in here.
		 */
		CDEBUG(D_MOUNT, "MGC still has %d references.\n",
		       atomic_read(&obd->u.cli.cl_mgc_refcount));
		GOTO(out, rc = -EBUSY);
	}

	/*
	 * The MGC has no recoverable data in any case.
	 * force shotdown set in umount_begin
	 */
	obd->obd_no_recov = 1;

	if (obd->u.cli.cl_mgc_mgsexp) {
		/*
		 * An error is not fatal, if we are unable to send the
		 * disconnect mgs ping evictor cleans up the export
		 */
		rc = obd_disconnect(obd->u.cli.cl_mgc_mgsexp);
		if (rc)
			CDEBUG(D_MOUNT, "disconnect failed %d\n", rc);
	}

	rc = class_manual_cleanup(obd);
	if (rc)
		GOTO(out, rc);

	for (i = 0; i < lsi->lsi_lmd->lmd_mgs_failnodes; i++) {
		snprintf(niduuid_suffix, NIDUUID_SUFFIX_MAX_LEN, "_%x", i);
		rc = do_lcfg(LUSTRE_MGC_OBDNAME, 0, LCFG_DEL_UUID,
			     niduuid, NULL, NULL, NULL);
		if (rc)
			CERROR("del MDC UUID %s failed: rc = %d\n",
			       niduuid, rc);
	}
out:
	/* class_import_put will get rid of the additional connections */
	mutex_unlock(&mgc_start_lock);

	mgc_niduuid_destroy(&niduuid);

	RETURN(rc);
}
SERVER_ONLY_EXPORT_SYMBOL(lustre_stop_mgc);

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

	s2lsi_nocast(sb) = lsi;
	/* we take 1 extra ref for our setup */
	kref_init(&lsi->lsi_mounts);

	/* Default umount style */
	lsi->lsi_flags = LSI_UMOUNT_FAILOVER;
	INIT_LIST_HEAD(&lsi->lsi_lwp_list);
	mutex_init(&lsi->lsi_lwp_mutex);

	RETURN(lsi);
}
EXPORT_SYMBOL(lustre_init_lsi);

static int lustre_free_lsi(struct lustre_sb_info *lsi)
{
	ENTRY;

	LASSERT(lsi != NULL);
	CDEBUG(D_MOUNT, "Freeing lsi %p\n", lsi);

	/* someone didn't call server_put_mount. */
	LASSERT(kref_read(&lsi->lsi_mounts) == 0);

	llcrypt_sb_free(lsi);
	if (lsi->lsi_lmd != NULL) {
		OBD_FREE(lsi->lsi_lmd->lmd_dev,
			 strlen(lsi->lsi_lmd->lmd_dev) + 1);
		OBD_FREE(lsi->lsi_lmd->lmd_profile,
			 strlen(lsi->lsi_lmd->lmd_profile) + 1);
		OBD_FREE(lsi->lsi_lmd->lmd_fileset,
			 strlen(lsi->lsi_lmd->lmd_fileset) + 1);
		OBD_FREE(lsi->lsi_lmd->lmd_mgssec,
			 strlen(lsi->lsi_lmd->lmd_mgssec) + 1);
		OBD_FREE(lsi->lsi_lmd->lmd_opts,
			 strlen(lsi->lsi_lmd->lmd_opts) + 1);
		if (lsi->lsi_lmd->lmd_exclude_count)
			OBD_FREE(lsi->lsi_lmd->lmd_exclude,
				sizeof(lsi->lsi_lmd->lmd_exclude[0]) *
				lsi->lsi_lmd->lmd_exclude_count);
		OBD_FREE(lsi->lsi_lmd->lmd_mgs,
			 strlen(lsi->lsi_lmd->lmd_mgs) + 1);
		OBD_FREE(lsi->lsi_lmd->lmd_osd_type,
			 strlen(lsi->lsi_lmd->lmd_osd_type) + 1);
		OBD_FREE(lsi->lsi_lmd->lmd_params, 4096);
		OBD_FREE(lsi->lsi_lmd->lmd_nidnet,
			 strlen(lsi->lsi_lmd->lmd_nidnet) + 1);

		OBD_FREE_PTR(lsi->lsi_lmd);
	}

	LASSERT(lsi->lsi_llsbi == NULL);
	OBD_FREE_PTR(lsi);

	RETURN(0);
}

static void lustre_put_lsi_free(struct kref *kref)
{
	struct lustre_sb_info *lsi = container_of(kref, struct lustre_sb_info,
						  lsi_mounts);

	if (IS_SERVER(lsi) && lsi->lsi_osd_exp) {
		lu_device_put(&lsi->lsi_dt_dev->dd_lu_dev);
		lsi->lsi_osd_exp->exp_obd->obd_lvfs_ctxt.dt = NULL;
		lsi->lsi_dt_dev = NULL;
		obd_disconnect(lsi->lsi_osd_exp);
		/* wait till OSD is gone */
		obd_zombie_barrier();
	}
	lustre_free_lsi(lsi);
}

/*
 * The lsi has one reference for every server that is using the disk -
 * e.g. MDT, MGS, and potentially MGC
 */
int lustre_put_lsi(struct super_block *sb)
{
	struct lustre_sb_info *lsi = s2lsi(sb);

	ENTRY;

	LASSERT(lsi != NULL);

	CDEBUG(D_MOUNT, "put %p %d\n", sb, kref_read(&lsi->lsi_mounts));
	if (kref_put(&lsi->lsi_mounts, lustre_put_lsi_free)) {
		s2lsi_nocast(sb) = NULL;
		RETURN(1);
	}
	RETURN(0);
}
EXPORT_SYMBOL(lustre_put_lsi);

/*
 * The goal of this function is to extract the file system name
 * from the OBD name. This can come in two flavors. One is
 * fsname-MDTXXXX or fsname-XXXXXXX were X is a hexadecimal
 * number. In both cases we should return fsname. If it is
 * not a valid OBD name it is assumed to be the file system
 * name itself.
 */
void obdname2fsname(const char *tgt, char *fsname, size_t buflen)
{
	const char *ptr;
	const char *tmp;
	size_t len = 0;

	/*
	 * First we have to see if the @tgt has '-' at all. It is
	 * valid for the user to request something like
	 * lctl set_param -P llite.lustre*.xattr_cache=0
	 */
	ptr = strrchr(tgt, '-');
	if (!ptr) {
		/* No '-' means it could end in '*' */
		ptr = strchr(tgt, '*');
		if (!ptr) {
			/* No '*' either. Assume tgt = fsname */
			len = strlen(tgt);
			goto valid_obd_name;
		}
		len = ptr - tgt;
		goto valid_obd_name;
	}

	/* tgt format fsname-MDT0000-* */
	if ((!strncmp(ptr, "-MDT", 4) ||
	     !strncmp(ptr, "-OST", 4)) &&
	     (isxdigit(ptr[4]) && isxdigit(ptr[5]) &&
	      isxdigit(ptr[6]) && isxdigit(ptr[7]))) {
		len = ptr - tgt;
		goto valid_obd_name;
	}

	/*
	 * tgt_format fsname-cli'dev'-'uuid' except for the llite case
	 * which are named fsname-'uuid'. Examples:
	 *
	 * lustre-clilov-ffff88104db5b800
	 * lustre-ffff88104db5b800  (for llite device)
	 *
	 * The length of the OBD uuid can vary on different platforms.
	 * This test if any invalid characters are in string. Allow
	 * wildcards with '*' character.
	 */
	ptr++;
	if (!strspn(ptr, "0123456789abcdefABCDEF*")) {
		len = 0;
		goto no_fsname;
	}

	/*
	 * Now that we validated the device name lets extract the
	 * file system name. Most of the names in this class will
	 * have '-cli' in its name which needs to be dropped. If
	 * it doesn't have '-cli' then its a llite device which
	 * ptr already points to the start of the uuid string.
	 */
	tmp = strstr(tgt, "-cli");
	if (tmp)
		ptr = tmp;
	else
		ptr--;
	len = ptr - tgt;
valid_obd_name:
	len = min_t(size_t, len, LUSTRE_MAXFSNAME);
	snprintf(fsname, buflen, "%.*s", (int)len, tgt);
no_fsname:
	fsname[len] = '\0';
}
EXPORT_SYMBOL(obdname2fsname);

/**
 * SERVER NAME ***
 * <FSNAME><SEPARATOR><TYPE><INDEX>
 * FSNAME is between 1 and 8 characters (inclusive).
 *	Excluded characters are '/' and ':'
 * SEPARATOR is either ':' or '-'
 * TYPE: "OST", "MDT", etc.
 * INDEX: Hex representation of the index
 */

/**
 * Get the fsname ("lustre") from the server name ("lustre-OST003F").
 * @param [in] svname server name including type and index
 * @param [out] fsname Buffer to copy filesystem name prefix into.
 *  Must have at least 'strlen(fsname) + 1' chars.
 * @param [out] endptr if endptr isn't NULL it is set to end of fsname
 * rc < 0  on error
 */
int server_name2fsname(const char *svname, char *fsname, const char **endptr)
{
	const char *dash;

	dash = svname + strnlen(svname, LUSTRE_MAXFSNAME);
	for (; dash > svname && *dash != '-' && *dash != ':'; dash--)
		;
	if (dash == svname)
		return -EINVAL;

	if (fsname != NULL) {
		strncpy(fsname, svname, dash - svname);
		fsname[dash - svname] = '\0';
	}

	if (endptr != NULL)
		*endptr = dash;

	return 0;
}
EXPORT_SYMBOL(server_name2fsname);

#ifdef HAVE_SERVER_SUPPORT
/**
 * Get service name (svname) from string
 * rc < 0 on error
 * if endptr isn't NULL it is set to end of fsname *
 */
int server_name2svname(const char *label, char *svname, const char **endptr,
		       size_t svsize)
{
	int rc;
	const char *dash;

	/* We use server_name2fsname() just for parsing */
	rc = server_name2fsname(label, NULL, &dash);
	if (rc != 0)
		return rc;

	if (endptr != NULL)
		*endptr = dash;

	rc = strscpy(svname, dash + 1, svsize);
	if (rc < 0)
		return rc;

	return 0;
}
EXPORT_SYMBOL(server_name2svname);
#endif /* HAVE_SERVER_SUPPORT */

#ifdef HAVE_SERVER_SUPPORT
/**
 * check server name is OST.
 **/
int server_name_is_ost(const char *svname)
{
	const char *dash;
	int rc;

	/* We use server_name2fsname() just for parsing */
	rc = server_name2fsname(svname, NULL, &dash);
	if (rc != 0)
		return rc;

	dash++;

	if (strncmp(dash, "OST", 3) == 0)
		return 1;
	return 0;
}
EXPORT_SYMBOL(server_name_is_ost);
#endif /* HAVE_SERVER_SUPPORT */

/**
 * Get the index from the target name MDTXXXX/OSTXXXX
 * rc = server type, or rc < 0  on error
 **/
SERVER_ONLY int target_name2index(const char *tgtname, u32 *idx, const char **endptr)
{
	const char *dash = tgtname;
	int type, len, rc;
	u16 index;

	if (strncmp(dash, "MDT", 3) == 0)
		type = LDD_F_SV_TYPE_MDT;
	else if (strncmp(dash, "OST", 3) == 0)
		type = LDD_F_SV_TYPE_OST;
	else
		return -EINVAL;

	dash += 3;

	if (strncmp(dash, "all", 3) == 0) {
		if (endptr != NULL)
			*endptr = dash + 3;
		return type | LDD_F_SV_ALL;
	}

	len = strspn(dash, "0123456789ABCDEFabcdef");
	if (len > 4)
		return -ERANGE;

	if (strlen(dash) != len) {
		char num[5];

		num[4] = '\0';
		memcpy(num, dash, sizeof(num) - 1);
		rc = kstrtou16(num, 16, &index);
		if (rc < 0)
			return rc;
	} else {
		rc = kstrtou16(dash, 16, &index);
		if (rc < 0)
			return rc;
	}

	if (idx)
		*idx = index;

	if (endptr)
		*endptr = dash  + len;

	return type;
}
SERVER_ONLY_EXPORT_SYMBOL(target_name2index);

/*
 * Get the index from the OBD name.
 * rc = server type, or
 * rc < 0  on error
 * if endptr isn't NULL it is set to end of name
 */
int server_name2index(const char *svname, __u32 *idx, const char **endptr)
{
	const char *dash;
	int rc;

	/* We use server_name2fsname() just for parsing */
	rc = server_name2fsname(svname, NULL, &dash);
	if (rc != 0)
		return rc;

	dash++;
	rc = target_name2index(dash, idx, endptr);
	if (rc < 0)
		return rc;

	/* Account for -mdc after index that is possible when specifying mdt */
	if (endptr != NULL && strncmp(LUSTRE_MDC_NAME, *endptr + 1,
				      sizeof(LUSTRE_MDC_NAME)-1) == 0)
		*endptr += sizeof(LUSTRE_MDC_NAME);

	return rc;
}
EXPORT_SYMBOL(server_name2index);

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
		/*
		 * BUSY just means that there's some other OBD that
		 * needs the mgc.  Let him clean it up.
		 */
		CDEBUG(D_MOUNT, "MGC still in use\n");
	}
	/* Drop a ref to the mounted disk */
	lustre_put_lsi(sb);

	RETURN(rc);
}
EXPORT_SYMBOL(lustre_common_put_super);

static void lmd_print(struct lustre_mount_data *lmd)
{
	int i;

	PRINT_CMD(D_MOUNT, "  mount data:\n");
	if (lmd_is_client(lmd))
		PRINT_CMD(D_MOUNT, "profile: %s\n", lmd->lmd_profile);
	PRINT_CMD(D_MOUNT, "device:  %s\n", lmd->lmd_dev);

	if (lmd->lmd_opts)
		PRINT_CMD(D_MOUNT, "options: %s\n", lmd->lmd_opts);

	if (lmd->lmd_recovery_time_soft)
		PRINT_CMD(D_MOUNT, "recovery time soft: %d\n",
			  lmd->lmd_recovery_time_soft);

	if (lmd->lmd_recovery_time_hard)
		PRINT_CMD(D_MOUNT, "recovery time hard: %d\n",
			  lmd->lmd_recovery_time_hard);

	for (i = 0; i < lmd->lmd_exclude_count; i++) {
		PRINT_CMD(D_MOUNT, "exclude %d:  OST%04x\n", i,
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

	for (i = 0; i < lmd->lmd_exclude_count; i++) {
		if (index == lmd->lmd_exclude[i]) {
			CWARN("Excluding %s (on exclusion list)\n", svname);
			RETURN(1);
		}
	}
	RETURN(0);
}

/* mount -v  -o exclude=lustre-OST0001:lustre-OST0002 -t lustre ... */
static int lmd_make_exclusion(struct lustre_mount_data *lmd, const char *ptr)
{
	const char *s1 = ptr, *s2;
	__u32 *exclude_list;
	__u32 index = 0;
	int rc = 0, devmax;

	ENTRY;

	/*
	 * The shortest an ost name can be is 8 chars: -OST0000.
	 * We don't actually know the fsname at this time, so in fact
	 * a user could specify any fsname.
	 */
	devmax = strlen(ptr) / 8 + 1;

	/* temp storage until we figure out how many we have */
	OBD_ALLOC_PTR_ARRAY(exclude_list, devmax);
	if (!exclude_list)
		RETURN(-ENOMEM);

	/* we enter this fn pointing at the '=' */
	while (*s1 && *s1 != ' ' && *s1 != ',') {
		s1++;
		rc = server_name2index(s1, &index, &s2);
		if (rc < 0) {
			CERROR("Can't parse server name '%s': rc = %d\n",
			       s1, rc);
			break;
		}
		if (rc == LDD_F_SV_TYPE_OST)
			exclude_list[lmd->lmd_exclude_count++] = index;
		else
			CDEBUG(D_MOUNT, "ignoring exclude %.*s: type = %#x\n",
			       (uint)(s2-s1), s1, rc);
		s1 = s2;
		/*
		 * now we are pointing at ':' (next exclude)
		 * or ',' (end of excludes)
		 */
		if (lmd->lmd_exclude_count >= devmax)
			break;
	}
	if (rc >= 0) /* non-err */
		rc = 0;

	if (lmd->lmd_exclude_count) {
		/* permanent, freed in lustre_free_lsi */
		OBD_ALLOC_PTR_ARRAY(lmd->lmd_exclude,
				    lmd->lmd_exclude_count);
		if (lmd->lmd_exclude) {
			memcpy(lmd->lmd_exclude, exclude_list,
			       sizeof(index) * lmd->lmd_exclude_count);
		} else {
			rc = -ENOMEM;
			lmd->lmd_exclude_count = 0;
		}
	}
	OBD_FREE_PTR_ARRAY(exclude_list, devmax);
	RETURN(rc);
}

static int lmd_parse_mgssec(struct lustre_mount_data *lmd, char *ptr)
{
	int length = strlen(ptr);

	if (lmd->lmd_mgssec != NULL) {
		OBD_FREE(lmd->lmd_mgssec, strlen(lmd->lmd_mgssec) + 1);
		lmd->lmd_mgssec = NULL;
	}

	OBD_ALLOC(lmd->lmd_mgssec, length + 1);
	if (lmd->lmd_mgssec == NULL)
		return -ENOMEM;

	memcpy(lmd->lmd_mgssec, ptr, length);
	lmd->lmd_mgssec[length] = '\0';
	return 0;
}

static int lmd_parse_network(struct lustre_mount_data *lmd, char *ptr)
{
	int length = strlen(ptr);

	if (lmd->lmd_nidnet != NULL) {
		OBD_FREE(lmd->lmd_nidnet, strlen(lmd->lmd_nidnet) + 1);
		lmd->lmd_nidnet = NULL;
	}

	OBD_ALLOC(lmd->lmd_nidnet, length + 1);
	if (lmd->lmd_nidnet == NULL)
		return -ENOMEM;

	memcpy(lmd->lmd_nidnet, ptr, length);
	lmd->lmd_nidnet[length] = '\0';
	return 0;
}

static int lmd_parse_string(char **handle, char *ptr)
{
	if (!handle || !ptr)
		return -EINVAL;

	OBD_FREE(*handle, strlen(*handle) + 1);
	*handle = NULL;

	*handle = kstrdup(ptr, GFP_NOFS);
	if (!*handle)
		return -ENOMEM;

	OBD_ALLOC_POST(*handle, strlen(ptr) + 1, "kmalloced");

	return 0;
}

/* Collect multiple values for mgsnid specifiers */
static int lmd_parse_mgs(struct lustre_mount_data *lmd, char *ptr, char **tail)
{
	int length = strlen(ptr);
	struct lnet_nid nid;
	char *next = *tail;
	char *mgsnid;
	int oldlen = 0;

	/* Find end of NID-list */
	while (class_parse_nid_quiet(*tail, &nid, tail) == 0)
		; /* do nothing */

	if (next && next != *tail)
		length += *tail - next + 1;
	if (length == 0) {
		LCONSOLE_ERROR("Can't parse NID '%s'\n", ptr);
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

	if (next && next != *tail)
		snprintf(mgsnid + oldlen, length + 1, "%s,%.*s", ptr,
			 (int)(*tail - next + 1), next);
	else
		snprintf(mgsnid + oldlen, length + 1, "%s", ptr);
	lmd->lmd_mgs = mgsnid;

	return 0;
}

enum lmd_mnt_flags {
	LMD_OPT_RECOVERY_TIME_SOFT	= LMD_FLG_NUM_FLAGS + 1,
	LMD_OPT_RECOVERY_TIME_HARD,
	LMD_OPT_MGSNODE,
	LMD_OPT_MGSSEC,
	LMD_OPT_EXCLUDE,
	LMD_OPT_SVNAME,
	LMD_OPT_PARAM,
	LMD_OPT_OSD,
	LMD_OPT_NETWORK,
	LMD_OPT_DEVICE,
	LMD_NUM_MOUNT_OPT
};

static const match_table_t lmd_flags_table = {
	{LMD_FLG_SKIP_LFSCK,		"skip_lfsck"},
	{LMD_FLG_ABORT_RECOV,		"abort_recov"},
	{LMD_FLG_ABORT_RECOV,		"abort_recovery"},
	{LMD_FLG_NOSVC,			"nosvc"},
	{LMD_FLG_MGS,			"mgs"},
	{LMD_FLG_NOMGS,			"nomgs"},
	{LMD_FLG_WRITECONF,		"writeconf"},
	{LMD_FLG_NOIR,			"noir"},
	{LMD_FLG_NOSCRUB,		"noscrub"},
	{LMD_FLG_NO_PRIMNODE,		"noprimnode"},
	{LMD_FLG_VIRGIN,		"virgin"},
	{LMD_FLG_UPDATE,		"update"},
	{LMD_FLG_DEV_RDONLY,		"rdonly_dev"},
	{LMD_FLG_NO_CREATE,		"no_create"},
	{LMD_FLG_NO_CREATE,		"no_precreate"},
	{LMD_FLG_LOCAL_RECOV,		"localrecov"},
	{LMD_FLG_ABORT_RECOV_MDT,	"abort_recov_mdt"},
	{LMD_FLG_ABORT_RECOV_MDT,	"abort_recovery_mdt"},
	{LMD_FLG_NO_LOCAL_LOGS,		"nolocallogs"},

	{LMD_OPT_RECOVERY_TIME_SOFT,	"recovery_time_soft=%u"},
	{LMD_OPT_RECOVERY_TIME_HARD,	"recovery_time_hard=%u"},
	{LMD_OPT_MGSNODE,		"mgsnode=%s"},
	{LMD_OPT_MGSSEC,		"mgssec=%s"},
	{LMD_OPT_EXCLUDE,		"exclude=%s"},
	{LMD_OPT_SVNAME,		"svname=%s"},
	{LMD_OPT_PARAM,			"param=%s"},
	{LMD_OPT_OSD,			"osd=%s"},
	{LMD_OPT_NETWORK,		"network=%s"},
	{LMD_OPT_DEVICE,		"device=%s"}, /* should be last */
	{LMD_NUM_MOUNT_OPT,		NULL}
};

/**
 * Find the first delimiter; comma; from the specified \a buf and
 * make \a *endh point to the string starting with the delimiter.
 * The character ':' is also a delimiter for Lustre but not match_table
 * so the string is not split on it. Making it safe to ignore.
 *
 * @buf		a delimiter-separated string
 * @endh	a pointer to a pointer that will point to the string
 *		starting with the delimiter
 *
 * Returns:	true if delimiter is found, false if delimiter is not found
 */
static bool lmd_find_delimiter(char *buf, char **endh)
{
	substring_t args[LMD_NUM_MOUNT_OPT];
	char *end, *tmp;
	size_t len;
	int token;

	if (!buf)
		return false;

	/* No more options so we are done */
	end = strchr(buf, ',');
	if (!end)
		return false;

	len = end - buf;
	tmp = kstrndup(buf, len, GFP_KERNEL);
	if (!tmp)
		return false;

	args[0].to = NULL;
	args[0].from = NULL;
	token = match_token(tmp, lmd_flags_table, args);
	kfree(tmp);
	if (token != LMD_NUM_MOUNT_OPT)
		return false;

	if (endh)
		*endh = end;

	return true;
}

/**
 * Make sure the string in \a buf is of a valid formt.
 *
 * @buf		a delimiter-separated string
 *
 * Returns:	true if string valid, false if string contains errors
 */
static bool lmd_validate_param(char *buf)
{
	char *c = buf;
	size_t pos;

	if (!buf)
		return false;
try_again:
	pos = strcspn(c, "[]");
	if (!pos)
		return true;

	c += pos;
	/* Not a valid mount string */
	if (*c == ']') {
		CWARN("invalid mount string format\n");
		return false;
	}

	if (*c == '[') {
		char *right = strchr(c, ']'), *tmp;

		/* invalid mount string */
		if (!right) {
			CWARN("invalid mount string format\n");
			return false;
		}
		c++;

		/* Test for [ .. [ .. ] */
		tmp = strchr(c, '[');
		if (tmp && tmp < right) {
			CWARN("invalid mount string format\n");
			return false;
		}

		/* Test for [ .. @ .. ] which means brackets
		 * span more than one NID string.
		 */
		tmp = strchr(c, '@');
		if (tmp && tmp < right) {
			CWARN("invalid mount string format\n");
			return false;
		}

		c = right++;
		goto try_again;
	}

	return true;
}

/**
 * Find the first valid string delimited by comma or colon from the specified
 * @buf and parse it to see whether it's a valid nid list. If yes, @*endh
 * will point to the next string starting with the delimiter.
 *
 * @buf:	a delimiter-separated string
 *
 * Returns:	false	if the string is a valid nid list
 *              true	if the string is not a valid nid list
 */
static bool lmd_parse_nidlist(char *buf)
{
	LIST_HEAD(nidlist);
	bool invalid;
	char *end;

	if (!buf)
		return true;

	end = strchr(buf, '=');
	if (end)
		buf = end + 1;

	while ((end = strchr(buf, '@')) != NULL) {
		size_t pos = strcspn(end, ":,");
		char c;

		end += pos;
		c = end[0];
		end[0] = '\0';
		/* FIXME !!! Add IPv6 support to cfs_parse_nidlist */
		if (strchr(buf, ':')) {
			struct lnet_nid nid;

			if (libcfs_strnid(&nid, buf) < 0) {
				invalid = true;
				goto failed;
			}
		} else {
			if (cfs_parse_nidlist(buf, &nidlist) < 0) {
				invalid = true;
				goto failed;
			} else {
				cfs_free_nidlist(&nidlist);
			}
		}
		end[0] = c;
		end++;
		buf = end;
	}
	invalid = false;
failed:
	return invalid;
}

/**
 * Parse mount line options
 * e.g. mount -v -t lustre -o abort_recov uml1:uml2:/lustre-client /mnt/lustre
 * dev is passed as device=uml1:/lustre by mount.lustre_tgt
 */
int lmd_parse(char *options, struct lustre_mount_data *lmd)
{
	char *s1, *s2, *opts, *orig_opts, *devname = NULL;
	struct lustre_mount_data *raw = (struct lustre_mount_data *)options;
	int rc = 0;

	ENTRY;
	LASSERT(lmd);
	if (!options) {
		LCONSOLE_ERROR("Missing mount data: check /sbin/mount.lustre_tgt is installed.\n");
		RETURN(-EINVAL);
	}

	/* Options should be a string - try to detect old lmd data */
	if ((raw->lmd_magic & 0xffffff00) == (LMD_MAGIC & 0xffffff00)) {
		LCONSOLE_ERROR("Using an old version of /sbin/mount.lustre. Please install version %s\n",
			       LUSTRE_VERSION_STRING);
		RETURN(-EINVAL);
	}
	lmd->lmd_magic = LMD_MAGIC;

	/* Don't stomp on lmd_opts */
	opts = kstrdup(options, GFP_KERNEL);
	if (!opts)
		RETURN(-ENOMEM);
	orig_opts = opts;
	s1 = opts;

	OBD_ALLOC(lmd->lmd_params, LMD_PARAMS_MAXLEN);
	if (!lmd->lmd_params)
		GOTO(invalid, rc = -ENOMEM);
	lmd->lmd_params[0] = '\0';

	/* Set default flags here */
	while ((s1 = strsep(&opts, ",")) != NULL) {
		int time_min = OBD_RECOVERY_TIME_MIN, tmp;
		substring_t args[LMD_NUM_MOUNT_OPT];
		int token;

		if (!*s1)
			continue;
		/*
		 * Initialize args struct so we know whether arg was
		 * found; some options take optional arguments.
		 */
		args[0].to = NULL;
		args[0].from = NULL;
		token = match_token(s1, lmd_flags_table, args);
		if (token == LMD_NUM_MOUNT_OPT) {
			if (match_wildcard("iam", s1) ||
			    match_wildcard("hsm", s1))
				continue;

			/* Normally we would error but client and
			 * server mounting is intertwine. So pass
			 * off unknown args to ll_options instead.
			 */
			continue;
		} else {
			/* We found a known server option. Filter out
			 * the result out of the options string. The
			 * reset will be stored in lmd_opts.
			 */
			char *tmp = strstr(options, s1);

			if (strcmp(tmp, s1) != 0) {
				s2 = tmp + strlen(s1) + 1;
				memmove(tmp, s2, strlen(s2) + 1);
			} else {
				*tmp = 0;
			}
		}

		/*
		 * Client options are parsed in ll_options: eg. flock,
		 * user_xattr, acl
		 */

		/*
		 * Parse non-ldiskfs options here. Rather than modifying
		 * ldiskfs, we just zero these out here
		 */
		switch (token) {
		case LMD_FLG_ABORT_RECOV_MDT:
		case LMD_FLG_ABORT_RECOV:
		case LMD_FLG_NO_CREATE:
		case LMD_FLG_NOIR: /* test purpose only. */
		case LMD_FLG_NOSVC:
		case LMD_FLG_NOMGS:
		case LMD_FLG_NOSCRUB:
		case LMD_FLG_SKIP_LFSCK:
		case LMD_FLG_DEV_RDONLY:
		case LMD_FLG_WRITECONF:
		case LMD_FLG_NO_LOCAL_LOGS:
		case LMD_FLG_UPDATE:
		case LMD_FLG_VIRGIN:
		case LMD_FLG_NO_PRIMNODE:
		case LMD_FLG_MGS: /* We are an MGS */
		case LMD_FLG_LOCAL_RECOV:
			set_bit(token, lmd->lmd_flags);
			break;
		case LMD_OPT_RECOVERY_TIME_SOFT:
			rc = match_int(args, &tmp);
			if (rc == 0)
				lmd->lmd_recovery_time_soft = max_t(int, tmp,
								    time_min);
			break;
		case LMD_OPT_RECOVERY_TIME_HARD:
			rc = match_int(args, &tmp);
			if (rc == 0)
				lmd->lmd_recovery_time_hard = max_t(int, tmp,
								    time_min);
			break;
		case LMD_OPT_MGSNODE:
			/* Assume the next mount opt is the first
			 * invalid NID we get to.
			 */
			rc = lmd_parse_mgs(lmd, args->from, &opts);
			if (rc < 0)
				GOTO(invalid, rc);

			if (strcmp(options, opts) != 0) {
				s2 = strstr(options, opts);
				if (s2)
					options = s2;
			}
			break;
		case LMD_OPT_MGSSEC:
			rc = lmd_parse_mgssec(lmd, args->from);
			break;
		case LMD_OPT_EXCLUDE:
			/* ost exclusion list */
			rc = lmd_make_exclusion(lmd, args->from);
			break;
		case LMD_OPT_SVNAME:
			rc = lmd_parse_string(&lmd->lmd_profile, args->from);
			break;
		case LMD_OPT_PARAM: {
			size_t length = strlen(args->from), params_length;
			char *tail = NULL, *entry;

			params_length = strlen(lmd->lmd_params);
			if (params_length + length + 1 >= LMD_PARAMS_MAXLEN) {
				rc = -E2BIG;
				goto bad_string;
			}
			entry = lmd->lmd_params + params_length;
			strncat(lmd->lmd_params, args->from, length);

			/* Find end of param string */
			while (lmd_find_delimiter(opts, &tail)) {
				params_length = strlen(lmd->lmd_params);
				/* match_table splits by ',' so fill it in */
				lmd->lmd_params[params_length++] = ',';

				length = tail - opts + 1;
				if (!length)
					break;
				if (params_length + length + 1 >=
				    LMD_PARAMS_MAXLEN) {
					rc = -E2BIG;
					goto bad_string;
				}

				strscpy(lmd->lmd_params + params_length,
					opts, length);
				opts = tail + 1;
			}

			lmd->lmd_params[params_length + length] = '\0';

			if (!lmd_validate_param(entry)) {
				rc = -EINVAL;
				goto bad_string;
			}

			/* param contains NIDs */
			if (strchr(entry, '@') && lmd_parse_nidlist(entry)) {
				rc = -EINVAL;
				goto bad_string;
			}

			/* remove params from opts string from options string */
			if (strlen(args->from) != strlen(entry)) {
				char *tmp = entry + strlen(args->from) + 1;

				s2 = strstr(options, tmp);
				if (s2) {
					size_t len = strlen(s2) - strlen(tmp);

					memmove(s2, s2 + strlen(tmp) + 1, len);
				}
			}

			strlcat(lmd->lmd_params, " ", LMD_PARAMS_MAXLEN);
			if (tail)
				opts = tail + 1;
bad_string:
			break;
		}
		case LMD_OPT_OSD:
			rc = lmd_parse_string(&lmd->lmd_osd_type, args->from);
			break;
		case LMD_OPT_DEVICE: {
			size_t len = 0;

			/* match_table splits strings at ',' so we need to
			 * piece things back together.
			 */
			if (opts) {
				len = strlen(opts) + 1;

				/* Move to last part of device string */
				s2 = strchr(opts, '/');
				if (!s2)
					GOTO(invalid, rc = -EINVAL);

				/* See if more options exist */
				s2 = strchr(s2, ',');
				if (s2)
					len = s2 - opts;
			}
			len += strlen(args->from) + 1;

			/* Freed in lustre_free_lsi */
			OBD_ALLOC(lmd->lmd_dev, len);
			if (!lmd->lmd_dev)
				GOTO(invalid, rc = -ENOMEM);

			if (opts)
				snprintf(lmd->lmd_dev, len, "%s,%s",
					 args->from, opts);
			else
				strscpy(lmd->lmd_dev, args->from, len);

			devname = lmd->lmd_dev;

			/* remove the split string 'opts' from options */
			if (opts) {
				s1 = strstr(options, opts);
				if (s1) {
					/* opts start after args->from so
					 * reduce len.
					 */
					len -= strlen(args->from) + 2;
					s2 = s1 + len;
					memmove(s1, s2, strlen(s2) + 1);
					opts += len;
				}
			}
			break;
		}
		case LMD_OPT_NETWORK:
			rc = lmd_parse_network(lmd, args->from);
			/* check if LNet dynamic peer discovery is activated */
			if (LNetGetPeerDiscoveryStatus()) {
				CERROR("LNet Dynamic Peer Discovery is enabled on this node. 'network' mount option cannot be taken into account.\n");
				rc = -EINVAL;
			}
			break;
		}
	}
	if (rc < 0)
		GOTO(invalid, rc);

	if (!devname) {
		LCONSOLE_ERROR("Can't find device name (need mount option 'device=...')\n");
		GOTO(invalid, rc = -ENODEV);
	}

	s1 = strstr(devname, ":/");
	if (s1) {
		++s1;
		set_bit(LMD_FLG_CLIENT, lmd->lmd_flags);
		/* Remove leading /s from fsname */
		while (*++s1 == '/')
			;
		s2 = s1;
		while (*s2 != '/' && *s2 != '\0')
			s2++;
		/* Freed in lustre_free_lsi */
		OBD_ALLOC(lmd->lmd_profile, s2 - s1 + 8);
		if (!lmd->lmd_profile)
			GOTO(invalid, rc = -ENOMEM);

		strncat(lmd->lmd_profile, s1, s2 - s1);
		strncat(lmd->lmd_profile, "-client", 7);

		s1 = s2;
		s2 = s1 + strlen(s1) - 1;
		/* Remove padding /s from fileset */
		while (*s2 == '/')
			s2--;
		if (s2 > s1) {
			OBD_ALLOC(lmd->lmd_fileset, s2 - s1 + 2);
			if (!lmd->lmd_fileset)
				GOTO(invalid, rc = -ENOMEM);
			strncat(lmd->lmd_fileset, s1, s2 - s1 + 1);
		}
	} else {
		/* server mount */
		if (lmd->lmd_nidnet != NULL) {
			/* 'network=' mount option forbidden for server */
			OBD_FREE(lmd->lmd_nidnet, strlen(lmd->lmd_nidnet) + 1);
			lmd->lmd_nidnet = NULL;
			rc = -EINVAL;
			CERROR("%s: option 'network=' not allowed for Lustre servers: rc = %d\n",
			       devname, rc);
			GOTO(invalid, rc);
		}
	}

	/* Save mount options */
	s1 = options + strlen(options) - 1;
	while (s1 >= options && (*s1 == ',' || *s1 == ' '))
		*s1-- = 0;
	while (*options && (*options == ',' || *options == ' '))
		options++;
	if (*options != 0) {
		/* Freed in lustre_free_lsi */
		OBD_ALLOC(lmd->lmd_opts, strlen(options) + 1);
		if (!lmd->lmd_opts)
			GOTO(invalid, rc = -ENOMEM);
		strncpy(lmd->lmd_opts, options, strlen(options));
	}

	lmd_print(lmd);
invalid:
	if (rc < 0)
		CERROR("Bad mount options %s\n", options);
	kfree(orig_opts);

	RETURN(rc);
}
EXPORT_SYMBOL(lmd_parse);
