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
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <asm/statfs.h>
#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <uapi/linux/lustre/lustre_param.h>
#include "mgs_internal.h"

#ifdef CONFIG_PROC_FS

static int mgs_fs_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device	*obd = seq->private;
	struct mgs_device	*mgs;
	struct list_head	 list;
	struct mgs_direntry	*dirent, *n;
	struct lu_env		 env;
	int rc, len;

	ENTRY;

	LASSERT(obd != NULL);
	LASSERT(obd->obd_lu_dev != NULL);
	mgs = lu2mgs_dev(obd->obd_lu_dev);

	rc = lu_env_init(&env, LCT_MG_THREAD);
	if (rc)
		RETURN(rc);

	rc = class_dentry_readdir(&env, mgs, &list);
	if (rc)
		GOTO(out, rc);

	list_for_each_entry_safe(dirent, n, &list, mde_list) {
		list_del_init(&dirent->mde_list);
		len = strlen(dirent->mde_name);
		if (len > 7 &&
		    strncmp(dirent->mde_name + len - 7, "-client", len) == 0)
			seq_printf(seq, "%.*s\n", len - 7, dirent->mde_name);
		mgs_direntry_free(dirent);
	}

out:
	lu_env_fini(&env);
	RETURN(0);
}

LDEBUGFS_SEQ_FOPS_RO(mgs_fs);

static void seq_show_srpc_rules(struct seq_file *seq, const char *tgtname,
				struct sptlrpc_rule_set *rset)
{
	struct sptlrpc_rule *r;
	char dirbuf[10];
	char flvrbuf[40];
	char net_buf[LNET_NIDSTR_SIZE];
	const char *net;
	int i;

	for (i = 0; i < rset->srs_nrule; i++) {
		r = &rset->srs_rules[i];

		if (r->sr_netid == LNET_NET_ANY)
			net = "default";
		else
			net = libcfs_net2str_r(r->sr_netid, net_buf,
					       sizeof(net_buf));

                if (r->sr_from == LUSTRE_SP_ANY && r->sr_to == LUSTRE_SP_ANY)
                        dirbuf[0] = '\0';
                else
                        snprintf(dirbuf, sizeof(dirbuf), ".%s2%s",
                                 sptlrpc_part2name(r->sr_from),
                                 sptlrpc_part2name(r->sr_to));

                sptlrpc_flavor2name(&r->sr_flvr, flvrbuf, sizeof(flvrbuf));
                seq_printf(seq, "%s.srpc.flavor.%s%s=%s\n", tgtname,
                           net, dirbuf, flvrbuf);
        }
}

static int mgsself_srpc_seq_show(struct seq_file *seq, void *v)
{
	struct obd_device	*obd = seq->private;
	struct mgs_device	*mgs = lu2mgs_dev(obd->obd_lu_dev);
	struct lu_target	*tgt = &mgs->mgs_lut;

	read_lock(&tgt->lut_sptlrpc_lock);
	seq_show_srpc_rules(seq, MGSSELF_NAME, &tgt->lut_sptlrpc_rset);
	read_unlock(&tgt->lut_sptlrpc_lock);

        return 0;
}
LDEBUGFS_SEQ_FOPS_RO(mgsself_srpc);

static int mgs_live_seq_show(struct seq_file *seq, void *v)
{
	struct fs_db             *fsdb = seq->private;
	struct mgs_tgt_srpc_conf *srpc_tgt;
	int i;

	mutex_lock(&fsdb->fsdb_mutex);

	seq_printf(seq, "fsname: %s\n", fsdb->fsdb_name);
	seq_printf(seq, "flags: %#lx     gen: %d\n",
		   fsdb->fsdb_flags, fsdb->fsdb_gen);
	for (i = 0; i < INDEX_MAP_SIZE * 8; i++)
		if (test_bit(i, fsdb->fsdb_mdt_index_map))
			 seq_printf(seq, "%s-MDT%04x\n", fsdb->fsdb_name, i);
	for (i = 0; i < INDEX_MAP_SIZE * 8; i++)
		if (test_bit(i, fsdb->fsdb_ost_index_map))
			 seq_printf(seq, "%s-OST%04x\n", fsdb->fsdb_name, i);

	seq_printf(seq, "\nSecure RPC Config Rules:\n");
#if 0
	seq_printf(seq, "%s.%s=%s\n", fsdb->fsdb_name,
		   PARAM_SRPC_UDESC, fsdb->fsdb_srpc_fl_udesc ? "yes" : "no");
#endif
	for (srpc_tgt = fsdb->fsdb_srpc_tgt; srpc_tgt;
	     srpc_tgt = srpc_tgt->mtsc_next) {
		seq_show_srpc_rules(seq, srpc_tgt->mtsc_tgt,
				    &srpc_tgt->mtsc_rset);
	}
	seq_show_srpc_rules(seq, fsdb->fsdb_name, &fsdb->fsdb_srpc_gen);

	lprocfs_rd_ir_state(seq, fsdb);

	mutex_unlock(&fsdb->fsdb_mutex);
	return 0;
}

static ssize_t mgs_live_seq_write(struct file *file, const char __user *buf,
				  size_t len, loff_t *off)
{
	struct seq_file *seq  = file->private_data;
	struct fs_db    *fsdb = seq->private;
	ssize_t rc;

	rc = lprocfs_wr_ir_state(file, buf, len, fsdb);
	if (rc >= 0)
		rc = len;
	return rc;
}
LPROC_SEQ_FOPS(mgs_live);

int lproc_mgs_add_live(struct mgs_device *mgs, struct fs_db *fsdb)
{
	int rc;

	if (!mgs->mgs_proc_live || fsdb->fsdb_has_lproc_entry)
		return 0;

	rc = lprocfs_seq_create(mgs->mgs_proc_live, fsdb->fsdb_name, 0644,
				&mgs_live_fops, fsdb);
	if (!rc)
		fsdb->fsdb_has_lproc_entry = 1;

	return rc;
}

int lproc_mgs_del_live(struct mgs_device *mgs, struct fs_db *fsdb)
{
	if (!mgs->mgs_proc_live || !fsdb->fsdb_has_lproc_entry)
		return 0;

	/* didn't create the proc file for MGSSELF_NAME */
	if (!test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags))
		lprocfs_remove_proc_entry(fsdb->fsdb_name, mgs->mgs_proc_live);
	return 0;
}

LPROC_SEQ_FOPS_RO_TYPE(mgs, hash);
LPROC_SEQ_FOPS_WR_ONLY(mgs, evict_client);
LPROC_SEQ_FOPS_RW_TYPE(mgs, ir_timeout);

static struct lprocfs_vars lprocfs_mgs_obd_vars[] = {
	{ .name	=	"hash_stats",
	  .fops	=	&mgs_hash_fops		},
	{ .name	=	"evict_client",
	  .fops	=	&mgs_evict_client_fops	},
	{ .name	=	"ir_timeout",
	  .fops	=	&mgs_ir_timeout_fops	},
	{ NULL }
};

LUSTRE_RO_ATTR(num_exports);

static ssize_t fstype_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mgs_device *mgs = lu2mgs_dev(obd->obd_lu_dev);
	struct kobject *osd_kobj;

	if (!mgs || !mgs->mgs_fstype || !mgs->mgs_bottom)
		return -ENODEV;

	osd_kobj = &mgs->mgs_bottom->dd_kobj;
	return lustre_attr_show(osd_kobj, mgs->mgs_fstype, buf);
}
LUSTRE_RO_ATTR(fstype);

static ssize_t mntdev_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mgs_device *mgs = lu2mgs_dev(obd->obd_lu_dev);
	struct kobject *osd_kobj;

	if (!mgs || !mgs->mgs_mntdev || !mgs->mgs_bottom)
		return -ENODEV;

	osd_kobj = &mgs->mgs_bottom->dd_kobj;
	return lustre_attr_show(osd_kobj, mgs->mgs_mntdev, buf);
}
LUSTRE_RO_ATTR(mntdev);

static struct attribute *mgs_attrs[] = {
	&lustre_attr_fstype.attr,
	&lustre_attr_mntdev.attr,
	&lustre_attr_num_exports.attr,
	NULL,
};

int lproc_mgs_setup(struct mgs_device *mgs, const char *osd_name)
{
	int osd_len = strlen(osd_name) - strlen("-osd");
	struct obd_device *obd = mgs->mgs_obd;
	struct kobj_type *bottom_type;
	struct obd_device *osd_obd;
	int rc;
	int i;

	obd->obd_vars = lprocfs_mgs_obd_vars;
	obd->obd_ktype.default_attrs = mgs_attrs;
	rc = lprocfs_obd_setup(obd, true);
	if (rc != 0)
		GOTO(out, rc);

	debugfs_create_file("filesystems", 0444, obd->obd_debugfs_entry, obd,
			    &mgs_fs_fops);

	debugfs_create_file("srpc_rules", 0400, obd->obd_debugfs_entry, obd,
			    &mgsself_srpc_fops);

	mgs->mgs_proc_live = lprocfs_register("live", obd->obd_proc_entry,
					      NULL, NULL);
        if (IS_ERR(mgs->mgs_proc_live)) {
                rc = PTR_ERR(mgs->mgs_proc_live);
                mgs->mgs_proc_live = NULL;
		GOTO(out, rc);
        }

	obd->obd_proc_exports_entry = lprocfs_register("exports",
						       obd->obd_proc_entry,
						       NULL, NULL);
        if (IS_ERR(obd->obd_proc_exports_entry)) {
                rc = PTR_ERR(obd->obd_proc_exports_entry);
                obd->obd_proc_exports_entry = NULL;
		GOTO(out, rc);
        }

	rc = sysfs_create_link(&obd->obd_kset.kobj, &mgs->mgs_bottom->dd_kobj,
			       "osd");
	if (rc) {
		CWARN("%s: failed to create symlink osd -> %s, rc = %d\n",
		      kobject_name(&obd->obd_kset.kobj),
		      kobject_name(&mgs->mgs_bottom->dd_kobj), rc);
		rc = 0;
	}

	bottom_type = get_ktype(&mgs->mgs_bottom->dd_kobj);

	for (i = 0; bottom_type->default_attrs[i]; i++) {
		if (strcmp(bottom_type->default_attrs[i]->name, "fstype") == 0) {
			mgs->mgs_fstype = bottom_type->default_attrs[i];
			break;
		}
	}

	for (i = 0; bottom_type->default_attrs[i]; i++) {
		if (strcmp(bottom_type->default_attrs[i]->name, "mntdev") == 0) {
			mgs->mgs_mntdev = bottom_type->default_attrs[i];
			break;
		}
	}

	osd_obd = mgs->mgs_bottom->dd_lu_dev.ld_obd;
	mgs->mgs_proc_osd = lprocfs_add_symlink("osd",
						obd->obd_proc_entry,
						"../../%s/%.*s",
						osd_obd->obd_type->typ_name,
						osd_len, /* Strip "-osd". */
						osd_name);
	if (mgs->mgs_proc_osd == NULL)
		rc = -ENOMEM;
out:
	if (rc != 0)
		lproc_mgs_cleanup(mgs);

	return rc;
}

void lproc_mgs_cleanup(struct mgs_device *mgs)
{
	struct obd_device *obd = mgs->mgs_obd;

	if (obd == NULL)
		return;

	if (mgs->mgs_proc_osd != NULL)
		lprocfs_remove(&mgs->mgs_proc_osd);

	sysfs_remove_link(&obd->obd_kset.kobj, "osd");

	if (mgs->mgs_proc_live != NULL) {
		/* Should be no live entries */
		lprocfs_remove(&mgs->mgs_proc_live);
		mgs->mgs_proc_live = NULL;
	}

        lprocfs_free_per_client_stats(obd);
	lprocfs_obd_cleanup(obd);
        lprocfs_free_obd_stats(obd);
        lprocfs_free_md_stats(obd);
}

void mgs_counter_incr(struct obd_export *exp, int opcode)
{
        lprocfs_counter_incr(exp->exp_obd->obd_stats, opcode);
        if (exp->exp_nid_stats && exp->exp_nid_stats->nid_stats != NULL)
                lprocfs_counter_incr(exp->exp_nid_stats->nid_stats, opcode);
}

void mgs_stats_counter_init(struct lprocfs_stats *stats)
{
        lprocfs_counter_init(stats, LPROC_MGS_CONNECT, 0, "connect", "reqs");
        lprocfs_counter_init(stats, LPROC_MGS_DISCONNECT, 0, "disconnect",
                             "reqs");
        lprocfs_counter_init(stats, LPROC_MGS_EXCEPTION, 0, "exception",
                             "reqs");
        lprocfs_counter_init(stats, LPROC_MGS_TARGET_REG, 0, "tgtreg", "reqs");
        lprocfs_counter_init(stats, LPROC_MGS_TARGET_DEL, 0, "tgtdel", "reqs");
}
#endif
