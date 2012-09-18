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
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <asm/statfs.h>
#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_param.h>
#include "mgs_internal.h"

#ifdef LPROCFS

static int lprocfs_mgs_rd_mntdev(char *page, char **start, off_t off, int count,
                                 int *eof, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;

	LASSERT(obd != NULL);
	LASSERT(mnt_get_devname(obd->u.mgs.mgs_vfsmnt));
	*eof = 1;

	return snprintf(page, count, "%s\n",
			mnt_get_devname(obd->u.mgs.mgs_vfsmnt));
}

static int mgs_fs_seq_show(struct seq_file *seq, void *v)
{
        struct obd_device *obd = seq->private;
        struct mgs_obd *mgs = &obd->u.mgs;
        cfs_list_t dentry_list;
        struct l_linux_dirent *dirent, *n;
        int rc, len;
        ENTRY;

        LASSERT(obd != NULL);
        rc = class_dentry_readdir(obd, mgs->mgs_configs_dir,
                                  mgs->mgs_vfsmnt, &dentry_list);
        if (rc) {
                CERROR("Can't read config dir\n");
                RETURN(rc);
        }
        cfs_list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                cfs_list_del(&dirent->lld_list);
                len = strlen(dirent->lld_name);
                if ((len > 7) && (strncmp(dirent->lld_name + len - 7, "-client",
                                          len) == 0)) {
                        seq_printf(seq, "%.*s\n", len - 7, dirent->lld_name);
                }
                OBD_FREE(dirent, sizeof(*dirent));
        }

        RETURN(0);
}

LPROC_SEQ_FOPS_RO(mgs_fs);

static void seq_show_srpc_rules(struct seq_file *seq, const char *tgtname,
                                struct sptlrpc_rule_set *rset)
{
        struct sptlrpc_rule    *r;
        char                    dirbuf[10];
        char                    flvrbuf[40];
        char                   *net;
        int                     i;

        for (i = 0; i < rset->srs_nrule; i++) {
                r = &rset->srs_rules[i];

                if (r->sr_netid == LNET_NIDNET(LNET_NID_ANY))
                        net = "default";
                else
                        net = libcfs_net2str(r->sr_netid);

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
        struct obd_device *obd = seq->private;
        struct fs_db      *fsdb;
        int                rc;

        rc = mgs_find_or_make_fsdb(obd, MGSSELF_NAME, &fsdb);
        if (rc)
                return rc;

        cfs_mutex_lock(&fsdb->fsdb_mutex);
        seq_show_srpc_rules(seq, fsdb->fsdb_name, &fsdb->fsdb_srpc_gen);
        cfs_mutex_unlock(&fsdb->fsdb_mutex);
        return 0;
}

LPROC_SEQ_FOPS_RO(mgsself_srpc);

int lproc_mgs_setup(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        int rc;

        rc = lprocfs_obd_seq_create(obd, "filesystems", 0444,
                                    &mgs_fs_fops, obd);
        rc = lprocfs_obd_seq_create(obd, "srpc_rules", 0600,
                                    &mgsself_srpc_fops, obd);

        mgs->mgs_proc_live = lprocfs_register("live", obd->obd_proc_entry,
                                              NULL, NULL);
        if (IS_ERR(mgs->mgs_proc_live)) {
                rc = PTR_ERR(mgs->mgs_proc_live);
                CERROR("error %d setting up lprocfs for %s\n", rc, "live");
                mgs->mgs_proc_live = NULL;
        }

        obd->obd_proc_exports_entry = lprocfs_register("exports",
                                                       obd->obd_proc_entry,
                                                       NULL, NULL);
        if (IS_ERR(obd->obd_proc_exports_entry)) {
                rc = PTR_ERR(obd->obd_proc_exports_entry);
                CERROR("error %d setting up lprocfs for %s\n", rc, "exports");
                obd->obd_proc_exports_entry = NULL;
        }

        return rc;
}

int lproc_mgs_cleanup(struct obd_device *obd)
{
        struct mgs_obd *mgs;

        if (!obd)
                return -EINVAL;

        mgs = &obd->u.mgs;
        if (mgs->mgs_proc_live) {
                /* Should be no live entries */
                LASSERT(mgs->mgs_proc_live->subdir == NULL);
                lprocfs_remove(&mgs->mgs_proc_live);
                mgs->mgs_proc_live = NULL;
        }
        lprocfs_free_per_client_stats(obd);
        lprocfs_free_obd_stats(obd);
        lprocfs_free_md_stats(obd);

        return lprocfs_obd_cleanup(obd);
}

static int mgs_live_seq_show(struct seq_file *seq, void *v)
{
        struct fs_db             *fsdb = seq->private;
        struct mgs_tgt_srpc_conf *srpc_tgt;
        int i;

        cfs_mutex_lock(&fsdb->fsdb_mutex);

        seq_printf(seq, "fsname: %s\n", fsdb->fsdb_name);
        seq_printf(seq, "flags: %#lx     gen: %d\n",
                   fsdb->fsdb_flags, fsdb->fsdb_gen);
        for (i = 0; i < INDEX_MAP_SIZE * 8; i++)
                 if (cfs_test_bit(i, fsdb->fsdb_mdt_index_map))
                         seq_printf(seq, "%s-MDT%04x\n", fsdb->fsdb_name, i);
        for (i = 0; i < INDEX_MAP_SIZE * 8; i++)
                 if (cfs_test_bit(i, fsdb->fsdb_ost_index_map))
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

        cfs_mutex_unlock(&fsdb->fsdb_mutex);
        return 0;
}

static ssize_t mgs_live_seq_write(struct file *file, const char *buf,
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

int lproc_mgs_add_live(struct obd_device *obd, struct fs_db *fsdb)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        int rc;

        if (!mgs->mgs_proc_live)
                return 0;
        rc = lprocfs_seq_create(mgs->mgs_proc_live, fsdb->fsdb_name, 0444,
                                &mgs_live_fops, fsdb);

        return 0;
}

int lproc_mgs_del_live(struct obd_device *obd, struct fs_db *fsdb)
{
        struct mgs_obd *mgs = &obd->u.mgs;

        if (!mgs->mgs_proc_live)
                return 0;

        lprocfs_remove_proc_entry(fsdb->fsdb_name, mgs->mgs_proc_live);
        return 0;
}

struct lprocfs_vars lprocfs_mgs_obd_vars[] = {
        { "uuid",            lprocfs_rd_uuid,        0, 0 },
        { "fstype",          lprocfs_rd_fstype,      0, 0 },
        { "mntdev",          lprocfs_mgs_rd_mntdev,  0, 0 },
        { "num_exports",     lprocfs_rd_num_exports, 0, 0 },
        { "hash_stats",      lprocfs_obd_rd_hash,    0, 0 },
        { "evict_client",    0, lprocfs_wr_evict_client, 0 },
        { "ir_timeout",      lprocfs_rd_ir_timeout, lprocfs_wr_ir_timeout, 0 },
        { 0 }
};

struct lprocfs_vars lprocfs_mgs_module_vars[] = {
        { 0 }
};

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

void lprocfs_mgs_init_vars(struct lprocfs_static_vars *lvars)
{
    lvars->module_vars  = lprocfs_mgs_module_vars;
    lvars->obd_vars     = lprocfs_mgs_obd_vars;
}
#endif
