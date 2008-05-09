/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
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
        struct obd_device* obd = (struct obd_device *)data;

        LASSERT(obd != NULL);
        LASSERT(obd->u.mgs.mgs_vfsmnt->mnt_devname);
        *eof = 1;

        return snprintf(page, count, "%s\n",obd->u.mgs.mgs_vfsmnt->mnt_devname);
}

static int mgs_fs_seq_show(struct seq_file *seq, void *v)
{
        struct obd_device *obd = seq->private;
        struct mgs_obd *mgs = &obd->u.mgs;
        struct list_head dentry_list;
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
        list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                list_del(&dirent->lld_list);
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

int lproc_mgs_setup(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        int rc;

        rc = lprocfs_obd_seq_create(obd, "filesystems", 0444,
                                    &mgs_fs_fops, obd);

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
                RETURN(-EINVAL);

        mgs = &obd->u.mgs;
        if (mgs->mgs_proc_live) {
                /* Should be no live entries */
                LASSERT(mgs->mgs_proc_live->subdir == NULL);
                lprocfs_remove(&mgs->mgs_proc_live);
                mgs->mgs_proc_live = NULL;
        }
        lprocfs_free_obd_stats(obd);

        return lprocfs_obd_cleanup(obd);
}

static void seq_show_srpc_rule(struct seq_file *seq, const char *tgtname,
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

static int mgs_live_seq_show(struct seq_file *seq, void *v) 
{
        struct fs_db             *fsdb = seq->private;
        struct mgs_tgt_srpc_conf *srpc_tgt;
        int i;
        
        down(&fsdb->fsdb_sem);

        seq_printf(seq, "fsname: %s\n", fsdb->fsdb_name);
        seq_printf(seq, "flags: %#x     gen: %d\n", 
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
                seq_show_srpc_rule(seq, srpc_tgt->mtsc_tgt,
                                   &srpc_tgt->mtsc_rset);
        }
        seq_show_srpc_rule(seq, fsdb->fsdb_name, &fsdb->fsdb_srpc_gen);

        up(&fsdb->fsdb_sem);
        return 0;
}

LPROC_SEQ_FOPS_RO(mgs_live);

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
        { "evict_client",    0, lprocfs_wr_evict_client, 0 },
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
