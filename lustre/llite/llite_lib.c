/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/seq_file.h>

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_dlm.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_acl.h>
#include <linux/lustre_sec.h>
#include "llite_internal.h"

kmem_cache_t *ll_file_data_slab;
kmem_cache_t *ll_intent_slab;

extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;

#ifndef log2
#define log2(n) ffz(~(n))
#endif

struct ll_sb_info *lustre_init_sbi(struct super_block *sb)
{
        struct ll_sb_info *sbi = NULL;
        class_uuid_t uuid;
        ENTRY;

        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi)
                RETURN(NULL);

        spin_lock_init(&sbi->ll_lock);
        INIT_LIST_HEAD(&sbi->ll_pglist);
        sbi->ll_pglist_gen = 0;
        if (num_physpages < SBI_DEFAULT_RA_MAX / 4)
                sbi->ll_ra_info.ra_max_pages = num_physpages / 4;
        else
                sbi->ll_ra_info.ra_max_pages = SBI_DEFAULT_RA_MAX;
        INIT_LIST_HEAD(&sbi->ll_conn_chain);
        INIT_HLIST_HEAD(&sbi->ll_orphan_dentry_list);
        INIT_LIST_HEAD(&sbi->ll_mnt_list);
	
        sema_init(&sbi->ll_gns_sem, 1);
        spin_lock_init(&sbi->ll_gns_lock);
        INIT_LIST_HEAD(&sbi->ll_gns_sbi_head);
        init_waitqueue_head(&sbi->ll_gns_waitq);
        init_completion(&sbi->ll_gns_mount_finished);

        /* this later may be reset via /proc/fs/... */
        memcpy(sbi->ll_gns_oname, ".mntinfo", strlen(".mntinfo"));
        sbi->ll_gns_oname[strlen(sbi->ll_gns_oname)] = '\0';
        
        /* this later may be reset via /proc/fs/... */
        memcpy(sbi->ll_gns_upcall, "/usr/sbin/gns_upcall",
               strlen("/usr/sbin/gns_upcall"));
        sbi->ll_gns_upcall[strlen(sbi->ll_gns_upcall)] = '\0';

        /* default values, may be changed via /proc/fs/... */
        sbi->ll_gns_state = LL_GNS_IDLE;
	sbi->ll_gns_pending_dentry = NULL;
        atomic_set(&sbi->ll_gns_enabled, 1);
        sbi->ll_gns_tick = GNS_TICK_TIMEOUT;
        sbi->ll_gns_timeout = GNS_MOUNT_TIMEOUT;

        sbi->ll_gns_timer.data = (unsigned long)sbi;
        sbi->ll_gns_timer.function = ll_gns_timer_callback;
        init_timer(&sbi->ll_gns_timer);

        ll_set_sbi(sb, sbi);

        generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &sbi->ll_sb_uuid);
        RETURN(sbi);
}

void lustre_free_sbi(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        ENTRY;

        if (sbi != NULL) {
                list_del(&sbi->ll_gns_sbi_head);
                del_timer(&sbi->ll_gns_timer);
                OBD_FREE(sbi, sizeof(*sbi));
        }
        ll_set_sbi(sb, NULL);
        EXIT;
}

int lustre_init_dt_desc(struct ll_sb_info *sbi)
{
        __u32 valsize;
        int rc = 0;
        ENTRY;
        
        valsize = sizeof(sbi->ll_dt_desc);
        memset(&sbi->ll_dt_desc, 0, sizeof(sbi->ll_dt_desc));
        rc = obd_get_info(sbi->ll_dt_exp, strlen("lovdesc") + 1,
                          "lovdesc", &valsize, &sbi->ll_dt_desc);
        RETURN(rc);
}

extern struct dentry_operations ll_d_ops;

int lustre_common_fill_super(struct super_block *sb, char *lmv, char *lov,
                             int async,  char *mds_security,  char *oss_security,
                             __u32 *nllu, int pag, __u64 *remote)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct ptlrpc_request *request = NULL;
        struct lustre_handle dt_conn = {0, };
        struct lustre_handle md_conn = {0, };
        struct obd_connect_data *data;
        struct inode *root = NULL;
        struct obd_device *obd;
        struct obd_statfs osfs;
        struct lustre_md md;
        unsigned long sec_flags;
        __u32 valsize;
        int err;
        ENTRY;

        obd = class_name2obd(lmv);
        if (!obd) {
                CERROR("MDC %s: not setup or attached\n", lmv);
                RETURN(-EINVAL);
        }
        obd_set_info(obd->obd_self_export, strlen("async"), "async",
                     sizeof(async), &async);

        if ((*remote & (OBD_CONNECT_LOCAL | OBD_CONNECT_REMOTE)) ==
            (OBD_CONNECT_LOCAL | OBD_CONNECT_REMOTE)) {
                CERROR("wrong remote flag "LPX64"\n", *remote);
                RETURN(-EINVAL);
        }

        OBD_ALLOC(data, sizeof(*data));
        if (!data)
                RETURN(-ENOMEM);

        data->ocd_connect_flags |= *remote & (OBD_CONNECT_LOCAL |
                                              OBD_CONNECT_REMOTE);
        memcpy(data->ocd_nllu, nllu, sizeof(data->ocd_nllu));

        if (mds_security == NULL)
                mds_security = "null";

        err = obd_set_info(obd->obd_self_export, strlen("sec"), "sec",
                           strlen(mds_security), mds_security);
        if (err) {
                CERROR("LMV %s: failed to set security %s, err %d\n",
                        lmv, mds_security, err);
                OBD_FREE(data, sizeof(*data));
                RETURN(err);
        }

        if (pag) {
                sec_flags = PTLRPC_SEC_FL_PAG;
                err = obd_set_info(obd->obd_self_export,
                                   strlen("sec_flags"), "sec_flags",
                                   sizeof(sec_flags), &sec_flags);
                if (err) {
                        OBD_FREE(data, sizeof(*data));
                        RETURN(err);
                }
        }

        if (proc_lustre_fs_root) {
                err = lprocfs_register_mountpoint(proc_lustre_fs_root,
                                                  sb, lov, lmv);
                if (err < 0)
                        CERROR("could not register mount in /proc/lustre");
        }

        err = obd_connect(&md_conn, obd, &sbi->ll_sb_uuid, data,
                          OBD_OPT_REAL_CLIENT);
        if (err == -EBUSY) {
                CERROR("An MDS (lmv %s) is performing recovery, of which this"
                       " client is not a part.  Please wait for recovery to "
                       "complete, abort, or time out.\n", lmv);
                GOTO(out, err);
        } else if (err) {
                CERROR("cannot connect to %s: rc = %d\n", lmv, err);
                GOTO(out, err);
        }
        sbi->ll_md_exp = class_conn2export(&md_conn);
        err = obd_statfs(obd, &osfs, jiffies - HZ);
        if (err)
                GOTO(out_lmv, err);

        if (!osfs.os_bsize) {
                CERROR("Invalid block size is detected.");
                GOTO(out_lmv, err);
        }

        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_blocksize = osfs.os_bsize;
        sb->s_blocksize_bits = log2(osfs.os_bsize);
        sb->s_maxbytes = PAGE_CACHE_MAXBYTES;

        /* in 2.6.x FS is not allowed to form s_dev */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        {
                kdev_t devno;
                
                devno = get_uuid2int((char *)sbi->ll_md_exp->exp_obd->obd_uuid.uuid, 
                                     strlen((char *)sbi->ll_md_exp->exp_obd->obd_uuid.uuid));
                
                sb->s_dev = devno;
        }
#endif

        /* after statfs, we are supposed to have connected to MDSs,
         * so it's ok to check remote flag returned.
         */
        valsize = sizeof(&sbi->ll_remote);
        err = obd_get_info(sbi->ll_md_exp, strlen("remote_flag"), "remote_flag",
                           &valsize, &sbi->ll_remote);
        if (err) {
                CERROR("fail to obtain remote flag\n");
                GOTO(out, err);
        }

        obd = class_name2obd(lov);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", lov);
                GOTO(out_lmv, err);
        }
        obd_set_info(obd->obd_self_export, strlen("async"), "async",
                     sizeof(async), &async);

       if (oss_security == NULL)
                oss_security = "null";

        err = obd_set_info(obd->obd_self_export, strlen("sec"), "sec",
                           strlen(oss_security), oss_security);
        if (err) {
                CERROR("LOV %s: failed to set security %s, err %d\n",
                        lov, oss_security, err);
                OBD_FREE(data, sizeof(*data));
                RETURN(err);
        }

        if (pag) {
                sec_flags = PTLRPC_SEC_FL_PAG;
                err = obd_set_info(obd->obd_self_export,
                                   strlen("sec_flags"), "sec_flags",
                                   sizeof(sec_flags), &sec_flags);
                if (err) {
                        OBD_FREE(data, sizeof(*data));
                        RETURN(err);
                }
        }

        err = obd_connect(&dt_conn, obd, &sbi->ll_sb_uuid, data, 0);
        if (err == -EBUSY) {
                CERROR("An OST (lov %s) is performing recovery, of which this"
                       " client is not a part.  Please wait for recovery to "
                       "complete, abort, or time out.\n", lov);
                GOTO(out, err);
        } else if (err) {
                CERROR("cannot connect to %s: rc = %d\n", lov, err);
                GOTO(out_lmv, err);
        }
        sbi->ll_dt_exp = class_conn2export(&dt_conn);

        err = lustre_init_dt_desc(sbi);
        if (err == 0) {
                int mdsize = obd_size_diskmd(sbi->ll_dt_exp, NULL);
                obd_init_ea_size(sbi->ll_md_exp, mdsize,
                                 sbi->ll_dt_desc.ld_tgt_count *
                                 sizeof(struct llog_cookie));
        }
        
        err = md_getstatus(sbi->ll_md_exp, &sbi->ll_rootid);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_lov, err);
        }
        CDEBUG(D_SUPER, "rootid "DLID4"\n", OLID4(&sbi->ll_rootid));

        sb->s_op = &lustre_super_operations;

        /* make root inode */
        err = md_getattr(sbi->ll_md_exp, &sbi->ll_rootid,
                         (OBD_MD_FLNOTOBD | OBD_MD_FLBLOCKS | OBD_MD_FID),
                         NULL, NULL, 0, 0, &request);
        if (err) {
                CERROR("md_getattr failed for root: rc = %d\n", err);
                GOTO(out_lov, err);
        }

        err = mdc_req2lustre_md(sbi->ll_md_exp, request, 0, 
                                sbi->ll_dt_exp, &md);
        if (err) {
                CERROR("failed to understand root inode md: rc = %d\n", err);
                ptlrpc_req_finished(request);
                GOTO(out_lov, err);
        }

        LASSERT(id_ino(&sbi->ll_rootid) != 0);
        root = ll_iget(sb, id_ino(&sbi->ll_rootid), &md);

        ptlrpc_req_finished(request);

        if (root == NULL || is_bad_inode(root)) {
                if (md.lsm != NULL)
                    obd_free_memmd(sbi->ll_dt_exp, &md.lsm);
                if (md.mea != NULL)
                    obd_free_memmd(sbi->ll_md_exp,
                                   (struct lov_stripe_md**)&md.mea);
                CERROR("lustre_lite: bad iget4 for root\n");
                GOTO(out_root, err = -EBADF);
        }

        err = ll_close_thread_start(&sbi->ll_lcq);
        if (err) {
                CERROR("cannot start close thread: rc %d\n", err);
                GOTO(out_root, err);
        }

        ll_gns_add_timer(sbi);

        /* making vm readahead 0 for 2.4.x. In the case of 2.6.x,
           backing dev info assigned to inode mapping is used for
           determining maximal readahead. */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)) && \
    !defined(KERNEL_HAS_AS_MAX_READAHEAD)
        /* bug 2805 - set VM readahead to zero */
        vm_max_readahead = vm_min_readahead = 0;
#endif

        sb->s_root = d_alloc_root(root);
        sb->s_root->d_op = &ll_d_ops;

        sb->s_flags |= MS_POSIXACL;
#ifdef S_PDIROPS
        CWARN("Enabling PDIROPS\n");
        sb->s_flags |= S_PDIROPS;
#endif

        if (data != NULL)
                OBD_FREE(data, sizeof(*data));
        RETURN(err);
out_root:
        if (root)
                iput(root);
out_lov:
        obd_disconnect(sbi->ll_dt_exp, 0);
out_lmv:
        obd_disconnect(sbi->ll_md_exp, 0);
out:
        if (data != NULL)
                OBD_FREE(data, sizeof(*data));
        lprocfs_unregister_mountpoint(sbi);
        return err;
}

void lustre_common_put_super(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct hlist_node *tmp, *next;
        ENTRY;

        ll_gns_del_timer(sbi);
        ll_close_thread_shutdown(sbi->ll_lcq);

        list_del(&sbi->ll_conn_chain);
        obd_disconnect(sbi->ll_dt_exp, 0);

        lprocfs_unregister_mountpoint(sbi);
        if (sbi->ll_proc_root) {
                lprocfs_remove(sbi->ll_proc_root);
                sbi->ll_proc_root = NULL;
        }

        obd_disconnect(sbi->ll_md_exp, 0);

        // We do this to get rid of orphaned dentries. That is not really trw.
        hlist_for_each_safe(tmp, next, &sbi->ll_orphan_dentry_list) {
                struct dentry *dentry = hlist_entry(tmp, struct dentry, d_hash);
                CWARN("orphan dentry %.*s (%p->%p) at unmount\n",
                      dentry->d_name.len, dentry->d_name.name, dentry, next);
                shrink_dcache_parent(dentry);
        }
        EXIT;
}

char *ll_read_opt(const char *opt, char *data)
{
        char *value;
        char *retval;
        ENTRY;

        CDEBUG(D_SUPER, "option: %s, data %s\n", opt, data);
        if (strncmp(opt, data, strlen(opt)))
                RETURN(NULL);
        if ((value = strchr(data, '=')) == NULL)
                RETURN(NULL);

        value++;
        OBD_ALLOC(retval, strlen(value) + 1);
        if (!retval) {
                CERROR("out of memory!\n");
                RETURN(NULL);
        }

        memcpy(retval, value, strlen(value)+1);
        CDEBUG(D_SUPER, "Assigned option: %s, value %s\n", opt, retval);
        RETURN(retval);
}

int ll_set_opt(const char *opt, char *data, int fl)
{
        ENTRY;

        CDEBUG(D_SUPER, "option: %s, data %s\n", opt, data);
        if (strncmp(opt, data, strlen(opt)))
                RETURN(0);
        else
                RETURN(fl);
}

void ll_options(char *options, char **lov, char **lmv, char **mds_sec,
                char **oss_sec, int *async, int *flags)
{
        char *this_char;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        char *opt_ptr = options;
#endif
        ENTRY;

        if (!options) {
                EXIT;
                return;
        }

        *async = 0;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        for (this_char = strtok (options, ",");
             this_char != NULL;
             this_char = strtok (NULL, ",")) {
#else
        while ((this_char = strsep (&opt_ptr, ",")) != NULL) {
#endif
                CDEBUG(D_SUPER, "this_char %s\n", this_char);
                if (!*lov && (*lov = ll_read_opt("osc", this_char)))
                        continue;
                if (!*lmv && (*lmv = ll_read_opt("mdc", this_char)))
                        continue;
                if (!strncmp(this_char, "lasync", strlen("lasync"))) {
                        *async = 1;
                        continue;
                }
                if (!*mds_sec && (*mds_sec = ll_read_opt("mds_sec", this_char)))
                        continue;
                if (!*oss_sec && (*oss_sec = ll_read_opt("oss_sec", this_char)))
                        continue;
                if (!(*flags & LL_SBI_NOLCK) &&
                    ((*flags) = (*flags) |
                                ll_set_opt("nolock", this_char,
                                           LL_SBI_NOLCK)))
                        continue;
        }
        
        EXIT;
}

void ll_lli_init(struct ll_inode_info *lli)
{
        sema_init(&lli->lli_open_sem, 1);
        sema_init(&lli->lli_size_sem, 1);
        lli->lli_flags = 0;
        lli->lli_size_pid = 0;
        lli->lli_maxbytes = PAGE_CACHE_MAXBYTES;
        spin_lock_init(&lli->lli_lock);
        INIT_LIST_HEAD(&lli->lli_pending_write_llaps);
        INIT_LIST_HEAD(&lli->lli_close_item);
        lli->lli_inode_magic = LLI_INODE_MAGIC;
        memset(&lli->lli_id, 0, sizeof(lli->lli_id));
        sema_init(&lli->lli_och_sem, 1);
        lli->lli_mds_read_och = lli->lli_mds_write_och = NULL;
        lli->lli_mds_exec_och = NULL;
        lli->lli_open_fd_read_count = lli->lli_open_fd_write_count = 0;
        lli->lli_open_fd_exec_count = 0;
}

int ll_fill_super(struct super_block *sb, void *data, int silent)
{
        struct ll_sb_info *sbi;
        char *lov = NULL;
        char *lmv = NULL;
        char *mds_sec = NULL;
        char *oss_sec = NULL;
        int async, err;
        __u32 nllu[2] = { NOBODY_UID, NOBODY_GID };
        __u64 remote_flag = 0;    
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op: sb %p\n", sb);

        sbi = lustre_init_sbi(sb);
        if (!sbi)
                RETURN(-ENOMEM);

        sbi->ll_flags |= LL_SBI_READAHEAD;
        ll_options(data, &lov, &lmv, &mds_sec, &oss_sec,
                   &async, &sbi->ll_flags);

        if (!lov) {
                CERROR("no osc\n");
                GOTO(out, err = -EINVAL);
        }

        if (!lmv) {
                CERROR("no mdc\n");
                GOTO(out, err = -EINVAL);
        }
        
        err = lustre_common_fill_super(sb, lmv, lov, async, mds_sec, oss_sec,
                                       nllu, 0, &remote_flag);
        EXIT;
out:
        if (err)
                lustre_free_sbi(sb);

        if (lmv)
                OBD_FREE(lmv, strlen(lmv) + 1);
        if (lov)
                OBD_FREE(lov, strlen(lov) + 1);
        if (mds_sec)
                OBD_FREE(mds_sec, strlen(mds_sec) + 1);
        if (oss_sec)
                OBD_FREE(oss_sec, strlen(oss_sec) + 1);

        return err;
} /* ll_read_super */

static int lustre_process_log(struct lustre_mount_data *lmd, char *profile,
                              struct config_llog_instance *cfg, int allow_recov)
{
        struct lustre_cfg *lcfg = NULL;
        struct lustre_cfg_bufs bufs;
        struct portals_cfg pcfg;
        char *peer = "MDS_PEER_UUID";
        struct obd_device *obd;
        struct lustre_handle md_conn = {0, };
        struct obd_export *exp;
        char *name = "mdc_dev";
        class_uuid_t uuid;
        struct obd_uuid lmv_uuid;
        struct llog_ctxt *ctxt;
        int rc = 0, err = 0;
        ENTRY;

        if (lmd_bad_magic(lmd))
                RETURN(-EINVAL);

        generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &lmv_uuid);

        if (lmd->lmd_local_nid) {
                PCFG_INIT(pcfg, NAL_CMD_REGISTER_MYNID);
                pcfg.pcfg_nal = lmd->lmd_nal;
                pcfg.pcfg_nid = lmd->lmd_local_nid;
                rc = libcfs_nal_cmd(&pcfg);
                if (rc < 0)
                        GOTO(out, rc);
        }

        if (lmd->lmd_nal == SOCKNAL ||
            lmd->lmd_nal == OPENIBNAL ||
            lmd->lmd_nal == IIBNAL ||
            lmd->lmd_nal == VIBNAL ||
            lmd->lmd_nal == RANAL) {
                PCFG_INIT(pcfg, NAL_CMD_ADD_PEER);
                pcfg.pcfg_nal     = lmd->lmd_nal;
                pcfg.pcfg_nid     = lmd->lmd_server_nid;
                pcfg.pcfg_id      = lmd->lmd_server_ipaddr;
                pcfg.pcfg_misc    = lmd->lmd_port;
                rc = libcfs_nal_cmd(&pcfg);
                if (rc < 0)
                        GOTO(out, rc);
        }
        lustre_cfg_bufs_reset(&bufs, name);
        lustre_cfg_bufs_set_string(&bufs, 1, peer);

        lcfg = lustre_cfg_new(LCFG_ADD_UUID, &bufs);
        lcfg->lcfg_nal = lmd->lmd_nal;
        lcfg->lcfg_nid = lmd->lmd_server_nid;
        LASSERT(lcfg->lcfg_nal);
        LASSERT(lcfg->lcfg_nid);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0)
                GOTO(out_del_conn, err);

        lustre_cfg_bufs_reset(&bufs, name);
        lustre_cfg_bufs_set_string(&bufs, 1, OBD_MDC_DEVICENAME);
        lustre_cfg_bufs_set_string(&bufs, 2, (char *)lmv_uuid.uuid);

        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0)
                GOTO(out_del_uuid, err);

        lustre_cfg_bufs_reset(&bufs, name);
        lustre_cfg_bufs_set_string(&bufs, 1, lmd->lmd_mds);
        lustre_cfg_bufs_set_string(&bufs, 2, peer);

        lcfg = lustre_cfg_new(LCFG_SETUP, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0)
                GOTO(out_detach, err);

        obd = class_name2obd(name);
        if (obd == NULL)
                GOTO(out_cleanup, rc = -EINVAL);

        rc = obd_set_info(obd->obd_self_export, strlen("sec"), "sec",
                          strlen(lmd->lmd_mds_security), lmd->lmd_mds_security);
        if (rc)
                GOTO(out_cleanup, rc);

        if (lmd->lmd_pag) {
                unsigned long sec_flags = PTLRPC_SEC_FL_PAG;
                rc = obd_set_info(obd->obd_self_export,
                                  strlen("sec_flags"), "sec_flags",
                                  sizeof(sec_flags), &sec_flags);
                if (rc)
                        GOTO(out_cleanup, rc);
        }

        /* Disable initial recovery on this import */
        rc = obd_set_info(obd->obd_self_export,
                          strlen("initial_recov"), "initial_recov",
                          sizeof(allow_recov), &allow_recov);
        if (rc)
                GOTO(out_cleanup, rc);

        rc = obd_connect(&md_conn, obd, &lmv_uuid, NULL, 0);
        if (rc) {
                CERROR("cannot connect to %s: rc = %d\n", lmd->lmd_mds, rc);
                GOTO(out_cleanup, rc);
        }

        exp = class_conn2export(&md_conn);

        ctxt = llog_get_context(&exp->exp_obd->obd_llogs,LLOG_CONFIG_REPL_CTXT);
        rc = class_config_process_llog(ctxt, profile, cfg);
        if (rc)
                CERROR("class_config_process_llog failed: rc = %d\n", rc);

        err = obd_disconnect(exp, 0);
        
        EXIT;
out_cleanup:
        lustre_cfg_bufs_reset(&bufs, name);
        lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0)
                GOTO(out, err);
out_detach:
        lustre_cfg_bufs_reset(&bufs, name);
        lcfg = lustre_cfg_new(LCFG_DETACH, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0)
                GOTO(out, err);

out_del_uuid:
        lustre_cfg_bufs_reset(&bufs, name);
        lustre_cfg_bufs_set_string(&bufs, 1, peer);
        lcfg = lustre_cfg_new(LCFG_DEL_UUID, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);

out_del_conn:
        if (lmd->lmd_nal == SOCKNAL ||
            lmd->lmd_nal == OPENIBNAL ||
            lmd->lmd_nal == IIBNAL ||
            lmd->lmd_nal == VIBNAL ||
            lmd->lmd_nal == RANAL) {
                int err2;

                PCFG_INIT(pcfg, NAL_CMD_DEL_PEER);
                pcfg.pcfg_nal     = lmd->lmd_nal;
                pcfg.pcfg_nid     = lmd->lmd_server_nid;
                pcfg.pcfg_flags   = 1;          /* single_share */
                err2 = libcfs_nal_cmd(&pcfg);
                if (err2 && !err)
                        err = err2;
                if (err < 0)
                        GOTO(out, err);
        }
out:
        if (rc == 0)
                rc = err;

        return rc;
}

static void lustre_manual_cleanup(struct ll_sb_info *sbi)
{
        struct lustre_cfg *lcfg;
        struct lustre_cfg_bufs bufs;
        struct obd_device *obd;
        int next = 0;

        while ((obd = class_devices_in_group(&sbi->ll_sb_uuid, &next)) != NULL)
        {
                int err;

                lustre_cfg_bufs_reset(&bufs, obd->obd_name);
                lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);
                err = class_process_config(lcfg);
                if (err) {
                        CERROR("cleanup failed: %s\n", obd->obd_name);
                        //continue;
                }
                
                lcfg->lcfg_command = LCFG_DETACH;
                err = class_process_config(lcfg);
                lustre_cfg_free(lcfg);
                if (err) {
                        CERROR("detach failed: %s\n", obd->obd_name);
                        //continue;
                }
        }

        if (sbi->ll_lmd != NULL)
                class_del_profile(sbi->ll_lmd->lmd_profile);
}

int lustre_fill_super(struct super_block *sb, void *data, int silent)
{
        struct lustre_mount_data * lmd = data;
        char *lov = NULL, *lmv = NULL;
        struct ll_sb_info *sbi;
        int err;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op: sb %p\n", sb);
        if (lmd_bad_magic(lmd))
                RETURN(-EINVAL);

        sbi = lustre_init_sbi(sb);
        if (!sbi)
                RETURN(-ENOMEM);

        sbi->ll_flags |= LL_SBI_READAHEAD;

        if (lmd->lmd_profile) {
                struct lustre_profile *lprof;
                struct config_llog_instance cfg;
                int len;

                if (lmd->lmd_mds[0] == '\0') {
                        CERROR("no mds name\n");
                        GOTO(out_free, err = -EINVAL);
                }
                lmd->lmd_mds_security[sizeof(lmd->lmd_mds_security) - 1] = 0;
                lmd->lmd_oss_security[sizeof(lmd->lmd_oss_security) - 1] = 0;

                OBD_ALLOC(sbi->ll_lmd, sizeof(*sbi->ll_lmd));
                if (sbi->ll_lmd == NULL)
                        GOTO(out_free, err = -ENOMEM);
                memcpy(sbi->ll_lmd, lmd, sizeof(*lmd));

                /* generate a string unique to this super, let's try
                 the address of the super itself.*/
                len = (sizeof(sb) * 2) + 1;
                OBD_ALLOC(sbi->ll_instance, len);
                if (sbi->ll_instance == NULL)
                        GOTO(out_free, err = -ENOMEM);
                sprintf(sbi->ll_instance, "%p", sb);

                cfg.cfg_instance = sbi->ll_instance;
                cfg.cfg_uuid = sbi->ll_sb_uuid;
                cfg.cfg_local_nid = lmd->lmd_local_nid;
                err = lustre_process_log(lmd, lmd->lmd_profile, &cfg, 0);
                if (err < 0) {
                        CERROR("Unable to process log: %s\n", lmd->lmd_profile);
                        GOTO(out_free, err);
                }

                lprof = class_get_profile(lmd->lmd_profile);
                if (lprof == NULL) {
                        CERROR("No profile found: %s\n", lmd->lmd_profile);
                        GOTO(out_free, err = -EINVAL);
                }
                if (lov)
                        OBD_FREE(lov, strlen(lov) + 1);
                OBD_ALLOC(lov, strlen(lprof->lp_lov) +
                          strlen(sbi->ll_instance) + 2);
                sprintf(lov, "%s-%s", lprof->lp_lov, sbi->ll_instance);

                if (lmv)
                        OBD_FREE(lmv, strlen(lmv) + 1);
                OBD_ALLOC(lmv, strlen(lprof->lp_lmv) +
                          strlen(sbi->ll_instance) + 2);
                sprintf(lmv, "%s-%s", lprof->lp_lmv, sbi->ll_instance);
        }

        if (!lov) {
                CERROR("no osc\n");
                GOTO(out_free, err = -EINVAL);
        }

        if (!lmv) {
                CERROR("no mdc\n");
                GOTO(out_free, err = -EINVAL);
        }

        err = lustre_common_fill_super(sb, lmv, lov, lmd->lmd_async,
                                       lmd->lmd_mds_security,
                                       lmd->lmd_oss_security,
                                       &lmd->lmd_nllu, lmd->lmd_pag,
                                       &lmd->lmd_remote_flag);

        if (err)
                GOTO(out_free, err);
        
out_dev:
        if (lmv)
                OBD_FREE(lmv, strlen(lmv) + 1);
        if (lov)
                OBD_FREE(lov, strlen(lov) + 1);

        RETURN(err);

out_free:
        if (sbi->ll_lmd) {
                int len = strlen(sbi->ll_lmd->lmd_profile) + sizeof("-clean")+1;
                int err;

                if (sbi->ll_instance != NULL) {
                        struct lustre_mount_data *lmd = sbi->ll_lmd;
                        struct config_llog_instance cfg;
            		char *cl_prof;

                        cfg.cfg_instance = sbi->ll_instance;
                        cfg.cfg_uuid = sbi->ll_sb_uuid;

                        OBD_ALLOC(cl_prof, len);
                        sprintf(cl_prof, "%s-clean", lmd->lmd_profile);
                        err = lustre_process_log(lmd, cl_prof, &cfg, 0);
                        if (err < 0) {
                                CERROR("Unable to process log: %s\n", cl_prof);
                                lustre_manual_cleanup(sbi);
                        }
                        OBD_FREE(cl_prof, len);
                        OBD_FREE(sbi->ll_instance, strlen(sbi->ll_instance) + 1);
                }
                OBD_FREE(sbi->ll_lmd, sizeof(*sbi->ll_lmd));
        }
        lustre_free_sbi(sb);
        goto out_dev;
} /* lustre_fill_super */

void lustre_put_super(struct super_block *sb)
{
        struct obd_device *obd;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        int force_umount = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op: sb %p\n", sb);
        obd = class_exp2obd(sbi->ll_md_exp);
        if (obd)
                force_umount = obd->obd_no_recov;
        obd = NULL;

        lustre_common_put_super(sb);
        if (sbi->ll_lmd != NULL) {
                char *cl_prof;
                int len = strlen(sbi->ll_lmd->lmd_profile) + sizeof("-clean")+1;
                int err;
                struct config_llog_instance cfg;

                if (force_umount) {
                        CERROR("force umount, doing manual cleanup\n");
                        lustre_manual_cleanup(sbi);
                        GOTO(free_lmd, 0);
                }

                cfg.cfg_instance = sbi->ll_instance;
                cfg.cfg_uuid = sbi->ll_sb_uuid;

                OBD_ALLOC(cl_prof, len);
                sprintf(cl_prof, "%s-clean", sbi->ll_lmd->lmd_profile);
                err = lustre_process_log(sbi->ll_lmd, cl_prof, &cfg, 0);
                if (err < 0) {
                        CERROR("Unable to process log: %s, doing manual cleanup"
                               "\n", cl_prof);
                        lustre_manual_cleanup(sbi);
                }

                OBD_FREE(cl_prof, len);
        free_lmd:
                OBD_FREE(sbi->ll_lmd, sizeof(*sbi->ll_lmd));
                OBD_FREE(sbi->ll_instance, strlen(sbi->ll_instance) + 1);
        }

        lustre_free_sbi(sb);

        EXIT;
} /* lustre_put_super */

int ll_process_config_update(struct ll_sb_info *sbi, int clean)
{
        struct lustre_mount_data *lmd = sbi->ll_lmd;
        char *profile = lmd->lmd_profile, *name = NULL;
        struct config_llog_instance cfg;
        int rc, namelen =  0, version;
        struct llog_ctxt *ctxt;
        ENTRY;

        if (profile == NULL)
                RETURN(0);
        if (lmd == NULL) {
                CERROR("Client not mounted with zero-conf; cannot "
                       "process update log.\n");
                RETURN(0);
        }

        rc = obd_cancel_unused(sbi->ll_md_exp, NULL,
                               LDLM_FL_CONFIG_CHANGE, NULL);
        if (rc != 0)
                CWARN("obd_cancel_unused(mdc): %d\n", rc);

        rc = obd_cancel_unused(sbi->ll_dt_exp, NULL,
                               LDLM_FL_CONFIG_CHANGE, NULL);
        if (rc != 0)
                CWARN("obd_cancel_unused(lov): %d\n", rc);

        cfg.cfg_instance = sbi->ll_instance;
        cfg.cfg_uuid = sbi->ll_sb_uuid;
        cfg.cfg_local_nid = lmd->lmd_local_nid;

        namelen = strlen(profile) + 20; /* -clean-######### */
        OBD_ALLOC(name, namelen);
        if (name == NULL)
                RETURN(-ENOMEM);

        if (clean) {
                version = sbi->ll_config_version - 1;
                sprintf(name, "%s-clean-%d", profile, version);
        } else {
                version = sbi->ll_config_version + 1;
                sprintf(name, "%s-%d", profile, version);
        }

        CWARN("Applying configuration log %s\n", name);

        ctxt = llog_get_context(&sbi->ll_md_exp->exp_obd->obd_llogs,
                                LLOG_CONFIG_REPL_CTXT);
        rc = class_config_process_llog(ctxt, name, &cfg);
        if (rc == 0)
                sbi->ll_config_version = version;
        CWARN("Finished applying configuration log %s: %d\n", name, rc);

        if (rc == 0 && clean == 0) {
                struct lov_desc desc;
                __u32 valsize;
                int rc = 0;
                
                valsize = sizeof(desc);
                rc = obd_get_info(sbi->ll_dt_exp, strlen("lovdesc") + 1,
                                  "lovdesc", &valsize, &desc);

                rc = obd_init_ea_size(sbi->ll_md_exp,
                                      obd_size_diskmd(sbi->ll_dt_exp, NULL),
                                      (desc.ld_tgt_count *
                                       sizeof(struct llog_cookie)));
        }
        OBD_FREE(name, namelen);
        RETURN(rc);
}

struct inode *ll_inode_from_lock(struct ldlm_lock *lock)
{
        struct inode *inode = NULL;

        /* NOTE: we depend on atomic igrab() -bzzz */
        lock_res_and_lock(lock);
        if (lock->l_ast_data) {
                struct ll_inode_info *lli = ll_i2info(lock->l_ast_data);
                if (lli->lli_inode_magic == LLI_INODE_MAGIC) {
                        inode = igrab(lock->l_ast_data);
                } else {
                        inode = lock->l_ast_data;
                        CDEBUG(inode->i_state & I_FREEING ? D_INFO : D_WARNING,
                               "l_ast_data %p is bogus: magic %0x8\n",
                               lock->l_ast_data, lli->lli_inode_magic);
                        inode = NULL;
                        unlock_res_and_lock(lock);
                        LBUG();
                }
        }
        unlock_res_and_lock(lock);
        return inode;
}

int null_if_equal(struct ldlm_lock *lock, void *data)
{
        if (data == lock->l_ast_data) {
                lock->l_ast_data = NULL;

                if (lock->l_req_mode != lock->l_granted_mode)
                        LDLM_ERROR(lock,"clearing inode with ungranted lock\n");
        }

        return LDLM_ITER_CONTINUE;
}

static void remote_acl_free(struct remote_acl *racl);

void ll_clear_inode(struct inode *inode)
{
        struct lustre_id id;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        ll_inode2id(&id, inode);
        
        clear_bit(LLI_F_HAVE_MDS_SIZE_LOCK, &(ll_i2info(inode)->lli_flags));
        md_change_cbdata(sbi->ll_md_exp, &id, null_if_equal, inode);

        LASSERT(!lli->lli_open_fd_write_count);
        LASSERT(!lli->lli_open_fd_read_count);
        LASSERT(!lli->lli_open_fd_exec_count);
        if (lli->lli_mds_write_och)
                ll_md_real_close(sbi->ll_md_exp, inode, FMODE_WRITE);
        if (lli->lli_mds_exec_och)
                ll_md_real_close(sbi->ll_md_exp, inode, FMODE_EXEC);
        if (lli->lli_mds_read_och)
                ll_md_real_close(sbi->ll_md_exp, inode, FMODE_READ);
        if (lli->lli_smd)
                obd_change_cbdata(sbi->ll_dt_exp, lli->lli_smd,
                                  null_if_equal, inode);

        if (lli->lli_smd) {
                obd_free_memmd(sbi->ll_dt_exp, &lli->lli_smd);
                lli->lli_smd = NULL;
        }

        if (lli->lli_mea) {
                obd_free_memmd(sbi->ll_md_exp,
                               (struct lov_stripe_md **) &lli->lli_mea);
                lli->lli_mea = NULL;
        }

        if (lli->lli_symlink_name) {
                OBD_FREE(lli->lli_symlink_name,
                         strlen(lli->lli_symlink_name) + 1);
                lli->lli_symlink_name = NULL;
        }

        if (lli->lli_posix_acl) {
                LASSERT(lli->lli_remote_acl == NULL);
                posix_acl_release(lli->lli_posix_acl);
                lli->lli_posix_acl = NULL;
        }

        if (lli->lli_remote_acl) {
                LASSERT(lli->lli_posix_acl == NULL);
                remote_acl_free(lli->lli_remote_acl);
                lli->lli_remote_acl = NULL;
        }

        lli->lli_inode_magic = LLI_INODE_DEAD;

        EXIT;
}

/* If this inode has objects allocated to it (lsm != NULL), then the OST
 * object(s) determine the file size and mtime.  Otherwise, the MDS will
 * keep these values until such a time that objects are allocated for it.
 * We do the MDS operations first, as it is checking permissions for us.
 * We don't to the MDS RPC if there is nothing that we want to store there,
 * otherwise there is no harm in updating mtime/atime on the MDS if we are
 * going to do an RPC anyways.
 *
 * If we are doing a truncate, we will send the mtime and ctime updates
 * to the OST with the punch RPC, otherwise we do an explicit setattr RPC.
 * I don't believe it is possible to get e.g. ATTR_MTIME_SET and ATTR_SIZE
 * at the same time.
 */
int ll_setattr_raw(struct inode *inode, struct iattr *attr)
{
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data *op_data;
        int ia_valid = attr->ia_valid;
        int err, rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu\n", inode->i_ino);
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_SETATTR);

        if (ia_valid & ATTR_SIZE) {
                if (attr->ia_size > ll_file_maxbytes(inode)) {
                        CDEBUG(D_INODE, "file too large %llu > "LPU64"\n",
                               attr->ia_size, ll_file_maxbytes(inode));
                        RETURN(-EFBIG);
                }

                attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
        }

        /* POSIX: check before ATTR_*TIME_SET set (from inode_change_ok) */
        if (ia_valid & (ATTR_MTIME_SET | ATTR_ATIME_SET)) {
                if (current->fsuid != inode->i_uid && !capable(CAP_FOWNER))
                        RETURN(-EPERM);
        }

        /* We mark all of the fields "set" so MDS/OST does not re-set them */
        if (attr->ia_valid & ATTR_CTIME) {
                attr->ia_ctime = CURRENT_TIME;
                attr->ia_valid |= ATTR_CTIME_SET;
        }
        if (!(ia_valid & ATTR_ATIME_SET) && (attr->ia_valid & ATTR_ATIME)) {
                attr->ia_atime = CURRENT_TIME;
                attr->ia_valid |= ATTR_ATIME_SET;
        }
        if (!(ia_valid & ATTR_MTIME_SET) && (attr->ia_valid & ATTR_MTIME)) {
                attr->ia_mtime = CURRENT_TIME;
                attr->ia_valid |= ATTR_MTIME_SET;
        }

        if (attr->ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu, now = %lu\n",
                       LTIME_S(attr->ia_mtime), LTIME_S(attr->ia_ctime),
                       LTIME_S(CURRENT_TIME));

        if (lsm)
                attr->ia_valid &= ~ATTR_SIZE;

        /* If only OST attributes being set on objects, don't do MDS RPC.
         * In that case, we need to check permissions and update the local
         * inode ourselves so we can call obdo_from_inode() always. */
        if (ia_valid & (lsm ? ~(ATTR_SIZE | ATTR_FROM_OPEN /*| ATTR_RAW*/) : ~0)) {
                struct lustre_md md;

                OBD_ALLOC(op_data, sizeof(*op_data));
                if (op_data == NULL)
                        RETURN(-ENOMEM);
                ll_prepare_mdc_data(op_data, inode, NULL, NULL, 0, 0);

                rc = md_setattr(sbi->ll_md_exp, op_data,
                                attr, NULL, 0, NULL, 0, &request);
                OBD_FREE(op_data, sizeof(*op_data));
                if (rc) {
                        ptlrpc_req_finished(request);
                        if (rc != -EPERM && rc != -EACCES)
                                CERROR("md_setattr fails: rc = %d\n", rc);
                        RETURN(rc);
                }

                rc = mdc_req2lustre_md(sbi->ll_md_exp, request, 0, 
                                       sbi->ll_dt_exp, &md);
                if (rc) {
                        ptlrpc_req_finished(request);
                        RETURN(rc);
                }

                /* We call inode_setattr to adjust timestamps, but we first
                 * clear ATTR_SIZE to avoid invoking vmtruncate.
                 *
                 * NB: ATTR_SIZE will only be set at this point if the size
                 * resides on the MDS, ie, this file has no objects. */
                attr->ia_valid &= ~ATTR_SIZE;

                /* 
                 * assigning inode_setattr() to @err to disable warning that
                 * function's result should be checked by by caller. error is
                 * impossible here, as vmtruncate() control path is disabled.
                 */
                err = inode_setattr(inode, attr);
                ll_update_inode(inode, &md);
                ptlrpc_req_finished(request);

                if (!lsm || !S_ISREG(inode->i_mode)) {
                        CDEBUG(D_INODE, "no lsm: not setting attrs on OST\n");
                        RETURN(0);
                }
        } else {
                /* The OST doesn't check permissions, but the alternative is
                 * a gratuitous RPC to the MDS.  We already rely on the client
                 * to do read/write/truncate permission checks, so is mtime OK?
                 */
                if (ia_valid & (ATTR_MTIME | ATTR_ATIME)) {
                        /* from sys_utime() */
                        if (!(ia_valid & (ATTR_MTIME_SET | ATTR_ATIME_SET))) {
                                if (current->fsuid != inode->i_uid &&
                                    (rc = ll_permission(inode, MAY_WRITE, NULL)) != 0)
                                        RETURN(rc);
                        } else {
                                /* from inode_change_ok() */
                                if (current->fsuid != inode->i_uid &&
                                    !capable(CAP_FOWNER))
                                        RETURN(-EPERM);
                        }
                }

                /* won't invoke vmtruncate, as we already cleared ATTR_SIZE */
                err = inode_setattr(inode, attr);
                /* 
                 * assigning inode_setattr() to @err to disable warning that
                 * function's result should be checked by by caller. error is
                 * impossible here, as vmtruncate() control path is disabled.
                 */
        }

        /* We really need to get our PW lock before we change inode->i_size.
         * If we don't we can race with other i_size updaters on our node, like
         * ll_file_read.  We can also race with i_size propogation to other
         * nodes through dirtying and writeback of final cached pages.  This
         * last one is especially bad for racing o_append users on other
         * nodes. */
        if (ia_valid & ATTR_SIZE) {
                ldlm_policy_data_t policy = { .l_extent = {attr->ia_size,
                                                           OBD_OBJECT_EOF } };
                struct lustre_handle lockh = { 0 };
                int err, ast_flags = 0;
                /* XXX when we fix the AST intents to pass the discard-range
                 * XXX extent, make ast_flags always LDLM_AST_DISCARD_DATA
                 * XXX here. */
                if (attr->ia_size == 0)
                        ast_flags = LDLM_AST_DISCARD_DATA;

                rc = ll_extent_lock(NULL, inode, lsm, LCK_PW, &policy, &lockh,
                                    ast_flags, &ll_i2sbi(inode)->ll_seek_stime);

                if (rc != 0)
                        RETURN(rc);

                down(&lli->lli_size_sem);
		lli->lli_size_pid = current->pid;
                rc = vmtruncate(inode, attr->ia_size);
                if (rc != 0) {
                        LASSERT(atomic_read(&lli->lli_size_sem.count) <= 0);
			lli->lli_size_pid = 0;
                        up(&lli->lli_size_sem);
                }

                err = ll_extent_unlock(NULL, inode, lsm, LCK_PW, &lockh);
                if (err) {
                        CERROR("ll_extent_unlock failed: %d\n", err);
                        if (!rc)
                                rc = err;
                }
        } else if (ia_valid & (ATTR_MTIME | ATTR_MTIME_SET | ATTR_UID | ATTR_GID)) {
                struct obdo *oa = NULL;

                CDEBUG(D_INODE, "set mtime on OST inode %lu to %lu\n",
                       inode->i_ino, LTIME_S(attr->ia_mtime));

                oa = obdo_alloc();
                if (oa == NULL)
                        RETURN(-ENOMEM);

                oa->o_id = lsm->lsm_object_id;
                oa->o_gr = lsm->lsm_object_gr;
                oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

                /* adding uid and gid, needed for quota */
                if (ia_valid & ATTR_UID) {
                        oa->o_uid = inode->i_uid;
                        oa->o_valid |= OBD_MD_FLUID;
                }

                if (ia_valid & ATTR_GID) {
                        oa->o_gid = inode->i_gid;
                        oa->o_valid |= OBD_MD_FLGID;
                }

                *(obdo_id(oa)) = lli->lli_id;
                oa->o_valid |= OBD_MD_FLIFID;

                obdo_from_inode(oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                OBD_MD_FLMTIME | OBD_MD_FLCTIME);
                rc = obd_setattr(sbi->ll_dt_exp, oa, lsm, NULL);
                obdo_free(oa);
                if (rc)
                        CERROR("obd_setattr fails: rc = %d\n", rc);
        }

        RETURN(rc);
}

int ll_setattr(struct dentry *de, struct iattr *attr)
{
        LASSERT(de->d_inode);
        return ll_setattr_raw(de->d_inode, attr);
}

int ll_statfs_internal(struct super_block *sb, struct obd_statfs *osfs,
                       unsigned long max_age)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_statfs obd_osfs;
        int rc;
        ENTRY;

        rc = obd_statfs(class_exp2obd(sbi->ll_md_exp), osfs, max_age);
        if (rc) {
                CERROR("obd_statfs fails: rc = %d\n", rc);
                RETURN(rc);
        }

        osfs->os_type = sb->s_magic;

        CDEBUG(D_SUPER, "MDC blocks "LPU64"/"LPU64" objects "LPU64"/"LPU64"\n",
               osfs->os_bavail, osfs->os_blocks, osfs->os_ffree,osfs->os_files);

        rc = obd_statfs(class_exp2obd(sbi->ll_dt_exp), &obd_osfs, max_age);
        if (rc) {
                CERROR("obd_statfs fails: rc = %d\n", rc);
                RETURN(rc);
        }

        CDEBUG(D_SUPER, "OSC blocks "LPU64"/"LPU64" objects "LPU64"/"LPU64"\n",
               obd_osfs.os_bavail, obd_osfs.os_blocks, obd_osfs.os_ffree,
               obd_osfs.os_files);

        osfs->os_blocks = obd_osfs.os_blocks;
        osfs->os_bfree = obd_osfs.os_bfree;
        osfs->os_bavail = obd_osfs.os_bavail;

        /* If we don't have as many objects free on the OST as inodes
         * on the MDS, we reduce the total number of inodes to
         * compensate, so that the "inodes in use" number is correct.
         */
        if (obd_osfs.os_ffree < osfs->os_ffree) {
                osfs->os_files = (osfs->os_files - osfs->os_ffree) +
                        obd_osfs.os_ffree;
                osfs->os_ffree = obd_osfs.os_ffree;
        }

        RETURN(rc);
}

int ll_statfs(struct super_block *sb, struct kstatfs *sfs)
{
        struct obd_statfs osfs;
        int rc;

        CDEBUG(D_VFSTRACE, "VFS Op: superblock %p\n", sb);
        lprocfs_counter_incr(ll_s2sbi(sb)->ll_stats, LPROC_LL_STAFS);

        /* For now we will always get up-to-date statfs values, but in the
         * future we may allow some amount of caching on the client (e.g.
         * from QOS or lprocfs updates). */
        rc = ll_statfs_internal(sb, &osfs, jiffies - 1);
        if (rc)
                return rc;

        statfs_unpack(sfs, &osfs);

        if (sizeof(sfs->f_blocks) == 4) {
                while (osfs.os_blocks > ~0UL) {
                        sfs->f_bsize <<= 1;

                        osfs.os_blocks >>= 1;
                        osfs.os_bfree >>= 1;
                        osfs.os_bavail >>= 1;
                }
        }

        sfs->f_blocks = osfs.os_blocks;
        sfs->f_bfree = osfs.os_bfree;
        sfs->f_bavail = osfs.os_bavail;

        return 0;
}


/********************************
 * remote acl                   *
 ********************************/

static struct remote_acl *remote_acl_alloc(void)
{
        struct remote_acl *racl;
        int i;

        OBD_ALLOC(racl, sizeof(*racl));
        if (!racl)
                return NULL;

        spin_lock_init(&racl->ra_lock);
        init_MUTEX(&racl->ra_update_sem);

        for (i = 0; i < REMOTE_ACL_HASHSIZE; i++)
                INIT_LIST_HEAD(&racl->ra_perm_cache[i]);

        return racl;
}

/*
 * caller should guarantee no race here.
 */
static void remote_perm_flush_xperms(struct lustre_remote_perm *perm)
{
        struct remote_perm_setxid *xperm;

        while (!list_empty(&perm->lrp_setxid_perms)) {
                xperm = list_entry(perm->lrp_setxid_perms.next,
                                   struct remote_perm_setxid,
                                   list);
                list_del(&xperm->list);
                OBD_FREE(xperm, sizeof(*xperm));
        }
}

/*
 * caller should guarantee no race here.
 */
static void remote_acl_flush(struct remote_acl *racl)
{
        struct list_head *head;
        struct lustre_remote_perm *perm, *tmp;
        int i;

        for (i = 0; i < REMOTE_ACL_HASHSIZE; i++) {
                head = &racl->ra_perm_cache[i];

                list_for_each_entry_safe(perm, tmp, head, lrp_list) {
                        remote_perm_flush_xperms(perm);
                        list_del(&perm->lrp_list);
                        OBD_FREE(perm, sizeof(*perm));
                }
        }
}

static void remote_acl_free(struct remote_acl *racl)
{
        if (!racl)
                return;

        down(&racl->ra_update_sem);
        spin_lock(&racl->ra_lock);
        remote_acl_flush(racl);
        spin_unlock(&racl->ra_lock);
        up(&racl->ra_update_sem);

        OBD_FREE(racl, sizeof(*racl));
}

static inline int remote_acl_hashfunc(__u32 id)
{
        return (id & (REMOTE_ACL_HASHSIZE - 1));
}

static
int __remote_acl_check(struct remote_acl *racl, unsigned int *perm)
{
        struct list_head *head;
        struct lustre_remote_perm *lperm;
        struct remote_perm_setxid *xperm;
        int found = 0, rc = -ENOENT;

        LASSERT(racl);
        head = &racl->ra_perm_cache[remote_acl_hashfunc(current->uid)];
        spin_lock(&racl->ra_lock);

        list_for_each_entry(lperm, head, lrp_list) {
                if (lperm->lrp_auth_uid == current->uid) {
                        found = 1;
                        break;
                }
        }

        if (!found)
                goto out;

        if (lperm->lrp_auth_uid == current->fsuid &&
            lperm->lrp_auth_gid == current->fsgid) {
                if (lperm->lrp_valid) {
                        *perm = lperm->lrp_perm;
                        rc = 0;
                }
                goto out;
        } else if ((!lperm->lrp_setuid &&
                    lperm->lrp_auth_uid != current->fsuid) ||
                   (!lperm->lrp_setgid &&
                    lperm->lrp_auth_gid != current->fsgid))  {
                *perm = 0;
                rc = 0;
                goto out;
        }

        list_for_each_entry(xperm, &lperm->lrp_setxid_perms, list) {
                if (xperm->uid == current->fsuid &&
                    xperm->gid == current->fsgid) {
                        *perm = xperm->perm;
                        rc = 0;
                        goto out;
                }
        }

out:
        spin_unlock(&racl->ra_lock);
        return rc;
}

static
int __remote_acl_update(struct remote_acl *racl,
                        struct mds_remote_perm *mperm,
                        struct lustre_remote_perm *lperm,
                        struct remote_perm_setxid *xperm)
{
        struct list_head *head;
        struct lustre_remote_perm *lp;
        struct remote_perm_setxid *xp;
        int found = 0, setuid = 0, setgid = 0;

        LASSERT(racl);
        LASSERT(mperm);
        LASSERT(lperm);
        LASSERT(current->uid == mperm->mrp_auth_uid);

        if (current->fsuid != mperm->mrp_auth_uid)
                setuid = 1;
        if (current->fsgid != mperm->mrp_auth_gid)
                setgid = 1;

        head = &racl->ra_perm_cache[remote_acl_hashfunc(current->uid)];
        spin_lock(&racl->ra_lock);

        list_for_each_entry(lp, head, lrp_list) {
                if (lp->lrp_auth_uid == current->uid) {
                        found = 1;
                        break;
                }
        }

        if (found) {
                OBD_FREE(lperm, sizeof(*lperm));

                if (!lp->lrp_valid && !setuid && !setgid) {
                        lp->lrp_perm = mperm->mrp_perm;
                        lp->lrp_valid = 1;
                }

                /* sanity check for changes of setxid rules */
                if ((lp->lrp_setuid != 0) != (mperm->mrp_allow_setuid != 0)) {
                        CWARN("setuid changes: %d => %d\n",
                              (lp->lrp_setuid != 0),
                              (mperm->mrp_allow_setuid != 0));
                        lp->lrp_setuid = (mperm->mrp_allow_setuid != 0);
                }

                if ((lp->lrp_setgid != 0) != (mperm->mrp_allow_setgid != 0)) {
                        CWARN("setgid changes: %d => %d\n",
                              (lp->lrp_setgid != 0),
                              (mperm->mrp_allow_setgid != 0));
                        lp->lrp_setgid = (mperm->mrp_allow_setgid != 0);
                }

                if (!lp->lrp_setuid && !lp->lrp_setgid &&
                    !list_empty(&lp->lrp_setxid_perms)) {
                        remote_perm_flush_xperms(lp);
                }
        } else {
                /* initialize lperm and linked into hashtable
                 */
                INIT_LIST_HEAD(&lperm->lrp_setxid_perms);
                lperm->lrp_auth_uid = mperm->mrp_auth_uid;
                lperm->lrp_auth_gid = mperm->mrp_auth_gid;
                lperm->lrp_setuid = (mperm->mrp_allow_setuid != 0);
                lperm->lrp_setgid = (mperm->mrp_allow_setgid != 0);
                list_add(&lperm->lrp_list, head);

                if (!setuid && !setgid) {
                        /* in this case, i'm the authenticated user,
                         * and mrp_perm is for me.
                         */
                        lperm->lrp_perm = mperm->mrp_perm;
                        lperm->lrp_valid = 1;
                        spin_unlock(&racl->ra_lock);

                        if (xperm)
                                OBD_FREE(xperm, sizeof(*xperm));
                        return 0;
                }

                lp = lperm;
                /* fall through */
        }

        LASSERT(lp->lrp_setuid || lp->lrp_setgid ||
                list_empty(&lp->lrp_setxid_perms));

        /* if no xperm supplied, we are all done here */
        if (!xperm) {
                spin_unlock(&racl->ra_lock);
                return 0;
        }

        /* whether we allow setuid/setgid */
        if ((!lp->lrp_setuid && setuid) || (!lp->lrp_setgid && setgid)) {
                OBD_FREE(xperm, sizeof(*xperm));
                spin_unlock(&racl->ra_lock);
                return 0;
        }

        /* traverse xperm list */
        list_for_each_entry(xp, &lp->lrp_setxid_perms, list) {
                if (xp->uid == current->fsuid &&
                    xp->gid == current->fsgid) {
                        if (xp->perm != mperm->mrp_perm) {
                                /* actually this should not happen */
                                CWARN("perm changed: %o => %o\n",
                                      xp->perm, mperm->mrp_perm);
                                xp->perm = mperm->mrp_perm;
                        }
                        OBD_FREE(xperm, sizeof(*xperm));
                        spin_unlock(&racl->ra_lock);
                        return 0;
                }
        }

        /* finally insert this xperm */
        xperm->uid = current->fsuid;
        xperm->gid = current->fsgid;
        xperm->perm = mperm->mrp_perm;
        list_add(&xperm->list, &lp->lrp_setxid_perms);

        spin_unlock(&racl->ra_lock);
        return 0;
}

/*
 * remote_acl semaphore must be held by caller
 */
static
int remote_acl_update_locked(struct remote_acl *racl,
                             struct mds_remote_perm *mperm)
{
        struct lustre_remote_perm *lperm;
        struct remote_perm_setxid *xperm;
        int setuid = 0, setgid = 0;

        might_sleep();

        if (current->uid != mperm->mrp_auth_uid) {
                CERROR("current uid %u while authenticated as %u\n",
                       current->uid, mperm->mrp_auth_uid);
                return -EINVAL;
        }

        if (current->fsuid != mperm->mrp_auth_uid)
                setuid = 1;
        if (current->fsgid == mperm->mrp_auth_gid)
                setgid = 1;

        OBD_ALLOC(lperm, sizeof(*lperm));
        if (!lperm)
                return -ENOMEM;

        if ((setuid || setgid) &&
            !(setuid && !mperm->mrp_allow_setuid) &&
            !(setgid && !mperm->mrp_allow_setgid)) {
                OBD_ALLOC(xperm, sizeof(*xperm));
                if (!xperm) {
                        OBD_FREE(lperm, sizeof(*lperm));
                        return -ENOMEM;
                }
        } else
                xperm = NULL;

        return __remote_acl_update(racl, mperm, lperm, xperm);
}

/*
 * return -EACCES at any error cases
 */
int ll_remote_acl_permission(struct inode *inode, int mode)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct remote_acl *racl = ll_i2info(inode)->lli_remote_acl;
        struct ptlrpc_request *req = NULL;
        struct lustre_id id;
        struct mds_remote_perm *mperm;
        int rc = -EACCES, perm;

        if (!racl)
                return -EACCES;

        if (__remote_acl_check(racl, &perm) == 0) {
                return ((perm & mode) == mode ? 0 : -EACCES);
        }

        might_sleep();

        /* doing update
         */
        down(&racl->ra_update_sem);

        /* we might lose the race when obtain semaphore,
         * so check again.
         */
        if (__remote_acl_check(racl, &perm) == 0) {
                if ((perm & mode) == mode)
                        rc = 0;
                goto out;
        }

        /* really fetch from mds
         */
        ll_inode2id(&id, inode);
        if (md_access_check(sbi->ll_md_exp, &id, &req))
                goto out;

        /* status non-zero indicate there's more apparent error
         * detected by mds, e.g. didn't allow this user at all.
         * we simply ignore and didn't cache it.
         */
        if (req->rq_repmsg->status)
                goto out;

        mperm = lustre_swab_repbuf(req, 1, sizeof(*mperm),
                                   lustre_swab_remote_perm);
        LASSERT(mperm);
        LASSERT_REPSWABBED(req, 1);

        if ((mperm->mrp_perm & mode) == mode)
                rc = 0;

        remote_acl_update_locked(racl, mperm);
out:
        if (req)
                ptlrpc_req_finished(req);

        up(&racl->ra_update_sem);
        return rc;
}

int ll_remote_acl_update(struct inode *inode, struct mds_remote_perm *perm)
{
        struct remote_acl *racl = ll_i2info(inode)->lli_remote_acl;
        int rc;

        LASSERT(perm);

        if (!racl)
                return -EACCES;

        down(&racl->ra_update_sem);
        rc = remote_acl_update_locked(racl, perm);
        up(&racl->ra_update_sem);

        return rc;
}

void ll_inode_invalidate_acl(struct inode *inode)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);

        if (sbi->ll_remote) {
                struct remote_acl *racl = lli->lli_remote_acl;

                LASSERT(!lli->lli_posix_acl);
                if (racl) {
                        down(&racl->ra_update_sem);
                        spin_lock(&racl->ra_lock);
                        remote_acl_flush(lli->lli_remote_acl);
                        spin_unlock(&racl->ra_lock);
                        up(&racl->ra_update_sem);
                }
        } else {
                LASSERT(!lli->lli_remote_acl);
                spin_lock(&lli->lli_lock);
                posix_acl_release(lli->lli_posix_acl);
                lli->lli_posix_acl = NULL;
                spin_unlock(&lli->lli_lock);
        }
}

void ll_update_inode(struct inode *inode, struct lustre_md *md)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct lov_stripe_md *lsm = md->lsm;
        struct mds_body *body = md->body;
        struct mea *mea = md->mea;
        struct posix_acl *posix_acl = md->posix_acl;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        ENTRY;

        LASSERT((lsm != NULL) == ((body->valid & OBD_MD_FLEASIZE) != 0));

        if (md->lsm && md->lsm->lsm_magic != LOV_MAGIC) {
                /* check for default striping info for dir. */
                LASSERT((mea != NULL) == ((body->valid & OBD_MD_FLDIREA) != 0));
        }
        
        if (lsm != NULL) {
                LASSERT(lsm->lsm_object_gr > 0);
                if (lli->lli_smd == NULL) {
                        lli->lli_smd = lsm;
                        lli->lli_maxbytes = lsm->lsm_maxbytes;
                        if (lli->lli_maxbytes > PAGE_CACHE_MAXBYTES)
                                lli->lli_maxbytes = PAGE_CACHE_MAXBYTES;
                } else {
                        int i;
                        if (memcmp(lli->lli_smd, lsm, sizeof(*lsm))) {
                                CERROR("lsm mismatch for inode %ld\n",
                                       inode->i_ino);
                                CERROR("lli_smd:\n");
                                dump_lsm(D_ERROR, lli->lli_smd);
                                CERROR("lsm:\n");
                                dump_lsm(D_ERROR, lsm);
                                LBUG();
                        }
                        /* XXX FIXME -- We should decide on a safer (atomic) and
                         * more elegant way to update the lsm */
                        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                                lli->lli_smd->lsm_oinfo[i].loi_id =
                                        lsm->lsm_oinfo[i].loi_id;
                                lli->lli_smd->lsm_oinfo[i].loi_gr =
                                        lsm->lsm_oinfo[i].loi_gr;
                                lli->lli_smd->lsm_oinfo[i].loi_ost_idx =
                                        lsm->lsm_oinfo[i].loi_ost_idx;
                                lli->lli_smd->lsm_oinfo[i].loi_ost_gen =
                                        lsm->lsm_oinfo[i].loi_ost_gen;
                        }
                }
                /* bug 2844 - limit i_blksize for broken user-space apps */
                LASSERTF(lsm->lsm_xfersize != 0, "%lu\n", lsm->lsm_xfersize);
                inode->i_blksize = min(lsm->lsm_xfersize, LL_MAX_BLKSIZE);
                if (lli->lli_smd != lsm)
                        obd_free_memmd(ll_i2dtexp(inode), &lsm);
        }

        if (mea != NULL) {
                if (lli->lli_mea == NULL) {
                        lli->lli_mea = mea;
                } else {
                        if (memcmp(lli->lli_mea, mea, body->eadatasize)) {
                                CERROR("mea mismatch for inode %lu\n",
                                        inode->i_ino);
                                LBUG();
                        }
                }
                if (lli->lli_mea != mea)
                        obd_free_memmd(ll_i2mdexp(inode),
                                       (struct lov_stripe_md **) &mea);
        }

        if (body->valid & OBD_MD_FID)
                id_assign_fid(&lli->lli_id, &body->id1);
        
	if (body->valid & OBD_MD_FLID)
		id_ino(&lli->lli_id) = id_ino(&body->id1);

	if (body->valid & OBD_MD_FLGENER)
		id_gen(&lli->lli_id) = id_gen(&body->id1);

        /* local/remote ACL */
        if (sbi->ll_remote) {
                LASSERT(md->posix_acl == NULL);
                if (md->remote_perm) {
                        ll_remote_acl_update(inode, md->remote_perm);
                        OBD_FREE(md->remote_perm, sizeof(*md->remote_perm));
                        md->remote_perm = NULL;
                }
        } else {
                LASSERT(md->remote_perm == NULL);
                spin_lock(&lli->lli_lock);
                if (posix_acl != NULL) {
                        if (lli->lli_posix_acl != NULL)
                                posix_acl_release(lli->lli_posix_acl);
                        lli->lli_posix_acl = posix_acl;
                }
                spin_unlock(&lli->lli_lock);
        }

        if (body->valid & OBD_MD_FLID)
                inode->i_ino = id_ino(&body->id1);
        if (body->valid & OBD_MD_FLGENER)
                inode->i_generation = id_gen(&body->id1);
        if (body->valid & OBD_MD_FLATIME)
                LTIME_S(inode->i_atime) = body->atime;
        if (body->valid & OBD_MD_FLMTIME &&
            body->mtime > LTIME_S(inode->i_mtime)) {
                CDEBUG(D_INODE, "setting ino %lu mtime from %lu to %u\n",
                       inode->i_ino, LTIME_S(inode->i_mtime), body->mtime);
                LTIME_S(inode->i_mtime) = body->mtime;
        }
        if (body->valid & OBD_MD_FLCTIME &&
            body->ctime > LTIME_S(inode->i_ctime))
                LTIME_S(inode->i_ctime) = body->ctime;
        if (body->valid & OBD_MD_FLMODE) {
                inode->i_mode = (inode->i_mode & S_IFMT) |
                        (body->mode & ~S_IFMT);
        }
        if (body->valid & OBD_MD_FLTYPE) {
                inode->i_mode = (inode->i_mode & ~S_IFMT) |
                        (body->mode & S_IFMT);
        }
        if (body->valid & OBD_MD_FLUID)
                inode->i_uid = body->uid;
        if (body->valid & OBD_MD_FLGID)
                inode->i_gid = body->gid;
        if (body->valid & OBD_MD_FLFLAGS)
                inode->i_flags = body->flags;
        if (body->valid & OBD_MD_FLNLINK)
                inode->i_nlink = body->nlink;
        if (body->valid & OBD_MD_FLRDEV)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                inode->i_rdev = body->rdev;
#else
                inode->i_rdev = old_decode_dev(body->rdev);
#endif
        if (body->valid & OBD_MD_FLSIZE)
                inode->i_size = body->size;
        if (body->valid & OBD_MD_FLBLOCKS)
                inode->i_blocks = body->blocks;

        if (body->valid & OBD_MD_FLSIZE)
                set_bit(LLI_F_HAVE_MDS_SIZE_LOCK, &lli->lli_flags);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        inode->i_dev = (kdev_t)id_group(&lli->lli_id);
#endif
        LASSERT(id_fid(&lli->lli_id) != 0);
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
static struct backing_dev_info ll_backing_dev_info = {
        .ra_pages       = 0,    /* No readahead */
        .memory_backed  = 0,    /* Does contribute to dirty memory */
};
#endif

void ll_read_inode2(struct inode *inode, void *opaque)
{
        struct lustre_md *md = opaque;
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        ll_lli_init(lli);

        LASSERT(!lli->lli_smd);

        if (ll_i2sbi(inode)->ll_remote) {
                lli->lli_remote_acl = remote_acl_alloc();
                /* if failed alloc, nobody will be able to access this inode */
        }

        /* Core attributes from the MDS first.  This is a new inode, and
         * the VFS doesn't zero times in the core inode so we have to do
         * it ourselves.  They will be overwritten by either MDS or OST
         * attributes - we just need to make sure they aren't newer. */
        LTIME_S(inode->i_mtime) = 0;
        LTIME_S(inode->i_atime) = 0;
        LTIME_S(inode->i_ctime) = 0;

        inode->i_rdev = 0;
        ll_update_inode(inode, md);

        /* OIDEBUG(inode); */

        if (S_ISREG(inode->i_mode)) {
                inode->i_op = &ll_file_inode_operations;
                inode->i_fop = &ll_file_operations;
                inode->i_mapping->a_ops = &ll_aops;
                EXIT;
        } else if (S_ISDIR(inode->i_mode)) {
                inode->i_op = &ll_dir_inode_operations;
                inode->i_fop = &ll_dir_operations;
                inode->i_mapping->a_ops = &ll_dir_aops;
                EXIT;
        } else if (S_ISLNK(inode->i_mode)) {
                inode->i_op = &ll_fast_symlink_inode_operations;
                EXIT;
        } else {
                inode->i_op = &ll_special_inode_operations;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
                init_special_inode(inode, inode->i_mode,
                                   kdev_t_to_nr(inode->i_rdev));

                /* initializing backing dev info. */
                inode->i_mapping->backing_dev_info = &ll_backing_dev_info;
#else
                init_special_inode(inode, inode->i_mode, inode->i_rdev);
#endif
                lli->ll_save_ifop = inode->i_fop;

                if (S_ISCHR(inode->i_mode))
                        inode->i_fop = &ll_special_chr_inode_fops;
                else if (S_ISBLK(inode->i_mode))
                        inode->i_fop = &ll_special_blk_inode_fops;
                else if (S_ISFIFO(inode->i_mode))
                        inode->i_fop = &ll_special_fifo_inode_fops;
                else if (S_ISSOCK(inode->i_mode))
                        inode->i_fop = &ll_special_sock_inode_fops;

                CWARN("saved %p, replaced with %p\n", lli->ll_save_ifop,
                      inode->i_fop);

                if (lli->ll_save_ifop->owner) {
                        CWARN("%p has owner %p\n", lli->ll_save_ifop,
                              lli->ll_save_ifop->owner);
                }
                EXIT;
        }
}

void ll_delete_inode(struct inode *inode)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct lustre_id id;
        int rc;
        ENTRY;

        ll_inode2id(&id, inode);

        rc = md_delete_inode(sbi->ll_md_exp, &id);
        if (rc) {
                CERROR("md_delete_inode() failed, error %d\n", 
                       rc);
        }

        clear_inode(inode);
        EXIT;
}

int ll_iocontrol(struct inode *inode, struct file *file,
                 unsigned int cmd, unsigned long arg)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ptlrpc_request *req = NULL;
        int rc, flags = 0;
        ENTRY;

        switch(cmd) {
        case EXT3_IOC_GETFLAGS: {
                struct lustre_id id;
                __u64 valid = OBD_MD_FLFLAGS;
                struct mds_body *body;

                ll_inode2id(&id, inode);
                rc = md_getattr(sbi->ll_md_exp, &id, valid, NULL, NULL, 0, 0,
                                &req);
                if (rc) {
                        CERROR("failure %d inode %lu\n", rc, inode->i_ino);
                        RETURN(-abs(rc));
                }

                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));

                if (body->flags & S_APPEND)
                        flags |= EXT3_APPEND_FL;
                if (body->flags & S_IMMUTABLE)
                        flags |= EXT3_IMMUTABLE_FL;
                if (body->flags & S_NOATIME)
                        flags |= EXT3_NOATIME_FL;

                ptlrpc_req_finished (req);

                RETURN(put_user(flags, (int *)arg));
        }
        case EXT3_IOC_SETFLAGS: {
                struct mdc_op_data *op_data;
                struct iattr attr;
                struct obdo *oa;
                struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;

                if (get_user(flags, (int *)arg))
                        RETURN(-EFAULT);

                oa = obdo_alloc();
                if (!oa)
                        RETURN(-ENOMEM);

                OBD_ALLOC(op_data, sizeof(*op_data));
                if (op_data == NULL) {
                        obdo_free(oa);
                        RETURN(-ENOMEM);
                }
                ll_prepare_mdc_data(op_data, inode, NULL, NULL, 0, 0);

                memset(&attr, 0x0, sizeof(attr));
                attr.ia_attr_flags = flags;
                attr.ia_valid |= ATTR_ATTR_FLAG;

                rc = md_setattr(sbi->ll_md_exp, op_data,
                                &attr, NULL, 0, NULL, 0, &req);
                OBD_FREE(op_data, sizeof(*op_data));
                if (rc) {
                        ptlrpc_req_finished(req);
                        if (rc != -EPERM && rc != -EACCES)
                                CERROR("md_setattr fails: rc = %d\n", rc);
                        obdo_free(oa);
                        RETURN(rc);
                }
                ptlrpc_req_finished(req);

                oa->o_id = lsm->lsm_object_id;
                oa->o_gr = lsm->lsm_object_gr;
                oa->o_flags = flags;
                *(obdo_id(oa)) = ll_i2info(inode)->lli_id;
                oa->o_valid = OBD_MD_FLID | OBD_MD_FLFLAGS | OBD_MD_FLGROUP 
                              | OBD_MD_FLIFID;

                rc = obd_setattr(sbi->ll_dt_exp, oa, lsm, NULL);
                obdo_free(oa);
                if (rc) {
                        if (rc != -EPERM && rc != -EACCES)
                                CERROR("md_setattr fails: rc = %d\n", rc);
                        RETURN(rc);
                }

                if (flags & EXT3_APPEND_FL)
                        inode->i_flags |= S_APPEND;
                else
                        inode->i_flags &= ~S_APPEND;
                if (flags & EXT3_IMMUTABLE_FL)
                        inode->i_flags |= S_IMMUTABLE;
                else
                        inode->i_flags &= ~S_IMMUTABLE;
                if (flags & EXT3_NOATIME_FL)
                        inode->i_flags |= S_NOATIME;
                else
                        inode->i_flags &= ~S_NOATIME;

                RETURN(0);
        }
        default:
                RETURN(-ENOSYS);
        }

        RETURN(0);
}

/* this is only called in the case of forced umount. */
void ll_umount_begin(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_ioctl_data ioc_data = { 0 };
        struct obd_device *obd;
        ENTRY;
     
        CDEBUG(D_VFSTRACE, "VFS Op: superblock %p count %d active %d\n", sb,
               sb->s_count, atomic_read(&sb->s_active));
        
        obd = class_exp2obd(sbi->ll_md_exp);
        if (obd == NULL) {
                CERROR("Invalid MDC connection handle "LPX64"\n",
                       sbi->ll_md_exp->exp_handle.h_cookie);
                EXIT;
                return;
        }
        obd->obd_no_recov = 1;
        obd_iocontrol(IOC_OSC_SET_ACTIVE, sbi->ll_md_exp,
                      sizeof(ioc_data), &ioc_data, NULL);

        obd = class_exp2obd(sbi->ll_dt_exp);
        if (obd == NULL) {
                CERROR("Invalid LOV connection handle "LPX64"\n",
                       sbi->ll_dt_exp->exp_handle.h_cookie);
                EXIT;
                return;
        }

        obd->obd_no_recov = 1;
        obd_iocontrol(IOC_OSC_SET_ACTIVE, sbi->ll_dt_exp,
                      sizeof(ioc_data), &ioc_data, NULL);

        /*
         * really, we'd like to wait until there are no requests outstanding,
         * and then continue.  For now, we just invalidate the requests,
         * schedule, and hope.
         */
        schedule();

        EXIT;
}

int ll_prep_inode(struct obd_export *dt_exp, struct obd_export *md_exp,
                  struct inode **inode, struct ptlrpc_request *req,
                  int offset, struct super_block *sb)
{
        struct lustre_md md;
        int rc = 0;

        rc = mdc_req2lustre_md(md_exp, req, offset, dt_exp, &md);
        if (rc)
                RETURN(rc);

        if (*inode) {
                ll_update_inode(*inode, &md);
        } else {
                LASSERT(sb);
                *inode = ll_iget(sb, id_ino(&md.body->id1), &md);
                if (*inode == NULL || is_bad_inode(*inode)) {
                        /* free the lsm if we allocated one above */
                        if (md.lsm != NULL)
                                obd_free_memmd(dt_exp, &md.lsm);
                        if (md.mea != NULL)
                                obd_free_memmd(md_exp,
                                               (struct lov_stripe_md**)&md.mea);
                        rc = -ENOMEM;
                        CERROR("new_inode -fatal: rc %d\n", rc);
                }
        }

        RETURN(rc);
}

int ll_show_options(struct seq_file *m, struct vfsmount *mnt)
{
        struct ll_sb_info *sbi = ll_s2sbi(mnt->mnt_sb);
        struct lustre_mount_data *lmd = sbi->ll_lmd;

        if (lmd) {
                seq_printf(m, ",mds_sec=%s,oss_sec=%s",
                           lmd->lmd_mds_security, lmd->lmd_oss_security);
        }
        seq_printf(m, ",%s", sbi->ll_remote ? "remote" : "local");
        if (sbi->ll_remote && lmd)
                seq_printf(m, ",nllu=%u:%u", lmd->lmd_nllu, lmd->lmd_nllg);

        if (lmd && lmd->lmd_pag)
                seq_printf(m, ",pag");

        return 0;
}

int ll_get_fid(struct obd_export *exp, struct lustre_id *idp,
               char *filename, struct lustre_id *ret)
{
        struct ptlrpc_request *request = NULL;
        struct mds_body *body;
        int rc;

        rc = md_getattr_lock(exp, idp, filename, strlen(filename) + 1,
                             OBD_MD_FID, 0, &request);
        if (rc < 0) {
                CDEBUG(D_INFO, "md_getattr_lock failed on %s: rc %d\n",
                       filename, rc);
                return rc;
        }

        body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*body));
        LASSERT(body != NULL);
        LASSERT_REPSWABBED(request, 0);

        *ret = body->id1;
        ptlrpc_req_finished(request);

        return rc;
}

int ll_flush_cred(struct inode *inode)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int rc = 0;

        /* XXX to avoid adding api, we simply use set_info() interface
         * to notify underlying obds. set_info() is more like a ioctl() now...
         */
        if (sbi->ll_md_exp) {
                rc = obd_set_info(sbi->ll_md_exp,
                                  strlen("flush_cred"), "flush_cred",
                                  0, NULL);
                if (rc)
                        return rc;
        }

        if (sbi->ll_dt_exp) {
                rc = obd_set_info(sbi->ll_dt_exp,
                                  strlen("flush_cred"), "flush_cred",
                                  0, NULL);
                if (rc)
                        return rc;
        }

        return rc;
}
