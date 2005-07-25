/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/lvfs/lvfs_mount.c
 *  Client/server mount routines
 *
 *  Copyright (c) 2005 Cluster File Systems, Inc.
 *   Author: Nathan Rutman <nathan@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org/
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


#include <linux/obd.h>
#include <linux/lvfs.h>
#include <linux/lustre_disk.h>
#include <linux/lustre_user.h>


/* requires a mounted device */
int parse_last_rcvd(struct obd_device *obd, char *uuid, int *first_mount)
{
        struct lvfs_run_ctxt saved;
        struct file *file;
        /* FIXME filter_server_data and mds_server_data are identical?? should merge*/
        struct lr_server_data *lsd;
        loff_t off = 0;
        int rc;
 
        OBD_ALLOC_WAIT(lsd, sizeof(*lsd));
        if (!lsd)
                return -ENOMEM;
 
        /*setup llog ctxt*/
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
 
        /* open and test the last rcvd file */
        file = filp_open(LAST_RCVD, O_RDONLY, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open %s file: rc = %d\n", LAST_RCVD, rc);
                goto out;
        }
 
        CERROR("Have last_rcvd, size %lu\n",
               (unsigned long)file->f_dentry->d_inode->i_size);
        rc = fsfilt_read_record(obd, file, lsd, sizeof(*lsd), &off);
        if (rc) {
                CERROR("OBD filter: error reading %s: rc %d\n", LAST_RCVD, rc);
                goto out_close;
        }
 
        strcpy(uuid, lsd->lsd_uuid);
        *first_mount = (lsd->lsd_mount_count == 0);
        CERROR("UUID from %s: %s, init=%d\n", LAST_RCVD, uuid, *first_mount);
 
out_close:
        filp_close(file, 0);
out:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        OBD_FREE(lsd, sizeof(*lsd));
        return(rc);
}

static int do_lcfg(char *cfgname, ptl_nid_t nid, int cmd,
                   char *s1, char *s2, char *s3, char *s4)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg    * lcfg = NULL;

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
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        return(err);
}

static int class_manual_cleanup(struct obd_device *obd, char *flags)
{
        struct lustre_cfg *lcfg;
        struct lustre_cfg_bufs bufs;
        int err, rc = 0;

        err = do_lcfg(obd->obd_name, 0, LCFG_CLEANUP, flags, 0, 0, 0);
        if (err) {
                CERROR("cleanup failed (%d): %s\n", err, obd->obd_name);
                rc = err;
        }
        
        err = do_lcfg(obd->obd_name, 0, LCFG_DETACH, 0, 0, 0, 0);
        if (err) {
                CERROR("detach failed (%d): %s\n", err, obd->obd_name);
                if (!rc) 
                        rc = err;
        }

        return(rc);
}

static void lustre_manual_cleanup(struct ll_sb_info *sbi)
{
        while ((obd = class_devices_in_group(&sbi->ll_sb_uuid, &next)) != NULL)
                class_manual_cleanup(obd, NULL);

        if (sbi->ll_lmd && lmd_is_client(sbi->ll_lmd))
                class_del_profile(sbi->ll_lmd->lmd_dev);
}

/* We need to have some extra twiddling here because some systems have
 * no random state when they start up. */
static void
lustre_generate_random_uuid(class_uuid_t uuid)
{
        struct timeval t;
        int *i, j, k;

        ENTRY;
        LASSERT(sizeof(class_uuid_t) % sizeof(*i) == 0);

        j = jiffies;
        do_gettimeofday(&t);
        k = t.tv_usec;

        generate_random_uuid(uuid);

        for (i = (int *)uuid; (char *)i < (char *)uuid + sizeof(class_uuid_t); i++) {
                *i ^= j ^ k;
                j = ((j << 8) & 0xffffff00) | ((j >> 24) & 0x000000ff);
                k = ((k >> 8) & 0x00ffffff) | ((k << 24) & 0xff000000);
        }

        EXIT;
}

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
        if (num_physpages >> (20 - PAGE_SHIFT) < 512)
                sbi->ll_async_page_max = num_physpages / 2;
        else
                sbi->ll_async_page_max = (num_physpages / 4) * 3;
        sbi->ll_ra_info.ra_max_pages = min(num_physpages / 8,
                                           SBI_DEFAULT_READAHEAD_MAX);

        INIT_LIST_HEAD(&sbi->ll_conn_chain);
        INIT_HLIST_HEAD(&sbi->ll_orphan_dentry_list);
        ll_s2sbi_nocast(sb) = sbi;

        lustre_generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &sbi->ll_sb_uuid);
        CDEBUG(D_HA, "generated uuid: %s\n", sbi->ll_sb_uuid.uuid);

        spin_lock(&ll_sb_lock);
        list_add_tail(&sbi->ll_list, &ll_super_blocks);
        spin_unlock(&ll_sb_lock);
        RETURN(sbi);
}

void lustre_free_sbi(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        ENTRY;

        if (sbi != NULL) {
                spin_lock(&ll_sb_lock);
                list_del(&sbi->ll_list);
                spin_unlock(&ll_sb_lock);
                OBD_FREE(sbi, sizeof(*sbi));
        }
        ll_s2sbi_nocast(sb) = NULL;
        EXIT;
}
           
static void server_put_super(struct super_block *sb)
{
        struct list_head dentry_list;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct l_linux_dirent *dirent, *n;
        struct obd_device *obd;
        struct conf_obd *confobd;
        char logname[LOG_NAME_MAX];
        char flags[2] = "";
        int err;
                                                                                       
        CERROR("server put_super uuid %s\n", sbi->ll_sb_uuid.uuid);
                                                                                       
        obd = class_uuid2obd(&sbi->ll_sb_uuid);
        if (!obd) {
                CERROR("Can't get confobd %s\n", sbi->ll_sb_uuid.uuid);
                return;
        }
        confobd = &obd->u.confobd;
                                                                                       
        if (confobd->cfobd_logs_info.ost_number > 0) {
                struct obd_ioctl_data ioc_data = { 0 };
                CERROR("update new logs.\n");
                err = obd_iocontrol(OBD_IOC_UPDATE_LOG, obd->obd_self_export,
                                    sizeof ioc_data, &ioc_data, NULL);
                if (err)
                        CERROR("Failed to Update logs. \n");
        }
                                                                                       
        /* Find all the logs in the LOGS directory */
        err = dentry_readdir(obd, confobd->cfobd_logs_dir,
                       confobd->cfobd_lvfs_ctxt->loc_mnt,
                       &dentry_list);
        if (err)
                CERROR("Can't read LOGS dir, %d\n", err);
                                                                                       
        if (sbi->ll_flags & LL_UMOUNT_FORCE)
                strcat(flags, "A");
        if (sbi->ll_flags & LL_UMOUNT_FAIL)
                strcat(flags, "F");
                                                                                       
        /* Clean up all the -conf obd's in the LOGS directory.
           FIXME this may not be complete / reasonable.
           Really, we should have a list of every obd we started,
           maybe an additional field to obd_device for group_uuid, then
           just use lustre_manual_cleanup. 
           CRAY_MDS:
                client  client-clean  mdsA  mdsA-clean  mdsA-conf
           CRAY_OST:
                OSS-conf  OST_uml2-conf
           This does clean up oss, ost, mds, but not mdt. mdt is set up
           as part of mdsA-conf.
        */
        list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                int len;
                list_del(&dirent->lld_list);
                strncpy(logname, dirent->lld_name, sizeof(logname));
                OBD_FREE(dirent, sizeof(*dirent));
                                                                                       
                /* Confobd start adds "-conf" */
                len = strlen(logname) - 5;
                if ((len < 1) || strcmp(logname + len, "-conf")) {
                        CDEBUG(D_CONFIG, "ignoring %s\n", logname);
                        continue;
                }
                logname[len] = 0;
                                                                                       
                obd = class_name2obd(logname);
                if (!obd) {
                        CERROR("no obd %s\n", logname);
                        continue;
                }
                                                                                       
                CERROR("stopping %s\n", logname);
                err = class_manual_cleanup(obd, flags);
                if (err) {
                        CERROR("failed to cleanup %s: %d\n", logname, err);
                }
        }
                                                                                       
        /* FIXME so until we decide the above, completly evil hack 
        the MDT, soon to be known as the MDS, will be started at insmod and 
        removed at rmmod, so take out of here. */
        obd = class_name2obd("MDT");
        if (obd)
                class_manual_cleanup(obd, flags);

        /* Cleanup the confobd itself */
        if (sbi->ll_lmd != NULL) {
                lustre_manual_cleanup(sbi);
                OBD_FREE(sbi->ll_lmd, sizeof(*sbi->ll_lmd));
                OBD_FREE(sbi->ll_instance, strlen(sbi->ll_instance) + 1);
        }
                                                                                       
        lustre_free_sbi(sb);
}

static void server_umount_force(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
                                                                                       
        CERROR("Umount -f\n");
        sbi->ll_flags |= LL_UMOUNT_FORCE;
}

static struct super_operations server_ops =
{
        //.statfs         = NULL,
        .put_super      = server_put_super,
        .umount_begin   = server_umount_force, /* umount -f */
};

static int server_fill_super(struct super_block *sb)
{
        struct inode *root = 0;
        //struct ll_sb_info *sbi = ll_s2sbi(sb);
        ENTRY;
                                                                                 
        CERROR("Server sb, dev=%d\n", (int)sb->s_dev);
                                                                                 
        sb->s_blocksize = 4096;
        sb->s_blocksize_bits = log2(sb->s_blocksize);
        sb->s_magic = LL_SUPER_MAGIC; /* FIXME different magic? */
        sb->s_maxbytes = PAGE_CACHE_MAXBYTES;
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
                           
/* Get the log "profile" from a remote MGMT and process it.
  FIXME  If remote doesn't exists, try local
  This func should work for both clients and servers */
int lustre_get_process_log(struct lustre_mount_data *lmd, char * profile,
                       struct config_llog_instance *cfg, int allow_recov)
{
        char * peer = "MDS_PEER_UUID";
        struct obd_device *obd;
        struct lustre_handle mdc_conn = {0, };
        struct obd_export *exp;
        char * mdcname = "mdc_dev";
        char   mdsname[sizeof(lmd->lmd_dev)];
        class_uuid_t uuid;
        struct obd_uuid mdc_uuid;
        struct llog_ctxt *ctxt;
        int rc = 0;
        int err;
        ENTRY;

        if (lmd_bad_magic(lmd))
                RETURN(-EINVAL);

        LASSERT(lmd->lmd_mgmtnid.primary != PTL_NID_ANY);

        lustre_generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &mdc_uuid);
        CDEBUG(D_HA, "generated uuid: %s\n", mdc_uuid.uuid);

        err = do_lcfg(mdcname, lmd->lmd_mgmtnid.primary, LCFG_ADD_UUID, 
                      peer, 0, 0, 0)
        if (err < 0)
                GOTO(out, err);

        /* FIXME setup MGC, not MDC */
        err = do_lcfg(mdcname, 0, LCFG_ATTACH, 
                      LUSTRE_MDC_NAME, mdc_uuid.uuid, 0, 0)
        if (err < 0)
                GOTO(out_del_uuid, err);

        /* FIXME get the mds name from the mgmt node */
        sprintf(mdsname, "%s-mds0001", lmd->lmd_dev);
        CERROR("MDS device: %s @ %s\n", mdsname, libcfs_nid2str(lcfg->lcfg_nid));
        err = do_lcfg(mdcname, 0, LCFG_SETUP, 
                      mdsname, peer, 0, 0)
        if (err < 0)
                GOTO(out_detach, err);

        obd = class_name2obd(mdcname);
        if (obd == NULL)
                GOTO(out_cleanup, err = -EINVAL);

        /* Disable initial recovery on this import */
        err = obd_set_info(obd->obd_self_export,
                           strlen("initial_recov"), "initial_recov",
                           sizeof(allow_recov), &allow_recov);
        if (err)
                GOTO(out_cleanup, err);

        err = obd_connect(&mdc_conn, obd, &mdc_uuid, NULL /* ocd */);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdsname, err);
                GOTO(out_cleanup, err);
        }

        exp = class_conn2export(&mdc_conn);

        ctxt = llog_get_context(exp->exp_obd, LLOG_CONFIG_REPL_CTXT);
#if 1
        rc = class_config_parse_llog(ctxt, profile, cfg);
#else
        /*
         * For debugging, it's useful to just dump the log
         */
        rc = class_config_dump_llog(ctxt, profile, cfg);
#endif
        switch (rc) {
        case 0:
                break;
        case -EINVAL:
                LCONSOLE_ERROR("%s: The configuration '%s' could not be read "
                               "from the MDS.  Make sure this client and the "
                               "MDS are running compatible versions of "
                               "Lustre.\n",
                               obd->obd_name, profile);
                /* fall through */
        default:
                CERROR("class_config_parse_llog failed: rc = %d\n", rc);
                break;
        }

        err = obd_disconnect(exp);

out_cleanup:
        err = do_lcfg(mdcname, 0, LCFG_CLEANUP, 
                      0, 0, 0, 0)
        if (err < 0)
                GOTO(out, err);

out_detach:
        err = do_lcfg(mdcname, 0, LCFG_DETACH, 
                      0, 0, 0, 0)
        if (err < 0)
                GOTO(out, err);

out_del_uuid:
        err = do_lcfg(mdcname, 0, LCFG_DEL_UUID, 
                      peer, 0, 0, 0)
out:
        if (rc == 0)
                rc = err;

        RETURN(rc);
}


/* Process all local logs.
FIXME clients and servers should use the same fn. No need to have MDS 
do client and confobd do servers. */
int lustre_process_logs(struct lustre_mount_data *lmd,
                        struct config_llog_instance *cfg, int allow_recov)
{
        struct obd_ioctl_data ioc_data = { 0 };
        struct list_head dentry_list;
        struct l_linux_dirent *dirent, *n;
        struct obd_device *obd;
        struct conf_obd *confobd;
        char lr_uuid[40];
        char logname[LOG_NAME_MAX];
        char confname[40];
        int is_first_mount = 0;
        int err;
                                                                                       
        if (lmd_bad_magic(lmd))
                return(-EINVAL);
                                                                                       
        if (lmd_is_client(lmd)) {
                return(lustre_get_process_log(lmd, lmd->lmd_dev,
                                              cfg, allow_recov));
        }

        /* We're a server, set up a confobd to process the logs */
        sprintf(confname, "CONF%s ", lmd->lmd_fsname);
        err = do_lcfg(LCFG_ATTACH, confname, LUSTRE_CONFOBD_NAME,
                      cfg->cfg_uuid.uuid, 0, 0);
        if (err)
                return(err);
                                                                                       
        /* Apparently servers mount the fs on top of the confobd mount,
           so our confobd mount options must be the same as the server?? */
        err = do_lcfg(LCFG_SETUP, confname, lmd->u.srv.lmd_source,
                      lmd->u.srv.lmd_fstype, lmd->u.srv.lmd_fsopts, 0);
        if (err) {
                CERROR("confobd setup error %d\n", err);
                do_lcfg(LCFG_DETACH, confname, 0, 0, 0, 0);
                return(err);
        }
                                                                                       
        obd = class_name2obd(confname);
        if (!obd) {
                CERROR("Can't find confobd %s\n", confname);
                return(-ENOTCONN);
        }
        confobd = &obd->u.confobd;
                                                                                       
        err = parse_last_rcvd(obd, lr_uuid, &is_first_mount);
        if (err) {
                CERROR("Can't read %s\n", LAST_RCVD);
                return(err);
        }
                                                                                       
        if ((strncmp(lr_uuid, "OST", 3) == 0) && is_first_mount) {
                /* Always register with MGS.  If this is the first mount
                   for an OST, we might have to change our name */
                err = ost_register(lmd, lr_uuid);
                if (err) {
                        CERROR("OST register Failed\n");
                        return(err);
                }
        } else if (strncmp(lr_uuid, "MDS", 3) == 0) {
                #if 0 
                //FIXME stripe count is set in the mds llog
                uint32_t stripe_size;
                err = get_stripe_size(obd, &stripe_size);
                if (err) {
                        CERROR("Can't read %s\n", STRIPE_FILE);
                        return(err);
                }
                confobd_start_accept(obd, lmd, lr_uuid, stripe_size);
                #endif                                                                       
        }
                                                                                       
        /* Find all the logs in the LOGS directory */
        err = dentry_readdir(obd, confobd->cfobd_logs_dir,
                       confobd->cfobd_lvfs_ctxt->loc_mnt,
                       &dentry_list);
        if (err) {
                CERROR("Can't read LOGS dir\n");
                return(err);
        }
                                                                                       
        /* Start up all the -conf logs in the LOGS directory */
        list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                int len;
                list_del(&dirent->lld_list);
                strncpy(logname, dirent->lld_name, sizeof(logname));
                OBD_FREE(dirent, sizeof(*dirent));
                                                                                       
                /* Confobd start adds "-conf" */
                len = strlen(logname) - 5;
                if ((len < 1) || (strcmp(logname + len, "-conf") != 0)) {
                        CDEBUG(D_CONFIG, "ignoring %s\n", logname);
                        continue;
                }
                logname[len] = 0;
                                                                                       
                CERROR("starting log %s\n", logname);
                ioc_data.ioc_inllen1 = len + 1;
                ioc_data.ioc_inlbuf1 = logname;
                err = obd_iocontrol(OBD_IOC_START, obd->obd_self_export,
                                    sizeof ioc_data, &ioc_data, NULL);
                if (err) {
                        CERROR("failed to start log %s: %d\n", logname, err);
                }
        }
                                                                                       
        return(err);
}
                                                 
static int lustre_kern_mount(struct lustre_mount_data *lmd)
{
        struct lustre_disk_data *ldd;
        char *options = NULL;
        struct vfsmount *mnt;
        unsigned long page;

        OBD_ALLOC(ldd, sizeof(*ldd));
        if (!ldd)
                return(-ENOMEM);
        
        //FIXME read MOUNT_DATA_FILE 

        page = __get_free_page(GFP_KERNEL);
        if (!page)
                return(-ENOMEM);

        options = (char *)page;
        memset(options, 0, PAGE_SIZE);

        /* lctl_setup 1:/dev/loop/0 2:ext3 3:mdsA 4:errors=remount-ro,iopen_nopriv*/
        if (LUSTRE_CFG_BUFLEN(lcfg, 4) > 0 && lustre_cfg_buf(lcfg, 4))
                sprintf(options + strlen(options), ",%s",
                        lustre_cfg_string(lcfg, 4));

        mnt = do_kern_mount(MT_STR(ldd), 0,
                            lmd->lmd_dev,
                            (void *)ldd->ldd_mount_opts);
        free_page(page);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                GOTO(err_ops, rc);
        }

        CDEBUG(D_SUPER, "%s: mnt = %p\n", lustre_cfg_string(lcfg, 1), mnt);
}

int lustre_fill_super(struct super_block *sb, void *data, int silent)
{
        struct lustre_mount_data * lmd = data;
        struct ll_sb_info *sbi;
        struct config_llog_instance cfg;
        char   ll_instance[sizeof(sb) * 2 + 1];
        int len;
        int err;
        ENTRY;
 
        CDEBUG(D_VFSTRACE, "VFS Op: sb %p\n", sb);
        if (lmd_bad_magic(lmd))
                RETURN(-EINVAL);
 
        sbi = lustre_init_sbi(sb);
        if (!sbi)
                RETURN(-ENOMEM);
 
        /* save mount data */
        OBD_ALLOC(sbi->ll_lmd, sizeof(*sbi->ll_lmd));
        if (sbi->ll_lmd == NULL)
                GOTO(out_free, err = -ENOMEM);
        memcpy(sbi->ll_lmd, lmd, sizeof(*lmd));
 
        /* generate a string unique to this super, let's try
         the address of the super itself.*/
        sprintf(ll_instance, "%p", sb);
        cfg.cfg_instance = ll_instance;
        cfg.cfg_uuid = sbi->ll_sb_uuid;
                                                                                
        if (!lmd_is_client(lmd)) {
               err = lustre_kern_mount(lmd);
               if (err) {
                       CERROR("Unable to mount device %s: %d\n", 
                              lmd->lmd_dev, err);
                       GOTO(out_free, err);
               }
        }

        /* sets up all obd devices (server or client) */
        err = lustre_process_logs(lmd, &cfg, 0);
        if (err < 0) {
                CERROR("Unable to process log: %d\n", err);
                GOTO(out_free, err);
        }
                                                                                
        if (lmd_is_client(lmd)) {
                /* Connect and start */
                err = client_fill_super(sb, lmd);
                if (err < 0) {
                        CERROR("Unable to mount client: %s\n",
                               lmd->u.cli.lmd_profile);
                        GOTO(out_free, err);
                }
        } else {
                CERROR("Mounting server\n");
                err = server_fill_super(sb);
                // FIXME overmount client here
        }
                                                                                
        RETURN(err);
                                                                                
out_free:
        if (sbi->ll_lmd) {
                lustre_manual_cleanup(sbi);
                OBD_FREE(sbi->ll_lmd, sizeof(*sbi->ll_lmd));
        }
        lustre_free_sbi(sb);
                                                                                
        RETURN(err);
} /* lustre_fill_super */
                                                                                


int lustre_remount_fs(struct super_block *sb, int *flags, char *data)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        int err;
        __u32 read_only;

        if ((*flags & MS_RDONLY) != (sb->s_flags & MS_RDONLY)) {
                read_only = *flags & MS_RDONLY;
                err = obd_set_info(sbi->ll_mdc_exp, strlen("read-only"),
                                   "read-only", sizeof(read_only), &read_only);
                if (err) {
                        CERROR("Failed to change the read-only flag during "
                               "remount: %d\n", err);
                        return err;
                }

                if (read_only)
                        sb->s_flags |= MS_RDONLY;
                else
                        sb->s_flags &= ~MS_RDONLY;
        }
        return 0;
}



