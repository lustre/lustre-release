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


int parse_mount_data(struct lvfs_run_ctxt *mount_ctxt, 
                     struct lustre_disk_data *ldd)
{
        struct lvfs_run_ctxt saved;
        struct file *file;
        loff_t off = 0;
        unsigned long len;

        push_ctxt(&saved, mount_ctxt, NULL);
        
        file = filp_open(MOUNT_DATA_FILE, O_RDONLY, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open %s: rc = %d\n", MOUNT_DATA_FILE, rc);
                goto out;
        }
 
        len = file->f_dentry->d_inode->i_size;
        CERROR("Have last_rcvd, size %lu\n", len);

        rc = lustre_fread(file, ldd, len, &off);
        if (rc) {
                CERROR("OBD filter: error reading %s: rc %d\n", 
                       MOUNT_DATA_FILE, rc);
                goto out_close;
        }
        if (ldd->ldd_magic != LDD_MAGIC) {
                CERROR("Bad magic in %s: %x!=%x\n", MOUNT_DATA_FILE, 
                       ldd->ldd_magic, LDD_MAGIC);
                rc = -EINVAL;
        }

out_close:
        filp_close(file, 0);
out:
        pop_ctxt(&saved, mount_ctxt, NULL);
        return(rc);
}

int parse_last_rcvd(struct ll_sb_info *sbi, 
                    char *uuid, int *first_mount)
{
        struct lvfs_run_ctxt saved;
        struct file *file;
        struct lr_server_data *lsd;
        loff_t off = 0;
        int rc;
 
        OBD_ALLOC_WAIT(lsd, sizeof(*lsd));
        if (!lsd)
                return -ENOMEM;
 
        /* requires a mounted device */
        LASSERT(sbi->ll_ctxt.pwdmnt);
        push_ctxt(&saved, &sbi->ll_ctxt, NULL);
 
        /* open and test the last rcvd file */
        file = filp_open(LAST_RCVD, O_RDONLY, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open %s file: rc = %d\n", LAST_RCVD, rc);
                goto out;
        }
 
        CERROR("Have last_rcvd, size %lu\n",
               (unsigned long)file->f_dentry->d_inode->i_size);
        LASSERT(sbi->ll_fsops);
        rc = sbi->ll_fsops->fs_read_record(file, lsd, sizeof(*lsd), &off);
        //rc = fsfilt_read_record(obd, file, lsd, sizeof(*lsd), &off);
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
        pop_ctxt(&saved, &sbi->ll_ctxt, NULL);
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

void lustre_manual_cleanup(struct ll_sb_info *sbi)
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
                if (sbi->ll_ldd != NULL) 
                        OBD_FREE(sbi->ll_ldd, sizeof(*sbi->ll_ldd));
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
        struct mgmtcli_obd *mcobd;
        char logname[LOG_NAME_MAX];
        char flags[2] = "";
        int err;
                                                                                       
        //FIXME create MGC

        CERROR("server put_super uuid %s\n", sbi->ll_sb_uuid.uuid);
                                                                                       
        obd = class_uuid2obd(&sbi->ll_sb_uuid);
        if (!obd) {
                CERROR("Can't get mcobd %s\n", sbi->ll_sb_uuid.uuid);
                return;
        }
        mcobd = &obd->u.mgmtcli;
                                                                                       
        if (mcobd->cfobd_logs_info.ost_number > 0) {
                struct obd_ioctl_data ioc_data = { 0 };
                CERROR("update new logs.\n");
                err = obd_iocontrol(OBD_IOC_UPDATE_LOG, obd->obd_self_export,
                                    sizeof ioc_data, &ioc_data, NULL);
                if (err)
                        CERROR("Failed to Update logs. \n");
        }
                                                                                       
        /* Find all the logs in the LOGS directory */
        err = dentry_readdir(obd, mcobd->cfobd_logs_dir,
                       mcobd->cfobd_lvfs_ctxt->loc_mnt,
                       &dentry_list);
        if (err)
                CERROR("Can't read LOGS dir, %d\n", err);
                                                                                       
        if (sbi->ll_flags & LL_UMOUNT_FORCE)
                strcat(flags, "A");
        if (sbi->ll_flags & LL_UMOUNT_FAILOVER)
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

        /* Cleanup the mcobd itself */
        if (sbi->ll_lmd != NULL) {
                lustre_manual_cleanup(sbi);
                OBD_FREE(sbi->ll_lmd, sizeof(*sbi->ll_lmd));
        }

        //FIXME cleanup does the mntput; we have to make sure MGS is done with
        //it as well - we should probably do it here.
                                                                                       
        lustre_free_sbi(sb);
}

static void server_umount_force(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
                                                                                       
        CERROR("Umount -f\n");
        // FIXME decide FORCE or FAILOVER based on mount option -o umount=failover
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
        sb->s_magic = LL_SUPER_MAGIC;
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
  FIXME  If remote doesn't exist, try local
  This func should work for both clients and servers */
int lustre_get_process_log(struct lustre_mount_data *lmd, char * profile,
                       struct config_llog_instance *cfg)
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
        int allow_recov = (lmd->lmd_flags & LMD_FLG_RECOVER) > 0;
        int err, rc = 0;
        ENTRY;

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
do client and confobd do servers. MGC should do both. */
int lustre_process_logs(struct lustre_mount_data *lmd,
                        struct config_llog_instance *cfg, int allow_recov)
{
        struct obd_ioctl_data ioc_data = { 0 };
        struct list_head dentry_list;
        struct l_linux_dirent *dirent, *n;
        struct obd_device *obd;
        struct mgmtcli_obd *mcobd;
        char lr_uuid[40];
        char logname[LOG_NAME_MAX];
        char mcname[40];
        int is_first_mount = 0;
        int err;
                                                                                       

        /* We're a server, set up a mcobd to process the logs */
        sprintf(mcname, "CONF%s ", lmd->lmd_dev);
        err = do_lcfg(LCFG_ATTACH, mcname, LUSTRE_CONFOBD_NAME,
                      cfg->cfg_uuid.uuid, 0, 0);
        if (err)
                return(err);
                                                                                       
        /* Apparently servers mount the fs on top of the confobd mount,
           so our confobd mount options must be the same as the server?? */
        err = do_lcfg(LCFG_SETUP, mcname, lmd->u.srv.lmd_source,
                      lmd->u.srv.lmd_fstype, lmd->u.srv.lmd_fsopts, 0);
        if (err) {
                CERROR("mcobd setup error %d\n", err);
                do_lcfg(LCFG_DETACH, mcname, 0, 0, 0, 0);
                return(err);
        }
                                                                                       
        obd = class_name2obd(mcname);
        if (!obd) {
                CERROR("Can't find mcobd %s\n", mcname);
                return(-ENOTCONN);
        }
        mcobd = &obd->u.mgmtcli;
                                                                                       
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
                mcobd_start_accept(obd, lmd, lr_uuid, stripe_size);
                #endif                                                                       
        }
                                                                                       
        /* Find all the logs in the LOGS directory */
        err = dentry_readdir(obd, mcobd->cfobd_logs_dir,
                       mcobd->cfobd_lvfs_ctxt->loc_mnt,
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
                                                 
/* Kernel mount using mount options in MOUNT_DATA_FILE */
static int lustre_kern_mount(struct ll_sb_info *sbi)
{
        struct lvfs_run_ctxt mount_ctxt;
        struct lvfs_run_ctxt saved;
        struct lustre_disk_data *ldd;
        struct lustre_mount_data *lmd = sbi->ll_lmd;
        char *options = NULL;
        struct vfsmount *mnt;
        unsigned long page;
        int rc;

        OBD_ALLOC(ldd, sizeof(*ldd));
        if (!ldd)
                return(-ENOMEM);

        /* Pre-mount ext3 with no options to read the MOUNT_DATA_FILE */
        CERROR("Pre-mount ext3 %s\n", lmd->lmd_dev);
        mnt = do_kern_mount("ext3", 0, lmd->lmd_dev, 0);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("premount failed: rc = %d\n", rc);
                goto out_free;
        }

        OBD_SET_CTXT_MAGIC(&mount_ctxt);
        mount_ctxt.pwdmnt = mnt;
        mount_ctxt.pwd = mnt->mnt_root;
        mount_ctxt.fs = get_ds();
        //mount_ctxt.cb_ops = mds_lvfs_ops;

        rc = parse_mount_data(&mount_ctxt, ldd); 
        //unlock_kernel();
        mntput(mnt);
        //lock_kernel();

        if (rc) {
                CERROR("premount parse options failed: rc = %d\n", rc);
                goto out_free;
        }

        /* Done with our pre-mount, now do the real mount. */

        /* Glom up mount options */
        page = __get_free_page(GFP_KERNEL);
        if (!page) {
                rc = -ENOMEM;
                goto out_free;
        }
        options = (char *)page;
        memset(options, 0, PAGE_SIZE);
        strcpy(options, ldd->ldd_mount_opts);
        if (strlen(lmd->lmd_opts)) {
                if (strlen(options)) 
                        strcat(options, ",");
                strcat(options, ldd->ldd_mount_opts);
        }

        CERROR("kern_mount: %s %s %s\n", MT_STR(ldd), lmd->lmd_dev, options);

        mnt = do_kern_mount(MT_STR(ldd), 0, lmd->lmd_dev, (void *)options);
        free_page(page);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                goto out_free;
        }

        /* ldd freed at sbi cleanup */
        sbi->ll_ldd = ldd;
        sbi->ll_ctxt.pwdmnt = mnt;
        sbi->ll_ctxt.pwd = mnt->mnt_root;
        sbi->ll_ctxt.fs = get_ds();
        sbi->ll_fsops = fsfilt_get_ops(MT_STR(ldd));

        CDEBUG(D_SUPER, "%s: mnt = %p\n", lmd->lmd_dev, mnt);
        return(0);

out_free:
        OBD_FREE(ldd, sizeof(*ldd));
        return(rc);
}

/* Common mount */
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
        
        /*FIXME mgc = create_mgc(sbi);
         name "fsname-mgc"? or 1 mgc per node?
         */

        if (lmd_is_client(lmd)) {
                err = lustre_get_process_log(lmd, 
                                             lmd->lmd_dev/* FIXME or "client"?*/, 
                                             &cfg)
                if (err < 0) {
                        CERROR("Unable to process log: %d\n", err);
                        GOTO(out_free, err);
                }
                /* Connect and start */
                err = client_fill_super(sb);
                if (err < 0) {
                        CERROR("Unable to mount client: %s\n",
                               lmd->u.cli.lmd_profile);
                        GOTO(out_free, err);
                }

        } else {
                /* Server, so mount to read server info */
                err = lustre_kern_mount(sbi);
                if (err) {
                        CERROR("Unable to mount device %s: %d\n", 
                               lmd->lmd_dev, err);
                        GOTO(out_free, err);
                }
                CERROR("Found service %s for fs %s on device %s\n",
                       sbi->ll_ldd->ldd_svname, sbi->ll_ldd->ldd_fsname, 
                       lmd->lmd_dev);

                /* Set up all obd devices for service */
                err = lustre_process_logs(lmd, &cfg, 0);
                if (err < 0) {
                        CERROR("Unable to process log: %d\n", err);
                        GOTO(out_free, err);
                }

                /* Finally, put something at the mount point. */
                CERROR("Mounting server\n");
                err = server_fill_super(sb);
                /* FIXME overmount client here,
                or can we just start a client log and client_fill_super on this sb? 
                have to fix up the s_ops after! */
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
                                                                                
/* Common umount */
void lustre_put_super(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        if (sbi->ll_lmd && !lmd_is_client(sbi->ll_lmd) {
                // FIXME unmount overmounted client first 
                return server_put_super(sb);
        } else {
                return client_put_super(sb);
        }
}

/* Common remount */
int lustre_remount_fs(struct super_block *sb, int *flags, char *data)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        int err;
        __u32 read_only;

        if ((*flags & MS_RDONLY) != (sb->s_flags & MS_RDONLY)) {
                read_only = *flags & MS_RDONLY;
                if (sbi->ll_lmd && !lmd_is_client(sbi->ll_lmd) {
                        CERROR("Remount server RO %d\n", read_only);
                } else {
                        err = obd_set_info(sbi->ll_mdc_exp, strlen("read-only"),
                                           "read-only", sizeof(read_only),
                                           &read_only);
                        if (err) {
                                CERROR("Failed to change the read-only flag "
                                       "during remount: %d\n", err);
                                return err;
                        }
                }

                if (read_only)
                        sb->s_flags |= MS_RDONLY;
                else
                        sb->s_flags &= ~MS_RDONLY;
        }
        return 0;
}


EXPORT_SYMBOL(lustre_init_sbi);
EXPORT_SYMBOL(lustre_free_sbi);
EXPORT_SYMBOL(lustre_fill_super);
EXPORT_SYMBOL(lustre_put_super);
EXPORT_SYMBOL(lustre_manual_cleanup);
EXPORT_SYMBOL(lustre_remount_fs);

