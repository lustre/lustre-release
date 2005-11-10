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


#define DEBUG_SUBSYSTEM S_MGMT
#define D_MOUNT D_ERROR

#include <linux/obd.h>
#include <linux/lvfs.h>
#include <linux/lustre_fsfilt.h>
//#include <linux/lustre_mgs.h>
#include <linux/obd_class.h>
#include <lustre/lustre_user.h>
#include <linux/version.h> 
#include <linux/lustre_log.h>
#include <linux/lustre_disk.h>
                      
static int (*client_fill_super)(struct super_block *sb) = NULL;

/*********** mount lookup *********/
DECLARE_MUTEX(lustre_mount_info_lock);
struct list_head lustre_mount_info_list = LIST_HEAD_INIT(lustre_mount_info_list);

static struct lustre_mount_info *lustre_find_mount(char *name)
{
        struct list_head *tmp;
        struct lustre_mount_info *lmi;
        int found = 0;
        list_for_each(tmp, &lustre_mount_info_list) {
                lmi = list_entry(tmp, struct lustre_mount_info, lmi_list_chain);
                if (strcmp(name, lmi->lmi_name) == 0) {
                        CDEBUG(D_MOUNT, "Match %s with mnt=%p\n", 
                               name, lmi->lmi_mnt);
                        found++;
                        break;
                }
        }
        if (found)
                return(lmi);
        return(NULL);
}

/* obd's using a mount must register for it before they call
   their setup routine.  They call lustre_get_mount to get the mnt struct
   by name, since we can't pass the pointer to setup. */
int lustre_register_mount(char *name, struct super_block *sb,
                          struct vfsmount *mnt)
{
        struct lustre_mount_info *lmi;
        char *name_cp;

        CDEBUG(D_MOUNT, "register %s\n", name);

        OBD_ALLOC(lmi, sizeof(*lmi));
        if (!lmi) 
                return -ENOMEM;
        OBD_ALLOC(name_cp, strlen(name) + 1);
        if (!name_cp) { 
                OBD_FREE(lmi, sizeof(*lmi));
                return -ENOMEM;
        }
        strcpy(name_cp, name);

        down(&lustre_mount_info_lock);
        
        if (lustre_find_mount(name)) {
                up(&lustre_mount_info_lock);
                OBD_FREE(lmi, sizeof(*lmi));
                OBD_FREE(name_cp, strlen(name) + 1);
                CERROR("Already registered %s\n", name);
                return -EEXIST;
        }
        lmi->lmi_name = name_cp;
        lmi->lmi_sb = sb;
        lmi->lmi_mnt = mnt;
        list_add(&lmi->lmi_list_chain, &lustre_mount_info_list);
         
        up(&lustre_mount_info_lock);
        return 0;
}

/* when an obd no longer needs a mount */
static int lustre_deregister_mount(char *name)
{
        struct lustre_mount_info *lmi;
        
        CDEBUG(D_MOUNT, "deregister %s\n", name);

        down(&lustre_mount_info_lock);
        lmi = lustre_find_mount(name);
        if (!lmi) {
                up(&lustre_mount_info_lock);
                CERROR("%s not registered\n", name);
                return -ENOENT;
        }
        OBD_FREE(lmi->lmi_name, strlen(lmi->lmi_name) + 1);
        list_del(&lmi->lmi_list_chain);
        OBD_FREE(lmi, sizeof(*lmi));
        up(&lustre_mount_info_lock);
        return 0;
}

/* Deregister anyone referencing the mnt. Everyone should have
   put_mount in *_cleanup, but this is a catch-all in case of err... */
static void lustre_deregister_mount_all(struct vfsmount *mnt)
{
        struct list_head *tmp, *n;
        struct lustre_mount_info *lmi;

        if (!mnt)
                return;

        down(&lustre_mount_info_lock);
        list_for_each_safe(tmp, n, &lustre_mount_info_list) {
                lmi = list_entry(tmp, struct lustre_mount_info, lmi_list_chain);
                if (lmi->lmi_mnt == mnt) {
                        CERROR("Deregister failsafe %s\n", lmi->lmi_name);
                        OBD_FREE(lmi->lmi_name, strlen(lmi->lmi_name) + 1);
                        list_del(&lmi->lmi_list_chain);
                        OBD_FREE(lmi, sizeof(*lmi));
                }
        }
        up(&lustre_mount_info_lock);
}

/* obd's look up a registered mount using their name. This is just
   for initial obd setup to find the mount struct.  It should not be
   called every time you want to mntget. */
struct lustre_mount_info *lustre_get_mount(char *name)
{
        struct lustre_mount_info *lmi;
        struct lustre_sb_info *lsi;

        down(&lustre_mount_info_lock);

        lmi = lustre_find_mount(name);
        if (!lmi) {
                up(&lustre_mount_info_lock);
                CERROR("Can't find mount for %s\n", name);
                return NULL;
        }
        lsi = s2lsi(lmi->lmi_sb);
        mntget(lmi->lmi_mnt);
        atomic_inc(&lsi->lsi_mounts);
        
        up(&lustre_mount_info_lock);
        CDEBUG(D_MOUNT, "got mount for %s\n", name);
        return lmi;
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

/* to be called from obd_cleanup methods */
int lustre_put_mount(char *name, struct vfsmount *mnt)
{
        struct lustre_mount_info *lmi;
        struct lustre_sb_info *lsi;

        down(&lustre_mount_info_lock);
        lmi = lustre_find_mount(name);
        if (!lmi) {
                up(&lustre_mount_info_lock);
                CERROR("Can't find mount for %s\n", name);
                return -ENOENT;
        }

        CDEBUG(D_MOUNT, "put mount for %s, #%d\n", name, 
               atomic_read(&lsi->lsi_mounts));
        lsi = s2lsi(lmi->lmi_sb);
        LASSERT(lmi->lmi_mnt == mnt);
        unlock_mntput(lmi->lmi_mnt);
        if (atomic_dec_and_test(&lsi->lsi_mounts)) {
                CDEBUG(D_MOUNT, "Last put of mnt %p from %s, mount count %d\n", 
                       lmi->lmi_mnt, name, 
                       atomic_read(&lmi->lmi_mnt->mnt_count));
        }
        up(&lustre_mount_info_lock);

        /* this obd should never need the mount again */
        lustre_deregister_mount(name);
        
        return 0;
}


/******* mount helper utilities *********/

int parse_mount_data(struct lvfs_run_ctxt *mount_ctxt, 
                     struct lustre_disk_data *ldd)
{
        struct lvfs_run_ctxt saved;
        struct file *file;
        loff_t off = 0;
        unsigned long len;
        int err;

        push_ctxt(&saved, mount_ctxt, NULL);
        
        file = filp_open(MOUNT_DATA_FILE, O_RDONLY, 0644);
        if (IS_ERR(file)) {
                err = PTR_ERR(file);
                CERROR("cannot open %s: err = %d\n", MOUNT_DATA_FILE, err);
                goto out;
        }
 
        len = file->f_dentry->d_inode->i_size;
        CDEBUG(D_MOUNT, "Have %s, size %lu\n", MOUNT_DATA_FILE, len);

        err = lustre_fread(file, ldd, len, &off);
        if (err != len) {
                CERROR("error reading %s: read %d of %lu\n", 
                       MOUNT_DATA_FILE, err, len);
                err = -EINVAL;
                goto out_close;
        }
        err = 0;

        if (ldd->ldd_magic != LDD_MAGIC) {
                CERROR("Bad magic in %s: %x!=%x\n", MOUNT_DATA_FILE, 
                       ldd->ldd_magic, LDD_MAGIC);
                err = -EINVAL;
        }

out_close:
        filp_close(file, 0);
out:
        pop_ctxt(&saved, mount_ctxt, NULL);
        return(err);
}

int parse_last_rcvd(struct obd_device *obd, char *uuid, int *first_mount)
{
        struct lvfs_run_ctxt saved;
        struct file *file;
        struct lr_server_data *lsd;
        loff_t off = 0;
        int err;
 
        OBD_ALLOC_WAIT(lsd, sizeof(*lsd));
        if (!lsd)
                return -ENOMEM;
 
        /* requires a mounted device */
        LASSERT(obd);
         /*setup llog ctxt*/
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        /* open and test the last rcvd file */
        file = filp_open(LAST_RCVD, O_RDONLY, 0644);
        if (IS_ERR(file)) {
                err = PTR_ERR(file);
                CERROR("cannot open %s file: err = %d\n", LAST_RCVD, err);
                goto out;
        }
 
        CDEBUG(D_MOUNT, "Have last_rcvd, size %lu\n",
               (unsigned long)file->f_dentry->d_inode->i_size);
        err = fsfilt_read_record(obd, file, lsd, sizeof(*lsd), &off);
        if (err) {
                CERROR("error reading %s: err %d\n", LAST_RCVD, err);
                goto out_close;
        }
 
        strcpy(uuid, lsd->lsd_uuid);
        *first_mount = (lsd->lsd_mount_count == 0);
        CDEBUG(D_MOUNT, "UUID from %s: %s, init=%d\n",
               LAST_RCVD, uuid, *first_mount);
 
out_close:
        filp_close(file, 0);
out:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        OBD_FREE(lsd, sizeof(*lsd));
        return(err);
}

/* Get the log "profile" from a remote MGS and process it.
  FIXME  If remote doesn't exist, try local
  This func should work for both clients and servers */
int lustre_get_process_log(struct super_block *sb, char *profile,
                           struct config_llog_instance *cfg)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        struct lustre_handle mgc_conn = {0, };
        struct obd_export *exp;
        struct llog_ctxt *ctxt;
        int err, rc;
        LASSERT(mgc);

        err = obd_connect(&mgc_conn, mgc, &(mgc->obd_uuid), NULL);
        if (err) {
                CERROR("cannot connect to MGS: rc = %d\n", err);
                return (err);
        }
        
        exp = class_conn2export(&mgc_conn);

        ctxt = llog_get_context(exp->exp_obd, LLOG_CONFIG_REPL_CTXT);
#if 0
        /* For debugging, it's useful to just dump the log */
        rc = class_config_dump_llog(ctxt, profile, cfg);
#endif
        rc = class_config_parse_llog(ctxt, profile, cfg);

        switch (rc) {
        case 0:
                break;
        case -EINVAL:
                LCONSOLE_ERROR("%s: The configuration '%s' could not be read "
                               "from the MGS.  Make sure this client and the "
                               "MGS are running compatible versions of "
                               "Lustre.\n",
                               mgc->obd_name, profile);
                /* fall through */
        default:
                CERROR("class_config_parse_llog failed: rc = %d\n", rc);
                break;
        }

        /* We don't so much care about errors in cleaning up the config llog
         * connection, as we have already read the config by this point. */
        err = obd_disconnect(exp);
        if (err)
                CERROR("disconnect failed: rc = %d\n", err);
        
        return (rc);
}

static int lustre_update_llog(struct obd_device *obd)
{
        int err = 0;

        // FIXME this should be called from lov_add_obd?
#if 0
        if (mgcobd->cfobd_logs_info.ost_number > 0) {
                struct obd_ioctl_data ioc_data = { 0 };
                CDEBUG(D_MOUNT, "update new logs.\n");
                err = obd_iocontrol(OBD_IOC_UPDATE_LOG, obd->obd_self_export,
                                    sizeof ioc_data, &ioc_data, NULL);
                if (err)
                        CERROR("Failed to update logs.\n");
        }
#endif
      return err;
}


static int do_lcfg(char *cfgname, lnet_nid_t nid, int cmd,
                   char *s1, char *s2, char *s3, char *s4)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg    * lcfg = NULL;
        int err;
               
        CDEBUG(D_ERROR, "lcfg %s %#x %s %s %s %s\n", cfgname, cmd, s1, s2, s3, s4); 

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

static int lustre_start_simple(char *obdname, char *type, char *s1, char *s2)
{
        int err;
        CDEBUG(D_MOUNT, "Starting obd %s\n", obdname);

        err = do_lcfg(obdname, 0, LCFG_ATTACH, type, obdname/*uuid*/, 0, 0);
        if (err) {
                CERROR("%s attach error %d\n", obdname, err);
                return(err);
        }
        err = do_lcfg(obdname, 0, LCFG_SETUP, s1, s2, 0, 0);
        if (err) {
                CERROR("%s setup error %d\n", obdname, err);
                do_lcfg(obdname, 0, LCFG_DETACH, 0, 0, 0, 0);
        }
        return err;
}

/* Set up a MGS to serve startup logs */
static int lustre_start_mgs(struct super_block *sb, struct vfsmount *mnt)
{
        char*  mgsname;
        int    mgsname_size, err = 0;

        mgsname_size = 2 * sizeof(sb) + 5;
        OBD_ALLOC(mgsname, mgsname_size);
        if (!mgsname)
                return (-ENOMEM);
        sprintf(mgsname, "MGS_%p", sb);

        CDEBUG(D_MOUNT, "Start MGS service %s\n", mgsname);

        err = lustre_register_mount(mgsname, sb, mnt);

        if (!err &&
            ((err = lustre_start_simple(mgsname, LUSTRE_MGS_NAME, 0, 0)))) 
                lustre_deregister_mount(mgsname);
        
        if (err)                                
                LCONSOLE_ERROR("Failed to start MGS %s (%d).  Is the 'mgs' "
                               "module loaded?\n", mgsname, err);

        OBD_FREE(mgsname, mgsname_size);

        return err;
}

static void lustre_stop_mgs(struct super_block *sb)
{
        struct obd_device *obd;
        char mgsname[2 * sizeof(sb) + 5];

        sprintf(mgsname, "MGS_%p", sb);
 
        CDEBUG(D_MOUNT, "Stop MGS service %s\n", mgsname);

        obd = class_name2obd(mgsname);
        if (!obd) {
                CDEBUG(D_CONFIG, "mgs %s not running\n", mgsname);
                return;
        }

        class_manual_cleanup(obd);
}

/* Set up a mgcobd to process startup logs */
static int lustre_start_mgc(struct super_block *sb, struct vfsmount *mnt)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *obd;
        char*  mgcname;
        int    mgcname_size, err = 0, i;
        lnet_nid_t nid;
        LASSERT(lsi->lsi_lmd);
        
        if (lsi->lsi_lmd->lmd_mgsnid_count == 0) {
                LCONSOLE_ERROR("No NIDs for the MGS were given.\n");
                return (-EINVAL);
        }

        mgcname_size = 2 * sizeof(sb) + 5;
        OBD_ALLOC(mgcname, mgcname_size);
        if (!mgcname)
                GOTO(out, err = -ENOMEM);
        sprintf(mgcname, "MGC_%p", sb);
        
        CDEBUG(D_MOUNT, "Start MGC %s\n", mgcname);

        /* register a mount for the mgc so it can call mgc_fs_setup() */
        if (mnt != NULL) {
                err = lustre_register_mount(mgcname, sb, mnt);
                if (err) 
                        GOTO(out_free, err);
        }
        
        /* Add a uuid for the MGS */
        nid = lsi->lsi_lmd->lmd_mgsnid[0];
        err = do_lcfg(mgcname, nid, LCFG_ADD_UUID, libcfs_nid2str(nid), 0,0,0);
        if (err < 0)
                GOTO(out_dereg, err);

        /* Start the MGC */
        if ((err = lustre_start_simple(mgcname, LUSTRE_MDC_NAME/*LUSTRE_MGC_NAME*/, "MGS", 
                                       libcfs_nid2str(nid))))
                GOTO(out_dereg, err);
        
        /* Add the redundant MGS's */
        for (i = 1; i < lsi->lsi_lmd->lmd_mgsnid_count; i++) {
                nid = lsi->lsi_lmd->lmd_mgsnid[i];
                err = do_lcfg(mgcname, nid, LCFG_ADD_UUID, libcfs_nid2str(nid),
                              0, 0, 0);
                if (err) {
                        CERROR("Add uuid for %s failed %d\n", 
                               libcfs_nid2str(nid), err);
                        continue;
                }
                err = do_lcfg(mgcname, 0, LCFG_ADD_CONN, libcfs_nid2str(nid),
                              0, 0, 0);
                if (err) 
                        CERROR("Add conn for %s failed %d\n", 
                               libcfs_nid2str(nid), err);
        }
        
        /* Keep the mgc info in the sb */
        obd = class_name2obd(mgcname);
        if (!obd) {
                CERROR("Can't find mgcobd %s\n", mgcname);
                GOTO(out_dereg, err = -ENOTCONN);
        }
        lsi->lsi_mgc = obd;

out_free:
        OBD_FREE(mgcname, mgcname_size);
out:
        return err;
out_dereg:
        lustre_deregister_mount(mgcname);
        goto out_free;
}

static void lustre_stop_mgc(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *obd;

        obd = lsi->lsi_mgc;
        if (obd) 
                class_manual_cleanup(obd);
        lsi->lsi_mgc = NULL;
}
          
/* Start targets */
static int server_start_targets(struct super_block *sb, struct vfsmount *mnt)
{
        struct obd_ioctl_data ioc_data = { 0 };
        struct obd_device *obd;
        struct lustre_sb_info *lsi = s2lsi(sb);
        int err;
                                                                                       
                                        
        CDEBUG(D_MOUNT, "starting target %s\n", lsi->lsi_ldd->ldd_svname);
        
        /* If we're an MDT, make sure the global MDS is running */
        if (lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_MDT) {
                /* make sure (what will be called) the MDS is started */
                obd = class_name2obd("MDS");
                if (!obd) {
                        //FIXME pre-rename, should eventually be LUSTRE_MDS_NAME
                        err = lustre_start_simple("MDS", LUSTRE_MDT_NAME, 0, 0);
                        if (err) 
                                CERROR("failed to start MDS: %d\n", err);
                }
        }

        /* If we're an OST, make sure the global OSS is running */
        if (lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_OST) {
                /* make sure OSS is started */
                obd = class_name2obd("OSS");
                if (!obd) 
                        err = lustre_start_simple("OSS", LUSTRE_OSS_NAME, 0, 0);
        }

        /* Get a new index if needed */
        if (lsi->lsi_ldd->ldd_flags & LDD_F_NEED_INDEX) {
                // FIXME implement
                CERROR("Need new target index from MGS!\n");
                // FIXME rewrite last_rcvd, ldd (for new svname)
        }

        /* The MGC starts targets using the svname llog */
        obd = lsi->lsi_mgc;
        LASSERT(obd);

        err = lustre_register_mount(lsi->lsi_ldd->ldd_svname, sb, mnt);
        if (err) 
                return (err);

        ioc_data.ioc_inllen1 = strlen(lsi->lsi_ldd->ldd_svname) + 1;
        ioc_data.ioc_inlbuf1 = lsi->lsi_ldd->ldd_svname;
        
        err = obd_iocontrol(OBD_IOC_START, obd->obd_self_export,
                            sizeof ioc_data, &ioc_data, NULL);
        if (err) {
                CERROR("failed to start server %s: %d\n",
                       lsi->lsi_ldd->ldd_svname, err);
                lustre_deregister_mount(lsi->lsi_ldd->ldd_svname);
        }

        // FIXME stop MDS, OSS on err?
        return(err);
}

/***************** mount **************/

struct lustre_sb_info *lustre_init_lsi(struct super_block *sb)
{
        struct lustre_sb_info *lsi = NULL;

        OBD_ALLOC(lsi, sizeof(*lsi));
        if (!lsi)
                return(NULL);
        OBD_ALLOC(lsi->lsi_lmd, sizeof(*lsi->lsi_lmd));
        if (!lsi->lsi_lmd) {
                OBD_FREE(lsi, sizeof(*lsi));
                return(NULL);
        }

        s2lsi_nocast(sb) = lsi;
        atomic_set(&lsi->lsi_mounts, 0);
        return(lsi);
}

void lustre_free_lsi(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        ENTRY;

        if (lsi != NULL) {
                if (lsi->lsi_ldd != NULL) 
                        OBD_FREE(lsi->lsi_ldd, sizeof(*lsi->lsi_ldd));

                if (lsi->lsi_lmd != NULL) {
                        if (lsi->lsi_lmd->lmd_dev != NULL) 
                                OBD_FREE(lsi->lsi_lmd->lmd_dev, 
                                         strlen(lsi->lsi_lmd->lmd_dev) + 1);
                        if (lsi->lsi_lmd->lmd_opts != NULL) 
                                OBD_FREE(lsi->lsi_lmd->lmd_opts, 
                                         strlen(lsi->lsi_lmd->lmd_opts) + 1);
                        OBD_FREE(lsi->lsi_lmd, sizeof(*lsi->lsi_lmd));
                }

                LASSERT(lsi->lsi_llsbi == NULL);
                
                lustre_deregister_mount_all(lsi->lsi_srv_mnt);

                OBD_FREE(lsi, sizeof(*lsi));
                s2lsi_nocast(sb) = NULL;
        }
        
        EXIT;
}
           

/*************** server mount ******************/

/* Kernel mount using mount options in MOUNT_DATA_FILE */
static struct vfsmount *lustre_kern_mount(struct super_block *sb)
{
        struct lvfs_run_ctxt mount_ctxt;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct lustre_disk_data *ldd;
        struct lustre_mount_data *lmd = lsi->lsi_lmd;
        struct vfsmount *mnt;
        char *options = NULL;
        unsigned long page, s_flags;
        int err;

        OBD_ALLOC(ldd, sizeof(*ldd));
        if (!ldd)
                return(ERR_PTR(-ENOMEM));

        /* In the past, we have always used flags = 0.
           Note ext3/ldiskfs can't be mounted ro. */
        s_flags = sb->s_flags;

        /* Pre-mount ext3 to read the MOUNT_DATA_FILE */
        CDEBUG(D_MOUNT, "Pre-mount ext3 %s\n", lmd->lmd_dev);
        mnt = do_kern_mount("ext3", s_flags, lmd->lmd_dev, 0);
        if (IS_ERR(mnt)) {
                err = PTR_ERR(mnt);
                CERROR("premount failed: err = %d\n", err);
                goto out_free;
        }

        OBD_SET_CTXT_MAGIC(&mount_ctxt);
        mount_ctxt.pwdmnt = mnt;
        mount_ctxt.pwd = mnt->mnt_root;
        mount_ctxt.fs = get_ds();

        err = parse_mount_data(&mount_ctxt, ldd); 
        unlock_mntput(mnt);

        if (err) {
                CERROR("premount parse options failed: err = %d\n", err);
                goto out_free;
        }

        /* Done with our pre-mount, now do the real mount. */

        /* Glom up mount options */
        page = __get_free_page(GFP_KERNEL);
        if (!page) {
                err = -ENOMEM;
                goto out_free;
        }
        options = (char *)page;
        memset(options, 0, PAGE_SIZE);
        strcpy(options, ldd->ldd_mount_opts);
        
        /* Add in any mount-line options */
        if (lmd->lmd_opts && (*(lmd->lmd_opts) != 0)) {
                if (*options != 0) 
                        strcat(options, ",");
                strcat(options, lmd->lmd_opts);
        }

        /* Special permanent mount flags */
        if (IS_OST(ldd)) 
            s_flags |= MS_NOATIME | MS_NODIRATIME;

        CDEBUG(D_MOUNT, "kern_mount: %s %s %s\n",
               MT_STR(ldd), lmd->lmd_dev, options);
        mnt = do_kern_mount(MT_STR(ldd), s_flags, lmd->lmd_dev, 
                            (void *)options);
        free_page(page);
        if (IS_ERR(mnt)) {
                err = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: err = %d\n", err);
                goto out_free;
        }

        lsi->lsi_ldd = ldd;   /* freed at lsi cleanup */
        CDEBUG(D_SUPER, "%s: mnt = %p\n", lmd->lmd_dev, mnt);
        return(mnt);

out_free:
        OBD_FREE(ldd, sizeof(*ldd));
        lsi->lsi_ldd = NULL;    
        return(ERR_PTR(err));
}
                      
static void server_put_super(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *obd;
                                                                                       
        CDEBUG(D_MOUNT, "server put_super %s\n", lsi->lsi_ldd->ldd_svname);
                                                                                       
        lustre_update_llog(obd);
                                                                                       
        obd = class_name2obd(lsi->lsi_ldd->ldd_svname);
        if (obd) {
                CDEBUG(D_MOUNT, "stopping %s\n", obd->obd_name);
                if (lsi->lsi_flags & LSI_UMOUNT_FORCE)
                        obd->obd_force = 1;
                if (lsi->lsi_flags & LSI_UMOUNT_FAILOVER)
                        obd->obd_fail = 1;
                class_manual_cleanup(obd);
        } else {
                CERROR("no obd %s\n", lsi->lsi_ldd->ldd_svname);
        }

        //class_del_profile(lsi->lsi_ldd->ldd_svname); /* if it exists */
                                                                                       
        /* if this was an MDT, and there are no more MDT's, clean up the MDS */
        if ((lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_MDT) &&
            (obd = class_name2obd("MDS"))) {
                //FIXME pre-rename, should eventually be LUSTRE_MDT_NAME
                struct obd_type *type = class_search_type(LUSTRE_MDS_NAME);
                if (!type || !type->typ_refcnt) {
                        /* nobody is using the MDT type, clean the MDS */
                        if (lsi->lsi_flags & LSI_UMOUNT_FORCE)
                                obd->obd_force = 1;
                        if (lsi->lsi_flags & LSI_UMOUNT_FAILOVER)
                                obd->obd_fail = 1;
                        class_manual_cleanup(obd);
                }
        }

        /* if this was an OST, and there are no more OST's, clean up the OSS */
        if ((lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_OST) &&
            (obd = class_name2obd("OSS"))) {
                struct obd_type *type = class_search_type(LUSTRE_OST_NAME);
                if (!type || !type->typ_refcnt) {
                        /* nobody is using the OST type, clean the OSS */
                        if (lsi->lsi_flags & LSI_UMOUNT_FORCE)
                                obd->obd_force = 1;
                        if (lsi->lsi_flags & LSI_UMOUNT_FAILOVER)
                                obd->obd_fail = 1;
                        class_manual_cleanup(obd);
                }
        }

        /* If they wanted the mgs to stop separately from the mdt, they
           should have put it on a different device. */ 
        if (lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_MGMT) 
                lustre_stop_mgs(sb);

        /* clean the mgc and sb */
        lustre_common_put_super(sb);
        
        /* drop the kernel mount from server_fill_super */
        unlock_mntput(lsi->lsi_srv_mnt);
}

static void server_umount_begin(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
                                                                                     
        CDEBUG(D_MOUNT, "umount -f\n");
        /* umount = normal
           umount -f = failover
           no third way to do LSI_UMOUNT_FORCE */
        lsi->lsi_flags |= LSI_UMOUNT_FAILOVER;
}

#define log2(n) ffz(~(n))
#define LUSTRE_SUPER_MAGIC 0x0BD00BD1

static struct super_operations server_ops =
{
        //.statfs         = NULL,
        .put_super      = server_put_super,
        .umount_begin   = server_umount_begin, /* umount -f */
};

static int server_fill_super_common(struct super_block *sb)
{
        struct inode *root = 0;
        //struct ll_sb_info *lsi = ll_s2lsi(sb);
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
        struct vfsmount *mnt;
        int mgs_service = 0, i = 0, err;
        ENTRY;

        /* the One True Mount */
        mnt = lustre_kern_mount(sb);
        if (IS_ERR(mnt)) {
                err = PTR_ERR(mnt);
                CERROR("Unable to mount device %s: %d\n", 
                      lsi->lsi_lmd->lmd_dev, err);
                GOTO(out, err);
        }
        lsi->lsi_srv_mnt = mnt;

        LASSERT(lsi->lsi_ldd);
        CDEBUG(D_MOUNT, "Found service %s for fs '%s' on device %s\n",
               lsi->lsi_ldd->ldd_svname, lsi->lsi_ldd->ldd_fsname, 
               lsi->lsi_lmd->lmd_dev);

        /* append ldd nids to lmd nids */
        while ((lsi->lsi_ldd->ldd_mgsnid[i] != LNET_NID_ANY) &&
               (lsi->lsi_lmd->lmd_mgsnid_count < MAX_FAILOVER_NIDS))
                lsi->lsi_lmd->lmd_mgsnid[lsi->lsi_lmd->lmd_mgsnid_count++] = 
                lsi->lsi_ldd->ldd_mgsnid[i++];

        if (lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_MGMT) {
                err = lustre_start_mgs(sb, mnt);
                if (err) {
                        CERROR("ignoring Failed MGS start!!\n");
                        //GOTO(out_mnt, err);
                } else {
                        mgs_service++;
                }
        }

        err = lustre_start_mgc(sb, mnt);
        if (err) 
                GOTO(out_mnt, err);

        /* Set up all obd devices for service */
        err = server_start_targets(sb, mnt);
        if (err < 0) {
                CERROR("Unable to start targets: %d\n", err);
                GOTO(out_mnt, err);
        }
        
        /* FIXME overmount client here,
           or can we just start a client log and client_fill_super on this sb? 
           have to fix up the s_ops after! */
        err = server_fill_super_common(sb);
        if (err) 
                GOTO(out_mnt, err);

        RETURN(0);

out_mnt:
        if (mgs_service)
                lustre_stop_mgs(sb);
        /* mgc is stopped in lustre_fill_super */
        unlock_mntput(mnt);
out:
        //if (lsi->lsi_ldd) class_del_profile(lsi->lsi_ldd->ldd_svname);
        RETURN(err);
}


/*************** mount common betweeen server and client ***************/

/* Common umount */
void lustre_common_put_super(struct super_block *sb)
{
        CDEBUG(D_MOUNT, "common put super %p\n", sb);
        
        lustre_stop_mgc(sb);
        lustre_free_lsi(sb);
}      

static void print_lmd(struct lustre_mount_data *lmd)
{
        int i;

        CDEBUG(D_MOUNT, "mount data\n"); 
        if (!lmd->lmd_mgsnid_count) 
                CDEBUG(D_MOUNT, "no MGS nids\n");
        else for (i = 0; i < lmd->lmd_mgsnid_count; i++) {
                CDEBUG(D_MOUNT, "nid %d:  %s\n", i, 
                       libcfs_nid2str(lmd->lmd_mgsnid[i]));
        }
        if (lmd_is_client(lmd)) 
                CDEBUG(D_MOUNT, "fsname:  %s\n", lmd->lmd_dev);
        else
                CDEBUG(D_MOUNT, "device:  %s\n", lmd->lmd_dev);
        CDEBUG(D_MOUNT, "flags:   %x\n", lmd->lmd_flags);
        if (lmd->lmd_opts)
                CDEBUG(D_MOUNT, "options: %s\n", lmd->lmd_opts);
}

static int parse_lmd(char *options, struct lustre_mount_data *lmd)
{
        char *s1, *s2, *devname = NULL;
        struct lustre_mount_data *raw = (struct lustre_mount_data *)options;
        ENTRY;

        LASSERT(lmd);
        if (!options) {
                LCONSOLE_ERROR("Missing mount data: check that " 
                               "/sbin/mount.lustre is installed.\n");
                RETURN(-EINVAL);          
        }
        
        /* Try to detect old lmd data in options */
        if ((raw->lmd_magic & 0xffffff00) == (LMD_MAGIC & 0xffffff00)) { 
                LCONSOLE_ERROR("You're using an old version of "        
                               "/sbin/mount.lustre.  Please install version "   
                               "1.%d\n", LMD_MAGIC & 0xFF);     
                RETURN(-EINVAL);
        }
        lmd->lmd_magic = LMD_MAGIC;

        /* default flags */
        lmd->lmd_flags |= LMD_FLG_MNTCNF | LMD_FLG_RECOVER;

        s1 = options;
        while(*s1) {
                while (*s1 == ' ' || *s1 == ',')
                        s1++;
                if (strncmp(s1, "recov", 5) == 0)
                        lmd->lmd_flags |= LMD_FLG_RECOVER;
                if (strncmp(s1, "norecov", 7) == 0)
                        lmd->lmd_flags &= ~LMD_FLG_RECOVER;
                /* Linux 2.4 doesn't pass the device, so we stuck it at the 
                   end of the options. */
                if (strncmp(s1, "device=", 7) == 0) {
                        devname = s1 + 7;
                        /* terminate options right before device.  device
                           must be the last one. */
                        *s1 = 0;
                }
                s2 = strstr(s1, ",");
                if (s2 == NULL) 
                        break;
                s1 = s2 + 1;
        }

        if (!devname) {
                LCONSOLE_ERROR("Can't find the device name "
                               "(need mount option 'device=...')\n");
                goto invalid;
        }

        if (strchr(devname, ',')) {
                LCONSOLE_ERROR("Device name must be the final option\n");
                goto invalid;
        }

        s1 = devname;
        /* Get MGS nids if client mount */
        while ((s2 = strchr(s1, ':'))) {
                lnet_nid_t nid;
                *s2 = 0;
                lmd->lmd_flags = LMD_FLG_CLIENT;
                nid = libcfs_str2nid(s1);
                if (nid == LNET_NID_ANY) {
                        LCONSOLE_ERROR("Can't parse NID '%s'\n", s1);
                        goto invalid;
                }
                if (lmd->lmd_mgsnid_count >= MAX_FAILOVER_NIDS) {
                        LCONSOLE_ERROR("Too many NIDs: '%s'\n", s1);
                        goto invalid;
                }
                lmd->lmd_mgsnid[lmd->lmd_mgsnid_count++] = nid;
                s1 = s2 + 1;
        }

        if (lmd_is_client(lmd)) {
                /* Remove leading /s from fsname */
                while (*++s1 == '/')
                        ;
        }

        if (*s1 == 0) {
                LCONSOLE_ERROR("No filesytem specified\n");
                goto invalid;
        }

        /* freed in lustre_free_lsi */
        OBD_ALLOC(lmd->lmd_dev, strlen(s1) + 1);
        if (!lmd->lmd_dev) 
                RETURN(-ENOMEM);
        strcpy(lmd->lmd_dev, s1);
        
        /* save mount options */
        s1 = options + strlen(options) - 1;
        while (s1 >= options && (*s1 == ',' || *s1 == ' ')) 
                *s1-- = 0;
        if (*options != 0) {
                /* freed in lustre_free_lsi */
                OBD_ALLOC(lmd->lmd_opts, strlen(options) + 1);
                if (!lmd->lmd_opts) 
                        RETURN(-ENOMEM);
                strcpy(lmd->lmd_opts, options);
        }

        lmd->lmd_magic = LMD_MAGIC;

        print_lmd(lmd);
        RETURN(0);

invalid:
        CERROR("Bad mount options %s\n", options);
        RETURN(-EINVAL);          
}


/* Common mount */
int lustre_fill_super(struct super_block *sb, void *data, int silent)
{
        struct lustre_mount_data *lmd;
        struct lustre_sb_info *lsi;
        int err;
        ENTRY;
 
        CDEBUG(D_MOUNT|D_VFSTRACE, "VFS Op: sb %p\n", sb);
        
        lsi = lustre_init_lsi(sb);
        if (!lsi) 
                RETURN(-ENOMEM);
        lmd = lsi->lsi_lmd;

        /* Figure out the lmd from the mount options */
        if (parse_lmd((char *)data, lmd)) {
                lustre_free_lsi(sb);
                RETURN(-EINVAL);
        }

        if (lmd_is_client(lmd)) {
                if (!client_fill_super) {
                        LCONSOLE_ERROR("Nothing registered for client mount!"
                               " Is llite module loaded?\n");
                        err = -ENOSYS;
                } else {
                        char mgcname[64];
                        snprintf(mgcname, sizeof(mgcname), "mgc-client-%s", 
                                 lmd->lmd_dev);
                        CDEBUG(D_MOUNT, "Mounting client for fs %s\n", lmd->lmd_dev);
                        err = lustre_start_mgc(sb, NULL);
                        if (err) {
                                lustre_free_lsi(sb);
                                RETURN(err);
                        }
                        /* Connect and start */
                        /* (should always be ll_fill_super) */
                        err = (*client_fill_super)(sb);
                }
        } else {
                CDEBUG(D_MOUNT, "Mounting server\n");
                err = server_fill_super(sb);
                /* calls lustre_start_mgc after the mount */
        }
                                                                                
        if (err){
                CERROR("Unable to mount %s\n", lmd->lmd_dev);
                lustre_stop_mgc(sb);
                lustre_free_lsi(sb);
        }
        RETURN(err);
} 
                                                                                

/* We can't call ll_fill_super by name because it lives in a module that
   must be loaded after this one. */
void lustre_register_client_fill_super(int (*cfs)(struct super_block *sb))
{
        client_fill_super = cfs;
}

/***************** FS registration ******************/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
/* 2.5 and later */
struct super_block * lustre_get_sb(struct file_system_type *fs_type,
                               int flags, const char *devname, void * data)
{
        /* calls back in fill super */
        /* we could append devname= onto options (*data) here, 
           but 2.4 doesn't get devname.  So we do it in mount_lustre.c */
        return get_sb_nodev(fs_type, flags, data, lustre_fill_super);
}

struct file_system_type lustre_fs_type = {
        .owner        = THIS_MODULE,
        .name         = "lustre",
        .get_sb       = lustre_get_sb,
        .kill_sb      = kill_anon_super,
        .fs_flags     = FS_BINARY_MOUNTDATA,
};

#else
/* 2.4 */
static struct super_block *lustre_read_super(struct super_block *sb,
                                             void *data, int silent)
{
        int err;
        ENTRY;

        err = lustre_fill_super(sb, data, silent);
        if (err)
                RETURN(NULL);
        RETURN(sb);
}

static struct file_system_type lustre_fs_type = {
        .owner          = THIS_MODULE,
        .name           = "lustre",
        .fs_flags       = FS_NFSEXP_FSID,
        .read_super     = lustre_read_super,
};
#endif

int lustre_register_fs(void)
{
        return register_filesystem(&lustre_fs_type);
}

int lustre_unregister_fs(void)
{
        return unregister_filesystem(&lustre_fs_type);
}

EXPORT_SYMBOL(lustre_register_client_fill_super);
EXPORT_SYMBOL(lustre_common_put_super);
EXPORT_SYMBOL(lustre_get_process_log);
EXPORT_SYMBOL(lustre_get_mount);
EXPORT_SYMBOL(lustre_put_mount);


