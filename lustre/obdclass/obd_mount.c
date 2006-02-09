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
#define D_MOUNT D_SUPER|D_CONFIG|D_WARNING
#define PRINT_CMD LCONSOLE
#define PRINT_MASK D_WARNING

#include <linux/obd.h>
#include <linux/lvfs.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd_class.h>
#include <lustre/lustre_user.h>
#include <linux/version.h> 
#include <linux/lustre_log.h>
#include <linux/lustre_disk.h>
                      
static int (*client_fill_super)(struct super_block *sb) = NULL;


/*********** mount lookup *********/

DECLARE_MUTEX(lustre_mount_info_lock);
struct list_head server_mount_info_list = LIST_HEAD_INIT(server_mount_info_list);

static struct lustre_mount_info *server_find_mount(char *name)
{
        struct list_head *tmp;
        struct lustre_mount_info *lmi;
        
        list_for_each(tmp, &server_mount_info_list) {
                lmi = list_entry(tmp, struct lustre_mount_info, lmi_list_chain);
                if (strcmp(name, lmi->lmi_name) == 0) 
                        return(lmi);
        }
        return(NULL);
}

/* we must register an obd for a mount before we call the setup routine.  
   *_setup will call lustre_get_mount to get the mnt struct
   by obd_name, since we can't pass the pointer to setup. */
static int server_register_mount(char *name, struct super_block *sb,
                          struct vfsmount *mnt)
{
        struct lustre_mount_info *lmi;
        char *name_cp;
        ENTRY;

        LASSERT(mnt);
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
        lmi->lmi_mnt = mnt;
        list_add(&lmi->lmi_list_chain, &server_mount_info_list);
         
        up(&lustre_mount_info_lock);

        CDEBUG(D_MOUNT, "reg_mnt %p from %s, vfscount=%d\n", 
               lmi->lmi_mnt, name, atomic_read(&lmi->lmi_mnt->mnt_count));

        RETURN(0);
}

/* when an obd no longer needs a mount */
static int server_deregister_mount(char *name)
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
        
        CDEBUG(D_MOUNT, "dereg_mnt %p from %s, vfscount=%d\n", 
               lmi->lmi_mnt, name, atomic_read(&lmi->lmi_mnt->mnt_count));
        
        OBD_FREE(lmi->lmi_name, strlen(lmi->lmi_name) + 1);
        list_del(&lmi->lmi_list_chain);
        OBD_FREE(lmi, sizeof(*lmi));
        up(&lustre_mount_info_lock);

        RETURN(0);
}

/* Deregister anyone referencing the mnt. Everyone should have
   put_mount in *_cleanup, but this is a catch-all in case of err... */
static void server_deregister_mount_all(struct vfsmount *mnt)
{
        struct list_head *tmp, *n;
        struct lustre_mount_info *lmi;

        if (!mnt)
                return;

        down(&lustre_mount_info_lock);
        list_for_each_safe(tmp, n, &server_mount_info_list) {
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
struct lustre_mount_info *server_get_mount(char *name)
{
        struct lustre_mount_info *lmi;
        struct lustre_sb_info *lsi;
        ENTRY;

        down(&lustre_mount_info_lock);

        lmi = server_find_mount(name);
        if (!lmi) {
                up(&lustre_mount_info_lock);
                CERROR("Can't find mount for %s\n", name);
                RETURN(NULL);
        }
        lsi = s2lsi(lmi->lmi_sb);
        mntget(lmi->lmi_mnt);
        atomic_inc(&lsi->lsi_mounts);
        
        up(&lustre_mount_info_lock);
        
        CDEBUG(D_MOUNT, "get_mnt %p from %s, refs=%d, vfscount=%d\n", 
               lmi->lmi_mnt, name, atomic_read(&lsi->lsi_mounts),
               atomic_read(&lmi->lmi_mnt->mnt_count));

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
int server_put_mount(char *name, struct vfsmount *mnt)
{
        struct lustre_mount_info *lmi;
        struct lustre_sb_info *lsi;
        ENTRY;

        down(&lustre_mount_info_lock);
        lmi = server_find_mount(name);
        if (!lmi) {
                up(&lustre_mount_info_lock);
                CERROR("Can't find mount for %s\n", name);
                RETURN(-ENOENT);
        }
        lsi = s2lsi(lmi->lmi_sb);
        LASSERT(lmi->lmi_mnt == mnt);
        unlock_mntput(lmi->lmi_mnt);

        CDEBUG(D_MOUNT, "put_mnt %p from %s, refs=%d, vfscount=%d\n", 
               lmi->lmi_mnt, name, atomic_read(&lsi->lsi_mounts),
               atomic_read(&lmi->lmi_mnt->mnt_count));

        if (lustre_put_lsi(lmi->lmi_sb)) {
                CDEBUG(D_MOUNT, "Last put of mnt %p from %s, vfscount=%d\n", 
                       lmi->lmi_mnt, name, 
                       atomic_read(&lmi->lmi_mnt->mnt_count));
                /* last mount is the One True Mount */
                if (atomic_read(&lmi->lmi_mnt->mnt_count) > 1)
                        CERROR("%s: mount busy, vfscount=%d!\n", name,
                               atomic_read(&lmi->lmi_mnt->mnt_count));
        }
        up(&lustre_mount_info_lock);

        /* this obd should never need the mount again */
        server_deregister_mount(name);
        
        RETURN(0);
}


/******* mount helper utilities *********/

static void ldd_print(struct lustre_disk_data *ldd)
{
        int i;

        PRINT_CMD(PRINT_MASK, "  disk data:\n"); 
        PRINT_CMD(PRINT_MASK, "config:  %d\n", ldd->ldd_config_ver);
        PRINT_CMD(PRINT_MASK, "fs:      %s\n", ldd->ldd_fsname);
        PRINT_CMD(PRINT_MASK, "server:  %s\n", ldd->ldd_svname);
        PRINT_CMD(PRINT_MASK, "index:   %04x\n", ldd->ldd_svindex);
        PRINT_CMD(PRINT_MASK, "flags:   %#x\n", ldd->ldd_flags);
        PRINT_CMD(PRINT_MASK, "diskfs:  %s\n", MT_STR(ldd));
        PRINT_CMD(PRINT_MASK, "options: %s\n", ldd->ldd_mount_opts);
        if (!ldd->ldd_mgsnid_count) 
                PRINT_CMD(PRINT_MASK, "no MGS nids\n");
        else for (i = 0; i < ldd->ldd_mgsnid_count; i++) {
                PRINT_CMD(PRINT_MASK, "mgs nid %d:  %s\n", i, 
                       libcfs_nid2str(ldd->ldd_mgsnid[i]));
        }
        if (!ldd->ldd_failnid_count)
                PRINT_CMD(PRINT_MASK, "no failover nids\n");
        else for (i = 0; i < ldd->ldd_failnid_count; i++) {
                PRINT_CMD(PRINT_MASK, "failover nid %d:  %s\n", i,
                          libcfs_nid2str(ldd->ldd_failnid[i]));
        }
}

static int ldd_parse(struct lvfs_run_ctxt *mount_ctxt, 
                           struct lustre_disk_data *ldd)
{       
        struct lvfs_run_ctxt saved;
        struct file *file;
        loff_t off = 0;
        unsigned long len;
        int rc;
        ENTRY;
               
        push_ctxt(&saved, mount_ctxt, NULL);
        
        file = filp_open(MOUNT_DATA_FILE, O_RDONLY, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open %s: rc = %d\n", MOUNT_DATA_FILE, rc);
                GOTO(out, rc);
        }
 
        len = file->f_dentry->d_inode->i_size;
        CDEBUG(D_MOUNT, "Have %s, size %lu\n", MOUNT_DATA_FILE, len);
        if (len != sizeof(*ldd)) {
                CERROR("disk data size does not match: see %lu expect %u\n", 
                       len, sizeof(*ldd));
                GOTO(out_close, rc = -EINVAL);
        }

        rc = lustre_fread(file, ldd, len, &off);
        if (rc != len) {
                CERROR("error reading %s: read %d of %lu\n", 
                       MOUNT_DATA_FILE, rc, len);
                GOTO(out_close, rc = -EINVAL);
        }
        rc = 0;

        if (ldd->ldd_magic != LDD_MAGIC) {
                /* FIXME add swabbing support */
                CERROR("Bad magic in %s: %x!=%x\n", MOUNT_DATA_FILE, 
                       ldd->ldd_magic, LDD_MAGIC);
                GOTO(out_close, rc = -EINVAL);
        }
        
        if (ldd->ldd_feature_incompat & ~LDD_INCOMPAT_SUPP) {
                CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
                       ldd->ldd_svname, 
                       ldd->ldd_feature_incompat & ~LDD_INCOMPAT_SUPP);
                GOTO(out_close, rc = -EINVAL);
        }
        if (ldd->ldd_feature_rocompat & ~LDD_ROCOMPAT_SUPP) {
                CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
                       ldd->ldd_svname,  
                       ldd->ldd_feature_rocompat & ~LDD_ROCOMPAT_SUPP);
                /* Do something like remount filesystem read-only */
                GOTO(out_close, rc = -EINVAL);
        }

        ldd_print(ldd);

out_close:
        filp_close(file, 0);
out:
        pop_ctxt(&saved, mount_ctxt, NULL);
        RETURN(rc);
}

static int ldd_write(struct lvfs_run_ctxt *mount_ctxt, 
                     struct lustre_disk_data *ldd)
{       
        struct lvfs_run_ctxt saved;
        struct file *file;
        loff_t off = 0;
        unsigned long len = sizeof(struct lustre_disk_data);
        int rc = 0;
        ENTRY;

        LASSERT(ldd->ldd_magic == LDD_MAGIC);
        
        ldd->ldd_config_ver++;  

        push_ctxt(&saved, mount_ctxt, NULL);
        
        file = filp_open(MOUNT_DATA_FILE, O_RDWR, 0644);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("cannot open %s: rc = %d\n", MOUNT_DATA_FILE, rc);
                GOTO(out, rc);
        }
 
        rc = lustre_fwrite(file, ldd, len, &off);
        if (rc != len) {
                CERROR("error writing %s: read %d of %lu\n", 
                       MOUNT_DATA_FILE, rc, len);
                GOTO(out_close, rc = -EINVAL);
        }

        rc = 0;
        ldd_print(ldd);

out_close:
        filp_close(file, 0);
out:
        pop_ctxt(&saved, mount_ctxt, NULL);
        RETURN(rc);
}


/**************** config llog ********************/

/* Get a config log from the MGS and process it.
   This func is called for both clients and servers. */
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
        lcfg = lustre_cfg_new(LCFG_LOG_START, &bufs);
        rc = obd_process_config(mgc, sizeof(*lcfg), lcfg);
        lustre_cfg_free(lcfg);

        if (rc) 
                LCONSOLE_ERROR("%s: The configuration '%s' could not be read "
                               "(%d), mount will fail.\n",
                               mgc->obd_name, logname, rc);

        class_obd_list();
        RETURN(rc);
}


int lustre_end_log(struct super_block *sb, char *logname, 
                       struct config_llog_instance *cfg)
{
        struct lustre_cfg *lcfg;
        struct lustre_cfg_bufs bufs;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        int rc;
        ENTRY;

        LASSERT(mgc);

        /* mgc_process_config */
        lustre_cfg_bufs_reset(&bufs, mgc->obd_name);
        lustre_cfg_bufs_set_string(&bufs, 1, logname);
        if (cfg)
                lustre_cfg_bufs_set(&bufs, 2, cfg, sizeof(*cfg));
        lcfg = lustre_cfg_new(LCFG_LOG_END, &bufs);
        rc = obd_process_config(mgc, sizeof(*lcfg), lcfg);
        lustre_cfg_free(lcfg);
        RETURN(0);
}

/**************** obd start *******************/

static int do_lcfg(char *cfgname, lnet_nid_t nid, int cmd,
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
                LCONSOLE_ERROR("The MGS service was already started from "
                               "server %s\n", lsi->lsi_ldd->ldd_svname);
                RETURN(-EALREADY);
        }

        CDEBUG(D_CONFIG, "Start MGS service %s\n", LUSTRE_MGS_OBDNAME);

        rc = server_register_mount(LUSTRE_MGS_OBDNAME, sb, mnt);

        if (!rc &&
            ((rc = lustre_start_simple(LUSTRE_MGS_OBDNAME, LUSTRE_MGS_NAME, 
                                       LUSTRE_MGS_OBDNAME, 0, 0)))) 
                server_deregister_mount(LUSTRE_MGS_OBDNAME);
        
        if (rc)                                
                LCONSOLE_ERROR("Failed to start MGS '%s' (%d).  Is the 'mgs' "
                               "module loaded?\n", LUSTRE_MGS_OBDNAME, rc);

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

/* Set up a mgcobd to process startup logs */
static int lustre_start_mgc(struct super_block *sb)
{
        struct lustre_handle mgc_conn = {0, };
        struct obd_connect_data ocd = { 0 };
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *obd;
        struct obd_export *exp;
        char *uuid;
        lnet_nid_t nid;
        lnet_process_id_t id;
        int recov_bk;
        int rc = 0, i;
        ENTRY;

        LASSERT(lsi->lsi_lmd);
        
        obd = class_name2obd(LUSTRE_MGC_OBDNAME);
        if (obd) {
                atomic_inc(&obd->u.cli.cl_mgc_refcount);
                /* FIXME There's only one MGC, but users could give different
                   MGS nids on the mount line.  So now do we add new MGS uuids
                   or not?  If there's truly one MGS per site, the MGS uuids
                   _should_ all be the same. Maybe check here?
                */
                
                /* Try all connections, but only once (again). 
                   We don't want to block another target from starting
                   (using its local copy of the log), but we do want to connect
                   if at all possible. */
                CDEBUG(D_MOUNT, "Set MGS reconnect\n");
                recov_bk = 1;
                rc = obd_set_info(obd->obd_self_export,
                                  strlen(KEY_INIT_RECOV_BACKUP),
                                  KEY_INIT_RECOV_BACKUP,
                                  sizeof(recov_bk), &recov_bk);

#if 0
                /* induces a module loop with ptlrpc */
                if (imp->imp_invalid) {
                        /* Resurrect if we previously died */
                        CDEBUG(D_MOUNT, "Reactivate %s %d:%d:%d\n", 
                               imp->imp_obd->obd_name,
                               imp->imp_deactive, imp->imp_invalid, 
                               imp->imp_state);
                        ptlrpc_activate_import(imp);
                        // lustre_reconnect_mgc(obd);
                        ptlrpc_set_import_active(imp, 1);
                        //ptlrpc_recover_import(imp);
                }
#endif
                GOTO(out, rc = 0);
        }

        if (lsi->lsi_lmd->lmd_mgsnid_count == 0) {
                LCONSOLE_ERROR("No NIDs for the MGS were given.\n");
                RETURN(-EINVAL);
        }

        CDEBUG(D_MOUNT, "Start MGC '%s'\n", LUSTRE_MGC_OBDNAME);

        /* Add the first uuid for the MGS */
        nid = lsi->lsi_lmd->lmd_mgsnid[0];
        rc = do_lcfg(LUSTRE_MGC_OBDNAME, nid, LCFG_ADD_UUID, 
                     libcfs_nid2str(nid), 0,0,0);
        if (rc < 0)
                RETURN(rc);

        /* Generate a unique uuid for each MGC - use the 1st non-loopback nid */
        i = 0;
        while ((rc = LNetGetId(i++, &id)) != -ENOENT) {
                if (LNET_NETTYP(LNET_NIDNET(id.nid)) == LOLND) 
                        continue;
                break;
        }
        OBD_ALLOC(uuid, sizeof(struct obd_uuid));
        sprintf(uuid, "mgc_"LPX64, id.nid);
        /* Start the MGC */
        rc = lustre_start_simple(LUSTRE_MGC_OBDNAME, LUSTRE_MGC_NAME, 
                                 uuid, LUSTRE_MGS_OBDNAME, libcfs_nid2str(nid));
        OBD_FREE(uuid, sizeof(struct obd_uuid));
        if (rc) 
                RETURN(rc);
        
        /* Add the redundant MGS nids */
        for (i = 1; i < lsi->lsi_lmd->lmd_mgsnid_count; i++) {
                nid = lsi->lsi_lmd->lmd_mgsnid[i];
                rc = do_lcfg(LUSTRE_MGC_OBDNAME, nid, LCFG_ADD_UUID, 
                             libcfs_nid2str(nid), 0, 0, 0);
                if (rc) {
                        CERROR("Add uuid for %s failed %d\n", 
                               libcfs_nid2str(nid), rc);
                        continue;
                }
                rc = do_lcfg(LUSTRE_MGC_OBDNAME, 0, LCFG_ADD_CONN,
                             libcfs_nid2str(nid), 0, 0, 0);
                if (rc) 
                        CERROR("Add conn for %s failed %d\n", 
                               libcfs_nid2str(nid), rc);
        }
        
        obd = class_name2obd(LUSTRE_MGC_OBDNAME);
        if (!obd) {
                CERROR("Can't find mgcobd %s\n", LUSTRE_MGC_OBDNAME);
                RETURN(-ENOTCONN);
        }

        /* Try all connections, but only once. */
        recov_bk = 1;
        rc = obd_set_info(obd->obd_self_export,
                          strlen(KEY_INIT_RECOV_BACKUP), KEY_INIT_RECOV_BACKUP,
                          sizeof(recov_bk), &recov_bk);
        if (rc) 
                /* nonfatal */
                CERROR("can't set %s %d\n", KEY_INIT_RECOV_BACKUP, rc);
       
        /* FIXME add ACL support? */
        //ocd.ocd_connect_flags = OBD_CONNECT_ACL;

        /* We connect to the MGS at setup, and don't disconnect until cleanup */
        rc = obd_connect(&mgc_conn, obd, &(obd->obd_uuid), &ocd);
        if (rc) {
                CERROR("connect failed %d\n", rc);
                GOTO(out, rc);
        }
        
        exp = class_conn2export(&mgc_conn);
        obd->u.cli.cl_mgc_mgsexp = exp;

        /* And keep a refcount of servers/clients who started with "mount",
           so we know when we can get rid of the mgc. */
        atomic_set(&obd->u.cli.cl_mgc_refcount, 1);

out:
        /* Keep the mgc info in the sb. Note that many lsi's can point
           to the same mgc.*/
        lsi->lsi_mgc = obd;
        RETURN(rc);
}

static int lustre_stop_mgc(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *obd;
        lnet_nid_t nid;
        int i, rc;
        ENTRY;

        if (!lsi)
                RETURN(-ENOENT);
        obd = lsi->lsi_mgc;
        if (!obd)
                RETURN(-ENOENT);

        lsi->lsi_mgc = NULL;
        if (!atomic_dec_and_test(&obd->u.cli.cl_mgc_refcount)) {
                /* This is not fatal, every client that stops 
                   will call in here. */
                CDEBUG(D_MOUNT, "mgc still has %d references.\n", 
                       atomic_read(&obd->u.cli.cl_mgc_refcount));
                RETURN(-EBUSY); 
        }

        if (obd->u.cli.cl_mgc_mgsexp)
                obd_disconnect(obd->u.cli.cl_mgc_mgsexp);

        rc = class_manual_cleanup(obd);
        if (rc)
                RETURN(rc);
        
        /* class_add_uuid adds a nid even if the same uuid exists; we might
           delete any copy here.  So they all better match. */
        for (i = 0; i < lsi->lsi_lmd->lmd_mgsnid_count; i++) {
                nid = lsi->lsi_lmd->lmd_mgsnid[i];
                rc = do_lcfg(obd->obd_name, nid, LCFG_DEL_UUID, 
                              libcfs_nid2str(nid), 0, 0, 0);
                if (rc)
                        CERROR("del MDC UUID %s failed: rc = %d\n", 
                               libcfs_nid2str(nid), rc);
        }
        /* class_import_put will get rid of the additional connections */

        RETURN(0);
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
        rc = obd_set_info(mgc->obd_self_export,
                          strlen("set_fs"), "set_fs",
                          sizeof(*sb), sb);
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
        
        rc = obd_set_info(mgc->obd_self_export,
                          strlen("clear_fs"), "clear_fs", 0, NULL);
        RETURN(rc);
}

/* Stop MDS/OSS if nobody is using them */
static int server_stop_servers(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *obd;
        int rc = 0;
        ENTRY;

        /* if this was an MDT, and there are no more MDT's, clean up the MDS */
        if (IS_MDT(lsi->lsi_ldd) && (obd = class_name2obd("MDS"))) {
                //FIXME pre-rename, should eventually be LUSTRE_MDT_NAME
                struct obd_type *type = class_search_type(LUSTRE_MDS_NAME);
                if (!type || !type->typ_refcnt) {
                        /* nobody is using the MDT type, clean the MDS */
                        if (lsi->lsi_flags & LSI_UMOUNT_FORCE)
                                obd->obd_force = 1;
                        if (lsi->lsi_flags & LSI_UMOUNT_FAILOVER)
                                obd->obd_fail = 1;
                        rc = class_manual_cleanup(obd);
                }
        }

        /* if this was an OST, and there are no more OST's, clean up the OSS */
        if (IS_OST(lsi->lsi_ldd) && (obd = class_name2obd("OSS"))) {
                struct obd_type *type = class_search_type(LUSTRE_OST_NAME);
                if (!type || !type->typ_refcnt) {
                        int err;
                        /* nobody is using the OST type, clean the OSS */
                        if (lsi->lsi_flags & LSI_UMOUNT_FORCE)
                                obd->obd_force = 1;
                        if (lsi->lsi_flags & LSI_UMOUNT_FAILOVER)
                                obd->obd_fail = 1;
                        err = class_manual_cleanup(obd);
                        if (!rc) 
                                rc = err;
                }
        }
        RETURN(rc);
}

/* Register an old or new target with the MGS. If needed MGS will construct
   startup logs and assign index */
static int server_register_target(struct super_block *sb, struct vfsmount *mnt)
{       
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        struct lustre_disk_data *ldd = lsi->lsi_ldd;
        struct mgs_target_info *mti = NULL;
        lnet_process_id_t         id;
        int i = 0;
        int rc;
        ENTRY;

        LASSERT(mgc);

        OBD_ALLOC(mti, sizeof(*mti));
        if (!mti) {
                RETURN(-ENOMEM);
        }
        strncpy(mti->mti_fsname, ldd->ldd_fsname,
                sizeof(mti->mti_fsname));
        strncpy(mti->mti_svname, ldd->ldd_svname,
                sizeof(mti->mti_svname));
        
        mti->mti_nid_count = 0;
        while ((rc = LNetGetId(i++, &id)) != -ENOENT) {
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
      
        mti->mti_failnid_count = ldd->ldd_failnid_count;
        memcpy(mti->mti_failnids, ldd->ldd_failnid, sizeof(mti->mti_failnids));
        mti->mti_config_ver = 0;
        mti->mti_flags = ldd->ldd_flags;
        mti->mti_stripe_index = ldd->ldd_svindex;
        mti->mti_stripe_count = ldd->ldd_stripe_count;
        mti->mti_stripe_pattern = ldd->ldd_stripe_pattern;
        mti->mti_stripe_size = ldd->ldd_stripe_sz; 
        mti->mti_stripe_offset = ldd->ldd_stripe_offset;  

        CDEBUG(D_MOUNT, "%sregistration %s, fs=%s, %s, index=%04x, flags=%#x\n",
               mti->mti_flags & LDD_F_NEED_REGISTER ? "Initial " : "",
               mti->mti_svname, mti->mti_fsname,
               libcfs_nid2str(mti->mti_nids[0]), mti->mti_stripe_index,
               mti->mti_flags);

        /* Register the target */
        /* FIXME use mdc_process_config instead */
        rc = obd_set_info(mgc->u.cli.cl_mgc_mgsexp,
                          strlen("add_target"), "add_target",
                          sizeof(*mti), mti);
        if (rc) {
                CERROR("registration with the MGS failed (%d)\n", rc);
                GOTO(out, rc);
        }

        /* If this flag is set, it means the MGS wants us to change our
           on-disk data. (So far this means just the index.) */
        if (mti->mti_flags & LDD_F_REWRITE) {
                CDEBUG(D_MOUNT, "Must change on-disk index from %#x to %#x for "
                       " %s\n",
                       ldd->ldd_svindex, mti->mti_stripe_index, 
                       mti->mti_svname);
                ldd->ldd_svindex = mti->mti_stripe_index;
                strncpy(ldd->ldd_svname, mti->mti_svname, 
                        sizeof(ldd->ldd_svname));
                /* or ldd_make_sv_name(ldd); */
                ldd->ldd_flags = mti->mti_flags & ~LDD_F_REWRITE;
                ldd_write(&mgc->obd_lvfs_ctxt, ldd);
                
                /* FIXME write last_rcvd?, disk label? */
        }

out:
        if (mti)        
                OBD_FREE(mti, sizeof(*mti));
        RETURN(rc);
}

/* Start targets */
static int server_start_targets(struct super_block *sb, struct vfsmount *mnt)
{
        struct obd_device *obd;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct config_llog_instance cfg;
        int rc;
        ENTRY;

        CDEBUG(D_MOUNT, "starting target %s\n", lsi->lsi_ldd->ldd_svname);
        
        /* If we're an MDT, make sure the global MDS is running */
        if (lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_MDT) {
                /* make sure (what will be called) the MDS is started */
                obd = class_name2obd("MDS");
                if (!obd) {
                        //FIXME pre-rename, should eventually be LUSTRE_MDS_NAME
                        rc = lustre_start_simple("MDS", LUSTRE_MDT_NAME, 
                                                 "MDS_uuid", 0, 0);
                        if (rc) {
                                CERROR("failed to start MDS: %d\n", rc);
                                GOTO(out_servers, rc);
                        }
                }
        }

        /* If we're an OST, make sure the global OSS is running */
        if (lsi->lsi_ldd->ldd_flags & LDD_F_SV_TYPE_OST) {
                /* make sure OSS is started */
                obd = class_name2obd("OSS");
                if (!obd) {
                        rc = lustre_start_simple("OSS", LUSTRE_OSS_NAME,
                                                 "OSS_uuid", 0, 0);
                        if (rc) {
                                CERROR("failed to start OSS: %d\n", rc);
                                GOTO(out_servers, rc);
                        }
                }
        }

        /* Set the mgc fs to our server disk.  This allows the MGC
           to read and write configs locally. */
        server_mgc_set_fs(lsi->lsi_mgc, sb);

        /* Register with MGS */
        rc = server_register_target(sb, mnt);
        if (rc && (lsi->lsi_ldd->ldd_flags & 
                   (LDD_F_NEED_INDEX | LDD_F_NEED_REGISTER | LDD_F_UPGRADE14))){
                CERROR("Required refistration failed for %s: %d\n", 
                       lsi->lsi_ldd->ldd_svname, rc);
                GOTO(out, rc);
        }

        if (class_name2obd(lsi->lsi_ldd->ldd_svname)) {
                LCONSOLE_ERROR("The target named %s is already running\n",
                               lsi->lsi_ldd->ldd_svname);
                GOTO(out, rc = -EBUSY);
        }

        /* Let the target look up the mount using the target's name 
           (we can't pass the sb or mnt through class_process_config.) */
        rc = server_register_mount(lsi->lsi_ldd->ldd_svname, sb, mnt);
        if (rc) 
                GOTO(out, rc);

        /* Start targets using the llog named for the target */
        memset(&cfg, 0, sizeof(cfg));
        rc = lustre_process_log(sb, lsi->lsi_ldd->ldd_svname, &cfg);
        if (rc) {
                CERROR("failed to start server %s: %d\n",
                       lsi->lsi_ldd->ldd_svname, rc);
                GOTO(out, rc);
        }

        if (!class_name2obd(lsi->lsi_ldd->ldd_svname)) {
                CERROR("no server named %s was started\n",
                       lsi->lsi_ldd->ldd_svname);
                rc = -ENXIO;
        }
        
out:
        /* Release the mgc fs for others to use */
        server_mgc_clear_fs(lsi->lsi_mgc);

out_servers:
        RETURN(rc);
}

/***************** mount **************/

struct lustre_sb_info *lustre_init_lsi(struct super_block *sb)
{
        struct lustre_sb_info *lsi = NULL;
        ENTRY;

        OBD_ALLOC(lsi, sizeof(*lsi));
        if (!lsi)
                RETURN(NULL);
        OBD_ALLOC(lsi->lsi_lmd, sizeof(*lsi->lsi_lmd));
        if (!lsi->lsi_lmd) {
                OBD_FREE(lsi, sizeof(*lsi));
                RETURN(NULL);
        }

        s2lsi_nocast(sb) = lsi;
        /* we take 1 extra ref for our setup */
        atomic_set(&lsi->lsi_mounts, 1);
        RETURN(lsi);
}

static int lustre_free_lsi(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        ENTRY;

        if (!lsi)
                RETURN(0);
                
        CDEBUG(D_MOUNT, "Freeing lsi\n");
        
        /* someone didn't call server_put_mount. */
        LASSERT(atomic_read(&lsi->lsi_mounts) == 0);

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
        
        server_deregister_mount_all(lsi->lsi_srv_mnt);
        
        OBD_FREE(lsi, sizeof(*lsi));
        s2lsi_nocast(sb) = NULL;
        
        RETURN(0);
}
           
static int lustre_put_lsi(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        ENTRY;

        LASSERT(lsi);
        
        CDEBUG(D_MOUNT, "put %p %d\n", sb, atomic_read(&lsi->lsi_mounts));

        if (atomic_dec_and_test(&lsi->lsi_mounts)) {
                lustre_free_lsi(sb);
                RETURN(1);
        }
        RETURN(0);
}

/*************** server mount ******************/

/* Kernel mount using mount options in MOUNT_DATA_FILE */
static struct vfsmount *server_kernel_mount(struct super_block *sb)
{
        struct lvfs_run_ctxt mount_ctxt;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct lustre_disk_data *ldd;
        struct lustre_mount_data *lmd = lsi->lsi_lmd;
        struct vfsmount *mnt;
        char *options = NULL;
        unsigned long page, s_flags;
        int rc;
        ENTRY;

        OBD_ALLOC(ldd, sizeof(*ldd));
        if (!ldd)
                RETURN(ERR_PTR(-ENOMEM));

        /* In the past, we have always used flags = 0.
           Note ext3/ldiskfs can't be mounted ro. */
        s_flags = sb->s_flags;

        /* Pre-mount ext3 to read the MOUNT_DATA_FILE */
        CDEBUG(D_MOUNT, "Pre-mount ext3 %s\n", lmd->lmd_dev);
        mnt = do_kern_mount("ext3", s_flags, lmd->lmd_dev, 0);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("premount ext3 failed (%d), trying ldiskfs\n", rc);
                /* If ext3 fails (bec. of mballoc, extents), try ldiskfs */
                mnt = do_kern_mount("ldiskfs", s_flags, lmd->lmd_dev, 0);
                if (IS_ERR(mnt)) {
                        rc = PTR_ERR(mnt);
                        CERROR("premount ldiskfs failed: rc = %d\n", rc);
                        GOTO(out_free, rc);
                }
        }

        OBD_SET_CTXT_MAGIC(&mount_ctxt);
        mount_ctxt.pwdmnt = mnt;
        mount_ctxt.pwd = mnt->mnt_root;
        mount_ctxt.fs = get_ds();

        rc = ldd_parse(&mount_ctxt, ldd); 
        unlock_mntput(mnt);

        if (rc) {
                CERROR("premount parse options failed: rc = %d\n", rc);
                GOTO(out_free, rc);
        }

        /* Done with our pre-mount, now do the real mount. */

        /* Glom up mount options */
        page = __get_free_page(GFP_KERNEL);
        if (!page) 
                GOTO(out_free, rc = -ENOMEM);

        options = (char *)page;
        memset(options, 0, PAGE_SIZE);
        strncpy(options, ldd->ldd_mount_opts, PAGE_SIZE - 2);
        
        /* Add in any mount-line options */
        if (lmd->lmd_opts && (*(lmd->lmd_opts) != 0)) {
                int len = PAGE_SIZE - strlen(options) - 2;
                if (*options != 0) 
                        strcat(options, ",");
                strncat(options, lmd->lmd_opts, len);
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
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                GOTO(out_free, rc);
        }

        lsi->lsi_ldd = ldd;   /* freed at lsi cleanup */
        CDEBUG(D_SUPER, "%s: mnt = %p\n", lmd->lmd_dev, mnt);
        RETURN(mnt);

out_free:
        OBD_FREE(ldd, sizeof(*ldd));
        lsi->lsi_ldd = NULL;    
        RETURN(ERR_PTR(rc));
}
                      
static void server_put_super(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct obd_device     *obd;
        struct vfsmount       *mnt = lsi->lsi_srv_mnt;
        int rc;
        ENTRY;

        CDEBUG(D_MOUNT, "server put_super %s\n", lsi->lsi_ldd->ldd_svname);
                                                                                       
        /* tell the mgc to drop the config log */
        lustre_end_log(sb, lsi->lsi_ldd->ldd_svname, NULL);

        obd = class_name2obd(lsi->lsi_ldd->ldd_svname);
        if (obd) {
                CDEBUG(D_MOUNT, "stopping %s\n", obd->obd_name);
                if (lsi->lsi_flags & LSI_UMOUNT_FORCE)
                        obd->obd_force = 1;
                if (lsi->lsi_flags & LSI_UMOUNT_FAILOVER)
                        obd->obd_fail = 1;
                /* We can't seem to give an error return code
                   to .put_super, so we better make sure we clean up!
                   FIXME is there a way to get around this? */
                obd->obd_force = 1;
                class_manual_cleanup(obd);
        } else {
                CERROR("no obd %s\n", lsi->lsi_ldd->ldd_svname);
                server_deregister_mount(lsi->lsi_ldd->ldd_svname);
        }

        server_stop_servers(sb);

        /* If they wanted the mgs to stop separately from the mdt, they
           should have put it on a different device. */ 
        if (IS_MGS(lsi->lsi_ldd)) {
                /* stop the mgc before the mgs so the connection gets cleaned
                   up */
                lustre_stop_mgc(sb);
                server_stop_mgs(sb);
        }

        /* clean the mgc and sb */
        rc = lustre_common_put_super(sb);
        // FIXME how do I return a failure? 

        /* drop the One True Mount */
        unlock_mntput(mnt);

        CDEBUG(D_MOUNT, "umount done\n");
        EXIT;
}

static void server_umount_begin(struct super_block *sb)
{
        struct lustre_sb_info *lsi = s2lsi(sb);
        ENTRY;

        CDEBUG(D_MOUNT, "umount -f\n");
        /* umount = normal
           umount -f = failover
           no third way to do LSI_UMOUNT_FORCE */
        lsi->lsi_flags |= LSI_UMOUNT_FAILOVER;
        EXIT;
}

static int server_statfs (struct super_block *sb, struct kstatfs *buf)
{
        struct vfsmount *mnt = s2lsi(sb)->lsi_srv_mnt;
        ENTRY;

        if (mnt && mnt->mnt_sb && mnt->mnt_sb->s_op->statfs) {
                int rc = mnt->mnt_sb->s_op->statfs(mnt->mnt_sb, buf);
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
        struct vfsmount *mnt;
        int mgs_service = 0, i = 0, rc;
        ENTRY;

        /* the One True Mount */
        mnt = server_kernel_mount(sb);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("Unable to mount device %s: %d\n", 
                      lsi->lsi_lmd->lmd_dev, rc);
                GOTO(out, rc);
        }
        lsi->lsi_srv_mnt = mnt;

        LASSERT(lsi->lsi_ldd);
        CDEBUG(D_MOUNT, "Found service %s for fs '%s' on device %s\n",
               lsi->lsi_ldd->ldd_svname, lsi->lsi_ldd->ldd_fsname, 
               lsi->lsi_lmd->lmd_dev);

        /* append on-disk MGS nids to mount-line MGS nids */
        for (i = 0; (i < lsi->lsi_ldd->ldd_mgsnid_count) && 
              (lsi->lsi_lmd->lmd_mgsnid_count < MTI_NIDS_MAX); i++) {
                lsi->lsi_lmd->lmd_mgsnid[lsi->lsi_lmd->lmd_mgsnid_count++] = 
                        lsi->lsi_ldd->ldd_mgsnid[i];
        }

        /* start MGS before MGC */
        if (IS_MGS(lsi->lsi_ldd)) {
                rc = server_start_mgs(sb);
                if (rc) {
                        CERROR("ignoring Failed MGS start!!\n");
                        //GOTO(out_mnt, rc);
                } else {
                        /* add local nids (including LO) to MGS nids */
                        lnet_process_id_t id;
                        int j = lsi->lsi_lmd->lmd_mgsnid_count;
                        i = 0;
                        while ((rc = LNetGetId(i++, &id)) != -ENOENT) {
                                if (j >= MTI_NIDS_MAX) 
                                        break;
                                lsi->lsi_lmd->lmd_mgsnid[j++] = id.nid;
                        }     
                        lsi->lsi_lmd->lmd_mgsnid_count = j;

                        mgs_service++;
                }
        }

        rc = lustre_start_mgc(sb);
        if (rc) 
                GOTO(out_mnt, rc);

        /* Set up all obd devices for service */
        if (!(lsi->lsi_lmd->lmd_flags & LMD_FLG_NOSVC) && 
                (IS_OST(lsi->lsi_ldd) || IS_MDT(lsi->lsi_ldd))) {
                rc = server_start_targets(sb, mnt);
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
           Note - MGMT-only server does NOT get a client, since there is no
           lustre fs associated - the MGMT is for all lustre fs's */
        }

        rc = server_fill_super_common(sb);
        if (rc) 
                GOTO(out_mnt, rc);

        RETURN(0);

out_mnt:
        server_put_super(sb);
out:
        RETURN(rc);
}


/*************** mount common betweeen server and client ***************/

/* Common umount */
int lustre_common_put_super(struct super_block *sb)
{
        int rc;
        ENTRY;

        CDEBUG(D_MOUNT, "dropping sb %p\n", sb);
        
        rc = lustre_stop_mgc(sb);
        if (rc && (rc != -ENOENT)) {
                if (rc != -EBUSY) {
                        CERROR("Can't stop MGC: %d\n", rc);
                        RETURN(rc);
                }
                /* BUSY just means that there's some other obd that
                   needs the mgc.  Let him clean it up. */
                CDEBUG(D_MOUNT, "MGC busy, will stop later\n");
        }
        lustre_put_lsi(sb);
        RETURN(rc);
}      

static void lmd_print(struct lustre_mount_data *lmd)
{
        int i;

        PRINT_CMD(PRINT_MASK, "  mount data:\n"); 
        if (!lmd->lmd_mgsnid_count) 
                PRINT_CMD(PRINT_MASK, "no MGS nids\n");
        else for (i = 0; i < lmd->lmd_mgsnid_count; i++) {
                PRINT_CMD(PRINT_MASK, "nid %d:  %s\n", i, 
                       libcfs_nid2str(lmd->lmd_mgsnid[i]));
        }
        if (lmd_is_client(lmd)) 
                PRINT_CMD(PRINT_MASK, "fsname:  %s\n", lmd->lmd_dev);
        else
                PRINT_CMD(PRINT_MASK, "device:  %s\n", lmd->lmd_dev);
        PRINT_CMD(PRINT_MASK, "flags:   %x\n", lmd->lmd_flags);
        if (lmd->lmd_opts)
                PRINT_CMD(PRINT_MASK, "options: %s\n", lmd->lmd_opts);
}

static int lmd_parse(char *options, struct lustre_mount_data *lmd)
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
        
        /* Options should be a string - try to detect old lmd data */
        if ((raw->lmd_magic & 0xffffff00) == (LMD_MAGIC & 0xffffff00)) { 
                LCONSOLE_ERROR("You're using an old version of "        
                               "/sbin/mount.lustre.  Please install version "   
                               "1.%d\n", LMD_MAGIC & 0xFF);     
                RETURN(-EINVAL);
        }
        lmd->lmd_magic = LMD_MAGIC;

        /* default flags */
        lmd->lmd_flags |= LMD_FLG_RECOVER;

        s1 = options;
        while(*s1) {
                while (*s1 == ' ' || *s1 == ',')
                        s1++;
                /* Client options are parsed in ll_options: eg. flock, 
                   user_xattr, acl */
                
                if (strncmp(s1, "recov", 5) == 0) 
                        /* FIXME do something with the RECOVER flag - see lconf */
                        lmd->lmd_flags |= LMD_FLG_RECOVER;
                else if (strncmp(s1, "norecov", 7) == 0)
                        lmd->lmd_flags &= ~LMD_FLG_RECOVER;
                else if (strncmp(s1, "nosvc", 5) == 0)
                        lmd->lmd_flags |= LMD_FLG_NOSVC;

                else if (strncmp(s1, "exclude=", 8) == 0) {
                        CERROR("Exclude: %s\n", s1);
                        /* FIXME implement */
                        /* store exlusion list in lmd_exclude, mdt & client
                         must check */
                }

                /* Linux 2.4 doesn't pass the device, so we stuck it at the 
                   end of the options. */
                else if (strncmp(s1, "device=", 7) == 0) {
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
        /* Get MGS nids if client mount:  uml1@tcp:uml2@tcp:/fsname-client */
        while ((s2 = strchr(s1, ':'))) {
                lnet_nid_t nid;
                *s2 = 0;
                lmd->lmd_flags = LMD_FLG_CLIENT;
                nid = libcfs_str2nid(s1);
                if (nid == LNET_NID_ANY) {
                        LCONSOLE_ERROR("Can't parse NID '%s'\n", s1);
                        goto invalid;
                }
                if (lmd->lmd_mgsnid_count >= MTI_NIDS_MAX) {
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

        lmd_print(lmd);
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
        int rc;
        ENTRY;
 
        CDEBUG(D_MOUNT|D_VFSTRACE, "VFS Op: sb %p\n", sb);
        
        lsi = lustre_init_lsi(sb);
        if (!lsi) 
                RETURN(-ENOMEM);
        lmd = lsi->lsi_lmd;

        /* Figure out the lmd from the mount options */
        if (lmd_parse((char *)data, lmd)) {
                lustre_put_lsi(sb);
                RETURN(-EINVAL);
        }

        if (lmd_is_client(lmd)) {
                CDEBUG(D_MOUNT, "Mounting client for fs %s\n", lmd->lmd_dev);
                if (!client_fill_super) {
                        LCONSOLE_ERROR("Nothing registered for client mount!"
                               " Is llite module loaded?\n");
                        rc = -ENOSYS;
                } else {
                        rc = lustre_start_mgc(sb);
                        if (rc) 
                                goto out;
                        /* Connect and start */
                        /* (should always be ll_fill_super) */
                        rc = (*client_fill_super)(sb);
                        if (rc) 
                                lustre_common_put_super(sb);
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
                                                                                
out:
        if (rc){
                CERROR("Unable to mount %s\n", 
                       s2lsi(sb) ? lmd->lmd_dev : "");
        } else {
                CDEBUG(D_MOUNT, "Successfully mounted %s\n", lmd->lmd_dev);
        }
        RETURN(rc);
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
        int rc;
        ENTRY;

        rc = lustre_fill_super(sb, data, silent);
        if (rc)
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
EXPORT_SYMBOL(lustre_process_log);
EXPORT_SYMBOL(lustre_end_log);
EXPORT_SYMBOL(server_get_mount);
EXPORT_SYMBOL(server_put_mount);

