/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_CONFOBD

#include <linux/version.h>
#include <linux/init.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_log.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd_class.h>
#include <linux/lprocfs_status.h>

static struct lprocfs_vars lprocfs_module_vars[] = { {0} };
static struct lprocfs_vars lprocfs_obd_vars[] = { {0} };

LPROCFS_INIT_VARS(confobd, lprocfs_module_vars, lprocfs_obd_vars)

static int confobd_fs_setup(struct obd_device *obd, 
                            struct lvfs_obd_ctxt *lvfs_ctxt)
{
        struct conf_obd *confobd = &obd->u.conf;
        struct lvfs_run_ctxt saved;
        struct dentry *dentry;
        int rc = 0;
        ENTRY;

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = lvfs_ctxt->loc_mnt;
        obd->obd_lvfs_ctxt.pwd = lvfs_ctxt->loc_mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        /*Now we did not set cb_ops of CONFOBD FIXME later*/ 
        
        /*setup llog ctxt*/
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        
        dentry = simple_mkdir(current->fs->pwd, "LOGS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create LOGS directory: rc = %d\n", rc);
                GOTO(err_out, rc);
        }
        confobd->cfobd_logs_dir = dentry;

        dentry = simple_mkdir(current->fs->pwd, "OBJECTS", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create OBJECTS directory: rc = %d\n", rc);
                GOTO(err_logs, rc);
        }
        confobd->cfobd_objects_dir = dentry;

        dentry = simple_mkdir(current->fs->pwd, "PENDING", 0777, 1);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot create PENDING directory: rc = %d\n", rc);
                GOTO(err_logs, rc);
        }
        confobd->cfobd_pending_dir = dentry;

err_logs:
        if (rc) 
               l_dput(confobd->cfobd_logs_dir);
err_out:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        RETURN(rc);
}
 
static int confobd_fs_cleanup(struct obd_device *obd, int flags)
{
        struct conf_obd *confobd = &obd->u.conf;
        struct lvfs_run_ctxt saved;
        int rc = 0;
        ENTRY;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (confobd->cfobd_logs_dir != NULL) {
                l_dput(confobd->cfobd_logs_dir);
                confobd->cfobd_logs_dir = NULL; 
        }
        if (confobd->cfobd_objects_dir != NULL) {
                l_dput(confobd->cfobd_objects_dir);
                confobd->cfobd_objects_dir = NULL; 
        }
        if (confobd->cfobd_pending_dir != NULL) {
                l_dput(confobd->cfobd_pending_dir);
                confobd->cfobd_pending_dir = NULL;
        }

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        RETURN(rc);
}

int confobd_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;
        int rc = 0;
	ENTRY;

        lprocfs_init_vars(confobd, &lvars);
        rc = lprocfs_obd_attach(dev, lvars.obd_vars);
        if (rc)
                RETURN(rc);

        rc = lprocfs_alloc_md_stats(dev, 0);
	RETURN(rc);
}

int confobd_detach(struct obd_device *dev)
{
	int rc;
	ENTRY;
	
        lprocfs_free_md_stats(dev);
        rc = lprocfs_obd_detach(dev);
	RETURN(rc);
}

static int confobd_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct conf_obd *confobd = &obd->u.conf;
        struct lvfs_obd_ctxt *lvfs_ctxt = NULL;
        struct lustre_cfg* lcfg = buf;
        char *mountoptions = NULL;
        unsigned long page = 0;
        char *fstype = NULL;
        char *name = NULL;
        int rc = 0;
        ENTRY;

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
            lustre_cfg_buf(lcfg, 1) == NULL) { 
                CERROR("CONFOBD setup requires device name\n");
                RETURN(-EINVAL);
        }
        if (LUSTRE_CFG_BUFLEN(lcfg, 2) < 1 ||
            lustre_cfg_buf(lcfg, 2) == NULL) { 
                CERROR("CONFOBD setup requires fstype\n");
                RETURN(-EINVAL);
        }

        OBD_ALLOC(name, LUSTRE_CFG_BUFLEN(lcfg, 1));
        if (!name) {
                CERROR("No memory\n");
                GOTO(out, rc = -ENOMEM);
        }
        memcpy(name, lustre_cfg_string(lcfg, 1), LUSTRE_CFG_BUFLEN(lcfg, 1));

        OBD_ALLOC(fstype, LUSTRE_CFG_BUFLEN(lcfg, 2));
        if (!fstype) {
                CERROR("No memory\n");
                GOTO(out, rc = -ENOMEM);
        }
        memcpy(fstype, lustre_cfg_string(lcfg, 2), 
               LUSTRE_CFG_BUFLEN(lcfg, 2));

        obd->obd_fsops = fsfilt_get_ops(fstype);
        if (IS_ERR(obd->obd_fsops)) {
               CERROR("No fstype %s rc=%ld\n", fstype, PTR_ERR(obd->obd_fsops));
               GOTO(err_ops, rc = PTR_ERR(obd->obd_fsops));
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 3) >= 1 && lustre_cfg_buf(lcfg, 3)) {
                /* 2.6.9 selinux wants a full option page for do_kern_mount
                 * (bug6471) */
                page = get_zeroed_page(GFP_KERNEL);
                if (!page) {
                        CERROR("No memory\n");
                        GOTO(err_ops, rc = -ENOMEM);
                }
                mountoptions = (char *)page;
                
                memcpy(mountoptions, lustre_cfg_string(lcfg, 3), 
                       LUSTRE_CFG_BUFLEN(lcfg, 3)); 
        }
        
        rc = lvfs_mount_fs(name, fstype, mountoptions, 0, &lvfs_ctxt);

        if (page) {
                free_page(page);
                page = 0;
        }

        if (rc)
                GOTO(err_ops, rc);

        LASSERT(lvfs_ctxt);
        confobd->cfobd_lvfs_ctxt = lvfs_ctxt;

        rc = confobd_fs_setup(obd, lvfs_ctxt);
        if (rc)
                GOTO(err_ops, rc);

        rc = obd_llog_setup(obd, &obd->obd_llogs, LLOG_CONFIG_ORIG_CTXT, 
			    obd, 0, NULL, &llog_lvfs_ops);
        if (rc)
                GOTO(err_ops, rc);

	EXIT;
out:
        if (rc && lvfs_ctxt)
                lvfs_umount_fs(lvfs_ctxt);
        if (name)
                OBD_FREE(name, LUSTRE_CFG_BUFLEN(lcfg, 1));
        if (fstype)
                OBD_FREE(fstype, LUSTRE_CFG_BUFLEN(lcfg, 2));

        return rc;
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
        goto out;
}

static int confobd_cleanup(struct obd_device *obd, int flags)
{
        struct conf_obd *confobd = &obd->u.conf;
        ENTRY;

        /* stop recording any log in case lconf didn't do that for us */
        if (confobd->cfobd_cfg_llh) {
                struct lvfs_run_ctxt saved;
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                llog_close(confobd->cfobd_cfg_llh);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        }

        obd_llog_cleanup(llog_get_context(&obd->obd_llogs, 
					  LLOG_CONFIG_ORIG_CTXT));
        confobd_fs_cleanup(obd, flags);
        if (confobd->cfobd_lvfs_ctxt)
                lvfs_umount_fs(confobd->cfobd_lvfs_ctxt);

        if (!list_empty(&obd->obd_exports))
                return (-EBUSY);
        fsfilt_put_ops(obd->obd_fsops);
        RETURN(0);
}

static int confobd_iocontrol(unsigned int cmd, struct obd_export *exp, 
			     int len, void *karg, void *uarg)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct obd_device *obd = exp->exp_obd;
        struct conf_obd *confobd = &obd->u.conf;
        struct obd_ioctl_data *data = karg;
        struct lvfs_run_ctxt saved;
        int rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "ioctl cmd %x\n", cmd);
        switch (cmd) {
        case OBD_IOC_CLEAR_LOG: {
                char *name = data->ioc_inlbuf1;
                if (confobd->cfobd_cfg_llh)
                        RETURN(-EBUSY);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_open(llog_get_context(&obd->obd_llogs, 
						LLOG_CONFIG_ORIG_CTXT),
                    	       &confobd->cfobd_cfg_llh, NULL, name,
			       OBD_LLOG_FL_CREATE);
                if (rc == 0) {
                        llog_init_handle(confobd->cfobd_cfg_llh,
                                         LLOG_F_IS_PLAIN, NULL);

                        rc = llog_destroy(confobd->cfobd_cfg_llh);
                        llog_free_handle(confobd->cfobd_cfg_llh);
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                confobd->cfobd_cfg_llh = NULL;
                RETURN(rc);
        }
        case OBD_IOC_RECORD: {
                char *name = data->ioc_inlbuf1;
                if (confobd->cfobd_cfg_llh)
                        RETURN(-EBUSY);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_open(llog_get_context(&obd->obd_llogs, 
						LLOG_CONFIG_ORIG_CTXT),
                    	       &confobd->cfobd_cfg_llh, NULL, name,
			       OBD_LLOG_FL_CREATE);
                if (rc == 0)
                        llog_init_handle(confobd->cfobd_cfg_llh,
                                         LLOG_F_IS_PLAIN, &cfg_uuid);
                else
                        confobd->cfobd_cfg_llh = NULL;
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                RETURN(rc);
        }
        case OBD_IOC_ENDRECORD: {
                if (!confobd->cfobd_cfg_llh)
                        RETURN(-EBADF);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_close(confobd->cfobd_cfg_llh);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                confobd->cfobd_cfg_llh = NULL;
                RETURN(rc);
        }
        case OBD_IOC_DORECORD: {
                char *cfg_buf;
                struct llog_rec_hdr rec;
                if (!confobd->cfobd_cfg_llh)
                        RETURN(-EBADF);

                rec.lrh_len = llog_data_len(data->ioc_plen1);

                switch(data->ioc_type) {
                case LUSTRE_CFG_TYPE:
                        rec.lrh_type = OBD_CFG_REC;
                        break;
                case PORTALS_CFG_TYPE:
                        rec.lrh_type = PTL_CFG_REC;
                        break;
                default:
                        CERROR("unknown cfg record type:%d \n", data->ioc_type);
                        RETURN(-EINVAL);
                }

                OBD_ALLOC(cfg_buf, data->ioc_plen1);
                if (cfg_buf == NULL) {
                        CERROR("No Memory\n");
                        RETURN(-ENOMEM);
                }
                if (copy_from_user(cfg_buf, data->ioc_pbuf1, data->ioc_plen1)) {
                        OBD_FREE(cfg_buf, data->ioc_plen1);
                        RETURN(-EFAULT);
                }

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_write_rec(confobd->cfobd_cfg_llh, &rec, NULL, 0,
                                    cfg_buf, -1);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                OBD_FREE(cfg_buf, data->ioc_plen1);
                RETURN(rc);
        }
        case OBD_IOC_DUMP_LOG: {
                struct llog_ctxt *ctxt =
                        llog_get_context(&obd->obd_llogs, LLOG_CONFIG_ORIG_CTXT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = class_config_dump_llog(ctxt, data->ioc_inlbuf1, NULL);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        RETURN(rc);

                RETURN(rc);
        }

        case OBD_IOC_START: {
                struct llog_ctxt *ctxt;
                char *conf_prof;
                char *name = data->ioc_inlbuf1;
                int len = strlen(name) + sizeof("-conf");

                OBD_ALLOC(conf_prof, len);
                if (!conf_prof) {
                        CERROR("no memory\n");
                        RETURN(-ENOMEM);
                }
                sprintf(conf_prof, "%s-conf", name);

                ctxt = llog_get_context(&obd->obd_llogs, LLOG_CONFIG_ORIG_CTXT);
                rc = class_config_process_llog(ctxt, conf_prof, NULL);
                if (rc < 0)
                        CERROR("Unable to process log: %s\n", conf_prof);
                OBD_FREE(conf_prof, len);

                RETURN(rc);
        }

        default:
                CDEBUG(D_INFO, "unknown command %x\n", cmd);
                RETURN(-EINVAL);
        }
        RETURN(0);
}

static struct obd_ops conf_obd_ops = {
        .o_owner         = THIS_MODULE,
        .o_setup         = confobd_setup,
        .o_cleanup       = confobd_cleanup,
        .o_attach        = confobd_attach,
        .o_detach        = confobd_detach,
        .o_iocontrol     = confobd_iocontrol,
};

static int __init confobd_init(void)
{
        struct lprocfs_static_vars lvars;
        ENTRY;

        lprocfs_init_vars(confobd, &lvars);
        RETURN(class_register_type(&conf_obd_ops, NULL,
                                   lvars.module_vars,
                                   OBD_CONF_DEVICENAME));
}

static void __exit confobd_exit(void)
{
        class_unregister_type(OBD_CONF_DEVICENAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Config OBD driver");
MODULE_LICENSE("GPL");

module_init(confobd_init);
module_exit(confobd_exit);
