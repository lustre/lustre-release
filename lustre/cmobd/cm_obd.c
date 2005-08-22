/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cluster File Systems, Inc. <info@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_CMOBD

#include <linux/version.h>
#include <linux/init.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_cmobd.h>
#include <linux/lprocfs_status.h>
#include <linux/obd_lov.h>
#include <linux/obd_ost.h>
#include <linux/obd_lmv.h>

#include "cm_internal.h"

static int cmobd_attach(struct obd_device *obd,
                        obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(cmobd, &lvars);
        return lprocfs_obd_attach(obd, lvars.obd_vars);
}

static int cmobd_detach(struct obd_device *obd)
{
        return lprocfs_obd_detach(obd);
}

static int cmobd_init_dt_desc(struct obd_device *obd)
{
        struct cm_obd *cmobd = &obd->u.cm;
        __u32 valsize;
        int rc = 0;
        ENTRY;
        
        /* as CMOBD is stand alone device, that is has not to be connected, we
         * have no other way to init EAs correctly but ask master device about
         * it. Thus both, DT and MD layers should be able to answer with correct
         * lov_desc. LOV knows it explicitly and LMV/MDC have to ask MDS server
         * of it. */
        valsize = sizeof(cmobd->master_desc);
        memset(&cmobd->master_desc, 0, sizeof(cmobd->master_desc));

        rc = obd_get_info(cmobd->master_exp, strlen("lovdesc") + 1,
                          "lovdesc", &valsize, &cmobd->master_desc);
        RETURN(rc);
}
        
static int cmobd_init_ea_size(struct obd_device *obd)
{
        int rc = 0, tgt_count, easize, cookiesize;
        struct cm_obd *cmobd = &obd->u.cm;
        ENTRY;

        if (!cmobd->master_exp)
                RETURN(-EINVAL);

        tgt_count = cmobd->master_desc.ld_tgt_count;

        /* no EA setup is needed as there is single OST with no LOV */
        if (tgt_count == 0)
                RETURN(0);

        easize = lov_mds_md_size(tgt_count);
        cookiesize = tgt_count * sizeof(struct llog_cookie);
        rc = obd_init_ea_size(cmobd->master_exp, easize, cookiesize);
        RETURN(rc);
}

static char *types[] = {
        OBD_LMV_DEVICENAME, OBD_MDC_DEVICENAME,
        OBD_LOV_DEVICENAME, OBD_OSC_DEVICENAME
};

static struct obd_device *
cmobd_find_obd(struct obd_device *obd, struct obd_uuid *uuid)
{
        struct obd_device *res;
        int i = 0;
        ENTRY;

        CWARN("%s: looking for client obd %s\n",
              obd->obd_uuid.uuid, uuid->uuid);

        for (i = 0; i < sizeof(types) / sizeof(char *); i++) {
                res = class_find_client_obd(NULL, types[i], uuid);
                if (res)
                        RETURN(res);
        }
        RETURN(NULL);
}

static int cmobd_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct obd_uuid master_uuid, cache_uuid;
        struct lustre_handle conn = { 0 };
        struct cm_obd *cmobd = &obd->u.cm;
        struct lustre_cfg* lcfg = buf;
        int rc;
        ENTRY;

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
                CERROR("%s: setup requires master device uuid\n", 
                       obd->obd_name);
                RETURN(-EINVAL);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 2) < 1) {
                CERROR("%s: setup requires cache device uuid\n",
                       obd->obd_name);
                RETURN(-EINVAL);
        }

        obd_str2uuid(&master_uuid, lustre_cfg_string(lcfg, 1));
        obd_str2uuid(&cache_uuid, lustre_cfg_string(lcfg, 2));

        /* getting master obd */
        cmobd->master_obd = cmobd_find_obd(obd, &master_uuid);
        if (!cmobd->master_obd) {
                CERROR("can't find master client obd by uuid %s\n",
                       master_uuid.uuid);
                RETURN(-EINVAL);
        }

        /* getting cache obd */
        cmobd->cache_obd = class_uuid2obd(&cache_uuid);
        if (cmobd->cache_obd == NULL) {
                CERROR("CMOBD: unable to find obd by uuid: %s\n",
                       cache_uuid.uuid);
                RETURN(-EINVAL);
        }

        /* connecting master */
        memset(&conn, 0, sizeof(conn));
        rc = obd_connect(&conn, cmobd->master_obd, &obd->obd_uuid, 
                         NULL, OBD_OPT_REAL_CLIENT);
        if (rc)
                RETURN(rc);
        cmobd->master_exp = class_conn2export(&conn);

        /* connecting cache */
        memset(&conn, 0, sizeof(conn));
        rc = class_connect(&conn, cmobd->cache_obd, &obd->obd_uuid);
        if (rc)
                GOTO(put_master, rc);
        cmobd->cache_exp = class_conn2export(&conn);

        /* initialing DT desc. Both, data and metadata layers should be able to
         * serve this call. */
        rc = cmobd_init_dt_desc(obd);
        if (rc != 0 && rc != -EPROTO) {
                CERROR("cannot get DT layer desc from master device %s, "
                       "err %d.\n", cmobd->master_exp->exp_obd->obd_name,
                       rc);
                GOTO(put_cache, rc);
        }

        if (obd_dt_type(cmobd->master_exp->exp_obd)) {
                /* for master dt device remove the recovery flag. */
                rc = obd_set_info(cmobd->master_exp, strlen("unrecovery"),
                                  "unrecovery", 0, NULL); 
                if (rc)
                        GOTO(put_cache, rc);
                
                rc = cmobd_init_write_srv(obd);
                if (rc)
                        GOTO(put_cache, rc);
        }

        if (obd_md_type(cmobd->master_exp->exp_obd)) {
                __u32 size = sizeof(struct fid_extent);
                struct fid_extent ext;
                
                rc = cmobd_init_ea_size(obd);
                if (rc) {
                        CERROR("can't init MD layer EA size, "
                               "err %d\n", rc);
                        GOTO(put_cache, rc);
                }
                cmobd->write_srv = NULL;

                /* getting fid pool from master to set it on cache */
                rc = obd_get_info(cmobd->master_exp, strlen("getext"),
                                  "getext", &size, &ext);
                if (rc) {
                        CERROR("can't get fids extent from master, "
                               "err %d\n", rc);
                        GOTO(put_cache, rc);
                }

                /* simple checks for validness */
                if (!ext.fe_start || !ext.fe_width || ext.fe_start == ext.fe_width) {
                        CERROR("invalid fids extent from master, ["LPD64"-"LPD64"]\n", 
			       ext.fe_start, ext.fe_width);
                        GOTO(put_cache, rc = -EINVAL);
                }

                CWARN("setting master fids extent ["LPD64"-"LPD64
                      "] -> %s\n", ext.fe_start, ext.fe_width,
                      cmobd->cache_exp->exp_obd->obd_name);
                
                rc = obd_set_info(cmobd->cache_exp, strlen("setext"),
                                  "setext", size, &ext); 
                if (rc) {
                        CERROR("can't set fids extent to cache, "
                               "err %d\n", rc);
                        GOTO(put_cache, rc);
                }
        }

        RETURN(rc);
put_cache:
        class_disconnect(cmobd->cache_exp, 0);
put_master:
        obd_disconnect(cmobd->master_exp, 0);
        return rc;
}

static int cmobd_cleanup(struct obd_device *obd, int flags)
{
        struct cm_obd *cmobd = &obd->u.cm;
        int rc;
        ENTRY;

        if (cmobd->write_srv) {
                cmobd_cleanup_write_srv(obd);
                cmobd->write_srv = NULL;
        }

        rc = obd_disconnect(cmobd->master_exp, flags);
        if (rc) {
                CERROR("error disconnecting master %s, err %d\n",
                       cmobd->master_exp->exp_obd->obd_name, rc);
        }
        
        rc = class_disconnect(cmobd->cache_exp, flags);
        if (rc) {
                CERROR("error disconnecting cache %s, err %d\n",
                       cmobd->cache_exp->exp_obd->obd_name, rc);
        }
        
        RETURN(0);
}

static int cmobd_iocontrol(unsigned int cmd, struct obd_export *exp,
                           int len, void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        int rc = 0;
        ENTRY;
        
        switch (cmd) {
        case OBD_IOC_CMOBD_SYNC:
                /* here would be nice to make sure somehow that all data is in
                 * cache and there are no outstanding requests, as otherwise
                 * cahce is not coherent. But how to check that from CMOBD? I do
                 * not know. --umka */
                rc = cmobd_reintegrate(obd);
                break;
        default:
                CERROR("unrecognized ioctl %#x\n", cmd);
                rc = -EINVAL;
                break;
        }
                
        RETURN(rc);
}

static struct obd_ops cmobd_ops = {
        .o_owner     = THIS_MODULE,
        .o_attach    = cmobd_attach,
        .o_detach    = cmobd_detach,
        .o_setup     = cmobd_setup,
        .o_cleanup   = cmobd_cleanup,
        .o_iocontrol = cmobd_iocontrol,
};

kmem_cache_t *cmobd_extent_slab;

static int __init cmobd_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        printk(KERN_INFO "Lustre: Cache Manager OBD driver; info@clusterfs.com\n");

        lprocfs_init_vars(cmobd, &lvars);
        rc = class_register_type(&cmobd_ops, NULL, lvars.module_vars,
                                 OBD_CMOBD_DEVICENAME);
        if (rc)
                RETURN(rc);
        cmobd_extent_slab = kmem_cache_create("cmobd_extents",
                                              sizeof(struct cmobd_extent_info), 0,
                                              SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (cmobd_extent_slab == NULL) {
                class_unregister_type(OBD_CMOBD_DEVICENAME);
                RETURN(-ENOMEM);
        }
        RETURN(0);
}

static void __exit cmobd_exit(void)
{
        class_unregister_type(OBD_CMOBD_DEVICENAME);
        if (kmem_cache_destroy(cmobd_extent_slab) != 0)
                CERROR("couldn't free cmobd extent slab\n");
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Cache Manager OBD driver");
MODULE_LICENSE("GPL");

module_init(cmobd_init);
module_exit(cmobd_exit);
