/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lustre GS client 
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_GSS

#include <linux/module.h>
#include <linux/init.h>
#include <linux/obd_class.h>
#include <linux/lustre_gs.h>

#include "gks_internal.h"

static int gkc_get_key(struct obd_export *exp, struct key_parms *kparms,
                       struct crypto_key *ckey, int op)
{
        struct ptlrpc_request *req;
        struct crypto_key *rep_key;
        int rc, bufcount = 1, size[3] = {0, 0, 0};
        void *buf;
        ENTRY;

        size[0] = lustre_secdesc_size();

        size[bufcount++] = kparms->context_size;
        if (kparms->perm && kparms->perm_size > 0) {
                size[bufcount++] = kparms->perm_size;
        }
        req = ptlrpc_prep_req(class_exp2cliimp(exp), LUSTRE_GKS_VERSION,
                              op, bufcount, size, NULL);
        if (req == NULL)
                RETURN(-ENOMEM);

        lustre_pack_secdesc(req, size[0]);
        
        buf = lustre_msg_buf(req->rq_reqmsg, 1, kparms->context_size);
        memcpy(buf, kparms->context, kparms->context_size);

        if (kparms->perm && kparms->perm_size) {
                buf = lustre_msg_buf(req->rq_reqmsg, 2, kparms->perm_size);
                memcpy(buf, kparms->perm, kparms->perm_size);
        } 
        
        size[0] = sizeof(struct crypto_key);
        req->rq_replen = lustre_msg_size(1, size);

        rc = ptlrpc_queue_wait(req);
        
        rep_key = lustre_msg_buf(req->rq_repmsg, 0, sizeof(struct crypto_key)); 

        memcpy(ckey, rep_key, sizeof(*rep_key));

        CDEBUG(D_INFO, "get key %s, mac %s type %d\n", ckey->ck_key, ckey->ck_mac, 
               ckey->ck_type); 
        ptlrpc_req_finished(req);
        
        RETURN(rc);
}

static int gkc_set_info(struct obd_export *exp, obd_count keylen,
                        void *key, obd_count vallen, void *val)
{
        int rc = -EINVAL;
        if (keylen == strlen("async") && memcmp(key, "async", keylen) == 0) {
                struct client_obd *cl = &exp->exp_obd->u.cli;
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                cl->cl_async = *(int *)val;
                CDEBUG(D_HA, "%s: set async = %d\n",
                       exp->exp_obd->obd_name, cl->cl_async);
                RETURN(0);
        }
        RETURN(rc);
}

static int gkc_get_info(struct obd_export *exp, __u32 keylen,
                        void *key, __u32 *vallen, void *val)
{
        struct key_parms *kparms = (struct key_parms *)key;
        struct crypto_key *ckey = (struct crypto_key *)val;
        int rc = 0;
        
        ENTRY;
       
        LASSERT(*vallen == sizeof(*ckey));

        switch (kparms->context->kc_command) {
        case GKS_GET_KEY:
        case GKS_DECRYPT_KEY:
        case GKS_GET_MAC:
                break;
        default:
                CERROR("Unknow op %d \n", kparms->context->kc_command);
                rc = -EINVAL; 
                RETURN(rc);
        }
        rc = gkc_get_key(exp, kparms, ckey, kparms->context->kc_command);
        RETURN(rc); 
}  
static int gkc_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct client_obd *cli = &obd->u.cli;
        int rc;
        ENTRY;

        OBD_ALLOC(cli->cl_rpc_lock, sizeof (*cli->cl_rpc_lock));
        if (!cli->cl_rpc_lock)
                RETURN(-ENOMEM);
        gkc_init_rpc_lock(cli->cl_rpc_lock);

        ptlrpcd_addref();

        rc = client_obd_setup(obd, len, buf);
        if (rc)
                GOTO(err_rpc_lock, rc);

        RETURN(rc);
err_rpc_lock:
        OBD_FREE(cli->cl_rpc_lock, sizeof (*cli->cl_rpc_lock));
        ptlrpcd_decref();
        RETURN(rc);
}

static int gkc_cleanup(struct obd_device *obd, int flags)
{
        struct client_obd *cli = &obd->u.cli;

        OBD_FREE(cli->cl_rpc_lock, sizeof (*cli->cl_rpc_lock));

        ptlrpcd_decref();

        return client_obd_cleanup(obd, 0);
}

static int gkc_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(gkc, &lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

static int gkc_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

static struct obd_ops gkc_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_connect         = client_connect_import,
        .o_disconnect      = client_disconnect_export,
        .o_attach          = gkc_attach,
        .o_detach          = gkc_detach,
        .o_setup           = gkc_setup,
        .o_cleanup         = gkc_cleanup,
        .o_get_info         = gkc_get_info,
        .o_set_info        = gkc_set_info,
};

static int __init gkc_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(gkc, &lvars);
        class_register_type(&gkc_obd_ops, NULL, lvars.module_vars,
                            LUSTRE_GKC_NAME);
        return 0;
}

static void gkc_exit(void)
{
        class_unregister_type(LUSTRE_GKC_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre GS Client (GS)");
MODULE_LICENSE("GPL");

module_init(gkc_init);
module_exit(gkc_exit);

