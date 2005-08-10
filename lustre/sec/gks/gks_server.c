/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lustre GS server
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
#define DEBUG_SUBSYSTEM S_GKS

#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/obd_class.h>
#include <linux/lustre_gs.h>

#include "gks_internal.h"

#define GKS_KEY "19760218"
#define GKS_KEY_LEN 8 
#define GKS_MAC_ALG "sha1"
#define GKS_KEY_ALG "des"
#define GKS_KEY_ALG_MODE CRYPTO_TFM_MODE_CBC

static int gks_cleanup(struct obd_device *obd, int flags)
{
        struct gks_obd *gks = &obd->u.gks;
        ENTRY;     

        if (gks->gks_mac_tfm) {
                crypto_free_tfm(gks->gks_mac_tfm);
        }
        if (gks->gks_key.key) {
                OBD_FREE(gks->gks_key.key, gks->gks_key.len);
        }  
        if (gks->gks_key_tfm) {
                crypto_free_tfm(gks->gks_key_tfm);
        }

        RETURN(0);
}

static int gks_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct gks_obd *gks = &obd->u.gks;
        int rc = 0;

        gks->gks_mac_tfm = crypto_alloc_tfm(GKS_MAC_ALG, 0);
        if (!gks->gks_mac_tfm)
                RETURN(-ENOSYS);
        /*Now: we only keep an unchanged key in the whole system*/
        gks->gks_key.len = GKS_KEY_LEN;
        
        OBD_ALLOC(gks->gks_key.key, GKS_KEY_LEN);

        LASSERT(gks->gks_key.key);
        
        memcpy(gks->gks_key.key, GKS_KEY, GKS_KEY_LEN); 
        /*set gks cipher type*/

        gks->gks_key_tfm = crypto_alloc_tfm(GKS_KEY_ALG, GKS_KEY_ALG_MODE);
        if (!gks->gks_key_tfm)
                GOTO(out, rc = -ENOSYS);                
        if (crypto_cipher_setkey(gks->gks_key_tfm, gks->gks_key.key, 
                                 gks->gks_key.len))
                GOTO(out, rc = -ENOSYS);
out:
        if (rc) {
                gks_cleanup(obd, 0);
        }
        RETURN(rc);
}

static int gks_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data,
                       unsigned long flags)
{
        int rc;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        rc = class_connect(conn, obd, cluuid);

        RETURN(rc);
}

static int gks_disconnect(struct obd_export *exp, unsigned long flags)
{
        int rc = 0;
        ENTRY;

        rc = class_disconnect(exp, flags);
        
        target_destroy_export(exp);
        
        RETURN(rc);
}

static int gks_msg_check_version(struct lustre_msg *msg)
{
        int rc = 0;
        ENTRY;

        switch (msg->opc) {
        case GKS_CONNECT:
        case GKS_DISCONNECT:
                rc = lustre_msg_check_version(msg, LUSTRE_OBD_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_OBD_VERSION);
                break;
        case GKS_GET_KEY:
        case GKS_DECRYPT_KEY:
        case GKS_GET_MAC:
                rc = lustre_msg_check_version(msg, LUSTRE_GKS_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_GKS_VERSION);
                break;
        default:
                CERROR("GKS unknown opcode %d\n", msg->opc);
                rc = -ENOTSUPP;
                break;
        }

        RETURN(rc);
}

static int crypto_get_gks_mac(struct ptlrpc_request *req, 
                              struct key_perm *kperm, 
                              __u8 *hmac)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct gks_obd *gks = &obd->u.gks;
        int perm_size = crypto_kperm_size(kperm->kp_acl_count);
        struct scatterlist sl = {
                .page   = virt_to_page(kperm),
                .offset = (unsigned long)(kperm) % PAGE_SIZE,
                .length = perm_size 
        };
        __u8 *key = gks->gks_key.key; 
        int keylen = gks->gks_key.len;
        struct crypto_tfm *tfm = gks->gks_mac_tfm;

        ENTRY;
        LASSERT(tfm);
        
        crypto_hmac(tfm, key, &keylen, &sl, 1, hmac);
       
        CDEBUG(D_INFO, "compute mac mac %s by uid %d gid %d" 
               "mode %d acl_count %d acl %p perm_size %d\n",
               hmac, kperm->kp_uid, kperm->kp_gid, kperm->kp_mode, 
               kperm->kp_acl_count, kperm->kp_acls, perm_size);
        
        RETURN(0); 
}
#define crypto_decrypt_gks_key(req, data, len) \
crypto_crypt_gks_key(req, data, len, DECRYPT_DATA)

#define crypto_encrypt_gks_key(req, data, len) \
crypto_crypt_gks_key(req, data, len, ENCRYPT_DATA)

static int crypto_crypt_gks_key(struct ptlrpc_request *req, 
                                __u8 *data, int len, int mode) 
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct gks_obd *gks = &obd->u.gks;
        struct scatterlist sl = {
                .page   = virt_to_page(data),
                .offset = (unsigned long)(data) % PAGE_SIZE,
                .length = len 
        };
        struct crypto_tfm *tfm = gks->gks_key_tfm;
        __u8 local_iv[16] = {0};

        ENTRY;
        LASSERT(tfm);
       
        if (mode == ENCRYPT_DATA) 
                crypto_cipher_encrypt_iv(tfm, &sl, &sl, (unsigned int)len, 
                                         local_iv);
        else
                crypto_cipher_decrypt_iv(tfm, &sl, &sl, (unsigned int)len, 
                                         local_iv);
 
        RETURN(0); 
}

static int gks_create_key(struct ptlrpc_request *req, int offset)
{
        struct key_context *kctxt;
        struct crypto_key  *ckey;

        kctxt = lustre_swab_reqbuf(req, offset, sizeof (*kctxt),
                                   lustre_swab_key_context);
     
        ckey = (struct crypto_key *)lustre_msg_buf(req->rq_repmsg, 0, 
                                                   sizeof (*ckey));
        
        crypto_get_gks_mac(req, &kctxt->kc_perm, ckey->ck_mac);

        CDEBUG(D_INFO, "compute mac mac %s by uid %d gid %d mode %d \n",
               ckey->ck_mac, kctxt->kc_perm.kp_uid, kctxt->kc_perm.kp_gid,
               kctxt->kc_perm.kp_mode);
       
        get_random_bytes(ckey->ck_key, KEY_SIZE);        
        
        ckey->ck_type = GKS_TYPE;
        
        CDEBUG(D_INFO, "get key %s\n", ckey->ck_key);

        crypto_encrypt_gks_key(req, ckey->ck_key, KEY_SIZE);

        CDEBUG(D_INFO, "encrypt key %s\n", ckey->ck_key);
        
        RETURN(0); 
}

static int gks_mac_verification(struct ptlrpc_request *req, 
                                struct crypto_key *key, 
                                struct key_perm *kperm)
{
        __u8 *tmp_mac;
        ENTRY;

        OBD_ALLOC(tmp_mac, MAC_SIZE);

        crypto_get_gks_mac(req, kperm, tmp_mac);

        if (!memcmp(tmp_mac, key->ck_mac, MAC_SIZE)) {
                OBD_FREE(tmp_mac, MAC_SIZE);
                RETURN(0); 
        }
        CERROR("new_created %s EA is %s \n", tmp_mac, key->ck_mac);
        OBD_FREE(tmp_mac, MAC_SIZE);
        RETURN(-EPERM);
}

static int gks_permission_check(struct key_context *kctxt,
                                struct key_perm *kperm)
{
        RETURN(0); 
}

static int gks_decrypt_key(struct ptlrpc_request *req, int offset)
{
        struct key_context *kctxt;
        struct key_perm    *kperm;
        struct crypto_key  *ckey;
        int                rc = 0;

        kctxt = lustre_swab_reqbuf(req, offset, sizeof(*kctxt),
                                   lustre_swab_key_context);
        
        /*authiticating the ops of the mac*/
        rc = gks_mac_verification(req, &kctxt->kc_ck, &kctxt->kc_perm);
        if (rc != 0) {
                CERROR("Not my authorization mac %s\n", kctxt->kc_ck.ck_mac);
                RETURN(rc);
        }

        kperm = lustre_swab_reqbuf(req, offset + 1, sizeof(*kperm),
                                   lustre_swab_key_perms);

        rc = gks_permission_check(kctxt, kperm);
        if (rc != 0) {
                CERROR("permssion check failed\n");
                RETURN(rc);
        }
        ckey = (struct crypto_key *)lustre_msg_buf(req->rq_repmsg, 0, 
                                                   sizeof (*ckey));
        memcpy(ckey, &kctxt->kc_ck, sizeof(*ckey));

        rc = crypto_decrypt_gks_key(req, ckey->ck_key, KEY_SIZE);
        if (rc != 0) {
                CERROR("permssion check failed\n");
                RETURN(rc);
        }
        
        RETURN(0); 
}

static int gks_get_mac(struct ptlrpc_request *req, int offset)
{
        struct key_context *kctxt;
        struct key_perm    *kperm;
        struct crypto_key  *ckey;
        int                rc = 0;

        kctxt = lustre_swab_reqbuf(req, offset, sizeof(*kctxt),
                                   lustre_swab_key_context);
        
        /*authiticating the ops of the mac*/
        rc = gks_mac_verification(req, &kctxt->kc_ck, &kctxt->kc_perm);
        if (rc != 0) {
                CERROR("Not my authorization mac %s\n", kctxt->kc_ck.ck_mac);
                RETURN(rc);
        }

        kperm = lustre_swab_reqbuf(req, offset + 1, sizeof(*kperm),
                                   lustre_swab_key_perms);

        rc = gks_permission_check(kctxt, kperm);
        if (rc != 0) {
                CERROR("permssion check failed\n");
                RETURN(rc);
        }
        ckey = (struct crypto_key *)lustre_msg_buf(req->rq_repmsg, 0, 
                                                   sizeof (*ckey));

        memcpy(ckey, &kctxt->kc_ck, sizeof(*ckey));

        ckey->ck_type = GKS_TYPE;
        rc = crypto_get_gks_mac(req, kperm, ckey->ck_mac);
        if (rc != 0) {
                CERROR("get new mac error %d \n", rc);
                RETURN(rc);
        }

        RETURN(rc);
}

int gks_handle(struct ptlrpc_request *req)
{
        int fail = OBD_FAIL_MDS_ALL_REPLY_NET;
        int rc;
        ENTRY;

        rc = gks_msg_check_version(req->rq_reqmsg);
        if (rc) {
                CERROR("GKS drop mal-formed request\n");
                RETURN(rc);
        }
        switch (req->rq_reqmsg->opc) {
        case GKS_CONNECT:
                DEBUG_REQ(D_INODE, req, "connect");
                rc = target_handle_connect(req);
                req->rq_status = rc;            /* superfluous? */
                break;
        case GKS_DISCONNECT:
                DEBUG_REQ(D_INODE, req, "disconnect");
                rc = target_handle_disconnect(req);
                req->rq_status = rc;            /* superfluous? */
                break;

        case GKS_GET_KEY: {
                int size[1] = {sizeof(struct crypto_key)};
                int bufcount = 1;
 
                DEBUG_REQ(D_INODE, req, "get_key");
                lustre_pack_reply(req, bufcount, size, NULL);
                rc = gks_create_key(req, MDS_REQ_REC_OFF);      
                req->rq_status = rc;            /* superfluous? */
                break;     
        }  
        case GKS_DECRYPT_KEY: {
                int size[1] = {sizeof(struct crypto_key)};
                int bufcount = 1;
 
                DEBUG_REQ(D_INODE, req, "decrypt_key");
                lustre_pack_reply(req, bufcount, size, NULL);
                rc = gks_decrypt_key(req, MDS_REQ_REC_OFF);      
                req->rq_status = rc;            /* superfluous? */
                break;     
        }  
        case GKS_GET_MAC: {
                int size[1] = {sizeof(struct crypto_key)};
                int bufcount = 1;
                  
                DEBUG_REQ(D_INODE, req, "get_mac");
                lustre_pack_reply(req, bufcount, size, NULL);
                rc = gks_get_mac(req, MDS_REQ_REC_OFF);      
                req->rq_status = rc;            /* superfluous? */
                break;
        }
        default:
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        } 
        target_send_reply(req, rc, fail);
        RETURN(rc);
}

static int gkt_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct gks_obd *gks = &obd->u.gks;
        int rc = 0;
        ENTRY;

        gks->gks_service =
                ptlrpc_init_svc(GKS_NBUFS, GKS_BUFSIZE, GKS_MAXREQSIZE,
                                GKS_REQUEST_PORTAL, GKC_REPLY_PORTAL,
                                GKS_SERVICE_WATCHDOG_TIMEOUT,
                                gks_handle, "gks", obd->obd_proc_entry);
        if (!gks->gks_service) {
                CERROR("failed to start service\n");
                RETURN(-ENOMEM);
        }

        rc = ptlrpc_start_n_threads(obd, gks->gks_service, GKT_NUM_THREADS,
                                    "ll_gkt");
        
        RETURN(rc);
}

static int gkt_cleanup(struct obd_device *obd, int flags)
{
        struct gks_obd *gks = &obd->u.gks;

        ptlrpc_stop_all_threads(gks->gks_service);
        ptlrpc_unregister_service(gks->gks_service);
        RETURN(0);
}

int gks_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(gks, &lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

int gks_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

int gkt_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(gkt, &lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

int gkt_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

static struct obd_ops gks_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_attach          = gks_attach,
        .o_detach          = gks_detach,
        .o_setup           = gks_setup,
        .o_cleanup         = gks_cleanup,
        .o_connect         = gks_connect,
        .o_disconnect         = gks_disconnect,
};

static struct obd_ops gkt_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_attach          = gkt_attach,
        .o_detach          = gkt_detach,
        .o_setup           = gkt_setup,
        .o_cleanup         = gkt_cleanup,
};

static int __init gks_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(gks, &lvars);
        class_register_type(&gks_obd_ops, NULL, lvars.module_vars,
                            LUSTRE_GKS_NAME);
        
        lprocfs_init_vars(gkt, &lvars);
        class_register_type(&gkt_obd_ops, NULL, lvars.module_vars,
                            LUSTRE_GKT_NAME);
        RETURN(0);
}

static void gks_exit(void)
{
        class_unregister_type(LUSTRE_GKS_NAME);
        class_unregister_type(LUSTRE_GKT_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre GS Server (GS)");
MODULE_LICENSE("GPL");

module_init(gks_init);
module_exit(gks_exit);

