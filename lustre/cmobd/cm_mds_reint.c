/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_smfs.h>

#include "cm_internal.h"

/* converts mds_rec_setattr to struct iattr. */
static inline void cmobd_rec2iattr(struct mds_rec_setattr *rec,
                                   struct iattr *iattr)
{
        iattr->ia_uid = rec->sa_uid;
        iattr->ia_gid = rec->sa_gid;
        iattr->ia_mode = rec->sa_mode;
        iattr->ia_size = rec->sa_size;
        iattr->ia_valid = rec->sa_valid;
        LTIME_S(iattr->ia_atime) = rec->sa_atime;
        LTIME_S(iattr->ia_mtime) = rec->sa_mtime;
        LTIME_S(iattr->ia_ctime) = rec->sa_ctime;
        iattr->ia_attr_flags = rec->sa_attr_flags;
}

static void
cmobd_prepare_mdc_data(struct mdc_op_data *data, struct lustre_id *id1,
                       struct lustre_id *id2, const char *name,
                       int namelen, __u32 mode)
{
        LASSERT(id1);
        LASSERT(data);

        memset(data, 0, sizeof(*data));

        data->id1 = *id1;
        if (id2)
                data->id2 = *id2;
	else
		memset(&data->id2, 0, sizeof(data->id2));

	data->valid = 0;
        data->name = name;
        data->namelen = namelen;
        data->create_mode = mode;
        data->mod_time = CURRENT_TIME;
}

/* If mdc_setattr() is called with an 'iattr', then it is a normal RPC that
 * should take the normal semaphore and go to the normal portal.
 *
 * If it is called with iattr->ia_valid & ATTR_FROM_OPEN, then it is a magic
 * open-path setattr that should take the setattr semaphore and go to the
 * setattr portal. */
static int cmobd_reint_setattr(struct obd_device *obd, void *record)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct ptlrpc_request *req = NULL;
        struct mds_kml_pack_info *mkpi;
        struct mds_rec_setattr *rec;
        struct mdc_op_data op_data;
        struct lustre_msg *msg;
        int ea1len, ea2len;
        struct iattr iattr;
        void *ea1, *ea2;
        int rc = 0;
        ENTRY;

        mkpi = (struct mds_kml_pack_info *)record;
        msg = (struct lustre_msg *)(record + sizeof(*mkpi));

        rec = lustre_msg_buf(msg, 0, 0);
        if (!rec) 
                RETURN(-EINVAL);

        /* converting setattr rec to struct iattr. */
        cmobd_rec2iattr(rec, &iattr);

        /* FIXME-UMKA: here should be handling of setattr() from open. Bug
         * #249. Will be fixed later. */

        /* converting localstore cookie to remote lustre_id. */
        rc = mds_read_mid(cmobd->cache_obd, &rec->sa_id,
                          &rec->sa_id, sizeof(rec->sa_id));
        if (rc) {
                CERROR("Can't read master MDS store cookie "
                       "from local inode EA, err = %d.\n", rc);
                RETURN(rc);
        }

        cmobd_prepare_mdc_data(&op_data, &rec->sa_id, NULL,
                               NULL, 0, 0);

        /* handling possible EAs. */
        ea1 = lustre_msg_buf(msg, 1, 0);
        ea1len = ea1 ? msg->buflens[1] : 0;

        ea2 = lustre_msg_buf(msg, 2, 0);
        ea2len = ea2 ? msg->buflens[2] : 0;

        rc = md_setattr(cmobd->master_exp, &op_data, &iattr,
                        ea1, ea1len, ea2, ea2len, &req);

        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

static int cmobd_reint_create(struct obd_device *obd, void *record)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct ptlrpc_request *req = NULL;
        struct mds_kml_pack_info *mkpi;
        int rc = 0, namelen, datalen;
        struct mds_rec_create *rec;
        struct mdc_op_data op_data;
        struct lustre_msg *msg;
        struct mds_body *body;
        struct lustre_id lid;
        char *name, *data;
        ENTRY;

        mkpi = (struct mds_kml_pack_info *)record;
        msg = (struct lustre_msg *)(record + sizeof(*mkpi));

        rec = lustre_msg_buf(msg, 0, 0);
        if (!rec) 
                RETURN(-EINVAL);
        
        lid = rec->cr_replayid;

        /* zeroing @rec->cr_replayid out in request, as master MDS should create
         * own inode (with own store cookie). */
        memset(&rec->cr_replayid, 0, sizeof(rec->cr_replayid));

        /* converting local inode store cookie to remote lustre_id. */
        rc = mds_read_mid(cmobd->cache_obd, &rec->cr_id,
                          &rec->cr_id, sizeof(rec->cr_id));
        if (rc) {
                CERROR("Can't read master MDS store cookie "
                       "from local inode EA, err = %d.\n", rc);
                RETURN(rc);
        }

        /* getting name to be created and its length */
        name = lustre_msg_string(msg, 1, 0);
        namelen = name ? msg->buflens[1] - 1 : 0;

        /* getting misc data (symlink) and its length */
        data = (char *)lustre_msg_buf(msg, 2, 0);
        datalen = data ? msg->buflens[2] : 0;

        /* prepare mdc request data. */
        cmobd_prepare_mdc_data(&op_data, &rec->cr_id, &rec->cr_replayid,
                               name, namelen, rec->cr_mode);

        /* requesting to master to create object with passed attributes. */
        rc = md_create(cmobd->master_exp, &op_data, data, datalen,
                       rec->cr_mode, current->fsuid, current->fsgid,
                       rec->cr_rdev, &req);

        if (!rc) {
                /* here we save store cookie from master MDS to local 
                 * inode EA. */
                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));

                rc = mds_update_mid(cmobd->cache_obd, &lid,
                                    &body->id1, sizeof(body->id1));
        }

        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

static int cmobd_reint_unlink(struct obd_device *obd, void *record)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct ptlrpc_request *req = NULL;
        struct mds_kml_pack_info *mkpi;
        struct mdc_op_data op_data;
        struct mds_rec_unlink *rec;
        struct lustre_msg *msg;
        int rc = 0, namelen;
        char *name = NULL;
        ENTRY;
        
        mkpi = (struct mds_kml_pack_info *)record;
        msg = (struct lustre_msg *)(record + sizeof(*mkpi));

        rec = lustre_msg_buf(msg, 0, 0);
        if (!rec) 
                RETURN(-EINVAL);

        /* converting local store cookie to remote lustre_id. */
        rc = mds_read_mid(cmobd->cache_obd, &rec->ul_id1,
                          &rec->ul_id1, sizeof(rec->ul_id1));
        if (rc) {
                CERROR("Can't read master MDS store cookie "
                       "from local inode EA, err = %d.\n", rc);
                RETURN(rc);
        }

        /* getting name to be created and its length */
        name = lustre_msg_string(msg, 1, 0);
        namelen = name ? msg->buflens[1] - 1 : 0;

        /* prepare mdc request data. */
        cmobd_prepare_mdc_data(&op_data, &rec->ul_id1, NULL,
                               name, namelen, rec->ul_mode);

        rc = md_unlink(cmobd->master_exp, &op_data, &req);

        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

static int cmobd_reint_link(struct obd_device *obd, void *record)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct ptlrpc_request *req = NULL;
        struct mds_kml_pack_info *mkpi;
        struct mdc_op_data op_data;
        struct mds_rec_link *rec;
        struct lustre_msg *msg;
        int rc = 0, namelen;
        char *name;
        ENTRY;

        mkpi = (struct mds_kml_pack_info *)record;
        msg = (struct lustre_msg *)(record + sizeof(*mkpi));
        
        rec = lustre_msg_buf(msg, 0, 0);
        if (!rec) 
                RETURN(-EINVAL);

        /* converting local store cookie for both ids to remote lustre_id. */
        rc = mds_read_mid(cmobd->cache_obd, &rec->lk_id1,
                          &rec->lk_id1, sizeof(rec->lk_id1));
        if (rc) {
                CERROR("Can't read master MDS store cookie "
                       "from local inode EA, err = %d.\n", rc);
                RETURN(rc);
        }
        
        rc = mds_read_mid(cmobd->cache_obd, &rec->lk_id2,
                          &rec->lk_id2, sizeof(rec->lk_id2));
        if (rc) {
                CERROR("Can't read master MDS store cookie "
                       "from local inode EA, err = %d.\n", rc);
                RETURN(rc);
        }
        
        /* getting name to be created and its length */
        name = lustre_msg_string(msg, 1, 0);
        namelen = name ? msg->buflens[1] - 1: 0;

        /* prepare mdc request data. */
        cmobd_prepare_mdc_data(&op_data, &rec->lk_id1, &rec->lk_id2,
                               name, namelen, 0);

        rc = md_link(cmobd->master_exp, &op_data, &req);

        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

static int cmobd_reint_rename(struct obd_device *obd, void *record)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct ptlrpc_request *req = NULL;
        struct mds_kml_pack_info *mkpi;
        struct mdc_op_data op_data;
        struct mds_rec_rename *rec;
        int rc = 0, oldlen, newlen;
        struct lustre_msg *msg;
        char *old, *new;
        ENTRY;

        mkpi = (struct mds_kml_pack_info *)record;
        msg = (struct lustre_msg *)(record + sizeof(*mkpi));
        
        rec = lustre_msg_buf(msg, 0, 0);
        if (!rec) 
                RETURN(-EINVAL);
        
        /* converting local store cookie for both ids to remote lustre_id. */
        rc = mds_read_mid(cmobd->cache_obd, &rec->rn_id1,
                          &rec->rn_id1, sizeof(rec->rn_id1));
        if (rc) {
                CERROR("Can't read master MDS store cookie "
                       "from local inode EA, err = %d.\n", rc);
                RETURN(rc);
        }
        
        rc = mds_read_mid(cmobd->cache_obd, &rec->rn_id2,
                          &rec->rn_id2, sizeof(rec->rn_id2));
        if (rc) {
                CERROR("Can't read master MDS store cookie "
                       "from local inode EA, err = %d.\n", rc);
                RETURN(rc);
        }

        /* getting old name and its length */
        old = lustre_msg_string(msg, 1, 0);
        oldlen = old ? msg->buflens[1] - 1 : 0;

        /* getting new len and its length */
        new = lustre_msg_string(msg, 2, 0);
        newlen = new ? msg->buflens[2] - 1: 0;
        
        /* prepare mdc request data. */
        cmobd_prepare_mdc_data(&op_data, &rec->rn_id1, &rec->rn_id1,
                               NULL, 0, 0);

        rc = md_rename(cmobd->master_exp, &op_data, old, oldlen,
                       new, newlen, &req);

        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

typedef int (*cmobd_reint_rec_func_t)(struct obd_device *, void *);

static cmobd_reint_rec_func_t mds_reint_handler[REINT_MAX + 1] = {
        [REINT_SETATTR] cmobd_reint_setattr,
        [REINT_CREATE] cmobd_reint_create,
        [REINT_LINK] cmobd_reint_link,
        [REINT_UNLINK] cmobd_reint_unlink,
        [REINT_RENAME] cmobd_reint_rename,
};

int cmobd_reint_mds(struct obd_device *obd, void *record, int dummy)
{
        struct mds_kml_pack_info *mkpi;
        struct lustre_msg *msg;
        __u32 opcode;
        
        mkpi = (struct mds_kml_pack_info *)record;
        msg = (struct lustre_msg *)(record + sizeof(*mkpi));
        
        opcode = *(__u32 *)lustre_msg_buf(msg, 0, 0);
        
        if (opcode > REINT_MAX || opcode <= 0) {
                CERROR("Invalid mds reint opcode %u\n",
                       opcode);
                return -EINVAL;
        }
        
        return mds_reint_handler[opcode](obd, record);
} 
