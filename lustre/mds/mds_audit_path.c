/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_fsfilt.h>
#include <linux/init.h>
#include <linux/obd_class.h>
#include <linux/fs.h>
#include <linux/namei.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
# include <linux/smp_lock.h>
# include <linux/buffer_head.h>
# include <linux/workqueue.h>
# include <linux/mount.h>
#else
# include <linux/locks.h>
#endif
#include <linux/lustre_audit.h>
#include "mds_internal.h"


#define PP_FILE         1
#define PP_DIR          2
#define PP_SPLIT_MASTER 3
#define PP_SPLIT_SLAVE  4
#define PP_CROSS_DIR    5
#define PP_AUDIT_LOG    6       /* search id in audit log */

struct scan_dir_data {
        int               rc;
        __u32            i_num;
        __u8             cross_ref;
        char             *name;
};

static int filldir(void *__buf, const char *name, int namlen,
                   loff_t offset, ino_t ino, unsigned int d_type)
{
        struct scan_dir_data *sd = __buf;
        ENTRY;

        if (name[0] == '.' &&
            (namlen == 1 || (namlen == 2 && name[1] == '.'))) {
                /* skip special entries */
                RETURN(0);
        }

        LASSERT(sd != NULL);

        /* skip non-cross_ref entries if we need cross-ref */
        if (sd->cross_ref && !(d_type & 128))
                RETURN(0);

        if (ino == sd->i_num) {
                strncpy(sd->name, name, namlen);
                sd->rc = 0;
                RETURN(-EINTR); /* break the readdir loop */
        }
        RETURN(0);
}

static int scan_name_in_parent(struct lustre_id *pid, struct lustre_id *id,
                               char *name, int cr)
{
        struct file * file;
        char *pname;
        struct scan_dir_data sd;
        int len, rc = 0;
        ENTRY;

        len = strlen("__iopen__/") + 10 + 1;
        OBD_ALLOC(pname, len);
        if (!pname)
                RETURN(-ENOMEM);
        
        sprintf(pname, "__iopen__/0x%llx", id_ino(pid));

        file = filp_open(pname, O_RDONLY, 0);
        if (IS_ERR(file)) {
                CERROR("can't open directory %s: %d\n",
                       pname, (int) PTR_ERR(file));
                GOTO(out, rc = PTR_ERR(file));
        }
        
        sd.i_num = id_ino(id);
        sd.name = name;
        sd.cross_ref = cr;
        sd.rc = -ENOENT;
        vfs_readdir(file, filldir, &sd);

        filp_close(file, 0);
        rc = sd.rc;

out:
        OBD_FREE(pname, len);
        RETURN(rc);

}

/* id2pid - given id, get parent id or master id.
 * @obd:   obd device
 * @id:    child id to be parsed
 * @pid:   parent id or master id
 * @type:  id type
 */
static int 
id2pid(struct obd_device *obd, struct lustre_id *id, struct lustre_id *pid, 
       __u32 *type)
{
        struct dentry *dentry = NULL;
        struct inode *inode = NULL;
        struct mea *mea = NULL;
        int mea_size, rc = 0;
        ENTRY;
        
        dentry = mds_id2dentry(obd, id, NULL);
        if (IS_ERR(dentry) || !dentry->d_inode) {
                CERROR("can't find inode "LPU64"\n", id_ino(id));
                if (!IS_ERR(dentry)) l_dput(dentry);
                RETURN(-ENOENT);
        }
        inode = dentry->d_inode;

        if (S_ISDIR(inode->i_mode)) {
                //LASSERT(S_ISDIR(id_type(id)));
                rc = mds_md_get_attr(obd, inode, &mea, &mea_size);
                if (rc)
                        GOTO(out, rc);
                
                if (!mea) {
                        *type = PP_DIR;
                        goto read_pid;
                } else if (mea && mea->mea_count) {
                        *type = PP_SPLIT_MASTER;
                        goto read_pid;
                } else {
                        *type = PP_SPLIT_SLAVE;
                        *pid = mea->mea_ids[mea->mea_master];
                }
                                
        } else {
                //LASSERT(!S_ISDIR(id_type(id)));
                *type = PP_FILE;
read_pid:
                rc = mds_read_inode_pid(obd, inode, pid);
                if (rc) {
                        CERROR("can't read parent ino(%lu) rc(%d).\n",
                               inode->i_ino, rc);
                        GOTO(out, rc);
                }
        }

        /* Well, if it's dir or master split, we have to check if it's 
         * a cross-ref dir */
        if ((*type == PP_DIR || *type == PP_SPLIT_MASTER) &&
             id_group(id) != id_group(pid))
                *type = PP_CROSS_DIR;
out:
        if (mea)
                OBD_FREE(mea, mea_size);
        l_dput(dentry);
        RETURN(rc);
}

static int local_parse_id(struct obd_device *obd, struct parseid_pkg *pkg)
{
        struct lvfs_run_ctxt saved;
        int rc = 0, cross_ref = 0;
        ENTRY;

        pkg->pp_rc = 0;
        pkg->pp_type = 0;
        memset(pkg->pp_name, 0, sizeof(pkg->pp_name));

        /* pp_id2 is present, which indicating we want to scan parent 
         * dir(pp_id2) to find the cross-ref entry(pp_id1) */
        if (id_fid(&pkg->pp_id2)) {
                LASSERT(obd->u.mds.mds_num == id_group(&pkg->pp_id2));
                pkg->pp_type = PP_DIR;
                cross_ref = 1;                
        } else {
                LASSERT(obd->u.mds.mds_num == id_group(&pkg->pp_id1));
                rc = id2pid(obd, &pkg->pp_id1, &pkg->pp_id2, &pkg->pp_type);
                if (rc)
                        GOTO(out, rc);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        
        switch (pkg->pp_type) {
        case PP_FILE:
        case PP_DIR:
        case PP_SPLIT_MASTER:
                rc = scan_name_in_parent(&pkg->pp_id2, &pkg->pp_id1,
                                         pkg->pp_name, cross_ref);
                if (rc) 
                        CERROR("scan "LPU64" in parent failed. rc=%d\n",
                               id_ino(&pkg->pp_id1), rc);
                break;
        case PP_SPLIT_SLAVE:
        case PP_CROSS_DIR:
                break;
        default:
                CERROR("invalid id\n");
                break;
        }

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
out:
        pkg->pp_rc = rc;
        RETURN(rc);
}

static int 
local_scan_audit_log(struct obd_device *obd, struct parseid_pkg *pkg);

int mds_parse_id(struct ptlrpc_request *req)
{
        struct parseid_pkg *pkg, *reppkg;
        struct obd_device *obd = req->rq_export->exp_obd;
        int rc = 0, size = sizeof(*reppkg);
        ENTRY;

        pkg = lustre_swab_reqbuf(req, 0, sizeof(*pkg), 
                                 lustre_swab_parseid_pkg);
        if (pkg == NULL)
                RETURN(-EPROTO);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);
        
        reppkg = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*reppkg));
        memcpy(reppkg, pkg, sizeof(*reppkg));

        if (reppkg->pp_type == PP_AUDIT_LOG)
                rc = local_scan_audit_log(obd, reppkg);
        else
                rc = local_parse_id(obd, reppkg);
        
        if (rc)
                CERROR("local parseid failed. (rc:%d)\n", rc);
        RETURN(0);  /* we do need pack reply here */
}

static int parse_id(struct obd_device *obd, struct parseid_pkg *pkg)
{
        int rc = 0;
        int mds_num = id_group(&pkg->pp_id1);
        ENTRY;
        
        LASSERT(mds_num >= 0);

        //for cross-ref dir we should send request to parent's MDS
        if (pkg->pp_type == PP_CROSS_DIR)
                mds_num = id_group(&pkg->pp_id2);
        
        if (mds_num == obd->u.mds.mds_num) {
                rc = local_parse_id(obd, pkg);
        } else {
                struct ptlrpc_request *req;
                struct lmv_obd *lmv = &obd->u.mds.mds_md_obd->u.lmv;
                struct parseid_pkg *body;
                int size = sizeof(*body);
                struct obd_export *exp;
                
                /* make sure connection established */
                rc = obd_set_info(obd->u.mds.mds_md_exp, strlen("chkconnect"),
                                  "chkconnect", 0, NULL);
                if (rc)
                        RETURN(rc);

                exp = lmv->tgts[mds_num].ltd_exp;
                LASSERT(exp);

                req = ptlrpc_prep_req(class_exp2cliimp(exp), 
                                      LUSTRE_MDS_VERSION, MDS_PARSE_ID, 1, 
                                      &size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*body));
                memcpy(body, pkg, sizeof(*body));
                
                req->rq_replen = lustre_msg_size(1, &size);

                rc = ptlrpc_queue_wait(req);
                if (rc)
                        GOTO(out, rc);

                body = lustre_swab_repbuf(req, 0, sizeof(*body), 
                                          lustre_swab_parseid_pkg);
                if (body == NULL) {
                        CERROR("can't unpack parseid_pkg\n");
                        GOTO(out, rc = -EPROTO);
                }
                memcpy(pkg, body, sizeof(*pkg));
out:
                ptlrpc_req_finished(req);
        }
        RETURN(rc);
}

#define ROOT_FID        2
struct name_item {
        struct list_head link;
        char             name[NAME_MAX + 1];
};

int 
mds_id2name(struct obd_device *obd, struct lustre_id *id, 
            struct list_head *list, struct lustre_id *lastid)
{
        struct name_item *item;
        struct parseid_pkg *pkg;
        int rc = 0;
        ENTRY;

        OBD_ALLOC(pkg, sizeof(*pkg));
        if (pkg == NULL)
                RETURN(-ENOMEM);

        pkg->pp_id1 = *id;
        while (id_fid(&pkg->pp_id1) != ROOT_FID) {
                
                rc = parse_id(obd, pkg);
                if (rc) {
                        CDEBUG(D_SEC, "parse id failed. rc=%d\n", rc);
                        *lastid = pkg->pp_id1;
                        break;
                }

                switch (pkg->pp_type) {
                case PP_FILE:
                case PP_DIR:
                case PP_SPLIT_MASTER:
                        OBD_ALLOC(item, sizeof(*item));
                        if (item == NULL)
                                GOTO(out, rc = -ENOMEM);
                        
                        INIT_LIST_HEAD(&item->link);
                        list_add(&item->link, list);
                        memcpy(item->name, pkg->pp_name, sizeof(item->name));

                case PP_SPLIT_SLAVE:
                        pkg->pp_id1 = pkg->pp_id2;
                        memset(&pkg->pp_id2, 0, sizeof(struct lustre_id));
                case PP_CROSS_DIR:
                        break;
                default:
                        CERROR("Wrong id = %i\n", pkg->pp_type);
                        break;
                }
                
        }
out:
        OBD_FREE(pkg, sizeof(*pkg));
        RETURN(rc);
}

static int
scan_audit_log_cb(struct llog_handle *llh, struct llog_rec_hdr *rec, void *data)
{
        struct parseid_pkg *pkg = (struct parseid_pkg *)data;
        struct audit_record *ad_rec; 
        struct audit_id_record *cid_rec, *pid_rec;
        struct audit_name_record *nm_rec;
        ENTRY;

        if (!(le32_to_cpu(llh->lgh_hdr->llh_flags) & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }

        if (rec->lrh_type != SMFS_AUDIT_NAME_REC)
                RETURN(0);

        ad_rec = (struct audit_record *)(rec + 1);

        if (ad_rec->result || 
            ad_rec->opcode != AUDIT_UNLINK ||
            ad_rec->opcode != AUDIT_RENAME)
                RETURN(0);

        cid_rec = (struct audit_id_record *)(ad_rec + 1);
        pid_rec = cid_rec + 1;
        nm_rec = (struct audit_name_record *)(pid_rec + 1);
        
        if (cid_rec->au_num == id_ino(&pkg->pp_id1) &&
            cid_rec->au_gen == id_gen(&pkg->pp_id1)) {
                /* get parent id */
                id_ino(&pkg->pp_id2) = pid_rec->au_num;
                id_gen(&pkg->pp_id2) = pid_rec->au_gen;
                id_type(&pkg->pp_id2) = pid_rec->au_type;
                id_fid(&pkg->pp_id2) = pid_rec->au_fid;
                id_group(&pkg->pp_id2) = pid_rec->au_mds;
                /* get name */
                memcpy(pkg->pp_name, nm_rec->name, 
                       le32_to_cpu(nm_rec->name_len));

                RETURN(LLOG_PROC_BREAK);
        }
        RETURN(0);
}

static int
local_scan_audit_log(struct obd_device *obd, struct parseid_pkg *pkg)
{
        struct llog_handle *llh = NULL;
        struct llog_ctxt *ctxt = llog_get_context(&obd->obd_llogs,
                                                  LLOG_AUDIT_ORIG_CTXT);
        int rc = 0;
        ENTRY;

        if (ctxt)
                llh = ctxt->loc_handle;

        if (llh == NULL)
                RETURN(-ENOENT);

        rc = llog_cat_process(llh, (llog_cb_t)&scan_audit_log_cb, (void *)pkg);
        if (rc != LLOG_PROC_BREAK) {
                CWARN("process catalog log failed: rc(%d)\n", rc);
                RETURN(-ENOENT);
        }
        RETURN(0);
}

static int 
scan_audit_log(struct obd_device *obd, struct lustre_id *cur_id, 
               struct list_head *list, struct lustre_id *parent_id)
{
        struct name_item *item = NULL;
        int rc = 0, mds_num = id_group(cur_id);
        struct parseid_pkg *pkg = NULL;
        ENTRY;

        OBD_ALLOC(pkg, sizeof(*pkg));
        if (pkg == NULL)
                RETURN(-ENOMEM);

        pkg->pp_type = PP_AUDIT_LOG;
        pkg->pp_id1 = *cur_id;

        if (obd->u.mds.mds_num == mds_num) {
                rc = local_scan_audit_log(obd, pkg);
        } else {
                struct ptlrpc_request *req;
                struct lmv_obd *lmv = &obd->u.mds.mds_md_obd->u.lmv;
                struct parseid_pkg *body;
                int size = sizeof(*body);
                struct obd_export *exp;
                
                /* make sure connection established */
                rc = obd_set_info(obd->u.mds.mds_md_exp, strlen("chkconnect"),
                                  "chkconnect", 0, NULL);
                if (rc)
                        RETURN(rc);

                exp = lmv->tgts[mds_num].ltd_exp;
                LASSERT(exp);

                req = ptlrpc_prep_req(class_exp2cliimp(exp), 
                                      LUSTRE_MDS_VERSION, MDS_PARSE_ID, 1, 
                                      &size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*body));
                memcpy(body, pkg, sizeof(*body));
                
                req->rq_replen = lustre_msg_size(1, &size);

                rc = ptlrpc_queue_wait(req);
                if (rc)
                        GOTO(out_req, rc);

                body = lustre_swab_repbuf(req, 0, sizeof(*body), 
                                          lustre_swab_parseid_pkg);
                if (body == NULL) {
                        CERROR("can't unpack parseid_pkg\n");
                        GOTO(out, rc = -EPROTO);
                }
                memcpy(pkg, body, sizeof(*pkg));
out_req:
                ptlrpc_req_finished(req);

        }

        if (!rc) rc = pkg->pp_rc;
        if (rc)
                GOTO(out, rc);
        
        *parent_id = pkg->pp_id2;

        OBD_ALLOC(item, sizeof(*item));
        if (item == NULL)
                GOTO(out, rc = -ENOMEM);
        
        INIT_LIST_HEAD(&item->link);
        list_add(&item->link, list);
        memcpy(item->name, pkg->pp_name, sizeof(item->name));
out:
        OBD_FREE(pkg, sizeof(*pkg));
        RETURN(rc);
}
       
int 
mds_audit_id2name(struct obd_device *obd, char **name, int *namelen, 
                  struct lustre_id *id)
{
        int rc = 0;
        struct list_head list, *pos, *n;
        struct name_item *item;
        struct lustre_id parent_id, cur_id;
        ENTRY;

        *namelen = 0;
        INIT_LIST_HEAD(&list);

        cur_id = *id;
        if (id_fid(&cur_id) == ROOT_FID)
                RETURN(0);
next:
        memset(&parent_id, 0, sizeof(parent_id));
        rc = mds_id2name(obd, &cur_id, &list, &parent_id);
        if (rc == -ENOENT) {
                /* can't reconstruct name from id, turn to audit log */
                LASSERT(id_fid(&parent_id));
                cur_id = parent_id;
                memset(&parent_id, 0, sizeof(parent_id));

                rc = scan_audit_log(obd, &cur_id, &list, &parent_id);
                if (rc) {
                        CERROR("scan id in audit log failed. (rc:%d)\n", rc);
                        GOTO(out, rc);
                }

                LASSERT(id_fid(&parent_id));
                cur_id = parent_id;
                goto next;

        } else if (rc) {
                CERROR("reconstruct name from id failed. (rc:%d)\n", rc);
                GOTO(out, rc);
        }
        
        list_for_each_safe (pos, n, &list) {
                item = list_entry(pos, struct name_item, link);
                *namelen += strlen(item->name) + 1;
        }
        
        *namelen++;     /* for the ending '\0' of string */
        OBD_ALLOC(*name, *namelen);
        if (*name == NULL)
                rc = -ENOMEM;
out:
        list_for_each_safe (pos, n, &list) {
                item = list_entry(pos, struct name_item, link);
                
                if (!rc) {
                        strcat(*name, "/");
                        strcat(*name, item->name);
                }
                list_del_init(&item->link);
                OBD_FREE(item, sizeof(*item));
                LASSERT(strlen(*name) < namelen);
        }
        RETURN(rc);
}
EXPORT_SYMBOL(mds_audit_id2name);
