/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_LMV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <asm/div64.h>
#include <linux/seq_file.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_ost.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd_lmv.h>
#include "lmv_internal.h"


LIST_HEAD(lmv_obj_list);
spinlock_t lmv_obj_list_lock = SPIN_LOCK_UNLOCKED;

struct lmv_obj *lmv_grab_obj(struct obd_device *obd,
                             struct ll_fid *fid, int create)
{
        struct lmv_obd *lmv = &obd->u.lmv;
        struct list_head *cur;
        struct lmv_obj *obj, *obj2;

        spin_lock(&lmv_obj_list_lock);
        list_for_each(cur, &lmv_obj_list) {
                obj = list_entry(cur, struct lmv_obj, list);
                if (obj->fid.mds == fid->mds && obj->fid.id == fid->id &&
                                obj->fid.generation == fid->generation) {
                        atomic_inc(&obj->count);
                        spin_unlock(&lmv_obj_list_lock);
                        RETURN(obj);
                }
        }
        spin_unlock(&lmv_obj_list_lock);

        if (!create)
                RETURN(NULL);

        /* no such object yet, allocate and initialize them */
        OBD_ALLOC(obj, sizeof(*obj));
        if (!obj)
                RETURN(NULL);
        atomic_set(&obj->count, 0);
        obj->fid = *fid;
        obj->obd = obd;

        OBD_ALLOC(obj->objs, sizeof(struct lmv_inode) * lmv->count);
        if (!obj->objs) {
                OBD_FREE(obj, sizeof(*obj));
                RETURN(NULL);
        }
        memset(obj->objs, 0,  sizeof(struct lmv_inode) * lmv->count);

        spin_lock(&lmv_obj_list_lock);
        list_for_each(cur, &lmv_obj_list) {
                obj2 = list_entry(cur, struct lmv_obj, list);
                if (obj2->fid.mds == fid->mds && obj2->fid.id == fid->id &&
                                obj2->fid.generation == fid->generation) {
                        /* someone created it already */
                        OBD_FREE(obj->objs,
                                  sizeof(struct lmv_inode) * lmv->count);
                        OBD_FREE(obj, sizeof(*obj));

                        atomic_inc(&obj2->count);
                        spin_unlock(&lmv_obj_list_lock);
                        RETURN(obj2);
                }
        }
        list_add(&obj->list, &lmv_obj_list);
        CDEBUG(D_OTHER, "new obj in lmv cache: %lu/%lu/%lu\n",
               (unsigned long) fid->mds, (unsigned long) fid->id,
               (unsigned long) fid->generation);
        spin_unlock(&lmv_obj_list_lock);

        RETURN(obj);
        
}

void lmv_put_obj(struct lmv_obj *obj)
{
        if (!obj)
                return;
        if (atomic_dec_and_test(&obj->count)) {
                CDEBUG(D_OTHER, "last reference to %lu/%lu/%lu\n",
                       (unsigned long) obj->fid.mds,
                       (unsigned long) obj->fid.id,
                       (unsigned long) obj->fid.generation);
        }
}

void lmv_cleanup_objs(struct obd_device *obd)
{
        struct lmv_obd *lmv = &obd->u.lmv;
        struct list_head *cur, *tmp;
        struct lmv_obj *obj;

        spin_lock(&lmv_obj_list_lock);
        list_for_each_safe(cur, tmp, &lmv_obj_list) {
                obj = list_entry(cur, struct lmv_obj, list);
                if (obj->obd != obd)
                        continue;

                list_del(&obj->list);
                OBD_FREE(obj->objs,
                                sizeof(struct lmv_inode) * lmv->count);
                OBD_FREE(obj, sizeof(*obj));
        }
        spin_unlock(&lmv_obj_list_lock);
}

int lmv_create_obj_from_attrs(struct obd_export *exp,
                              struct ll_fid *fid, struct mea *mea)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ptlrpc_request *req = NULL;
        struct lmv_obj *obj;
        struct lustre_md md;
        int mealen, i, rc = 0;
        ENTRY;

        CDEBUG(D_OTHER, "get mea for %lu/%lu/%lu and create lmv obj\n",
               (unsigned long) fid->mds, (unsigned long) fid->id,
               (unsigned long) fid->generation);

        if (!mea) {
                unsigned long valid;
                
                CDEBUG(D_OTHER, "mea isn't passed in, get it now\n");
                mealen = MEA_SIZE_LMV(lmv);
                
                /* time to update mea of parent fid */
                i = fid->mds;
                md.mea = NULL;
                
                valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA;
                rc = md_getattr(lmv->tgts[fid->mds].exp, fid,
                                valid, mealen, &req);
                if (rc) {
                        CERROR("md_getattr() failed, rc = %d\n", rc);
                        GOTO(cleanup, rc);
                }

                rc = mdc_req2lustre_md(exp, req, 0, NULL, &md);
                if (rc) {
                        CERROR("mdc_req2lustre_md() failed, rc = %d\n", rc);
                        GOTO(cleanup, rc);
                }

                if (md.mea == NULL)
                        GOTO(cleanup, rc = -ENODATA);
                        
                mea = md.mea;
        }

        /* got mea, now create obj for it */
        obj = lmv_grab_obj(obd, fid, 1);
        if (!obj)
                GOTO(cleanup, rc = -ENOMEM);

        obj->objcount = mea->mea_count;
        /* put all fids in */
        for (i = 0; i < mea->mea_count; i++) {
                CDEBUG(D_OTHER, "subobj %lu/%lu/%lu\n",
                       (unsigned long) mea->mea_fids[i].mds,
                       (unsigned long) mea->mea_fids[i].id,
                       (unsigned long) mea->mea_fids[i].generation);
                obj->objs[i].fid = mea->mea_fids[i];
        }

cleanup:
        if (req)       
                ptlrpc_req_finished(req);
        RETURN(rc); 
}


