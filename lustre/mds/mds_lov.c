/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_lov.c
 *  Lustre Metadata Server (mds) handling of striped file data
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
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
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_fsfilt.h>

#include "mds_internal.h"

void le_lov_desc_to_cpu (struct lov_desc *ld)
{
        ld->ld_tgt_count = le32_to_cpu (ld->ld_tgt_count);
        ld->ld_default_stripe_count = le32_to_cpu (ld->ld_default_stripe_count);
        ld->ld_default_stripe_size = le32_to_cpu (ld->ld_default_stripe_size);
        ld->ld_pattern = le32_to_cpu (ld->ld_pattern);
}

void cpu_to_le_lov_desc (struct lov_desc *ld)
{
        ld->ld_tgt_count = cpu_to_le32 (ld->ld_tgt_count);
        ld->ld_default_stripe_count = cpu_to_le32 (ld->ld_default_stripe_count);
        ld->ld_default_stripe_size = cpu_to_le32 (ld->ld_default_stripe_size);
        ld->ld_pattern = cpu_to_le32 (ld->ld_pattern);
}

void mds_lov_update_objids(struct obd_device *obd, obd_id *ids)
{
        struct mds_obd *mds = &obd->u.mds;
        int i;
        ENTRY;

        lock_kernel();
        for (i = 0; i < mds->mds_lov_desc.ld_tgt_count; i++)
                if (ids[i] > (mds->mds_lov_objids)[i])
                        (mds->mds_lov_objids)[i] = ids[i];
        unlock_kernel();
        EXIT;
}

static int mds_lov_read_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        obd_id *ids;
        loff_t off = 0;
        int i, rc, size = mds->mds_lov_desc.ld_tgt_count * sizeof(*ids);
        ENTRY;

        if (mds->mds_lov_objids != NULL)
                RETURN(0);

        OBD_ALLOC(ids, size);
        if (ids == NULL)
                RETURN(-ENOMEM);
        mds->mds_lov_objids = ids;

        if (mds->mds_lov_objid_filp->f_dentry->d_inode->i_size == 0)
                RETURN(0);
        rc = fsfilt_read_record(obd, mds->mds_lov_objid_filp, ids, size, &off);
        if (rc < 0) {
                CERROR("Error reading objids %d\n", rc);
        } else {
                mds->mds_lov_objids_valid = 1;
                rc = 0;
        }

        for (i = 0; i < mds->mds_lov_desc.ld_tgt_count; i++)
                CDEBUG(D_INFO, "read last object "LPU64" for idx %d\n",
                       mds->mds_lov_objids[i], i);

        RETURN(rc);
}

int mds_lov_write_objids(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        loff_t off = 0;
        int i, rc, size = mds->mds_lov_desc.ld_tgt_count * sizeof(obd_id);
        ENTRY;

        /* I'm pretty sure we don't need this mds_lov_connect here,
         * but we definitely don't want to do it during recovery. */
        if (!obd->obd_recovering && unlikely(mds->mds_osc_obd == NULL))
                mds_lov_connect(obd);

        for (i = 0; i < mds->mds_lov_desc.ld_tgt_count; i++)
                CDEBUG(D_INFO, "writing last object "LPU64" for idx %d\n",
                       mds->mds_lov_objids[i], i);

        rc = fsfilt_write_record(obd, mds->mds_lov_objid_filp,
                                 mds->mds_lov_objids, size, &off, 0);
        RETURN(rc);
}


int mds_set_lovdesc(struct obd_device *obd, struct lov_desc *desc,
                    struct obd_uuid *uuidarray)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_run_ctxt saved;
        struct file *f;
        int tgt_count;
        int rc;
        int i;
        struct lov_desc *disk_desc;
        ENTRY;

        tgt_count = desc->ld_tgt_count;
        if (desc->ld_default_stripe_count > desc->ld_tgt_count) {
                CERROR("default stripe count %u > OST count %u\n",
                       desc->ld_default_stripe_count, desc->ld_tgt_count);
                RETURN(-EINVAL);
        }
        if (desc->ld_default_stripe_size & (PAGE_SIZE - 1)) {
                CERROR("default stripe size "LPU64" not a multiple of %lu\n",
                       desc->ld_default_stripe_size, PAGE_SIZE);
                RETURN(-EINVAL);
        }
        if (desc->ld_default_stripe_offset > desc->ld_tgt_count) {
                CERROR("default stripe offset "LPU64" > max OST index %u\n",
                       desc->ld_default_stripe_offset, desc->ld_tgt_count);
                RETURN(-EINVAL);
        }
        if (desc->ld_pattern != 0) {
                CERROR("stripe pattern %u unknown\n",
                       desc->ld_pattern);
                RETURN(-EINVAL);
        }

        OBD_ALLOC (disk_desc, sizeof (*disk_desc));
        if (disk_desc == NULL) {
                CERROR ("Can't allocate disk_desc\n");
                RETURN (-ENOMEM);
        }

        *disk_desc = *desc;
        cpu_to_le_lov_desc (disk_desc);

        rc = 0;
        push_ctxt(&saved, &obd->obd_ctxt, NULL);

        /* Bug 1186: FIXME: if there is an existing LOVDESC, verify new
         * tgt_count > old */
        f = filp_open("LOVDESC", O_CREAT|O_RDWR, 0644);
        if (IS_ERR(f)) {
                CERROR("Cannot open/create LOVDESC file\n");
                GOTO(out, rc = PTR_ERR(f));
        }

        rc = lustre_fwrite(f, (char *)disk_desc, sizeof(*disk_desc), &f->f_pos);
        if (filp_close(f, 0))
                CERROR("Error closing LOVDESC file\n");
        if (rc != sizeof(*desc)) {
                CERROR("Cannot open/create LOVDESC file\n");
                if (rc >= 0)
                        rc = -EIO;
                GOTO(out, rc);
        }

        /* Bug 1186: FIXME: if there is an existing LOVTGTS, verify
         * existing UUIDs same */
        f = filp_open("LOVTGTS", O_CREAT|O_RDWR, 0644);
        if (IS_ERR(f)) {
                CERROR("Cannot open/create LOVTGTS file\n");
                GOTO(out, rc = PTR_ERR(f));
        }

        rc = 0;
        for (i = 0; i < tgt_count ; i++) {
                rc = lustre_fwrite(f, uuidarray[i].uuid,
                                   sizeof(uuidarray[i]), &f->f_pos);
                if (rc != sizeof(uuidarray[i])) {
                        CERROR("cannot write LOV UUID %s (%d)\n",
                               uuidarray[i].uuid, i);
                        if (rc >= 0)
                                rc = -EIO;
                        break;
                }
                rc = 0;
        }
        if (filp_close(f, 0))
                CERROR("Error closing LOVTGTS file\n");

        memcpy(&mds->mds_lov_desc, desc, sizeof *desc);
        mds->mds_has_lov_desc = 1;
        /* XXX the MDS should not really know about this */
        mds->mds_max_mdsize = lov_mds_md_size(desc->ld_tgt_count);
        mds->mds_max_cookiesize = desc->ld_tgt_count*sizeof(struct llog_cookie);

out:
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        OBD_FREE (disk_desc, sizeof (*disk_desc));

        RETURN(rc);
}

int mds_get_lovdesc(struct mds_obd *mds, struct lov_desc *desc)
{
        struct file *f;
        int rc;
        ENTRY;

        f = filp_open("LOVDESC", O_RDONLY, 0644);
        if (IS_ERR(f)) {
                CERROR("Cannot open LOVDESC file\n");
                GOTO(out, rc = PTR_ERR(f));
        }

        rc = lustre_fread(f, (char *)desc, sizeof(*desc), &f->f_pos);
        if (filp_close(f, 0))
                CERROR("Error closing LOVDESC file\n");

        if (rc != sizeof(*desc)) {
                CERROR("Cannot read LOVDESC file: rc = %d\n", rc);
                GOTO(out, rc = -EIO);
        } else
                rc = 0;

        le_lov_desc_to_cpu (desc);              /* convert to my byte order */

        EXIT;
out:

        return rc;
}

int mds_get_lovtgts(struct obd_device *obd, int tgt_count,
                    struct obd_uuid *uuidarray)
{
        struct obd_run_ctxt saved;
        struct file *f;
        int rc;
        int rc2;

        push_ctxt(&saved, &obd->obd_ctxt, NULL);
        f = filp_open("LOVTGTS", O_RDONLY, 0644);
        if (IS_ERR(f)) {
                CERROR("Cannot open LOVTGTS file\n");
                GOTO(out, rc = PTR_ERR(f));
        }

        rc = lustre_fread(f, (char *)uuidarray, tgt_count * sizeof(*uuidarray),
                          &f->f_pos);
        rc2 = filp_close(f, 0);
        if (rc2)
                CERROR("Error closing LOVTGTS file: rc = %d\n", rc2);

        if (rc != tgt_count * sizeof(*uuidarray)) {
                CERROR("Error reading LOVTGTS file: rc = %d\n", rc);
                if (rc >= 0)
                        rc = -EIO;
                GOTO(out, rc);
        } else
                rc = 0;
        EXIT;
out:
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        RETURN(rc);
}

static int mds_lov_clearorphans(struct mds_obd *mds)
{
        int rc;
        struct obdo oa;
        struct obd_trans_info oti = {0};
        struct lov_stripe_md  *empty_ea = NULL;
        ENTRY;

        LASSERT(mds->mds_lov_objids != NULL);

        /* This create will in fact either create or destroy:  If the OST is
         * missing objects below this ID, they will be created.  If it finds
         * objects above this ID, they will be removed. */
        memset(&oa, 0, sizeof(oa));
        oa.o_valid = OBD_MD_FLFLAGS;
        oa.o_flags = OBD_FL_DELORPHAN;
        rc = obd_create(mds->mds_osc_exp, &oa, &empty_ea, &oti);

        RETURN(rc);
}

/* update the LOV-OSC knowledge of the last used object id's */
int mds_lov_set_nextid(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc;
        ENTRY;

        LASSERT(!obd->obd_recovering);

        if (mds->mds_osc_obd == NULL)
                mds_lov_connect(obd);

        // XXX CONFIG remove me when configuration is better
        down(&mds->mds_orphan_recovery_sem);
        if (mds->mds_lov_nextid_set) {
                up(&mds->mds_orphan_recovery_sem);
                RETURN(0);
        }

        LASSERT(mds->mds_lov_objids != NULL);

        rc = obd_set_info(mds->mds_osc_exp, strlen("next_id"), "next_id",
                          mds->mds_lov_desc.ld_tgt_count, mds->mds_lov_objids);
        if (rc < 0)
                GOTO(out, rc);

        rc = mds_lov_clearorphans(mds);
        if (rc < 0)
                GOTO(out, rc);

        // XXX CONFIG warning remove me when configuration is better
        mds->mds_lov_nextid_set = 1;
out:
        if (rc && mds->mds_lov_objids)
                OBD_FREE(mds->mds_lov_objids,
                         mds->mds_lov_desc.ld_tgt_count * sizeof(obd_id));

        up(&mds->mds_orphan_recovery_sem);
        RETURN(rc);
}

/* tell the LOV-OSC by how much to pre-create */
int mds_lov_set_growth(struct mds_obd *mds, int count)
{
        int rc;
        ENTRY;

        rc = obd_set_info(mds->mds_osc_exp, strlen("growth_count"), 
                          "growth_count", sizeof(count), &count);
                
        RETURN(rc);
}

/* Establish a connection to the OSC when we first need it.  We don't do
 * this during MDS setup because that would introduce setup ordering issues. */
int mds_lov_connect(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_handle conn = {0,};
        int rc, i;
        ENTRY;

        LASSERT(!obd->obd_recovering);

        if (IS_ERR(mds->mds_osc_obd))
                RETURN(PTR_ERR(mds->mds_osc_obd));

        if (mds->mds_osc_obd)
                RETURN(0);

        mds->mds_osc_obd = class_name2obd(mds->mds_lov_name);
        if (!mds->mds_osc_obd) {
                CERROR("MDS cannot locate LOV %s - no logging!\n",
                       mds->mds_lov_name);
                mds->mds_osc_obd = ERR_PTR(-ENOTCONN);
                RETURN(-ENOTCONN);
        }

        rc = obd_connect(&conn, mds->mds_osc_obd, &obd->obd_uuid);
        if (rc) {
                CERROR("MDS cannot connect to LOV %s (%d) - no logging!\n",
                       mds->mds_lov_name, rc);
                mds->mds_osc_obd = ERR_PTR(rc);
                RETURN(rc);
        }
        mds->mds_osc_exp = class_conn2export(&conn);

        rc = obd_set_info(mds->mds_osc_exp, strlen("mds_conn"), "mds_conn",
                          0, NULL);
        if (rc) {
                obd_disconnect(mds->mds_osc_exp, 0);
                mds->mds_osc_exp = NULL;
                RETURN(rc);
        }

        /* If we're mounting this code for the first time on an existing FS,
         * we need to populate the objids array from the real OST values */
        if (!mds->mds_lov_objids_valid) {
                int size = sizeof(obd_id) * mds->mds_lov_desc.ld_tgt_count;
                rc = obd_get_info(mds->mds_osc_exp, strlen("last_id"),
                                  "last_id", &size, mds->mds_lov_objids);
                if (!rc) {
                        for (i = 0; i < mds->mds_lov_desc.ld_tgt_count; i++)
                                CWARN("got last object "LPU64" from OST %d\n",
                                      mds->mds_lov_objids[i], i);
                        mds->mds_lov_objids_valid = 1;
                        rc = mds_lov_write_objids(obd);
                        if (rc)
                                CERROR("got last objids from OSTs, but error "
                                       "writing objids file: %d\n", rc);
                }
        }

        // XXX CONFIG LOV-OSC may not be used before this call completes!!!
        // XXX CONFIG this cannot be called here, because the osc is not set up
        // rc = mds_lov_set_nextid(obd);
        RETURN(rc);
}

int mds_post_mds_lovconf(struct obd_device *obd)
{
        int rc = mds_lov_read_objids(obd);
        if (rc)
                CERROR("cannot read %s: rc = %d\n", "lov_objids", rc);
        return rc;
}

int 
mds_process_log_rec(struct llog_handle * loghandle, 
                            struct llog_rec_hdr *rec, void *data)
{
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        int rc = 0;

        if (rec->lrh_type == OBD_CFG_REC) {
                char *buf;
                rc = lustre_cfg_getdata(&buf,cfg_len, cfg_buf, 1);
                if (rc) 
                        RETURN(rc);
                rc = class_process_config((struct lustre_cfg* ) buf);
                lustre_cfg_freedata(buf, cfg_len);
        } else if (rec->lrh_type == PTL_CFG_REC) {
                rc = kportal_nal_cmd((struct portals_cfg *)cfg_buf);
        }
        RETURN(rc);
}

int mds_iocontrol(unsigned int cmd, struct obd_export *exp, int len, 
                  void *karg, void *uarg)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct obd_device *obd = exp->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct obd_ioctl_data *data = karg;
        struct lov_desc *desc;
        struct obd_uuid *uuidarray;
        struct obd_run_ctxt saved;
        int count;
        int rc = 0;

        switch (cmd) {
        case OBD_IOC_RECORD: {
                char *name = data->ioc_inlbuf1;
                if (mds->mds_cfg_llh)
                        RETURN(-EBUSY);

                obd->obd_log_exp = class_export_get(exp);

                push_ctxt(&saved, &obd->obd_ctxt, NULL);
                rc = llog_create(obd, &mds->mds_cfg_llh, NULL, name);
                if (rc == 0)
                        llog_init_handle(mds->mds_cfg_llh, LLOG_F_IS_PLAIN, 
                                         &cfg_uuid);
                else
                        mds->mds_cfg_llh = NULL;
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);
                        

                RETURN(rc);
        }

        case OBD_IOC_ENDRECORD: {
                if (!mds->mds_cfg_llh)
                        RETURN(-EBADF);

                push_ctxt(&saved, &obd->obd_ctxt, NULL);
                rc = llog_close(mds->mds_cfg_llh);
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);

                mds->mds_cfg_llh = NULL;
                class_export_put(obd->obd_log_exp);
                obd->obd_log_exp = NULL;
                RETURN(rc);
        }

        case OBD_IOC_DORECORD: {
                char *cfg_buf;
                struct llog_rec_hdr rec;
                if (!mds->mds_cfg_llh)
                        RETURN(-EBADF);

                rec.lrh_len = data->ioc_plen1;

                if (data->ioc_type == LUSTRE_CFG_TYPE) {
                        rec.lrh_type = OBD_CFG_REC;
                } else if (data->ioc_type == PORTALS_CFG_TYPE) {
                        rec.lrh_type = PTL_CFG_REC;
                } else {
                        CERROR("unknown cfg record type:%d \n", data->ioc_type);
                        RETURN(-EINVAL);
                }

                OBD_ALLOC(cfg_buf, data->ioc_plen1);
                if (cfg_buf == NULL)
                        RETURN(-EINVAL);
                rc = copy_from_user(cfg_buf, data->ioc_pbuf1, data->ioc_plen1);
                if (rc) {
                        OBD_FREE(cfg_buf, data->ioc_plen1);
                        RETURN(rc);
                }

                push_ctxt(&saved, &obd->obd_ctxt, NULL);
                rc = llog_write_rec(mds->mds_cfg_llh, &rec, NULL, 0,
                                    cfg_buf, -1);
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);

                OBD_FREE(cfg_buf, data->ioc_plen1);
                RETURN(rc);
        }

        case OBD_IOC_PARSE: {
                char *name = data->ioc_inlbuf1;
                struct llog_handle *llh;

                obd->obd_log_exp = class_export_get(exp);

                push_ctxt(&saved, &obd->obd_ctxt, NULL);
                rc = llog_create(obd, &llh, NULL, name);
                if (rc) {
                        class_export_put(obd->obd_log_exp);
                        obd->obd_log_exp = NULL;
                        RETURN(rc);
                }

                rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, 
                                      &cfg_uuid);
                if (rc) {
                        class_export_put(obd->obd_log_exp);
                        obd->obd_log_exp = NULL;
                        RETURN(rc);
                }

                rc = llog_process(llh, mds_process_log_rec, NULL);
                if (rc) {
                        class_export_put(obd->obd_log_exp);
                        obd->obd_log_exp = NULL;
                        RETURN(rc);
                }

                rc = llog_close(llh);
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);

                // XXX CONFIG this is here because the LOV is set up at an unexpected time
                rc  = mds_post_mds_lovconf(obd);
                if (rc)
                        RETURN(rc);

                RETURN(rc);
        }


        case OBD_IOC_LOV_GET_CONFIG: {
                desc = (struct lov_desc *)data->ioc_inlbuf1;
                if (sizeof(*desc) > data->ioc_inllen1) {
                        CERROR("descriptor size wrong\n");
                        RETURN(-EINVAL);
                }

                count = desc->ld_tgt_count;
                uuidarray = (struct obd_uuid *)data->ioc_inlbuf2;
                if (sizeof(*uuidarray) * count != data->ioc_inllen2) {
                        CERROR("UUID array size wrong\n");
                        RETURN(-EINVAL);
                }
                push_ctxt(&saved, &obd->obd_ctxt, NULL);
                rc = mds_get_lovdesc(&obd->u.mds, desc);
                pop_ctxt(&saved, &obd->obd_ctxt, NULL);

                if (desc->ld_tgt_count > count) {
                        CERROR("UUID array size too small\n");
                        RETURN(-ENOSPC);
                }
                rc = mds_get_lovtgts(obd, desc->ld_tgt_count, uuidarray);

                RETURN(rc);
        }
        case OBD_IOC_SET_READONLY: {
                void *handle;
                struct inode *inode = obd->u.mds.mds_sb->s_root->d_inode;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                BDEVNAME_DECLARE_STORAGE(tmp);
                CERROR("setting device %s read-only\n",
                       ll_bdevname(obd->u.mds.mds_sb->s_dev, tmp));
                
                handle = fsfilt_start(obd, inode, FSFILT_OP_MKNOD, NULL);
                LASSERT(handle);
                rc = fsfilt_commit(obd, inode, handle, 1);

                dev_set_rdonly(obd->u.mds.mds_sb->s_dev, 2);
                RETURN(0);
#else
#warning "port dev_set_rdonly patch on 2.6"
#endif
        }

        case OBD_IOC_ABORT_RECOVERY:
                CERROR("aborting recovery for device %s\n", obd->obd_name);
                target_abort_recovery(obd);
                RETURN(0);

        default:
                RETURN(-EINVAL);
        }
        RETURN(0);
}
