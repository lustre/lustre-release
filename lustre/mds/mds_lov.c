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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/lustre_lib.h>

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
        push_ctxt(&saved, &mds->mds_ctxt, NULL);

#warning FIXME: if there is an existing LOVDESC, verify new tgt_count > old
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

#warning FIXME: if there is an existing LOVTGTS, verify existing UUIDs same
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

out:
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);
        OBD_FREE (disk_desc, sizeof (*disk_desc));

        RETURN(rc);
}

int mds_get_lovdesc(struct mds_obd *mds, struct lov_desc *desc)
{
        struct obd_run_ctxt saved;
        struct file *f;
        int rc;
        ENTRY;

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
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
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);

        return rc;
}

int mds_get_lovtgts(struct mds_obd *mds, int tgt_count,struct obd_uuid *uuidarray)
{
        struct obd_run_ctxt saved;
        struct file *f;
        int rc;
        int rc2;

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
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
        pop_ctxt(&saved, &mds->mds_ctxt, NULL);

        RETURN(rc);
}

int mds_iocontrol(unsigned int cmd, struct lustre_handle *conn,
                  int len, void *karg, void *uarg)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct obd_ioctl_data *data = karg;
        struct lov_desc *desc;
        struct obd_uuid *uuidarray;
        int count;
        int rc;

        switch (cmd) {
        case OBD_IOC_LOV_SET_CONFIG:
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
                rc = mds_set_lovdesc(obd, desc, uuidarray);

                RETURN(rc);
        case OBD_IOC_LOV_GET_CONFIG:
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
                rc = mds_get_lovdesc(&obd->u.mds, desc);
                if (desc->ld_tgt_count > count) {
                        CERROR("UUID array size too small\n");
                        RETURN(-ENOSPC);
                }
                rc = mds_get_lovtgts(&obd->u.mds, desc->ld_tgt_count,
                                     uuidarray);

                RETURN(rc);

        case OBD_IOC_SET_READONLY:
                CERROR("setting device %s read-only\n",
                       ll_bdevname(obd->u.mds.mds_sb->s_dev));
#ifdef CONFIG_DEV_RDONLY
                dev_set_rdonly(obd->u.mds.mds_sb->s_dev, 2);
#endif
                RETURN(0);

        case OBD_IOC_ABORT_RECOVERY:
                CERROR("aborting recovery for device %s\n", obd->obd_name);
                target_abort_recovery(obd);
                RETURN(0);

        default:
                RETURN(-EINVAL);
        }
        RETURN(0);
}
