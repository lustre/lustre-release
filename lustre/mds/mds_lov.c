/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_lov.c
 *
 *  Lustre Metadata Server (mds) handling of striped file data
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  by Peter Braam <braam@clusterfs.com> &
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/lustre_lib.h>

int mds_set_lovdesc(struct obd_device *obd, struct lov_desc *desc,
                    obd_uuid_t *uuidarray)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_run_ctxt saved;
        struct file *f;
        int tgt_count;
        int rc;
        int i;

        tgt_count = desc->ld_tgt_count;
        lov_packdesc(desc);

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        f = filp_open("LOVDESC", O_CREAT|O_RDWR, 0644);
        if (IS_ERR(f)) {
                CERROR("Cannot open/create LOVDESC file\n");
                GOTO(out, rc = PTR_ERR(f));
        }

        rc = lustre_fwrite(f, (char *)desc, sizeof(*desc), &f->f_pos);
        if (filp_close(f, 0))
                CERROR("Error closing LOVDESC file\n");
        if (rc != sizeof(*desc)) {
                CERROR("Cannot open/create LOVDESC file\n");
                GOTO(out, rc = PTR_ERR(f));
        }

        f = filp_open("LOVTGTS", O_CREAT|O_RDWR, 0644);
        if (IS_ERR(f)) {
                CERROR("Cannot open/create LOVTGTS file\n");
                GOTO(out, rc = PTR_ERR(f));
        }

        rc = 0;
        for (i = 0; i < tgt_count ; i++) {
                rc = lustre_fwrite(f, uuidarray[i],
                                   sizeof(uuidarray[i]), &f->f_pos);
                if (rc != sizeof(uuidarray[i])) {
                        CERROR("cannot write LOV UUID %s (%d)\n",
                               uuidarray[i], i);
                        if (rc >= 0)
                                rc = -EIO;
                        break;
                } else
                        rc = 0;
        }
        if (filp_close(f, 0))
                CERROR("Error closing LOVTGTS file\n");

out:
        pop_ctxt(&saved);
        RETURN(rc);
}

int mds_get_lovdesc(struct mds_obd *mds, struct lov_desc *desc)
{
        struct obd_run_ctxt saved;
        struct file *f;
        int rc;

        push_ctxt(&saved, &mds->mds_ctxt, NULL);
        f = filp_open("LOVDESC", O_RDONLY, 0644);
        if (!f || IS_ERR(f)) {
                CERROR("Cannot open LOVDESC file\n");
                pop_ctxt(&saved);
                RETURN(-EIO);
        }

        rc = lustre_fread(f, (char *)desc, sizeof(*desc), &f->f_pos);
        if (filp_close(f, 0))
                CERROR("Error closing LOVDESC file\n");

        if (rc != sizeof(*desc)) {
                CERROR("Cannot read LOVDESC file\n");
                pop_ctxt(&saved);
                RETURN(-EIO);
        }
        pop_ctxt(&saved);

        RETURN(0);
}

int mds_get_lovtgts(struct mds_obd *mds, int tgt_count,obd_uuid_t *uuidarray)
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
        pop_ctxt(&saved);

        RETURN(rc);
}

int mds_iocontrol(long cmd, struct lustre_handle *conn,
                          int len, void *karg, void *uarg)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct obd_ioctl_data *data = karg;
        struct lov_desc *desc;
        obd_uuid_t *uuidarray;
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
                uuidarray = (obd_uuid_t *)data->ioc_inlbuf2;
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
                uuidarray = (obd_uuid_t *)data->ioc_inlbuf2;
                if (sizeof(*uuidarray) * count != data->ioc_inllen2) {
                        CERROR("UUID array size wrong\n");
                        RETURN(-EINVAL);
                }
                rc = mds_get_lovdesc(&obd->u.mds, desc);
                if (desc->ld_tgt_count > count) {
                        CERROR("UUID array size too small\n");
                        RETURN(-ENOSPC);
                }
                rc = mds_get_lovtgts(&obd->u.mds, desc->ld_tgt_count, uuidarray);

                RETURN(rc);
        default:
                RETURN(-EINVAL);
        }

        RETURN(0);
}
