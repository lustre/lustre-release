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
#include <linux/obd_lov.h>

int mds_configure_lov(struct obd_device *obd, struct lov_desc *desc, 
                      uuid_t *uuidarray)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_run_ctxt saved;
        struct file *f;
        loff_t off = 0;
        int count;
        int rc;
        int i;

        count = desc->ld_tgt_count;
        lov_packdesc(desc); 

        push_ctxt(&saved, &mds->mds_ctxt);
        f = filp_open("LOVDESC", O_CREAT|O_RDWR, 0644);
        if (!f || IS_ERR(f)) { 
                pop_ctxt(&saved); 
                CERROR("Cannot open/create LOVDESC file\n");
                RETURN(-EIO);
        }
        
        rc = lustre_fwrite(f, (char *)desc, sizeof(*desc), &off); 
        filp_close(f, 0);
        if (rc != sizeof(*desc)) { 
                pop_ctxt(&saved); 
                CERROR("Cannot open/create LOVDESC file\n");
                RETURN(-EIO);
        }

        off = 0;
        f = filp_open("LOVTGTS", O_CREAT|O_RDWR, 0644);
        if (!f || IS_ERR(f)) { 
                pop_ctxt(&saved); 
                CERROR("Cannot open/create LOVDESC file\n");
                RETURN(-EIO);
        }

        for (i=0 ; i < count ; i++) { 
                rc = lustre_fwrite(f, uuidarray[i], 
                                   sizeof(uuidarray[i]), &off); 
                if (rc != sizeof(uuidarray[i])) { 
                        CERROR("cannot write LOV UUID %s (%d)\n",
                               uuidarray[i], i);
                        break;
                }
                rc = 0; 
        }
        filp_close(f, 0);
        pop_ctxt(&saved); 

        RETURN(rc); 
}

int mds_get_lovdesc(struct obd_device *obd, struct lov_desc *desc)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_run_ctxt saved;
        struct file *f;
        loff_t off = 0;
        int rc, rc2;

        push_ctxt(&saved, &mds->mds_ctxt);
        f = filp_open("LOVDESC", O_RDONLY, 0644);
        if (!f || IS_ERR(f)) { 
                CERROR("Cannot open LOVDESC file\n");
                pop_ctxt(&saved); 
                RETURN(-EIO);
        }
        
        rc = lustre_fread(f, (char *)desc, sizeof(*desc), &off); 
        rc2 = filp_close(f, 0);
        if (rc2) { 
                CERROR("Error closing LOVDESC file %d\n", rc); 
        }
        if (rc != sizeof(*desc)) { 
                CERROR("Cannot read LOVDESC file\n");
                pop_ctxt(&saved); 
                RETURN(-EIO);
        }
        pop_ctxt(&saved); 

        RETURN(0); 
}

int mds_get_lovtgts(struct obd_device *obd, uuid_t *uuidarray)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_run_ctxt saved;
        struct lov_desc desc; 
        struct file *f;
        loff_t off = 0;
        int rc;
        int rc2;
        int count;

        rc = mds_get_lovdesc(obd, &desc); 
        if (rc) { 
                CERROR("cannot get descriptor\n"); 
                RETURN(-EIO); 
        }

        push_ctxt(&saved, &mds->mds_ctxt);
        f = filp_open("LOVTGTS", O_RDONLY, 0644);
        if (!f || IS_ERR(f)) { 
                CERROR("Cannot open LOVTGTS file\n");
                pop_ctxt(&saved); 
                RETURN(-EIO);
        }

        lov_unpackdesc(&desc); 
        count = desc.ld_tgt_count;

        off = 0;
        rc = lustre_fread(f, (char *)uuidarray, count * sizeof(uuid_t), 
                          &off); 
        rc2 = filp_close(f, 0);
        if (rc2) { 
                CERROR("Error closing LOVTGTS file %d\n", rc); 
        }
        if (rc != count * sizeof(uuid_t)) { 
                CERROR("Error reading LOVTGTS file\n");
                pop_ctxt(&saved); 
                RETURN(-EIO);
        }
        pop_ctxt(&saved); 

        RETURN(0); 
}

int mds_iocontrol(long cmd, struct lustre_handle *conn, 
                          int len, void *karg, void *uarg)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct obd_ioctl_data *data = karg;
        struct lov_desc *desc; 
        int count; 
        int rc; 


        switch (cmd) { 
        case OBD_IOC_LOV_CONFIG:
                desc = (struct lov_desc *)data->ioc_inlbuf1;
                if (sizeof(*desc) > data->ioc_inllen1) { 
                        CERROR("descriptor size wrong\n");
                        RETURN(-EINVAL); 
                }

                count = desc->ld_tgt_count;
                if (sizeof(uuid_t) * count != data->ioc_inllen2) { 
                        CERROR("UUID array size wrong\n");
                        RETURN(-EINVAL); 
                }
                rc = mds_configure_lov(obd, desc, (uuid_t *)data->ioc_inlbuf2);

                RETURN(rc); 
        default:
                RETURN(-EINVAL); 
        }

        RETURN(0);
}
