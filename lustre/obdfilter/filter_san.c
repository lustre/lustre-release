/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter_san.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/pagemap.h> // XXX kill me soon
#include <linux/version.h>

#include <linux/obd_class.h>
#include <linux/lustre_fsfilt.h>
#include "filter_internal.h"

/* sanobd setup methods - use a specific mount option */
int filter_san_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        char *option = NULL;

        if (!data->ioc_inlbuf2)
                RETURN(-EINVAL);

        /* for extN/ext3 filesystem, we must mount it with 'writeback' mode */
        if (!strcmp(data->ioc_inlbuf2, "extN"))
                option = "data=writeback";
        else if (!strcmp(data->ioc_inlbuf2, "ext3"))
                option = "data=writeback,asyncdel";
        else
                LBUG(); /* just a reminder */

        return filter_common_setup(obd, len, buf, option);
}

int filter_san_preprw(int cmd, struct lustre_handle *conn, int objcount,
                      struct obd_ioobj *obj, int niocount,
                      struct niobuf_remote *nb)
{
        struct obd_device *obd;
        struct obd_ioobj *o = obj;
        struct niobuf_remote *rnb = nb;
        int rc = 0;
        int i;
        ENTRY;

        obd = class_conn2obd(conn);
        if (!obd) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       conn->cookie);
                RETURN(-EINVAL);
        }

        for (i = 0; i < objcount; i++, o++) {
                struct dentry *dentry;
                struct inode *inode;
                int (*fs_bmap)(struct address_space *, long);
                int j;

                dentry = filter_fid2dentry(obd, NULL, o->ioo_type, o->ioo_id);
                if (IS_ERR(dentry))
                        GOTO(out, rc = PTR_ERR(dentry));
                inode = dentry->d_inode;
                if (!inode) {
                        CERROR("trying to BRW to non-existent file "LPU64"\n",
                               o->ioo_id);
                        f_dput(dentry);
                        GOTO(out, rc = -ENOENT);
                }
                fs_bmap = inode->i_mapping->a_ops->bmap;

                for (j = 0; j < o->ioo_bufcnt; j++, rnb++) {
                        long block;

                        block = rnb->offset >> inode->i_blkbits;

                        if (cmd == OBD_BRW_READ) {
                                block = fs_bmap(inode->i_mapping, block);
                        } else {
                                loff_t newsize = rnb->offset + rnb->len;
                                /* fs_prep_san_write will also update inode
                                 * size for us:
                                 * (1) new alloced block
                                 * (2) existed block but size extented
                                 */
                                /* FIXME We could call fs_prep_san_write()
                                 * only once for all the blocks allocation.
                                 * Now call it once for each block, for
                                 * simplicity. And if error happens, we
                                 * probably need to release previous alloced
                                 * block */
                                rc = fs_prep_san_write(obd, inode, &block,
                                                       1, newsize);
                                if (rc)
                                        break;
                        }

                        rnb->offset = block;
                }
                f_dput(dentry);
        }
out:
        RETURN(rc);
}

