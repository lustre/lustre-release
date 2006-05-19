/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter_san.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/config.h>
#include <linux/module.h>
#include <linux/pagemap.h> // XXX kill me soon
#include <linux/version.h>

#include <obd_class.h>
#include <lustre_fsfilt.h>
#include "filter_internal.h"

/* sanobd setup methods - use a specific mount option */
int filter_san_setup(struct obd_device *obd, struct lustre_cfg* lcfg)
{
        unsigned long page;
        int rc;

        if (lcfg->lcfg_bufcount < 3 || LUSTRE_CFG_BUFLEN(lcfg, 2) < 1)
                RETURN(-EINVAL);

        /* 2.6.9 selinux wants a full option page for do_kern_mount (bug6471) */
        page = get_zeroed_page(GFP_KERNEL);
        if (!page)
                RETURN(-ENOMEM);

        /* for ext3/ldiskfs filesystem, we must mount in 'writeback' mode */
        if (!strcmp(lustre_cfg_string(lcfg, 2), "ldiskfs"))
                strcpy((void *)page, "data=writeback");
        else if (!strcmp(lustre_cfg_string(lcfg, 2), "ext3"))
                strcpy((void *)page, "data=writeback,asyncdel");
        else
                LBUG(); /* just a reminder */

        rc = filter_common_setup(obd, lcfg, (void *)page);
        free_page(page);

        return rc;
}

int filter_san_preprw(int cmd, struct obd_export *exp, struct obdo *oa,
                      int objcount, struct obd_ioobj *obj, int niocount,
                      struct niobuf_remote *nb)
{
        struct obd_ioobj *o = obj;
        struct niobuf_remote *rnb = nb;
        int rc = 0;
        int i;
        ENTRY;
        LASSERT(objcount == 1);

        for (i = 0; i < objcount; i++, o++) {
                struct dentry *dentry;
                struct inode *inode;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
                sector_t (*fs_bmap)(struct address_space *, sector_t);
#else
                int (*fs_bmap)(struct address_space *, long);
#endif
                int j;

                dentry = filter_oa2dentry(exp->exp_obd, oa);
                if (IS_ERR(dentry))
                        GOTO(out, rc = PTR_ERR(dentry));

                inode = dentry->d_inode;
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
                                rc = fs_prep_san_write(exp->exp_obd, inode,
                                                       &block, 1, newsize);
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

