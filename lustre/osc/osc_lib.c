/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/obd.h>
# include <linux/obd_ost.h>
# include <linux/lustre_net.h>
# include <linux/lustre_dlm.h>

/* convert a pathname into a kdev_t */
static kdev_t path2dev(char *path)
{
        struct dentry *dentry;
        struct nameidata nd;
        kdev_t dev;
        KDEVT_VAL(dev, 0);

        if (!path_init(path, LOOKUP_FOLLOW, &nd))
                return 0;

        if (path_walk(path, &nd))
                return 0;

        dentry = nd.dentry;
        if (dentry->d_inode && !is_bad_inode(dentry->d_inode) &&
            S_ISBLK(dentry->d_inode->i_mode))
                dev = dentry->d_inode->i_rdev;
        path_release(&nd);

        return dev;
}

int client_sanobd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct client_obd *cli = &obddev->u.cli;
        ENTRY;

        if (data->ioc_inllen3 < 1) {
                CERROR("setup requires a SAN device pathname\n");
                RETURN(-EINVAL);
        }

        client_obd_setup(obddev, len, buf);

        cli->cl_sandev = path2dev(data->ioc_inlbuf3);
        if (!kdev_t_to_nr(cli->cl_sandev)) {
                CERROR("%s seems not a valid SAN device\n", data->ioc_inlbuf3);
                RETURN(-EINVAL);
        }

        RETURN(0);
}
#endif
