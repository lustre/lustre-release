/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
# include <linux/module.h>
# include <obd.h>
# include <obd_ost.h>
# include <lustre_net.h>
# include <lustre_dlm.h>
# include <lustre_lib.h>
# include <linux/lustre_compat25.h>

/* convert a pathname into a kdev_t */
static kdev_t path2dev(char *path)
{
        struct dentry *dentry;
        struct nameidata nd;
        kdev_t dev = KDEVT_INIT(0);

        if (ll_path_lookup(path, LOOKUP_FOLLOW, &nd))
                return val_to_kdev(0);

        dentry = nd.dentry;
        if (dentry->d_inode && !is_bad_inode(dentry->d_inode) &&
            S_ISBLK(dentry->d_inode->i_mode))
                dev = dentry->d_inode->i_rdev;
        path_release(&nd);

        return dev;
}

int client_sanobd_setup(struct obd_device *obddev, struct lustre_cfg* lcfg)
{
        struct client_obd *cli = &obddev->u.cli;
        ENTRY;

        if (lcfg->lcfg_bufcount < 4 || LUSTRE_CFG_BUFLEN(lcfg, 3) < 1) {
                CERROR("setup requires a SAN device pathname\n");
                RETURN(-EINVAL);
        }

        client_obd_setup(obddev, lcfg);

        cli->cl_sandev = path2dev(lustre_cfg_string(lcfg, 3));
        if (!kdev_t_to_nr(cli->cl_sandev)) {
                CERROR("%s seems not a valid SAN device\n",
                       lustre_cfg_string(lcfg, 3));
                RETURN(-EINVAL);
        }

        RETURN(0);
}
#endif
