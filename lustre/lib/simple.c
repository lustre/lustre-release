/*
 *  lib/simple.c
 *
 * Copyright (C) 2002  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Peter Braam <braam@clusterfs.com>
 * and Andreas Dilger <adilger@clusterfs.com>
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/lustre_mds.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>

/* utility to make a directory */
int simple_mkdir(struct dentry *dir, char *name, int mode)
{
        struct dentry *dchild;
        int err;
        ENTRY;

        dchild = lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                RETURN(PTR_ERR(dchild));

        if (dchild->d_inode)
                GOTO(out, err = -EEXIST);

        err = vfs_mkdir(dir->d_inode, dchild, mode);
out:
        l_dput(dchild);

        RETURN(err);
}
