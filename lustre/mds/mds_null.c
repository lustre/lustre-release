/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_null.c
 *
 *  Lustre Metadata Server (mds) journal abstraction routines
 *
 *  Copyright (C) 2002  Cluster File Systems, Inc.
 *  author: Andreas Dilger <adilger@clusterfs.com>
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/fs.h>
#include <linux/lustre_mds.h>

static void *mds_null_start(struct inode *inode, int nblocks)
{
        return 0;
}

static int mds_null_stop(void *handle, struct inode *inode)
{
        return 0;
}

struct mds_journal_operations mds_null_journal_ops = {
        tr_start:       mds_null_start,
        tr_commit:      mds_null_stop,
};
