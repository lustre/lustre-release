/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_ext3.c
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
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/ext3_jbd.h>
#include <linux/lustre_mds.h>

/*
 * We don't currently need any additional blocks for rmdir and
 * unlink transactions because we are storing the OST oa_id inside
 * the inode (which we will be changing anyways as part of this
 * transaction).  When we store the oa_id in an EA (which may be
 * in an external block) we need to increase nblocks by 1.
 */
static void *mds_ext3_start(struct inode *inode, int op)
{
        int nblocks = 0;

        switch(op) {
        case MDS_JOP_RMDIR:
        case MDS_JOP_UNLINK:     nblocks = EXT3_DELETE_TRANS_BLOCKS; break;
        }

        return journal_start(EXT3_JOURNAL(inode), nblocks);
}

static int mds_ext3_stop(void *handle, struct inode *inode)
{
        return journal_stop((handle_t *)handle);
}

struct mds_journal_operations mds_ext3_journal_ops = {
        tr_start:       mds_ext3_start,
        tr_commit:      mds_ext3_stop,
};
