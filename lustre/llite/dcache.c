/*
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 *  Copyright (C) 2001, Cluster File Systems, Inc.
 * 
 */

#include <linux/fs.h>
#include <linux/locks.h>
#include <linux/quotaops.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/obd_support.h>
#include <linux/lustre_lite.h>

extern struct address_space_operations ll_aops;

int ll_revalidate2(struct dentry *de, int flags, struct lookup_intent *it)
{
        ENTRY;
        

        RETURN(1);
}


struct dentry_operations ll_d_ops = { 
        d_revalidate2: ll_revalidate2
};
