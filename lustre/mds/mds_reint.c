/*
 *  linux/mds/handler.c
 *  
 *  Lustre Metadata Server (mds) request handler
 * 
 *  Copyright (C) 2001  Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  by Peter Braam <braam@clusterfs.com>
 * 
 *  This server is single threaded at present (but can easily be multi threaded). 
 * 
 */


#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/ext2_fs.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/obd_support.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>

extern struct mds_request *mds_prep_req(int size, int opcode, int namelen, char *name, int tgtlen, char *tgt);


int mds_reint_setattr(struct mds_request *req)
{
	struct vfsmount *mnt;
	struct dentry *de;
	struct mds_rep *rep;
	struct mds_rec_setattr *rec;
	struct iattr attr;
	int rc;

	if (req->rq_req->tgtlen != sizeof(struct mds_rec_setattr) ) { 
		EXIT;
		printk("mds: out of memory\n");
		req->rq_status = -EINVAL;
		return -EINVAL;
	}
	rec = mds_req_tgt(req->rq_req);

	mds_setattr_unpack(rec, &attr); 
	de = mds_fid2dentry(req->rq_obd, &rec->sa_fid, &mnt);

	printk("mds_setattr: ino %ld\n", de->d_inode->i_ino);
	
	rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep, 
			  &req->rq_replen, &req->rq_repbuf);
	if (rc) { 
		EXIT;
		printk("mds: out of memory\n");
		req->rq_status = -ENOMEM;
		return -ENOMEM;
	}

	req->rq_rephdr->seqno = req->rq_reqhdr->seqno;
	rep = req->rq_rep;
	req->rq_rephdr->status = notify_change(de, &attr);

	dput(de);
	EXIT;
	return 0;
}


