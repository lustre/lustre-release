/*
 *  linux/mds/mds_reint.c
 *  
 *  Lustre Metadata Server (mds) reintegration routines
 * 
 *  Copyright (C) 2002  Cluster File Systems, Inc.
 *  author: Peter Braam <braam@clusterfs.com>
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 */

// XXX - add transaction sequence numbers

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

extern struct ptlrpc_request *mds_prep_req(int size, int opcode, int namelen, char *name, int tgtlen, char *tgt);

static int mds_reint_setattr(struct mds_update_record *rec, struct ptlrpc_request *req)
{
	struct vfsmount *mnt;
	struct dentry *de;

	de = mds_fid2dentry(req->rq_obd, rec->ur_fid1, &mnt);
	if (IS_ERR(de)) { 
		req->rq_rephdr->status = -ESTALE;
		return 0;
	}

	printk("mds_setattr: ino %ld\n", de->d_inode->i_ino);
	req->rq_rephdr->status = notify_change(de, &rec->ur_iattr);

	dput(de);
	EXIT;
	return 0;
}

/* 
   XXX nasty hack: store the object id in the first two
   direct block spots 
*/
static inline void mds_store_objid(struct inode *inode, __u64 *id)
{
	memcpy(&inode->u.ext2_i.i_data, id, sizeof(*id));
}


static int mds_reint_create(struct mds_update_record *rec, 
			    struct ptlrpc_request *req)
{
	struct vfsmount *mnt;
	int type = rec->ur_mode & S_IFMT;
	struct dentry *de;
	struct mds_rep *rep = req->rq_rep.mds;
	struct dentry *dchild; 
	int rc;

	de = mds_fid2dentry(req->rq_obd, rec->ur_fid1, &mnt);
	if (IS_ERR(de)) { 
		req->rq_rephdr->status = -ESTALE;
		return 0;
	}
	printk("mds_reint_create: ino %ld\n", de->d_inode->i_ino);

	dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen);
	rc = PTR_ERR(dchild);
	if (IS_ERR(dchild)) { 
		printk(__FUNCTION__ "child lookup error %d\n", rc);
		dput(de); 
		req->rq_rephdr->status = -ESTALE;
		return 0;
	}

	if (dchild->d_inode) {
		printk(__FUNCTION__ "child exists (dir %ld, name %s\n", 
		       de->d_inode->i_ino, rec->ur_name);
		dput(de); 
		req->rq_rephdr->status = -ESTALE;
		return 0;
	}

	switch (type) {
	case S_IFREG: { 
		rc = vfs_create(de->d_inode, dchild, rec->ur_mode);
		
		if (!rc) { 
			mds_store_objid(dchild->d_inode, &rec->ur_id); 
			dchild->d_inode->i_atime = rec->ur_time;
			dchild->d_inode->i_ctime = rec->ur_time;
			dchild->d_inode->i_mtime = rec->ur_time;
			dchild->d_inode->i_uid = rec->ur_uid;
			dchild->d_inode->i_gid = rec->ur_gid;
			rep->ino = dchild->d_inode->i_ino;
		}
		break;
	}
	case S_IFDIR: { 
		rc = vfs_mkdir(de->d_inode, dchild, rec->ur_mode);
		break;
	} 
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK: { 
		int rdev = rec->ur_id;
		rc = vfs_mknod(de->d_inode, dchild, rec->ur_mode, rdev); 
		break;
	}
	}
	req->rq_rephdr->status = rc;

	dput(de);
	dput(dchild); 
	EXIT;
	return 0;
}

typedef int (*mds_reinter)(struct mds_update_record *, struct ptlrpc_request*); 

static mds_reinter  reinters[REINT_MAX+1] = { 
	[REINT_SETATTR]   mds_reint_setattr, 
	[REINT_CREATE]   mds_reint_create
};

int mds_reint_rec(struct mds_update_record *rec, struct ptlrpc_request *req)
{
	int rc; 

	if (rec->ur_opcode < 0 || rec->ur_opcode > REINT_MAX) { 
		printk(__FUNCTION__ "opcode %d not valid\n", 
		       rec->ur_opcode); 
		rc = req->rq_status = -EINVAL;
		return rc;
	}

	rc = mds_pack_rep(NULL, 0, NULL, 0, &req->rq_rephdr, &req->rq_rep.mds, 
			  &req->rq_replen, &req->rq_repbuf);
	if (rc) { 
		EXIT;
		printk("mds: out of memory\n");
		rc = req->rq_status = -ENOMEM;
		return rc;
	}
	req->rq_rephdr->seqno = req->rq_reqhdr->seqno;

	rc = reinters[rec->ur_opcode](rec, req); 
	req->rq_status = rc;

	return rc;
} 

