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
	struct dentry *de;

	de = mds_fid2dentry(req->rq_obd, rec->ur_fid1, NULL);
	if (IS_ERR(de)) { 
		req->rq_rephdr->status = -ESTALE;
		return 0;
	}

	printk("mds_setattr: ino %ld\n", de->d_inode->i_ino);

	/* a _really_ horrible hack to avoid removing the data stored
	   in the block pointers; this data is the object id 
           this will go into an extended attribute at some point.
	*/
	if ( rec->ur_iattr.ia_valid & ATTR_SIZE ) { 
		/* ATTR_SIZE would invoke truncate: clear it */ 
		rec->ur_iattr.ia_valid &= ~ATTR_SIZE;
		de->d_inode->i_size = rec->ur_iattr.ia_size;
		/* make sure _something_ gets set - so new inode
		   goes to disk (probably won't work over XFS */
		if (!rec->ur_iattr.ia_valid & ATTR_MODE) { 
			rec->ur_iattr.ia_valid |= ATTR_MODE;
			rec->ur_iattr.ia_mode = de->d_inode->i_mode;
		}
	}
	if ( de->d_inode->i_op->setattr ) {
		req->rq_rephdr->status =
			de->d_inode->i_op->setattr(de, &rec->ur_iattr);
	} else { 
		req->rq_rephdr->status =
			inode_setattr(de->d_inode, &rec->ur_iattr);
	}

	l_dput(de);
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
	int type = rec->ur_mode & S_IFMT;
	struct dentry *de;
	struct mds_rep *rep = req->rq_rep.mds;
	struct dentry *dchild; 
	int rc;
	ENTRY;

	de = mds_fid2dentry(req->rq_obd, rec->ur_fid1, NULL);
	if (IS_ERR(de)) { 
		req->rq_rephdr->status = -ESTALE;
		EXIT;
		return 0;
	}
	printk("mds_reint_create: ino %ld\n", de->d_inode->i_ino);

	dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
	rc = PTR_ERR(dchild);
	if (IS_ERR(dchild)) { 
		printk(__FUNCTION__ "child lookup error %d\n", rc);
		dput(de); 
		req->rq_rephdr->status = -ESTALE;
		EXIT;
		return 0;
	}

	if (dchild->d_inode) {
		printk(__FUNCTION__ "child exists (dir %ld, name %s\n", 
		       de->d_inode->i_ino, rec->ur_name);
		dput(de); 
		req->rq_rephdr->status = -ESTALE;
		EXIT;
		return 0;
	}

	switch (type) {
	case S_IFREG: { 
		rc = vfs_create(de->d_inode, dchild, rec->ur_mode);
		
		EXIT;
		break;
	}
	case S_IFDIR: { 
		rc = vfs_mkdir(de->d_inode, dchild, rec->ur_mode);
		EXIT;
		break;
	} 
	case S_IFLNK: { 
		rc = vfs_symlink(de->d_inode, dchild, rec->ur_tgt);
		EXIT;
		break;
	} 
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK: { 
		int rdev = rec->ur_id;
		rc = vfs_mknod(de->d_inode, dchild, rec->ur_mode, rdev); 
		EXIT;
		break;
	}
	}

	req->rq_rephdr->status = rc;
	if (!rc) { 
		if (type == S_IFREG)
			mds_store_objid(dchild->d_inode, &rec->ur_id); 
		dchild->d_inode->i_atime = rec->ur_time;
		dchild->d_inode->i_ctime = rec->ur_time;
		dchild->d_inode->i_mtime = rec->ur_time;
		dchild->d_inode->i_uid = rec->ur_uid;
		dchild->d_inode->i_gid = rec->ur_gid;
		rep->ino = dchild->d_inode->i_ino;
	}

	dput(de);
	dput(dchild); 
	EXIT;
	return 0;
}

static int mds_reint_unlink(struct mds_update_record *rec, 
			    struct ptlrpc_request *req)
{
	struct dentry *de;
	struct dentry *dchild; 
	int rc;
	ENTRY;

	de = mds_fid2dentry(req->rq_obd, rec->ur_fid1, NULL);
	if (IS_ERR(de)) { 
		req->rq_rephdr->status = -ESTALE;
		EXIT;
		return 0;
	}
	printk("mds_reint_create: ino %ld\n", de->d_inode->i_ino);

	dchild = lookup_one_len(rec->ur_name, de, rec->ur_namelen - 1);
	rc = PTR_ERR(dchild);
	if (IS_ERR(dchild)) { 
		printk(__FUNCTION__ ": child lookup error %d\n", rc);
		dput(de); 
		req->rq_rephdr->status = -ESTALE;
		EXIT;
		return 0;
	}

	if (!dchild->d_inode) {
		printk(__FUNCTION__ ": child doesn't exist (dir %ld, name %s\n", 
		       de->d_inode->i_ino, rec->ur_name);
		dput(de); 
		req->rq_rephdr->status = -ESTALE;
		EXIT;
		return 0;
	}

	switch (dchild->d_inode->i_mode & S_IFMT) {
	case S_IFDIR:
		rc = vfs_rmdir(de->d_inode, dchild);
		EXIT;
		break;
	default:
		rc = vfs_unlink(de->d_inode, dchild);
		
		EXIT;
		break;
	}

	req->rq_rephdr->status = rc;
	dput(de);
	dput(dchild); 
	EXIT;
	return 0;
}

static int mds_reint_link(struct mds_update_record *rec, 
			    struct ptlrpc_request *req)
{
	struct dentry *de_src = NULL;
	struct dentry *de_tgt_dir = NULL;
	struct dentry *dchild = NULL; 
	int rc;
	ENTRY;

	rc = -ESTALE;
	de_src = mds_fid2dentry(req->rq_obd, rec->ur_fid1, NULL);
	if (IS_ERR(de_src)) { 
		EXIT;
		goto out_link;
	}

	de_tgt_dir = mds_fid2dentry(req->rq_obd, rec->ur_fid2, NULL);
	if (IS_ERR(de_tgt_dir)) { 
		rc = -ESTALE;
		EXIT;
		goto out_link;
	}

	dchild = lookup_one_len(rec->ur_name, de_tgt_dir, rec->ur_namelen - 1);
	if (IS_ERR(dchild)) { 
		printk(__FUNCTION__ ": child lookup error %d\n", rc);
		req->rq_rephdr->status = -ESTALE;
		goto out_link;
	}

	if (dchild->d_inode) {
		printk(__FUNCTION__ ": child exists (dir %ld, name %s\n", 
		       de_tgt_dir->d_inode->i_ino, rec->ur_name);
		EXIT;
		goto out_link;
	}

	rc = vfs_link(de_src, de_tgt_dir->d_inode, dchild); 

 out_link:
	req->rq_rephdr->status = rc;
	l_dput(de_src);
	l_dput(de_tgt_dir); 
	l_dput(dchild); 
	EXIT;
	return 0;
}


static int mds_reint_rename(struct mds_update_record *rec, 
			    struct ptlrpc_request *req)
{
	struct dentry *de_srcdir = NULL;
	struct dentry *de_tgtdir = NULL;
	struct dentry *de_old = NULL; 
	struct dentry *de_new = NULL; 
	int rc;
	ENTRY;

	rc = -ESTALE;
	de_srcdir = mds_fid2dentry(req->rq_obd, rec->ur_fid1, NULL);
	if (IS_ERR(de_srcdir)) { 
		EXIT;
		goto out_rename;
	}

	de_tgtdir = mds_fid2dentry(req->rq_obd, rec->ur_fid2, NULL);
	if (IS_ERR(de_tgtdir)) { 
		rc = -ESTALE;
		EXIT;
		goto out_rename;
	}

	de_old = lookup_one_len(rec->ur_name, de_srcdir, rec->ur_namelen - 1);
	if (IS_ERR(de_old)) { 
		printk(__FUNCTION__ "child lookup error %d\n", rc);
		goto out_rename;
	}

	de_new = lookup_one_len(rec->ur_tgt, de_tgtdir, rec->ur_tgtlen - 1);
	if (IS_ERR(de_new)) { 
		printk(__FUNCTION__ "child lookup error %d\n", rc);
		goto out_rename;
	}

	rc = vfs_rename(de_srcdir->d_inode, de_old, de_tgtdir->d_inode, de_new);

 out_rename:
	req->rq_rephdr->status = rc;
	l_dput(de_new);
	l_dput(de_old); 
	l_dput(de_tgtdir); 
	l_dput(de_srcdir); 
	EXIT;
	return 0;
}

typedef int (*mds_reinter)(struct mds_update_record *, struct ptlrpc_request*); 

static mds_reinter  reinters[REINT_MAX+1] = { 
	[REINT_SETATTR]   mds_reint_setattr, 
	[REINT_CREATE]    mds_reint_create,
	[REINT_UNLINK]    mds_reint_unlink, 
	[REINT_LINK]      mds_reint_link,
	[REINT_RENAME]    mds_reint_rename
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

