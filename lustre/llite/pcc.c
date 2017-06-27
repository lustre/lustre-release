/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, DDN Storage Corporation.
 */
/*
 * Persistent Client Cache
 *
 * PCC is a new framework which provides a group of local cache on Lustre
 * client side. It works in two modes: RW-PCC enables a read-write cache on the
 * local SSDs of a single client; RO-PCC provides a read-only cache on the
 * local SSDs of multiple clients. Less overhead is visible to the applications
 * and network latencies and lock conflicts can be significantly reduced.
 *
 * For RW-PCC, no global namespace will be provided. Each client uses its own
 * local storage as a cache for itself. Local file system is used to manage
 * the data on local caches. Cached I/O is directed to local file system while
 * normal I/O is directed to OSTs. RW-PCC uses HSM for data synchronization.
 * It uses HSM copytool to restore file from local caches to Lustre OSTs. Each
 * PCC has a copytool instance running with unique archive number. Any remote
 * access from another Lustre client would trigger the data synchronization. If
 * a client with RW-PCC goes offline, the cached data becomes inaccessible for
 * other client temporarily. And after the RW-PCC client reboots and the
 * copytool restarts, the data will be accessible again.
 *
 * Following is what will happen in different conditions for RW-PCC:
 *
 * > When file is being created on RW-PCC
 *
 * A normal HSM released file is created on MDT;
 * An empty mirror file is created on local cache;
 * The HSM status of the Lustre file will be set to archived and released;
 * The archive number will be set to the proper value.
 *
 * > When file is being prefetched to RW-PCC
 *
 * An file is copied to the local cache;
 * The HSM status of the Lustre file will be set to archived and released;
 * The archive number will be set to the proper value.
 *
 * > When file is being accessed from PCC
 *
 * Data will be read directly from local cache;
 * Metadata will be read from MDT, except file size;
 * File size will be got from local cache.
 *
 * > When PCC cached file is being accessed on another client
 *
 * RW-PCC cached files are automatically restored when a process on another
 * client tries to read or modify them. The corresponding I/O will block
 * waiting for the released file to be restored. This is transparent to the
 * process.
 *
 * For RW-PCC, when a file is being created, a rule-based policy is used to
 * determine whether it will be cached. Rule-based caching of newly created
 * files can determine which file can use a cache on PCC directly without any
 * admission control.
 *
 * RW-PCC design can accelerate I/O intensive applications with one-to-one
 * mappings between files and accessing clients. However, in several use cases,
 * files will never be updated, but need to be read simultaneously from many
 * clients. RO-PCC implements a read-only caching on Lustre clients using
 * SSDs. RO-PCC is based on the same framework as RW-PCC, expect
 * that no HSM mechanism is used.
 *
 * The main advantages to use this SSD cache on the Lustre clients via PCC
 * is that:
 * - The I/O stack becomes much simpler for the cached data, as there is no
 *   interference with I/Os from other clients, which enables easier
 *   performance optimizations;
 * - The requirements on the HW inside the client nodes are small, any kind of
 *   SSDs or even HDDs can be used as cache devices;
 * - Caching reduces the pressure on the object storage targets (OSTs), as
 *   small or random I/Os can be regularized to big sequential I/Os and
 *   temporary files do not even need to be flushed to OSTs.
 *
 * PCC can accelerate applications with certain I/O patterns:
 * - small-sized random writes (< 1MB) from a single client
 * - repeated read of data that is larger than RAM
 * - clients with high network latency
 *
 * Author: Li Xi <lixi@ddn.com>
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include "pcc.h"
#include <linux/namei.h>
#include <linux/file.h>
#include <lustre_compat.h>
#include "llite_internal.h"

struct kmem_cache *pcc_inode_slab;

void pcc_super_init(struct pcc_super *super)
{
	spin_lock_init(&super->pccs_lock);
	INIT_LIST_HEAD(&super->pccs_datasets);
}

/**
 * pcc_dataset_add - Add a Cache policy to control which files need be
 * cached and where it will be cached.
 *
 * @super: superblock of pcc
 * @pathname: root path of pcc
 * @id: HSM archive ID
 * @projid: files with specified project ID will be cached.
 */
static int
pcc_dataset_add(struct pcc_super *super, const char *pathname,
		__u32 archive_id, __u32 projid)
{
	int rc;
	struct pcc_dataset *dataset;
	struct pcc_dataset *tmp;
	bool found = false;

	OBD_ALLOC_PTR(dataset);
	if (dataset == NULL)
		return -ENOMEM;

	rc = kern_path(pathname, LOOKUP_DIRECTORY, &dataset->pccd_path);
	if (unlikely(rc)) {
		OBD_FREE_PTR(dataset);
		return rc;
	}
	strncpy(dataset->pccd_pathname, pathname, PATH_MAX);
	dataset->pccd_id = archive_id;
	dataset->pccd_projid = projid;
	atomic_set(&dataset->pccd_refcount, 1);

	spin_lock(&super->pccs_lock);
	list_for_each_entry(tmp, &super->pccs_datasets, pccd_linkage) {
		if (tmp->pccd_id == archive_id) {
			found = true;
			break;
		}
	}
	if (!found)
		list_add(&dataset->pccd_linkage, &super->pccs_datasets);
	spin_unlock(&super->pccs_lock);

	if (found) {
		pcc_dataset_put(dataset);
		rc = -EEXIST;
	}

	return rc;
}

struct pcc_dataset *
pcc_dataset_get(struct pcc_super *super, __u32 projid, __u32 archive_id)
{
	struct pcc_dataset *dataset;
	struct pcc_dataset *selected = NULL;

	if (projid == 0 && archive_id == 0)
		return NULL;

	/*
	 * archive ID is unique in the list, projid might be duplicate,
	 * we just return last added one as first priority.
	 */
	spin_lock(&super->pccs_lock);
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		if (projid && dataset->pccd_projid != projid)
			continue;
		if (archive_id && dataset->pccd_id != archive_id)
			continue;
		atomic_inc(&dataset->pccd_refcount);
		selected = dataset;
		break;
	}
	spin_unlock(&super->pccs_lock);
	if (selected)
		CDEBUG(D_CACHE, "matched projid %u, PCC create\n",
		       selected->pccd_projid);
	return selected;
}

void
pcc_dataset_put(struct pcc_dataset *dataset)
{
	if (atomic_dec_and_test(&dataset->pccd_refcount)) {
		path_put(&dataset->pccd_path);
		OBD_FREE_PTR(dataset);
	}
}

static int
pcc_dataset_del(struct pcc_super *super, char *pathname)
{
	struct list_head *l, *tmp;
	struct pcc_dataset *dataset;
	int rc = -ENOENT;

	spin_lock(&super->pccs_lock);
	list_for_each_safe(l, tmp, &super->pccs_datasets) {
		dataset = list_entry(l, struct pcc_dataset, pccd_linkage);
		if (strcmp(dataset->pccd_pathname, pathname) == 0) {
			list_del(&dataset->pccd_linkage);
			pcc_dataset_put(dataset);
			rc = 0;
			break;
		}
	}
	spin_unlock(&super->pccs_lock);
	return rc;
}

static void
pcc_dataset_dump(struct pcc_dataset *dataset, struct seq_file *m)
{
	seq_printf(m, "%s:\n", dataset->pccd_pathname);
	seq_printf(m, "  rwid: %u\n", dataset->pccd_id);
	seq_printf(m, "  autocache: projid=%u\n", dataset->pccd_projid);
}

int
pcc_super_dump(struct pcc_super *super, struct seq_file *m)
{
	struct pcc_dataset *dataset;

	spin_lock(&super->pccs_lock);
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		pcc_dataset_dump(dataset, m);
	}
	spin_unlock(&super->pccs_lock);
	return 0;
}

void pcc_super_fini(struct pcc_super *super)
{
	struct pcc_dataset *dataset, *tmp;

	list_for_each_entry_safe(dataset, tmp,
				 &super->pccs_datasets, pccd_linkage) {
		list_del(&dataset->pccd_linkage);
		pcc_dataset_put(dataset);
	}
}


static bool pathname_is_valid(const char *pathname)
{
	/* Needs to be absolute path */
	if (pathname == NULL || strlen(pathname) == 0 ||
	    strlen(pathname) >= PATH_MAX || pathname[0] != '/')
		return false;
	return true;
}

static struct pcc_cmd *
pcc_cmd_parse(char *buffer, unsigned long count)
{
	static struct pcc_cmd *cmd;
	char *token;
	char *val;
	unsigned long tmp;
	int rc = 0;

	OBD_ALLOC_PTR(cmd);
	if (cmd == NULL)
		GOTO(out, rc = -ENOMEM);

	/* clear all setting */
	if (strncmp(buffer, "clear", 5) == 0) {
		cmd->pccc_cmd = PCC_CLEAR_ALL;
		GOTO(out, rc = 0);
	}

	val = buffer;
	token = strsep(&val, " ");
	if (val == NULL || strlen(val) == 0)
		GOTO(out_free_cmd, rc = -EINVAL);

	/* Type of the command */
	if (strcmp(token, "add") == 0)
		cmd->pccc_cmd = PCC_ADD_DATASET;
	else if (strcmp(token, "del") == 0)
		cmd->pccc_cmd = PCC_DEL_DATASET;
	else
		GOTO(out_free_cmd, rc = -EINVAL);

	/* Pathname of the dataset */
	token = strsep(&val, " ");
	if ((val == NULL && cmd->pccc_cmd != PCC_DEL_DATASET) ||
	    !pathname_is_valid(token))
		GOTO(out_free_cmd, rc = -EINVAL);
	cmd->pccc_pathname = token;

	if (cmd->pccc_cmd == PCC_ADD_DATASET) {
		/* archive ID */
		token = strsep(&val, " ");
		if (val == NULL)
			GOTO(out_free_cmd, rc = -EINVAL);

		rc = kstrtoul(token, 10, &tmp);
		if (rc != 0)
			GOTO(out_free_cmd, rc = -EINVAL);
		if (tmp == 0)
			GOTO(out_free_cmd, rc = -EINVAL);
		cmd->u.pccc_add.pccc_id = tmp;

		token = val;
		rc = kstrtoul(token, 10, &tmp);
		if (rc != 0)
			GOTO(out_free_cmd, rc = -EINVAL);
		if (tmp == 0)
			GOTO(out_free_cmd, rc = -EINVAL);
		cmd->u.pccc_add.pccc_projid = tmp;
	}

	goto out;
out_free_cmd:
	OBD_FREE_PTR(cmd);
out:
	if (rc)
		cmd = ERR_PTR(rc);
	return cmd;
}

int pcc_cmd_handle(char *buffer, unsigned long count,
		   struct pcc_super *super)
{
	int rc = 0;
	struct pcc_cmd *cmd;

	cmd = pcc_cmd_parse(buffer, count);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	switch (cmd->pccc_cmd) {
	case PCC_ADD_DATASET:
		rc = pcc_dataset_add(super, cmd->pccc_pathname,
				      cmd->u.pccc_add.pccc_id,
				      cmd->u.pccc_add.pccc_projid);
		break;
	case PCC_DEL_DATASET:
		rc = pcc_dataset_del(super, cmd->pccc_pathname);
		break;
	case PCC_CLEAR_ALL:
		pcc_super_fini(super);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	OBD_FREE_PTR(cmd);
	return rc;
}

static inline void pcc_inode_lock(struct inode *inode)
{
	mutex_lock(&ll_i2info(inode)->lli_pcc_lock);
}

static inline void pcc_inode_unlock(struct inode *inode)
{
	mutex_unlock(&ll_i2info(inode)->lli_pcc_lock);
}

static void pcc_inode_init(struct pcc_inode *pcci)
{
	atomic_set(&pcci->pcci_refcount, 0);
	pcci->pcci_type = LU_PCC_NONE;
}

static void pcc_inode_fini(struct pcc_inode *pcci)
{
	path_put(&pcci->pcci_path);
	pcci->pcci_type = LU_PCC_NONE;
	OBD_SLAB_FREE_PTR(pcci, pcc_inode_slab);
}

static void pcc_inode_get(struct pcc_inode *pcci)
{
	atomic_inc(&pcci->pcci_refcount);
}

static void pcc_inode_put(struct pcc_inode *pcci)
{
	if (atomic_dec_and_test(&pcci->pcci_refcount))
		pcc_inode_fini(pcci);
}

void pcc_inode_free(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci = lli->lli_pcc_inode;

	if (pcci) {
		WARN_ON(atomic_read(&pcci->pcci_refcount) > 1);
		pcc_inode_put(pcci);
		lli->lli_pcc_inode = NULL;
	}
}

/*
 * TODO:
 * As Andreas suggested, we'd better use new layout to
 * reduce overhead:
 * (fid->f_oid >> 16 & oxFFFF)/FID
 */
#define MAX_PCC_DATABASE_PATH (6 * 5 + FID_NOBRACE_LEN + 1)
static int pcc_fid2dataset_path(char *buf, int sz, struct lu_fid *fid)
{
	return snprintf(buf, sz, "%04x/%04x/%04x/%04x/%04x/%04x/"
			DFID_NOBRACE,
			(fid)->f_oid       & 0xFFFF,
			(fid)->f_oid >> 16 & 0xFFFF,
			(unsigned int)((fid)->f_seq       & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 16 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 32 & 0xFFFF),
			(unsigned int)((fid)->f_seq >> 48 & 0xFFFF),
			PFID(fid));
}

void pcc_file_init(struct pcc_file *pccf)
{
	pccf->pccf_file = NULL;
	pccf->pccf_type = LU_PCC_NONE;
}

int pcc_file_open(struct inode *inode, struct file *file)
{
	struct pcc_inode *pcci;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct file *pcc_file;
	struct path *path;
	struct qstr *dname;
	int rc = 0;

	ENTRY;

	if (!S_ISREG(inode->i_mode))
		RETURN(0);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (!pcci)
		GOTO(out_unlock, rc = 0);

	if (atomic_read(&pcci->pcci_refcount) == 0)
		GOTO(out_unlock, rc = 0);

	pcc_inode_get(pcci);
	WARN_ON(pccf->pccf_file);

	path = &pcci->pcci_path;
	dname = &path->dentry->d_name;
	CDEBUG(D_CACHE, "opening pcc file '%.*s'\n", dname->len,
	       dname->name);
#ifdef HAVE_DENTRY_OPEN_USE_PATH
	pcc_file = dentry_open(path, file->f_flags, current_cred());
#else
	pcc_file = dentry_open(path->dentry, path->mnt,
			       file->f_flags, current_cred());
#endif
	if (IS_ERR_OR_NULL(pcc_file)) {
		rc = pcc_file == NULL ? -EINVAL : PTR_ERR(pcc_file);
		pcc_inode_put(pcci);
	} else {
		pccf->pccf_file = pcc_file;
		pccf->pccf_type = pcci->pcci_type;
	}

out_unlock:
	pcc_inode_unlock(inode);
	RETURN(rc);
}

void pcc_file_release(struct inode *inode, struct file *file)
{
	struct pcc_inode *pcci;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf;
	struct path *path;
	struct qstr *dname;

	ENTRY;

	if (!S_ISREG(inode->i_mode) || fd == NULL)
		RETURN_EXIT;

	pccf = &fd->fd_pcc_file;
	pcc_inode_lock(inode);
	if (pccf->pccf_file == NULL)
		goto out;

	pcci = ll_i2pcci(inode);
	LASSERT(pcci);
	path = &pcci->pcci_path;
	dname = &path->dentry->d_name;
	CDEBUG(D_CACHE, "releasing pcc file \"%.*s\"\n", dname->len,
	       dname->name);
	pcc_inode_put(pcci);
	fput(pccf->pccf_file);
	pccf->pccf_file = NULL;
out:
	pcc_inode_unlock(inode);
}

ssize_t pcc_file_read_iter(struct kiocb *iocb,
			   struct iov_iter *iter, bool *cached)
{
	struct file *file = iocb->ki_filp;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	ssize_t result;

	ENTRY;

	if (pccf->pccf_file == NULL) {
		*cached = false;
		RETURN(0);
	}
	*cached = true;
	iocb->ki_filp = pccf->pccf_file;

	result = generic_file_read_iter(iocb, iter);
	iocb->ki_filp = file;

	RETURN(result);
}

static ssize_t
__pcc_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;

#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
	return file->f_op->write_iter(iocb, iter);
#else
	struct iovec iov;
	struct iov_iter i;
	ssize_t bytes = 0;

	iov_for_each(iov, i, *iter) {
		ssize_t res;

		res = file->f_op->aio_write(iocb, &iov, 1, iocb->ki_pos);
		if (-EIOCBQUEUED == res)
			res = wait_on_sync_kiocb(iocb);
		if (res <= 0) {
			if (bytes == 0)
				bytes = res;
			break;
		}

		bytes += res;
		if (res < iov.iov_len)
			break;
	}

	if (bytes > 0)
		iov_iter_advance(iter, bytes);
	return bytes;
#endif
}

ssize_t pcc_file_write_iter(struct kiocb *iocb,
			    struct iov_iter *iter, bool *cached)
{
	struct file *file = iocb->ki_filp;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	ssize_t result;

	ENTRY;

	if (pccf->pccf_file == NULL) {
		*cached = false;
		RETURN(0);
	}
	*cached = true;

	if (pccf->pccf_type != LU_PCC_READWRITE)
		RETURN(-EWOULDBLOCK);

	iocb->ki_filp = pccf->pccf_file;

	/* Since __pcc_file_write_iter makes write calls via
	 * the normal vfs interface to the local PCC file system,
	 * the inode lock is not needed.
	 */
	result = __pcc_file_write_iter(iocb, iter);
	iocb->ki_filp = file;
	RETURN(result);
}

int pcc_inode_setattr(struct inode *inode, struct iattr *attr,
		      bool *cached)
{
	int rc;
	struct pcc_inode *pcci;
	struct iattr attr2 = *attr;
	struct dentry *pcc_dentry;

	ENTRY;

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		RETURN(0);
	}

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci == NULL || atomic_read(&pcci->pcci_refcount) == 0)
		GOTO(out_unlock, rc = 0);

	*cached = true;
	attr2.ia_valid = attr->ia_valid & (ATTR_SIZE | ATTR_ATIME |
			 ATTR_ATIME_SET | ATTR_MTIME | ATTR_MTIME_SET |
			 ATTR_CTIME);
	pcc_dentry = pcci->pcci_path.dentry;
	inode_lock(pcc_dentry->d_inode);
	rc = pcc_dentry->d_inode->i_op->setattr(pcc_dentry, &attr2);
	inode_unlock(pcc_dentry->d_inode);
out_unlock:
	pcc_inode_unlock(inode);
	RETURN(rc);
}

int pcc_inode_getattr(struct inode *inode, bool *cached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	struct kstat stat;
	s64 atime;
	s64 mtime;
	s64 ctime;
	int rc;

	ENTRY;

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		RETURN(0);
	}

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci == NULL || atomic_read(&pcci->pcci_refcount) == 0)
		GOTO(out_unlock, rc = 0);

	*cached = true;
	rc = ll_vfs_getattr(&pcci->pcci_path, &stat);
	if (rc)
		GOTO(out_unlock, rc);

	ll_inode_size_lock(inode);
	if (inode->i_atime.tv_sec < lli->lli_atime ||
	    lli->lli_update_atime) {
		inode->i_atime.tv_sec = lli->lli_atime;
		lli->lli_update_atime = 0;
	}
	inode->i_mtime.tv_sec = lli->lli_mtime;
	inode->i_ctime.tv_sec = lli->lli_ctime;

	atime = inode->i_atime.tv_sec;
	mtime = inode->i_mtime.tv_sec;
	ctime = inode->i_ctime.tv_sec;

	if (atime < stat.atime.tv_sec)
		atime = stat.atime.tv_sec;

	if (ctime < stat.ctime.tv_sec)
		ctime = stat.ctime.tv_sec;

	if (mtime < stat.mtime.tv_sec)
		mtime = stat.mtime.tv_sec;

	i_size_write(inode, stat.size);
	inode->i_blocks = stat.blocks;

	inode->i_atime.tv_sec = atime;
	inode->i_mtime.tv_sec = mtime;
	inode->i_ctime.tv_sec = ctime;

	ll_inode_size_unlock(inode);

out_unlock:
	pcc_inode_unlock(inode);
	RETURN(rc);
}

/* Create directory under base if directory does not exist */
static struct dentry *
pcc_mkdir(struct dentry *base, const char *name, umode_t mode)
{
	int rc;
	struct dentry *dentry;
	struct inode *dir = base->d_inode;

	inode_lock(dir);
	dentry = lookup_one_len(name, base, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_is_positive(dentry))
		goto out;

	rc = vfs_mkdir(dir, dentry, mode);
	if (rc) {
		dput(dentry);
		dentry = ERR_PTR(rc);
		goto out;
	}
out:
	inode_unlock(dir);
	return dentry;
}

static struct dentry *
pcc_mkdir_p(struct dentry *root, char *path, umode_t mode)
{
	char *ptr, *entry_name;
	struct dentry *parent;
	struct dentry *child = ERR_PTR(-EINVAL);

	ptr = path;
	while (*ptr == '/')
		ptr++;

	entry_name = ptr;
	parent = dget(root);
	while ((ptr = strchr(ptr, '/')) != NULL) {
		*ptr = '\0';
		child = pcc_mkdir(parent, entry_name, mode);
		*ptr = '/';
		if (IS_ERR(child))
			break;
		dput(parent);
		parent = child;
		ptr++;
		entry_name = ptr;
	}

	return child;
}

/* Create file under base. If file already exist, return failure */
static struct dentry *
pcc_create(struct dentry *base, const char *name, umode_t mode)
{
	int rc;
	struct dentry *dentry;
	struct inode *dir = base->d_inode;

	inode_lock(dir);
	dentry = lookup_one_len(name, base, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_is_positive(dentry))
		goto out;

	rc = vfs_create(dir, dentry, mode, LL_VFS_CREATE_FALSE);
	if (rc) {
		dput(dentry);
		dentry = ERR_PTR(rc);
		goto out;
	}
out:
	inode_unlock(dir);
	return dentry;
}

/* Must be called with pcci->pcci_lock held */
static void pcc_inode_attach_init(struct pcc_dataset *dataset,
				  struct pcc_inode *pcci,
				  struct dentry *dentry,
				  enum lu_pcc_type type)
{
	pcci->pcci_path.mnt = mntget(dataset->pccd_path.mnt);
	pcci->pcci_path.dentry = dentry;
	LASSERT(atomic_read(&pcci->pcci_refcount) == 0);
	atomic_set(&pcci->pcci_refcount, 1);
	pcci->pcci_type = type;
	pcci->pcci_attr_valid = false;
}

static int __pcc_inode_create(struct pcc_dataset *dataset,
			      struct lu_fid *fid,
			      struct dentry **dentry)
{
	char *path;
	struct dentry *base;
	struct dentry *child;
	int rc = 0;

	OBD_ALLOC(path, MAX_PCC_DATABASE_PATH);
	if (path == NULL)
		return -ENOMEM;

	pcc_fid2dataset_path(path, MAX_PCC_DATABASE_PATH, fid);

	base = pcc_mkdir_p(dataset->pccd_path.dentry, path, 0700);
	if (IS_ERR(base)) {
		rc = PTR_ERR(base);
		GOTO(out, rc);
	}

	snprintf(path, MAX_PCC_DATABASE_PATH, DFID_NOBRACE, PFID(fid));
	child = pcc_create(base, path, 0600);
	if (IS_ERR(child)) {
		rc = PTR_ERR(child);
		GOTO(out_base, rc);
	}
	*dentry = child;

out_base:
	dput(base);
out:
	OBD_FREE(path, MAX_PCC_DATABASE_PATH);
	return rc;
}

int pcc_inode_create(struct pcc_dataset *dataset, struct lu_fid *fid,
		     struct dentry **pcc_dentry)
{
	return __pcc_inode_create(dataset, fid, pcc_dentry);
}

int pcc_inode_create_fini(struct pcc_dataset *dataset, struct inode *inode,
			  struct dentry *pcc_dentry)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;

	ENTRY;

	LASSERT(ll_i2pcci(inode) == NULL);
	OBD_SLAB_ALLOC_PTR_GFP(pcci, pcc_inode_slab, GFP_NOFS);
	if (pcci == NULL)
		RETURN(-ENOMEM);

	pcc_inode_init(pcci);
	pcc_inode_lock(inode);
	pcc_inode_attach_init(dataset, pcci, pcc_dentry, LU_PCC_READWRITE);
	lli->lli_pcc_inode = pcci;
	pcc_inode_unlock(inode);

	RETURN(0);
}

static int pcc_filp_write(struct file *filp, const void *buf, ssize_t count,
			  loff_t *offset)
{
	while (count > 0) {
		ssize_t size;

		size = vfs_write(filp, (const void __user *)buf, count, offset);
		if (size < 0)
			return size;
		count -= size;
		buf += size;
	}
	return 0;
}

static int pcc_copy_data(struct file *src, struct file *dst)
{
	int rc = 0;
	ssize_t rc2;
	mm_segment_t oldfs;
	loff_t pos, offset = 0;
	size_t buf_len = 1048576;
	void *buf;

	ENTRY;

	OBD_ALLOC_LARGE(buf, buf_len);
	if (buf == NULL)
		RETURN(-ENOMEM);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	while (1) {
		pos = offset;
		rc2 = vfs_read(src, (void __user *)buf, buf_len, &pos);
		if (rc2 < 0)
			GOTO(out_fs, rc = rc2);
		else if (rc2 == 0)
			break;

		pos = offset;
		rc = pcc_filp_write(dst, buf, rc2, &pos);
		if (rc < 0)
			GOTO(out_fs, rc);
		offset += rc2;
	}

out_fs:
	set_fs(oldfs);
	OBD_FREE_LARGE(buf, buf_len);
	RETURN(rc);
}

int pcc_readwrite_attach(struct file *file, struct inode *inode,
			 __u32 archive_id)
{
	struct pcc_dataset *dataset;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	struct dentry *dentry;
	struct file *pcc_filp;
	struct path path;
	int rc;

	ENTRY;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci == NULL) {
		OBD_SLAB_ALLOC_PTR_GFP(pcci, pcc_inode_slab, GFP_NOFS);
		if (pcci == NULL) {
			pcc_inode_unlock(inode);
			RETURN(-ENOMEM);
		}

		pcc_inode_init(pcci);
	} else if (atomic_read(&pcci->pcci_refcount) > 0) {
		pcc_inode_unlock(inode);
		RETURN(-EEXIST);
	}
	pcc_inode_unlock(inode);

	dataset = pcc_dataset_get(&ll_i2sbi(inode)->ll_pcc_super, 0,
				  archive_id);
	if (dataset == NULL)
		GOTO(out_free_pcci, rc = -ENOENT);

	rc = __pcc_inode_create(dataset, &lli->lli_fid, &dentry);
	if (rc)
		GOTO(out_dataset_put, rc);

	path.mnt = dataset->pccd_path.mnt;
	path.dentry = dentry;
#ifdef HAVE_DENTRY_OPEN_USE_PATH
	pcc_filp = dentry_open(&path, O_TRUNC | O_WRONLY | O_LARGEFILE,
			       current_cred());
#else
	pcc_filp = dentry_open(path.dentry, path.mnt,
			       O_TRUNC | O_WRONLY | O_LARGEFILE,
			       current_cred());
#endif
	if (IS_ERR_OR_NULL(pcc_filp)) {
		rc = pcc_filp == NULL ? -EINVAL : PTR_ERR(pcc_filp);
		GOTO(out_dentry, rc);
	}

	rc = pcc_copy_data(file, pcc_filp);
	if (rc)
		GOTO(out_fput, rc);

	pcc_inode_lock(inode);
	if (lli->lli_pcc_inode)
		GOTO(out_unlock, rc = -EEXIST);
	pcc_inode_attach_init(dataset, pcci, dentry, LU_PCC_READWRITE);
	lli->lli_pcc_inode = pcci;
out_unlock:
	pcc_inode_unlock(inode);
out_fput:
	fput(pcc_filp);
out_dentry:
	if (rc)
		dput(dentry);
out_dataset_put:
	pcc_dataset_put(dataset);
out_free_pcci:
	if (rc)
		OBD_SLAB_FREE_PTR(pcci, pcc_inode_slab);
	RETURN(rc);

}

int pcc_readwrite_attach_fini(struct file *file, struct inode *inode,
			      bool lease_broken, int rc, bool attached)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	ENTRY;

	if ((rc || lease_broken) && attached && pcci)
		pcc_inode_put(pcci);

	RETURN(rc);
}

int pcc_ioctl_detach(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci = lli->lli_pcc_inode;
	int rc = 0;
	int count;

	ENTRY;

	pcc_inode_lock(inode);
	if (pcci == NULL)
		GOTO(out_unlock, rc = 0);

	count = atomic_read(&pcci->pcci_refcount);
	if (count > 1)
		GOTO(out_unlock, rc = -EBUSY);
	else if (count == 0)
		GOTO(out_unlock, rc = 0);

	pcc_inode_put(pcci);
	lli->lli_pcc_inode = NULL;
out_unlock:
	pcc_inode_unlock(inode);

	RETURN(rc);
}

int pcc_ioctl_state(struct inode *inode, struct lu_pcc_state *state)
{
	int rc = 0;
	int count;
	char *buf;
	char *path;
	int buf_len = sizeof(state->pccs_path);
	struct pcc_inode *pcci;

	ENTRY;

	if (buf_len <= 0)
		RETURN(-EINVAL);

	OBD_ALLOC(buf, buf_len);
	if (buf == NULL)
		RETURN(-ENOMEM);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci == NULL) {
		state->pccs_type = LU_PCC_NONE;
		GOTO(out_unlock, rc = 0);
	}

	count = atomic_read(&pcci->pcci_refcount);
	if (count == 0) {
		state->pccs_type = LU_PCC_NONE;
		GOTO(out_unlock, rc = 0);
	}
	state->pccs_type = pcci->pcci_type;
	state->pccs_open_count = count - 1;
	state->pccs_flags = pcci->pcci_attr_valid ?
			    PCC_STATE_FLAG_ATTR_VALID : 0;
#ifdef HAVE_DENTRY_PATH_RAW
	path = dentry_path_raw(pcci->pcci_path.dentry, buf, buf_len);
	if (IS_ERR(path))
		GOTO(out_unlock, rc = PTR_ERR(path));
#else
	path = "UNKNOWN";
#endif

	if (strlcpy(state->pccs_path, path, buf_len) >= buf_len)
		GOTO(out_unlock, rc = -ENAMETOOLONG);

out_unlock:
	pcc_inode_unlock(inode);
	OBD_FREE(buf, buf_len);
	RETURN(rc);
}
