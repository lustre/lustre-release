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

int pcc_super_init(struct pcc_super *super)
{
	struct cred *cred;

	super->pccs_cred = cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	/* Never override disk quota limits or use reserved space */
	cap_lower(cred->cap_effective, CAP_SYS_RESOURCE);
	spin_lock_init(&super->pccs_lock);
	INIT_LIST_HEAD(&super->pccs_datasets);

	return 0;
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

static void pcc_remove_datasets(struct pcc_super *super)
{
	struct pcc_dataset *dataset, *tmp;

	list_for_each_entry_safe(dataset, tmp,
				 &super->pccs_datasets, pccd_linkage) {
		list_del(&dataset->pccd_linkage);
		pcc_dataset_put(dataset);
	}
}

void pcc_super_fini(struct pcc_super *super)
{
	pcc_remove_datasets(super);
	put_cred(super->pccs_cred);
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
		pcc_remove_datasets(super);
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

static void pcc_inode_init(struct pcc_inode *pcci, struct ll_inode_info *lli)
{
	pcci->pcci_lli = lli;
	lli->lli_pcc_inode = pcci;
	atomic_set(&pcci->pcci_refcount, 0);
	pcci->pcci_type = LU_PCC_NONE;
	pcci->pcci_layout_gen = CL_LAYOUT_GEN_NONE;
	atomic_set(&pcci->pcci_active_ios, 0);
	init_waitqueue_head(&pcci->pcci_waitq);
}

static void pcc_inode_fini(struct pcc_inode *pcci)
{
	struct ll_inode_info *lli = pcci->pcci_lli;

	path_put(&pcci->pcci_path);
	pcci->pcci_type = LU_PCC_NONE;
	OBD_SLAB_FREE_PTR(pcci, pcc_inode_slab);
	lli->lli_pcc_inode = NULL;
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
	struct pcc_inode *pcci = ll_i2pcci(inode);

	if (pcci) {
		WARN_ON(atomic_read(&pcci->pcci_refcount) > 1);
		pcc_inode_put(pcci);
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

static inline const struct cred *pcc_super_cred(struct super_block *sb)
{
	return ll_s2sbi(sb)->ll_pcc_super.pccs_cred;
}

void pcc_file_init(struct pcc_file *pccf)
{
	pccf->pccf_file = NULL;
	pccf->pccf_type = LU_PCC_NONE;
}

static inline bool pcc_inode_has_layout(struct pcc_inode *pcci)
{
	return pcci->pcci_layout_gen != CL_LAYOUT_GEN_NONE;
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

	if (atomic_read(&pcci->pcci_refcount) == 0 ||
	    !pcc_inode_has_layout(pcci))
		GOTO(out_unlock, rc = 0);

	pcc_inode_get(pcci);
	WARN_ON(pccf->pccf_file);

	path = &pcci->pcci_path;
	dname = &path->dentry->d_name;
	CDEBUG(D_CACHE, "opening pcc file '%.*s'\n", dname->len,
	       dname->name);

#ifdef HAVE_DENTRY_OPEN_USE_PATH
	pcc_file = dentry_open(path, file->f_flags,
			       pcc_super_cred(inode->i_sb));
#else
	pcc_file = dentry_open(path->dentry, path->mnt, file->f_flags,
			       pcc_super_cred(inode->i_sb));
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
	RETURN_EXIT;
}

static inline void pcc_layout_gen_set(struct pcc_inode *pcci,
				      __u32 gen)
{
	pcci->pcci_layout_gen = gen;
}

static void pcc_io_init(struct inode *inode, bool *cached)
{
	struct pcc_inode *pcci;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 0);
		atomic_inc(&pcci->pcci_active_ios);
		*cached = true;
	} else {
		*cached = false;
	}
	pcc_inode_unlock(inode);
}

static void pcc_io_fini(struct inode *inode)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	LASSERT(pcci && atomic_read(&pcci->pcci_active_ios) > 0);
	if (atomic_dec_and_test(&pcci->pcci_active_ios))
		wake_up_all(&pcci->pcci_waitq);
}


static ssize_t
__pcc_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;

#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
	return file->f_op->read_iter(iocb, iter);
#else
	struct iovec iov;
	struct iov_iter i;
	ssize_t bytes = 0;

	iov_for_each(iov, i, *iter) {
		ssize_t res;

		res = file->f_op->aio_read(iocb, &iov, 1, iocb->ki_pos);
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

ssize_t pcc_file_read_iter(struct kiocb *iocb,
			   struct iov_iter *iter, bool *cached)
{
	struct file *file = iocb->ki_filp;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct inode *inode = file_inode(file);
	ssize_t result;

	ENTRY;

	if (pccf->pccf_file == NULL) {
		*cached = false;
		RETURN(0);
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		RETURN(0);

	iocb->ki_filp = pccf->pccf_file;
	/* generic_file_aio_read does not support ext4-dax,
	 * __pcc_file_read_iter uses ->aio_read hook directly
	 * to add support for ext4-dax.
	 */
	result = __pcc_file_read_iter(iocb, iter);
	iocb->ki_filp = file;

	pcc_io_fini(inode);
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
	struct inode *inode = file_inode(file);
	ssize_t result;

	ENTRY;

	if (pccf->pccf_file == NULL) {
		*cached = false;
		RETURN(0);
	}

	if (pccf->pccf_type != LU_PCC_READWRITE) {
		*cached = false;
		RETURN(-EAGAIN);
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		RETURN(0);

	if (OBD_FAIL_CHECK(OBD_FAIL_LLITE_PCC_FAKE_ERROR))
		GOTO(out, result = -ENOSPC);

	iocb->ki_filp = pccf->pccf_file;

	/* Since __pcc_file_write_iter makes write calls via
	 * the normal vfs interface to the local PCC file system,
	 * the inode lock is not needed.
	 */
	result = __pcc_file_write_iter(iocb, iter);
	iocb->ki_filp = file;
out:
	pcc_io_fini(inode);
	RETURN(result);
}

int pcc_inode_setattr(struct inode *inode, struct iattr *attr,
		      bool *cached)
{
	int rc;
	const struct cred *old_cred;
	struct iattr attr2 = *attr;
	struct dentry *pcc_dentry;
	struct pcc_inode *pcci;

	ENTRY;

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		RETURN(0);
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		RETURN(0);

	attr2.ia_valid = attr->ia_valid & (ATTR_SIZE | ATTR_ATIME |
			 ATTR_ATIME_SET | ATTR_MTIME | ATTR_MTIME_SET |
			 ATTR_CTIME | ATTR_UID | ATTR_GID);
	pcci = ll_i2pcci(inode);
	pcc_dentry = pcci->pcci_path.dentry;
	inode_lock(pcc_dentry->d_inode);
	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	rc = pcc_dentry->d_inode->i_op->setattr(pcc_dentry, &attr2);
	revert_creds(old_cred);
	inode_unlock(pcc_dentry->d_inode);

	pcc_io_fini(inode);
	RETURN(rc);
}

int pcc_inode_getattr(struct inode *inode, bool *cached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	const struct cred *old_cred;
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

	pcc_io_init(inode, cached);
	if (!*cached)
		RETURN(0);

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	rc = ll_vfs_getattr(&ll_i2pcci(inode)->pcci_path, &stat);
	revert_creds(old_cred);
	if (rc)
		GOTO(out, rc);

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
out:
	pcc_io_fini(inode);
	RETURN(rc);
}

ssize_t pcc_file_splice_read(struct file *in_file, loff_t *ppos,
			     struct pipe_inode_info *pipe,
			     size_t count, unsigned int flags,
			     bool *cached)
{
	struct inode *inode = file_inode(in_file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(in_file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	ssize_t result;

	ENTRY;

	*cached = false;
	if (!pcc_file)
		RETURN(0);

	if (!file_inode(pcc_file)->i_fop->splice_read)
		RETURN(-ENOTSUPP);

	pcc_io_init(inode, cached);
	if (!*cached)
		RETURN(0);

	result = file_inode(pcc_file)->i_fop->splice_read(pcc_file,
							  ppos, pipe, count,
							  flags);

	pcc_io_fini(inode);
	RETURN(result);
}

int pcc_fsync(struct file *file, loff_t start, loff_t end,
	      int datasync, bool *cached)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	int rc;

	ENTRY;

	if (!pcc_file) {
		*cached = false;
		RETURN(0);
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		RETURN(0);

#ifdef HAVE_FILE_FSYNC_4ARGS
	rc = file_inode(pcc_file)->i_fop->fsync(pcc_file,
						start, end, datasync);
#elif defined(HAVE_FILE_FSYNC_2ARGS)
	rc = file_inode(pcc_file)->i_fop->fsync(pcc_file, datasync);
#else
	rc = file_inode(pcc_file)->i_fop->fsync(pcc_file,
				file_dentry(dentry), datasync);
#endif

	pcc_io_fini(inode);
	RETURN(rc);
}

int pcc_file_mmap(struct file *file, struct vm_area_struct *vma,
		  bool *cached)
{
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	struct pcc_inode *pcci;
	int rc = 0;

	ENTRY;

	if (!pcc_file || !file_inode(pcc_file)->i_fop->mmap) {
		*cached = false;
		RETURN(0);
	}

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 1);
		*cached = true;
		vma->vm_file = pcc_file;
		rc = file_inode(pcc_file)->i_fop->mmap(pcc_file, vma);
		vma->vm_file = file;
		/* Save the vm ops of backend PCC */
		vma->vm_private_data = (void *)vma->vm_ops;
	} else {
		*cached = false;
	}
	pcc_inode_unlock(inode);

	RETURN(rc);
}

void pcc_vm_open(struct vm_area_struct *vma)
{
	struct pcc_inode *pcci;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;

	ENTRY;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->open)
		RETURN_EXIT;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		vma->vm_file = pcc_file;
		pcc_vm_ops->open(vma);
		vma->vm_file = file;
	}
	pcc_inode_unlock(inode);
	EXIT;
}

void pcc_vm_close(struct vm_area_struct *vma)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;

	ENTRY;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->close)
		RETURN_EXIT;

	pcc_inode_lock(inode);
	/* Layout lock maybe revoked here */
	vma->vm_file = pcc_file;
	pcc_vm_ops->close(vma);
	vma->vm_file = file;
	pcc_inode_unlock(inode);
	EXIT;
}

int pcc_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
		     bool *cached)
{
	struct page *page = vmf->page;
	struct mm_struct *mm = vma->vm_mm;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;
	int rc;

	ENTRY;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->page_mkwrite) {
		*cached = false;
		RETURN(0);
	}

	/* Pause to allow for a race with concurrent detach */
	OBD_FAIL_TIMEOUT(OBD_FAIL_LLITE_PCC_MKWRITE_PAUSE, cfs_fail_val);

	pcc_io_init(inode, cached);
	if (!*cached) {
		/* This happens when the file is detached from PCC after got
		 * the fault page via ->fault() on the inode of the PCC copy.
		 * Here it can not simply fall back to normal Lustre I/O path.
		 * The reason is that the address space of fault page used by
		 * ->page_mkwrite() is still the one of PCC inode. In the
		 * normal Lustre ->page_mkwrite() I/O path, it will be wrongly
		 * handled as the address space of the fault page is not
		 * consistent with the one of the Lustre inode (though the
		 * fault page was truncated).
		 * As the file is detached from PCC, the fault page must
		 * be released frist, and retry the mmap write (->fault() and
		 * ->page_mkwrite).
		 * We use an ugly and tricky method by returning
		 * VM_FAULT_NOPAGE | VM_FAULT_RETRY to the caller
		 * __do_page_fault and retry the memory fault handling.
		 */
		if (page->mapping == file_inode(pcc_file)->i_mapping) {
			*cached = true;
			up_read(&mm->mmap_sem);
			RETURN(VM_FAULT_RETRY | VM_FAULT_NOPAGE);
		}

		RETURN(0);
	}

	/*
	 * This fault injection can also be used to simulate -ENOSPC and
	 * -EDQUOT failure of underlying PCC backend fs.
	 */
	if (OBD_FAIL_CHECK(OBD_FAIL_LLITE_PCC_DETACH_MKWRITE)) {
		pcc_io_fini(inode);
		pcc_ioctl_detach(inode);
		up_read(&mm->mmap_sem);
		RETURN(VM_FAULT_RETRY | VM_FAULT_NOPAGE);
	}

	vma->vm_file = pcc_file;
#ifdef HAVE_VM_OPS_USE_VM_FAULT_ONLY
	rc = pcc_vm_ops->page_mkwrite(vmf);
#else
	rc = pcc_vm_ops->page_mkwrite(vma, vmf);
#endif
	vma->vm_file = file;

	pcc_io_fini(inode);
	RETURN(rc);
}

int pcc_fault(struct vm_area_struct *vma, struct vm_fault *vmf,
	      bool *cached)
{
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct file *pcc_file = fd->fd_pcc_file.pccf_file;
	struct vm_operations_struct *pcc_vm_ops = vma->vm_private_data;
	int rc;

	ENTRY;

	if (!pcc_file || !pcc_vm_ops || !pcc_vm_ops->fault) {
		*cached = false;
		RETURN(0);
	}

	pcc_io_init(inode, cached);
	if (!*cached)
		RETURN(0);

	vma->vm_file = pcc_file;
#ifdef HAVE_VM_OPS_USE_VM_FAULT_ONLY
	rc = pcc_vm_ops->fault(vmf);
#else
	rc = pcc_vm_ops->fault(vma, vmf);
#endif
	vma->vm_file = file;

	pcc_io_fini(inode);
	RETURN(rc);
}

static void pcc_layout_wait(struct pcc_inode *pcci)
{
	struct l_wait_info lwi = { 0 };

	while (atomic_read(&pcci->pcci_active_ios) > 0) {
		CDEBUG(D_CACHE, "Waiting for IO completion: %d\n",
		       atomic_read(&pcci->pcci_active_ios));
		l_wait_event(pcci->pcci_waitq,
			     atomic_read(&pcci->pcci_active_ios) == 0, &lwi);
	}
}

static void __pcc_layout_invalidate(struct pcc_inode *pcci)
{
	pcci->pcci_type = LU_PCC_NONE;
	pcc_layout_gen_set(pcci, CL_LAYOUT_GEN_NONE);
	pcc_layout_wait(pcci);
}

void pcc_layout_invalidate(struct inode *inode)
{
	struct pcc_inode *pcci;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 0);
		__pcc_layout_invalidate(pcci);

		CDEBUG(D_CACHE, "Invalidate "DFID" layout gen %d\n",
		       PFID(&ll_i2info(inode)->lli_fid), pcci->pcci_layout_gen);

		pcc_inode_put(pcci);
	}
	pcc_inode_unlock(inode);
}

static int pcc_inode_remove(struct pcc_inode *pcci)
{
	struct dentry *dentry;
	int rc;

	dentry = pcci->pcci_path.dentry;
	rc = ll_vfs_unlink(dentry->d_parent->d_inode, dentry);
	if (rc)
		CWARN("failed to unlink cached file, rc = %d\n", rc);

	return rc;
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
		dput(parent);
		if (IS_ERR(child))
			break;

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

	base = pcc_mkdir_p(dataset->pccd_path.dentry, path, 0);
	if (IS_ERR(base)) {
		rc = PTR_ERR(base);
		GOTO(out, rc);
	}

	snprintf(path, MAX_PCC_DATABASE_PATH, DFID_NOBRACE, PFID(fid));
	child = pcc_create(base, path, 0);
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

/* TODO: Set the project ID for PCC copy */
int pcc_inode_store_ugpid(struct dentry *dentry, kuid_t uid, kgid_t gid)
{
	struct inode *inode = dentry->d_inode;
	struct iattr attr;
	int rc;

	ENTRY;

	attr.ia_valid = ATTR_UID | ATTR_GID;
	attr.ia_uid = uid;
	attr.ia_gid = gid;

	inode_lock(inode);
	rc = notify_change(dentry, &attr, NULL);
	inode_unlock(inode);

	RETURN(rc);
}

int pcc_inode_create(struct super_block *sb, struct pcc_dataset *dataset,
		     struct lu_fid *fid, struct dentry **pcc_dentry)
{
	const struct cred *old_cred;
	int rc;

	old_cred = override_creds(pcc_super_cred(sb));
	rc = __pcc_inode_create(dataset, fid, pcc_dentry);
	revert_creds(old_cred);
	return rc;
}

int pcc_inode_create_fini(struct pcc_dataset *dataset, struct inode *inode,
			  struct dentry *pcc_dentry)
{
	const struct cred *old_cred;
	struct pcc_inode *pcci;
	int rc = 0;

	ENTRY;

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	pcc_inode_lock(inode);
	LASSERT(ll_i2pcci(inode) == NULL);
	OBD_SLAB_ALLOC_PTR_GFP(pcci, pcc_inode_slab, GFP_NOFS);
	if (pcci == NULL)
		GOTO(out_unlock, rc = -ENOMEM);

	rc = pcc_inode_store_ugpid(pcc_dentry, old_cred->suid,
				   old_cred->sgid);
	if (rc)
		GOTO(out_unlock, rc);

	pcc_inode_init(pcci, ll_i2info(inode));
	pcc_inode_attach_init(dataset, pcci, pcc_dentry, LU_PCC_READWRITE);
	/* Set the layout generation of newly created file with 0 */
	pcc_layout_gen_set(pcci, 0);

out_unlock:
	if (rc) {
		int rc2;

		rc2 = ll_vfs_unlink(pcc_dentry->d_parent->d_inode, pcc_dentry);
		if (rc2)
			CWARN("failed to unlink PCC file, rc = %d\n", rc2);

		dput(pcc_dentry);
	}

	pcc_inode_unlock(inode);
	revert_creds(old_cred);
	if (rc && pcci)
		OBD_SLAB_FREE_PTR(pcci, pcc_inode_slab);

	RETURN(rc);
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

static int pcc_attach_allowed_check(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	int rc = 0;

	ENTRY;

	pcc_inode_lock(inode);
	if (lli->lli_pcc_state & PCC_STATE_FL_ATTACHING)
		GOTO(out_unlock, rc = -EBUSY);

	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci))
		GOTO(out_unlock, rc = -EEXIST);

	lli->lli_pcc_state |= PCC_STATE_FL_ATTACHING;
out_unlock:
	pcc_inode_unlock(inode);
	RETURN(rc);
}

int pcc_readwrite_attach(struct file *file, struct inode *inode,
			 __u32 archive_id)
{
	struct pcc_dataset *dataset;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	const struct cred *old_cred;
	struct dentry *dentry;
	struct file *pcc_filp;
	struct path path;
	int rc;

	ENTRY;

	rc = pcc_attach_allowed_check(inode);
	if (rc)
		RETURN(rc);

	dataset = pcc_dataset_get(&ll_i2sbi(inode)->ll_pcc_super, 0,
				  archive_id);
	if (dataset == NULL)
		RETURN(-ENOENT);

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	rc = __pcc_inode_create(dataset, &lli->lli_fid, &dentry);
	if (rc) {
		revert_creds(old_cred);
		GOTO(out_dataset_put, rc);
	}

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
		revert_creds(old_cred);
		GOTO(out_dentry, rc);
	}

	rc = pcc_inode_store_ugpid(dentry, old_cred->uid, old_cred->gid);
	revert_creds(old_cred);
	if (rc)
		GOTO(out_fput, rc);

	rc = pcc_copy_data(file, pcc_filp);
	if (rc)
		GOTO(out_fput, rc);

	/* Pause to allow for a race with concurrent HSM remove */
	OBD_FAIL_TIMEOUT(OBD_FAIL_LLITE_PCC_ATTACH_PAUSE, cfs_fail_val);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	LASSERT(!pcci);
	OBD_SLAB_ALLOC_PTR_GFP(pcci, pcc_inode_slab, GFP_NOFS);
	if (pcci == NULL)
		GOTO(out_unlock, rc = -ENOMEM);

	pcc_inode_init(pcci, lli);
	pcc_inode_attach_init(dataset, pcci, dentry, LU_PCC_READWRITE);
out_unlock:
	pcc_inode_unlock(inode);
out_fput:
	fput(pcc_filp);
out_dentry:
	if (rc) {
		int rc2;

		old_cred = override_creds(pcc_super_cred(inode->i_sb));
		rc2 = ll_vfs_unlink(dentry->d_parent->d_inode, dentry);
		revert_creds(old_cred);
		if (rc2)
			CWARN("failed to unlink PCC file, rc = %d\n", rc2);

		dput(dentry);
	}
out_dataset_put:
	pcc_dataset_put(dataset);
	RETURN(rc);
}

int pcc_readwrite_attach_fini(struct file *file, struct inode *inode,
			      __u32 gen, bool lease_broken, int rc,
			      bool attached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	const struct cred *old_cred;
	struct pcc_inode *pcci;
	__u32 gen2;

	ENTRY;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	lli->lli_pcc_state &= ~PCC_STATE_FL_ATTACHING;
	if (rc || lease_broken) {
		if (attached && pcci)
			pcc_inode_put(pcci);

		GOTO(out_unlock, rc);
	}

	/* PCC inode may be released due to layout lock revocatioin */
	if (!pcci)
		GOTO(out_unlock, rc = -ESTALE);

	LASSERT(attached);
	rc = ll_layout_refresh(inode, &gen2);
	if (!rc) {
		if (gen2 == gen) {
			pcc_layout_gen_set(pcci, gen);
		} else {
			CDEBUG(D_CACHE,
			       DFID" layout changed from %d to %d.\n",
			       PFID(ll_inode2fid(inode)), gen, gen2);
			GOTO(out_put, rc = -ESTALE);
		}
	}

out_put:
	if (rc) {
		old_cred = override_creds(pcc_super_cred(inode->i_sb));
		pcc_inode_remove(pcci);
		revert_creds(old_cred);
		pcc_inode_put(pcci);
	}
out_unlock:
	pcc_inode_unlock(inode);
	RETURN(rc);
}

int pcc_ioctl_detach(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	int rc = 0;

	ENTRY;

	pcc_inode_lock(inode);
	pcci = lli->lli_pcc_inode;
	if (!pcci || lli->lli_pcc_state & PCC_STATE_FL_ATTACHING ||
	    !pcc_inode_has_layout(pcci))
		GOTO(out_unlock, rc = 0);

	__pcc_layout_invalidate(pcci);
	pcc_inode_put(pcci);

out_unlock:
	pcc_inode_unlock(inode);
	RETURN(rc);
}

int pcc_ioctl_state(struct file *file, struct inode *inode,
		    struct lu_pcc_state *state)
{
	int rc = 0;
	int count;
	char *buf;
	char *path;
	int buf_len = sizeof(state->pccs_path);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct pcc_file *pccf = &fd->fd_pcc_file;
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
		state->pccs_open_count = 0;
		GOTO(out_unlock, rc = 0);
	}

	if (pcc_inode_has_layout(pcci))
		count--;
	if (pccf->pccf_file != NULL)
		count--;
	state->pccs_type = pcci->pcci_type;
	state->pccs_open_count = count;
	state->pccs_flags = ll_i2info(inode)->lli_pcc_state;
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
