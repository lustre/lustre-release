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
 *
 * Persistent Client Cache
 *
 * Author: Li Xi <lixi@ddn.com>
 */

#ifndef LLITE_PCC_H
#define LLITE_PCC_H

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/kref.h>
#include <linux/types.h>
#include <linux/seq_file.h>
#include <uapi/linux/lustre/lustre_user.h>

extern struct kmem_cache *pcc_inode_slab;

#define LPROCFS_WR_PCC_MAX_CMD 4096

/* User/Group/Project ID */
struct pcc_match_id {
	__u32			pmi_id;
	struct list_head	pmi_linkage;
};

/* Lazy file size */
struct pcc_match_size {
	__u64			pms_size;
	struct list_head	pms_linkage;
};

/* wildcard file name */
struct pcc_match_fname {
	char			*pmf_name;
	struct list_head	 pmf_linkage;
};

enum pcc_field {
	PCC_FIELD_UID,
	PCC_FIELD_GID,
	PCC_FIELD_PROJID,
	PCC_FIELD_FNAME,
	PCC_FIELD_SIZE,
	PCC_FIELD_MTIME,
	PCC_FIELD_MAX
};

enum pcc_field_op {
	PCC_FIELD_OP_EQ		= 0,
	PCC_FIELD_OP_LT		= 1,
	PCC_FIELD_OP_GT		= 2,
	PCC_FIELD_OP_MAX	= 3,
	PCC_FIELD_OP_INV	= PCC_FIELD_MAX,
};

struct pcc_expression {
	struct list_head	pe_linkage;
	enum pcc_field		pe_field;
	enum pcc_field_op	pe_opc;
	union {
		struct list_head	pe_cond;
		__u64			pe_size;  /* file size in bytes */
		__u64			pe_mtime; /* relative age in seconds */
		__u32			pe_id;    /* UID/GID/PROJID */
	};
};

struct pcc_conjunction {
	/* link to disjunction */
	struct list_head	pc_linkage;
	/* list of logical conjunction */
	struct list_head	pc_expressions;
};

/**
 * Match rule for auto PCC-cached files.
 */
struct pcc_match_rule {
	char			*pmr_conds_str;
	struct list_head	 pmr_conds;
};

struct pcc_matcher {
	__u32		 pm_uid;
	__u32		 pm_gid;
	__u32		 pm_projid;
	__u64		 pm_size;
	__u64		 pm_mtime;
	struct qstr	*pm_name;
};

enum pcc_dataset_flags {
	PCC_DATASET_INVALID	= 0x0,
	/* Indicate that known the file is not in PCC. */
	PCC_DATASET_NONE	= 0x01,
	/* Try auto attach at open, enabled by default */
	PCC_DATASET_OPEN_ATTACH	= 0x02,
	/* Try auto attach during IO when layout refresh, enabled by default */
	PCC_DATASET_IO_ATTACH	= 0x04,
	/* Try auto attach at stat */
	PCC_DATASET_STAT_ATTACH	= 0x08,
	PCC_DATASET_AUTO_ATTACH	= PCC_DATASET_OPEN_ATTACH |
				  PCC_DATASET_IO_ATTACH |
				  PCC_DATASET_STAT_ATTACH,
	/* PCC backend is only used for PCC-RW */
	PCC_DATASET_PCCRW	= 0x10,
	/* PCC backend is only used for PCC-RO */
	PCC_DATASET_PCCRO	= 0x20,
	/* PCC backend provides caching services for both PCC-RW and PCC-RO */
	PCC_DATASET_PCC_ALL	= PCC_DATASET_PCCRW | PCC_DATASET_PCCRO,
	/* Default PCC caching mode: PCC-RO mode */
	PCC_DATASET_PCC_DEFAULT	= PCC_DATASET_PCCRO,
	/* Move pagecache from mapping of PCC copy to Lustre file for mmap */
	PCC_DATASET_MMAP_CONV	= 0x40,
	/* Set the project ID for the PCC copy */
	PCC_DATASET_PROJ_QUOTA	= 0x80,
};

struct pcc_dataset {
	__u32			pccd_rwid;	 /* Archive ID */
	__u32			pccd_roid;	 /* Readonly ID */
	struct pcc_match_rule	pccd_rule;	 /* Match rule */
	enum pcc_dataset_flags	pccd_flags;	 /* Flags of PCC backend */
	char			pccd_pathname[PATH_MAX]; /* full path */
	struct path		pccd_path;	 /* Root path */
	struct list_head	pccd_linkage;  /* Linked to pccs_datasets */
	struct kref		pccd_refcount; /* Reference count */
	enum hsmtool_type	pccd_hsmtool_type; /* HSM copytool type */
};

#define PCC_DEFAULT_ASYNC_THRESHOLD	(256 << 20)

struct pcc_super {
	/* Protect pccs_datasets */
	struct rw_semaphore	 pccs_rw_sem;
	/* List of datasets */
	struct list_head	 pccs_datasets;
	/* creds of process who forced instantiation of super block */
	const struct cred	*pccs_cred;
	/*
	 * Gobal PCC Generation: it will be increased once the configuration
	 * for PCC is changed, i.e. add or delete a PCC backend, modify the
	 * parameters for PCC.
	 */
	__u64			 pccs_generation;
	/* Size threshold for asynchrous PCC-RO attach in background. */
	__u64			 pccs_async_threshold;
	bool			 pccs_async_affinity;
	umode_t			 pccs_mode;
};

struct pcc_inode {
	struct ll_inode_info	*pcci_lli;
	/* Cache path on local file system */
	struct path		 pcci_path;
	/*
	 * If reference count is 0, then the cache is not inited, if 1, then
	 * no one is using it.
	 */
	atomic_t		 pcci_refcount;
	/* Whether readonly or readwrite PCC */
	enum lu_pcc_type	 pcci_type:8;
	/* Whether the inode attr is cached locally */
	bool			 pcci_attr_valid;
	/* Whether the PCC inode is unlinked at detach */
	bool			 pcci_unlinked;
	/* Layout generation */
	__u32			 pcci_layout_gen;
	/*
	 * How many IOs are on going on this cached object. Layout can be
	 * changed only if there is no active IO.
	 */
	atomic_t		 pcci_active_ios;
	/* Waitq - wait for PCC I/O completion. */
	wait_queue_head_t	 pcci_waitq;
};

struct pcc_file {
	/* Opened cache file */
	struct file		*pccf_file;
	/* Whether readonly or readwrite PCC */
	enum lu_pcc_type	 pccf_type;
	/* I/O especially mmap() I/O must fallback to Lustre OSTs. */
	__u32			 pccf_fallback:1;
};

struct pcc_vma {
	atomic_t				 pccv_refcnt;
	struct file				*pccv_file;
	const struct vm_operations_struct	*pccv_vm_ops;
};

struct pcc_attach_context {
	struct file		*pccx_file;
	struct inode		*pccx_inode;
	__u32			 pccx_attach_id;
};

enum pcc_io_type {
	/* read system call */
	PIT_READ = 1,
	/* write system call */
	PIT_WRITE,
	/* truncate, utime system calls */
	PIT_SETATTR,
	/* stat system call */
	PIT_GETATTR,
	/* mmap write handling */
	PIT_PAGE_MKWRITE,
	/* page fault handling */
	PIT_FAULT,
	/* fsync system call handling */
	PIT_FSYNC,
	/* splice_read system call */
	PIT_SPLICE_READ,
	/* open system call */
	PIT_OPEN
};

enum pcc_cmd_type {
	PCC_ADD_DATASET = 0,
	PCC_DEL_DATASET,
	PCC_CLEAR_ALL,
};

struct pcc_cmd {
	enum pcc_cmd_type			 pccc_cmd;
	char					*pccc_pathname;
	union {
		struct pcc_cmd_add {
			__u32			 pccc_rwid;
			__u32			 pccc_roid;
			struct list_head	 pccc_conds;
			char			*pccc_conds_str;
			enum pcc_dataset_flags	 pccc_flags;
			enum hsmtool_type	 pccc_hsmtool_type;
		} pccc_add;
		struct pcc_cmd_del {
			__u32			 pccc_pad;
		} pccc_del;
	} u;
};

struct pcc_create_attach {
	struct pcc_dataset *pca_dataset;
	struct dentry *pca_dentry;
};

int pcc_super_init(struct pcc_super *super);
void pcc_super_fini(struct pcc_super *super);
int pcc_cmd_handle(char *buffer, unsigned long count,
		   struct pcc_super *super);
int pcc_super_dump(struct pcc_super *super, struct seq_file *m);
int pcc_readwrite_attach(struct file *file, struct inode *inode,
			 __u32 arch_id);
int pcc_readwrite_attach_fini(struct file *file, struct inode *inode,
			      __u32 gen, bool lease_broken, int rc,
			      bool attached);
int pcc_ioctl_attach(struct file *file, struct inode *inode,
		     struct lu_pcc_attach *attach);
int pcc_ioctl_detach(struct inode *inode, __u32 *flags);
int pcc_ioctl_state(struct file *file, struct inode *inode,
		    struct lu_pcc_state *state);
void pcc_file_init(struct pcc_file *pccf);
bool pcc_inode_permission(struct inode *inode);
int pcc_file_open(struct inode *inode, struct file *file);
void pcc_file_release(struct inode *inode, struct file *file);
ssize_t pcc_file_read_iter(struct kiocb *iocb, struct iov_iter *iter,
			   bool *cached);
ssize_t pcc_file_write_iter(struct kiocb *iocb, struct iov_iter *iter,
			    bool *cached);
int pcc_inode_getattr(struct inode *inode, u32 request_mask,
		      unsigned int flags, bool *cached);
int pcc_inode_setattr(struct inode *inode, struct iattr *attr, bool *cached);
ssize_t pcc_file_splice_read(struct file *in_file, loff_t *ppos,
			     struct pipe_inode_info *pipe, size_t count,
			     unsigned int flags);
int pcc_fsync(struct file *file, loff_t start, loff_t end,
	      int datasync, bool *cached);
int pcc_file_mmap(struct file *file, struct vm_area_struct *vma, bool *cached);
void pcc_vm_open(struct vm_area_struct *vma);
void pcc_vm_close(struct vm_area_struct *vma);
int pcc_fault(struct vm_area_struct *mva, struct vm_fault *vmf, bool *cached);
int pcc_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
		     bool *cached);
int pcc_inode_create(struct super_block *sb, struct pcc_dataset *dataset,
		     struct lu_fid *fid, struct dentry **pcc_dentry);
int pcc_inode_create_fini(struct inode *inode, struct pcc_create_attach *pca);
void pcc_create_attach_cleanup(struct super_block *sb,
			       struct pcc_create_attach *pca);
struct pcc_dataset *pcc_dataset_match_get(struct pcc_super *super,
					  enum lu_pcc_type type,
					  struct pcc_matcher *matcher);
void pcc_dataset_free(struct kref *kref);
void pcc_dataset_put(struct pcc_dataset *dataset);
void pcc_inode_free(struct inode *inode);
void pcc_layout_invalidate(struct inode *inode);

static inline struct file *pcc_vma_file(struct vm_area_struct *vma)
{
	struct pcc_vma *pccv = (struct pcc_vma *)vma->vm_private_data;
	struct file *file;

	if (pccv)
		file = pccv->pccv_file;
	else
		file = vma->vm_file;

	return file;
}

#endif /* LLITE_PCC_H */
