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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * API and structure definitions for params_tree.
 *
 * Author: LiuYing <emoly.liu@oracle.com>
 */
#ifndef __PARAMS_TREE_H__
#define __PARAMS_TREE_H__

#include <libcfs/libcfs.h>

#undef LPROCFS
#if (defined(__KERNEL__) && defined(CONFIG_PROC_FS))
# define LPROCFS
#endif

#ifdef LPROCFS
typedef struct inode                            cfs_inode_t;
typedef struct file_operations                  cfs_param_file_ops_t;
typedef struct proc_dir_entry                   cfs_param_dentry_t;
typedef struct poll_table_struct                cfs_poll_table_t;
#define CFS_PARAM_MODULE                        THIS_MODULE
#define cfs_file_private(file)                  (file->private_data)

#ifndef HAVE_ONLY_PROCFS_SEQ
/* in lprocfs_stat.c, to protect the private data for proc entries */
extern struct rw_semaphore		_lprocfs_lock;

static inline
int LPROCFS_ENTRY_CHECK(struct proc_dir_entry *dp)
{
	int deleted = 0;

	spin_lock(&(dp)->pde_unload_lock);
	if (dp->proc_fops == NULL)
		deleted = 1;
	spin_unlock(&(dp)->pde_unload_lock);
	if (deleted)
		return -ENODEV;
	return 0;
}
#define LPROCFS_SRCH_ENTRY()            \
do {                                    \
        down_read(&_lprocfs_lock);      \
} while(0)

#define LPROCFS_SRCH_EXIT()             \
do {                                    \
        up_read(&_lprocfs_lock);        \
} while(0)

#define LPROCFS_WRITE_ENTRY()		\
do {					\
	down_write(&_lprocfs_lock);	\
} while(0)

#define LPROCFS_WRITE_EXIT()		\
do {					\
	up_write(&_lprocfs_lock);	\
} while(0)

#define PDE_DATA(inode)		PDE(inode)->data

#else /* New proc api */

static inline cfs_param_dentry_t* PDE(struct inode *inode)
{
	return NULL;
}

static inline
int LPROCFS_ENTRY_CHECK(cfs_param_dentry_t *dp)
{
	return 0;
}

#define LPROCFS_WRITE_ENTRY() do {} while(0)
#define LPROCFS_WRITE_EXIT()  do {} while(0)

#endif

#else /* !LPROCFS */

struct file {
	void		*param_private;
	loff_t		param_pos;
	unsigned int	param_flags;
};

typedef struct cfs_param_inode {
	void    *param_private;
} cfs_inode_t;

typedef struct cfs_param_dentry {
	void *param_data;
} cfs_param_dentry_t;

typedef struct cfs_proc_inode {
	cfs_param_dentry_t	*param_pde;
	cfs_inode_t		param_inode;
} cfs_proc_inode_t;

struct seq_operations;
struct seq_file {
	char				*buf;
	size_t				size;
	size_t				from;
	size_t				count;
	loff_t				index;
	loff_t				version;
	struct mutex			lock;
	const struct seq_operations	*op;
	void				*private;
};

struct seq_operations {
	void *(*start) (struct seq_file *m, loff_t *pos);
	void  (*stop) (struct seq_file *m, void *v);
	void *(*next) (struct seq_file *m, void *v, loff_t *pos);
	int   (*show) (struct seq_file *m, void *v);
};

typedef void *cfs_poll_table_t;

typedef struct cfs_param_file_ops {
	struct module	*owner;
	int (*open) (cfs_inode_t *, struct file *);
	loff_t (*llseek)(struct file *, loff_t, int);
	int (*release) (cfs_inode_t *, struct file *);
	unsigned int (*poll) (struct file *, cfs_poll_table_t *);
	ssize_t (*write) (struct file *, const char *, size_t, loff_t *);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
} cfs_param_file_ops_t;
typedef cfs_param_file_ops_t *cfs_lproc_filep_t;

#define CFS_PARAM_MODULE	NULL
#define seq_lseek		NULL

static inline int seq_read(char *buf, size_t count, loff_t *ppos)
{
	return 0;
}

static inline int
seq_open(struct file *file, const struct seq_operations *fops)
{
	struct seq_file *p = file->param_private;

	if (!p) {
		LIBCFS_ALLOC(p, sizeof(*p));
		if (!p)
			return -ENOMEM;
		file->param_private = p;
	}
	memset(p, 0, sizeof(*p));
	p->op = fops;
	return 0;
}

static inline cfs_proc_inode_t *FAKE_PROC_I(const cfs_inode_t *inode)
{
	return container_of(inode, cfs_proc_inode_t, param_inode);
}

static inline cfs_param_dentry_t *PDE(cfs_inode_t *inode)
{
	return FAKE_PROC_I(inode)->param_pde;
}

static inline
int LPROCFS_ENTRY_CHECK(cfs_param_dentry_t *dp)
{
	return 0;
}
#define LPROCFS_WRITE_ENTRY()       do {} while(0)
#define LPROCFS_WRITE_EXIT()        do {} while(0)

int seq_printf(struct seq_file *, const char *, ...)
	__attribute__ ((format (printf,2,3)));

#endif /* LPROCFS */

/* XXX: params_tree APIs */

#endif  /* __PARAMS_TREE_H__ */
