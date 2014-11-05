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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/lprocfs_status.c
 *
 * Author: Hariharan Thantry <thantry@users.sourceforge.net>
 */

#define DEBUG_SUBSYSTEM S_CLASS


#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>

#if defined(LPROCFS)

static int lprocfs_no_percpu_stats = 0;
CFS_MODULE_PARM(lprocfs_no_percpu_stats, "i", int, 0644,
                "Do not alloc percpu data for lprocfs stats");

#define MAX_STRING_SIZE 128

int lprocfs_single_release(struct inode *inode, struct file *file)
{
        return single_release(inode, file);
}
EXPORT_SYMBOL(lprocfs_single_release);

int lprocfs_seq_release(struct inode *inode, struct file *file)
{
        return seq_release(inode, file);
}
EXPORT_SYMBOL(lprocfs_seq_release);

struct proc_dir_entry *
lprocfs_add_simple(struct proc_dir_entry *root, char *name,
		   void *data, const struct file_operations *fops)
{
	struct proc_dir_entry *proc;
	mode_t mode = 0;

	if (root == NULL || name == NULL || fops == NULL)
                return ERR_PTR(-EINVAL);

	if (fops->read)
		mode = 0444;
	if (fops->write)
		mode |= 0200;
	proc = proc_create_data(name, mode, root, fops, data);
	if (!proc) {
		CERROR("LprocFS: No memory to create /proc entry %s\n",
		       name);
		return ERR_PTR(-ENOMEM);
	}
        return proc;
}
EXPORT_SYMBOL(lprocfs_add_simple);

struct proc_dir_entry *lprocfs_add_symlink(const char *name,
                        struct proc_dir_entry *parent, const char *format, ...)
{
        struct proc_dir_entry *entry;
        char *dest;
        va_list ap;

        if (parent == NULL || format == NULL)
                return NULL;

        OBD_ALLOC_WAIT(dest, MAX_STRING_SIZE + 1);
        if (dest == NULL)
                return NULL;

        va_start(ap, format);
        vsnprintf(dest, MAX_STRING_SIZE, format, ap);
        va_end(ap);

        entry = proc_symlink(name, parent, dest);
	if (entry == NULL)
		CERROR("LprocFS: Could not create symbolic link from "
		       "%s to %s\n", name, dest);

        OBD_FREE(dest, MAX_STRING_SIZE + 1);
        return entry;
}
EXPORT_SYMBOL(lprocfs_add_symlink);

#ifdef HAVE_ONLY_PROCFS_SEQ
static const struct file_operations lprocfs_generic_fops = { };
#else

ssize_t
lprocfs_fops_read(struct file *f, char __user *buf, size_t size, loff_t *ppos)
{
        struct proc_dir_entry *dp = PDE(f->f_dentry->d_inode);
        char *page, *start = NULL;
        int rc = 0, eof = 1, count;

	if (*ppos >= PAGE_CACHE_SIZE)
                return 0;

        page = (char *)__get_free_page(GFP_KERNEL);
        if (page == NULL)
                return -ENOMEM;

	if (LPROCFS_ENTRY_CHECK(dp)) {
                rc = -ENOENT;
                goto out;
        }

        OBD_FAIL_TIMEOUT(OBD_FAIL_LPROC_REMOVE, 10);
        if (dp->read_proc)
		rc = dp->read_proc(page, &start, *ppos, PAGE_CACHE_SIZE,
                                   &eof, dp->data);
        if (rc <= 0)
                goto out;

        /* for lustre proc read, the read count must be less than PAGE_SIZE */
        LASSERT(eof == 1);

        if (start == NULL) {
                rc -= *ppos;
                if (rc < 0)
                        rc = 0;
                if (rc == 0)
                        goto out;
                start = page + *ppos;
        } else if (start < page) {
                start = page;
        }

        count = (rc < size) ? rc : size;
	if (copy_to_user(buf, start, count)) {
                rc = -EFAULT;
                goto out;
        }
        *ppos += count;

out:
        free_page((unsigned long)page);
        return rc;
}

ssize_t
lprocfs_fops_write(struct file *f, const char __user *buf, size_t size,
		   loff_t *ppos)
{
        struct proc_dir_entry *dp = PDE(f->f_dentry->d_inode);
        int rc = -EIO;

	if (LPROCFS_ENTRY_CHECK(dp))
                return -ENOENT;
        if (dp->write_proc)
                rc = dp->write_proc(f, buf, size, dp->data);
        return rc;
}

static struct file_operations lprocfs_generic_fops = {
        .owner = THIS_MODULE,
        .read = lprocfs_fops_read,
        .write = lprocfs_fops_write,
};

/* for b=10866, global variable */
DECLARE_RWSEM(_lprocfs_lock);
EXPORT_SYMBOL(_lprocfs_lock);

static struct proc_dir_entry *__lprocfs_srch(struct proc_dir_entry *head,
					     const char *name)
{
	struct proc_dir_entry *temp;

	if (head == NULL)
		return NULL;

	temp = head->subdir;
	while (temp != NULL) {
		if (strcmp(temp->name, name) == 0)
			return temp;
		temp = temp->next;
	}
	return NULL;
}

struct proc_dir_entry *lprocfs_srch(struct proc_dir_entry *head,
				    const char *name)
{
	struct proc_dir_entry *temp;

	LPROCFS_SRCH_ENTRY();
	temp = __lprocfs_srch(head, name);
	LPROCFS_SRCH_EXIT();
	return temp;
}
EXPORT_SYMBOL(lprocfs_srch);

static int __lprocfs_add_vars(struct proc_dir_entry *root,
			      struct lprocfs_vars *list,
			      void *data)
{
        int rc = 0;

        if (root == NULL || list == NULL)
                return -EINVAL;

        while (list->name != NULL) {
                struct proc_dir_entry *cur_root, *proc;
                char *pathcopy, *cur, *next, pathbuf[64];
                int pathsize = strlen(list->name) + 1;

                proc = NULL;
                cur_root = root;

                /* need copy of path for strsep */
                if (strlen(list->name) > sizeof(pathbuf) - 1) {
                        OBD_ALLOC(pathcopy, pathsize);
                        if (pathcopy == NULL)
                                GOTO(out, rc = -ENOMEM);
                } else {
                        pathcopy = pathbuf;
                }

                next = pathcopy;
                strcpy(pathcopy, list->name);

                while (cur_root != NULL && (cur = strsep(&next, "/"))) {
                        if (*cur =='\0') /* skip double/trailing "/" */
                                continue;

                        proc = __lprocfs_srch(cur_root, cur);
                        CDEBUG(D_OTHER, "cur_root=%s, cur=%s, next=%s, (%s)\n",
                               cur_root->name, cur, next,
                               (proc ? "exists" : "new"));
                        if (next != NULL) {
                                cur_root = (proc ? proc :
                                            proc_mkdir(cur, cur_root));
                        } else if (proc == NULL) {
                                mode_t mode = 0;
                                if (list->proc_mode != 0000) {
                                        mode = list->proc_mode;
                                } else {
                                        if (list->read_fptr)
                                                mode = 0444;
                                        if (list->write_fptr)
                                                mode |= 0200;
                                }
                                proc = create_proc_entry(cur, mode, cur_root);
                        }
                }

                if (pathcopy != pathbuf)
                        OBD_FREE(pathcopy, pathsize);

                if (cur_root == NULL || proc == NULL) {
			CERROR("LprocFS: No memory to create /proc entry %s\n",
			       list->name);
			GOTO(out, rc = -ENOMEM);
                }

                if (list->fops)
                        proc->proc_fops = list->fops;
                else
                        proc->proc_fops = &lprocfs_generic_fops;
                proc->read_proc = list->read_fptr;
                proc->write_proc = list->write_fptr;
                proc->data = (list->data ? list->data : data);
                list++;
        }
out:
        return rc;
}

int lprocfs_add_vars(struct proc_dir_entry *root, struct lprocfs_vars *list,
		     void *data)
{
	int rc = 0;

	LPROCFS_WRITE_ENTRY();
	rc = __lprocfs_add_vars(root, list, data);
	LPROCFS_WRITE_EXIT();

	return rc;
}
EXPORT_SYMBOL(lprocfs_add_vars);
#endif

/**
 * Add /proc entries.
 *
 * \param root [in]  The parent proc entry on which new entry will be added.
 * \param list [in]  Array of proc entries to be added.
 * \param data [in]  The argument to be passed when entries read/write routines
 *                   are called through /proc file.
 *
 * \retval 0   on success
 *         < 0 on error
 */
int
lprocfs_seq_add_vars(struct proc_dir_entry *root, struct lprocfs_seq_vars *list,
		     void *data)
{
	if (root == NULL || list == NULL)
		return -EINVAL;

	while (list->name != NULL) {
		struct proc_dir_entry *proc;
		mode_t mode = 0;

		if (list->proc_mode != 0000) {
			mode = list->proc_mode;
		} else if (list->fops) {
			if (list->fops->read)
				mode = 0444;
			if (list->fops->write)
				mode |= 0200;
		}
		proc = proc_create_data(list->name, mode, root,
					list->fops ?: &lprocfs_generic_fops,
					list->data ?: data);
		if (proc == NULL)
			return -ENOMEM;
		list++;
	}
	return 0;
}
EXPORT_SYMBOL(lprocfs_seq_add_vars);

#ifndef HAVE_ONLY_PROCFS_SEQ
void lprocfs_remove_nolock(struct proc_dir_entry **proot)
{
	struct proc_dir_entry *root = *proot;
	struct proc_dir_entry *temp = root;
	struct proc_dir_entry *rm_entry;
	struct proc_dir_entry *parent;

	*proot = NULL;
	if (root == NULL || IS_ERR(root))
		return;

        parent = root->parent;
        LASSERT(parent != NULL);

        while (1) {
                while (temp->subdir != NULL)
                        temp = temp->subdir;

                rm_entry = temp;
                temp = temp->parent;

                /* Memory corruption once caused this to fail, and
                   without this LASSERT we would loop here forever. */
                LASSERTF(strlen(rm_entry->name) == rm_entry->namelen,
                         "0x%p  %s/%s len %d\n", rm_entry, temp->name,
                         rm_entry->name, (int)strlen(rm_entry->name));

                remove_proc_entry(rm_entry->name, temp);
                if (temp == parent)
                        break;
        }
}
#endif

void lprocfs_remove(struct proc_dir_entry **rooth)
{
#ifndef HAVE_ONLY_PROCFS_SEQ
	LPROCFS_WRITE_ENTRY(); /* search vs remove race */
	lprocfs_remove_nolock(rooth);
	LPROCFS_WRITE_EXIT();
#else
	proc_remove(*rooth);
	*rooth = NULL;
#endif
}
EXPORT_SYMBOL(lprocfs_remove);

void lprocfs_remove_proc_entry(const char *name, struct proc_dir_entry *parent)
{
        LASSERT(parent != NULL);
        remove_proc_entry(name, parent);
}
EXPORT_SYMBOL(lprocfs_remove_proc_entry);

#ifndef HAVE_ONLY_PROCFS_SEQ
void lprocfs_try_remove_proc_entry(const char *name,
				   struct proc_dir_entry *parent)
{
	struct proc_dir_entry	 *t = NULL;
	struct proc_dir_entry	**p;
	int			  len, busy = 0;

	LASSERT(parent != NULL);
	len = strlen(name);

	LPROCFS_WRITE_ENTRY();

	/* lookup target name */
	for (p = &parent->subdir; *p; p = &(*p)->next) {
		if ((*p)->namelen != len)
			continue;
		if (memcmp(name, (*p)->name, len))
			continue;
		t = *p;
		break;
	}

	if (t) {
		/* verify it's empty: do not count "num_refs" */
		for (p = &t->subdir; *p; p = &(*p)->next) {
			if ((*p)->namelen != strlen("num_refs")) {
				busy = 1;
				break;
			}
			if (memcmp("num_refs", (*p)->name,
				   strlen("num_refs"))) {
				busy = 1;
				break;
			}
		}
	}

	if (busy == 0)
		lprocfs_remove_nolock(&t);

	LPROCFS_WRITE_EXIT();

	return;
}
EXPORT_SYMBOL(lprocfs_try_remove_proc_entry);

struct proc_dir_entry *lprocfs_register(const char *name,
					struct proc_dir_entry *parent,
					struct lprocfs_vars *list, void *data)
{
	struct proc_dir_entry *entry;
	int rc;

	LPROCFS_WRITE_ENTRY();
	entry = __lprocfs_srch(parent, name);
	if (entry != NULL) {
		CERROR("entry '%s' already registered\n", name);
		GOTO(out, entry = ERR_PTR(-EALREADY));
	}

	entry = proc_mkdir(name, parent);
	if (entry == NULL)
		GOTO(out, entry = ERR_PTR(-ENOMEM));

	if (list != NULL) {
		rc = __lprocfs_add_vars(entry, list, data);
		if (rc != 0) {
			lprocfs_remove_nolock(&entry);
			GOTO(out, entry = ERR_PTR(rc));
		}
	}
out:
	LPROCFS_WRITE_EXIT();
	return entry;
}
EXPORT_SYMBOL(lprocfs_register);
#endif

struct proc_dir_entry *
lprocfs_seq_register(const char *name, struct proc_dir_entry *parent,
		     struct lprocfs_seq_vars *list, void *data)
{
	struct proc_dir_entry *newchild;

	newchild = proc_mkdir(name, parent);
	if (newchild == NULL)
		return ERR_PTR(-ENOMEM);

	if (list != NULL) {
		int rc = lprocfs_seq_add_vars(newchild, list, data);
		if (rc) {
			lprocfs_remove(&newchild);
			return ERR_PTR(rc);
		}
	}
	return newchild;
}
EXPORT_SYMBOL(lprocfs_seq_register);

/* Generic callbacks */
int lprocfs_uint_seq_show(struct seq_file *m, void *data)
{
	return seq_printf(m, "%u\n", *(unsigned int *)data);
}
EXPORT_SYMBOL(lprocfs_uint_seq_show);

int lprocfs_wr_uint(struct file *file, const char __user *buffer,
                    unsigned long count, void *data)
{
        unsigned *p = data;
        char dummy[MAX_STRING_SIZE + 1], *end;
        unsigned long tmp;

        dummy[MAX_STRING_SIZE] = '\0';
	if (copy_from_user(dummy, buffer, MAX_STRING_SIZE))
                return -EFAULT;

        tmp = simple_strtoul(dummy, &end, 0);
        if (dummy == end)
                return -EINVAL;

        *p = (unsigned int)tmp;
        return count;
}
EXPORT_SYMBOL(lprocfs_wr_uint);

ssize_t lprocfs_uint_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off)
{
	int *data = ((struct seq_file *)file->private_data)->private;
	int val = 0, rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc < 0)
		return rc;

	return lprocfs_wr_uint(file, buffer, count, data);
}
EXPORT_SYMBOL(lprocfs_uint_seq_write);

int lprocfs_u64_seq_show(struct seq_file *m, void *data)
{
	LASSERT(data != NULL);
	return seq_printf(m, LPU64"\n", *(__u64 *)data);
}
EXPORT_SYMBOL(lprocfs_u64_seq_show);

int lprocfs_atomic_seq_show(struct seq_file *m, void *data)
{
	atomic_t *atom = data;
	LASSERT(atom != NULL);
	return seq_printf(m, "%d\n", atomic_read(atom));
}
EXPORT_SYMBOL(lprocfs_atomic_seq_show);

ssize_t
lprocfs_atomic_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	atomic_t *atm = ((struct seq_file *)file->private_data)->private;
	int val = 0;
	int rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc < 0)
		return rc;

	if (val <= 0)
		return -ERANGE;

	atomic_set(atm, val);
	return count;
}
EXPORT_SYMBOL(lprocfs_atomic_seq_write);

int lprocfs_uuid_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;

	LASSERT(obd != NULL);
	return seq_printf(m, "%s\n", obd->obd_uuid.uuid);
}
EXPORT_SYMBOL(lprocfs_uuid_seq_show);

int lprocfs_name_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *dev = data;

	LASSERT(dev != NULL);
	return seq_printf(m, "%s\n", dev->obd_name);
}
EXPORT_SYMBOL(lprocfs_name_seq_show);

int lprocfs_blksize_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_statfs  osfs;
	int rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			    cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
			    OBD_STATFS_NODELAY);
	if (!rc)
		rc = seq_printf(m, "%u\n", osfs.os_bsize);
	return rc;
}
EXPORT_SYMBOL(lprocfs_blksize_seq_show);

int lprocfs_kbytestotal_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_statfs  osfs;
	int rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			    cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
			    OBD_STATFS_NODELAY);
	if (!rc) {
		__u32 blk_size = osfs.os_bsize >> 10;
		__u64 result = osfs.os_blocks;

		while (blk_size >>= 1)
			result <<= 1;

		rc = seq_printf(m, LPU64"\n", result);
	}
	return rc;
}
EXPORT_SYMBOL(lprocfs_kbytestotal_seq_show);

int lprocfs_kbytesfree_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_statfs  osfs;
	int rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			    cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
			    OBD_STATFS_NODELAY);
	if (!rc) {
		__u32 blk_size = osfs.os_bsize >> 10;
		__u64 result = osfs.os_bfree;

		while (blk_size >>= 1)
			result <<= 1;

		rc = seq_printf(m, LPU64"\n", result);
	}
	return rc;
}
EXPORT_SYMBOL(lprocfs_kbytesfree_seq_show);

int lprocfs_kbytesavail_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_statfs  osfs;
	int rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			    cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
			    OBD_STATFS_NODELAY);
	if (!rc) {
		__u32 blk_size = osfs.os_bsize >> 10;
		__u64 result = osfs.os_bavail;

		while (blk_size >>= 1)
			result <<= 1;

		rc = seq_printf(m, LPU64"\n", result);
	}
	return rc;
}
EXPORT_SYMBOL(lprocfs_kbytesavail_seq_show);

int lprocfs_filestotal_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_statfs  osfs;
	int rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			    cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
			    OBD_STATFS_NODELAY);
	if (!rc)
		rc = seq_printf(m, LPU64"\n", osfs.os_files);
	return rc;
}
EXPORT_SYMBOL(lprocfs_filestotal_seq_show);

int lprocfs_filesfree_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_statfs  osfs;
	int rc = obd_statfs(NULL, obd->obd_self_export, &osfs,
			    cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
			    OBD_STATFS_NODELAY);
	if (!rc)
		rc = seq_printf(m, LPU64"\n", osfs.os_ffree);
	return rc;
}
EXPORT_SYMBOL(lprocfs_filesfree_seq_show);

int lprocfs_server_uuid_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct obd_import *imp;
	char *imp_state_name = NULL;
	int rc = 0;

	LASSERT(obd != NULL);
	LPROCFS_CLIMP_CHECK(obd);
	imp = obd->u.cli.cl_import;
	imp_state_name = ptlrpc_import_state_name(imp->imp_state);
	rc = seq_printf(m, "%s\t%s%s\n", obd2cli_tgt(obd), imp_state_name,
			imp->imp_deactive ? "\tDEACTIVATED" : "");

	LPROCFS_CLIMP_EXIT(obd);
	return rc;
}
EXPORT_SYMBOL(lprocfs_server_uuid_seq_show);

int lprocfs_conn_uuid_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	struct ptlrpc_connection *conn;
	int rc = 0;

	LASSERT(obd != NULL);

	LPROCFS_CLIMP_CHECK(obd);
	conn = obd->u.cli.cl_import->imp_connection;
	if (conn && obd->u.cli.cl_import)
		rc = seq_printf(m, "%s\n", conn->c_remote_uuid.uuid);
	else
		rc = seq_printf(m, "%s\n", "<none>");

	LPROCFS_CLIMP_EXIT(obd);
	return rc;
}
EXPORT_SYMBOL(lprocfs_conn_uuid_seq_show);

/** add up per-cpu counters */
void lprocfs_stats_collect(struct lprocfs_stats *stats, int idx,
			   struct lprocfs_counter *cnt)
{
	unsigned int			num_entry;
	struct lprocfs_counter		*percpu_cntr;
	int				i;
	unsigned long			flags = 0;

	memset(cnt, 0, sizeof(*cnt));

	if (stats == NULL) {
		/* set count to 1 to avoid divide-by-zero errs in callers */
		cnt->lc_count = 1;
		return;
	}

	cnt->lc_min = LC_MIN_INIT;

	num_entry = lprocfs_stats_lock(stats, LPROCFS_GET_NUM_CPU, &flags);

	for (i = 0; i < num_entry; i++) {
		if (stats->ls_percpu[i] == NULL)
			continue;
		percpu_cntr = lprocfs_stats_counter_get(stats, i, idx);

		cnt->lc_count += percpu_cntr->lc_count;
		cnt->lc_sum += percpu_cntr->lc_sum;
		if (percpu_cntr->lc_min < cnt->lc_min)
			cnt->lc_min = percpu_cntr->lc_min;
		if (percpu_cntr->lc_max > cnt->lc_max)
			cnt->lc_max = percpu_cntr->lc_max;
		cnt->lc_sumsquare += percpu_cntr->lc_sumsquare;
	}

	lprocfs_stats_unlock(stats, LPROCFS_GET_NUM_CPU, &flags);
}
EXPORT_SYMBOL(lprocfs_stats_collect);

/**
 * Append a space separated list of current set flags to str.
 */
#define flag2str(flag)						\
	do {								\
		if (imp->imp_##flag) {					\
			seq_printf(m, "%s" #flag, first ? "" : ", ");	\
			first = false;					\
		}							\
	} while (0)
static void obd_import_flags2str(struct obd_import *imp, struct seq_file *m)
{
	bool first = true;

	if (imp->imp_obd->obd_no_recov) {
		seq_printf(m, "no_recov");
		first = false;
	}

	flag2str(invalid);
	flag2str(deactive);
	flag2str(replayable);
	flag2str(delayed_recovery);
	flag2str(no_lock_replay);
	flag2str(vbr_failed);
	flag2str(pingable);
	flag2str(resend_replay);
	flag2str(no_pinger_recover);
	flag2str(need_mne_swab);
	flag2str(connect_tried);
}
#undef flag2str

static const char *obd_connect_names[] = {
	"read_only",
	"lov_index",
	"connect_from_mds",
	"write_grant",
	"server_lock",
	"version",
	"request_portal",
	"acl",
	"xattr",
	"create_on_write",
	"truncate_lock",
	"initial_transno",
	"inode_bit_locks",
	"join_file(obsolete)",
	"getattr_by_fid",
	"no_oh_for_devices",
	"remote_client",
	"remote_client_by_force",
	"max_byte_per_rpc",
	"64bit_qdata",
	"mds_capability",
	"oss_capability",
	"early_lock_cancel",
	"som",
	"adaptive_timeouts",
	"lru_resize",
	"mds_mds_connection",
	"real_conn",
	"change_qunit_size",
	"alt_checksum_algorithm",
	"fid_is_enabled",
	"version_recovery",
	"pools",
	"grant_shrink",
	"skip_orphan",
	"large_ea",
	"full20",
	"layout_lock",
	"64bithash",
	"object_max_bytes",
	"imp_recov",
	"jobstats",
	"umask",
	"einprogress",
	"grant_param",
	"flock_owner",
	"lvb_type",
	"nanoseconds_times",
	"lightweight_conn",
	"short_io",
	"pingless",
	"flock_deadlock",
	"disp_stripe",
	"open_by_fid",
	"lfsck",
	"unknown",
	"unlink_close",
	"unknown",
	"dir_stripe",
	"unknown",
	NULL
};

static void obd_connect_seq_flags2str(struct seq_file *m, __u64 flags, char *sep)
{
	bool first = true;
	__u64 mask = 1;
	int i;

	for (i = 0; obd_connect_names[i] != NULL; i++, mask <<= 1) {
		if (flags & mask) {
			seq_printf(m, "%s%s",
				   first ? "" : sep, obd_connect_names[i]);
			first = false;
		}
	}
	if (flags & ~(mask - 1))
		seq_printf(m, "%sunknown_"LPX64,
			   first ? "" : sep, flags & ~(mask - 1));
}

int obd_connect_flags2str(char *page, int count, __u64 flags, char *sep)
{
	__u64 mask = 1;
	int i, ret = 0;

	for (i = 0; obd_connect_names[i] != NULL; i++, mask <<= 1) {
		if (flags & mask)
			ret += snprintf(page + ret, count - ret, "%s%s",
					ret ? sep : "", obd_connect_names[i]);
	}
	if (flags & ~(mask - 1))
		ret += snprintf(page + ret, count - ret,
				"%sunknown_"LPX64,
				ret ? sep : "", flags & ~(mask - 1));
	return ret;
}
EXPORT_SYMBOL(obd_connect_flags2str);

static void obd_connect_data_seqprint(struct seq_file *m,
				      struct obd_connect_data *ocd)
{
	int flags;

	LASSERT(ocd != NULL);
	flags = ocd->ocd_connect_flags;

	seq_printf(m, "    connect_data:\n"
		      "       flags: "LPX64"\n"
		      "       instance: %u\n",
		      ocd->ocd_connect_flags,
		      ocd->ocd_instance);
	if (flags & OBD_CONNECT_VERSION)
		seq_printf(m, "       target_version: %u.%u.%u.%u\n",
			      OBD_OCD_VERSION_MAJOR(ocd->ocd_version),
			      OBD_OCD_VERSION_MINOR(ocd->ocd_version),
			      OBD_OCD_VERSION_PATCH(ocd->ocd_version),
			      OBD_OCD_VERSION_FIX(ocd->ocd_version));
	if (flags & OBD_CONNECT_MDS)
		seq_printf(m, "       mdt_index: %d\n", ocd->ocd_group);
	if (flags & OBD_CONNECT_GRANT)
		seq_printf(m, "       initial_grant: %d\n", ocd->ocd_grant);
	if (flags & OBD_CONNECT_INDEX)
		seq_printf(m, "       target_index: %u\n", ocd->ocd_index);
	if (flags & OBD_CONNECT_BRW_SIZE)
		seq_printf(m, "       max_brw_size: %d\n", ocd->ocd_brw_size);
	if (flags & OBD_CONNECT_IBITS)
		seq_printf(m, "       ibits_known: "LPX64"\n",
				ocd->ocd_ibits_known);
	if (flags & OBD_CONNECT_GRANT_PARAM)
		seq_printf(m, "       grant_block_size: %d\n"
			      "       grant_inode_size: %d\n"
			      "       grant_extent_overhead: %d\n",
			      ocd->ocd_blocksize,
			      ocd->ocd_inodespace,
			      ocd->ocd_grant_extent);
	if (flags & OBD_CONNECT_TRANSNO)
		seq_printf(m, "       first_transno: "LPX64"\n",
				ocd->ocd_transno);
	if (flags & OBD_CONNECT_CKSUM)
		seq_printf(m, "       cksum_types: %#x\n",
			      ocd->ocd_cksum_types);
	if (flags & OBD_CONNECT_MAX_EASIZE)
		seq_printf(m, "       max_easize: %d\n", ocd->ocd_max_easize);
	if (flags & OBD_CONNECT_MAXBYTES)
		seq_printf(m, "       max_object_bytes: "LPU64"\n",
			      ocd->ocd_maxbytes);
}

int lprocfs_import_seq_show(struct seq_file *m, void *data)
{
	struct lprocfs_counter          ret;
	struct lprocfs_counter_header   *header;
	struct obd_device               *obd    = (struct obd_device *)data;
	struct obd_import               *imp;
	struct obd_import_conn          *conn;
	struct obd_connect_data		*ocd;
	int                             j;
	int                             k;
	int                             rw      = 0;

	LASSERT(obd != NULL);
	LPROCFS_CLIMP_CHECK(obd);
	imp = obd->u.cli.cl_import;
	ocd = &imp->imp_connect_data;

	seq_printf(m, "import:\n"
		      "    name: %s\n"
		      "    target: %s\n"
		      "    state: %s\n"
		      "    connect_flags: [ ",
		      obd->obd_name,
		      obd2cli_tgt(obd),
		      ptlrpc_import_state_name(imp->imp_state));
	obd_connect_seq_flags2str(m, imp->imp_connect_data.ocd_connect_flags,
					", ");
	seq_printf(m, " ]\n");
	obd_connect_data_seqprint(m, ocd);
	seq_printf(m, "    import_flags: [ ");
	obd_import_flags2str(imp, m);

	seq_printf(m, " ]\n"
		      "    connection:\n"
		      "       failover_nids: [ ");
	spin_lock(&imp->imp_lock);
	j = 0;
	list_for_each_entry(conn, &imp->imp_conn_list, oic_item) {
		seq_printf(m, "%s%s", j ? ", " : "",
			   libcfs_nid2str(conn->oic_conn->c_peer.nid));
		j++;
	}
	seq_printf(m, " ]\n"
		      "       current_connection: %s\n"
		      "       connection_attempts: %u\n"
		      "       generation: %u\n"
		      "       in-progress_invalidations: %u\n",
		      imp->imp_connection == NULL ? "<none>" :
			      libcfs_nid2str(imp->imp_connection->c_peer.nid),
		      imp->imp_conn_cnt,
		      imp->imp_generation,
		      atomic_read(&imp->imp_inval_count));
	spin_unlock(&imp->imp_lock);

	if (obd->obd_svc_stats == NULL)
		goto out_climp;

	header = &obd->obd_svc_stats->ls_cnt_header[PTLRPC_REQWAIT_CNTR];
	lprocfs_stats_collect(obd->obd_svc_stats, PTLRPC_REQWAIT_CNTR, &ret);
	if (ret.lc_count != 0) {
		/* first argument to do_div MUST be __u64 */
		__u64 sum = ret.lc_sum;
		do_div(sum, ret.lc_count);
		ret.lc_sum = sum;
	} else
		ret.lc_sum = 0;
	seq_printf(m, "    rpcs:\n"
		      "       inflight: %u\n"
		      "       unregistering: %u\n"
		      "       timeouts: %u\n"
		      "       avg_waittime: "LPU64" %s\n",
		      atomic_read(&imp->imp_inflight),
		      atomic_read(&imp->imp_unregistering),
		      atomic_read(&imp->imp_timeouts),
		      ret.lc_sum, header->lc_units);

	k = 0;
	for(j = 0; j < IMP_AT_MAX_PORTALS; j++) {
		if (imp->imp_at.iat_portal[j] == 0)
			break;
		k = max_t(unsigned int, k,
			  at_get(&imp->imp_at.iat_service_estimate[j]));
	}
	seq_printf(m, "    service_estimates:\n"
		      "       services: %u sec\n"
		      "       network: %u sec\n",
		      k,
		      at_get(&imp->imp_at.iat_net_latency));

	seq_printf(m, "    transactions:\n"
		      "       last_replay: "LPU64"\n"
		      "       peer_committed: "LPU64"\n"
		      "       last_checked: "LPU64"\n",
		      imp->imp_last_replay_transno,
		      imp->imp_peer_committed_transno,
		      imp->imp_last_transno_checked);

	/* avg data rates */
	for (rw = 0; rw <= 1; rw++) {
		lprocfs_stats_collect(obd->obd_svc_stats,
				      PTLRPC_LAST_CNTR + BRW_READ_BYTES + rw,
				      &ret);
		if (ret.lc_sum > 0 && ret.lc_count > 0) {
			/* first argument to do_div MUST be __u64 */
			__u64 sum = ret.lc_sum;
			do_div(sum, ret.lc_count);
			ret.lc_sum = sum;
			seq_printf(m, "    %s_data_averages:\n"
				      "       bytes_per_rpc: "LPU64"\n",
				      rw ? "write" : "read",
				      ret.lc_sum);
		}
		k = (int)ret.lc_sum;
		j = opcode_offset(OST_READ + rw) + EXTRA_MAX_OPCODES;
		header = &obd->obd_svc_stats->ls_cnt_header[j];
		lprocfs_stats_collect(obd->obd_svc_stats, j, &ret);
		if (ret.lc_sum > 0 && ret.lc_count != 0) {
			/* first argument to do_div MUST be __u64 */
			__u64 sum = ret.lc_sum;
			do_div(sum, ret.lc_count);
			ret.lc_sum = sum;
			seq_printf(m, "       %s_per_rpc: "LPU64"\n",
					header->lc_units, ret.lc_sum);
			j = (int)ret.lc_sum;
			if (j > 0)
				seq_printf(m, "       MB_per_sec: %u.%.02u\n",
						k / j, (100 * k / j) % 100);
		}
	}

out_climp:
	LPROCFS_CLIMP_EXIT(obd);
	return 0;
}
EXPORT_SYMBOL(lprocfs_import_seq_show);

int lprocfs_state_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;
	struct obd_import *imp;
	int j, k;

	LASSERT(obd != NULL);
	LPROCFS_CLIMP_CHECK(obd);
	imp = obd->u.cli.cl_import;

	seq_printf(m, "current_state: %s\n",
		   ptlrpc_import_state_name(imp->imp_state));
	seq_printf(m, "state_history:\n");
	k = imp->imp_state_hist_idx;
	for (j = 0; j < IMP_STATE_HIST_LEN; j++) {
		struct import_state_hist *ish =
			&imp->imp_state_hist[(k + j) % IMP_STATE_HIST_LEN];
		if (ish->ish_state == 0)
			continue;
		seq_printf(m, " - [ "CFS_TIME_T", %s ]\n",
			   ish->ish_time,
		ptlrpc_import_state_name(ish->ish_state));
	}

	LPROCFS_CLIMP_EXIT(obd);
	return 0;
}
EXPORT_SYMBOL(lprocfs_state_seq_show);

int lprocfs_seq_at_hist_helper(struct seq_file *m, struct adaptive_timeout *at)
{
	int i;
	for (i = 0; i < AT_BINS; i++)
		seq_printf(m, "%3u ", at->at_hist[i]);
	seq_printf(m, "\n");
	return 0;
}
EXPORT_SYMBOL(lprocfs_seq_at_hist_helper);

/* See also ptlrpc_lprocfs_timeouts_show_seq */
int lprocfs_timeouts_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;
	struct obd_import *imp;
	unsigned int cur, worst;
	time_t now, worstt;
	struct dhms ts;
	int i;

	LASSERT(obd != NULL);
	LPROCFS_CLIMP_CHECK(obd);
	imp = obd->u.cli.cl_import;

	now = cfs_time_current_sec();

	/* Some network health info for kicks */
	s2dhms(&ts, now - imp->imp_last_reply_time);
	seq_printf(m, "%-10s : %ld, "DHMS_FMT" ago\n",
		   "last reply", imp->imp_last_reply_time, DHMS_VARS(&ts));

	cur = at_get(&imp->imp_at.iat_net_latency);
	worst = imp->imp_at.iat_net_latency.at_worst_ever;
	worstt = imp->imp_at.iat_net_latency.at_worst_time;
	s2dhms(&ts, now - worstt);
	seq_printf(m, "%-10s : cur %3u  worst %3u (at %ld, "DHMS_FMT" ago) ",
		   "network", cur, worst, worstt, DHMS_VARS(&ts));
	lprocfs_seq_at_hist_helper(m, &imp->imp_at.iat_net_latency);

	for(i = 0; i < IMP_AT_MAX_PORTALS; i++) {
		if (imp->imp_at.iat_portal[i] == 0)
			break;
		cur = at_get(&imp->imp_at.iat_service_estimate[i]);
		worst = imp->imp_at.iat_service_estimate[i].at_worst_ever;
		worstt = imp->imp_at.iat_service_estimate[i].at_worst_time;
		s2dhms(&ts, now - worstt);
		seq_printf(m, "portal %-2d  : cur %3u  worst %3u (at %ld, "
			   DHMS_FMT" ago) ", imp->imp_at.iat_portal[i],
			   cur, worst, worstt, DHMS_VARS(&ts));
		lprocfs_seq_at_hist_helper(m, &imp->imp_at.iat_service_estimate[i]);
	}

	LPROCFS_CLIMP_EXIT(obd);
	return 0;
}
EXPORT_SYMBOL(lprocfs_timeouts_seq_show);

int lprocfs_connect_flags_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;
	__u64 flags;

	LPROCFS_CLIMP_CHECK(obd);
	flags = obd->u.cli.cl_import->imp_connect_data.ocd_connect_flags;
	seq_printf(m, "flags="LPX64"\n", flags);
	obd_connect_seq_flags2str(m, flags, "\n");
	seq_printf(m, "\n");
	LPROCFS_CLIMP_EXIT(obd);
	return 0;
}
EXPORT_SYMBOL(lprocfs_connect_flags_seq_show);

int
lprocfs_obd_setup(struct obd_device *obd)
{
	int rc = 0;

	LASSERT(obd != NULL);
	LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
	LASSERT(obd->obd_type->typ_procroot != NULL);

	obd->obd_proc_entry = lprocfs_seq_register(obd->obd_name,
						   obd->obd_type->typ_procroot,
						   obd->obd_vars, obd);
	if (IS_ERR(obd->obd_proc_entry)) {
		rc = PTR_ERR(obd->obd_proc_entry);
		CERROR("error %d setting up lprocfs for %s\n",rc,obd->obd_name);
		obd->obd_proc_entry = NULL;
	}
	return rc;
}
EXPORT_SYMBOL(lprocfs_obd_setup);

int lprocfs_obd_cleanup(struct obd_device *obd)
{
        if (!obd)
                return -EINVAL;
        if (obd->obd_proc_exports_entry) {
                /* Should be no exports left */
                lprocfs_remove(&obd->obd_proc_exports_entry);
                obd->obd_proc_exports_entry = NULL;
        }
        if (obd->obd_proc_entry) {
                lprocfs_remove(&obd->obd_proc_entry);
                obd->obd_proc_entry = NULL;
        }
        return 0;
}
EXPORT_SYMBOL(lprocfs_obd_cleanup);

int lprocfs_stats_alloc_one(struct lprocfs_stats *stats, unsigned int cpuid)
{
	struct lprocfs_counter  *cntr;
	unsigned int            percpusize;
	int                     rc = -ENOMEM;
	unsigned long           flags = 0;
	int                     i;

	LASSERT(stats->ls_percpu[cpuid] == NULL);
	LASSERT((stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU) == 0);

	percpusize = lprocfs_stats_counter_size(stats);
	LIBCFS_ALLOC_ATOMIC(stats->ls_percpu[cpuid], percpusize);
	if (stats->ls_percpu[cpuid] != NULL) {
		rc = 0;
		if (unlikely(stats->ls_biggest_alloc_num <= cpuid)) {
			if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE)
				spin_lock_irqsave(&stats->ls_lock, flags);
			else
				spin_lock(&stats->ls_lock);
			if (stats->ls_biggest_alloc_num <= cpuid)
				stats->ls_biggest_alloc_num = cpuid + 1;
			if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE) {
				spin_unlock_irqrestore(&stats->ls_lock, flags);
			} else {
				spin_unlock(&stats->ls_lock);
			}
		}
		/* initialize the ls_percpu[cpuid] non-zero counter */
		for (i = 0; i < stats->ls_num; ++i) {
			cntr = lprocfs_stats_counter_get(stats, cpuid, i);
			cntr->lc_min = LC_MIN_INIT;
		}
	}
	return rc;
}
EXPORT_SYMBOL(lprocfs_stats_alloc_one);

struct lprocfs_stats *lprocfs_alloc_stats(unsigned int num,
                                          enum lprocfs_stats_flags flags)
{
	struct lprocfs_stats	*stats;
	unsigned int		num_entry;
	unsigned int		percpusize = 0;
	int			i;

        if (num == 0)
                return NULL;

        if (lprocfs_no_percpu_stats != 0)
                flags |= LPROCFS_STATS_FLAG_NOPERCPU;

	if (flags & LPROCFS_STATS_FLAG_NOPERCPU)
		num_entry = 1;
	else
		num_entry = num_possible_cpus();

	/* alloc percpu pointers for all possible cpu slots */
	LIBCFS_ALLOC(stats, offsetof(typeof(*stats), ls_percpu[num_entry]));
	if (stats == NULL)
		return NULL;

	stats->ls_num = num;
	stats->ls_flags = flags;
	spin_lock_init(&stats->ls_lock);

	/* alloc num of counter headers */
	LIBCFS_ALLOC(stats->ls_cnt_header,
		     stats->ls_num * sizeof(struct lprocfs_counter_header));
	if (stats->ls_cnt_header == NULL)
		goto fail;

	if ((flags & LPROCFS_STATS_FLAG_NOPERCPU) != 0) {
		/* contains only one set counters */
		percpusize = lprocfs_stats_counter_size(stats);
		LIBCFS_ALLOC_ATOMIC(stats->ls_percpu[0], percpusize);
		if (stats->ls_percpu[0] == NULL)
			goto fail;
		stats->ls_biggest_alloc_num = 1;
	} else if ((flags & LPROCFS_STATS_FLAG_IRQ_SAFE) != 0) {
		/* alloc all percpu data, currently only obd_memory use this */
		for (i = 0; i < num_entry; ++i)
			if (lprocfs_stats_alloc_one(stats, i) < 0)
				goto fail;
	}

	return stats;

fail:
	lprocfs_free_stats(&stats);
	return NULL;
}
EXPORT_SYMBOL(lprocfs_alloc_stats);

void lprocfs_free_stats(struct lprocfs_stats **statsh)
{
	struct lprocfs_stats *stats = *statsh;
	unsigned int num_entry;
	unsigned int percpusize;
	unsigned int i;

        if (stats == NULL || stats->ls_num == 0)
                return;
        *statsh = NULL;

	if (stats->ls_flags & LPROCFS_STATS_FLAG_NOPERCPU)
		num_entry = 1;
	else
		num_entry = num_possible_cpus();

	percpusize = lprocfs_stats_counter_size(stats);
	for (i = 0; i < num_entry; i++)
		if (stats->ls_percpu[i] != NULL)
			LIBCFS_FREE(stats->ls_percpu[i], percpusize);
	if (stats->ls_cnt_header != NULL)
		LIBCFS_FREE(stats->ls_cnt_header, stats->ls_num *
					sizeof(struct lprocfs_counter_header));
	LIBCFS_FREE(stats, offsetof(typeof(*stats), ls_percpu[num_entry]));
}
EXPORT_SYMBOL(lprocfs_free_stats);

void lprocfs_clear_stats(struct lprocfs_stats *stats)
{
	struct lprocfs_counter		*percpu_cntr;
	int				i;
	int				j;
	unsigned int			num_entry;
	unsigned long			flags = 0;

	num_entry = lprocfs_stats_lock(stats, LPROCFS_GET_NUM_CPU, &flags);

	for (i = 0; i < num_entry; i++) {
		if (stats->ls_percpu[i] == NULL)
			continue;
		for (j = 0; j < stats->ls_num; j++) {
			percpu_cntr = lprocfs_stats_counter_get(stats, i, j);
			percpu_cntr->lc_count		= 0;
			percpu_cntr->lc_min		= LC_MIN_INIT;
			percpu_cntr->lc_max		= 0;
			percpu_cntr->lc_sumsquare	= 0;
			percpu_cntr->lc_sum		= 0;
			if (stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE)
				percpu_cntr->lc_sum_irq	= 0;
		}
	}

	lprocfs_stats_unlock(stats, LPROCFS_GET_NUM_CPU, &flags);
}
EXPORT_SYMBOL(lprocfs_clear_stats);

static ssize_t lprocfs_stats_seq_write(struct file *file,
				       const char __user *buf,
				       size_t len, loff_t *off)
{
        struct seq_file *seq = file->private_data;
        struct lprocfs_stats *stats = seq->private;

        lprocfs_clear_stats(stats);

        return len;
}

static void *lprocfs_stats_seq_start(struct seq_file *p, loff_t *pos)
{
	struct lprocfs_stats *stats = p->private;

	return (*pos < stats->ls_num) ? pos : NULL;
}

static void lprocfs_stats_seq_stop(struct seq_file *p, void *v)
{
}

static void *lprocfs_stats_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	(*pos)++;

	return lprocfs_stats_seq_start(p, pos);
}

/* seq file export of one lprocfs counter */
static int lprocfs_stats_seq_show(struct seq_file *p, void *v)
{
	struct lprocfs_stats		*stats	= p->private;
	struct lprocfs_counter_header	*hdr;
	struct lprocfs_counter		 ctr;
	int				 idx	= *(loff_t *)v;
	int				 rc	= 0;

	if (idx == 0) {
		struct timeval now;

		do_gettimeofday(&now);
		rc = seq_printf(p, "%-25s %lu.%lu secs.usecs\n",
				"snapshot_time", now.tv_sec, now.tv_usec);
		if (rc < 0)
			return rc;
	}

	hdr = &stats->ls_cnt_header[idx];
	lprocfs_stats_collect(stats, idx, &ctr);

	if (ctr.lc_count == 0)
		goto out;

	rc = seq_printf(p, "%-25s "LPD64" samples [%s]", hdr->lc_name,
			ctr.lc_count, hdr->lc_units);
	if (rc < 0)
		goto out;

	if ((hdr->lc_config & LPROCFS_CNTR_AVGMINMAX) && ctr.lc_count > 0) {
		rc = seq_printf(p, " "LPD64" "LPD64" "LPD64,
				ctr.lc_min, ctr.lc_max, ctr.lc_sum);
		if (rc < 0)
			goto out;
		if (hdr->lc_config & LPROCFS_CNTR_STDDEV)
			rc = seq_printf(p, " "LPD64, ctr.lc_sumsquare);
		if (rc < 0)
			goto out;
	}
	rc = seq_printf(p, "\n");
out:
	return (rc < 0) ? rc : 0;
}

struct seq_operations lprocfs_stats_seq_sops = {
	.start	= lprocfs_stats_seq_start,
	.stop	= lprocfs_stats_seq_stop,
	.next	= lprocfs_stats_seq_next,
	.show	= lprocfs_stats_seq_show,
};

static int lprocfs_stats_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

#ifndef HAVE_ONLY_PROCFS_SEQ
	if (LPROCFS_ENTRY_CHECK(PDE(inode)))
		return -ENOENT;
#endif
	rc = seq_open(file, &lprocfs_stats_seq_sops);
	if (rc)
		return rc;
	seq = file->private_data;
	seq->private = PDE_DATA(inode);
	return 0;
}

struct file_operations lprocfs_stats_seq_fops = {
        .owner   = THIS_MODULE,
        .open    = lprocfs_stats_seq_open,
        .read    = seq_read,
        .write   = lprocfs_stats_seq_write,
        .llseek  = seq_lseek,
        .release = lprocfs_seq_release,
};

int lprocfs_register_stats(struct proc_dir_entry *root, const char *name,
                           struct lprocfs_stats *stats)
{
	struct proc_dir_entry *entry;
	LASSERT(root != NULL);

	entry = proc_create_data(name, 0644, root,
				 &lprocfs_stats_seq_fops, stats);
	if (entry == NULL)
		return -ENOMEM;
	return 0;
}
EXPORT_SYMBOL(lprocfs_register_stats);

void lprocfs_counter_init(struct lprocfs_stats *stats, int index,
			  unsigned conf, const char *name, const char *units)
{
	struct lprocfs_counter_header	*header;
	struct lprocfs_counter		*percpu_cntr;
	unsigned long			flags = 0;
	unsigned int			i;
	unsigned int			num_cpu;

	LASSERT(stats != NULL);

	header = &stats->ls_cnt_header[index];
	LASSERTF(header != NULL, "Failed to allocate stats header:[%d]%s/%s\n",
		 index, name, units);

	header->lc_config = conf;
	header->lc_name   = name;
	header->lc_units  = units;

	num_cpu = lprocfs_stats_lock(stats, LPROCFS_GET_NUM_CPU, &flags);
	for (i = 0; i < num_cpu; ++i) {
		if (stats->ls_percpu[i] == NULL)
			continue;
		percpu_cntr = lprocfs_stats_counter_get(stats, i, index);
		percpu_cntr->lc_count		= 0;
		percpu_cntr->lc_min		= LC_MIN_INIT;
		percpu_cntr->lc_max		= 0;
		percpu_cntr->lc_sumsquare	= 0;
		percpu_cntr->lc_sum		= 0;
		if ((stats->ls_flags & LPROCFS_STATS_FLAG_IRQ_SAFE) != 0)
			percpu_cntr->lc_sum_irq	= 0;
	}
	lprocfs_stats_unlock(stats, LPROCFS_GET_NUM_CPU, &flags);
}
EXPORT_SYMBOL(lprocfs_counter_init);

/* Note that we only init md counters for ops whose offset is less
 * than NUM_MD_STATS. This is explained in a comment in the definition
 * of struct md_ops. */
#define LPROCFS_MD_OP_INIT(base, stats, op)				       \
	do {								       \
		unsigned int _idx = base + MD_COUNTER_OFFSET(op);	       \
									       \
		if (MD_COUNTER_OFFSET(op) < NUM_MD_STATS) {		       \
			LASSERT(_idx < stats->ls_num);			       \
			lprocfs_counter_init(stats, _idx, 0, #op, "reqs");     \
		}							       \
	} while (0)

void lprocfs_init_mps_stats(int num_private_stats, struct lprocfs_stats *stats)
{
        LPROCFS_MD_OP_INIT(num_private_stats, stats, getstatus);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, null_inode);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, find_cbdata);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, close);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, create);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, done_writing);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, enqueue);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, getattr);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, getattr_name);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, intent_lock);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, link);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, rename);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, setattr);
	LPROCFS_MD_OP_INIT(num_private_stats, stats, fsync);
	LPROCFS_MD_OP_INIT(num_private_stats, stats, read_page);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, unlink);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, setxattr);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, getxattr);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, init_ea_size);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, get_lustre_md);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, free_lustre_md);
	LPROCFS_MD_OP_INIT(num_private_stats, stats, update_lsm_md);
	LPROCFS_MD_OP_INIT(num_private_stats, stats, merge_attr);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, set_open_replay_data);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, clear_open_replay_data);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, set_lock_data);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, lock_match);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, cancel_unused);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, renew_capa);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, unpack_capa);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, get_remote_perm);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, intent_getattr_async);
        LPROCFS_MD_OP_INIT(num_private_stats, stats, revalidate_lock);
}
EXPORT_SYMBOL(lprocfs_init_mps_stats);

int lprocfs_alloc_md_stats(struct obd_device *obd,
			   unsigned int num_private_stats)
{
	struct lprocfs_stats *stats;
	unsigned int num_stats;
	int rc, i;

	CLASSERT(offsetof(struct md_ops, MD_STATS_FIRST_OP) == 0);
	CLASSERT(_MD_COUNTER_OFFSET(MD_STATS_FIRST_OP) == 0);
	CLASSERT(_MD_COUNTER_OFFSET(MD_STATS_LAST_OP) > 0);

	/* TODO Ensure that this function is only used where
	 * appropriate by adding an assertion to the effect that
	 * obd->obd_type->typ_md_ops is not NULL. We can't do this now
	 * because mdt_procfs_init() uses this function to allocate
	 * the stats backing /proc/fs/lustre/mdt/.../md_stats but the
	 * mdt layer does not use the md_ops interface. This is
	 * confusing and a waste of memory. See LU-2484.
	 */
	LASSERT(obd->obd_proc_entry != NULL);
	LASSERT(obd->obd_md_stats == NULL);
	LASSERT(obd->obd_md_cntr_base == 0);

	num_stats = NUM_MD_STATS + num_private_stats;
	stats = lprocfs_alloc_stats(num_stats, 0);
	if (stats == NULL)
		return -ENOMEM;

	lprocfs_init_mps_stats(num_private_stats, stats);

	for (i = num_private_stats; i < num_stats; i++) {
		if (stats->ls_cnt_header[i].lc_name == NULL) {
			CERROR("Missing md_stat initializer md_op "
			       "operation at offset %d. Aborting.\n",
			       i - num_private_stats);
			LBUG();
		}
	}

	rc = lprocfs_register_stats(obd->obd_proc_entry, "md_stats", stats);
	if (rc < 0) {
		lprocfs_free_stats(&stats);
	} else {
		obd->obd_md_stats = stats;
		obd->obd_md_cntr_base = num_private_stats;
	}

	return rc;
}
EXPORT_SYMBOL(lprocfs_alloc_md_stats);

void lprocfs_free_md_stats(struct obd_device *obd)
{
	struct lprocfs_stats *stats = obd->obd_md_stats;

	if (stats != NULL) {
		obd->obd_md_stats = NULL;
		obd->obd_md_cntr_base = 0;
		lprocfs_free_stats(&stats);
	}
}
EXPORT_SYMBOL(lprocfs_free_md_stats);

void lprocfs_init_ldlm_stats(struct lprocfs_stats *ldlm_stats)
{
        lprocfs_counter_init(ldlm_stats,
                             LDLM_ENQUEUE - LDLM_FIRST_OPC,
                             0, "ldlm_enqueue", "reqs");
        lprocfs_counter_init(ldlm_stats,
                             LDLM_CONVERT - LDLM_FIRST_OPC,
                             0, "ldlm_convert", "reqs");
        lprocfs_counter_init(ldlm_stats,
                             LDLM_CANCEL - LDLM_FIRST_OPC,
                             0, "ldlm_cancel", "reqs");
        lprocfs_counter_init(ldlm_stats,
                             LDLM_BL_CALLBACK - LDLM_FIRST_OPC,
                             0, "ldlm_bl_callback", "reqs");
        lprocfs_counter_init(ldlm_stats,
                             LDLM_CP_CALLBACK - LDLM_FIRST_OPC,
                             0, "ldlm_cp_callback", "reqs");
        lprocfs_counter_init(ldlm_stats,
                             LDLM_GL_CALLBACK - LDLM_FIRST_OPC,
                             0, "ldlm_gl_callback", "reqs");
}
EXPORT_SYMBOL(lprocfs_init_ldlm_stats);

__s64 lprocfs_read_helper(struct lprocfs_counter *lc,
			  struct lprocfs_counter_header *header,
			  enum lprocfs_stats_flags flags,
			  enum lprocfs_fields_flags field)
{
	__s64 ret = 0;

	if (lc == NULL || header == NULL)
		RETURN(0);

	switch (field) {
		case LPROCFS_FIELDS_FLAGS_CONFIG:
			ret = header->lc_config;
			break;
		case LPROCFS_FIELDS_FLAGS_SUM:
			ret = lc->lc_sum;
			if ((flags & LPROCFS_STATS_FLAG_IRQ_SAFE) != 0)
				ret += lc->lc_sum_irq;
			break;
		case LPROCFS_FIELDS_FLAGS_MIN:
			ret = lc->lc_min;
			break;
		case LPROCFS_FIELDS_FLAGS_MAX:
			ret = lc->lc_max;
			break;
		case LPROCFS_FIELDS_FLAGS_AVG:
			ret = (lc->lc_max - lc->lc_min) / 2;
			break;
		case LPROCFS_FIELDS_FLAGS_SUMSQUARE:
			ret = lc->lc_sumsquare;
			break;
		case LPROCFS_FIELDS_FLAGS_COUNT:
			ret = lc->lc_count;
			break;
		default:
			break;
	};
	RETURN(ret);
}
EXPORT_SYMBOL(lprocfs_read_helper);

int lprocfs_write_helper(const char __user *buffer, unsigned long count,
                         int *val)
{
        return lprocfs_write_frac_helper(buffer, count, val, 1);
}
EXPORT_SYMBOL(lprocfs_write_helper);

int lprocfs_write_frac_helper(const char __user *buffer, unsigned long count,
                              int *val, int mult)
{
        char kernbuf[20], *end, *pbuf;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';
        pbuf = kernbuf;
        if (*pbuf == '-') {
                mult = -mult;
                pbuf++;
        }

        *val = (int)simple_strtoul(pbuf, &end, 10) * mult;
        if (pbuf == end)
                return -EINVAL;

        if (end != NULL && *end == '.') {
                int temp_val, pow = 1;
                int i;

                pbuf = end + 1;
                if (strlen(pbuf) > 5)
                        pbuf[5] = '\0'; /*only allow 5bits fractional*/

                temp_val = (int)simple_strtoul(pbuf, &end, 10) * mult;

                if (pbuf < end) {
                        for (i = 0; i < (end - pbuf); i++)
                                pow *= 10;

                        *val += temp_val / pow;
                }
        }
        return 0;
}
EXPORT_SYMBOL(lprocfs_write_frac_helper);

int lprocfs_read_frac_helper(char *buffer, unsigned long count, long val,
                             int mult)
{
        long decimal_val, frac_val;
        int prtn;

        if (count < 10)
                return -EINVAL;

        decimal_val = val / mult;
        prtn = snprintf(buffer, count, "%ld", decimal_val);
        frac_val = val % mult;

        if (prtn < (count - 4) && frac_val > 0) {
                long temp_frac;
                int i, temp_mult = 1, frac_bits = 0;

                temp_frac = frac_val * 10;
                buffer[prtn++] = '.';
                while (frac_bits < 2 && (temp_frac / mult) < 1 ) {
                        /* only reserved 2 bits fraction */
                        buffer[prtn++] ='0';
                        temp_frac *= 10;
                        frac_bits++;
                }
                /*
                 * Need to think these cases :
                 *      1. #echo x.00 > /proc/xxx       output result : x
                 *      2. #echo x.0x > /proc/xxx       output result : x.0x
                 *      3. #echo x.x0 > /proc/xxx       output result : x.x
                 *      4. #echo x.xx > /proc/xxx       output result : x.xx
                 *      Only reserved 2 bits fraction.
                 */
                for (i = 0; i < (5 - prtn); i++)
                        temp_mult *= 10;

                frac_bits = min((int)count - prtn, 3 - frac_bits);
                prtn += snprintf(buffer + prtn, frac_bits, "%ld",
                                 frac_val * temp_mult / mult);

                prtn--;
                while(buffer[prtn] < '1' || buffer[prtn] > '9') {
                        prtn--;
                        if (buffer[prtn] == '.') {
                                prtn--;
                                break;
                        }
                }
                prtn++;
        }
        buffer[prtn++] ='\n';
        return prtn;
}
EXPORT_SYMBOL(lprocfs_read_frac_helper);

int lprocfs_seq_read_frac_helper(struct seq_file *m, long val, int mult)
{
	long decimal_val, frac_val;

	decimal_val = val / mult;
	seq_printf(m, "%ld", decimal_val);
	frac_val = val % mult;

	if (frac_val > 0) {
		frac_val *= 100;
		frac_val /= mult;
	}
	if (frac_val > 0) {
		/* Three cases: x0, xx, 0x */
		if ((frac_val % 10) != 0)
			seq_printf(m, ".%ld", frac_val);
		else
			seq_printf(m, ".%ld", frac_val / 10);
	}

	seq_printf(m, "\n");
	return 0;
}
EXPORT_SYMBOL(lprocfs_seq_read_frac_helper);

int lprocfs_write_u64_helper(const char __user *buffer, unsigned long count,
			     __u64 *val)
{
        return lprocfs_write_frac_u64_helper(buffer, count, val, 1);
}
EXPORT_SYMBOL(lprocfs_write_u64_helper);

int lprocfs_write_frac_u64_helper(const char __user *buffer,
				  unsigned long count,
				  __u64 *val, int mult)
{
        char kernbuf[22], *end, *pbuf;
        __u64 whole, frac = 0, units;
        unsigned frac_d = 1;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';
        pbuf = kernbuf;
        if (*pbuf == '-') {
                mult = -mult;
                pbuf++;
        }

        whole = simple_strtoull(pbuf, &end, 10);
        if (pbuf == end)
                return -EINVAL;

        if (end != NULL && *end == '.') {
                int i;
                pbuf = end + 1;

                /* need to limit frac_d to a __u32 */
                if (strlen(pbuf) > 10)
                        pbuf[10] = '\0';

                frac = simple_strtoull(pbuf, &end, 10);
                /* count decimal places */
                for (i = 0; i < (end - pbuf); i++)
                        frac_d *= 10;
        }

        units = 1;
	if (end != NULL) {
		switch (*end) {
		case 'p': case 'P':
			units <<= 10;
		case 't': case 'T':
			units <<= 10;
		case 'g': case 'G':
			units <<= 10;
		case 'm': case 'M':
			units <<= 10;
		case 'k': case 'K':
			units <<= 10;
		}
	}
        /* Specified units override the multiplier */
	if (units > 1)
                mult = mult < 0 ? -units : units;

        frac *= mult;
        do_div(frac, frac_d);
        *val = whole * mult + frac;
        return 0;
}
EXPORT_SYMBOL(lprocfs_write_frac_u64_helper);

static char *lprocfs_strnstr(const char *s1, const char *s2, size_t len)
{
	size_t l2;

	l2 = strlen(s2);
	if (!l2)
		return (char *)s1;
	while (len >= l2) {
		len--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}

/**
 * Find the string \a name in the input \a buffer, and return a pointer to the
 * value immediately following \a name, reducing \a count appropriately.
 * If \a name is not found the original \a buffer is returned.
 */
char *lprocfs_find_named_value(const char *buffer, const char *name,
				size_t *count)
{
	char *val;
	size_t buflen = *count;

	/* there is no strnstr() in rhel5 and ubuntu kernels */
	val = lprocfs_strnstr(buffer, name, buflen);
	if (val == NULL)
		return (char *)buffer;

	val += strlen(name);                             /* skip prefix */
	while (val < buffer + buflen && isspace(*val)) /* skip separator */
		val++;

	*count = 0;
	while (val < buffer + buflen && isalnum(*val)) {
		++*count;
		++val;
	}

	return val - *count;
}
EXPORT_SYMBOL(lprocfs_find_named_value);

int lprocfs_seq_create(struct proc_dir_entry *parent,
		       const char *name,
		       mode_t mode,
		       const struct file_operations *seq_fops,
		       void *data)
{
	struct proc_dir_entry *entry;
	ENTRY;

	/* Disallow secretly (un)writable entries. */
	LASSERT((seq_fops->write == NULL) == ((mode & 0222) == 0));

	entry = proc_create_data(name, mode, parent, seq_fops, data);

	if (entry == NULL)
		RETURN(-ENOMEM);

	RETURN(0);
}
EXPORT_SYMBOL(lprocfs_seq_create);

int lprocfs_obd_seq_create(struct obd_device *dev,
			   const char *name,
			   mode_t mode,
			   const struct file_operations *seq_fops,
			   void *data)
{
        return (lprocfs_seq_create(dev->obd_proc_entry, name,
                                   mode, seq_fops, data));
}
EXPORT_SYMBOL(lprocfs_obd_seq_create);

void lprocfs_oh_tally(struct obd_histogram *oh, unsigned int value)
{
	if (value >= OBD_HIST_MAX)
		value = OBD_HIST_MAX - 1;

	spin_lock(&oh->oh_lock);
	oh->oh_buckets[value]++;
	spin_unlock(&oh->oh_lock);
}
EXPORT_SYMBOL(lprocfs_oh_tally);

void lprocfs_oh_tally_log2(struct obd_histogram *oh, unsigned int value)
{
	unsigned int val = 0;

	if (likely(value != 0))
		val = min(fls(value - 1), OBD_HIST_MAX);

	lprocfs_oh_tally(oh, val);
}
EXPORT_SYMBOL(lprocfs_oh_tally_log2);

unsigned long lprocfs_oh_sum(struct obd_histogram *oh)
{
        unsigned long ret = 0;
        int i;

        for (i = 0; i < OBD_HIST_MAX; i++)
                ret +=  oh->oh_buckets[i];
        return ret;
}
EXPORT_SYMBOL(lprocfs_oh_sum);

void lprocfs_oh_clear(struct obd_histogram *oh)
{
	spin_lock(&oh->oh_lock);
	memset(oh->oh_buckets, 0, sizeof(oh->oh_buckets));
	spin_unlock(&oh->oh_lock);
}
EXPORT_SYMBOL(lprocfs_oh_clear);

int lprocfs_obd_rd_max_pages_per_rpc(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	struct obd_device *dev = data;
	struct client_obd *cli = &dev->u.cli;
	int rc;

	spin_lock(&cli->cl_loi_list_lock);
	rc = snprintf(page, count, "%d\n", cli->cl_max_pages_per_rpc);
	spin_unlock(&cli->cl_loi_list_lock);

	return rc;
}
EXPORT_SYMBOL(lprocfs_obd_rd_max_pages_per_rpc);

int lprocfs_obd_max_pages_per_rpc_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *dev = data;
	struct client_obd *cli = &dev->u.cli;
	int rc;

	spin_lock(&cli->cl_loi_list_lock);
	rc = seq_printf(m, "%d\n", cli->cl_max_pages_per_rpc);
	spin_unlock(&cli->cl_loi_list_lock);
	return rc;
}
EXPORT_SYMBOL(lprocfs_obd_max_pages_per_rpc_seq_show);

int lprocfs_wr_root_squash(const char __user *buffer, unsigned long count,
			   struct root_squash_info *squash, char *name)
{
	int rc;
	char kernbuf[64], *tmp, *errmsg;
	unsigned long uid, gid;
	ENTRY;

	if (count >= sizeof(kernbuf)) {
		errmsg = "string too long";
		GOTO(failed_noprint, rc = -EINVAL);
	}
	if (copy_from_user(kernbuf, buffer, count)) {
		errmsg = "bad address";
		GOTO(failed_noprint, rc = -EFAULT);
	}
	kernbuf[count] = '\0';

	/* look for uid gid separator */
	tmp = strchr(kernbuf, ':');
	if (tmp == NULL) {
		errmsg = "needs uid:gid format";
		GOTO(failed, rc = -EINVAL);
	}
	*tmp = '\0';
	tmp++;

	/* parse uid */
	if (kstrtoul(kernbuf, 0, &uid) != 0) {
		errmsg = "bad uid";
		GOTO(failed, rc = -EINVAL);
	}

	/* parse gid */
	if (kstrtoul(tmp, 0, &gid) != 0) {
		errmsg = "bad gid";
		GOTO(failed, rc = -EINVAL);
	}

	squash->rsi_uid = uid;
	squash->rsi_gid = gid;

	LCONSOLE_INFO("%s: root_squash is set to %u:%u\n",
		      name, squash->rsi_uid, squash->rsi_gid);
	RETURN(count);

failed:
	if (tmp != NULL) {
		tmp--;
		*tmp = ':';
	}
	CWARN("%s: failed to set root_squash to \"%s\", %s, rc = %d\n",
	      name, kernbuf, errmsg, rc);
	RETURN(rc);
failed_noprint:
	CWARN("%s: failed to set root_squash due to %s, rc = %d\n",
	      name, errmsg, rc);
	RETURN(rc);
}
EXPORT_SYMBOL(lprocfs_wr_root_squash);


int lprocfs_wr_nosquash_nids(const char __user *buffer, unsigned long count,
			     struct root_squash_info *squash, char *name)
{
	int rc;
	char *kernbuf = NULL;
	char *errmsg;
	struct list_head tmp;
	ENTRY;

	if (count > 4096) {
		errmsg = "string too long";
		GOTO(failed, rc = -EINVAL);
	}

	OBD_ALLOC(kernbuf, count + 1);
	if (kernbuf == NULL) {
		errmsg = "no memory";
		GOTO(failed, rc = -ENOMEM);
	}
	if (copy_from_user(kernbuf, buffer, count)) {
		errmsg = "bad address";
		GOTO(failed, rc = -EFAULT);
	}
	kernbuf[count] = '\0';

	if (count > 0 && kernbuf[count - 1] == '\n')
		kernbuf[count - 1] = '\0';

	if (strcmp(kernbuf, "NONE") == 0 || strcmp(kernbuf, "clear") == 0) {
		/* empty string is special case */
		down_write(&squash->rsi_sem);
		if (!list_empty(&squash->rsi_nosquash_nids))
			cfs_free_nidlist(&squash->rsi_nosquash_nids);
		up_write(&squash->rsi_sem);
		LCONSOLE_INFO("%s: nosquash_nids is cleared\n", name);
		OBD_FREE(kernbuf, count + 1);
		RETURN(count);
	}

	INIT_LIST_HEAD(&tmp);
	if (cfs_parse_nidlist(kernbuf, count, &tmp) <= 0) {
		errmsg = "can't parse";
		GOTO(failed, rc = -EINVAL);
	}
	LCONSOLE_INFO("%s: nosquash_nids set to %s\n",
		      name, kernbuf);
	OBD_FREE(kernbuf, count + 1);
	kernbuf = NULL;

	down_write(&squash->rsi_sem);
	if (!list_empty(&squash->rsi_nosquash_nids))
		cfs_free_nidlist(&squash->rsi_nosquash_nids);
	list_splice(&tmp, &squash->rsi_nosquash_nids);
	up_write(&squash->rsi_sem);

	RETURN(count);

failed:
	if (kernbuf) {
		CWARN("%s: failed to set nosquash_nids to \"%s\", %s rc = %d\n",
		      name, kernbuf, errmsg, rc);
		OBD_FREE(kernbuf, count + 1);
	} else {
		CWARN("%s: failed to set nosquash_nids due to %s rc = %d\n",
		      name, errmsg, rc);
	}
	RETURN(rc);
}
EXPORT_SYMBOL(lprocfs_wr_nosquash_nids);

#endif /* LPROCFS*/
