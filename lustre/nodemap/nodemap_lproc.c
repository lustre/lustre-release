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
 * Copyright (C) 2013, Trustees of Indiana University
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#define NODEMAP_LPROC_ID_LEN 16
#define NODEMAP_LPROC_FLAG_LEN 2

#include <lprocfs_status.h>
#include <lustre_net.h>
#include <interval_tree.h>
#include "nodemap_internal.h"

static int nodemap_idmap_show(struct seq_file *m, void *data)
{
	struct lu_nodemap	*nodemap = m->private;
	struct lu_idmap		*idmap;
	struct rb_node		*node;
	bool			cont = 0;

	seq_printf(m, "[\n");
	for (node = rb_first(&nodemap->nm_client_to_fs_uidmap); node;
				node = rb_next(node)) {
		if (cont)
			seq_printf(m, ",\n");
		cont = 1;
		idmap = rb_entry(node, struct lu_idmap, id_client_to_fs);
		if (idmap != NULL)
			seq_printf(m, " { idtype: uid, client_id: %u, "
				   "fs_id: %u }", idmap->id_client,
				   idmap->id_fs);
	}
	for (node = rb_first(&nodemap->nm_client_to_fs_gidmap);
				node; node = rb_next(node)) {
		if (cont)
			seq_printf(m, ",\n");
		idmap = rb_entry(node, struct lu_idmap, id_client_to_fs);
		if (idmap != NULL)
			seq_printf(m, " { idtype: gid, client_id: %u, "
				   "fs_id: %u }", idmap->id_client,
				   idmap->id_fs);
	}
	seq_printf(m, "\n");
	seq_printf(m, "]\n");

	return 0;
}

static int nodemap_idmap_open(struct inode *inode, struct file *file)
{
	struct lu_nodemap *nodemap = PDE_DATA(inode);

	return single_open(file, nodemap_idmap_show, nodemap);
}

static int nodemap_ranges_show(struct seq_file *m, void *data)
{
	struct lu_nodemap		*nodemap = m->private;
	struct lu_nid_range		*range;
	struct interval_node_extent	ext;
	bool				cont = 0;

	seq_printf(m, "[\n");
	list_for_each_entry(range, &nodemap->nm_ranges, rn_list) {
		if (cont)
			seq_printf(m, ",\n");
		cont = 1;
		ext = range->rn_node.in_extent;
		seq_printf(m, " { id: %u, start_nid: %s, "
				"end_nid: %s }",
			   range->rn_id, libcfs_nid2str(ext.start),
			   libcfs_nid2str(ext.end));
	}
	seq_printf(m, "\n");
	seq_printf(m, "]\n");

	return 0;
}

static int nodemap_ranges_open(struct inode *inode, struct file *file)
{
	struct lu_nodemap *nodemap = PDE_DATA(inode);

	return single_open(file, nodemap_ranges_show, nodemap);
}

static int nodemap_active_seq_show(struct seq_file *m, void *data)
{
	return seq_printf(m, "%u\n", (unsigned int)nodemap_active);
}

static ssize_t
nodemap_active_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off)
{
	char	active_string[NODEMAP_LPROC_FLAG_LEN + 1];
	__u32	active;
	int	rc = count;

	if (count == 0)
		return 0;

	if (count > NODEMAP_LPROC_FLAG_LEN)
		return -EINVAL;

	if (copy_from_user(active_string, buffer, count))
		return -EFAULT;

	active_string[count] = '\0';
	active = simple_strtoul(active_string, NULL, 10);
	nodemap_active = active;

	return rc;
}
LPROC_SEQ_FOPS(nodemap_active);

static int nodemap_id_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%u\n", nodemap->nm_id);
}
LPROC_SEQ_FOPS_RO(nodemap_id);

static int nodemap_squash_uid_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%u\n", nodemap->nm_squash_uid);
}

static int nodemap_squash_gid_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%u\n", nodemap->nm_squash_gid);
}

static int nodemap_trusted_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%d\n", (int)nodemap->nmf_trust_client_ids);
}

static int nodemap_admin_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%d\n", (int)nodemap->nmf_allow_root_access);
}

#ifdef NODEMAP_PROC_DEBUG
static int nodemap_proc_read_flag(const char __user *buffer,
				  unsigned long count, unsigned int *flag_p)
{
	char scratch[NODEMAP_LPROC_FLAG_LEN + 1];

	if (count == 0)
		return 0;

	if (count > NODEMAP_LPROC_FLAG_LEN)
		return -EINVAL;

	if (copy_from_user(scratch, buffer, count))
		return -EFAULT;

	scratch[count] = '\0';
	*flag_p = simple_strtoul(scratch, NULL, 10);

	return 0;
}

static ssize_t
nodemap_squash_uid_seq_write(struct file *file, const char __user *buffer,
			     size_t count, loff_t *off)
{
	char			squash[NODEMAP_LPROC_ID_LEN + 1];
	struct seq_file		*m = file->private_data;
	struct lu_nodemap	*nodemap = m->private;
	uid_t			squash_uid;
	int			rc = count;

	if (count == 0)
		return 0;

	if (count > NODEMAP_LPROC_FLAG_LEN)
		return -EINVAL;

	if (copy_from_user(squash, buffer, count))
		return -EFAULT;

	squash[count] = '\0';
	squash_uid = simple_strtoul(squash, NULL, 10);
	nodemap->nm_squash_uid = squash_uid;

	return rc;
}

static ssize_t
nodemap_squash_gid_seq_write(struct file *file, const char __user *buffer,
			     size_t count, loff_t *off)
{
	char			squash[NODEMAP_LPROC_ID_LEN + 1];
	struct seq_file		*m = file->private_data;
	struct lu_nodemap	*nodemap = m->private;
	gid_t			squash_gid;
	int			rc = count;

	if (count == 0)
		return 0;

	if (count > NODEMAP_LPROC_FLAG_LEN)
		return -EINVAL;

	if (copy_from_user(squash, buffer, count))
		return -EFAULT;

	squash[count] = '\0';
	squash_gid = simple_strtoul(squash, NULL, 10);
	nodemap->nm_squash_gid = squash_gid;

	return rc;
}

static ssize_t
nodemap_trusted_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct lu_nodemap	*nodemap = m->private;
	int			flags;
	int			rc;

	rc = nodemap_proc_read_flag(buffer, count, &flags);
	if (rc == 0)
		nodemap->nmf_trust_client_ids = !!flags;

	return rc;
}

static ssize_t
nodemap_admin_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct lu_nodemap	*nodemap = m->private;
	int			flags;
	int			rc;

	rc = nodemap_proc_read_flag(buffer, count, &flags);
	if (rc == 0)
		nodemap->nmf_allow_root_access = !!flags;

	return rc;
}

static ssize_t
lprocfs_add_nodemap_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	char	buf[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	char	*cpybuf = NULL;
	char	*name;
	char	*pos;
	int	rc = count;

	if (count == 0)
		return 0;

	if (count > LUSTRE_NODEMAP_NAME_LENGTH)
		return -EINVAL;

	if (copy_from_user(buf, buffer, count))
		return -EFAULT;

	buf[count] = '\0';
	pos = strchr(buf, '\n');
	if (pos != NULL)
		*pos = '\0';

	cpybuf = buf;
	name = strsep(&cpybuf, " ");
	if (name == NULL)
		return -EINVAL;

	rc = nodemap_add(name);
	if (rc == 0)
		rc = count;

	return rc;
}
LPROC_SEQ_FOPS_WO_TYPE(nodemap, add_nodemap);

static ssize_t
lprocfs_del_nodemap_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	char	buf[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	char	*cpybuf = NULL;
	char	*name;
	char	*pos;
	int	rc = count;

	if (count == 0)
		return 0;

	if (count > LUSTRE_NODEMAP_NAME_LENGTH)
		return -EINVAL;

	if (copy_from_user(buf, buffer, count))
		return -EFAULT;

	buf[count] = '\0';
	pos = strchr(buf, '\n');
	if (pos != NULL)
		*pos = '\0';

	cpybuf = buf;
	name = strsep(&cpybuf, " ");
	if (name == NULL)
		return -EINVAL;

	rc = nodemap_del(name);
	if (rc == 0)
		rc = count;

	return rc;

}
LPROC_SEQ_FOPS_WO_TYPE(nodemap, del_nodemap);

#endif /* NODEMAP_PROC_DEBUG */

static struct lprocfs_seq_vars lprocfs_nodemap_module_vars[] = {
	{
		.name		= "active",
		.fops		= &nodemap_active_fops,
	},
#ifdef NODEMAP_PROC_DEBUG
	{
		.name		= "add_nodemap",
		.fops		= &nodemap_add_nodemap_fops,
	},
	{
		.name		= "remove_nodemap",
		.fops		= &nodemap_del_nodemap_fops,
	},
#endif /* NODEMAP_PROC_DEBUG */
	{
		NULL
	}
};

#ifdef NODEMAP_PROC_DEBUG
LPROC_SEQ_FOPS(nodemap_trusted);
LPROC_SEQ_FOPS(nodemap_admin);
LPROC_SEQ_FOPS(nodemap_squash_uid);
LPROC_SEQ_FOPS(nodemap_squash_gid);
#else
LPROC_SEQ_FOPS_RO(nodemap_trusted);
LPROC_SEQ_FOPS_RO(nodemap_admin);
LPROC_SEQ_FOPS_RO(nodemap_squash_uid);
LPROC_SEQ_FOPS_RO(nodemap_squash_gid);
#endif

const struct file_operations nodemap_ranges_fops = {
	.open			= nodemap_ranges_open,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= single_release
};

const struct file_operations nodemap_idmap_fops = {
	.open			= nodemap_idmap_open,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= single_release
};

static struct lprocfs_seq_vars lprocfs_nodemap_vars[] = {
	{
		.name		= "id",
		.fops		= &nodemap_id_fops,
	},
	{
		.name		= "trusted_nodemap",
		.fops		= &nodemap_trusted_fops,
	},
	{
		.name		= "admin_nodemap",
		.fops		= &nodemap_admin_fops,
	},
	{
		.name		= "squash_uid",
		.fops		= &nodemap_squash_uid_fops,
	},
	{
		.name		= "squash_gid",
		.fops		= &nodemap_squash_gid_fops,
	},
	{
		.name		= "ranges",
		.fops		= &nodemap_ranges_fops,
	},
	{
		.name		= "idmap",
		.fops		= &nodemap_idmap_fops,
	},
	{
		NULL
	}
};

static struct lprocfs_seq_vars lprocfs_default_nodemap_vars[] = {
	{
		.name		= "id",
		.fops		= &nodemap_id_fops,
	},
	{
		.name		= "trusted_nodemap",
		.fops		= &nodemap_trusted_fops,
	},
	{
		.name		= "admin_nodemap",
		.fops		= &nodemap_admin_fops,
	},
	{
		.name		= "squash_uid",
		.fops		= &nodemap_squash_uid_fops,
	},
	{
		.name		= "squash_gid",
		.fops		= &nodemap_squash_gid_fops,
	},
	{
		NULL
	}
};

int nodemap_procfs_init(void)
{
	int rc = 0;

	proc_lustre_nodemap_root = lprocfs_seq_register(LUSTRE_NODEMAP_NAME,
							proc_lustre_root,
							lprocfs_nodemap_module_vars,
							NULL);

	if (IS_ERR(proc_lustre_nodemap_root)) {
		rc = PTR_ERR(proc_lustre_nodemap_root);
		CERROR("cannot create 'nodemap' directory: rc = %d\n",
		       rc);
		proc_lustre_nodemap_root = NULL;
	}

	return rc;
}

/**
 * Register the proc directory for a nodemap
 *
 * \param	name		name of nodemap
 * \param	is_default:	1 if default nodemap
 * \retval	0		success
 */
int lprocfs_nodemap_register(const char *name,
			     bool is_default,
			     struct lu_nodemap *nodemap)
{
	struct proc_dir_entry	*nodemap_proc_entry;
	int			rc = 0;

	if (is_default)
		nodemap_proc_entry =
			lprocfs_seq_register(name,
					 proc_lustre_nodemap_root,
					 lprocfs_default_nodemap_vars,
					 nodemap);
	else
		nodemap_proc_entry = lprocfs_seq_register(name,
							  proc_lustre_nodemap_root,
							  lprocfs_nodemap_vars,
							  nodemap);

	if (IS_ERR(nodemap_proc_entry)) {
		rc = PTR_ERR(nodemap_proc_entry);
		CERROR("cannot create 'nodemap/%s': rc = %d\n", name, rc);
		nodemap_proc_entry = NULL;
	}

	nodemap->nm_proc_entry = nodemap_proc_entry;

	return rc;
}
