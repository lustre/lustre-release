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
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#define NODEMAP_LPROC_ID_LEN 16
#define NODEMAP_LPROC_FLAG_LEN 2

#include <lprocfs_status.h>
#include <lustre_net.h>
#include <lustre_export.h>
#include <obd_class.h>
#include <interval_tree.h>
#include "nodemap_internal.h"

/* Turn on proc debug interface to allow OSS and
 * MDS nodes to configure nodemap independently of
 * MGS (since the nodemap distribution is not written
 * yet */
#define NODEMAP_PROC_DEBUG 1

/**
 * Reads and prints the idmap for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_idmap_show(struct seq_file *m, void *data)
{
	struct lu_nodemap	*nodemap = m->private;
	struct lu_idmap		*idmap;
	struct rb_node		*node;
	bool			cont = 0;

	seq_printf(m, "[\n");
	read_lock(&nodemap->nm_idmap_lock);
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
	read_unlock(&nodemap->nm_idmap_lock);
	seq_printf(m, "\n");
	seq_printf(m, "]\n");

	return 0;
}

/**
 * Attaches nodemap_idmap_show to proc file.
 *
 * \param	inode		inode of seq file in proc fs
 * \param	file		seq file
 * \retval	0		success
 */
static int nodemap_idmap_open(struct inode *inode, struct file *file)
{
	struct lu_nodemap *nodemap = PDE_DATA(inode);

	return single_open(file, nodemap_idmap_show, nodemap);
}

/**
 * Reads and prints the NID ranges for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_ranges_show(struct seq_file *m, void *data)
{
	struct lu_nodemap		*nodemap = m->private;
	struct lu_nid_range		*range;
	struct interval_node_extent	ext;
	bool				cont = false;

	seq_printf(m, "[\n");
	read_lock(&nm_range_tree_lock);
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
	read_unlock(&nm_range_tree_lock);
	seq_printf(m, "\n");
	seq_printf(m, "]\n");

	return 0;
}

/**
 * Connects nodemap_idmap_show to proc file.
 *
 * \param	inode		inode of seq file in proc fs
 * \param	file		seq file
 * \retval	0		success
 */
static int nodemap_ranges_open(struct inode *inode, struct file *file)
{
	struct lu_nodemap *nodemap = PDE_DATA(inode);

	return single_open(file, nodemap_ranges_show, nodemap);
}

/**
 * Hash callback, reads and prints the exports attached to this nodemap.
 *
 * \param	hs		nodemap member hash
 * \param	bd		unused
 * \param	hnode		current member in hash
 * \param	data		seq_file to print to
 * \retval	0		success
 */
static int nodemap_exports_show_cb(cfs_hash_t *hs, cfs_hash_bd_t *bd,
				   struct hlist_node *hnode, void *data)
{
	struct seq_file		*m = data;
	struct obd_export	*exp;
	char			*key;

	exp = hlist_entry(hnode, struct obd_export,
			  exp_target_data.ted_nodemap_member);
	key = cfs_hash_key(hs, hnode);
	seq_printf(m, " { nid: %s, uuid: %s },",
		   obd_export_nid2str(exp), exp->exp_client_uuid.uuid);

	return 0;
}

/**
 * Reads and prints the exports attached to the given nodemap via hash
 * foreach callback.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_exports_show(struct seq_file *m, void *data)
{
	struct lu_nodemap		*nodemap = m->private;

	seq_printf(m, "[\n");

	cfs_hash_for_each(nodemap->nm_member_hash, nodemap_exports_show_cb, m);

	seq_printf(m, "\n");
	seq_printf(m, "]\n");

	return 0;
}

/**
 * Attaches nodemap_idmap_show to proc file.
 *
 * \param	inode		inode of seq file in proc fs
 * \param	file		seq file
 * \retval	0		success
 */
static int nodemap_exports_open(struct inode *inode, struct file *file)
{
	struct lu_nodemap	*nodemap = PDE_DATA(inode);

	return single_open(file, nodemap_exports_show, nodemap);
}

/**
 * Reads and prints the active flag for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_active_seq_show(struct seq_file *m, void *data)
{
	return seq_printf(m, "%u\n", (unsigned int)nodemap_active);
}

/**
 * Activate/deactivate nodemap.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, "1" or "0" to activate/deactivate nodemap
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
nodemap_active_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off)
{
	char			active_string[NODEMAP_LPROC_FLAG_LEN + 1];
	long unsigned int	active;
	int			rc;

	if (count == 0)
		return 0;

	if (count >= sizeof(active_string))
		return -EINVAL;

	if (copy_from_user(active_string, buffer, count))
		return -EFAULT;

	active_string[count] = '\0';
	rc = kstrtoul(active_string, 10, &active);
	if (rc != 0)
		return -EINVAL;

	nodemap_active = active;

	return count;
}
LPROC_SEQ_FOPS(nodemap_active);

/**
 * Reads and prints the nodemap ID for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_id_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%u\n", nodemap->nm_id);
}
LPROC_SEQ_FOPS_RO(nodemap_id);

/**
 * Reads and prints the root squash UID for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_squash_uid_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%u\n", nodemap->nm_squash_uid);
}

/**
 * Reads and prints the root squash GID for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_squash_gid_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%u\n", nodemap->nm_squash_gid);
}

/**
 * Reads and prints the trusted flag for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_trusted_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%d\n", (int)nodemap->nmf_trust_client_ids);
}

/**
 * Reads and prints the admin flag for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_admin_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap = m->private;

	return seq_printf(m, "%d\n", (int)nodemap->nmf_allow_root_access);
}

#ifdef NODEMAP_PROC_DEBUG
/**
 * Helper functions to set nodemap flags.
 *
 * \param[in] buffer    string, which is "1" or "0" to set/unset flag
 * \param[in] count     \a buffer length
 * \param[out] flag_p	where to store flag value
 * \retval              \a count on success
 * \retval              negative number on error
 */
static int nodemap_proc_read_flag(const char __user *buffer,
				  unsigned long count, unsigned int *flag_p)
{
	char			scratch[NODEMAP_LPROC_FLAG_LEN + 1];
	long unsigned int	flag_buf;
	int			rc;

	if (count == 0)
		return 0;

	if (count >= sizeof(scratch))
		return -EINVAL;

	if (copy_from_user(scratch, buffer, count))
		return -EFAULT;

	scratch[count] = '\0';
	rc = kstrtoul(scratch, 10, &flag_buf);
	if (rc != 0)
		return -EINVAL;

	*flag_p = flag_buf;

	return count;
}

/**
 * Set the squash UID.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string representing squash UID to set
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
nodemap_squash_uid_seq_write(struct file *file, const char __user *buffer,
			     size_t count, loff_t *off)
{
	char			 squash[NODEMAP_LPROC_ID_LEN + 1];
	struct seq_file		*m = file->private_data;
	struct lu_nodemap	*nodemap = m->private;
	long unsigned int	 squash_uid;
	int			 rc;

	if (count == 0)
		return 0;

	if (count >= sizeof(squash))
		return -EINVAL;

	if (copy_from_user(squash, buffer, count))
		return -EFAULT;

	squash[count] = '\0';
	rc = kstrtoul(squash, 10, &squash_uid);
	if (rc != 0)
		return -EINVAL;

	nodemap->nm_squash_uid = squash_uid;

	return count;
}

/**
 * Set the squash GID.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string representing squash GID to set
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
nodemap_squash_gid_seq_write(struct file *file, const char __user *buffer,
			     size_t count, loff_t *off)
{
	char			 squash[NODEMAP_LPROC_ID_LEN + 1];
	struct seq_file		*m = file->private_data;
	struct lu_nodemap	*nodemap = m->private;
	long unsigned int	 squash_gid;
	int			 rc;

	if (count == 0)
		return 0;

	if (count >= sizeof(squash))
		return -EINVAL;

	if (copy_from_user(squash, buffer, count))
		return -EFAULT;

	squash[count] = '\0';
	rc = kstrtoul(squash, 10, &squash_gid);
	if (rc != 0)
		return -EINVAL;

	nodemap->nm_squash_gid = squash_gid;

	return count;
}

/**
 * Set/unset the trusted flag.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, "1" or "0"
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
nodemap_trusted_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct lu_nodemap	*nodemap = m->private;
	int			flags;
	int			rc;

	rc = nodemap_proc_read_flag(buffer, count, &flags);
	if (rc >= 0) {
		nodemap->nmf_trust_client_ids = !!flags;
		nm_member_revoke_locks(nodemap);
	}

	return rc;
}

/**
 * Set/unset the admin flag.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, "1" or "0"
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
nodemap_admin_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct lu_nodemap	*nodemap = m->private;
	int			flags;
	int			rc;

	rc = nodemap_proc_read_flag(buffer, count, &flags);
	if (rc >= 0) {
		nodemap->nmf_allow_root_access = !!flags;
		nm_member_revoke_locks(nodemap);
	}

	return rc;
}

/**
 * Add a nodemap.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, name of the nodemap to add
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
lprocfs_add_nodemap_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	char	nodemap_name[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	char	*cpybuf = NULL;
	char	*pos;
	int	rc;

	if (count == 0)
		return 0;

	if (count >= sizeof(nodemap_name))
		return -EINVAL;

	if (copy_from_user(nodemap_name, buffer, count))
		return -EFAULT;

	nodemap_name[count] = '\0';

	cpybuf = nodemap_name;
	pos = strsep(&cpybuf, " \n");
	if (pos == NULL)
		return -EINVAL;

	rc = nodemap_add(nodemap_name);
	if (rc == 0)
		rc = count;

	return rc;
}
LPROC_SEQ_FOPS_WO_TYPE(nodemap, add_nodemap);

/**
 * Delete a nodemap.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, name of the nodemap to delete
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
lprocfs_del_nodemap_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	char	nodemap_name[LUSTRE_NODEMAP_NAME_LENGTH + 1];
	char	*cpybuf = NULL;
	char	*pos;
	int	rc = count;

	if (count == 0)
		return 0;

	if (count >= sizeof(nodemap_name))
		return -EINVAL;

	if (copy_from_user(nodemap_name, buffer, count))
		return -EFAULT;

	nodemap_name[count] = '\0';

	cpybuf = nodemap_name;
	pos = strsep(&cpybuf, " \n");
	if (pos == NULL)
		return -EINVAL;

	rc = nodemap_del(nodemap_name);
	if (rc == 0)
		rc = count;

	return rc;

}
LPROC_SEQ_FOPS_WO_TYPE(nodemap, del_nodemap);

/**
 * Helper function to parse a NID string.
 *
 * \param[in] rangestr	string representation of NIDs, see libcfs_str2nid()
 * \param[out] nids	array of two nids
 * \retval              0 on success
 * \retval              negative number on error
 */
static int parse_nids(char *rangestr, lnet_nid_t nids[2])
{
	struct list_head	nidlist;
	char			nidstr[2][LNET_NIDSTR_SIZE];
	char			nidrange_str[2 * LNET_NIDSTR_SIZE + 2];
	int			rc = 0;

	INIT_LIST_HEAD(&nidlist);

	if (cfs_parse_nidlist(rangestr, strlen(rangestr),
	    &nidlist) <= 0)
		return -EINVAL;

	if (!cfs_nidrange_is_contiguous(&nidlist))
		return -EINVAL;

	cfs_nidrange_find_min_max(&nidlist, nidstr[0], nidstr[1],
				  LNET_NIDSTR_SIZE);
	snprintf(nidrange_str, sizeof(nidrange_str), "%s:%s",
		nidstr[0], nidstr[1]);

	rc = nodemap_parse_range(nidrange_str, nids);
	if (rc != 0)
		return -EINVAL;

	cfs_free_nidlist(&nidlist);

	return 0;
}

/**
 * Add a NID range to nodemap.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, "<nodemap name> <nid range>"
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
lprocfs_add_nodemap_range_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	char			name_range[LUSTRE_NODEMAP_NAME_LENGTH +
					   LNET_NIDSTR_SIZE * 2 + 2];
	char			*cpybuf = NULL;
	char			*name;
	char			*rangestr = NULL;
	lnet_nid_t		nids[2];
	int			rc;

	if (count == 0)
		return 0;

	if (count >= sizeof(name_range))
		GOTO(out, rc = -EINVAL);

	if (copy_from_user(name_range, buffer, count))
		GOTO(out, rc = -EFAULT);

	name_range[count] = '\0';

	cpybuf = name_range;
	name = strsep(&cpybuf, " ");
	if (name == NULL)
		GOTO(out, rc = -EINVAL);

	rangestr = strsep(&cpybuf, " \n");
	if (rangestr == NULL)
		GOTO(out, rc = -EINVAL);

	rc = parse_nids(rangestr, nids);
	if (rc != 0)
		GOTO(out, rc = rc);

	rc = nodemap_add_range(name, nids);
	if (rc != 0)
		GOTO(out, rc = -EINVAL);

	if (rc == 0)
		rc = count;

out:
	return rc;
}
LPROC_SEQ_FOPS_WO_TYPE(nodemap, add_nodemap_range);

/**
 * Delete a NID range from nodemap.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, "<nodemap name> <nid range>"
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
lprocfs_del_nodemap_range_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	char			name_range[LUSTRE_NODEMAP_NAME_LENGTH +
					   LNET_NIDSTR_SIZE * 2 + 2];
	char			*cpybuf = NULL;
	char			*name;
	char			*rangestr = NULL;
	lnet_nid_t		nids[2];
	int			rc;

	if (count == 0)
		return 0;

	if (count >= sizeof(name_range))
		GOTO(out, rc = -EINVAL);

	if (copy_from_user(name_range, buffer, count))
		GOTO(out, rc = -EFAULT);

	name_range[count] = '\0';

	cpybuf = name_range;
	name = strsep(&cpybuf, " ");
	if (name == NULL)
		GOTO(out, rc = -EINVAL);

	rangestr = strsep(&cpybuf, " \n");
	if (rangestr == NULL)
		GOTO(out, rc = -EINVAL);

	rc = parse_nids(rangestr, nids);
	if (rc != 0)
		GOTO(out, rc = rc);

	rc = nodemap_del_range(name, nids);
	if (rc != 0)
		GOTO(out, rc = -EINVAL);

	if (rc == 0)
		rc = count;

out:
	return rc;
}
LPROC_SEQ_FOPS_WO_TYPE(nodemap, del_nodemap_range);

/**
 * Add an idmap to nodemap.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, "<nodemap name> <uid|gid> <idmap>"
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
lprocfs_add_nodemap_idmap_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	char			name_idmapstr[LUSTRE_NODEMAP_NAME_LENGTH + 16];
	char			*cpybuf = NULL;
	char			*name;
	char			*idtypestr = NULL;
	char			*idmapstr = NULL;
	__u32			idmap[2];
	int			rc = count;

	if (count == 0)
		return 0;

	if (count >= sizeof(name_idmapstr))
		GOTO(out, rc = -EINVAL);

	if (copy_from_user(name_idmapstr, buffer, count))
		GOTO(out, rc = -EFAULT);

	name_idmapstr[count] = '\0';

	cpybuf = name_idmapstr;
	name = strsep(&cpybuf, " ");
	if (name == NULL)
		GOTO(out, rc = -EINVAL);

	idtypestr = strsep(&cpybuf, " ");
	if (idtypestr == NULL)
		GOTO(out, rc = -EINVAL);

	idmapstr = strsep(&cpybuf, " \n");
	if (idmapstr == NULL)
		GOTO(out, rc = -EINVAL);

	rc = nodemap_parse_idmap(idmapstr, idmap);
	if (rc != 0)
		GOTO(out, rc = -EINVAL);

	if (strcmp(idtypestr, "uid") == 0)
		rc = nodemap_add_idmap(name, NODEMAP_UID, idmap);
	else if (strcmp(idtypestr, "gid") == 0)
		rc = nodemap_add_idmap(name, NODEMAP_GID, idmap);
	else
		GOTO(out, rc = -EINVAL);

	if (rc != 0)
		GOTO(out, rc = -EINVAL);

	if (rc == 0)
		rc = count;

out:
	return rc;
}
LPROC_SEQ_FOPS_WO_TYPE(nodemap, add_nodemap_idmap);

/**
 * Delete an idmap from nodemap.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, "<nodemap name> <uid|gid> <idmap>"
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
lprocfs_del_nodemap_idmap_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	char			name_idmapstr[LUSTRE_NODEMAP_NAME_LENGTH + 16];
	char			*cpybuf = NULL;
	char			*name;
	char			*idtypestr = NULL;
	char			*idmapstr = NULL;
	__u32			idmap[2];
	int			rc = count;

	if (count == 0)
		return 0;

	if (count >= sizeof(name_idmapstr))
		GOTO(out, rc = -EINVAL);

	if (copy_from_user(name_idmapstr, buffer, count))
		GOTO(out, rc = -EFAULT);

	name_idmapstr[count] = '\0';

	cpybuf = name_idmapstr;
	name = strsep(&cpybuf, " ");
	if (name == NULL)
		GOTO(out, rc = -EINVAL);

	idtypestr = strsep(&cpybuf, " ");
	if (idtypestr == NULL)
		GOTO(out, rc = -EINVAL);

	idmapstr = strsep(&cpybuf, " \n");
	if (idmapstr == NULL)
		GOTO(out, rc = -EINVAL);

	rc = nodemap_parse_idmap(idmapstr, idmap);
	if (rc != 0)
		GOTO(out, rc = -EINVAL);

	if (strcmp(idtypestr, "uid") == 0)
		rc = nodemap_del_idmap(name, NODEMAP_UID, idmap);
	else if (strcmp(idtypestr, "gid") == 0)
		rc = nodemap_del_idmap(name, NODEMAP_GID, idmap);
	else
		GOTO(out, rc = -EINVAL);

	if (rc != 0)
		GOTO(out, rc = -EINVAL);

	if (rc == 0)
		rc = count;

out:
	return rc;
}
LPROC_SEQ_FOPS_WO_TYPE(nodemap, del_nodemap_idmap);
#endif /* NODEMAP_PROC_DEBUG */

static struct lprocfs_vars lprocfs_nm_module_vars[] = {
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
	{
		.name		= "add_nodemap_range",
		.fops		= &nodemap_add_nodemap_range_fops,
	},
	{
		.name		= "del_nodemap_range",
		.fops		= &nodemap_del_nodemap_range_fops,
	},
	{
		.name		= "add_nodemap_idmap",
		.fops		= &nodemap_add_nodemap_idmap_fops,
	},
	{
		.name		= "del_nodemap_idmap",
		.fops		= &nodemap_del_nodemap_idmap_fops,
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

const struct file_operations nodemap_exports_fops = {
	.open			= nodemap_exports_open,
	.read			= seq_read,
	.llseek			= seq_lseek,
	.release		= single_release
};

static struct lprocfs_vars lprocfs_nodemap_vars[] = {
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
		.name		= "exports",
		.fops		= &nodemap_exports_fops,
	},
	{
		.name		= "idmap",
		.fops		= &nodemap_idmap_fops,
	},
	{
		NULL
	}
};

static struct lprocfs_vars lprocfs_default_nodemap_vars[] = {
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
		.name		= "exports",
		.fops		= &nodemap_exports_fops,
	},
	{
		NULL
	}
};

/**
 * Initialize the nodemap procfs directory.
 *
 * \retval	0		success
 */
int nodemap_procfs_init(void)
{
	int rc = 0;

	proc_lustre_nodemap_root = lprocfs_register(LUSTRE_NODEMAP_NAME,
						    proc_lustre_root,
						    lprocfs_nm_module_vars,
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
			lprocfs_register(name, proc_lustre_nodemap_root,
					 lprocfs_default_nodemap_vars,
					 nodemap);
	else
		nodemap_proc_entry =
			lprocfs_register(name, proc_lustre_nodemap_root,
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
