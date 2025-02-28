// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2013, Trustees of Indiana University
 *
 * Copyright (c) 2014, 2017, Intel Corporation.
 *
 * Author: Joshua Walgenbach <jjw@iu.edu>
 */

#define NODEMAP_LDEBUGFS_ID_LEN 16
#define NODEMAP_LDEBUGFS_FLAG_LEN 2

#include <lprocfs_status.h>
#include <lustre_net.h>
#include <lustre_export.h>
#include <obd_class.h>
#include "nodemap_internal.h"

static LIST_HEAD(nodemap_pde_list);

/* nodemap debugfs root directory under lustre */
struct dentry *nodemap_root;

/**
 * Reads and prints the idmap for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_idmap_show(struct seq_file *m, void *data)
{
	struct lu_nodemap	*nodemap;
	struct lu_idmap		*idmap;
	struct rb_node		*node;
	bool cont = false;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_puts(m, "[");
	down_read(&nodemap->nm_idmap_lock);
	for (node = rb_first(&nodemap->nm_client_to_fs_uidmap); node;
				node = rb_next(node)) {
		idmap = rb_entry(node, struct lu_idmap, id_client_to_fs);
		if (idmap == NULL)
			continue;

		if (cont)
			seq_puts(m, ",");
		cont = true;
		seq_printf(m, "\n { idtype: uid, client_id: %u, fs_id: %u }",
			   idmap->id_client, idmap->id_fs);
	}
	for (node = rb_first(&nodemap->nm_client_to_fs_gidmap);
				node; node = rb_next(node)) {
		idmap = rb_entry(node, struct lu_idmap, id_client_to_fs);
		if (idmap == NULL)
			continue;

		if (cont)
			seq_puts(m, ",");
		cont = true;
		seq_printf(m, "\n { idtype: gid, client_id: %u, fs_id: %u }",
			   idmap->id_client, idmap->id_fs);
	}
	for (node = rb_first(&nodemap->nm_client_to_fs_projidmap);
	     node; node = rb_next(node)) {
		idmap = rb_entry(node, struct lu_idmap, id_client_to_fs);
		if (idmap == NULL)
			continue;

		if (cont)
			seq_puts(m, ",");
		cont = true;
		seq_printf(m, "\n { idtype: projid, client_id: %u, fs_id: %u }",
			   idmap->id_client, idmap->id_fs);
	}
	up_read(&nodemap->nm_idmap_lock);
	if (cont)
		seq_puts(m, "\n");
	seq_printf(m, "]\n");

	nodemap_putref(nodemap);
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
	return single_open(file, nodemap_idmap_show, inode->i_private);
}

/**
 * Reads and prints the UID/GID/PROJID offsets for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_offset_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("%s: nodemap not found: rc = %d\n",
		       (char *)m->private, rc);
		return rc;
	}

	seq_puts(m, "{\n");

	seq_printf(m, " start_uid: %u,\n", nodemap->nm_offset_start_uid);
	seq_printf(m, " limit_uid: %u,\n", nodemap->nm_offset_limit_uid);
	seq_printf(m, " start_gid: %u,\n", nodemap->nm_offset_start_gid);
	seq_printf(m, " limit_gid: %u,\n", nodemap->nm_offset_limit_gid);
	seq_printf(m, " start_projid: %u,\n", nodemap->nm_offset_start_projid);
	seq_printf(m, " limit_projid: %u\n", nodemap->nm_offset_limit_projid);

	seq_puts(m, "}\n");

	nodemap_putref(nodemap);
	return 0;
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
	struct lu_nodemap		*nodemap;
	struct lu_nid_range		*range;
	char				start_nidstr[LNET_NIDSTR_SIZE];
	char				end_nidstr[LNET_NIDSTR_SIZE];
	bool				cont = false;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	if (IS_ERR(nodemap)) {
		mutex_unlock(&active_config_lock);
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_puts(m, "[");
	down_read(&active_config->nmc_range_tree_lock);
	list_for_each_entry(range, &nodemap->nm_ranges, rn_list) {
		if (cont)
			seq_puts(m, ",");
		cont = true;
		libcfs_nidstr_r(&range->rn_start, start_nidstr, sizeof(start_nidstr));
		libcfs_nidstr_r(&range->rn_end, end_nidstr, sizeof(end_nidstr));
		seq_printf(m, "\n { id: %u, start_nid: %s, end_nid: %s }",
			   range->rn_id, start_nidstr, end_nidstr);
	}
	up_read(&active_config->nmc_range_tree_lock);
	mutex_unlock(&active_config_lock);
	if (cont)
		seq_puts(m, "\n");
	seq_printf(m, "]\n");

	nodemap_putref(nodemap);
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
	return single_open(file, nodemap_ranges_show, inode->i_private);
}

/**
 * Reads and prints the fileset for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_fileset_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	int rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}
	if (nodemap->nm_prim_fileset && nodemap->nm_prim_fileset[0] != '\0')
		seq_printf(m, "%s\n", nodemap->nm_prim_fileset);
	else
		seq_puts(m, "\n");

	nodemap_putref(nodemap);
	return rc;
}

/**
 * Set a fileset on a nodemap.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, "<fileset>"
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
nodemap_fileset_seq_write(struct file *file,
			  const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	char *nm_fileset;
	int rc = 0;
	ENTRY;

	if (count == 0)
		RETURN(0);

	if (count > PATH_MAX)
		RETURN(-EINVAL);

	OBD_ALLOC(nm_fileset, count + 1);
	/* OBD_ALLOC zero-fills the buffer */
	if (nm_fileset == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(nm_fileset, buffer, count))
		GOTO(out, rc = -EFAULT);

	rc = nodemap_set_fileset(m->private, nm_fileset, false, false);
	if (rc != 0)
		GOTO(out, rc = -EINVAL);

	rc = count;
out:
	OBD_FREE(nm_fileset, count + 1);

	return rc;
}
LDEBUGFS_SEQ_FOPS(nodemap_fileset);

/**
 * Reads and prints the SELinux policy info for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_sepol_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	int rc = 0;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%s\n", nodemap_get_sepol(nodemap));
	nodemap_putref(nodemap);
	return rc;
}

/**
 * Set SELinux policy info on a nodemap.
 *
 * \param[in] file      proc file
 * \param[in] buffer    string, "<sepol>"
 * \param[in] count     \a buffer length
 * \param[in] off       unused
 * \retval              \a count on success
 * \retval              negative number on error
 */
static ssize_t
nodemap_sepol_seq_write(struct file *file,
			const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	char sepol[LUSTRE_NODEMAP_SEPOL_LENGTH + 1];
	int rc = 0;

	BUILD_BUG_ON(sizeof(sepol) !=
		     sizeof(((struct lu_nodemap *)0)->nm_sepol));

	if (count > 0) {
		if (count >= sizeof(sepol))
			GOTO(out, rc = -ENAMETOOLONG);

		if (copy_from_user(sepol, buffer, count))
			GOTO(out, rc = -EFAULT);

		sepol[count] = '\0';

		rc = nodemap_set_sepol(m->private, sepol, false);
	}

out:
	if (rc != 0)
		return rc;

	return count;
}
LDEBUGFS_SEQ_FOPS(nodemap_sepol);

/**
 * Reads and prints the exports attached to the given nodemap.
 *
 * \param	m		seq file in proc fs, stores nodemap
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_exports_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	struct obd_export *exp;
	char nidstr[LNET_NIDSTR_SIZE] = "<unknown>";
	bool cont = false;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_puts(m, "[");

	mutex_lock(&nodemap->nm_member_list_lock);
	list_for_each_entry(exp, &nodemap->nm_member_list,
			    exp_target_data.ted_nodemap_member) {
		if (exp->exp_connection != NULL)
			libcfs_nidstr_r(&exp->exp_connection->c_peer.nid,
					  nidstr, sizeof(nidstr));
		if (cont)
			seq_puts(m, ",");
		cont = true;
		seq_printf(m, "\n { nid: %s, uuid: %s }",
			   nidstr, exp->exp_client_uuid.uuid);
	}
	mutex_unlock(&nodemap->nm_member_list_lock);

	if (cont)
		seq_puts(m, "\n");
	seq_printf(m, "]\n");

	nodemap_putref(nodemap);
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
	return single_open(file, nodemap_exports_show, inode->i_private);
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
	seq_printf(m, "%u\n", (unsigned int)nodemap_active);
	return 0;
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
	char			active_string[NODEMAP_LDEBUGFS_FLAG_LEN + 1];
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

	nodemap_activate(active);

	return count;
}
LDEBUGFS_SEQ_FOPS(nodemap_active);

/**
 * Reads and prints the nodemap ID for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_id_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		int rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%u\n", nodemap->nm_id);
	nodemap_putref(nodemap);
	return 0;
}
LDEBUGFS_SEQ_FOPS_RO(nodemap_id);

/**
 * Reads and prints the root squash UID for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_squash_uid_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		int rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%u\n", nodemap->nm_squash_uid);
	nodemap_putref(nodemap);
	return 0;
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
	struct lu_nodemap *nodemap;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		int rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%u\n", nodemap->nm_squash_gid);
	nodemap_putref(nodemap);
	return 0;
}

/**
 * Reads and prints the squash PROJID for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_squash_projid_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		int rc = PTR_ERR(nodemap);

		CERROR("cannot find nodemap '%s': rc = %d\n",
		       (char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%u\n", nodemap->nm_squash_projid);
	nodemap_putref(nodemap);
	return 0;
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
	struct lu_nodemap *nodemap;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		int rc = PTR_ERR(nodemap);

		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%d\n", (int)nodemap->nmf_trust_client_ids);
	nodemap_putref(nodemap);
	return 0;
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
	struct lu_nodemap *nodemap;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%d\n", (int)nodemap->nmf_allow_root_access);
	nodemap_putref(nodemap);
	return 0;
}

/**
 * Reads and prints the mapping mode for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_map_mode_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	bool need_sep = false;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	if (nodemap->nmf_map_mode == NODEMAP_MAP_ALL) {
		seq_puts(m, "all\n");
	} else {
		if (nodemap->nmf_map_mode & NODEMAP_MAP_UID) {
			seq_puts(m, "uid");
			need_sep = true;
		}
		if (nodemap->nmf_map_mode & NODEMAP_MAP_GID) {
			seq_puts(m, need_sep ? ",gid" : "gid");
			need_sep = true;
		}
		if (nodemap->nmf_map_mode & NODEMAP_MAP_PROJID)
			seq_puts(m, need_sep ? ",projid" : "projid");
		seq_puts(m, "\n");
	}

	nodemap_putref(nodemap);
	return 0;
}

/**
 * Reads and prints the rbac for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_rbac_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	char *sep = "";
	int i, rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
		       (char *)m->private, rc);
		return rc;
	}

	if (nodemap->nmf_rbac == NODEMAP_RBAC_ALL) {
		for (i = 0; i < ARRAY_SIZE(nodemap_rbac_names); i++)
			seq_printf(m, "%s%s", i == 0 ? "" : ",",
				   nodemap_rbac_names[i].nrn_name);
		seq_puts(m, "\n");
	} else if (nodemap->nmf_rbac == NODEMAP_RBAC_NONE) {
		seq_puts(m, "none\n");
	} else {
		for (i = 0; i < ARRAY_SIZE(nodemap_rbac_names); i++) {
			if (nodemap->nmf_rbac &
			    nodemap_rbac_names[i].nrn_mode) {
				seq_printf(m, "%s%s", sep,
					   nodemap_rbac_names[i].nrn_name);
				sep = ",";
			}
		}
		seq_puts(m, "\n");
	}

	nodemap_putref(nodemap);
	return 0;
}

/**
 * Reads and prints the deny_unknown flag for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_deny_unknown_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
			(char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%d\n", (int)nodemap->nmf_deny_unknown);
	nodemap_putref(nodemap);
	return 0;
}

/**
 * Reads and prints the audit_mode flag for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_audit_mode_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
		       (char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%d\n", (int)nodemap->nmf_enable_audit);
	nodemap_putref(nodemap);
	return 0;
}

/**
 * Reads and prints the forbid_encryption flag for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_forbid_encryption_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
		       (char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%d\n", (int)nodemap->nmf_forbid_encryption);
	nodemap_putref(nodemap);
	return 0;
}

/**
 * Reads and prints the readonly_mount flag for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_readonly_mount_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
		       (char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%d\n", (int)nodemap->nmf_readonly_mount);
	nodemap_putref(nodemap);
	return 0;
}

/**
 * Reads and prints the deny_mount flag for the given nodemap.
 *
 * \param	m		seq file in proc fs
 * \param	data		unused
 * \retval	0		success
 */
static int nodemap_deny_mount_seq_show(struct seq_file *m, void *data)
{
	struct lu_nodemap *nodemap;
	int rc;

	mutex_lock(&active_config_lock);
	nodemap = nodemap_lookup(m->private);
	mutex_unlock(&active_config_lock);
	if (IS_ERR(nodemap)) {
		rc = PTR_ERR(nodemap);
		CERROR("cannot find nodemap '%s': rc = %d\n",
		       (char *)m->private, rc);
		return rc;
	}

	seq_printf(m, "%d\n", (int)nodemap->nmf_deny_mount);
	nodemap_putref(nodemap);

	return 0;
}

static struct ldebugfs_vars lprocfs_nm_module_vars[] = {
	{
		.name		= "active",
		.fops		= &nodemap_active_fops,
	},
	{
		NULL
	}
};

LDEBUGFS_SEQ_FOPS_RO(nodemap_trusted);
LDEBUGFS_SEQ_FOPS_RO(nodemap_admin);
LDEBUGFS_SEQ_FOPS_RO(nodemap_squash_uid);
LDEBUGFS_SEQ_FOPS_RO(nodemap_squash_gid);
LDEBUGFS_SEQ_FOPS_RO(nodemap_squash_projid);

LDEBUGFS_SEQ_FOPS_RO(nodemap_deny_unknown);
LDEBUGFS_SEQ_FOPS_RO(nodemap_map_mode);
LDEBUGFS_SEQ_FOPS_RO(nodemap_offset);
LDEBUGFS_SEQ_FOPS_RO(nodemap_rbac);
LDEBUGFS_SEQ_FOPS_RO(nodemap_audit_mode);
LDEBUGFS_SEQ_FOPS_RO(nodemap_forbid_encryption);
LDEBUGFS_SEQ_FOPS_RO(nodemap_readonly_mount);
LDEBUGFS_SEQ_FOPS_RO(nodemap_deny_mount);

static const struct file_operations nodemap_ranges_fops = {
	.open		= nodemap_ranges_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release
};

static const struct file_operations nodemap_idmap_fops = {
	.open		= nodemap_idmap_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release
};

static const struct file_operations nodemap_exports_fops = {
	.open		= nodemap_exports_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release
};

static struct ldebugfs_vars lprocfs_nodemap_vars[] = {
	/* in alphabetical order */
	{
		.name		= "admin_nodemap",
		.fops		= &nodemap_admin_fops,
	},
	{
		.name		= "audit_mode",
		.fops		= &nodemap_audit_mode_fops,
	},
	{
		.name		= "deny_unknown",
		.fops		= &nodemap_deny_unknown_fops,
	},
	{
		.name		= "exports",
		.fops		= &nodemap_exports_fops,
	},
	{
		.name		= "fileset",
		.fops		= &nodemap_fileset_fops,
	},
	{
		.name		= "forbid_encryption",
		.fops		= &nodemap_forbid_encryption_fops,
	},
	{
		.name		= "id",
		.fops		= &nodemap_id_fops,
	},
	{
		.name		= "idmap",
		.fops		= &nodemap_idmap_fops,
	},
	{
		.name		= "offset",
		.fops		= &nodemap_offset_fops,
	},
	{
		.name		= "map_mode",
		.fops		= &nodemap_map_mode_fops,
	},
	{
		.name		= "ranges",
		.fops		= &nodemap_ranges_fops,
	},
	{
		.name		= "rbac",
		.fops		= &nodemap_rbac_fops,
	},
	{
		.name		= "readonly_mount",
		.fops		= &nodemap_readonly_mount_fops,
	},
	{
		.name		= "deny_mount",
		.fops		= &nodemap_deny_mount_fops,
	},
	{
		.name		= "sepol",
		.fops		= &nodemap_sepol_fops,
	},
	{
		.name		= "squash_gid",
		.fops		= &nodemap_squash_gid_fops,
	},
	{
		.name		= "squash_projid",
		.fops		= &nodemap_squash_projid_fops,
	},
	{
		.name		= "squash_uid",
		.fops		= &nodemap_squash_uid_fops,
	},
	{
		.name		= "trusted_nodemap",
		.fops		= &nodemap_trusted_fops,
	},
	{
		NULL
	}
};

static struct ldebugfs_vars lprocfs_default_nodemap_vars[] = {
	/* in alphabetical order */
	{
		.name		= "admin_nodemap",
		.fops		= &nodemap_admin_fops,
	},
	{
		.name		= "audit_mode",
		.fops		= &nodemap_audit_mode_fops,
	},
	{
		.name		= "deny_unknown",
		.fops		= &nodemap_deny_unknown_fops,
	},
	{
		.name		= "exports",
		.fops		= &nodemap_exports_fops,
	},
	{
		.name		= "fileset",
		.fops		= &nodemap_fileset_fops,
	},
	{
		.name		= "forbid_encryption",
		.fops		= &nodemap_forbid_encryption_fops,
	},
	{
		.name		= "id",
		.fops		= &nodemap_id_fops,
	},
	{
		.name		= "map_mode",
		.fops		= &nodemap_map_mode_fops,
	},
	{
		.name		= "readonly_mount",
		.fops		= &nodemap_readonly_mount_fops,
	},
	{
		.name		= "deny_mount",
		.fops		= &nodemap_deny_mount_fops,
	},
	{
		.name		= "squash_gid",
		.fops		= &nodemap_squash_gid_fops,
	},
	{
		.name		= "squash_projid",
		.fops		= &nodemap_squash_projid_fops,
	},
	{
		.name		= "squash_uid",
		.fops		= &nodemap_squash_uid_fops,
	},
	{
		.name		= "trusted_nodemap",
		.fops		= &nodemap_trusted_fops,
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

	nodemap_root = debugfs_create_dir(LUSTRE_NODEMAP_NAME,
					  debugfs_lustre_root);
	if (!nodemap_root) {
		int rc = -EINVAL;
		CERROR("cannot create 'nodemap' directory: rc = %d\n",
		       rc);
	} else {
		ldebugfs_add_vars(nodemap_root, lprocfs_nm_module_vars, NULL);
	}
	return rc;
}

/**
 * Cleanup nodemap proc entry data structures.
 */
void nodemap_procfs_exit(void)
{
	struct nodemap_pde *nm_pde;
	struct nodemap_pde *tmp;

	debugfs_remove_recursive(nodemap_root);
	list_for_each_entry_safe(nm_pde, tmp, &nodemap_pde_list,
				 npe_list_member) {
		list_del(&nm_pde->npe_list_member);
		OBD_FREE_PTR(nm_pde);
	}
}

/**
 * Remove a nodemap's procfs entry and related data.
 */
void lprocfs_nodemap_remove(struct nodemap_pde *nm_pde)
{
	debugfs_remove_recursive(nm_pde->npe_debugfs_entry);
	list_del(&nm_pde->npe_list_member);
	OBD_FREE_PTR(nm_pde);
}

/**
 * Register the proc directory for a nodemap
 *
 * \param	nodemap		nodemap to make the proc dir for
 * \param	is_default:	1 if default nodemap
 * \retval	0		success
 */
int lprocfs_nodemap_register(struct lu_nodemap *nodemap, bool is_default)
{
	struct nodemap_pde *nm_entry;
	int rc = 0;

	OBD_ALLOC_PTR(nm_entry);
	if (!nm_entry)
		GOTO(out, rc = -ENOMEM);

	nm_entry->npe_debugfs_entry = debugfs_create_dir(nodemap->nm_name,
							 nodemap_root);
	if (!nm_entry->npe_debugfs_entry)
		GOTO(out, rc = -ENOENT);

	snprintf(nm_entry->npe_name, sizeof(nm_entry->npe_name), "%s",
		 nodemap->nm_name);

	/* Use the nodemap name as stored on the PDE as the private data. This
	 * is so a nodemap struct can be replaced without updating the proc
	 * entries.
	 */
	ldebugfs_add_vars(nm_entry->npe_debugfs_entry,
			  (is_default ? lprocfs_default_nodemap_vars :
					lprocfs_nodemap_vars),
			  nm_entry->npe_name);
	list_add(&nm_entry->npe_list_member, &nodemap_pde_list);
out:
	if (rc != 0) {
		CERROR("cannot create 'nodemap/%s': rc = %d\n",
		       nodemap->nm_name, rc);
		if (nm_entry != NULL) {
			OBD_FREE_PTR(nm_entry);
			nm_entry = NULL;
		}
	}

	nodemap->nm_pde_data = nm_entry;

	return rc;
}
