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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/fld/lproc_fld.c
 *
 * FLD (FIDs Location Database)
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 *	Di Wang <di.wang@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FLD

#include <libcfs/libcfs.h>
#include <linux/module.h>

#ifdef HAVE_SERVER_SUPPORT
#include <dt_object.h>
#endif
#include <obd_support.h>
#include <lustre_fld.h>
#include <lustre_fid.h>
#include "fld_internal.h"

static int
fld_debugfs_targets_seq_show(struct seq_file *m, void *unused)
{
	struct lu_client_fld *fld = (struct lu_client_fld *)m->private;
        struct lu_fld_target *target;

	ENTRY;
	spin_lock(&fld->lcf_lock);
	list_for_each_entry(target, &fld->lcf_targets, ft_chain)
	seq_printf(m, "%s\n", fld_target_name(target));
	spin_unlock(&fld->lcf_lock);

	RETURN(0);
}

static int
fld_debugfs_hash_seq_show(struct seq_file *m, void *unused)
{
	struct lu_client_fld *fld = (struct lu_client_fld *)m->private;

	ENTRY;
	spin_lock(&fld->lcf_lock);
	seq_printf(m, "%s\n", fld->lcf_hash->fh_name);
	spin_unlock(&fld->lcf_lock);

	RETURN(0);
}

static ssize_t
fld_debugfs_hash_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct lu_client_fld *fld = m->private;
	struct lu_fld_hash *hash = NULL;
	char fh_name[8];
	int i;

	if (count > sizeof(fh_name))
		return -ENAMETOOLONG;

	if (copy_from_user(fh_name, buffer, count) != 0)
		return -EFAULT;

	for (i = 0; fld_hash[i].fh_name; i++) {
		if (count != strlen(fld_hash[i].fh_name))
			continue;

		if (!strncmp(fld_hash[i].fh_name, fh_name, count)) {
			hash = &fld_hash[i];
			break;
		}
	}

	if (hash) {
		spin_lock(&fld->lcf_lock);
		fld->lcf_hash = hash;
		spin_unlock(&fld->lcf_lock);

		CDEBUG(D_INFO, "%s: Changed hash to \"%s\"\n",
		       fld->lcf_name, hash->fh_name);
	}

	return count;
}

static ssize_t ldebugfs_cache_flush_seq_write(struct file *file,
					      const char __user *buffer,
					      size_t count, loff_t *pos)
{
	struct seq_file *m = file->private_data;
	struct lu_client_fld *fld = m->private;

	ENTRY;
        fld_cache_flush(fld->lcf_cache);

        CDEBUG(D_INFO, "%s: Lookup cache is flushed\n", fld->lcf_name);

        RETURN(count);
}

LDEBUGFS_SEQ_FOPS_RO(fld_debugfs_targets);
LDEBUGFS_SEQ_FOPS(fld_debugfs_hash);
LDEBUGFS_FOPS_WR_ONLY(fld, cache_flush);

struct ldebugfs_vars fld_client_debugfs_list[] = {
	{ .name	=	"targets",
	  .fops	=	&fld_debugfs_targets_fops	},
	{ .name	=	"hash",
	  .fops	=	&fld_debugfs_hash_fops	},
	{ .name	=	"cache_flush",
	  .fops	=	&fld_cache_flush_fops	},
	{ NULL }
};

#ifdef HAVE_SERVER_SUPPORT
struct fld_seq_param {
	struct lu_env		fsp_env;
	struct dt_it		*fsp_it;
	struct lu_server_fld	*fsp_fld;
	unsigned int		fsp_stop:1;
};

static void *fldb_seq_start(struct seq_file *p, loff_t *pos)
{
	struct fld_seq_param    *param = p->private;
	struct lu_server_fld    *fld;
	struct dt_object        *obj;
	const struct dt_it_ops  *iops;
	struct dt_key		*key;
	int			rc;

	if (param == NULL || param->fsp_stop)
		return NULL;

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	rc = iops->load(&param->fsp_env, param->fsp_it, *pos);
	if (rc <= 0)
		return NULL;

	key = iops->key(&param->fsp_env, param->fsp_it);
	if (IS_ERR(key))
		return NULL;

	*pos = be64_to_cpu(*(__u64 *)key);

	return param;
}

static void fldb_seq_stop(struct seq_file *p, void *v)
{
	struct fld_seq_param    *param = p->private;
	const struct dt_it_ops	*iops;
	struct lu_server_fld	*fld;
	struct dt_object	*obj;

	if (param == NULL)
		return;

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	iops->put(&param->fsp_env, param->fsp_it);
}

static void *fldb_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct fld_seq_param    *param = p->private;
	struct lu_server_fld	*fld;
	struct dt_object	*obj;
	const struct dt_it_ops	*iops;
	int			rc;

	++*pos;
	if (param == NULL || param->fsp_stop)
		return NULL;

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	rc = iops->next(&param->fsp_env, param->fsp_it);
	if (rc > 0) {
		param->fsp_stop = 1;
		return NULL;
	}

	*pos = be64_to_cpu(*(__u64 *)iops->key(&param->fsp_env, param->fsp_it));
	return param;
}

static int fldb_seq_show(struct seq_file *p, void *v)
{
	struct fld_seq_param    *param = p->private;
	struct lu_server_fld	*fld;
	struct dt_object	*obj;
	const struct dt_it_ops	*iops;
	struct fld_thread_info	*info;
	struct lu_seq_range	*fld_rec;
	int			rc;

	if (param == NULL || param->fsp_stop)
		return 0;

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	info = lu_context_key_get(&param->fsp_env.le_ctx,
				  &fld_thread_key);
	fld_rec = &info->fti_rec;
	rc = iops->rec(&param->fsp_env, param->fsp_it,
		       (struct dt_rec *)fld_rec, 0);
	if (rc != 0) {
		CERROR("%s:read record error: rc %d\n",
		       fld->lsf_name, rc);
	} else if (fld_rec->lsr_start != 0) {
		range_be_to_cpu(fld_rec, fld_rec);
		seq_printf(p, DRANGE"\n", PRANGE(fld_rec));
	}

	return rc;
}

static const struct seq_operations fldb_sops = {
	.start = fldb_seq_start,
	.stop = fldb_seq_stop,
	.next = fldb_seq_next,
	.show = fldb_seq_show,
};

static int fldb_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file		*seq;
	struct lu_server_fld    *fld = inode->i_private;
	struct dt_object	*obj;
	const struct dt_it_ops  *iops;
	struct fld_seq_param    *param = NULL;
	int			env_init = 0;
	int			rc;

	rc = seq_open(file, &fldb_sops);
	if (rc)
		GOTO(out, rc);

	obj = fld->lsf_obj;
	if (obj == NULL) {
		seq = file->private_data;
		seq->private = NULL;
		return 0;
	}

	OBD_ALLOC_PTR(param);
	if (param == NULL)
		GOTO(out, rc = -ENOMEM);

	rc = lu_env_init(&param->fsp_env, LCT_MD_THREAD);
	if (rc != 0)
		GOTO(out, rc);

	env_init = 1;
	iops = &obj->do_index_ops->dio_it;
	param->fsp_it = iops->init(&param->fsp_env, obj, 0);
	if (IS_ERR(param->fsp_it))
		GOTO(out, rc = PTR_ERR(param->fsp_it));

	param->fsp_fld = fld;
	param->fsp_stop = 0;

	seq = file->private_data;
	seq->private = param;
out:
	if (rc != 0) {
		if (env_init == 1)
			lu_env_fini(&param->fsp_env);
		if (param != NULL)
			OBD_FREE_PTR(param);
	}
	return rc;
}

static int fldb_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file		*seq = file->private_data;
	struct fld_seq_param	*param;
	struct lu_server_fld	*fld;
	struct dt_object	*obj;
	const struct dt_it_ops	*iops;

	param = seq->private;
	if (param == NULL) {
		lprocfs_seq_release(inode, file);
		return 0;
	}

	fld = param->fsp_fld;
	obj = fld->lsf_obj;
	LASSERT(obj != NULL);
	iops = &obj->do_index_ops->dio_it;

	LASSERT(iops != NULL);
	LASSERT(param->fsp_it != NULL);
	iops->fini(&param->fsp_env, param->fsp_it);
	lu_env_fini(&param->fsp_env);
	OBD_FREE_PTR(param);
	lprocfs_seq_release(inode, file);

	return 0;
}

const struct file_operations fld_debugfs_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = fldb_seq_open,
	.read    = seq_read,
	.release = fldb_seq_release,
};

# endif /* HAVE_SERVER_SUPPORT */
