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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/fld/lproc_fld.c
 *
 * FLD (FIDs Location Database)
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 *	Di Wang <di.wang@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FLD

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/module.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <dt_object.h>
#include <md_object.h>
#include <obd_support.h>
#include <lustre_req_layout.h>
#include <lustre_fld.h>
#include <lustre_fid.h>
#include "fld_internal.h"

#ifdef LPROCFS
static int
fld_proc_read_targets(char *page, char **start, off_t off,
                      int count, int *eof, void *data)
{
        struct lu_client_fld *fld = (struct lu_client_fld *)data;
        struct lu_fld_target *target;
	int total = 0, rc;
	ENTRY;

        LASSERT(fld != NULL);

        cfs_spin_lock(&fld->lcf_lock);
        cfs_list_for_each_entry(target,
                                &fld->lcf_targets, ft_chain)
        {
                rc = snprintf(page, count, "%s\n",
                              fld_target_name(target));
                page += rc;
                count -= rc;
                total += rc;
                if (count == 0)
                        break;
        }
        cfs_spin_unlock(&fld->lcf_lock);
	RETURN(total);
}

static int
fld_proc_read_hash(char *page, char **start, off_t off,
                   int count, int *eof, void *data)
{
        struct lu_client_fld *fld = (struct lu_client_fld *)data;
	int rc;
	ENTRY;

        LASSERT(fld != NULL);

        cfs_spin_lock(&fld->lcf_lock);
        rc = snprintf(page, count, "%s\n",
                      fld->lcf_hash->fh_name);
        cfs_spin_unlock(&fld->lcf_lock);

	RETURN(rc);
}

static int
fld_proc_write_hash(struct file *file, const char *buffer,
                    unsigned long count, void *data)
{
        struct lu_client_fld *fld = (struct lu_client_fld *)data;
        struct lu_fld_hash *hash = NULL;
        int i;
	ENTRY;

        LASSERT(fld != NULL);

        for (i = 0; fld_hash[i].fh_name != NULL; i++) {
                if (count != strlen(fld_hash[i].fh_name))
                        continue;

                if (!strncmp(fld_hash[i].fh_name, buffer, count)) {
                        hash = &fld_hash[i];
                        break;
                }
        }

        if (hash != NULL) {
                cfs_spin_lock(&fld->lcf_lock);
                fld->lcf_hash = hash;
                cfs_spin_unlock(&fld->lcf_lock);

                CDEBUG(D_INFO, "%s: Changed hash to \"%s\"\n",
                       fld->lcf_name, hash->fh_name);
        }

        RETURN(count);
}

static int
fld_proc_write_cache_flush(struct file *file, const char *buffer,
                           unsigned long count, void *data)
{
        struct lu_client_fld *fld = (struct lu_client_fld *)data;
	ENTRY;

        LASSERT(fld != NULL);

        fld_cache_flush(fld->lcf_cache);

        CDEBUG(D_INFO, "%s: Lookup cache is flushed\n", fld->lcf_name);

        RETURN(count);
}

struct fld_seq_param {
	struct lu_env  fsp_env;
	struct dt_it  *fsp_it;
};

static void *fldb_seq_start(struct seq_file *p, loff_t *pos)
{
	struct lu_server_fld	*fld = p->private;
	struct dt_object	*obj;
	const struct dt_it_ops	*iops;
	struct fld_seq_param	*param;

	if (fld->lsf_obj == NULL)
		return NULL;

	obj = fld->lsf_obj;
	iops = &obj->do_index_ops->dio_it;

	OBD_ALLOC_PTR(param);
	if (param == NULL)
		return ERR_PTR(-ENOMEM);

	lu_env_init(&param->fsp_env, LCT_MD_THREAD);
	param->fsp_it = iops->init(&param->fsp_env, obj, 0, NULL);

	iops->load(&param->fsp_env, param->fsp_it, *pos);

	return param;
}

static void fldb_seq_stop(struct seq_file *p, void *v)
{
	struct lu_server_fld	*fld = p->private;
	struct dt_object	*obj;
	const struct dt_it_ops	*iops;
	struct fld_seq_param	*param = (struct fld_seq_param *)v;

	if (fld->lsf_obj == NULL)
		return;

	obj = fld->lsf_obj;
	iops = &obj->do_index_ops->dio_it;
	if (IS_ERR(param) || param == NULL)
		return;

	iops->put(&param->fsp_env, param->fsp_it);
	iops->fini(&param->fsp_env, param->fsp_it);
	lu_env_fini(&param->fsp_env);
	OBD_FREE_PTR(param);

	return;
}

static void *fldb_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct lu_server_fld	*fld = p->private;
	struct dt_object	*obj;
	const struct dt_it_ops	*iops;
	struct fld_seq_param	*param = (struct fld_seq_param *)v;
	int			rc;

	if (fld->lsf_obj == NULL)
		return NULL;

	obj = fld->lsf_obj;
	iops = &obj->do_index_ops->dio_it;

	iops->get(&param->fsp_env, param->fsp_it,
		  (const struct dt_key *)pos);

	rc = iops->next(&param->fsp_env, param->fsp_it);
	if (rc > 0) {
		iops->put(&param->fsp_env, param->fsp_it);
		iops->fini(&param->fsp_env, param->fsp_it);
		lu_env_fini(&param->fsp_env);
		OBD_FREE_PTR(param);
		return NULL;
	}

	*pos = *(loff_t *)iops->key(&param->fsp_env, param->fsp_it);

	return param;
}

static int fldb_seq_show(struct seq_file *p, void *v)
{
	struct lu_server_fld	*fld = p->private;
	struct dt_object	*obj = fld->lsf_obj;
	struct fld_seq_param	*param = (struct fld_seq_param *)v;
	const struct dt_it_ops	*iops;
	struct fld_thread_info	*info;
	struct lu_seq_range	*fld_rec;
	int			rc;

	if (fld->lsf_obj == NULL)
		return 0;

	obj = fld->lsf_obj;
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
		rc = seq_printf(p, DRANGE"\n", PRANGE(fld_rec));
	}

	iops->put(&param->fsp_env, param->fsp_it);

	return rc;
}

struct seq_operations fldb_sops = {
	.start = fldb_seq_start,
	.stop = fldb_seq_stop,
	.next = fldb_seq_next,
	.show = fldb_seq_show,
};

static int fldb_seq_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *dp = PDE(inode);
	struct seq_file *seq;
	int rc;

	LPROCFS_ENTRY_AND_CHECK(dp);
	rc = seq_open(file, &fldb_sops);
	if (rc) {
		LPROCFS_EXIT();
		return rc;
	}

	seq = file->private_data;
	seq->private = dp->data;
	return 0;
}

struct lprocfs_vars fld_server_proc_list[] = {
	{ NULL }};

struct lprocfs_vars fld_client_proc_list[] = {
	{ "targets",     fld_proc_read_targets, NULL, NULL },
	{ "hash",        fld_proc_read_hash, fld_proc_write_hash, NULL },
	{ "cache_flush", NULL, fld_proc_write_cache_flush, NULL },
	{ NULL }};

struct file_operations fld_proc_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = fldb_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = lprocfs_seq_release,
};

#endif
