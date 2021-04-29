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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * cl_device and cl_device_type implementation for VVP layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd.h>
#include "llite_internal.h"
#include "vvp_internal.h"
#include <linux/kallsyms.h>

/*****************************************************************************
 *
 * Vvp device and device type functions.
 *
 */

/*
 * vvp_ prefix stands for "Vfs Vm Posix". It corresponds to historical
 * "llite_" (var. "ll_") prefix.
 */

static struct kmem_cache *ll_thread_kmem;
struct kmem_cache *vvp_object_kmem;
static struct kmem_cache *vvp_session_kmem;
static struct kmem_cache *vvp_thread_kmem;

static struct lu_kmem_descr vvp_caches[] = {
	{
		.ckd_cache = &ll_thread_kmem,
		.ckd_name  = "ll_thread_kmem",
		.ckd_size  = sizeof(struct ll_thread_info),
	},
	{
		.ckd_cache = &vvp_object_kmem,
		.ckd_name  = "vvp_object_kmem",
		.ckd_size  = sizeof(struct vvp_object),
	},
        {
                .ckd_cache = &vvp_session_kmem,
                .ckd_name  = "vvp_session_kmem",
                .ckd_size  = sizeof (struct vvp_session)
        },
	{
		.ckd_cache = &vvp_thread_kmem,
		.ckd_name  = "vvp_thread_kmem",
		.ckd_size  = sizeof(struct vvp_thread_info),
	},
        {
                .ckd_cache = NULL
        }
};

static void *ll_thread_key_init(const struct lu_context *ctx,
				struct lu_context_key *key)
{
	struct ll_thread_info *lti;

	OBD_SLAB_ALLOC_PTR_GFP(lti, ll_thread_kmem, GFP_NOFS);
	if (lti == NULL)
		lti = ERR_PTR(-ENOMEM);

	return lti;
}

static void ll_thread_key_fini(const struct lu_context *ctx,
			       struct lu_context_key *key, void *data)
{
	struct ll_thread_info *lti = data;

	OBD_SLAB_FREE_PTR(lti, ll_thread_kmem);
}

struct lu_context_key ll_thread_key = {
	.lct_tags = LCT_CL_THREAD,
	.lct_init = ll_thread_key_init,
	.lct_fini = ll_thread_key_fini,
};

static void *vvp_session_key_init(const struct lu_context *ctx,
				  struct lu_context_key *key)
{
	struct vvp_session *session;

	OBD_SLAB_ALLOC_PTR_GFP(session, vvp_session_kmem, GFP_NOFS);
	if (session == NULL)
		session = ERR_PTR(-ENOMEM);
	return session;
}

static void vvp_session_key_fini(const struct lu_context *ctx,
                                 struct lu_context_key *key, void *data)
{
        struct vvp_session *session = data;
        OBD_SLAB_FREE_PTR(session, vvp_session_kmem);
}

struct lu_context_key vvp_session_key = {
        .lct_tags = LCT_SESSION,
        .lct_init = vvp_session_key_init,
        .lct_fini = vvp_session_key_fini
};

static void *vvp_thread_key_init(const struct lu_context *ctx,
				 struct lu_context_key *key)
{
	struct vvp_thread_info *vti;

	OBD_SLAB_ALLOC_PTR_GFP(vti, vvp_thread_kmem, GFP_NOFS);
	if (vti == NULL)
		vti = ERR_PTR(-ENOMEM);
	return vti;
}

static void vvp_thread_key_fini(const struct lu_context *ctx,
				struct lu_context_key *key, void *data)
{
	struct vvp_thread_info *vti = data;
	OBD_SLAB_FREE_PTR(vti, vvp_thread_kmem);
}

struct lu_context_key vvp_thread_key = {
	.lct_tags = LCT_CL_THREAD,
	.lct_init = vvp_thread_key_init,
	.lct_fini = vvp_thread_key_fini,
};

/* type constructor/destructor: vvp_type_{init,fini,start,stop}(). */
LU_TYPE_INIT_FINI(vvp, &ll_thread_key, &vvp_session_key, &vvp_thread_key);

static const struct lu_device_operations vvp_lu_ops = {
        .ldo_object_alloc      = vvp_object_alloc
};

static struct lu_device *vvp_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct vvp_device *vdv  = lu2vvp_dev(d);
	struct cl_site    *site = lu2cl_site(d->ld_site);
	struct lu_device  *next = cl2lu_dev(vdv->vdv_next);

	if (d->ld_site != NULL) {
		cl_site_fini(site);
		OBD_FREE_PTR(site);
	}

	cl_device_fini(lu2cl_dev(d));
	OBD_FREE_PTR(vdv);
	return next;
}

static struct lu_device *vvp_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct vvp_device *vdv;
	struct lu_device *lud;
	struct cl_site *site;
	int rc;
	ENTRY;

	OBD_ALLOC_PTR(vdv);
	if (vdv == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	lud = &vdv->vdv_cl.cd_lu_dev;
	cl_device_init(&vdv->vdv_cl, t);
	vvp2lu_dev(vdv)->ld_ops = &vvp_lu_ops;

	OBD_ALLOC_PTR(site);
	if (site != NULL) {
		rc = cl_site_init(site, &vdv->vdv_cl);
		if (rc == 0)
			rc = lu_site_init_finish(&site->cs_lu);
		else {
			LASSERT(lud->ld_site == NULL);
			CERROR("Cannot init lu_site, rc %d.\n", rc);
			OBD_FREE_PTR(site);
		}
	} else
		rc = -ENOMEM;
	if (rc != 0) {
		vvp_device_free(env, lud);
		lud = ERR_PTR(rc);
	}
	RETURN(lud);
}

static int vvp_device_init(const struct lu_env *env, struct lu_device *d,
			   const char *name, struct lu_device *next)
{
	struct vvp_device  *vdv;
	int rc;
	ENTRY;

	vdv = lu2vvp_dev(d);
	vdv->vdv_next = lu2cl_dev(next);

	LASSERT(d->ld_site != NULL && next->ld_type != NULL);
	next->ld_site = d->ld_site;
	rc = next->ld_type->ldt_ops->ldto_device_init(
		env, next, next->ld_type->ldt_name, NULL);
	if (rc == 0) {
		lu_device_get(next);
		lu_ref_add(&next->ld_reference, "lu-stack", &lu_site_init);
	}
	RETURN(rc);
}

static struct lu_device *vvp_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	return cl2lu_dev(lu2vvp_dev(d)->vdv_next);
}

static const struct lu_device_type_operations vvp_device_type_ops = {
        .ldto_init = vvp_type_init,
        .ldto_fini = vvp_type_fini,

        .ldto_start = vvp_type_start,
        .ldto_stop  = vvp_type_stop,

	.ldto_device_alloc	= vvp_device_alloc,
	.ldto_device_free	= vvp_device_free,
	.ldto_device_init	= vvp_device_init,
	.ldto_device_fini	= vvp_device_fini,
};

struct lu_device_type vvp_device_type = {
        .ldt_tags     = LU_DEVICE_CL,
        .ldt_name     = LUSTRE_VVP_NAME,
        .ldt_ops      = &vvp_device_type_ops,
        .ldt_ctx_tags = LCT_CL_THREAD
};

#ifndef HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT
unsigned int (*vvp_account_page_dirtied)(struct page *page,
					 struct address_space *mapping);

unsigned int ll_account_page_dirtied(struct page *page,
				     struct address_space *mapping)
{
	/* must use __set_page_dirty, which means unlocking and
	 * relocking, which hurts performance.
	 */
	ll_xa_unlock(&mapping->i_pages);
	__set_page_dirty(page, mapping, 0);
	ll_xa_lock(&mapping->i_pages);
	return 0;
}
#endif

/**
 * A mutex serializing calls to vvp_inode_fini() under extreme memory
 * pressure, when environments cannot be allocated.
 */
int vvp_global_init(void)
{
	int rc;

	rc = lu_kmem_init(vvp_caches);
	if (rc != 0)
		return rc;

	rc = lu_device_type_init(&vvp_device_type);
	if (rc != 0)
		goto out_kmem;

#ifndef HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT
	/*
	 * Kernel v5.2-5678-gac1c3e4 no longer exports account_page_dirtied
	 */
	vvp_account_page_dirtied = (void *)
		cfs_kallsyms_lookup_name("account_page_dirtied");
	if (!vvp_account_page_dirtied)
		vvp_account_page_dirtied = ll_account_page_dirtied;
#endif

	return 0;

out_kmem:
	lu_kmem_fini(vvp_caches);

	return rc;
}

void vvp_global_fini(void)
{
	lu_device_type_fini(&vvp_device_type);
	lu_kmem_fini(vvp_caches);
}

/*****************************************************************************
 *
 * mirror obd-devices into cl devices.
 *
 */

int cl_sb_init(struct super_block *sb)
{
        struct ll_sb_info *sbi;
        struct cl_device  *cl;
        struct lu_env     *env;
        int rc = 0;
	__u16 refcheck;

        sbi  = ll_s2sbi(sb);
        env = cl_env_get(&refcheck);
        if (!IS_ERR(env)) {
                cl = cl_type_setup(env, NULL, &vvp_device_type,
                                   sbi->ll_dt_exp->exp_obd->obd_lu_dev);
                if (!IS_ERR(cl)) {
                        sbi->ll_cl = cl;
                        sbi->ll_site = cl2lu_dev(cl)->ld_site;
                }
                cl_env_put(env, &refcheck);
        } else
                rc = PTR_ERR(env);
        RETURN(rc);
}

int cl_sb_fini(struct super_block *sb)
{
        struct ll_sb_info *sbi;
        struct lu_env     *env;
        struct cl_device  *cld;
	__u16              refcheck;
        int                result;

        ENTRY;
        sbi = ll_s2sbi(sb);
        env = cl_env_get(&refcheck);
        if (!IS_ERR(env)) {
                cld = sbi->ll_cl;

                if (cld != NULL) {
                        cl_stack_fini(env, cld);
                        sbi->ll_cl = NULL;
                        sbi->ll_site = NULL;
                }
                cl_env_put(env, &refcheck);
                result = 0;
        } else {
                CERROR("Cannot cleanup cl-stack due to memory shortage.\n");
                result = PTR_ERR(env);
        }

	RETURN(result);
}

/****************************************************************************
 *
 * debugfs/lustre/llite/$MNT/dump_page_cache
 *
 ****************************************************************************/

struct vvp_seq_private {
	struct ll_sb_info	*vsp_sbi;
	struct lu_env		*vsp_env;
	u16			vsp_refcheck;
	struct cl_object	*vsp_clob;
	struct rhashtable_iter	vsp_iter;
	u32			vsp_page_index;
	/*
	 * prev_pos is the 'pos' of the last object returned
	 * by ->start of ->next.
	 */
	loff_t			vvp_prev_pos;
};

static struct page *vvp_pgcache_current(struct vvp_seq_private *priv)
{
	struct lu_device *dev = &priv->vsp_sbi->ll_cl->cd_lu_dev;
	struct lu_object_header *h;
	struct page *vmpage = NULL;

	rhashtable_walk_start(&priv->vsp_iter);
	while ((h = rhashtable_walk_next(&priv->vsp_iter)) != NULL) {
		struct inode *inode;
		int nr;

		if (!priv->vsp_clob) {
			struct lu_object *lu_obj;

			lu_obj = lu_object_get_first(h, dev);
			if (!lu_obj)
				continue;

			priv->vsp_clob = lu2cl(lu_obj);
			lu_object_ref_add(lu_obj, "dump", current);
			priv->vsp_page_index = 0;
		}

		inode = vvp_object_inode(priv->vsp_clob);
		nr = find_get_pages_contig(inode->i_mapping,
					   priv->vsp_page_index, 1, &vmpage);
		if (nr > 0) {
			priv->vsp_page_index = vmpage->index;
			break;
		}
		lu_object_ref_del(&priv->vsp_clob->co_lu, "dump", current);
		cl_object_put(priv->vsp_env, priv->vsp_clob);
		priv->vsp_clob = NULL;
		priv->vsp_page_index = 0;
	}
	rhashtable_walk_stop(&priv->vsp_iter);
	return vmpage;
}

#define seq_page_flag(seq, page, flag, has_flags) do {                  \
	if (test_bit(PG_##flag, &(page)->flags)) {                  \
                seq_printf(seq, "%s"#flag, has_flags ? "|" : "");       \
                has_flags = 1;                                          \
        }                                                               \
} while(0)

static void vvp_pgcache_page_show(const struct lu_env *env,
				  struct seq_file *seq, struct cl_page *page)
{
	struct vvp_page *vpg;
	struct page      *vmpage;
	int              has_flags;

	vpg = cl2vvp_page(cl_page_at(page, &vvp_device_type));
	vmpage = vpg->vpg_page;
	seq_printf(seq, " %5i | %p %p %s %s %s | %p "DFID"(%p) %lu %u [",
		   0 /* gen */,
		   vpg, page,
		   "none",
		   vpg->vpg_defer_uptodate ? "du" : "- ",
		   PageWriteback(vmpage) ? "wb" : "-",
		   vmpage,
		   PFID(ll_inode2fid(vmpage->mapping->host)),
		   vmpage->mapping->host, vmpage->index,
		   page_count(vmpage));
	has_flags = 0;
	seq_page_flag(seq, vmpage, locked, has_flags);
	seq_page_flag(seq, vmpage, error, has_flags);
	seq_page_flag(seq, vmpage, referenced, has_flags);
	seq_page_flag(seq, vmpage, uptodate, has_flags);
	seq_page_flag(seq, vmpage, dirty, has_flags);
	seq_page_flag(seq, vmpage, writeback, has_flags);
	seq_printf(seq, "%s]\n", has_flags ? "" : "-");
}

static int vvp_pgcache_show(struct seq_file *f, void *v)
{
	struct vvp_seq_private *priv = f->private;
	struct page *vmpage = v;
	struct cl_page *page;

	seq_printf(f, "%8lx@" DFID ": ", vmpage->index,
		   PFID(lu_object_fid(&priv->vsp_clob->co_lu)));
	lock_page(vmpage);
	page = cl_vmpage_page(vmpage, priv->vsp_clob);
	unlock_page(vmpage);
	put_page(vmpage);

	if (page) {
		vvp_pgcache_page_show(priv->vsp_env, f, page);
		cl_page_put(priv->vsp_env, page);
	} else {
		seq_puts(f, "missing\n");
	}

	return 0;
}

static void vvp_pgcache_rewind(struct vvp_seq_private *priv)
{
	if (priv->vvp_prev_pos) {
		struct lu_site *s = priv->vsp_sbi->ll_cl->cd_lu_dev.ld_site;

		rhashtable_walk_exit(&priv->vsp_iter);
		rhashtable_walk_enter(&s->ls_obj_hash, &priv->vsp_iter);
		priv->vvp_prev_pos = 0;
		if (priv->vsp_clob) {
			lu_object_ref_del(&priv->vsp_clob->co_lu, "dump",
					  current);
			cl_object_put(priv->vsp_env, priv->vsp_clob);
		}
		priv->vsp_clob = NULL;
	}
}

static struct page *vvp_pgcache_next_page(struct vvp_seq_private *priv)
{
	priv->vsp_page_index += 1;
	return vvp_pgcache_current(priv);
}

static void *vvp_pgcache_start(struct seq_file *f, loff_t *pos)
{
	struct vvp_seq_private *priv = f->private;

	if (*pos == 0) {
		vvp_pgcache_rewind(priv);
	} else if (*pos == priv->vvp_prev_pos) {
		/* Return the current item */;
	} else {
		WARN_ON(*pos != priv->vvp_prev_pos + 1);
		priv->vsp_page_index += 1;
	}

	priv->vvp_prev_pos = *pos;
	return vvp_pgcache_current(priv);
}

static void *vvp_pgcache_next(struct seq_file *f, void *v, loff_t *pos)
{
	struct vvp_seq_private *priv = f->private;

	WARN_ON(*pos != priv->vvp_prev_pos);
	*pos += 1;
	priv->vvp_prev_pos = *pos;
	return vvp_pgcache_next_page(priv);
}

static void vvp_pgcache_stop(struct seq_file *f, void *v)
{
        /* Nothing to do */
}

static const struct seq_operations vvp_pgcache_ops = {
	.start = vvp_pgcache_start,
	.next  = vvp_pgcache_next,
	.stop  = vvp_pgcache_stop,
	.show  = vvp_pgcache_show
};

static int vvp_dump_pgcache_seq_open(struct inode *inode, struct file *filp)
{
	struct vvp_seq_private *priv;
	struct lu_site *s;

	priv = __seq_open_private(filp, &vvp_pgcache_ops, sizeof(*priv));
	if (!priv)
		return -ENOMEM;

	priv->vsp_sbi = inode->i_private;
	priv->vsp_env = cl_env_get(&priv->vsp_refcheck);
	priv->vsp_clob = NULL;
	if (IS_ERR(priv->vsp_env)) {
		int err = PTR_ERR(priv->vsp_env);

		seq_release_private(inode, filp);
		return err;
	}

	s = priv->vsp_sbi->ll_cl->cd_lu_dev.ld_site;
	rhashtable_walk_enter(&s->ls_obj_hash, &priv->vsp_iter);

	return 0;
}

static int vvp_dump_pgcache_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct vvp_seq_private *priv = seq->private;

	if (priv->vsp_clob) {
		lu_object_ref_del(&priv->vsp_clob->co_lu, "dump", current);
		cl_object_put(priv->vsp_env, priv->vsp_clob);
	}
	cl_env_put(priv->vsp_env, &priv->vsp_refcheck);
	rhashtable_walk_exit(&priv->vsp_iter);
	return seq_release_private(inode, file);
}

const struct file_operations vvp_dump_pgcache_file_ops = {
	.owner	 = THIS_MODULE,
	.open	 = vvp_dump_pgcache_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = vvp_dump_pgcache_seq_release,
};
