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
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 * Author: Johann Lombardi <johann@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <obd_class.h>
#include <lustre_param.h>
#include <lustre_fid.h>
#include <lustre_lfsck.h>

#include "ofd_internal.h"

/* Slab for OFD object allocation */
static struct kmem_cache *ofd_object_kmem;

static struct lu_kmem_descr ofd_caches[] = {
	{
		.ckd_cache = &ofd_object_kmem,
		.ckd_name  = "ofd_obj",
		.ckd_size  = sizeof(struct ofd_object)
	},
	{
		.ckd_cache = NULL
	}
};

static int ofd_connect_to_next(const struct lu_env *env, struct ofd_device *m,
			       const char *next, struct obd_export **exp)
{
	struct obd_connect_data *data = NULL;
	struct obd_device	*obd;
	int			 rc;
	ENTRY;

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		GOTO(out, rc = -ENOMEM);

	obd = class_name2obd(next);
	if (obd == NULL) {
		CERROR("%s: can't locate next device: %s\n",
		       m->ofd_dt_dev.dd_lu_dev.ld_obd->obd_name, next);
		GOTO(out, rc = -ENOTCONN);
	}

	data->ocd_connect_flags = OBD_CONNECT_VERSION;
	data->ocd_version = LUSTRE_VERSION_CODE;

	rc = obd_connect(NULL, exp, obd, &obd->obd_uuid, data, NULL);
	if (rc) {
		CERROR("%s: cannot connect to next dev %s: rc = %d\n",
		       m->ofd_dt_dev.dd_lu_dev.ld_obd->obd_name, next, rc);
		GOTO(out, rc);
	}

	m->ofd_dt_dev.dd_lu_dev.ld_site =
		m->ofd_osd_exp->exp_obd->obd_lu_dev->ld_site;
	LASSERT(m->ofd_dt_dev.dd_lu_dev.ld_site);
	m->ofd_osd = lu2dt_dev(m->ofd_osd_exp->exp_obd->obd_lu_dev);
	m->ofd_dt_dev.dd_lu_dev.ld_site->ls_top_dev = &m->ofd_dt_dev.dd_lu_dev;

out:
	if (data)
		OBD_FREE_PTR(data);
	RETURN(rc);
}

static int ofd_stack_init(const struct lu_env *env,
			  struct ofd_device *m, struct lustre_cfg *cfg)
{
	const char		*dev = lustre_cfg_string(cfg, 0);
	struct lu_device	*d;
	struct ofd_thread_info	*info = ofd_info(env);
	struct lustre_mount_info *lmi;
	int			 rc;
	char			*osdname;

	ENTRY;

	lmi = server_get_mount(dev);
	if (lmi == NULL) {
		CERROR("Cannot get mount info for %s!\n", dev);
		RETURN(-ENODEV);
	}

	/* find bottom osd */
	OBD_ALLOC(osdname, MTI_NAME_MAXLEN);
	if (osdname == NULL)
		RETURN(-ENOMEM);

	snprintf(osdname, MTI_NAME_MAXLEN, "%s-osd", dev);
	rc = ofd_connect_to_next(env, m, osdname, &m->ofd_osd_exp);
	OBD_FREE(osdname, MTI_NAME_MAXLEN);
	if (rc)
		RETURN(rc);

	d = m->ofd_osd_exp->exp_obd->obd_lu_dev;
	LASSERT(d);
	m->ofd_osd = lu2dt_dev(d);

	snprintf(info->fti_u.name, sizeof(info->fti_u.name),
		 "%s-osd", lustre_cfg_string(cfg, 0));

	RETURN(rc);
}

static void ofd_stack_fini(const struct lu_env *env, struct ofd_device *m,
			   struct lu_device *top)
{
	struct obd_device	*obd = ofd_obd(m);
	struct lustre_cfg_bufs	 bufs;
	struct lustre_cfg	*lcfg;
	char			 flags[3] = "";

	ENTRY;

	lu_site_purge(env, top->ld_site, ~0);

	/* process cleanup, pass mdt obd name to get obd umount flags */
	lustre_cfg_bufs_reset(&bufs, obd->obd_name);
	if (obd->obd_force)
		strcat(flags, "F");
	if (obd->obd_fail)
		strcat(flags, "A");
	lustre_cfg_bufs_set_string(&bufs, 1, flags);
	lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);
	if (!lcfg) {
		CERROR("Cannot alloc lcfg!\n");
		RETURN_EXIT;
	}

	LASSERT(top);
	top->ld_ops->ldo_process_config(env, top, lcfg);
	lustre_cfg_free(lcfg);

	lu_site_purge(env, top->ld_site, ~0);

	LASSERT(m->ofd_osd_exp);
	obd_disconnect(m->ofd_osd_exp);

	EXIT;
}

/* For interoperability, see mdt_interop_param[]. */
static struct cfg_interop_param ofd_interop_param[] = {
	{ "ost.quota_type",	NULL },
	{ NULL }
};

/* Some parameters were moved from ofd to osd and only their
 * symlinks were kept in ofd by LU-3106. They are:
 * -writehthrough_cache_enable
 * -readcache_max_filese
 * -read_cache_enable
 * -brw_stats
 * Since they are not included by the static lprocfs var list,
 * a pre-check is added for them to avoid "unknown param" error
 * message confuses the customer. If they are matched in this
 * check, they will be passed to the osd directly.
 */
static bool match_symlink_param(char *param)
{
	char *sval;
	int paramlen;

	if (class_match_param(param, PARAM_OST, &param) == 0) {
		sval = strchr(param, '=');
		if (sval != NULL) {
			paramlen = sval - param;
			if (strncmp(param, "writethrough_cache_enable",
				    paramlen) == 0 ||
			    strncmp(param, "readcache_max_filesize",
				    paramlen) == 0 ||
			    strncmp(param, "read_cache_enable",
				    paramlen) == 0 ||
			    strncmp(param, "brw_stats", paramlen) == 0)
				return true;
		}
	}

	return false;
}

/* used by MGS to process specific configurations */
static int ofd_process_config(const struct lu_env *env, struct lu_device *d,
			      struct lustre_cfg *cfg)
{
	struct ofd_device	*m = ofd_dev(d);
	struct dt_device	*dt_next = m->ofd_osd;
	struct lu_device	*next = &dt_next->dd_lu_dev;
	int			 rc;

	ENTRY;

	switch (cfg->lcfg_command) {
	case LCFG_PARAM: {
		struct lprocfs_static_vars lvars;

		/* For interoperability */
		struct cfg_interop_param   *ptr = NULL;
		struct lustre_cfg	   *old_cfg = NULL;
		char			   *param = NULL;

		param = lustre_cfg_string(cfg, 1);
		if (param == NULL) {
			CERROR("param is empty\n");
			rc = -EINVAL;
			break;
		}

		ptr = class_find_old_param(param, ofd_interop_param);
		if (ptr != NULL) {
			if (ptr->new_param == NULL) {
				rc = 0;
				CWARN("For interoperability, skip this %s."
				      " It is obsolete.\n", ptr->old_param);
				break;
			}

			CWARN("Found old param %s, changed it to %s.\n",
			      ptr->old_param, ptr->new_param);

			old_cfg = cfg;
			cfg = lustre_cfg_rename(old_cfg, ptr->new_param);
			if (IS_ERR(cfg)) {
				rc = PTR_ERR(cfg);
				break;
			}
		}

		if (match_symlink_param(param)) {
			rc = next->ld_ops->ldo_process_config(env, next, cfg);
			break;
		}

		lprocfs_ofd_init_vars(&lvars);
		rc = class_process_proc_param(PARAM_OST, lvars.obd_vars, cfg,
					      d->ld_obd);
		if (rc > 0 || rc == -ENOSYS) {
			CDEBUG(D_CONFIG, "pass param %s down the stack.\n",
			       param);
			/* we don't understand; pass it on */
			rc = next->ld_ops->ldo_process_config(env, next, cfg);
		}
		break;
	}
	case LCFG_SPTLRPC_CONF: {
		rc = -ENOTSUPP;
		break;
	}
	default:
		/* others are passed further */
		rc = next->ld_ops->ldo_process_config(env, next, cfg);
		break;
	}
	RETURN(rc);
}

static int ofd_object_init(const struct lu_env *env, struct lu_object *o,
			   const struct lu_object_conf *conf)
{
	struct ofd_device	*d = ofd_dev(o->lo_dev);
	struct lu_device	*under;
	struct lu_object	*below;
	int			 rc = 0;

	ENTRY;

	CDEBUG(D_INFO, "object init, fid = "DFID"\n",
	       PFID(lu_object_fid(o)));

	under = &d->ofd_osd->dd_lu_dev;
	below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
	if (below != NULL)
		lu_object_add(o, below);
	else
		rc = -ENOMEM;

	RETURN(rc);
}

static void ofd_object_free(const struct lu_env *env, struct lu_object *o)
{
	struct ofd_object	*of = ofd_obj(o);
	struct lu_object_header	*h;

	ENTRY;

	h = o->lo_header;
	CDEBUG(D_INFO, "object free, fid = "DFID"\n",
	       PFID(lu_object_fid(o)));

	lu_object_fini(o);
	lu_object_header_fini(h);
	OBD_SLAB_FREE_PTR(of, ofd_object_kmem);
	EXIT;
}

static int ofd_object_print(const struct lu_env *env, void *cookie,
			    lu_printer_t p, const struct lu_object *o)
{
	return (*p)(env, cookie, LUSTRE_OST_NAME"-object@%p", o);
}

struct lu_object_operations ofd_obj_ops = {
	.loo_object_init	= ofd_object_init,
	.loo_object_free	= ofd_object_free,
	.loo_object_print	= ofd_object_print
};

static struct lu_object *ofd_object_alloc(const struct lu_env *env,
					  const struct lu_object_header *hdr,
					  struct lu_device *d)
{
	struct ofd_object *of;

	ENTRY;

	OBD_SLAB_ALLOC_PTR_GFP(of, ofd_object_kmem, GFP_NOFS);
	if (of != NULL) {
		struct lu_object	*o;
		struct lu_object_header *h;

		o = &of->ofo_obj.do_lu;
		h = &of->ofo_header;
		lu_object_header_init(h);
		lu_object_init(o, h, d);
		lu_object_add_top(h, o);
		o->lo_ops = &ofd_obj_ops;
		RETURN(o);
	} else {
		RETURN(NULL);
	}
}

extern int ost_handle(struct ptlrpc_request *req);

static int ofd_prepare(const struct lu_env *env, struct lu_device *pdev,
		       struct lu_device *dev)
{
	struct ofd_thread_info		*info;
	struct ofd_device		*ofd = ofd_dev(dev);
	struct obd_device		*obd = ofd_obd(ofd);
	struct lu_device		*next = &ofd->ofd_osd->dd_lu_dev;
	struct lfsck_start_param	 lsp;
	int				 rc;

	ENTRY;

	rc = lu_env_refill((struct lu_env *)env);
	if (rc != 0) {
		CERROR("Failure to refill session: '%d'\n", rc);
		RETURN(rc);
	}

	info = ofd_info_init(env, NULL);
	if (info == NULL)
		RETURN(-EFAULT);

	/* initialize lower device */
	rc = next->ld_ops->ldo_prepare(env, dev, next);
	if (rc != 0)
		RETURN(rc);

	rc = lfsck_register(env, ofd->ofd_osd, &ofd->ofd_dt_dev, false);
	if (rc != 0) {
		CERROR("%s: failed to initialize lfsck: rc = %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	lsp.lsp_start = NULL;
	lsp.lsp_namespace = ofd->ofd_namespace;
	rc = lfsck_start(env, ofd->ofd_osd, &lsp);
	if (rc != 0) {
		CWARN("%s: auto trigger paused LFSCK failed: rc = %d\n",
		      obd->obd_name, rc);
		rc = 0;
	}

	target_recovery_init(&ofd->ofd_lut, ost_handle);
	LASSERT(obd->obd_no_conn);
	spin_lock(&obd->obd_dev_lock);
	obd->obd_no_conn = 0;
	spin_unlock(&obd->obd_dev_lock);

	if (obd->obd_recovering == 0)
		ofd_postrecov(env, ofd);

	RETURN(rc);
}

static int ofd_recovery_complete(const struct lu_env *env,
				 struct lu_device *dev)
{
	struct ofd_device	*ofd = ofd_dev(dev);
	struct lu_device	*next = &ofd->ofd_osd->dd_lu_dev;
	int			 rc = 0, max_precreate;

	ENTRY;

	/* Grant space for object precreation on the self export.
	 * This initial reserved space (i.e. 10MB for zfs and 280KB for ldiskfs)
	 * is enough to create 10k objects. More space is then acquired for
	 * precreation in ofd_grant_create().
	 */
	max_precreate = OST_MAX_PRECREATE * ofd->ofd_dt_conf.ddp_inodespace / 2;
	ofd_grant_connect(env, dev->ld_obd->obd_self_export, max_precreate,
			  false);
	rc = next->ld_ops->ldo_recovery_complete(env, next);
	RETURN(rc);
}

static struct lu_device_operations ofd_lu_ops = {
	.ldo_object_alloc	= ofd_object_alloc,
	.ldo_process_config	= ofd_process_config,
	.ldo_recovery_complete	= ofd_recovery_complete,
	.ldo_prepare		= ofd_prepare,
};

static int ofd_procfs_init(struct ofd_device *ofd)
{
	struct lprocfs_static_vars	 lvars;
	struct obd_device		*obd = ofd_obd(ofd);
	cfs_proc_dir_entry_t		*entry;
	int				 rc = 0;

	ENTRY;

	/* lprocfs must be setup before the ofd so state can be safely added
	 * to /proc incrementally as the ofd is setup */
	lprocfs_ofd_init_vars(&lvars);
	rc = lprocfs_obd_setup(obd, lvars.obd_vars);
	if (rc) {
		CERROR("%s: lprocfs_obd_setup failed: %d.\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	rc = lprocfs_alloc_obd_stats(obd, LPROC_OFD_LAST);
	if (rc) {
		CERROR("%s: lprocfs_alloc_obd_stats failed: %d.\n",
		       obd->obd_name, rc);
		GOTO(obd_cleanup, rc);
	}

	/* Init OFD private stats here */
	lprocfs_counter_init(obd->obd_stats, LPROC_OFD_READ_BYTES,
			     LPROCFS_CNTR_AVGMINMAX, "read_bytes", "bytes");
	lprocfs_counter_init(obd->obd_stats, LPROC_OFD_WRITE_BYTES,
			     LPROCFS_CNTR_AVGMINMAX, "write_bytes", "bytes");

	obd->obd_uses_nid_stats = 1;

	entry = lprocfs_register("exports", obd->obd_proc_entry, NULL, NULL);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CERROR("%s: error %d setting up lprocfs for %s\n",
		       obd->obd_name, rc, "exports");
		GOTO(obd_cleanup, rc);
	}
	obd->obd_proc_exports_entry = entry;

	entry = lprocfs_add_simple(obd->obd_proc_exports_entry, "clear",
				   lprocfs_nid_stats_clear_read,
				   lprocfs_nid_stats_clear_write, obd, NULL);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CERROR("%s: add proc entry 'clear' failed: %d.\n",
		       obd->obd_name, rc);
		GOTO(obd_cleanup, rc);
	}

	rc = lprocfs_job_stats_init(obd, LPROC_OFD_STATS_LAST,
				    ofd_stats_counter_init);
	if (rc)
		GOTO(remove_entry_clear, rc);
	RETURN(0);
remove_entry_clear:
	lprocfs_remove_proc_entry("clear", obd->obd_proc_exports_entry);
obd_cleanup:
	lprocfs_obd_cleanup(obd);
	lprocfs_free_obd_stats(obd);

	return rc;
}

static void ofd_procfs_add_brw_stats_symlink(struct ofd_device *ofd)
{
	struct obd_device	*obd = ofd_obd(ofd);
	struct obd_device	*osd_obd = ofd->ofd_osd_exp->exp_obd;
	cfs_proc_dir_entry_t	*osd_root = osd_obd->obd_type->typ_procroot;
	cfs_proc_dir_entry_t	*osd_dir;

	osd_dir = lprocfs_srch(osd_root, obd->obd_name);
	if (osd_dir == NULL)
		return;

	if (lprocfs_srch(osd_dir, "brw_stats") != NULL)
		lprocfs_add_symlink("brw_stats", obd->obd_proc_entry,
				    "../../%s/%s/brw_stats",
				    osd_root->name, osd_dir->name);

	if (lprocfs_srch(osd_dir, "read_cache_enable") != NULL)
		lprocfs_add_symlink("read_cache_enable", obd->obd_proc_entry,
				    "../../%s/%s/read_cache_enable",
				    osd_root->name, osd_dir->name);

	if (lprocfs_srch(osd_dir, "readcache_max_filesize") != NULL)
		lprocfs_add_symlink("readcache_max_filesize",
				    obd->obd_proc_entry,
				    "../../%s/%s/readcache_max_filesize",
				    osd_root->name, osd_dir->name);

	if (lprocfs_srch(osd_dir, "writethrough_cache_enable") != NULL)
		lprocfs_add_symlink("writethrough_cache_enable",
				    obd->obd_proc_entry,
				    "../../%s/%s/writethrough_cache_enable",
				    osd_root->name, osd_dir->name);
}

static void ofd_procfs_fini(struct ofd_device *ofd)
{
	struct obd_device *obd = ofd_obd(ofd);

	lprocfs_remove_proc_entry("writethrough_cache_enable",
				  obd->obd_proc_entry);
	lprocfs_remove_proc_entry("readcache_max_filesize",
				  obd->obd_proc_entry);
	lprocfs_remove_proc_entry("read_cache_enable", obd->obd_proc_entry);
	lprocfs_remove_proc_entry("brw_stats", obd->obd_proc_entry);
	lprocfs_remove_proc_entry("clear", obd->obd_proc_exports_entry);
	lprocfs_free_per_client_stats(obd);
	lprocfs_obd_cleanup(obd);
	lprocfs_free_obd_stats(obd);
	lprocfs_job_stats_fini(obd);
}

extern int ost_handle(struct ptlrpc_request *req);

int ofd_fid_fini(const struct lu_env *env, struct ofd_device *ofd)
{
	return seq_site_fini(env, &ofd->ofd_seq_site);
}

int ofd_fid_init(const struct lu_env *env, struct ofd_device *ofd)
{
	struct seq_server_site	*ss = &ofd->ofd_seq_site;
	struct lu_device	*lu = &ofd->ofd_dt_dev.dd_lu_dev;
	char			*obd_name = ofd_name(ofd);
	char			*name = NULL;
	int			rc = 0;

	ss = &ofd->ofd_seq_site;
	lu->ld_site->ld_seq_site = ss;
	ss->ss_lu = lu->ld_site;
	ss->ss_node_id = ofd->ofd_lut.lut_lsd.lsd_osd_index;

	OBD_ALLOC_PTR(ss->ss_server_seq);
	if (ss->ss_server_seq == NULL)
		GOTO(out_free, rc = -ENOMEM);

	OBD_ALLOC(name, strlen(obd_name) + 10);
	if (!name) {
		OBD_FREE_PTR(ss->ss_server_seq);
		ss->ss_server_seq = NULL;
		GOTO(out_free, rc = -ENOMEM);
	}

	rc = seq_server_init(ss->ss_server_seq, ofd->ofd_osd, obd_name,
			     LUSTRE_SEQ_SERVER, ss, env);
	if (rc) {
		CERROR("%s : seq server init error %d\n", obd_name, rc);
		GOTO(out_free, rc);
	}
	ss->ss_server_seq->lss_space.lsr_index = ss->ss_node_id;

	OBD_ALLOC_PTR(ss->ss_client_seq);
	if (ss->ss_client_seq == NULL)
		GOTO(out_free, rc = -ENOMEM);

	snprintf(name, strlen(obd_name) + 6, "%p-super", obd_name);
	rc = seq_client_init(ss->ss_client_seq, NULL, LUSTRE_SEQ_DATA,
			     name, NULL);
	if (rc) {
		CERROR("%s : seq client init error %d\n", obd_name, rc);
		GOTO(out_free, rc);
	}
	OBD_FREE(name, strlen(obd_name) + 10);
	name = NULL;

	rc = seq_server_set_cli(ss->ss_server_seq, ss->ss_client_seq, env);

out_free:
	if (rc) {
		if (ss->ss_server_seq) {
			seq_server_fini(ss->ss_server_seq, env);
			OBD_FREE_PTR(ss->ss_server_seq);
			ss->ss_server_seq = NULL;
		}

		if (ss->ss_client_seq) {
			seq_client_fini(ss->ss_client_seq);
			OBD_FREE_PTR(ss->ss_client_seq);
			ss->ss_client_seq = NULL;
		}

		if (name) {
			OBD_FREE(name, strlen(obd_name) + 10);
			name = NULL;
		}
	}

	return rc;
}

static struct tgt_opc_slice ofd_common_slice[] = {
	{
		.tos_opc_start = UPDATE_OBJ,
		.tos_opc_end   = UPDATE_LAST_OPC,
		.tos_hs        = tgt_out_handlers
	},
	{
		.tos_opc_start	= SEQ_FIRST_OPC,
		.tos_opc_end	= SEQ_LAST_OPC,
		.tos_hs		= seq_handlers
	},
	{
		.tos_hs		= NULL
	}
};

static int ofd_init0(const struct lu_env *env, struct ofd_device *m,
		     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
	const char		*dev = lustre_cfg_string(cfg, 0);
	struct ofd_thread_info	*info = NULL;
	struct obd_device	*obd;
	struct obd_statfs	*osfs;
	int			 rc;

	ENTRY;

	obd = class_name2obd(dev);
	if (obd == NULL) {
		CERROR("Cannot find obd with name %s\n", dev);
		RETURN(-ENODEV);
	}

	rc = lu_env_refill((struct lu_env *)env);
	if (rc != 0)
		RETURN(rc);

	obd->u.obt.obt_magic = OBT_MAGIC;

	m->ofd_fmd_max_num = OFD_FMD_MAX_NUM_DEFAULT;
	m->ofd_fmd_max_age = OFD_FMD_MAX_AGE_DEFAULT;

	spin_lock_init(&m->ofd_flags_lock);
	m->ofd_raid_degraded = 0;
	m->ofd_syncjournal = 0;
	ofd_slc_set(m);
	m->ofd_grant_compat_disable = 0;

	/* statfs data */
	spin_lock_init(&m->ofd_osfs_lock);
	m->ofd_osfs_age = cfs_time_shift_64(-1000);
	m->ofd_osfs_unstable = 0;
	m->ofd_statfs_inflight = 0;
	m->ofd_osfs_inflight = 0;

	/* grant data */
	spin_lock_init(&m->ofd_grant_lock);
	m->ofd_tot_dirty = 0;
	m->ofd_tot_granted = 0;
	m->ofd_tot_pending = 0;
	m->ofd_seq_count = 0;

	spin_lock_init(&m->ofd_batch_lock);
	rwlock_init(&obd->u.filter.fo_sptlrpc_lock);
	sptlrpc_rule_set_init(&obd->u.filter.fo_sptlrpc_rset);

	obd->u.filter.fo_fl_oss_capa = 0;
	CFS_INIT_LIST_HEAD(&obd->u.filter.fo_capa_keys);
	obd->u.filter.fo_capa_hash = init_capa_hash();
	if (obd->u.filter.fo_capa_hash == NULL)
		RETURN(-ENOMEM);

	m->ofd_dt_dev.dd_lu_dev.ld_ops = &ofd_lu_ops;
	m->ofd_dt_dev.dd_lu_dev.ld_obd = obd;
	/* set this lu_device to obd, because error handling need it */
	obd->obd_lu_dev = &m->ofd_dt_dev.dd_lu_dev;

	rc = ofd_procfs_init(m);
	if (rc) {
		CERROR("Can't init ofd lprocfs, rc %d\n", rc);
		RETURN(rc);
	}

	/* No connection accepted until configurations will finish */
	spin_lock(&obd->obd_dev_lock);
	obd->obd_no_conn = 1;
	spin_unlock(&obd->obd_dev_lock);
	obd->obd_replayable = 1;
	if (cfg->lcfg_bufcount > 4 && LUSTRE_CFG_BUFLEN(cfg, 4) > 0) {
		char *str = lustre_cfg_string(cfg, 4);

		if (strchr(str, 'n')) {
			CWARN("%s: recovery disabled\n", obd->obd_name);
			obd->obd_replayable = 0;
		}
	}

	info = ofd_info_init(env, NULL);
	if (info == NULL)
		RETURN(-EFAULT);

	rc = ofd_stack_init(env, m, cfg);
	if (rc) {
		CERROR("Can't init device stack, rc %d\n", rc);
		GOTO(err_fini_proc, rc);
	}

	ofd_procfs_add_brw_stats_symlink(m);

	/* populate cached statfs data */
	osfs = &ofd_info(env)->fti_u.osfs;
	rc = ofd_statfs_internal(env, m, osfs, 0, NULL);
	if (rc != 0) {
		CERROR("%s: can't get statfs data, rc %d\n", obd->obd_name, rc);
		GOTO(err_fini_stack, rc);
	}
	if (!IS_PO2(osfs->os_bsize)) {
		CERROR("%s: blocksize (%d) is not a power of 2\n",
				obd->obd_name, osfs->os_bsize);
		GOTO(err_fini_stack, rc = -EPROTO);
	}
	m->ofd_blockbits = fls(osfs->os_bsize) - 1;

	m->ofd_precreate_batch = OFD_PRECREATE_BATCH_DEFAULT;
	if (osfs->os_bsize * osfs->os_blocks < OFD_PRECREATE_SMALL_FS)
		m->ofd_precreate_batch = OFD_PRECREATE_BATCH_SMALL;

	snprintf(info->fti_u.name, sizeof(info->fti_u.name), "%s-%s",
		 "filter"/*LUSTRE_OST_NAME*/, obd->obd_uuid.uuid);
	m->ofd_namespace = ldlm_namespace_new(obd, info->fti_u.name,
					      LDLM_NAMESPACE_SERVER,
					      LDLM_NAMESPACE_GREEDY,
					      LDLM_NS_TYPE_OST);
	if (m->ofd_namespace == NULL)
		GOTO(err_fini_stack, rc = -ENOMEM);
	/* set obd_namespace for compatibility with old code */
	obd->obd_namespace = m->ofd_namespace;
	ldlm_register_intent(m->ofd_namespace, ofd_intent_policy);
	m->ofd_namespace->ns_lvbo = &ofd_lvbo;
	m->ofd_namespace->ns_lvbp = m;

	ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
			   "filter_ldlm_cb_client", &obd->obd_ldlm_client);

	dt_conf_get(env, m->ofd_osd, &m->ofd_dt_conf);

	/* Allow at most ddp_grant_reserved% of the available filesystem space
	 * to be granted to clients, so that any errors in the grant overhead
	 * calculations do not allow granting more space to clients than can be
	 * written. Assumes that in aggregate the grant overhead calculations do
	 * not have more than ddp_grant_reserved% estimation error in them. */
	m->ofd_grant_ratio =
		ofd_grant_ratio_conv(m->ofd_dt_conf.ddp_grant_reserved);

	rc = tgt_init(env, &m->ofd_lut, obd, m->ofd_osd, ofd_common_slice,
		      OBD_FAIL_OST_ALL_REQUEST_NET,
		      OBD_FAIL_OST_ALL_REPLY_NET);
	if (rc)
		GOTO(err_free_ns, rc);

	rc = ofd_fs_setup(env, m, obd);
	if (rc)
		GOTO(err_fini_lut, rc);

	RETURN(0);
err_fini_lut:
	tgt_fini(env, &m->ofd_lut);
err_free_ns:
	ldlm_namespace_free(m->ofd_namespace, 0, obd->obd_force);
	obd->obd_namespace = m->ofd_namespace = NULL;
err_fini_stack:
	ofd_stack_fini(env, m, &m->ofd_osd->dd_lu_dev);
err_fini_proc:
	ofd_procfs_fini(m);
	return rc;
}

static void ofd_fini(const struct lu_env *env, struct ofd_device *m)
{
	struct obd_device *obd = ofd_obd(m);
	struct lu_device  *d = &m->ofd_dt_dev.dd_lu_dev;

	lfsck_stop(env, m->ofd_osd, true);
	lfsck_degister(env, m->ofd_osd);
	target_recovery_fini(obd);
	obd_exports_barrier(obd);
	obd_zombie_barrier();

	tgt_fini(env, &m->ofd_lut);
	ofd_fs_cleanup(env, m);

	ofd_free_capa_keys(m);
	cleanup_capa_hash(obd->u.filter.fo_capa_hash);

	if (m->ofd_namespace != NULL) {
		ldlm_namespace_free(m->ofd_namespace, NULL,
				    d->ld_obd->obd_force);
		d->ld_obd->obd_namespace = m->ofd_namespace = NULL;
	}

	ofd_stack_fini(env, m, &m->ofd_dt_dev.dd_lu_dev);
	ofd_procfs_fini(m);
	LASSERT(cfs_atomic_read(&d->ld_ref) == 0);
	server_put_mount(obd->obd_name);
	EXIT;
}

static struct lu_device *ofd_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	ENTRY;
	ofd_fini(env, ofd_dev(d));
	RETURN(NULL);
}

static struct lu_device *ofd_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct ofd_device *m = ofd_dev(d);

	dt_device_fini(&m->ofd_dt_dev);
	OBD_FREE_PTR(m);
	RETURN(NULL);
}

static struct lu_device *ofd_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct ofd_device *m;
	struct lu_device  *l;
	int		   rc;

	OBD_ALLOC_PTR(m);
	if (m == NULL)
		return ERR_PTR(-ENOMEM);

	l = &m->ofd_dt_dev.dd_lu_dev;
	dt_device_init(&m->ofd_dt_dev, t);
	rc = ofd_init0(env, m, t, cfg);
	if (rc != 0) {
		ofd_device_free(env, l);
		l = ERR_PTR(rc);
	}

	return l;
}

/* thread context key constructor/destructor */
LU_KEY_INIT_FINI(ofd, struct ofd_thread_info);

static void ofd_key_exit(const struct lu_context *ctx,
			 struct lu_context_key *key, void *data)
{
	struct ofd_thread_info *info = data;

	info->fti_env = NULL;
	info->fti_exp = NULL;

	info->fti_xid = 0;
	info->fti_transno = 0;
	info->fti_pre_version = 0;
	info->fti_obj = NULL;
	info->fti_has_trans = 0;
	info->fti_mult_trans = 0;
	info->fti_used = 0;

	memset(&info->fti_attr, 0, sizeof info->fti_attr);
}

struct lu_context_key ofd_thread_key = {
	.lct_tags = LCT_DT_THREAD,
	.lct_init = ofd_key_init,
	.lct_fini = ofd_key_fini,
	.lct_exit = ofd_key_exit
};

/* type constructor/destructor: mdt_type_init, mdt_type_fini */
LU_TYPE_INIT_FINI(ofd, &ofd_thread_key);

static struct lu_device_type_operations ofd_device_type_ops = {
	.ldto_init		= ofd_type_init,
	.ldto_fini		= ofd_type_fini,

	.ldto_start		= ofd_type_start,
	.ldto_stop		= ofd_type_stop,

	.ldto_device_alloc	= ofd_device_alloc,
	.ldto_device_free	= ofd_device_free,
	.ldto_device_fini	= ofd_device_fini
};

static struct lu_device_type ofd_device_type = {
	.ldt_tags	= LU_DEVICE_DT,
	.ldt_name	= LUSTRE_OST_NAME,
	.ldt_ops	= &ofd_device_type_ops,
	.ldt_ctx_tags	= LCT_DT_THREAD
};

int __init ofd_init(void)
{
	struct lprocfs_static_vars	lvars;
	int				rc;

	rc = lu_kmem_init(ofd_caches);
	if (rc)
		return rc;

	rc = ofd_fmd_init();
	if (rc) {
		lu_kmem_fini(ofd_caches);
		return(rc);
	}

	lprocfs_ofd_init_vars(&lvars);

	rc = class_register_type(&ofd_obd_ops, NULL, lvars.module_vars,
				 LUSTRE_OST_NAME, &ofd_device_type);
	return rc;
}

void __exit ofd_exit(void)
{
	ofd_fmd_exit();
	lu_kmem_fini(ofd_caches);
	class_unregister_type(LUSTRE_OST_NAME);
}

MODULE_AUTHOR("Whamcloud, Inc. <http://www.whamcloud.com/>");
MODULE_DESCRIPTION("Lustre Object Filtering Device");
MODULE_LICENSE("GPL");

module_init(ofd_init);
module_exit(ofd_exit);
