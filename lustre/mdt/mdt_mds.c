/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/mdt/mdt_mds.c
 *
 * Lustre Metadata Service Layer
 *
 * Author: Di Wang <di.wang@whamcloud.com>
 **/

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

#include <obd_support.h>
/* struct ptlrpc_request */
#include <lustre_net.h>
/* struct obd_export */
#include <lustre_export.h>
/* struct obd_device */
#include <obd.h>
/* lu2dt_dev() */
#include <dt_object.h>
#include <lustre_mds.h>
#include "mdt_internal.h"
#include <lustre_quota.h>
#include <lustre_acl.h>
#include <lustre_param.h>

struct mds_device {
	/* super-class */
	struct md_device	   mds_md_dev;
	struct ptlrpc_service     *mds_regular_service;
	struct ptlrpc_service     *mds_readpage_service;
	struct ptlrpc_service     *mds_out_service;
	struct ptlrpc_service     *mds_setattr_service;
	struct ptlrpc_service     *mds_mdsc_service;
	struct ptlrpc_service     *mds_mdss_service;
	struct ptlrpc_service     *mds_fld_service;
};

/*
 *  * Initialized in mdt_mod_init().
 *   */
static unsigned long mdt_num_threads;
CFS_MODULE_PARM(mdt_num_threads, "ul", ulong, 0444,
		"number of MDS service threads to start "
		"(deprecated in favor of mds_num_threads)");

static unsigned long mds_num_threads;
CFS_MODULE_PARM(mds_num_threads, "ul", ulong, 0444,
		"number of MDS service threads to start");

static char *mds_num_cpts;
CFS_MODULE_PARM(mds_num_cpts, "c", charp, 0444,
		"CPU partitions MDS threads should run on");

static unsigned long mds_rdpg_num_threads;
CFS_MODULE_PARM(mds_rdpg_num_threads, "ul", ulong, 0444,
		"number of MDS readpage service threads to start");

static char *mds_rdpg_num_cpts;
CFS_MODULE_PARM(mds_rdpg_num_cpts, "c", charp, 0444,
		"CPU partitions MDS readpage threads should run on");

/* NB: these two should be removed along with setattr service in the future */
static unsigned long mds_attr_num_threads;
CFS_MODULE_PARM(mds_attr_num_threads, "ul", ulong, 0444,
		"number of MDS setattr service threads to start");

static char *mds_attr_num_cpts;
CFS_MODULE_PARM(mds_attr_num_cpts, "c", charp, 0444,
		"CPU partitions MDS setattr threads should run on");

/* device init/fini methods */
static void mds_stop_ptlrpc_service(struct mds_device *m)
{
	ENTRY;
	if (m->mds_regular_service != NULL) {
		ptlrpc_unregister_service(m->mds_regular_service);
		m->mds_regular_service = NULL;
	}
	if (m->mds_readpage_service != NULL) {
		ptlrpc_unregister_service(m->mds_readpage_service);
		m->mds_readpage_service = NULL;
	}
	if (m->mds_out_service != NULL) {
		ptlrpc_unregister_service(m->mds_out_service);
		m->mds_out_service = NULL;
	}
	if (m->mds_setattr_service != NULL) {
		ptlrpc_unregister_service(m->mds_setattr_service);
		m->mds_setattr_service = NULL;
	}
	if (m->mds_mdsc_service != NULL) {
		ptlrpc_unregister_service(m->mds_mdsc_service);
		m->mds_mdsc_service = NULL;
	}
	if (m->mds_mdss_service != NULL) {
		ptlrpc_unregister_service(m->mds_mdss_service);
		m->mds_mdss_service = NULL;
	}
	if (m->mds_fld_service != NULL) {
		ptlrpc_unregister_service(m->mds_fld_service);
		m->mds_fld_service = NULL;
	}
	EXIT;
}

static int mds_start_ptlrpc_service(struct mds_device *m)
{
	static struct ptlrpc_service_conf conf;
	struct obd_device *obd = m->mds_md_dev.md_lu_dev.ld_obd;
	struct proc_dir_entry *procfs_entry;
	int rc = 0;
	ENTRY;

	procfs_entry = obd->obd_proc_entry;
	LASSERT(procfs_entry != NULL);

	conf = (typeof(conf)) {
		.psc_name		= LUSTRE_MDT_NAME,
		.psc_watchdog_factor	= MDT_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= MDS_NBUFS,
			.bc_buf_size		= MDS_REG_BUFSIZE,
			.bc_req_max_size	= MDS_REG_MAXREQSIZE,
			.bc_rep_max_size	= MDS_REG_MAXREPSIZE,
			.bc_req_portal		= MDS_REQUEST_PORTAL,
			.bc_rep_portal		= MDC_REPLY_PORTAL,
		},
		/*
		 * We'd like to have a mechanism to set this on a per-device
		 * basis, but alas...
		 */
		.psc_thr		= {
			.tc_thr_name		= LUSTRE_MDT_NAME,
			.tc_thr_factor		= MDS_THR_FACTOR,
			.tc_nthrs_init		= MDS_NTHRS_INIT,
			.tc_nthrs_base		= MDS_NTHRS_BASE,
			.tc_nthrs_max		= MDS_NTHRS_MAX,
			.tc_nthrs_user		= mds_num_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_MD_THREAD,
		},
		.psc_cpt		= {
			.cc_pattern		= mds_num_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= ptlrpc_hpreq_handler,
		},
	};
	m->mds_regular_service = ptlrpc_register_service(&conf, procfs_entry);
	if (IS_ERR(m->mds_regular_service)) {
		rc = PTR_ERR(m->mds_regular_service);
		CERROR("failed to start regular mdt service: %d\n", rc);
		m->mds_regular_service = NULL;

		RETURN(rc);
	}

	/*
	 * readpage service configuration. Parameters have to be adjusted,
	 * ideally.
	 */
	memset(&conf, 0, sizeof(conf));
	conf = (typeof(conf)) {
		.psc_name		= LUSTRE_MDT_NAME "_readpage",
		.psc_watchdog_factor	= MDT_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= MDS_NBUFS,
			.bc_buf_size		= MDS_BUFSIZE,
			.bc_req_max_size	= MDS_MAXREQSIZE,
			.bc_rep_max_size	= MDS_MAXREPSIZE,
			.bc_req_portal		= MDS_READPAGE_PORTAL,
			.bc_rep_portal		= MDC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= LUSTRE_MDT_NAME "_rdpg",
			.tc_thr_factor		= MDS_RDPG_THR_FACTOR,
			.tc_nthrs_init		= MDS_RDPG_NTHRS_INIT,
			.tc_nthrs_base		= MDS_RDPG_NTHRS_BASE,
			.tc_nthrs_max		= MDS_RDPG_NTHRS_MAX,
			.tc_nthrs_user		= mds_rdpg_num_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_MD_THREAD,
		},
		.psc_cpt		= {
			.cc_pattern		= mds_rdpg_num_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
		},
	};
	m->mds_readpage_service = ptlrpc_register_service(&conf, procfs_entry);
	if (IS_ERR(m->mds_readpage_service)) {
		rc = PTR_ERR(m->mds_readpage_service);
		CERROR("failed to start readpage service: %d\n", rc);
		m->mds_readpage_service = NULL;

		GOTO(err_mds_svc, rc);
	}

	/*
	 * setattr service configuration.
	 *
	 * XXX To keep the compatibility with old client(< 2.2), we need to
	 * preserve this portal for a certain time, it should be removed
	 * eventually. LU-617.
	 */
	memset(&conf, 0, sizeof(conf));
	conf = (typeof(conf)) {
		.psc_name		= LUSTRE_MDT_NAME "_setattr",
		.psc_watchdog_factor	= MDT_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= MDS_NBUFS,
			.bc_buf_size		= MDS_BUFSIZE,
			.bc_req_max_size	= MDS_MAXREQSIZE,
			.bc_rep_max_size	= MDS_LOV_MAXREPSIZE,
			.bc_req_portal		= MDS_SETATTR_PORTAL,
			.bc_rep_portal		= MDC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= LUSTRE_MDT_NAME "_attr",
			.tc_thr_factor		= MDS_SETA_THR_FACTOR,
			.tc_nthrs_init		= MDS_SETA_NTHRS_INIT,
			.tc_nthrs_base		= MDS_SETA_NTHRS_BASE,
			.tc_nthrs_max		= MDS_SETA_NTHRS_MAX,
			.tc_nthrs_user		= mds_attr_num_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_MD_THREAD,
		},
		.psc_cpt		= {
			.cc_pattern		= mds_attr_num_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= NULL,
		},
	};
	m->mds_setattr_service = ptlrpc_register_service(&conf, procfs_entry);
	if (IS_ERR(m->mds_setattr_service)) {
		rc = PTR_ERR(m->mds_setattr_service);
		CERROR("failed to start setattr service: %d\n", rc);
		m->mds_setattr_service = NULL;

		GOTO(err_mds_svc, rc);
	}

	/* Object update service */
	conf = (typeof(conf)) {
		.psc_name		= LUSTRE_MDT_NAME "_out",
		.psc_watchdog_factor	= MDT_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= MDS_NBUFS,
			.bc_buf_size		= OUT_BUFSIZE,
			.bc_req_max_size	= OUT_MAXREQSIZE,
			.bc_rep_max_size	= OUT_MAXREPSIZE,
			.bc_req_portal		= OUT_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		/*
		 * We'd like to have a mechanism to set this on a per-device
		 * basis, but alas...
		 */
		.psc_thr		= {
			.tc_thr_name		= LUSTRE_MDT_NAME "_out",
			.tc_thr_factor		= MDS_THR_FACTOR,
			.tc_nthrs_init		= MDS_NTHRS_INIT,
			.tc_nthrs_base		= MDS_NTHRS_BASE,
			.tc_nthrs_max		= MDS_NTHRS_MAX,
			.tc_nthrs_user		= mds_num_threads,
			.tc_cpu_affinity	= 1,
			.tc_ctx_tags		= LCT_MD_THREAD |
						  LCT_DT_THREAD,
		},
		.psc_cpt		= {
			.cc_pattern		= mds_num_cpts,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= NULL,
		},
	};
	m->mds_out_service = ptlrpc_register_service(&conf, procfs_entry);
	if (IS_ERR(m->mds_out_service)) {
		rc = PTR_ERR(m->mds_out_service);
		CERROR("failed to start out service: %d\n", rc);
		m->mds_out_service = NULL;
		GOTO(err_mds_svc, rc);
	}

	/*
	 * sequence controller service configuration
	 */
	memset(&conf, 0, sizeof(conf));
	conf = (typeof(conf)) {
		.psc_name		= LUSTRE_MDT_NAME "_seqs",
		.psc_watchdog_factor	= MDT_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= MDS_NBUFS,
			.bc_buf_size		= SEQ_BUFSIZE,
			.bc_req_max_size	= SEQ_MAXREQSIZE,
			.bc_rep_max_size	= SEQ_MAXREPSIZE,
			.bc_req_portal		= SEQ_CONTROLLER_PORTAL,
			.bc_rep_portal		= MDC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= LUSTRE_MDT_NAME "_seqs",
			.tc_nthrs_init		= MDS_OTHR_NTHRS_INIT,
			.tc_nthrs_max		= MDS_OTHR_NTHRS_MAX,
			.tc_ctx_tags		= LCT_MD_THREAD,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= NULL,
		},
	};
	m->mds_mdsc_service = ptlrpc_register_service(&conf, procfs_entry);
	if (IS_ERR(m->mds_mdsc_service)) {
		rc = PTR_ERR(m->mds_mdsc_service);
		CERROR("failed to start seq controller service: %d\n", rc);
		m->mds_mdsc_service = NULL;

		GOTO(err_mds_svc, rc);
	}

	/*
	 * metadata sequence server service configuration
	 */
	memset(&conf, 0, sizeof(conf));
	conf = (typeof(conf)) {
		.psc_name		= LUSTRE_MDT_NAME "_seqm",
		.psc_watchdog_factor	= MDT_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= MDS_NBUFS,
			.bc_buf_size		= SEQ_BUFSIZE,
			.bc_req_max_size	= SEQ_MAXREQSIZE,
			.bc_rep_max_size	= SEQ_MAXREPSIZE,
			.bc_req_portal		= SEQ_METADATA_PORTAL,
			.bc_rep_portal		= MDC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= LUSTRE_MDT_NAME "_seqm",
			.tc_nthrs_init		= MDS_OTHR_NTHRS_INIT,
			.tc_nthrs_max		= MDS_OTHR_NTHRS_MAX,
			.tc_ctx_tags		= LCT_MD_THREAD | LCT_DT_THREAD
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= NULL,
		},
	};
	m->mds_mdss_service = ptlrpc_register_service(&conf, procfs_entry);
	if (IS_ERR(m->mds_mdss_service)) {
		rc = PTR_ERR(m->mds_mdss_service);
		CERROR("failed to start metadata seq server service: %d\n", rc);
		m->mds_mdss_service = NULL;

		GOTO(err_mds_svc, rc);
	}

	/* FLD service start */
	memset(&conf, 0, sizeof(conf));
	conf = (typeof(conf)) {
		.psc_name	     = LUSTRE_MDT_NAME "_fld",
		.psc_watchdog_factor = MDT_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= MDS_NBUFS,
			.bc_buf_size		= FLD_BUFSIZE,
			.bc_req_max_size	= FLD_MAXREQSIZE,
			.bc_rep_max_size	= FLD_MAXREPSIZE,
			.bc_req_portal		= FLD_REQUEST_PORTAL,
			.bc_rep_portal		= MDC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= LUSTRE_MDT_NAME "_fld",
			.tc_nthrs_init		= MDS_OTHR_NTHRS_INIT,
			.tc_nthrs_max		= MDS_OTHR_NTHRS_MAX,
			.tc_ctx_tags		= LCT_DT_THREAD | LCT_MD_THREAD,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= NULL,
		},
	};
	m->mds_fld_service = ptlrpc_register_service(&conf, procfs_entry);
	if (IS_ERR(m->mds_fld_service)) {
		rc = PTR_ERR(m->mds_fld_service);
		CERROR("failed to start fld service: %d\n", rc);
		m->mds_fld_service = NULL;

		GOTO(err_mds_svc, rc);
	}

	EXIT;
err_mds_svc:
	if (rc)
		mds_stop_ptlrpc_service(m);

	return rc;
}

static inline struct mds_device *mds_dev(struct lu_device *d)
{
	return container_of0(d, struct mds_device, mds_md_dev.md_lu_dev);
}

static struct lu_device *mds_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct mds_device *m = mds_dev(d);
	struct obd_device *obd = d->ld_obd;
	ENTRY;

	mds_stop_ptlrpc_service(m);
	lprocfs_obd_cleanup(obd);
	RETURN(NULL);
}

static struct lu_device *mds_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct mds_device *m = mds_dev(d);
	ENTRY;

	md_device_fini(&m->mds_md_dev);
	OBD_FREE_PTR(m);
	RETURN(NULL);
}

LPROC_SEQ_FOPS_RO_TYPE(mds, uuid);

static struct lprocfs_seq_vars lprocfs_mds_obd_vars[] = {
	{ "uuid",	&mds_uuid_fops  },
	{ 0 }
};

static struct lu_device *mds_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct mds_device	 *m;
	struct obd_device	 *obd;
	struct lu_device	  *l;
	int rc;

	OBD_ALLOC_PTR(m);
	if (m == NULL)
		return ERR_PTR(-ENOMEM);

	md_device_init(&m->mds_md_dev, t);
	l = &m->mds_md_dev.md_lu_dev;

	obd = class_name2obd(lustre_cfg_string(cfg, 0));
	LASSERT(obd != NULL);

	l->ld_obd = obd;
	/* set this lu_device to obd, because error handling need it */
	obd->obd_lu_dev = l;

	obd->obd_vars = lprocfs_mds_obd_vars;
	rc = lprocfs_obd_setup(obd);
	if (rc != 0) {
		mds_device_free(env, l);
		l = ERR_PTR(rc);
		return l;
	}

	rc = mds_start_ptlrpc_service(m);

	if (rc != 0) {
		mds_device_free(env, l);
		l = ERR_PTR(rc);
		return l;
	}
	return l;
}

/* type constructor/destructor: mdt_type_init, mdt_type_fini */
LU_TYPE_INIT_FINI(mds, &mdt_thread_key);

static struct lu_device_type_operations mds_device_type_ops = {
	.ldto_init = mds_type_init,
	.ldto_fini = mds_type_fini,

	.ldto_start = mds_type_start,
	.ldto_stop  = mds_type_stop,

	.ldto_device_alloc = mds_device_alloc,
	.ldto_device_free  = mds_device_free,
	.ldto_device_fini  = mds_device_fini
};

static struct lu_device_type mds_device_type = {
	.ldt_tags     = LU_DEVICE_MD,
	.ldt_name     = LUSTRE_MDS_NAME,
	.ldt_ops      = &mds_device_type_ops,
	.ldt_ctx_tags = LCT_MD_THREAD
};

static struct obd_ops mds_obd_device_ops = {
	.o_owner	   = THIS_MODULE,
};

int mds_mod_init(void)
{
	if (mdt_num_threads != 0 && mds_num_threads == 0) {
		LCONSOLE_INFO("mdt_num_threads module parameter is deprecated, "
			      "use mds_num_threads instead or unset both for "
			      "dynamic thread startup\n");
		mds_num_threads = mdt_num_threads;
	}

	return class_register_type(&mds_obd_device_ops, NULL, true, NULL,
				   LUSTRE_MDS_NAME, &mds_device_type);
}

void mds_mod_exit(void)
{
	class_unregister_type(LUSTRE_MDS_NAME);
}
