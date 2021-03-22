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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/ost/ost_handler.c
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_OST

#include <linux/module.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>
#include <obd_class.h>
#include "ost_internal.h"

int oss_max_threads = 512;
module_param(oss_max_threads, int, 0444);
MODULE_PARM_DESC(oss_max_threads, "maximum number of OSS service threads");

static int oss_num_threads;
module_param(oss_num_threads, int, 0444);
MODULE_PARM_DESC(oss_num_threads, "number of OSS service threads to start");

static unsigned int oss_cpu_bind = 1;
module_param(oss_cpu_bind, uint, 0444);
MODULE_PARM_DESC(oss_cpu_bind,
		 "bind OSS service threads to particular CPU partitions");

static int oss_num_create_threads;
module_param(oss_num_create_threads, int, 0444);
MODULE_PARM_DESC(oss_num_create_threads,
		 "number of OSS create threads to start");

static unsigned int oss_create_cpu_bind = 1;
module_param(oss_create_cpu_bind, uint, 0444);
MODULE_PARM_DESC(oss_create_cpu_bind,
		 "bind OSS create threads to particular CPU partitions");

static char *oss_cpts;
module_param(oss_cpts, charp, 0444);
MODULE_PARM_DESC(oss_cpts, "CPU partitions OSS threads should run on");

static char *oss_io_cpts;
module_param(oss_io_cpts, charp, 0444);
MODULE_PARM_DESC(oss_io_cpts, "CPU partitions OSS IO threads should run on");

#define OST_WATCHDOG_TIMEOUT (obd_timeout * 1000)

static struct cfs_cpt_table *ost_io_cptable;

/* Sigh - really, this is an OSS, the _server_, not the _target_ */
static int ost_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	static struct ptlrpc_service_conf svc_conf;
	struct ost_obd *ost = &obd->u.ost;
	nodemask_t *mask;
	int rc;

	ENTRY;

	rc = lprocfs_obd_setup(obd, true);
	if (rc)
		return rc;

	mutex_init(&ost->ost_health_mutex);

	svc_conf = (typeof(svc_conf)) {
		.psc_name		= LUSTRE_OSS_NAME,
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
			.bc_buf_size		= OST_BUFSIZE,
			.bc_req_max_size	= OST_MAXREQSIZE,
			.bc_rep_max_size	= OST_MAXREPSIZE,
			.bc_req_portal		= OST_REQUEST_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ll_ost",
			.tc_thr_factor		= OSS_THR_FACTOR,
			.tc_nthrs_init		= OSS_NTHRS_INIT,
			.tc_nthrs_base		= OSS_NTHRS_BASE,
			.tc_nthrs_max		= oss_max_threads,
			.tc_nthrs_user		= oss_num_threads,
			.tc_cpu_bind		= oss_cpu_bind,
			.tc_ctx_tags		= LCT_DT_THREAD,
		},
		.psc_cpt                = {
			.cc_pattern             = oss_cpts,
			.cc_affinity		= true,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= ptlrpc_hpreq_handler,
		},
	};
	ost->ost_service = ptlrpc_register_service(&svc_conf,
						   &obd->obd_kset,
						   obd->obd_debugfs_entry);
	if (IS_ERR(ost->ost_service)) {
		rc = PTR_ERR(ost->ost_service);
		CERROR("failed to start service: %d\n", rc);
		GOTO(out_lprocfs, rc);
	}

	memset(&svc_conf, 0, sizeof(svc_conf));
	svc_conf = (typeof(svc_conf)) {
		.psc_name		= "ost_create",
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
			.bc_buf_size		= OST_BUFSIZE,
			.bc_req_max_size	= OST_MAXREQSIZE,
			.bc_rep_max_size	= OST_MAXREPSIZE,
			.bc_req_portal		= OST_CREATE_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ll_ost_create",
			.tc_thr_factor		= OSS_CR_THR_FACTOR,
			.tc_nthrs_init		= OSS_CR_NTHRS_INIT,
			.tc_nthrs_base		= OSS_CR_NTHRS_BASE,
			.tc_nthrs_max		= OSS_CR_NTHRS_MAX,
			.tc_nthrs_user		= oss_num_create_threads,
			.tc_cpu_bind		= oss_create_cpu_bind,
			.tc_ctx_tags		= LCT_DT_THREAD,
		},
		.psc_cpt                = {
			.cc_pattern             = oss_cpts,
			.cc_affinity		= true,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
		},
	};
	ost->ost_create_service = ptlrpc_register_service(&svc_conf,
							  &obd->obd_kset,
							  obd->obd_debugfs_entry
							  );
	if (IS_ERR(ost->ost_create_service)) {
		rc = PTR_ERR(ost->ost_create_service);
		CERROR("failed to start OST create service: %d\n", rc);
		GOTO(out_service, rc);
	}

	mask = cfs_cpt_nodemask(cfs_cpt_tab, CFS_CPT_ANY);
	/* event CPT feature is disabled in libcfs level by set partition
	 * number to 1, we still want to set node affinity for io service
	 */
	if (cfs_cpt_number(cfs_cpt_tab) == 1 && nodes_weight(*mask) > 1) {
		int	cpt = 0;
		int	i;

		ost_io_cptable = cfs_cpt_table_alloc(nodes_weight(*mask));
		for_each_node_mask(i, *mask) {
			if (!ost_io_cptable) {
				CWARN("OSS failed to create CPT table\n");
				break;
			}

			rc = cfs_cpt_set_node(ost_io_cptable, cpt++, i);
			if (!rc) {
				CWARN("OSS Failed to set node %d for IO CPT table\n",
				      i);
				cfs_cpt_table_free(ost_io_cptable);
				ost_io_cptable = NULL;
				break;
			}
		}
	}

	memset(&svc_conf, 0, sizeof(svc_conf));
	svc_conf = (typeof(svc_conf)) {
		.psc_name		= "ost_io",
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
			.bc_buf_size		= OST_IO_BUFSIZE,
			.bc_req_max_size	= OST_IO_MAXREQSIZE,
			.bc_rep_max_size	= OST_IO_MAXREPSIZE,
			.bc_req_portal		= OST_IO_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ll_ost_io",
			.tc_thr_factor		= OSS_THR_FACTOR,
			.tc_nthrs_init		= OSS_NTHRS_INIT,
			.tc_nthrs_base		= OSS_NTHRS_BASE,
			.tc_nthrs_max		= oss_max_threads,
			.tc_nthrs_user		= oss_num_threads,
			.tc_cpu_bind		= oss_cpu_bind,
			.tc_ctx_tags		= LCT_DT_THREAD,
		},
		.psc_cpt		= {
			.cc_cptable		= ost_io_cptable,
			.cc_pattern		= ost_io_cptable == NULL ?
						  oss_io_cpts : NULL,
			.cc_affinity		= true,
		},
		.psc_ops		= {
			.so_thr_init		= tgt_io_thread_init,
			.so_thr_done		= tgt_io_thread_done,
			.so_req_handler		= tgt_request_handle,
			.so_hpreq_handler	= tgt_hpreq_handler,
			.so_req_printer		= target_print_req,
		},
	};
	ost->ost_io_service = ptlrpc_register_service(&svc_conf,
						      &obd->obd_kset,
						      obd->obd_debugfs_entry);
	if (IS_ERR(ost->ost_io_service)) {
		rc = PTR_ERR(ost->ost_io_service);
		CERROR("failed to start OST I/O service: %d\n", rc);
		ost->ost_io_service = NULL;
		GOTO(out_create, rc);
	}

	memset(&svc_conf, 0, sizeof(svc_conf));
	svc_conf = (typeof(svc_conf)) {
		.psc_name		= "ost_seq",
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
			.bc_buf_size		= OST_BUFSIZE,
			.bc_req_max_size	= OST_MAXREQSIZE,
			.bc_rep_max_size	= OST_MAXREPSIZE,
			.bc_req_portal		= SEQ_DATA_PORTAL,
			.bc_rep_portal		= OSC_REPLY_PORTAL,
		},
		.psc_thr		= {
			.tc_thr_name		= "ll_ost_seq",
			.tc_thr_factor		= OSS_CR_THR_FACTOR,
			.tc_nthrs_init		= OSS_CR_NTHRS_INIT,
			.tc_nthrs_base		= OSS_CR_NTHRS_BASE,
			.tc_nthrs_max		= OSS_CR_NTHRS_MAX,
			.tc_nthrs_user		= oss_num_create_threads,
			.tc_cpu_bind		= oss_create_cpu_bind,
			.tc_ctx_tags		= LCT_DT_THREAD,
		},

		.psc_cpt		= {
			.cc_pattern		= oss_cpts,
			.cc_affinity		= true,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= NULL,
		},
	};
	ost->ost_seq_service = ptlrpc_register_service(&svc_conf,
						       &obd->obd_kset,
						       obd->obd_debugfs_entry);
	if (IS_ERR(ost->ost_seq_service)) {
		rc = PTR_ERR(ost->ost_seq_service);
		CERROR("failed to start OST seq service: %d\n", rc);
		ost->ost_seq_service = NULL;
		GOTO(out_io, rc);
	}

	/* Object update service */
	memset(&svc_conf, 0, sizeof(svc_conf));
	svc_conf = (typeof(svc_conf)) {
		.psc_name		= "ost_out",
		.psc_watchdog_factor	= OSS_SERVICE_WATCHDOG_FACTOR,
		.psc_buf		= {
			.bc_nbufs		= OST_NBUFS,
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
			.tc_thr_name		= "ll_ost_out",
			.tc_thr_factor		= OSS_CR_THR_FACTOR,
			.tc_nthrs_init		= OSS_CR_NTHRS_INIT,
			.tc_nthrs_base		= OSS_CR_NTHRS_BASE,
			.tc_nthrs_max		= OSS_CR_NTHRS_MAX,
			.tc_nthrs_user		= oss_num_create_threads,
			.tc_cpu_bind		= oss_create_cpu_bind,
			.tc_ctx_tags		= LCT_MD_THREAD |
						  LCT_DT_THREAD,
		},
		.psc_cpt		= {
			.cc_pattern		= oss_cpts,
			.cc_affinity		= true,
		},
		.psc_ops		= {
			.so_req_handler		= tgt_request_handle,
			.so_req_printer		= target_print_req,
			.so_hpreq_handler	= NULL,
		},
	};
	ost->ost_out_service = ptlrpc_register_service(&svc_conf,
						       &obd->obd_kset,
						       obd->obd_debugfs_entry);
	if (IS_ERR(ost->ost_out_service)) {
		rc = PTR_ERR(ost->ost_out_service);
		CERROR("failed to start out service: %d\n", rc);
		ost->ost_out_service = NULL;
		GOTO(out_seq, rc);
	}

	ping_evictor_start();

	RETURN(0);

out_seq:
	ptlrpc_unregister_service(ost->ost_seq_service);
	ost->ost_seq_service = NULL;
out_io:
	ptlrpc_unregister_service(ost->ost_io_service);
	ost->ost_io_service = NULL;
out_create:
	ptlrpc_unregister_service(ost->ost_create_service);
	ost->ost_create_service = NULL;
out_service:
	ptlrpc_unregister_service(ost->ost_service);
	ost->ost_service = NULL;
out_lprocfs:
	lprocfs_obd_cleanup(obd);
	RETURN(rc);
}

static int ost_cleanup(struct obd_device *obd)
{
	struct ost_obd *ost = &obd->u.ost;
	int err = 0;

	ENTRY;

	ping_evictor_stop();

	/* there is no recovery for OST OBD, all recovery is controlled by
	 * obdfilter OBD
	 */
	LASSERT(obd->obd_recovering == 0);
	mutex_lock(&ost->ost_health_mutex);
	ptlrpc_unregister_service(ost->ost_service);
	ptlrpc_unregister_service(ost->ost_create_service);
	ptlrpc_unregister_service(ost->ost_io_service);
	ptlrpc_unregister_service(ost->ost_seq_service);
	ptlrpc_unregister_service(ost->ost_out_service);

	ost->ost_service = NULL;
	ost->ost_create_service = NULL;
	ost->ost_io_service = NULL;
	ost->ost_seq_service = NULL;
	ost->ost_out_service = NULL;

	mutex_unlock(&ost->ost_health_mutex);

	lprocfs_obd_cleanup(obd);

	if (ost_io_cptable) {
		cfs_cpt_table_free(ost_io_cptable);
		ost_io_cptable = NULL;
	}

	RETURN(err);
}

static int ost_health_check(const struct lu_env *env, struct obd_device *obd)
{
	struct ost_obd *ost = &obd->u.ost;
	int rc = 0;

	mutex_lock(&ost->ost_health_mutex);
	rc |= ptlrpc_service_health_check(ost->ost_service);
	rc |= ptlrpc_service_health_check(ost->ost_create_service);
	rc |= ptlrpc_service_health_check(ost->ost_io_service);
	rc |= ptlrpc_service_health_check(ost->ost_seq_service);
	mutex_unlock(&ost->ost_health_mutex);

	return rc != 0 ? 1 : 0;
}

/* use obd ops to offer management infrastructure */
static const struct obd_ops ost_obd_ops = {
	.o_owner        = THIS_MODULE,
	.o_setup        = ost_setup,
	.o_cleanup      = ost_cleanup,
	.o_health_check = ost_health_check,
};

static int __init ost_init(void)
{
	int rc;

	ENTRY;

	rc = class_register_type(&ost_obd_ops, NULL, false,
				 LUSTRE_OSS_NAME, NULL);

	RETURN(rc);
}

static void __exit ost_exit(void)
{
	class_unregister_type(LUSTRE_OSS_NAME);
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Object Storage Target (OST)");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(ost_init);
module_exit(ost_exit);
