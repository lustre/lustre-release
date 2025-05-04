// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/version.h>
#include <linux/vfs.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "mgc_internal.h"

#ifdef CONFIG_PROC_FS

LDEBUGFS_SEQ_FOPS_RO_TYPE(mgc, connect_flags);

LDEBUGFS_SEQ_FOPS_RO_TYPE(mgc, server_uuid);

LDEBUGFS_SEQ_FOPS_RO_TYPE(mgc, import);

LDEBUGFS_SEQ_FOPS_RO_TYPE(mgc, state);

static int mgc_ir_state_seq_show(struct seq_file *m, void *v)
{
	return lprocfs_mgc_rd_ir_state(m, m->private);
}

LDEBUGFS_SEQ_FOPS_RO(mgc_ir_state);

static struct ldebugfs_vars ldebugfs_mgc_obd_vars[] = {
	{ .name	=	"connect_flags",
	  .fops	=	&mgc_connect_flags_fops	},
	{ .name	=	"mgs_server_uuid",
	  .fops	=	&mgc_server_uuid_fops	},
	{ .name	=	"import",
	  .fops	=	&mgc_import_fops	},
	{ .name	=	"state",
	  .fops	=	&mgc_state_fops		},
	{ .name	=	"ir_state",
	  .fops	=	&mgc_ir_state_fops	},
	{ NULL }
};
#endif /* CONFIG_PROC_FS */

LUSTRE_ATTR(mgs_conn_uuid, 0444, conn_uuid_show, NULL);
LUSTRE_RO_ATTR(conn_uuid);

LUSTRE_RW_ATTR(ping);

static ssize_t dynamic_nids_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	ssize_t count;

	ENTRY;
	count = snprintf(buf, PAGE_SIZE, "%u\n", obd->obd_dynamic_nids);

	RETURN(count);
}

static ssize_t dynamic_nids_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	ENTRY;
	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&obd->obd_dev_lock);
	obd->obd_dynamic_nids = val;
	spin_unlock(&obd->obd_dev_lock);

	RETURN(count);
}

LUSTRE_RW_ATTR(dynamic_nids);

LUSTRE_OBD_UINT_PARAM_ATTR(at_min);
LUSTRE_OBD_UINT_PARAM_ATTR(at_max);
LUSTRE_OBD_UINT_PARAM_ATTR(at_history);

static struct attribute *mgc_attrs[] = {
	&lustre_attr_mgs_conn_uuid.attr,
	&lustre_attr_conn_uuid.attr,
	&lustre_attr_ping.attr,
	&lustre_attr_dynamic_nids.attr,
	&lustre_attr_at_min.attr,
	&lustre_attr_at_max.attr,
	&lustre_attr_at_history.attr,
	NULL,
};

KOBJ_ATTRIBUTE_GROUPS(mgc);

int mgc_tunables_init(struct obd_device *obd)
{
	int rc;

	obd->obd_ktype.default_groups = KOBJ_ATTR_GROUPS(mgc);
	obd->obd_debugfs_vars = ldebugfs_mgc_obd_vars;
	rc = lprocfs_obd_setup(obd, true);
	if (rc)
		return rc;

	return sptlrpc_lprocfs_cliobd_attach(obd);
}
