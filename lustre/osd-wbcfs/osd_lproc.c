// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Author: Timothy Day <timday@amazon.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre_scrub.h>

#include "osd_internal.h"

static struct attribute *wbcfs_attrs[] = {
	NULL
};

static struct ldebugfs_vars ldebugfs_osd_obd_vars[] = {
	{ 0 }
};

KOBJ_ATTRIBUTE_GROUPS(wbcfs);

int osd_procfs_init(struct osd_device *osd, const char *name)
{
	struct obd_type *type;
	int rc;

	ENTRY;

	/* at the moment there is no linkage between lu_type
	 * and obd_type, so we lookup obd_type this way
	 */
	type = class_search_type(LUSTRE_OSD_WBCFS_NAME);

	LASSERT(type);
	LASSERT(name);

	/* put reference taken by class_search_type */
	kobject_put(&type->typ_kobj);

	osd->od_dt_dev.dd_ktype.default_groups = KOBJ_ATTR_GROUPS(wbcfs);
	rc = dt_tunables_init(&osd->od_dt_dev, type, name,
			      ldebugfs_osd_obd_vars);
	if (rc) {
		CERROR("%s: cannot setup sysfs / debugfs entry: %d\n",
		       name, rc);
		osd_procfs_fini(osd);
	}

	RETURN(rc);
}

void osd_procfs_fini(struct osd_device *osd)
{
	dt_tunables_fini(&osd->od_dt_dev);
}
