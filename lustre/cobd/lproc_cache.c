/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/lustre_lite.h>
#include <linux/lprocfs_status.h>

/*
 * Common STATUS namespace
 */

static int 
rd_uuid (char *page, char **start, off_t off, int count, 
	 int *eof, void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
	
        return (snprintf(page, count, "%s\n", dev->obd_uuid));
}

static int 
rd_target (char *page, char **start, off_t off, int count, 
	   int *eof, void *data)
{
        struct obd_device    *dev = (struct obd_device*)data;
        struct cache_obd     *cobd = &dev->u.cobd;
	struct lustre_handle *conn = &cobd->cobd_target;
	struct obd_export    *exp;
	int    rc;

	if ((dev->obd_flags & OBD_SET_UP) == 0)
		rc = snprintf (page, count, "not set up\n");
	else {
		exp = class_conn2export (conn);
		LASSERT (exp != NULL);
		rc = snprintf(page, count, "%s\n", exp->exp_obd->obd_uuid);
	}
	return (rc);
}

static int 
rd_cache (char *page, char **start, off_t off, int count, 
	  int *eof, void *data)
{
        struct obd_device    *dev = (struct obd_device*)data;
	struct cache_obd     *cobd = &dev->u.cobd;
	struct lustre_handle *conn = &cobd->cobd_cache;
	struct obd_export    *exp;
	int    rc;
	
	if ((dev->obd_flags & OBD_SET_UP) == 0)
		rc = snprintf (page, count, "not set up\n");
	else {
		exp = class_conn2export (conn);
		LASSERT (exp != NULL);
		rc = snprintf(page, count, "%s\n", exp->exp_obd->obd_uuid);
	}
	return (rc);
}

struct lprocfs_vars status_var_nm_1[] = {
        {"status/uuid", rd_uuid, 0, 0},
        {"status/target_uuid", rd_target, 0, 0},
        {"status/cache_uuid", rd_cache, 0, 0},
       
        {0}
};

int 
rd_numrefs (char* page, char **start, off_t off, int count, 
	    int *eof, void *data)
{
        struct obd_type* class = (struct obd_type*)data;

        return (snprintf(page, count, "%d\n", class->typ_refcnt));
}

struct lprocfs_vars status_class_var[] = {
        {"status/num_refs", rd_numrefs, 0, 0},
        {0}
};
