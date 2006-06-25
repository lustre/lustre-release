/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fid/lproc_fid.c
 *  Lustre Sequence Manager
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_FID

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
#include <lustre_fid.h>
#include "fid_internal.h"

#ifdef LPROCFS
/* server side procfs stuff */
static int
seq_proc_write_common(struct file *file, const char *buffer,
                      unsigned long count, void *data,
                      struct lu_range *range)
{
	struct lu_range tmp;
	int rc;
	ENTRY;

	LASSERT(range != NULL);

        rc = sscanf(buffer, "["LPU64"-"LPU64"]\n",
		    &tmp.lr_start, &tmp.lr_end);

	/* did not match 2 values */
	if (rc != 2 || !range_is_sane(&tmp) || range_is_zero(&tmp)) {
		CERROR("can't parse input string or "
		       "input is not correct\n");
		RETURN(-EINVAL);
	}

	*range = tmp;
        RETURN(0);
}

static int
seq_proc_read_common(char *page, char **start, off_t off,
                     int count, int *eof, void *data,
                     struct lu_range *range)
{
	int rc;
	ENTRY;

        *eof = 1;
        rc = snprintf(page, count, "["LPU64"-"LPU64"]\n",
		      range->lr_start, range->lr_end);
	RETURN(rc);
}

static int
seq_proc_write_space(struct file *file, const char *buffer,
		     unsigned long count, void *data)
{
        struct lu_server_seq *seq = (struct lu_server_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->seq_sem);
	rc = seq_proc_write_common(file, buffer, count,
                                   data, &seq->seq_space);
	if (rc == 0) {
		CDEBUG(D_WARNING, "SEQ-MGR(srv): sequences space has changed "
		       "to ["LPU64"-"LPU64"]\n", seq->seq_space.lr_start,
		       seq->seq_space.lr_end);
	}
	
	up(&seq->seq_sem);
	
        RETURN(count);
}

static int
seq_proc_read_space(char *page, char **start, off_t off,
		    int count, int *eof, void *data)
{
        struct lu_server_seq *seq = (struct lu_server_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->seq_sem);
	rc = seq_proc_read_common(page, start, off, count, eof,
                                  data, &seq->seq_space);
	up(&seq->seq_sem);
	
	RETURN(rc);
}

static int
seq_proc_write_super(struct file *file, const char *buffer,
		     unsigned long count, void *data)
{
        struct lu_server_seq *seq = (struct lu_server_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->seq_sem);
	rc = seq_proc_write_common(file, buffer, count,
                                   data, &seq->seq_super);

	if (rc == 0) {
		CDEBUG(D_WARNING, "SEQ-MGR(srv): super-sequence has changed to "
		       "["LPU64"-"LPU64"]\n", seq->seq_super.lr_start,
		       seq->seq_super.lr_end);
	}
	
	up(&seq->seq_sem);
	
        RETURN(count);
}

static int
seq_proc_read_super(char *page, char **start, off_t off,
		    int count, int *eof, void *data)
{
        struct lu_server_seq *seq = (struct lu_server_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->seq_sem);
	rc = seq_proc_read_common(page, start, off, count, eof,
                                  data, &seq->seq_super);
	up(&seq->seq_sem);
	
	RETURN(rc);
}

static int
seq_proc_read_controller(char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
        struct lu_server_seq *seq = (struct lu_server_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	*eof = 1;
	if (seq->seq_cli) {
		struct obd_export *exp = seq->seq_cli->seq_exp;

		rc = snprintf(page, count, "%s\n",
			      exp->exp_client_uuid.uuid);
	} else {
		rc = snprintf(page, count, "<not assigned>\n");
	}
	
	RETURN(rc);
}

/* client side procfs stuff */
static int
seq_proc_write_range(struct file *file, const char *buffer,
                     unsigned long count, void *data)
{
        struct lu_client_seq *seq = (struct lu_client_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->seq_sem);
	rc = seq_proc_write_common(file, buffer, count,
                                   data, &seq->seq_range);

	if (rc == 0) {
		CDEBUG(D_WARNING, "SEQ-MGR(cli): meta-sequence has changed to "
		       "["LPU64"-"LPU64"]\n", seq->seq_range.lr_start,
		       seq->seq_range.lr_end);
	}
	
	up(&seq->seq_sem);
	
        RETURN(count);
}

static int
seq_proc_read_range(char *page, char **start, off_t off,
                    int count, int *eof, void *data)
{
        struct lu_client_seq *seq = (struct lu_client_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->seq_sem);
	rc = seq_proc_read_common(page, start, off, count, eof,
                                  data, &seq->seq_range);
	up(&seq->seq_sem);
	
	RETURN(rc);
}

struct lprocfs_vars seq_server_proc_list[] = {
	{ "space",      seq_proc_read_space, seq_proc_write_space, NULL },
	{ "super",      seq_proc_read_super, seq_proc_write_super, NULL },
	{ "controller", seq_proc_read_controller, NULL, NULL },
	{ NULL }};

struct lprocfs_vars seq_client_proc_list[] = {
	{ "range",      seq_proc_read_range, seq_proc_write_range, NULL },
	{ NULL }};
#endif
