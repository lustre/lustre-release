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
/*
 * Note: this function is only used for testing, it is no safe for production
 * use.
 */
static int
seq_proc_write_common(struct file *file, const char *buffer,
                      unsigned long count, void *data,
                      struct lu_range *range)
{
	struct lu_range tmp;
	int rc;
	ENTRY;

	LASSERT(range != NULL);

        rc = sscanf(buffer, DRANGE"\n",
		    &tmp.lr_start, &tmp.lr_end);

	/* did not match 2 values */
	if (rc != 2 || !range_is_sane(&tmp) || range_is_zero(&tmp)) {
		CERROR("Can't parse input string or input is not correct\n");
		RETURN(-EINVAL);
	}

	*range = tmp;
        RETURN(0);
}

/*
 * Server side procfs stuff.
 */
static int
seq_proc_read_common(char *page, char **start, off_t off,
                     int count, int *eof, void *data,
                     struct lu_range *range)
{
	int rc;
	ENTRY;

        *eof = 1;
        rc = snprintf(page, count, DRANGE"]\n",
		      PRANGE(range));
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

	down(&seq->lss_sem);
	rc = seq_proc_write_common(file, buffer, count,
                                   data, &seq->lss_space);
	if (rc == 0) {
		CDEBUG(D_WARNING, "%s: sequences space has "
                       "changed to "DRANGE"\n", seq->lss_name,
                       PRANGE(&seq->lss_space));
	}
	
	up(&seq->lss_sem);
	
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

	down(&seq->lss_sem);
	rc = seq_proc_read_common(page, start, off, count, eof,
                                  data, &seq->lss_space);
	up(&seq->lss_sem);
	
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

	down(&seq->lss_sem);
	rc = seq_proc_write_common(file, buffer, count,
                                   data, &seq->lss_super);

	if (rc == 0) {
		CDEBUG(D_WARNING, "%s: super-sequence has "
                       "changed to "DRANGE"\n", seq->lss_name,
                       PRANGE(&seq->lss_super));
	}
	
	up(&seq->lss_sem);
	
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

	down(&seq->lss_sem);
	rc = seq_proc_read_common(page, start, off, count, eof,
                                  data, &seq->lss_super);
	up(&seq->lss_sem);
	
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
	if (seq->lss_cli) {
		struct obd_export *exp = seq->lss_cli->lcs_exp;

		rc = snprintf(page, count, "%s\n",
			      exp->exp_client_uuid.uuid);
	} else {
		rc = snprintf(page, count, "<not assigned>\n");
	}
	
	RETURN(rc);
}

static int
seq_proc_write_super_width(struct file *file, const char *buffer,
                           unsigned long count, void *data)
{
        struct lu_server_seq *seq = (struct lu_server_seq *)data;
	int rc, val;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->lss_sem);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                RETURN(rc);

        seq->lss_super_width = val;
        
	if (rc == 0) {
		CDEBUG(D_WARNING, "%s: super-sequence width "
                       "has changed to "LPU64"\n", seq->lss_name,
                       seq->lss_super_width);
	}
	
	up(&seq->lss_sem);
	
        RETURN(count);
}

static int
seq_proc_read_super_width(char *page, char **start, off_t off,
                          int count, int *eof, void *data)
{
        struct lu_server_seq *seq = (struct lu_server_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->lss_sem);
        rc = snprintf(page, count, LPU64"\n", seq->lss_super_width);
	up(&seq->lss_sem);
	
	RETURN(rc);
}

static int
seq_proc_write_meta_width(struct file *file, const char *buffer,
                          unsigned long count, void *data)
{
        struct lu_server_seq *seq = (struct lu_server_seq *)data;
	int rc, val;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->lss_sem);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                RETURN(rc);

        if (val <= seq->lss_super_width) {
                seq->lss_meta_width = val;
                
                if (rc == 0) {
                        CDEBUG(D_WARNING, "%s: meta-sequence width "
                               "has changed to "LPU64"\n", seq->lss_name, 
                               seq->lss_meta_width);
                }
        }
	
	up(&seq->lss_sem);
        RETURN(count);
}

static int
seq_proc_read_meta_width(char *page, char **start, off_t off,
                         int count, int *eof, void *data)
{
        struct lu_server_seq *seq = (struct lu_server_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->lss_sem);
        rc = snprintf(page, count, LPU64"\n", seq->lss_meta_width);
	up(&seq->lss_sem);
	
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

	down(&seq->lcs_sem);
	rc = seq_proc_write_common(file, buffer, count,
                                   data, &seq->lcs_range);

	if (rc == 0) {
		CDEBUG(D_WARNING, "%s: range has changed to "
		       DRANGE"\n", seq->lcs_name, 
                       PRANGE(&seq->lcs_range));
	}
	
	up(&seq->lcs_sem);
	
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

	down(&seq->lcs_sem);
	rc = seq_proc_read_common(page, start, off, count, eof,
                                  data, &seq->lcs_range);
	up(&seq->lcs_sem);
	
	RETURN(rc);
}

static int
seq_proc_write_seq_width(struct file *file, const char *buffer,
                         unsigned long count, void *data)
{
        struct lu_client_seq *seq = (struct lu_client_seq *)data;
	int rc, val;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->lcs_sem);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                RETURN(rc);

        if (val <= LUSTRE_SEQ_MAX_WIDTH) {
                seq->lcs_width = val;
                
                if (rc == 0) {
                        CDEBUG(D_WARNING, "%s: sequence width "
                               "has changed to "LPU64"\n", seq->lcs_name,
                               seq->lcs_width);
                }
        }
	
	up(&seq->lcs_sem);
	
        RETURN(count);
}

static int
seq_proc_read_seq_width(char *page, char **start, off_t off,
                        int count, int *eof, void *data)
{
        struct lu_client_seq *seq = (struct lu_client_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->lcs_sem);
        rc = snprintf(page, count, LPU64"\n", seq->lcs_width);
	up(&seq->lcs_sem);
	
	RETURN(rc);
}

static int
seq_proc_read_next_fid(char *page, char **start, off_t off,
                       int count, int *eof, void *data)
{
        struct lu_client_seq *seq = (struct lu_client_seq *)data;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);

	down(&seq->lcs_sem);
        rc = snprintf(page, count, DFID"\n", PFID(&seq->lcs_fid));
	up(&seq->lcs_sem);
	
	RETURN(rc);
}

static int
seq_proc_read_server(char *page, char **start, off_t off,
                     int count, int *eof, void *data)
{
        struct lu_client_seq *seq = (struct lu_client_seq *)data;
        struct client_obd *cli = &seq->lcs_exp->exp_obd->u.cli;
	int rc;
	ENTRY;

        LASSERT(seq != NULL);
        rc = snprintf(page, count, "%s\n",
                      cli->cl_target_uuid.uuid);
	RETURN(rc);
}

struct lprocfs_vars seq_server_proc_list[] = {
	{ "space",       seq_proc_read_space, seq_proc_write_space, NULL },
	{ "super",       seq_proc_read_super, seq_proc_write_super, NULL },
	{ "controller",  seq_proc_read_controller, NULL, NULL },
	{ "super_width", seq_proc_read_super_width, seq_proc_write_super_width, NULL },
	{ "meta_width",  seq_proc_read_meta_width, seq_proc_write_meta_width, NULL },
	{ NULL }};

struct lprocfs_vars seq_client_proc_list[] = {
	{ "range",      seq_proc_read_range, seq_proc_write_range, NULL },
	{ "server",     seq_proc_read_server, NULL, NULL },
	{ "next_fid" ,  seq_proc_read_next_fid, NULL, NULL },
	{ "seq_width",  seq_proc_read_seq_width, seq_proc_write_seq_width, NULL },
	{ NULL }};
#endif
