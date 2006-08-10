/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fld/lproc_fld.c
 *  FLD (FIDs Location Database)
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
#include "fld_internal.h"

#ifdef LPROCFS
static int
fld_proc_read_targets(char *page, char **start, off_t off,
                      int count, int *eof, void *data)
{
        struct lu_client_fld *fld = (struct lu_client_fld *)data;
        struct fld_target *target;
	int total = 0, rc;
	ENTRY;

        LASSERT(fld != NULL);

        spin_lock(&fld->fld_lock);
        list_for_each_entry(target,
                            &fld->fld_targets, fldt_chain)
        {
                struct client_obd *cli = &target->fldt_exp->exp_obd->u.cli;
                
                rc = snprintf(page, count, "%s\n",
                              cli->cl_target_uuid.uuid);
                page += rc;
                count -= rc;
                total += rc;
                if (count == 0)
                        break;
        }
        spin_unlock(&fld->fld_lock);
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

        spin_lock(&fld->fld_lock);
        rc = snprintf(page, count, "%s\n",
                      fld->fld_hash->fh_name);
        spin_unlock(&fld->fld_lock);

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

        for (i = 0; i < ARRAY_SIZE(fld_hash); i++) {
                if (fld_hash[i].fh_name == NULL ||
                    count != strlen(fld_hash[i].fh_name))
                        continue;
                        
                if (!strncmp(fld_hash[i].fh_name, buffer, count)) {
                        hash = &fld_hash[i];
                        break;
                }
        }

        if (hash != NULL) {
                spin_lock(&fld->fld_lock);
                fld->fld_hash = hash;
                spin_unlock(&fld->fld_lock);

                CDEBUG(D_WARNING, "FLD(cli): changed hash to \"%s\"\n",
                       hash->fh_name);
        }
	
        RETURN(count);
}

struct lprocfs_vars fld_server_proc_list[] = {
	{ NULL }};

struct lprocfs_vars fld_client_proc_list[] = {
	{ "targets", fld_proc_read_targets, NULL, NULL },
	{ "hash",    fld_proc_read_hash, fld_proc_write_hash, NULL },
	{ NULL }};
#endif
