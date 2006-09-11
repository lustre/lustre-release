/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author Peter Braam <braam@clusterfs.com>
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
 *
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC
#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/random.h>
#else
#include <liblustre.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre/lustre_idl.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lprocfs_status.h>
#include <lustre_sec.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"

static struct proc_dir_entry *gss_proc_root = NULL;

static int gss_proc_write_secinit(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        int rc;

        rc = gss_do_ctx_init_rpc((char *) buffer, count);
        if (rc) {
                LASSERT(rc < 0);
                return rc;
        }

        return ((int) count);
}

static struct lprocfs_vars gss_lprocfs_vars[] = {
        { "init_channel", NULL, gss_proc_write_secinit, NULL },
        { NULL }
};

int gss_init_lproc(void)
{
        int rc;
        gss_proc_root = lprocfs_register("gss", proc_lustre_root,
                                         gss_lprocfs_vars, NULL);

        if (IS_ERR(gss_proc_root)) {
                rc = PTR_ERR(gss_proc_root);
                gss_proc_root = NULL;
                CERROR("failed to initialize lproc entries: %d\n", rc);
                return rc;
        }

        return 0;
}

void gss_exit_lproc(void)
{
        if (gss_proc_root) {
                lprocfs_remove(gss_proc_root);
                gss_proc_root = NULL;
        }
}
