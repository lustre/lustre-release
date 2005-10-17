/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2005 Cluster File Systems, Inc.
 *   Author LinSongTao <lincent@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org
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
 *  For testing and management it is treated as an obd_device,
 *  although * it does not export a full OBD method table (the
 *  requests are coming * in over the wire, so object target modules
 *  do not have a full * method table.)
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MGC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
# include <linux/miscdevice.h>
# include <linux/init.h>
#else
# include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_disk.h>

#include "mgc_internal.h"

int mgc_get_process_llog(struct obd_device *obd, char *llog_name,
                         struct config_llog_instance *cfg)
{
        struct llog_ctxt *ctxt;

        ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);

        rc = class_config_parse_llog(ctxt, llog_name, cfg);

        if (!rc) {
                if (rc == -EINVAL)
                        LCONSOLE_ERROR("%s: The configuration '%s' could not " 
                                       "be read from the MGS.  Make sure this " 
                                       "client and the MGS are running " 
                                       "compatible versions of Lustre.\n",
                                       obd->obd_name, llog_name);
                else
                        CERROR("class_config_parse_llog failed: rc = %d\n", rc);
        }
        return 0;
}

EXPORT_SYMBOL(mgc_get_process_llog)
