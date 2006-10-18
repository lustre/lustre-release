/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2006 Cluster File Systems, Inc.
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
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/libcfs.h>
#ifndef __KERNEL__
#include <liblustre.h>
#include <libcfs/list.h>
#else
#include <linux/crypto.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

#ifdef __KERNEL__

struct proc_dir_entry *sptlrpc_proc_root = NULL;
EXPORT_SYMBOL(sptlrpc_proc_root);

void sec_flags2str(unsigned long flags, char *buf, int bufsize)
{
        buf[0] = '\0';

        if (flags & PTLRPC_SEC_FL_REVERSE)
                strncat(buf, "reverse,", bufsize);
        if (flags & PTLRPC_SEC_FL_ROOTONLY)
                strncat(buf, "rootonly,", bufsize);
        if (flags & PTLRPC_SEC_FL_BULK)
                strncat(buf, "bulk,", bufsize);
        if (flags & PTLRPC_SEC_FL_PAG)
                strncat(buf, "pag,", bufsize);
        if (buf[0] == '\0')
                strncat(buf, "-,", bufsize);

        buf[strlen(buf) - 1] = '\0';

}

int sptlrpc_lprocfs_rd(char *page, char **start, off_t off, int count,
                       int *eof, void *data)
{
        struct obd_device        *obd = data;
        struct sec_flavor_config *conf = &obd->u.cli.cl_sec_conf;
        struct ptlrpc_sec        *sec = NULL;
        struct ptlrpc_cli_ctx    *ctx;
        struct hlist_node        *pos, *next;
        char                      flags_str[32];
        int                       written, i;

        if (obd == NULL)
                return 0;

        LASSERT(strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) == 0 ||
                strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) == 0 ||
                strcmp(obd->obd_type->typ_name, LUSTRE_MGC_NAME) == 0);
        LASSERT(conf->sfc_bulk_csum < BULK_CSUM_ALG_MAX);
        LASSERT(conf->sfc_bulk_priv < BULK_PRIV_ALG_MAX);

        if (obd->u.cli.cl_import)
                sec = obd->u.cli.cl_import->imp_sec;

        if (sec == NULL) {
                written = snprintf(page, count, "\n");
                goto out;
        }

        sec_flags2str(sec->ps_flags, flags_str, sizeof(flags_str));

        written = snprintf(page, count,
                        "rpc msg flavor:        %s\n"
                        "bulk checksum:         %s\n"
                        "bulk encrypt:          %s\n"
                        "flags:                 %s\n"
                        "ctx cache size         %u\n"
                        "ctx cache busy         %d\n"
                        "gc interval            %lu\n"
                        "gc next                %ld\n",
                        sptlrpc_flavor2name(sec->ps_flavor),
                        sptlrpc_bulk_csum_alg2name(conf->sfc_bulk_csum),
                        sptlrpc_bulk_priv_alg2name(conf->sfc_bulk_priv),
                        flags_str,
                        sec->ps_ccache_size,
                        atomic_read(&sec->ps_busy),
                        sec->ps_gc_interval,
                        sec->ps_gc_interval ?
                                sec->ps_gc_next - cfs_time_current_sec() : 0
                          );
        /*
         * list contexts
         */
        if (sec->ps_policy->sp_policy != SPTLRPC_POLICY_GSS)
                goto out;

        written += snprintf(page + written, count - written,
                            "GSS contexts ==>\n");

        spin_lock(&sec->ps_lock);
        for (i = 0; i < sec->ps_ccache_size; i++) {
                hlist_for_each_entry_safe(ctx, pos, next,
                                          &sec->ps_ccache[i], cc_hash) {
                        if (written >= count)
                                break;
                        written += sptlrpc_ctx_display(ctx, page + written,
                                                       count - written);
                }
        }
        spin_unlock(&sec->ps_lock);

out:
        return written;
}
EXPORT_SYMBOL(sptlrpc_lprocfs_rd);

static struct lprocfs_vars sptlrpc_lprocfs_vars[] = {
        { "enc_pool", sptlrpc_proc_read_enc_pool, NULL, NULL },
        { NULL }
};

int sptlrpc_lproc_init(void)
{
        int     rc;

        LASSERT(sptlrpc_proc_root == NULL);

        sptlrpc_proc_root = lprocfs_register("sptlrpc", proc_lustre_root,
                                             sptlrpc_lprocfs_vars, NULL);
        if (IS_ERR(sptlrpc_proc_root)) {
                rc = PTR_ERR(sptlrpc_proc_root);
                sptlrpc_proc_root = NULL;
                return rc;
        }
        return 0;
}

void sptlrpc_lproc_fini(void)
{
        if (sptlrpc_proc_root) {
                lprocfs_remove(sptlrpc_proc_root);
                sptlrpc_proc_root = NULL;
        }
}

#else /* !__KERNEL__ */

int sptlrpc_lproc_init(void)
{
        return 0;
}

void sptlrpc_lproc_fini(void)
{
}

#endif
