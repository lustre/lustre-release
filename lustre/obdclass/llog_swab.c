/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004-2005 Cluster File Systems, Inc.
 *   Author: jacob berkman  <jacob@clusterfs.com>
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
 * Swabbing of llog datatypes (from disk or over the wire).
 *
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <linux/lustre_log.h>

static void print_llogd_body(struct llogd_body *d)
{
        CDEBUG(D_OTHER, "llogd body: %p\n", d);
        CDEBUG(D_OTHER, "\tlgd_logid.lgl_oid: "LPX64"\n", d->lgd_logid.lgl_oid);
        CDEBUG(D_OTHER, "\tlgd_logid.lgl_ogr: "LPX64"\n", d->lgd_logid.lgl_ogr);
        CDEBUG(D_OTHER, "\tlgd_logid.lgl_ogen: %#x\n", d->lgd_logid.lgl_ogen);
        CDEBUG(D_OTHER, "\tlgd_ctxt_idx: %#x\n", d->lgd_ctxt_idx);
        CDEBUG(D_OTHER, "\tlgd_llh_flags: %#x\n", d->lgd_llh_flags);
        CDEBUG(D_OTHER, "\tlgd_index: %#x\n", d->lgd_index);
        CDEBUG(D_OTHER, "\tlgd_saved_index: %#x\n", d->lgd_saved_index);
        CDEBUG(D_OTHER, "\tlgd_len: %#x\n", d->lgd_len);
        CDEBUG(D_OTHER, "\tlgd_cur_offset: "LPX64"\n", d->lgd_cur_offset);
}

void lustre_swab_llogd_body (struct llogd_body *d)
{
        ENTRY;
        print_llogd_body(d);
        __swab64s (&d->lgd_logid.lgl_oid);
        __swab64s (&d->lgd_logid.lgl_ogr);
        __swab32s (&d->lgd_logid.lgl_ogen);
        __swab32s (&d->lgd_ctxt_idx);
        __swab32s (&d->lgd_llh_flags);
        __swab32s (&d->lgd_index);
        __swab32s (&d->lgd_saved_index);
        __swab32s (&d->lgd_len);
        __swab64s (&d->lgd_cur_offset);
        print_llogd_body(d);
        EXIT;
}
EXPORT_SYMBOL(lustre_swab_llogd_body);

void lustre_swab_llogd_conn_body (struct llogd_conn_body *d)
{
        __swab64s (&d->lgdc_gen.mnt_cnt);
        __swab64s (&d->lgdc_gen.conn_cnt);
        __swab64s (&d->lgdc_logid.lgl_oid);
        __swab64s (&d->lgdc_logid.lgl_ogr);
        __swab32s (&d->lgdc_logid.lgl_ogen);
        __swab32s (&d->lgdc_ctxt_idx);
}
EXPORT_SYMBOL(lustre_swab_llogd_conn_body);

void lustre_swab_llog_hdr (struct llog_log_hdr *h)
{
        __swab32s (&h->llh_hdr.lrh_index);
        __swab32s (&h->llh_hdr.lrh_len);
        __swab32s (&h->llh_hdr.lrh_type);
        __swab64s (&h->llh_timestamp);
        __swab32s (&h->llh_count);
        __swab32s (&h->llh_bitmap_offset);
        __swab32s (&h->llh_flags);
        __swab32s (&h->llh_tail.lrt_index);
        __swab32s (&h->llh_tail.lrt_len);
}
EXPORT_SYMBOL(lustre_swab_llog_hdr);

#define PRINT_PCFG32(x) CDEBUG(D_OTHER, "\tpcfg->pcfg_"#x": %#x\n", pcfg->pcfg_##x)
#define PRINT_PCFG64(x) CDEBUG(D_OTHER, "\tpcfg->pcfg_"#x": "LPX64"\n", pcfg->pcfg_##x)

static void print_portals_cfg(struct portals_cfg *pcfg)
{
        ENTRY;

        if (!(portal_debug & D_OTHER)) /* don't loop on nothing */
                return;
        CDEBUG(D_OTHER, "portals_cfg: %p\n", pcfg);
        PRINT_PCFG32(version);
        PRINT_PCFG32(command);

        PRINT_PCFG32(nal);
        PRINT_PCFG32(flags);

        PRINT_PCFG32(gw_nal);
        PRINT_PCFG64(nid);
        PRINT_PCFG64(nid2);
        PRINT_PCFG64(nid3);
        PRINT_PCFG32(id);
        PRINT_PCFG32(misc);
        PRINT_PCFG32(fd);
        PRINT_PCFG32(count);
        PRINT_PCFG32(size);
        PRINT_PCFG32(wait);

        PRINT_PCFG32(plen1);
        PRINT_PCFG32(plen2);

        EXIT;
}

void lustre_swab_portals_cfg(struct portals_cfg *pcfg)
{
        ENTRY;

        __swab32s(&pcfg->pcfg_version);
        __swab32s(&pcfg->pcfg_command);

        __swab32s(&pcfg->pcfg_nal);
        __swab32s(&pcfg->pcfg_flags);

        __swab32s(&pcfg->pcfg_gw_nal);
        __swab64s(&pcfg->pcfg_nid);
        __swab64s(&pcfg->pcfg_nid2);
        __swab64s(&pcfg->pcfg_nid3);
        __swab32s(&pcfg->pcfg_id);
        __swab32s(&pcfg->pcfg_misc);
        __swab32s(&pcfg->pcfg_fd);
        __swab32s(&pcfg->pcfg_count);
        __swab32s(&pcfg->pcfg_size);
        __swab32s(&pcfg->pcfg_wait);

        __swab32s(&pcfg->pcfg_plen1);
        __swab32s(&pcfg->pcfg_plen2);

        print_portals_cfg(pcfg);
        EXIT;
}
EXPORT_SYMBOL(lustre_swab_portals_cfg);

static void print_lustre_cfg(struct lustre_cfg *lcfg)
{
        int i;
        ENTRY;

        if (!(portal_debug & D_OTHER)) /* don't loop on nothing */
                return;
        CDEBUG(D_OTHER, "lustre_cfg: %p\n", lcfg);
        CDEBUG(D_OTHER, "\tlcfg->lcfg_version: %#x\n", lcfg->lcfg_version);

        CDEBUG(D_OTHER, "\tlcfg->lcfg_command: %#x\n", lcfg->lcfg_command);
        CDEBUG(D_OTHER, "\tlcfg->lcfg_num: %#x\n", lcfg->lcfg_num);
        CDEBUG(D_OTHER, "\tlcfg->lcfg_flags: %#x\n", lcfg->lcfg_flags);
        CDEBUG(D_OTHER, "\tlcfg->lcfg_nid: "LPX64"\n", lcfg->lcfg_nid);
        CDEBUG(D_OTHER, "\tlcfg->lcfg_nal: %#x\n", lcfg->lcfg_nal);

        CDEBUG(D_OTHER, "\tlcfg->lcfg_bufcount: %d\n", lcfg->lcfg_bufcount);
        if (lcfg->lcfg_bufcount < LUSTRE_CFG_MAX_BUFCOUNT)
                for (i = 0; i < lcfg->lcfg_bufcount; i++)
                        CDEBUG(D_OTHER, "\tlcfg->lcfg_buflens[%d]: %d\n",
                               i, lcfg->lcfg_buflens[i]);
        EXIT;
}

void lustre_swab_lustre_cfg(struct lustre_cfg *lcfg)
{
        int i;
        ENTRY;

        __swab32s(&lcfg->lcfg_version);

        if (lcfg->lcfg_version != LUSTRE_CFG_VERSION) {
                CERROR("not swabbing lustre_cfg version %#x (expecting %#x)\n",
                       lcfg->lcfg_version, LUSTRE_CFG_VERSION);
                EXIT;
                return;
        }

        __swab32s(&lcfg->lcfg_command);

        __swab32s(&lcfg->lcfg_num);
        __swab32s(&lcfg->lcfg_flags);
        __swab64s(&lcfg->lcfg_nid);
        __swab32s(&lcfg->lcfg_nal);

        __swab32s(&lcfg->lcfg_bufcount);
        for (i = 0; i < lcfg->lcfg_bufcount && i < LUSTRE_CFG_MAX_BUFCOUNT; i++)
                __swab32s(&lcfg->lcfg_buflens[i]);

        print_lustre_cfg(lcfg);
        EXIT;
        return;
}
EXPORT_SYMBOL(lustre_swab_lustre_cfg);
