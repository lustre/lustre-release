/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Nathan Rutman <nathan@clusterfs.com>
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
 *
 * User-settable parameter keys
 */

#ifndef _LUSTRE_PARAM_H
#define _LUSTRE_PARAM_H

/* obd_config.c */
int class_find_param(char *buf, char *key, char **valp);
int class_match_param(char *buf, char *key, char **valp);
int class_parse_nid(char *buf, lnet_nid_t *nid, char **endh);
/* obd_mount.c */
int do_lcfg(char *cfgname, lnet_nid_t nid, int cmd,
            char *s1, char *s2, char *s3, char *s4);



/****************** User-settable parameter keys *********************/
/* e.g. 
        tunefs.lustre --param="failover.node=192.168.0.13@tcp0" /dev/sda
        lctl conf_param testfs-OST0000 failover.node=3@elan,192.168.0.3@tcp0
                    ... testfs-MDT0000.lov.stripesize=4M
                    ... testfs-OST0000.ost.client_cache_seconds=15
                    ... testfs.sys.timeout=<secs> 
                    ... testfs.llite.max_read_ahead_mb=16
*/

/* System global or special params not handled in obd's proc */
#define PARAM_SYS_TIMEOUT          "sys.timeout="      /* global */
#define PARAM_MGSNODE              "mgsnode="          /* during mount */
#define PARAM_FAILNODE             "failover.node="    /* llog generation */
#define PARAM_FAILMODE             "failover.mode="    /* llog generation */
#define PARAM_ACTIVE               "active="           /* llog generation */
#define PARAM_MDT_UPCALL           "mdt.group_upcall=" /* mds group upcall */

/* Prefixes for parameters handled by obd's proc methods (XXX_process_config) */
#define PARAM_OST                  "ost."
#define PARAM_OSC                  "osc."
#define PARAM_MDT                  "mdt."
#define PARAM_MDC                  "mdc."
#define PARAM_LLITE                "llite."
#define PARAM_LOV                  "lov."
#define PARAM_SEC                  "security."
#define PARAM_SEC_RPC              PARAM_SEC"rpc."
#define PARAM_SEC_RPC_MDT          PARAM_SEC_RPC"mdt="
#define PARAM_SEC_RPC_CLI          PARAM_SEC_RPC"cli="

#endif /* _LUSTRE_PARAM_H */
