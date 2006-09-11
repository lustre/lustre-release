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

#define PARAM_SYS_TIMEOUT          "sys.timeout="
#define PARAM_MGSNODE              "mgsnode="
#define PARAM_FAILNODE             "failover.node="
#define PARAM_FAILMODE             "failover.mode="
#define PARAM_OST                  "ost."
#define PARAM_OSC                  "osc."
#define PARAM_MDT                  "mdt."
#define PARAM_MDC                  "mdc."
#define PARAM_LLITE                "llite."
#define PARAM_LOV                  "lov."
/* LOV_STRIPE_* aren't settable in proc. But match the proc names. */
#define PARAM_LOV_STRIPE_SIZE      PARAM_LOV"stripesize="
#define PARAM_LOV_STRIPE_COUNT     PARAM_LOV"stripecount="
#define PARAM_LOV_STRIPE_OFFSET    PARAM_LOV"stripeoffset="
#define PARAM_LOV_STRIPE_PATTERN   PARAM_LOV"stripetype="
#define PARAM_SEC                  "security."
#define PARAM_SEC_RPC              PARAM_SEC"rpc."
#define PARAM_SEC_RPC_MDT          PARAM_SEC_RPC"mdt="
#define PARAM_SEC_RPC_CLI          PARAM_SEC_RPC"cli="

#endif // _LUSTRE_PARAM_H
