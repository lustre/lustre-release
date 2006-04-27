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

/* obd_mount.c */
int class_find_param(char *buf, char *key, char **valp);
int class_match_param(char *buf, char *key, char **valp);
int class_parse_nid(char *buf, lnet_nid_t *nid, char **endh);


/****************** User-settable parameter keys *********************/

#define PARAM_MGSNODE          "mgsnode="
#define PARAM_FAILNODE         "failnode="
#define PARAM_OBD_TIMEOUT      "obd_timeout="
#define PARAM_DEFAULT_STRIPE   "default_stripe_"
#define PARAM_D_STRIPE_SIZE    PARAM_DEFAULT_STRIPE"size"
#define PARAM_D_STRIPE_COUNT   PARAM_DEFAULT_STRIPE"count"
#define PARAM_D_STRIPE_OFFSET  PARAM_DEFAULT_STRIPE"offset"
#define PARAM_D_STRIPE_PATTERN PARAM_DEFAULT_STRIPE"pattern"

#endif // _LUSTRE_PARAM_H
