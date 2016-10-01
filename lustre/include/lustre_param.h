/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/lustre_param.h
 *
 * User-settable parameter keys
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#ifndef _LUSTRE_PARAM_H
#define _LUSTRE_PARAM_H

#include <libcfs/libcfs.h>
#include <lnet/types.h>

/** \defgroup param param
 *
 * @{
 */

/* For interoperability */
struct cfg_interop_param {
	char *old_param;
	char *new_param;
};

/* obd_config.c */
int class_find_param(char *buf, char *key, char **valp);
struct cfg_interop_param *class_find_old_param(const char *param,
					       struct cfg_interop_param *ptr);
int class_get_next_param(char **params, char *copy);
int class_match_param(char *buf, const char *key, char **valp);
int class_parse_nid(char *buf, lnet_nid_t *nid, char **endh);
int class_parse_nid_quiet(char *buf, lnet_nid_t *nid, char **endh);
int class_parse_net(char *buf, __u32 *net, char **endh);
int class_match_nid(char *buf, char *key, lnet_nid_t nid);
int class_match_net(char *buf, char *key, __u32 net);
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

/* System global or special params not handled in obd's proc
 * See mgs_write_log_sys()
 */
#define PARAM_TIMEOUT              "timeout="          /* global */
#define PARAM_LDLM_TIMEOUT         "ldlm_timeout="     /* global */
#define PARAM_AT_MIN               "at_min="           /* global */
#define PARAM_AT_MAX               "at_max="           /* global */
#define PARAM_AT_EXTRA             "at_extra="         /* global */
#define PARAM_AT_EARLY_MARGIN      "at_early_margin="  /* global */
#define PARAM_AT_HISTORY           "at_history="       /* global */
#define PARAM_JOBID_VAR		   "jobid_var="	       /* global */
#define PARAM_MGSNODE              "mgsnode="          /* only at mounttime */
#define PARAM_FAILNODE             "failover.node="    /* add failover nid */
#define PARAM_FAILMODE             "failover.mode="    /* initial mount only */
#define PARAM_ACTIVE               "active="           /* activate/deactivate */
#define PARAM_NETWORK              "network="          /* bind on nid */
#define PARAM_ID_UPCALL		"identity_upcall="  /* identity upcall */

/* Prefixes for parameters handled by obd's proc methods (XXX_process_config) */
#define PARAM_OST		"ost."
#define PARAM_OSD		"osd."
#define PARAM_OSC		"osc."
#define PARAM_MDT		"mdt."
#define PARAM_HSM		"mdt.hsm."
#define PARAM_MDD		"mdd."
#define PARAM_MDC		"mdc."
#define PARAM_LLITE		"llite."
#define PARAM_LOV		"lov."
#define PARAM_LOD		"lod."
#define PARAM_OSP		"osp."
#define PARAM_SYS		"sys."		/* global */
#define PARAM_SRPC		"srpc."
#define PARAM_SRPC_FLVR		"srpc.flavor."
#define PARAM_SRPC_UDESC	"srpc.udesc.cli2mdt"
#define PARAM_SEC		"security."
#define PARAM_QUOTA		"quota."	/* global */

/** @} param */

#define LUSTRE_MAXFSNAME	8

/**
 * Check whether the name is valid.
 *
 * \param name [in]	the name to be checked
 * \param minlen [in]	the minimum length of the name
 * \param maxlen [in]	the maximum length of the name
 *
 * \retval 0	the name is valid
 * \retval >0	the invalid character in the name
 * \retval -1	the name is too short
 * \retval -2	the name is too long
 */
static inline int lustre_is_name_valid(const char *name, const int minlen,
				       const int maxlen)
{
	const char	*tmp;
	size_t		len;

	len = strlen(name);

	if (len < minlen)
		return -1;

	if (len > maxlen)
		return -2;

	for (tmp = name; *tmp != '\0'; ++tmp) {
		if (isalnum(*tmp) || *tmp == '_' || *tmp == '-')
			continue;
		else
			break;
	}

	return *tmp == '\0' ? 0 : *tmp;
}

/**
 * Check whether the fsname is valid.
 *
 * \param fsname [in]	the fsname to be checked
 * \param minlen [in]	the minimum length of the fsname
 * \param maxlen [in]	the maximum length of the fsname
 *
 * \retval 0	the fsname is valid
 * \retval >0	the invalid character in the fsname
 * \retval -1	the fsname is too short
 * \retval -2	the fsname is too long
 */
static inline int lustre_is_fsname_valid(const char *fsname, const int minlen,
					 const int maxlen)
{
	return lustre_is_name_valid(fsname, minlen, maxlen);
}

/**
 * Check whether the poolname is valid.
 *
 * \param poolname [in]	the poolname to be checked
 * \param minlen [in]	the minimum length of the poolname
 * \param maxlen [in]	the maximum length of the poolname
 *
 * \retval 0	the poolname is valid
 * \retval >0	the invalid character in the poolname
 * \retval -1	the poolname is too short
 * \retval -2	the poolname is too long
 */
static inline int lustre_is_poolname_valid(const char *poolname,
					   const int minlen, const int maxlen)
{
	return lustre_is_name_valid(poolname, minlen, maxlen);
}

#endif /* _LUSTRE_PARAM_H */
