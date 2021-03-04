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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/gss/lsupport.h
 */

#ifndef __LSUPPORT_H__
#define __LSUPPORT_H__

#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include <libcfs/util/list.h>
#include <linux/lnet/lnet-types.h>
#include <linux/lnet/nidstr.h>

#define GSSD_CLI        (0)
#define GSSD_SVC        (1)

void gssd_init_unique(int type);
void gssd_exit_unique(int type);

/*
 * copied from lustre source
 */

#define LUSTRE_GSS_SVC_MGS      0
#define LUSTRE_GSS_SVC_MDS      1
#define LUSTRE_GSS_SVC_OSS      2

#define LUSTRE_GSS_SVC_MASK	0x0000FFFF
#define LUSTRE_GSS_MECH_MASK	0xFFFF0000
#define LUSTRE_GSS_MECH_SHIFT	16

extern const char * lustre_svc_name[];

enum lgss_mech {
	LGSS_MECH_KRB5  = 0,
	LGSS_MECH_NULL  = 1,
	LGSS_MECH_SK    = 2,
};

enum {
	/* sec part flags */
	LGSS_ROOT_CRED_ROOT     = 0x01,
	LGSS_ROOT_CRED_MDT      = 0x02,
	LGSS_ROOT_CRED_OST      = 0x04,
	/* service type flags */
	LGSS_SVC_NULL		= 0x10,
	LGSS_SVC_AUTH		= 0x20,
	LGSS_SVC_INTG		= 0x40,
	LGSS_SVC_PRIV		= 0x80,
	/* Number of sec part flags */
	LGSS_ROOT_CRED_NR       = 3,
};

struct lgssd_upcall_data {
        uint32_t        seq;
        uint32_t        uid;
        uint32_t        gid;
        uint32_t        svc;
        uint64_t        nid;
        char            obd[64];
};

#define GSSD_INTERFACE_VERSION          GSSD_INTERFACE_VERSION_V2
#define GSSD_INTERFACE_VERSION_V2       (2)
#define GSSD_INTERFACE_VERSION_V1       (1)

struct lgssd_ioctl_param {
        int             version;        /* in   */
        int             secid;          /* in   */
        char           *uuid;           /* in   */
        int             lustre_svc;     /* in   */
        uid_t           uid;            /* in   */
        gid_t           gid;            /* in   */
        long            send_token_size;/* in   */
        char           *send_token;     /* in   */
        long            reply_buf_size; /* in   */
        char           *reply_buf;      /* in   */
        long            status;         /* out  */
        long            reply_length;   /* out  */
};

#define GSSD_DEFAULT_GETHOSTNAME_EX     "/etc/lustre/nid2hostname"
#define MAPPING_DATABASE_FILE           "/etc/lustre/idmap.conf"

int lnet_nid2hostname(lnet_nid_t nid, char *buf, int buflen);
void cleanup_mapping(void);
int lookup_mapping(char *princ, lnet_nid_t nid, uid_t *uid);

#endif /* __LSUPPORT_H__ */
