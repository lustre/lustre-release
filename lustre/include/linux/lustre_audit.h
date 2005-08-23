/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc. <info@clusterfs.com>
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
 *   smfs data structures.
 *   See also lustre_idl.h for wire formats of requests.
 *
 */

#ifndef __LUSTRE_AUDIT_H
#define __LUSTRE_AUDIT_H

/* Audit plugin stuff */
#define AUDIT_MDS_NAME    "audit_mds"
#define AUDIT_OST_NAME    "audit_ost"
#define AUDIT_CLI_NAME    "audit_client-"
#define AUDIT_ATTR_EA     "audit"
#define AUDIT_ATTR_FILE   "audit_setting"
//AUDIT OPCODES, also bit number in audit_setting mask

typedef enum {
        AUDIT_NONE = 0,
        AUDIT_CREATE,
        AUDIT_LINK,
        AUDIT_UNLINK,
        AUDIT_RENAME,
        AUDIT_SETATTR,
        AUDIT_WRITE,
        AUDIT_READ,
        AUDIT_OPEN,
        AUDIT_STAT,
        AUDIT_MMAP,
        AUDIT_READLINK,
        AUDIT_READDIR,
        AUDIT_MAX,
} audit_op;

#define AUDIT_FAIL AUDIT_MAX
#define AUDIT_DIR  (AUDIT_MAX + 1)
#define AUDIT_FS   (AUDIT_MAX + 2)

#define AUD_BIT(a) (1 << a)

#define AUDIT_ALL_OPS ((1 << AUDIT_MAX) - 1)
#define AUDIT_OFF 0

#define IS_AUDIT_OP(mask,op) (mask & (1<<op))
#define IS_AUDIT(mask) (mask & AUDIT_ALL_OPS)
#define SET_AUDIT_OP(mask,op) (mask |= (1<<op))

//llog audit record 24 bytes
struct audit_record {
        __u64 nid;
        __u32 uid;
        __u32 gid;
        __u32 time;
        __u16 opcode;
        __u16 result;
} __attribute__ ((packed));

//32 bytes
struct audit_id_record {
        __u64 au_num;
        __u64 au_fid;
        __u32 au_gen;
        __u32 au_type;
        __u64 au_mds;
} __attribute__ ((packed));

//1 + namelen
struct audit_name_record {
        __u8 name_len;
        char name[0];
} __attribute__ ((packed));

struct audit_info {
        struct audit_msg m;
        char * name;
        __u32 namelen;
};

struct audit_lov_msg {
        struct lov_stripe_md * lsm;
        __u64 mask;
        uid_t uid;
        gid_t gid;
};

#endif
