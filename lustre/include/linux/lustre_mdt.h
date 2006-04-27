/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_MDT_H
#define _LUSTRE_MDT_H

#ifdef __KERNEL__
# include <linux/fs.h>
# include <linux/dcache.h>
#endif
#include <linux/lustre_handles.h>
#include <libcfs/kp30.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_export.h>


struct mdt_reint_record {
        __u32 rr_opcode;
        struct lu_fid *rr_fid1;
        struct lu_fid *rr_fid2;
        int rr_namelen;
        char *rr_name;
        int rr_tgtlen;
        char *rr_tgt;
        int rr_eadatalen;
        void *rr_eadata;
        int rr_cookielen;
        struct llog_cookie *rr_logcookies;
        struct lvfs_ucred rr_uc;
        __u64 rr_rdev;
        __u64 rr_time;
        __u32 rr_mode;
        __u32 rr_flags;
};

#endif
