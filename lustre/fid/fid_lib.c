/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fid/fid_lib.c
 *  Miscellaneous fid functions.
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *           Yury Umanets <umka@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_FID

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/module.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <obd.h>
#include <lu_object.h>
#include <lustre_fid.h>

/*
 * Sequence space, starts from 0x400 to have first 0x400 sequences used for
 * special purposes. This means that if we have seq-with 10000 fids, we have
 * ~10M fids reserved for special purposes (igifs, etc.).
 */
const struct lu_range LUSTRE_SEQ_SPACE_RANGE = {
        (0x400),
        ((__u64)~0ULL)
};
EXPORT_SYMBOL(LUSTRE_SEQ_SPACE_RANGE);

/* Zero range, used for init and other purposes. */
const struct lu_range LUSTRE_SEQ_ZERO_RANGE = {
        0,
        0
};
EXPORT_SYMBOL(LUSTRE_SEQ_ZERO_RANGE);

/* Lustre Big Fs Lock fid. */
const struct lu_fid LUSTRE_BFL_FID = { .f_seq = 0x0000000000000003, 
                                       .f_oid = 0x0000000000000001,
                                       .f_ver = 0x0000000000000000 };
EXPORT_SYMBOL(LUSTRE_BFL_FID);

void fid_cpu_to_le(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        dst->f_seq = cpu_to_le64(fid_seq(src));
        dst->f_oid = cpu_to_le32(fid_oid(src));
        dst->f_ver = cpu_to_le32(fid_ver(src));
}
EXPORT_SYMBOL(fid_cpu_to_le);

void fid_le_to_cpu(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        dst->f_seq = le64_to_cpu(fid_seq(src));
        dst->f_oid = le32_to_cpu(fid_oid(src));
        dst->f_ver = le32_to_cpu(fid_ver(src));
}
EXPORT_SYMBOL(fid_le_to_cpu);

#ifdef __KERNEL__
void fid_cpu_to_be(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        dst->f_seq = cpu_to_be64(fid_seq(src));
        dst->f_oid = cpu_to_be32(fid_oid(src));
        dst->f_ver = cpu_to_be32(fid_ver(src));
}
EXPORT_SYMBOL(fid_cpu_to_be);

void fid_be_to_cpu(struct lu_fid *dst, const struct lu_fid *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof fid_seq(src) +
                 sizeof fid_oid(src) + sizeof fid_ver(src));
        dst->f_seq = be64_to_cpu(fid_seq(src));
        dst->f_oid = be32_to_cpu(fid_oid(src));
        dst->f_ver = be32_to_cpu(fid_ver(src));
}
EXPORT_SYMBOL(fid_be_to_cpu);
#endif

void range_cpu_to_le(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = cpu_to_le64(src->lr_start);
        dst->lr_end = cpu_to_le64(src->lr_end);
}
EXPORT_SYMBOL(range_cpu_to_le);

void range_le_to_cpu(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = le64_to_cpu(src->lr_start);
        dst->lr_end = le64_to_cpu(src->lr_end);
}
EXPORT_SYMBOL(range_le_to_cpu);

#ifdef __KERNEL__
void range_cpu_to_be(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = cpu_to_be64(src->lr_start);
        dst->lr_end = cpu_to_be64(src->lr_end);
}
EXPORT_SYMBOL(range_cpu_to_be);

void range_be_to_cpu(struct lu_range *dst, const struct lu_range *src)
{
        /* check that all fields are converted */
        CLASSERT(sizeof *src ==
                 sizeof src->lr_start +
                 sizeof src->lr_end);
        dst->lr_start = be64_to_cpu(src->lr_start);
        dst->lr_end = be64_to_cpu(src->lr_end);
}
EXPORT_SYMBOL(range_be_to_cpu);
#endif

/* issues dlm lock on passed @ns, @f stores it lock handle into @lh. */
int fid_lock(struct ldlm_namespace *ns, const struct lu_fid *f,
             struct lustre_handle *lh, ldlm_mode_t mode,
             ldlm_policy_data_t *policy,
             struct ldlm_res_id *res_id)
{
        int flags = LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB;
        int rc;

        LASSERT(ns != NULL);
        LASSERT(lh != NULL);
        LASSERT(f != NULL);

        rc = ldlm_cli_enqueue_local(ns, *fid_build_res_name(f, res_id),
                                    LDLM_IBITS, policy, mode, &flags,
                                    ldlm_blocking_ast, ldlm_completion_ast,
                                    NULL, NULL, 0, NULL, lh);
        return rc == ELDLM_OK ? 0 : -EIO;
}
EXPORT_SYMBOL(fid_lock);

void fid_unlock(const struct lu_fid *f,
                struct lustre_handle *lh, ldlm_mode_t mode)
{
        {
                /* XXX: this is debug stuff, remove it later. */
                struct ldlm_lock *lock = ldlm_handle2lock(lh);
                if (!lock) {
                        CERROR("Invalid lock handle "LPX64"\n",
                               lh->cookie);
                        LBUG();
                }
                LASSERT(fid_res_name_eq(f, &lock->l_resource->lr_name));
                LDLM_LOCK_PUT(lock);
        }
        ldlm_lock_decref(lh, mode);
}
EXPORT_SYMBOL(fid_unlock);

