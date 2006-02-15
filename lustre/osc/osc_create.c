/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author Peter Braam <braam@clusterfs.com>
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
 *
 *  For testing and management it is treated as an obd_device,
 *  although * it does not export a full OBD method table (the
 *  requests are coming * in over the wire, so object target modules
 *  do not have a full * method table.)
 *
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#ifdef  __CYGWIN__
# include <ctype.h>
#endif

# include <lustre_dlm.h>
#include <obd_class.h>
#include "osc_internal.h"

int oscc_recovering(struct osc_creator *oscc)
{
        int recov = 0;

        spin_lock(&oscc->oscc_lock);
        recov = oscc->oscc_flags & OSCC_FLAG_RECOVERING;
        spin_unlock(&oscc->oscc_lock);

        return recov;
}

static int osc_check_state(struct obd_export *exp)
{
        int rc;
        ENTRY;

        /* ->os_state contains positive error code on remote OST. To convert it
         * to usual errno form we have to make an sign inversion. */
        spin_lock(&exp->exp_obd->obd_osfs_lock);
        rc = -exp->exp_obd->obd_osfs.os_state;
        spin_unlock(&exp->exp_obd->obd_osfs_lock);
        
        RETURN(rc);
}

static int osc_check_nospc(struct obd_export *exp)
{
        __u64 blocks, bavail;
        int rc = 0;
        ENTRY;

        spin_lock(&exp->exp_obd->obd_osfs_lock);
        blocks = exp->exp_obd->obd_osfs.os_blocks;
        bavail = exp->exp_obd->obd_osfs.os_bavail;
        spin_unlock(&exp->exp_obd->obd_osfs_lock);
        
        /* return 1 if available space smaller then (blocks >> 10) of all space
         * on OST. The main point of this water mark is to stop create files at
         * some point, to let all created and opened files finish possible
         * writes. */
        if (blocks > 0 && bavail < (blocks >> 10))
                rc = 1;

        RETURN(rc);
}

int osc_create(struct obd_export *exp, struct obdo *oa,
               struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct osc_creator *oscc = &exp->exp_obd->u.cli.cl_oscc;
        int try_again = 1, rc = 0;
        ENTRY;

        LASSERT(oa != NULL);
        LASSERT(ea != NULL);
        
        /* this is the special case where create removes orphans */
        if (oa->o_valid & OBD_MD_FLFLAGS && oa->o_flags == OBD_FL_DELORPHAN) {
                spin_lock(&oscc->oscc_lock);
                if (oscc->oscc_flags & OSCC_FLAG_SYNC_IN_PROGRESS) {
                        spin_unlock(&oscc->oscc_lock);
                        return -EBUSY;
                }
                if (!(oscc->oscc_flags & OSCC_FLAG_RECOVERING)) {
                        spin_unlock(&oscc->oscc_lock);
                        return 0;
                }
                oscc->oscc_flags |= OSCC_FLAG_SYNC_IN_PROGRESS;
                spin_unlock(&oscc->oscc_lock);
                CDEBUG(D_HA, "%s: oscc recovery started\n",
                       oscc->oscc_obd->obd_name);
                LASSERT(oscc->oscc_flags & OSCC_FLAG_RECOVERING);

                CDEBUG(D_HA, "%s: deleting to next_id: "LPU64"\n",
                       oscc->oscc_obd->obd_name, oa->o_id);

                rc = osc_real_create(exp, oa, ea, NULL);
                if (oscc->oscc_obd == NULL) {
                        CWARN("the obd for oscc %p has been freed\n", oscc);
                        RETURN(rc);
                }

                spin_lock(&oscc->oscc_lock);
                oscc->oscc_flags &= ~OSCC_FLAG_SYNC_IN_PROGRESS;
                if (rc == 0 || rc == -ENOSPC) {
                        if (rc == -ENOSPC)
                                oscc->oscc_flags |= OSCC_FLAG_NOSPC;
                        oscc->oscc_flags &= ~OSCC_FLAG_RECOVERING;
                        CDEBUG(D_HA, "%s: oscc recovery finished: %d\n",
                               oscc->oscc_obd->obd_name, rc);
                        cfs_waitq_signal(&oscc->oscc_waitq);
                } else {
                        CDEBUG(D_ERROR, "%s: oscc recovery failed: %d\n",
                               oscc->oscc_obd->obd_name, rc);
                }
                spin_unlock(&oscc->oscc_lock);
                RETURN(rc);
        }

        LASSERT(ergo(oa->o_valid & OBD_MD_FLFLAGS,
                     !!(oa->o_flags & OBD_FL_CREATE_CROW) !=
                     !!(oa->o_flags & OBD_FL_RECREATE_OBJS)));

        /* perform urgent create if asked or import is not crow capable or
         * ENOSPC case if detected. */
        if (OBDO_URGENT_CREATE(oa) || !IMP_CROW_ABLE(class_exp2cliimp(exp)) ||
            osc_check_nospc(exp)) {
                CDEBUG(D_HA, "perform urgent create\n");
                oa->o_flags &= ~OBD_FL_CREATE_CROW;
                if (!oa->o_flags)
                        oa->o_valid &= ~OBD_MD_FLFLAGS;
                rc = osc_real_create(exp, oa, ea, oti);
                RETURN(rc);
        }

        /* check OST fs state. */
        rc = osc_check_state(exp);
        if (rc) { 
                CDEBUG(D_HA,"OST is in bad shape to create objects, err %d\n",
                       rc);
                RETURN(rc);
        }
        
        while (try_again) {
                /* if orphans are being recovered, then we must wait until it is
                 * finished before we can continue with create. */
                if (oscc_recovering(oscc)) {
                        struct l_wait_info lwi;

                        CDEBUG(D_HA,"%p: oscc recovery in progress, waiting\n",
                               oscc);

                        lwi = LWI_TIMEOUT(cfs_timeout_cap(cfs_time_seconds(obd_timeout/4)),
                                          NULL, NULL);
                        rc = l_wait_event(oscc->oscc_waitq,
                                          !oscc_recovering(oscc), &lwi);
                        LASSERT(rc == 0 || rc == -ETIMEDOUT);
                        if (rc == -ETIMEDOUT) {
                                CDEBUG(D_HA, "%p: timeout waiting on recovery\n",
                                       oscc);
                                RETURN(rc);
                        }
                        CDEBUG(D_HA, "%p: oscc recovery over, waking up\n",
                               oscc);
                }

                spin_lock(&oscc->oscc_lock);
                if (oscc->oscc_flags & OSCC_FLAG_EXITING) {
                        spin_unlock(&oscc->oscc_lock);
                        break;
                }

                if (oscc->oscc_flags & OSCC_FLAG_NOSPC) {
                        rc = -ENOSPC;
                        spin_unlock(&oscc->oscc_lock);
                        break;
                }

                oscc->oscc_next_id++;
                oa->o_id = oscc->oscc_next_id;
                try_again = 0;
                spin_unlock(&oscc->oscc_lock);

                CDEBUG(D_HA, "%s: returning objid "LPU64"\n",
                       oscc->oscc_obd->u.cli.cl_import->imp_target_uuid.uuid,
                       oa->o_id);
        }

        RETURN(rc);
}

void oscc_init(struct obd_device *obd)
{
        struct osc_creator *oscc;

        if (obd == NULL)
                return;

        oscc = &obd->u.cli.cl_oscc;
        memset(oscc, 0, sizeof(*oscc));

        oscc->oscc_obd = obd;
        spin_lock_init(&oscc->oscc_lock);
        oscc->oscc_flags |= OSCC_FLAG_RECOVERING;
        cfs_waitq_init(&oscc->oscc_waitq);
}
