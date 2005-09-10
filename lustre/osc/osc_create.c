/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author Peter Braam <braam@clusterfs.com>
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
# include <linux/version.h>
# include <linux/module.h>
# include <linux/mm.h>
# include <linux/highmem.h>
# include <linux/ctype.h>
# include <linux/init.h>
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  include <linux/workqueue.h>
#  include <linux/smp_lock.h>
# else
#  include <linux/locks.h>
# endif
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#ifdef  __CYGWIN__
# include <ctype.h>
#endif

# include <linux/lustre_dlm.h>
#include <linux/obd_class.h>
#include "osc_internal.h"

int oscc_recovering(struct osc_creator *oscc)
{
        int recov = 0;

        spin_lock(&oscc->oscc_lock);
        recov = oscc->oscc_flags & OSCC_FLAG_RECOVERING;
        spin_unlock(&oscc->oscc_lock);

        return recov;
}

/* this only is used now for deleting orphanes */
int osc_create(struct obd_export *exp, struct obdo *oa,
               void *acl, int acl_size, struct lov_stripe_md **ea,
               struct obd_trans_info *oti)
{
        struct osc_creator *oscc = &exp->exp_obd->u.cli.cl_oscc;
        int rc = 0, try_again = 1;
        ENTRY;

        LASSERT(oa);
        LASSERT(ea);
        LASSERT(oa->o_gr > 0);
        LASSERT(oa->o_valid & OBD_MD_FLGROUP);
        LASSERT(acl == NULL && acl_size == 0);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        if (current->journal_info != NULL) {
                static int dump_counter = 0;
                CDEBUG(D_ERROR, "calling osc_create() with an "
                       "open transaction isn't a good idea\n");
                if (dump_counter++ % 100 == 0)
                        portals_debug_dumpstack(NULL);
        }
#endif

        if (oa->o_gr == FILTER_GROUP_LLOG || oa->o_gr == FILTER_GROUP_ECHO)
                RETURN(osc_real_create(exp, oa, ea, oti));

        /* this is the special case where create removes orphans */
        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            oa->o_flags == OBD_FL_DELORPHAN) {
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
                CDEBUG(D_HA, "%s; oscc recovery started\n",
                       exp->exp_obd->obd_name);
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
                        wake_up(&oscc->oscc_waitq);
                } else {
                        CDEBUG(D_ERROR, "%s: oscc recovery failed: %d\n",
                               oscc->oscc_obd->obd_name, rc);
                }
                spin_unlock(&oscc->oscc_lock);
                RETURN(rc);
        }

        while (try_again) {
                /* If orphans are being recovered, then we must wait until
                   it is finished before we can continue with create. */
                if (oscc_recovering(oscc)) {
                        struct l_wait_info lwi;

                        CDEBUG(D_HA,"%p: oscc recovery in progress, waiting\n",
                               oscc);

                        lwi = LWI_TIMEOUT(MAX(obd_timeout*HZ/4, 1), NULL, NULL);
                        rc = l_wait_event(oscc->oscc_waitq,
                                          !oscc_recovering(oscc), &lwi);
                        LASSERT(rc == 0 || rc == -ETIMEDOUT);
                        if (rc == -ETIMEDOUT) {
                                CDEBUG(D_ERROR,"%p: timeout waiting on recovery\n",
                                       oscc);
                                portals_debug_dumplog();
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
        init_waitqueue_head(&oscc->oscc_waitq);
}
