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
# include <linux/lustre_dlm.h>
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  include <linux/workqueue.h>
#  include <linux/smp_lock.h>
# else
#  include <linux/locks.h>
# endif
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#ifndef  __CYGWIN__
# include <linux/ctype.h>
# include <linux/init.h>
#else
# include <ctype.h>
#endif

#include <linux/obd_class.h>
#include "osc_internal.h"

static int osc_interpret_create(struct ptlrpc_request *req, void *data,
                                int rc)
{
        struct osc_creator *oscc;
        struct ost_body *body = NULL;
        ENTRY;

        if (req->rq_repmsg) {
                body = lustre_swab_repbuf(req, 0, sizeof(*body),
                                          lustre_swab_ost_body);
                if (body == NULL && rc == 0)
                        rc = -EPROTO;
        }

        oscc = req->rq_async_args.pointer_arg[0];
        spin_lock(&oscc->oscc_lock);
        if (body)
                oscc->oscc_last_id = body->oa.o_id;
        if (rc == -ENOSPC) {
                DEBUG_REQ(D_INODE, req, "OST out of space, flagging");
                oscc->oscc_flags |= OSCC_FLAG_NOSPC;
        } else if (rc != 0 && rc != -EIO) {
                DEBUG_REQ(D_ERROR, req,
                          "unknown rc %d from async create: failing oscc",
                          rc);
                oscc->oscc_flags |= OSCC_FLAG_RECOVERING;
                ptlrpc_fail_import(req->rq_import, req->rq_import_generation);
        }
        oscc->oscc_flags &= ~OSCC_FLAG_CREATING;
        spin_unlock(&oscc->oscc_lock);

        CDEBUG(D_INFO, "preallocated through id "LPU64" (last used "LPU64")\n",
               oscc->oscc_last_id, oscc->oscc_next_id);

        wake_up(&oscc->oscc_waitq);
        RETURN(rc);
}

static int oscc_internal_create(struct osc_creator *oscc)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int size = sizeof(*body);
        ENTRY;

        spin_lock(&oscc->oscc_lock);
        if (oscc->oscc_flags & OSCC_FLAG_CREATING) {
                spin_unlock(&oscc->oscc_lock);
                RETURN(0);
        }
        oscc->oscc_flags |= OSCC_FLAG_CREATING;
        spin_unlock(&oscc->oscc_lock);

        request = ptlrpc_prep_req(oscc->oscc_obd->u.cli.cl_import, OST_CREATE,
                                  1, &size, NULL);
        if (request == NULL) {
                spin_lock(&oscc->oscc_lock);
                oscc->oscc_flags &= ~OSCC_FLAG_CREATING;
                spin_unlock(&oscc->oscc_lock);
                RETURN(-ENOMEM);
        }

        request->rq_request_portal = OST_CREATE_PORTAL; //XXX FIXME bug 249
        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof(*body));

        spin_lock(&oscc->oscc_lock);
        body->oa.o_id = oscc->oscc_last_id + oscc->oscc_grow_count;
        body->oa.o_valid |= OBD_MD_FLID;
        CDEBUG(D_INFO, "preallocating through id "LPU64" (last used "LPU64")\n",
               body->oa.o_id, oscc->oscc_next_id);
        spin_unlock(&oscc->oscc_lock);

        request->rq_replen = lustre_msg_size(1, &size);

        request->rq_async_args.pointer_arg[0] = oscc;
        request->rq_interpret_reply = osc_interpret_create;
        ptlrpcd_add_req(request);

        RETURN(0);
}

static int oscc_has_objects(struct osc_creator *oscc, int count)
{
        int have_objs;
        spin_lock(&oscc->oscc_lock);
        have_objs = ((__s64)(oscc->oscc_last_id - oscc->oscc_next_id) >= count);
        spin_unlock(&oscc->oscc_lock);

        if (!have_objs)
                oscc_internal_create(oscc);

        return have_objs;
}

static int oscc_wait_for_objects(struct osc_creator *oscc, int count)
{
        int have_objs;
        int ost_full;
        int osc_invalid;

        have_objs = oscc_has_objects(oscc, count);

        spin_lock(&oscc->oscc_lock);
        ost_full = (oscc->oscc_flags & OSCC_FLAG_NOSPC);
        spin_unlock(&oscc->oscc_lock);

        osc_invalid = oscc->oscc_obd->u.cli.cl_import->imp_invalid;
                      
        return have_objs || ost_full || osc_invalid;
}

static int oscc_precreate(struct osc_creator *oscc, int wait)
{
        struct l_wait_info lwi = { 0 };
        int rc = 0;
        ENTRY;

        if (oscc_has_objects(oscc, oscc->oscc_kick_barrier))
                RETURN(0);

        if (!wait)
                RETURN(0);

        /* no rc check -- a no-INTR, no-TIMEOUT wait can't fail */
        l_wait_event(oscc->oscc_waitq, oscc_wait_for_objects(oscc, 1), &lwi);

        if (!oscc_has_objects(oscc, 1) && (oscc->oscc_flags & OSCC_FLAG_NOSPC))
                rc = -ENOSPC;

        if (oscc->oscc_obd->u.cli.cl_import->imp_invalid)
                rc = -EIO;

        RETURN(rc);
}

int oscc_recovering(struct osc_creator *oscc) 
{
        int recov = 0;

        spin_lock(&oscc->oscc_lock);
        recov = oscc->oscc_flags & OSCC_FLAG_RECOVERING;
        spin_unlock(&oscc->oscc_lock);

        return recov;
}

int osc_create(struct obd_export *exp, struct obdo *oa,
               struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct lov_stripe_md *lsm;
        struct osc_creator *oscc = &exp->exp_obd->u.cli.cl_oscc;
        int try_again = 1, rc = 0;
        ENTRY;
        LASSERT(oa);
        LASSERT(ea);

        if ((oa->o_valid & OBD_MD_FLGROUP) && (oa->o_gr != 0))
                RETURN(osc_real_create(exp, oa, ea, oti));

        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            oa->o_flags == OBD_FL_RECREATE_OBJS) { 
                RETURN(osc_real_create(exp, oa, ea, oti));
        }

        lsm = *ea;
        if (lsm == NULL) {
                rc = obd_alloc_memmd(exp, &lsm);
                if (rc < 0)
                        RETURN(rc);
        }

	/* this is the special case where create removes orphans */
	if ((oa->o_valid & OBD_MD_FLFLAGS) &&
	    oa->o_flags == OBD_FL_DELORPHAN) {
                CDEBUG(D_HA, "%p: oscc recovery started\n", oscc);
                /* delete from next_id on up */
                oa->o_valid |= OBD_MD_FLID;
                oa->o_id = oscc->oscc_next_id - 1;

                rc = osc_real_create(exp, oa, ea, NULL);

                spin_lock(&oscc->oscc_lock);
                if (rc == -ENOSPC)
                        oscc->oscc_flags |= OSCC_FLAG_NOSPC;
                oscc->oscc_flags &= ~OSCC_FLAG_RECOVERING;
                oscc->oscc_last_id = oa->o_id;
                wake_up(&oscc->oscc_waitq);
                spin_unlock(&oscc->oscc_lock);

                CDEBUG(D_HA, "%p: oscc recovery finished\n", oscc);

		RETURN(rc);
	}

        /* If orphans are being recovered, then we must wait until it is 
           finished before we can continue with create. */
        if (oscc_recovering(oscc)) {
                struct l_wait_info lwi;

                CDEBUG(D_HA, "%p: oscc recovery in progress, waiting\n", oscc);

                lwi = LWI_TIMEOUT(MAX(obd_timeout * HZ, 1), NULL, NULL);
                rc = l_wait_event(oscc->oscc_waitq, !oscc_recovering(oscc),
                                  &lwi);
                LASSERT(rc == 0 || rc == -ETIMEDOUT);
                if (rc == -ETIMEDOUT)
                        RETURN(rc);
                CDEBUG(D_HA, "%p: oscc recovery over, waking up\n", oscc);
        }
        
        
        while (try_again) {
                spin_lock(&oscc->oscc_lock);
                if (oscc->oscc_last_id >= oscc->oscc_next_id) {
                        memcpy(oa, &oscc->oscc_oa, sizeof(*oa));
                        oa->o_id = oscc->oscc_next_id;
                        lsm->lsm_object_id = oscc->oscc_next_id;
                        *ea = lsm;
                        oscc->oscc_next_id++;
                        try_again = 0;
                } else if (oscc->oscc_flags & OSCC_FLAG_NOSPC) {
                        rc = -ENOSPC;
                        spin_unlock(&oscc->oscc_lock);
                        break;
                }
                spin_unlock(&oscc->oscc_lock);
                rc = oscc_precreate(oscc, try_again);
                if (rc == -EIO)
                        break;
        }

        if (rc == 0)
                CDEBUG(D_INFO, "returning objid "LPU64"\n", lsm->lsm_object_id);
        else if (*ea == NULL)
                obd_free_memmd(exp, &lsm);
        RETURN(rc);
}

void oscc_init(struct obd_device *obd)
{
        struct osc_creator *oscc;

        if (obd == NULL)
                return;

        oscc = &obd->u.cli.cl_oscc;

        memset(oscc, 0, sizeof(*oscc));
        INIT_LIST_HEAD(&oscc->oscc_list);
        init_waitqueue_head(&oscc->oscc_waitq);
        spin_lock_init(&oscc->oscc_lock);
        oscc->oscc_obd = obd;
        oscc->oscc_kick_barrier = 100;
        oscc->oscc_grow_count = 2000;
        oscc->oscc_initial_create_count = 2000;

        oscc->oscc_next_id = 2;
        oscc->oscc_last_id = 1;
        oscc->oscc_flags |= OSCC_FLAG_RECOVERING;
        /* XXX the export handle should give the oscc the last object */
        /* oed->oed_oscc.oscc_last_id = exph->....; */
}
