/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 *
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osc/osc_create.c
 * For testing and management it is treated as an obd_device,
 * although * it does not export a full OBD method table (the
 * requests are coming * in over the wire, so object target modules
 * do not have a full * method table.)
 *
 * Author: Peter Braam <braam@clusterfs.com>
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

#include <lustre_dlm.h>
#include <obd_class.h>
#include "osc_internal.h"

/* XXX need AT adjust ? */
#define osc_create_timeout      (obd_timeout / 2)

struct osc_create_async_args {
        struct osc_creator      *rq_oscc;
        struct lov_stripe_md    *rq_lsm;
        struct obd_info         *rq_oinfo;
        int                      rq_grow_count;
};

static int oscc_internal_create(struct osc_creator *oscc);
static int handle_async_create(struct ptlrpc_request *req, int rc);

static int osc_interpret_create(const struct lu_env *env,
                                struct ptlrpc_request *req, void *data, int rc)
{
        struct osc_create_async_args *args = ptlrpc_req_async_args(req);
        struct osc_creator *oscc = args->rq_oscc;
        struct ost_body *body = NULL;
        struct ptlrpc_request *fake_req, *pos;
        ENTRY;

        if (req->rq_repmsg) {
                body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
                if (body == NULL && rc == 0)
                        rc = -EPROTO;
        }

        LASSERT(oscc && (oscc->oscc_obd != LP_POISON));

        cfs_spin_lock(&oscc->oscc_lock);
        oscc->oscc_flags &= ~OSCC_FLAG_CREATING;
        switch (rc) {
        case 0: {
                if (body) {
                        int diff =ostid_id(&body->oa.o_oi)- oscc->oscc_last_id;

                        /* oscc_internal_create() stores the original value of
                         * grow_count in osc_create_async_args::rq_grow_count.
                         * We can't compare against oscc_grow_count directly,
                         * because it may have been increased while the RPC
                         * is in flight, so we would always find ourselves
                         * having created fewer objects and decreasing the
                         * precreate request size.  b=18577 */
                        if (diff < args->rq_grow_count) {
                                /* the OST has not managed to create all the
                                 * objects we asked for */
                                oscc->oscc_grow_count = max(diff,
                                                            OST_MIN_PRECREATE);
                                /* don't bump grow_count next time */
                                oscc->oscc_flags |= OSCC_FLAG_LOW;
                        } else {
                                /* the OST is able to keep up with the work,
                                 * we could consider increasing grow_count
                                 * next time if needed */
                                oscc->oscc_flags &= ~OSCC_FLAG_LOW;
                        }
                        oscc->oscc_last_id = ostid_id(&body->oa.o_oi);
                }
                cfs_spin_unlock(&oscc->oscc_lock);
                break;
        }
        case -EROFS:
                oscc->oscc_flags |= OSCC_FLAG_RDONLY;
        case -ENOSPC:
        case -EFBIG: 
                if (rc != -EROFS) {
                        oscc->oscc_flags |= OSCC_FLAG_NOSPC;
                        if (body && rc == -ENOSPC) {
                                oscc->oscc_last_id = body->oa.o_id;
                                oscc->oscc_grow_count = OST_MIN_PRECREATE;

                                if ((body->oa.o_valid & OBD_MD_FLFLAGS) &&
                                    (body->oa.o_flags & OBD_FL_NOSPC_BLK))
                                        oscc->oscc_flags |= OSCC_FLAG_NOSPC_BLK;
                                else
                                        rc = 0;
                        }
                }
                cfs_spin_unlock(&oscc->oscc_lock);
                DEBUG_REQ(D_INODE, req, "OST out of space, flagging");
                break;
        case -EIO: {
                /* filter always set body->oa.o_id as the last_id
                 * of filter (see filter_handle_precreate for detail)*/
                if (body && body->oa.o_id > oscc->oscc_last_id)
                        oscc->oscc_last_id = body->oa.o_id;
                cfs_spin_unlock(&oscc->oscc_lock);
                break;
        }
        case -EINTR:
        case -EWOULDBLOCK: {
                /* aka EAGAIN we should not delay create if import failed -
                 * this avoid client stick in create and avoid race with
                 * delorphan */
                /* EINTR say - old create request is killed due mds<>ost
                 * eviction - OSCC_FLAG_RECOVERING can already set due
                 * IMP_DISCONN event */
                oscc->oscc_flags |= OSCC_FLAG_RECOVERING;
                /* oscc->oscc_grow_count = OST_MIN_PRECREATE; */
                cfs_spin_unlock(&oscc->oscc_lock);
                break;
        }
        default: {
                oscc->oscc_flags |= OSCC_FLAG_RECOVERING;
                oscc->oscc_grow_count = OST_MIN_PRECREATE;
                cfs_spin_unlock(&oscc->oscc_lock);
                DEBUG_REQ(D_ERROR, req,
                          "Unknown rc %d from async create: failing oscc", rc);
                ptlrpc_fail_import(req->rq_import,
                                   lustre_msg_get_conn_cnt(req->rq_reqmsg));
        }
        }

        CDEBUG(D_HA, "preallocated through id "LPU64" (next to use "LPU64")\n",
               oscc->oscc_last_id, oscc->oscc_next_id);

        cfs_spin_lock(&oscc->oscc_lock);
        cfs_list_for_each_entry_safe(fake_req, pos,
                                     &oscc->oscc_wait_create_list, rq_list) {
                if (handle_async_create(fake_req, rc)  == -EAGAIN) {
                        oscc_internal_create(oscc);
                        /* sending request should be never fail because
                         * osc use preallocated requests pool */
                        GOTO(exit_wakeup, rc);
                }
        }
        cfs_spin_unlock(&oscc->oscc_lock);

exit_wakeup:
        cfs_waitq_signal(&oscc->oscc_waitq);
        RETURN(rc);
}

static int oscc_internal_create(struct osc_creator *oscc)
{
        struct osc_create_async_args *args;
        struct ptlrpc_request *request;
        struct ost_body *body;
        ENTRY;

        LASSERT_SPIN_LOCKED(&oscc->oscc_lock);

        /* Do not check for a degraded OST here - bug21563/bug18539 */
        if (oscc->oscc_flags & OSCC_FLAG_RECOVERING) {
                cfs_spin_unlock(&oscc->oscc_lock);
                RETURN(0);
        }

        /* we need check it before OSCC_FLAG_CREATING - because need
         * see lower number of precreate objects */
        if (oscc->oscc_grow_count < oscc->oscc_max_grow_count &&
            ((oscc->oscc_flags & OSCC_FLAG_LOW) == 0) &&
            (__s64)(oscc->oscc_last_id - oscc->oscc_next_id) <=
                   (oscc->oscc_grow_count / 4 + 1)) {
                oscc->oscc_flags |= OSCC_FLAG_LOW;
                oscc->oscc_grow_count *= 2;
        }

        if (oscc->oscc_flags & OSCC_FLAG_CREATING) {
                cfs_spin_unlock(&oscc->oscc_lock);
                RETURN(0);
        }

        if (oscc->oscc_grow_count > oscc->oscc_max_grow_count / 2)
                oscc->oscc_grow_count = oscc->oscc_max_grow_count / 2;

        oscc->oscc_flags |= OSCC_FLAG_CREATING;
        cfs_spin_unlock(&oscc->oscc_lock);

        request = ptlrpc_request_alloc_pack(oscc->oscc_obd->u.cli.cl_import,
                                            &RQF_OST_CREATE,
                                            LUSTRE_OST_VERSION, OST_CREATE);
        if (request == NULL) {
                cfs_spin_lock(&oscc->oscc_lock);
                oscc->oscc_flags &= ~OSCC_FLAG_CREATING;
                cfs_spin_unlock(&oscc->oscc_lock);
                RETURN(-ENOMEM);
        }

        request->rq_request_portal = OST_CREATE_PORTAL;
        ptlrpc_at_set_req_timeout(request);
        body = req_capsule_client_get(&request->rq_pill, &RMF_OST_BODY);
        args = ptlrpc_req_async_args(request);
        args->rq_oscc = oscc;

        cfs_spin_lock(&oscc->oscc_lock);
        args->rq_grow_count = oscc->oscc_grow_count;

        if (likely(fid_seq_is_mdt(oscc->oscc_oa.o_seq))) {
                body->oa.o_oi.oi_seq = oscc->oscc_oa.o_seq;
                body->oa.o_oi.oi_id  = oscc->oscc_last_id +
                                       oscc->oscc_grow_count;
        } else {
                /*Just warning here currently, since not sure how fid-on-ost
                 *will be implemented here */
                CWARN("o_seq: "LPU64" is not indicate any MDTs.\n",
                       oscc->oscc_oa.o_seq);
        }
        cfs_spin_unlock(&oscc->oscc_lock);

        body->oa.o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP;
        CDEBUG(D_RPCTRACE, "prealloc through id "LPU64" (last seen "LPU64")\n",
               body->oa.o_id, oscc->oscc_last_id);

        /* we should not resend create request - anyway we will have delorphan
         * and kill these objects */
        request->rq_no_delay = request->rq_no_resend = 1;
        ptlrpc_request_set_replen(request);

        request->rq_interpret_reply = osc_interpret_create;
        ptlrpcd_add_req(request, PSCOPE_OTHER);

        RETURN(0);
}

static int oscc_has_objects_nolock(struct osc_creator *oscc, int count)
{
        return ((__s64)(oscc->oscc_last_id - oscc->oscc_next_id) >= count);
}


static int oscc_has_objects(struct osc_creator *oscc, int count)
{
        int have_objs;

        cfs_spin_lock(&oscc->oscc_lock);
        have_objs = oscc_has_objects_nolock(oscc, count);
        cfs_spin_unlock(&oscc->oscc_lock);

        return have_objs;
}

static int oscc_wait_for_objects(struct osc_creator *oscc, int count)
{
        int have_objs;
        int ost_unusable;

        ost_unusable = oscc->oscc_obd->u.cli.cl_import->imp_invalid;

        cfs_spin_lock(&oscc->oscc_lock);
        ost_unusable |= (OSCC_FLAG_NOSPC | OSCC_FLAG_RDONLY |
                         OSCC_FLAG_EXITING) & oscc->oscc_flags;
        have_objs = oscc_has_objects_nolock(oscc, count);

        if (!ost_unusable && !have_objs)
                /* they release lock himself */
                have_objs = oscc_internal_create(oscc);
        else
                cfs_spin_unlock(&oscc->oscc_lock);

        return have_objs || ost_unusable;
}

static int oscc_precreate(struct osc_creator *oscc)
{
        struct l_wait_info lwi;
        int rc = 0;
        ENTRY;

        if (oscc_has_objects(oscc, oscc->oscc_grow_count / 2))
                RETURN(0);

        /* we should be not block forever - because client's create rpc can
         * stick in mds for long time and forbid client reconnect */
        lwi = LWI_TIMEOUT(cfs_timeout_cap(cfs_time_seconds(osc_create_timeout)),
                          NULL, NULL);

        rc = l_wait_event(oscc->oscc_waitq, oscc_wait_for_objects(oscc, 1), &lwi);
        RETURN(rc);
}

static int oscc_in_sync(struct osc_creator *oscc)
{
        int sync;

        cfs_spin_lock(&oscc->oscc_lock);
        sync = oscc->oscc_flags & OSCC_FLAG_SYNC_IN_PROGRESS;
        cfs_spin_unlock(&oscc->oscc_lock);

        return sync;
}

/* decide if the OST has remaining object, return value :
        0 : the OST has remaining objects, may or may not send precreation RPC.
        1 : the OST has no remaining object, and the sent precreation RPC
            has not been completed yet.
        2 : the OST has no remaining object, and will not get any for
            a potentially very long time
     1000 : unusable
 */
int osc_precreate(struct obd_export *exp)
{
        struct osc_creator *oscc = &exp->exp_obd->u.cli.cl_oscc;
        struct obd_import *imp = exp->exp_imp_reverse;
        int rc;
        ENTRY;

        LASSERT(oscc != NULL);
        if (imp != NULL && imp->imp_deactive)
                GOTO(out_nolock, rc = 1000);

        /* Handle critical states first */
        cfs_spin_lock(&oscc->oscc_lock);
        if (oscc->oscc_flags & OSCC_FLAG_NOSPC_BLK ||
            oscc->oscc_flags & OSCC_FLAG_RDONLY ||
            oscc->oscc_flags & OSCC_FLAG_EXITING)
                GOTO(out, rc = 1000);

        if ((oscc->oscc_flags & OSCC_FLAG_RECOVERING) ||
            (oscc->oscc_flags & OSCC_FLAG_DEGRADED))
                GOTO(out, rc = 2);

        if (oscc_has_objects_nolock(oscc, oscc->oscc_grow_count / 2))
                GOTO(out, rc = 0);

        /* Return 0, if we have at least one object - bug 22884 */
        rc = oscc_has_objects_nolock(oscc, 1) ? 0 : 1;

        if (oscc->oscc_flags & OSCC_FLAG_NOSPC)
                GOTO(out, (rc == 0) ? 0 : 1000);

        /* Do not check for OSCC_FLAG_CREATING flag here, let
         * osc_precreate() call oscc_internal_create() and
         * adjust oscc_grow_count bug21563 */
        if (oscc->oscc_flags & OSCC_FLAG_SYNC_IN_PROGRESS)
                GOTO(out, rc);

        if (oscc_internal_create(oscc))
                GOTO(out_nolock, rc = 1000);

        RETURN(rc);
out:
        cfs_spin_unlock(&oscc->oscc_lock);
out_nolock:
        return rc;
}

static int handle_async_create(struct ptlrpc_request *req, int rc)
{
        struct osc_create_async_args *args = ptlrpc_req_async_args(req);
        struct osc_creator    *oscc = args->rq_oscc;
        struct lov_stripe_md  *lsm  = args->rq_lsm;
        struct obd_info       *oinfo = args->rq_oinfo;
        struct obdo           *oa = oinfo->oi_oa;

        LASSERT_SPIN_LOCKED(&oscc->oscc_lock);

        if(rc)
                GOTO(out_wake, rc);

        /* Handle the critical type errors first.
         * Should we also test cl_import state as well ? */
        if (oscc->oscc_flags & OSCC_FLAG_EXITING)
                GOTO(out_wake, rc = -EIO);

        if (oscc->oscc_flags & OSCC_FLAG_NOSPC_BLK)
                GOTO(out_wake, rc = -ENOSPC);

        if (oscc->oscc_flags & OSCC_FLAG_RDONLY)
                GOTO(out_wake, rc = -EROFS);

        /* should be try wait until recovery finished */
        if((oscc->oscc_flags & OSCC_FLAG_RECOVERING) ||
           (oscc->oscc_flags & OSCC_FLAG_DEGRADED))
                RETURN(-EAGAIN);

        if (oscc_has_objects_nolock(oscc, 1)) {
                memcpy(oa, &oscc->oscc_oa, sizeof(*oa));
                oa->o_id = oscc->oscc_next_id;
                lsm->lsm_object_id = oscc->oscc_next_id;
                oscc->oscc_next_id++;

                CDEBUG(D_RPCTRACE, " set oscc_next_id = "LPU64"\n",
                       oscc->oscc_next_id);
                GOTO(out_wake, rc = 0);
        }

        /* we don't have objects now - continue wait */
        RETURN(-EAGAIN);

out_wake:

        rc = oinfo->oi_cb_up(oinfo, rc);
        ptlrpc_fakereq_finished(req);

        RETURN(rc);
}

static int async_create_interpret(const struct lu_env *env,
                                  struct ptlrpc_request *req, void *data,
                                  int rc)
{
        struct osc_create_async_args *args = ptlrpc_req_async_args(req);
        struct osc_creator    *oscc = args->rq_oscc;
        int ret;

        cfs_spin_lock(&oscc->oscc_lock);
        ret = handle_async_create(req, rc);
        cfs_spin_unlock(&oscc->oscc_lock);

        return ret;
}

int osc_create_async(struct obd_export *exp, struct obd_info *oinfo,
                     struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        int rc;
        struct ptlrpc_request *fake_req;
        struct osc_create_async_args *args;
        struct osc_creator *oscc = &exp->exp_obd->u.cli.cl_oscc;
        struct obdo *oa = oinfo->oi_oa;
        ENTRY;

        if ((oa->o_valid & OBD_MD_FLGROUP) && !fid_seq_is_mdt(oa->o_seq)) {
                rc = osc_real_create(exp, oinfo->oi_oa, ea, oti);
                rc = oinfo->oi_cb_up(oinfo, rc);
                RETURN(rc);
        }

        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            oa->o_flags == OBD_FL_RECREATE_OBJS) {
                rc = osc_real_create(exp, oinfo->oi_oa, ea, oti);
                rc = oinfo->oi_cb_up(oinfo, rc);
                RETURN(rc);
        }

        LASSERT((*ea) != NULL);

        fake_req = ptlrpc_prep_fakereq(oscc->oscc_obd->u.cli.cl_import,
                                       osc_create_timeout,
                                       async_create_interpret);
        if (fake_req == NULL) {
                rc = oinfo->oi_cb_up(oinfo, -ENOMEM);
                RETURN(-ENOMEM);
        }

        args = ptlrpc_req_async_args(fake_req);
        CLASSERT(sizeof(*args) <= sizeof(fake_req->rq_async_args));

        args->rq_oscc  = oscc;
        args->rq_lsm   = *ea;
        args->rq_oinfo = oinfo;

        cfs_spin_lock(&oscc->oscc_lock);
        /* try fast path */
        rc = handle_async_create(fake_req, 0);
        if (rc == -EAGAIN) {
                int is_add;
                /* we not have objects - try wait */
                is_add = ptlrpcd_add_req(fake_req, PSCOPE_OTHER);
                if (!is_add)
                        cfs_list_add(&fake_req->rq_list,
                                     &oscc->oscc_wait_create_list);
                else
                        rc = is_add;
        }
        cfs_spin_unlock(&oscc->oscc_lock);

        if (rc != -EAGAIN)
                /* need free request if was error hit or
                 * objects already allocated */
                ptlrpc_req_finished(fake_req);
        else
                /* EAGAIN mean - request is delayed */
                rc = 0;

        RETURN(rc);
}

int osc_create(struct obd_export *exp, struct obdo *oa,
               struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct osc_creator *oscc = &exp->exp_obd->u.cli.cl_oscc;
        struct obd_import  *imp  = exp->exp_obd->u.cli.cl_import;
        struct lov_stripe_md *lsm;
        int del_orphan = 0, rc = 0;
        ENTRY;

        LASSERT(oa);
        LASSERT(ea);
        LASSERT(oa->o_valid & OBD_MD_FLGROUP);

        if ((oa->o_valid & OBD_MD_FLFLAGS) &&
            oa->o_flags == OBD_FL_RECREATE_OBJS) {
                RETURN(osc_real_create(exp, oa, ea, oti));
        }

        if (!fid_seq_is_mdt(oa->o_seq))
                RETURN(osc_real_create(exp, oa, ea, oti));

        /* this is the special case where create removes orphans */
        if (oa->o_valid & OBD_MD_FLFLAGS &&
            oa->o_flags == OBD_FL_DELORPHAN) {
                cfs_spin_lock(&oscc->oscc_lock);
                if (oscc->oscc_flags & OSCC_FLAG_SYNC_IN_PROGRESS) {
                        cfs_spin_unlock(&oscc->oscc_lock);
                        RETURN(-EBUSY);
                }
                if (!(oscc->oscc_flags & OSCC_FLAG_RECOVERING)) {
                        cfs_spin_unlock(&oscc->oscc_lock);
                        RETURN(0);
                }

                oscc->oscc_flags |= OSCC_FLAG_SYNC_IN_PROGRESS;
                /* seting flag LOW we prevent extra grow precreate size
                 * and enforce use last assigned size */
                oscc->oscc_flags |= OSCC_FLAG_LOW;
                cfs_spin_unlock(&oscc->oscc_lock);
                CDEBUG(D_HA, "%s: oscc recovery started - delete to "LPU64"\n",
                       oscc->oscc_obd->obd_name, oscc->oscc_next_id - 1);

                del_orphan = 1;

                /* delete from next_id on up */
                oa->o_valid |= OBD_MD_FLID;
                oa->o_id = oscc->oscc_next_id - 1;

                rc = osc_real_create(exp, oa, ea, NULL);

                cfs_spin_lock(&oscc->oscc_lock);
                oscc->oscc_flags &= ~OSCC_FLAG_SYNC_IN_PROGRESS;
                if (rc == 0 || rc == -ENOSPC) {
                        struct obd_connect_data *ocd;

                        if (rc == -ENOSPC) {
                                oscc->oscc_flags |= OSCC_FLAG_NOSPC;
                                if ((oa->o_valid & OBD_MD_FLFLAGS) &&
                                    (oa->o_flags & OBD_FL_NOSPC_BLK))
                                        oscc->oscc_flags |= OSCC_FLAG_NOSPC_BLK;
                        }
                        oscc->oscc_flags &= ~OSCC_FLAG_RECOVERING;

                        oscc->oscc_last_id = oa->o_id;
                        ocd = &imp->imp_connect_data;
                        if (ocd->ocd_connect_flags & OBD_CONNECT_SKIP_ORPHAN) {
                                /*
                                 * The OST reports back in oa->o_id from where
                                 * we should restart in order to skip orphan
                                 * objects
                                 */
                                CDEBUG(D_HA, "%s: Skip orphan set, reset last "
                                       "objid\n", oscc->oscc_obd->obd_name);
                                oscc->oscc_next_id = oa->o_id + 1;
                        }

                        /* sanity check for next objid. see bug 17025 */
                        LASSERT(oscc->oscc_next_id == oa->o_id + 1);

                        CDEBUG(D_HA, "%s: oscc recovery finished, last_id: "
                               LPU64", rc: %d\n", oscc->oscc_obd->obd_name,
                               oscc->oscc_last_id, rc);
                } else {
                        CDEBUG(D_ERROR, "%s: oscc recovery failed: %d\n",
                               oscc->oscc_obd->obd_name, rc);
                }

                cfs_waitq_signal(&oscc->oscc_waitq);
                cfs_spin_unlock(&oscc->oscc_lock);

                if (rc < 0)
                        RETURN(rc);
        }

        lsm = *ea;
        if (lsm == NULL) {
                rc = obd_alloc_memmd(exp, &lsm);
                if (rc < 0)
                        RETURN(rc);
        }

        while (1) {
                if (oscc_in_sync(oscc))
                        CDEBUG(D_HA,"%s: oscc recovery in progress, waiting\n",
                               oscc->oscc_obd->obd_name);

                rc = oscc_precreate(oscc);
                if (rc)
                        CDEBUG(D_HA,"%s: error create %d\n",
                               oscc->oscc_obd->obd_name, rc);

                cfs_spin_lock(&oscc->oscc_lock);

                /* wakeup but recovery did not finished */
                if ((oscc->oscc_obd->u.cli.cl_import->imp_invalid) ||
                    (oscc->oscc_flags & OSCC_FLAG_RECOVERING)) {
                        rc = -EIO;
                        cfs_spin_unlock(&oscc->oscc_lock);
                        break;
                }

                if (oscc->oscc_flags & OSCC_FLAG_NOSPC_BLK) {
                        rc = -ENOSPC;
                        cfs_spin_unlock(&oscc->oscc_lock);
                        break;
                }

                if (oscc->oscc_flags & OSCC_FLAG_RDONLY) {
                        rc = -EROFS;
                        cfs_spin_unlock(&oscc->oscc_lock);
                        break;
                }

                // Should we report -EIO error ?
                if (oscc->oscc_flags & OSCC_FLAG_EXITING) {
                        cfs_spin_unlock(&oscc->oscc_lock);
                        break;
                }

                /**
                 * If this is DELORPHAN process, no need create object here,
                 * otherwise this will create a gap of object id, and MDS
                 * might create some orphan log (mds_lov_update_objids), then
                 * remove objects wrongly on OST. Bug 21379.
                 */
                if (oa->o_valid & OBD_MD_FLFLAGS &&
                        oa->o_flags == OBD_FL_DELORPHAN) {
                        cfs_spin_unlock(&oscc->oscc_lock);
                        break;
                }

                if (oscc_has_objects_nolock(oscc, 1)) {
                        memcpy(oa, &oscc->oscc_oa, sizeof(*oa));
                        oa->o_id = oscc->oscc_next_id;
                        lsm->lsm_object_id = oscc->oscc_next_id;
                        *ea = lsm;
                        oscc->oscc_next_id++;
                        cfs_spin_unlock(&oscc->oscc_lock);

                        CDEBUG(D_RPCTRACE, "%s: set oscc_next_id = "LPU64"\n",
                               exp->exp_obd->obd_name, oscc->oscc_next_id);
                        break;
                }

                if (oscc->oscc_flags & OSCC_FLAG_NOSPC) {
                        rc = -ENOSPC;
                        cfs_spin_unlock(&oscc->oscc_lock);
                        break;
                }

                cfs_spin_unlock(&oscc->oscc_lock);
        }

        if (rc == 0) {
                CDEBUG(D_INFO, "%s: returning objid "LPU64"\n",
                       obd2cli_tgt(oscc->oscc_obd), lsm->lsm_object_id);
        } else {
                if (*ea == NULL)
                        obd_free_memmd(exp, &lsm);
                if (del_orphan != 0 && rc != -EIO)
                        /* Ignore non-IO precreate error for clear orphan */
                        rc = 0;
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

        cfs_waitq_init(&oscc->oscc_waitq);
        cfs_spin_lock_init(&oscc->oscc_lock);
        oscc->oscc_obd = obd;
        oscc->oscc_grow_count = OST_MIN_PRECREATE;
        oscc->oscc_max_grow_count = OST_MAX_PRECREATE;

        oscc->oscc_next_id = 2;
        oscc->oscc_last_id = 1;
        oscc->oscc_flags |= OSCC_FLAG_RECOVERING;

        CFS_INIT_LIST_HEAD(&oscc->oscc_wait_create_list);

        /* XXX the export handle should give the oscc the last object */
        /* oed->oed_oscc.oscc_last_id = exph->....; */
}

void oscc_fini(struct obd_device *obd)
{
        struct osc_creator *oscc = &obd->u.cli.cl_oscc;
        ENTRY;


        cfs_spin_lock(&oscc->oscc_lock);
        oscc->oscc_flags &= ~OSCC_FLAG_RECOVERING;
        oscc->oscc_flags |= OSCC_FLAG_EXITING;
        cfs_spin_unlock(&oscc->oscc_lock);
}
