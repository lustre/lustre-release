/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
 */

#define DEBUG_SUBSYSTEM S_LDLM
#ifndef __KERNEL__
#include <signal.h>
#include <liblustre.h>
#endif

#include <linux/lustre_dlm.h>
#include <linux/obd_class.h>
#include <linux/obd.h>

#include "ldlm_internal.h"

static void interrupted_completion_wait(void *data)
{
}

struct lock_wait_data {
        struct ldlm_lock *lwd_lock;
        int               lwd_generation;
};

int ldlm_expired_completion_wait(void *data)
{
        struct lock_wait_data *lwd = data;
        struct ldlm_lock *lock = lwd->lwd_lock;
        struct obd_import *imp;
        struct obd_device *obd;

        if (lock->l_conn_export == NULL) {
                static unsigned long next_dump = 0;

                LDLM_ERROR(lock, "lock timed out; not entering recovery in "
                           "server code, just going back to sleep");
                if (time_after(jiffies, next_dump)) {
                        ldlm_namespace_dump(lock->l_resource->lr_namespace);
                        if (next_dump == 0)
                                portals_debug_dumplog();
                        next_dump = jiffies + 300 * HZ;
                }
                RETURN(0);
        }

        obd = lock->l_conn_export->exp_obd;
        imp = obd->u.cli.cl_import;
        ptlrpc_fail_import(imp, lwd->lwd_generation);
        LDLM_ERROR(lock, "lock timed out, entering recovery for %s@%s",
                   imp->imp_target_uuid.uuid,
                   imp->imp_connection->c_remote_uuid.uuid);

        RETURN(0);
}

int ldlm_completion_ast(struct ldlm_lock *lock, int flags, void *data)
{
        /* XXX ALLOCATE - 160 bytes */
        struct lock_wait_data lwd;
        unsigned long irqflags;
        struct obd_device *obd;
        struct obd_import *imp = NULL;
        struct l_wait_info lwi;
        int rc = 0;
        ENTRY;

        if (flags == LDLM_FL_WAIT_NOREPROC)
                goto noreproc;

        if (!(flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED |
                       LDLM_FL_BLOCK_CONV))) {
                wake_up(&lock->l_waitq);
                RETURN(0);
        }

        LDLM_DEBUG(lock, "client-side enqueue returned a blocked lock, "
                   "sleeping");
        ldlm_lock_dump(D_OTHER, lock, 0);
        ldlm_reprocess_all(lock->l_resource);

noreproc:

        obd = class_exp2obd(lock->l_conn_export);

        /* if this is a local lock, then there is no import */
        if (obd != NULL)
                imp = obd->u.cli.cl_import;

        lwd.lwd_lock = lock;

        lwi = LWI_TIMEOUT_INTR(obd_timeout * HZ, ldlm_expired_completion_wait,
                               interrupted_completion_wait, &lwd);
        if (imp != NULL) {
                spin_lock_irqsave(&imp->imp_lock, irqflags);
                lwd.lwd_generation = imp->imp_generation;
                spin_unlock_irqrestore(&imp->imp_lock, irqflags);
        }

        /* Go to sleep until the lock is granted or cancelled. */
        rc = l_wait_event(lock->l_waitq,
                          ((lock->l_req_mode == lock->l_granted_mode) ||
                           (lock->l_flags & LDLM_FL_CANCEL)), &lwi);

        if (lock->l_destroyed) {
                LDLM_DEBUG(lock, "client-side enqueue waking up: destroyed");
                RETURN(-EIO);
        }

        if (rc) {
                LDLM_DEBUG(lock, "client-side enqueue waking up: failed (%d)",
                           rc);
                RETURN(rc);
        }

        LDLM_DEBUG(lock, "client-side enqueue waking up: granted");
        RETURN(0);
}

static int ldlm_cli_enqueue_local(struct ldlm_namespace *ns,
                                  struct ldlm_res_id res_id,
                                  __u32 type,
                                  ldlm_policy_data_t *policy,
                                  ldlm_mode_t mode,
                                  int *flags,
                                  ldlm_blocking_callback blocking,
                                  ldlm_completion_callback completion,
                                  ldlm_glimpse_callback glimpse,
                                  void *data, __u32 lvb_len,
                                  void *lvb_swabber,
                                  struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        int err;
        ENTRY;

        if (ns->ns_client) {
                CERROR("Trying to enqueue local lock in a shadow namespace\n");
                LBUG();
        }

        lock = ldlm_lock_create(ns, NULL, res_id, type, mode, blocking,
                                completion, glimpse, data, lvb_len);
        if (!lock)
                GOTO(out_nolock, err = -ENOMEM);
        LDLM_DEBUG(lock, "client-side local enqueue handler, new lock created");

        ldlm_lock_addref_internal(lock, mode);
        ldlm_lock2handle(lock, lockh);
        lock->l_flags |= LDLM_FL_LOCAL;
        lock->l_lvb_swabber = lvb_swabber;
        if (policy != NULL)
                memcpy(&lock->l_policy_data, policy, sizeof(*policy));

        err = ldlm_lock_enqueue(ns, &lock, policy, flags);
        if (err != ELDLM_OK)
                GOTO(out, err);

        if (policy != NULL)
                memcpy(policy, &lock->l_policy_data, sizeof(*policy));
        if ((*flags) & LDLM_FL_LOCK_CHANGED)
                memcpy(&res_id, &lock->l_resource->lr_name, sizeof(res_id));

        LDLM_DEBUG_NOLOCK("client-side local enqueue handler END (lock %p)",
                          lock);

        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, *flags, NULL);

        LDLM_DEBUG(lock, "client-side local enqueue END");
        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
 out_nolock:
        return err;
}

static void failed_lock_cleanup(struct ldlm_namespace *ns,
                                struct ldlm_lock *lock,
                                struct lustre_handle *lockh, int mode)
{
        /* Set a flag to prevent us from sending a CANCEL (bug 407) */
        l_lock(&ns->ns_lock);
        lock->l_flags |= LDLM_FL_LOCAL_ONLY;
        LDLM_DEBUG(lock, "setting FL_LOCAL_ONLY");
        l_unlock(&ns->ns_lock);

        ldlm_lock_decref_and_cancel(lockh, mode);
}

int ldlm_cli_enqueue(struct obd_export *exp,
                     struct ptlrpc_request *req,
                     struct ldlm_namespace *ns,
                     struct ldlm_res_id res_id,
                     __u32 type,
                     ldlm_policy_data_t *policy,
                     ldlm_mode_t mode,
                     int *flags,
                     ldlm_blocking_callback blocking,
                     ldlm_completion_callback completion,
                     ldlm_glimpse_callback glimpse,
                     void *data,
                     void *lvb,
                     __u32 lvb_len,
                     void *lvb_swabber,
                     struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        int rc, size[2] = {sizeof(*body), lvb_len}, req_passed_in = 1;
        int is_replay = *flags & LDLM_FL_REPLAY;
        ENTRY;

        if (exp == NULL) {
                LASSERT(!is_replay);
                rc = ldlm_cli_enqueue_local(ns, res_id, type, policy, mode,
                                            flags, blocking, completion,
                                            glimpse, data, lvb_len, lvb_swabber,
                                            lockh);
                RETURN(rc);
        }

        /* If we're replaying this lock, just check some invariants.
         * If we're creating a new lock, get everything all setup nice. */
        if (is_replay) {
                lock = ldlm_handle2lock(lockh);
                LDLM_DEBUG(lock, "client-side enqueue START");
                LASSERT(exp == lock->l_conn_export);
        } else {
                lock = ldlm_lock_create(ns, NULL, res_id, type, mode, blocking,
                                        completion, glimpse, data, lvb_len);
                if (lock == NULL)
                        GOTO(out_nolock, rc = -ENOMEM);
                /* for the local lock, add the reference */
                ldlm_lock_addref_internal(lock, mode);
                ldlm_lock2handle(lock, lockh);
                lock->l_lvb_swabber = lvb_swabber;
                if (policy != NULL)
                        memcpy(&lock->l_policy_data, policy, sizeof(*policy));
                LDLM_DEBUG(lock, "client-side enqueue START");
        }

        if (req == NULL) {
                req = ptlrpc_prep_req(class_exp2cliimp(exp), LDLM_ENQUEUE, 1,
                                      size, NULL);
                if (req == NULL)
                        GOTO(out_lock, rc = -ENOMEM);
                req_passed_in = 0;
        } else if (req->rq_reqmsg->buflens[0] != sizeof(*body))
                LBUG();

        /* Dump lock data into the request buffer */
        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        ldlm_lock2desc(lock, &body->lock_desc);
        body->lock_flags = *flags;

        memcpy(&body->lock_handle1, lockh, sizeof(*lockh));

        /* Continue as normal. */
        if (!req_passed_in) {
                int buffers = 1;
                if (lvb_len > 0)
                        buffers = 2;
                size[0] = sizeof(*reply);
                req->rq_replen = lustre_msg_size(buffers, size);
        }
        lock->l_conn_export = exp;
        lock->l_export = NULL;
        lock->l_blocking_ast = blocking;

        LDLM_DEBUG(lock, "sending request");
        rc = ptlrpc_queue_wait(req);

        if (rc != ELDLM_OK) {
                LASSERT(!is_replay);
                LDLM_DEBUG(lock, "client-side enqueue END (%s)",
                           rc == ELDLM_LOCK_ABORTED ? "ABORTED" : "FAILED");
                if (rc == ELDLM_LOCK_ABORTED) {
                        /* Before we return, swab the reply */
                        reply = lustre_swab_repbuf(req, 0, sizeof(*reply),
                                                   lustre_swab_ldlm_reply);
                        if (reply == NULL) {
                                CERROR("Can't unpack ldlm_reply\n");
                                rc = -EPROTO;
                        }
                        if (lvb_len) {
                                void *tmplvb;
                                tmplvb = lustre_swab_repbuf(req, 1, lvb_len,
                                                            lvb_swabber);
                                if (tmplvb == NULL)
                                        GOTO(out_lock, rc = -EPROTO);
                                if (lvb != NULL)
                                        memcpy(lvb, tmplvb, lvb_len);
                        }
                }
                GOTO(out_lock, rc);
        }

        reply = lustre_swab_repbuf(req, 0, sizeof(*reply),
                                   lustre_swab_ldlm_reply);
        if (reply == NULL) {
                CERROR("Can't unpack ldlm_reply\n");
                GOTO(out_lock, rc = -EPROTO);
        }

        memcpy(&lock->l_remote_handle, &reply->lock_handle,
               sizeof(lock->l_remote_handle));
        *flags = reply->lock_flags;

        CDEBUG(D_INFO, "local: %p, remote cookie: "LPX64", flags: 0x%x\n",
               lock, reply->lock_handle.cookie, *flags);
        if (type == LDLM_EXTENT) {
                CDEBUG(D_INFO, "requested extent: "LPU64" -> "LPU64", got "
                       "extent "LPU64" -> "LPU64"\n",
                       body->lock_desc.l_policy_data.l_extent.start,
                       body->lock_desc.l_policy_data.l_extent.end,
                       reply->lock_desc.l_policy_data.l_extent.start,
                       reply->lock_desc.l_policy_data.l_extent.end);
        }
        if (policy != NULL)
                memcpy(&lock->l_policy_data, &reply->lock_desc.l_policy_data,
                       sizeof(reply->lock_desc.l_policy_data));

        /* If enqueue returned a blocked lock but the completion handler has
         * already run, then it fixed up the resource and we don't need to do it
         * again. */
        if ((*flags) & LDLM_FL_LOCK_CHANGED) {
                int newmode = reply->lock_desc.l_req_mode;
                LASSERT(!is_replay);
                if (newmode && newmode != lock->l_req_mode) {
                        LDLM_DEBUG(lock, "server returned different mode %s",
                                   ldlm_lockname[newmode]);
                        lock->l_req_mode = newmode;
                }

                if (reply->lock_desc.l_resource.lr_name.name[0] !=
                    lock->l_resource->lr_name.name[0]) {
                        CDEBUG(D_INFO, "remote intent success, locking %ld "
                               "instead of %ld\n",
                              (long)reply->lock_desc.l_resource.lr_name.name[0],
                               (long)lock->l_resource->lr_name.name[0]);

                        ldlm_lock_change_resource(ns, lock,
                                           reply->lock_desc.l_resource.lr_name);
                        if (lock->l_resource == NULL) {
                                LBUG();
                                GOTO(out_lock, rc = -ENOMEM);
                        }
                        LDLM_DEBUG(lock, "client-side enqueue, new resource");
                }
        }
        if ((*flags) & LDLM_FL_AST_SENT) {
                l_lock(&ns->ns_lock);
                lock->l_flags |= LDLM_FL_CBPENDING;
                l_unlock(&ns->ns_lock);
                LDLM_DEBUG(lock, "enqueue reply includes blocking AST");
        }

        if (lvb_len) {
                void *tmplvb;
                tmplvb = lustre_swab_repbuf(req, 1, lvb_len, lvb_swabber);
                if (tmplvb == NULL)
                        GOTO(out_lock, rc = -EPROTO);
                memcpy(lock->l_lvb_data, tmplvb, lvb_len);
        }

        if (!is_replay) {
                rc = ldlm_lock_enqueue(ns, &lock, NULL, flags);
                if (lock->l_completion_ast != NULL) {
                        int err = lock->l_completion_ast(lock, *flags, NULL);
                        if (!rc)
                                rc = err;
                }
        }

        if (lvb_len && lvb != NULL) {
                /* Copy the LVB here, and not earlier, because the completion
                 * AST (if any) can override what we got in the reply */
                memcpy(lvb, lock->l_lvb_data, lvb_len);
        }

        LDLM_DEBUG(lock, "client-side enqueue END");
        EXIT;
 out_lock:
        if (rc)
                failed_lock_cleanup(ns, lock, lockh, mode);
        if (!req_passed_in && req != NULL)
                ptlrpc_req_finished(req);
        LDLM_LOCK_PUT(lock);
 out_nolock:
        return rc;
}

static int ldlm_cli_convert_local(struct ldlm_lock *lock, int new_mode,
                                  int *flags)
{
        ENTRY;
        if (lock->l_resource->lr_namespace->ns_client) {
                CERROR("Trying to cancel local lock\n");
                LBUG();
        }
        LDLM_DEBUG(lock, "client-side local convert");

        ldlm_lock_convert(lock, new_mode, flags);
        ldlm_reprocess_all(lock->l_resource);

        LDLM_DEBUG(lock, "client-side local convert handler END");
        LDLM_LOCK_PUT(lock);
        RETURN(0);
}

/* FIXME: one of ldlm_cli_convert or the server side should reject attempted
 * conversion of locks which are on the waiting or converting queue */
int ldlm_cli_convert(struct lustre_handle *lockh, int new_mode, int *flags)
{
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        struct ptlrpc_request *req;
        int rc, size = sizeof(*body);
        ENTRY;

        lock = ldlm_handle2lock(lockh);
        if (!lock) {
                LBUG();
                RETURN(-EINVAL);
        }
        *flags = 0;

        if (lock->l_conn_export == NULL)
                RETURN(ldlm_cli_convert_local(lock, new_mode, flags));

        LDLM_DEBUG(lock, "client-side convert");

        req = ptlrpc_prep_req(class_exp2cliimp(lock->l_conn_export),
                              LDLM_CONVERT, 1, &size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->lock_handle1, &lock->l_remote_handle,
               sizeof(body->lock_handle1));

        body->lock_desc.l_req_mode = new_mode;
        body->lock_flags = *flags;

        size = sizeof(*reply);
        req->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(req);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        reply = lustre_swab_repbuf(req, 0, sizeof (*reply),
                                   lustre_swab_ldlm_reply);
        if (reply == NULL) {
                CERROR ("Can't unpack ldlm_reply\n");
                GOTO (out, rc = -EPROTO);
        }

        res = ldlm_lock_convert(lock, new_mode, &reply->lock_flags);
        if (res != NULL)
                ldlm_reprocess_all(res);
        /* Go to sleep until the lock is granted. */
        /* FIXME: or cancelled. */
        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, LDLM_FL_WAIT_NOREPROC, NULL);
        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
        ptlrpc_req_finished(req);
        return rc;
}

int ldlm_cli_cancel(struct lustre_handle *lockh)
{
        struct ptlrpc_request *req;
        struct ldlm_lock *lock;
        struct ldlm_request *body;
        int rc = 0, size = sizeof(*body);
        ENTRY;

        /* concurrent cancels on the same handle can happen */
        lock = __ldlm_handle2lock(lockh, LDLM_FL_CANCELING);
        if (lock == NULL)
                RETURN(0);

        if (lock->l_conn_export) {
                int local_only;
                struct obd_import *imp;

                LDLM_DEBUG(lock, "client-side cancel");
                /* Set this flag to prevent others from getting new references*/
                l_lock(&lock->l_resource->lr_namespace->ns_lock);
                lock->l_flags |= LDLM_FL_CBPENDING;
                local_only = (lock->l_flags & LDLM_FL_LOCAL_ONLY);
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                ldlm_cancel_callback(lock);

                if (local_only) {
                        CDEBUG(D_INFO, "not sending request (at caller's "
                               "instruction)\n");
                        goto local_cancel;
                }

        restart:
                imp = class_exp2cliimp(lock->l_conn_export);
                if (imp == NULL || imp->imp_invalid) {
                        CDEBUG(D_HA, "skipping cancel on invalid import %p\n",
                               imp);
                        goto local_cancel;
                }

                req = ptlrpc_prep_req(imp, LDLM_CANCEL, 1, &size, NULL);
                if (!req)
                        GOTO(out, rc = -ENOMEM);
                req->rq_no_resend = 1;

                /* XXX FIXME bug 249 */
                req->rq_request_portal = LDLM_CANCEL_REQUEST_PORTAL;
                req->rq_reply_portal = LDLM_CANCEL_REPLY_PORTAL;

                body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
                memcpy(&body->lock_handle1, &lock->l_remote_handle,
                       sizeof(body->lock_handle1));

                req->rq_replen = lustre_msg_size(0, NULL);

                rc = ptlrpc_queue_wait(req);

                if (rc == ESTALE) {
                        CERROR("client/server (nid "LPU64") out of sync--not "
                               "fatal\n",
                               req->rq_import->imp_connection->c_peer.peer_nid);
                } else if (rc == -ETIMEDOUT) {
                        ptlrpc_req_finished(req);
                        GOTO(restart, rc);
                } else if (rc != ELDLM_OK) {
                        CERROR("Got rc %d from cancel RPC: canceling "
                               "anyway\n", rc);
                }

                ptlrpc_req_finished(req);
        local_cancel:
                ldlm_lock_cancel(lock);
        } else {
                if (lock->l_resource->lr_namespace->ns_client) {
                        LDLM_ERROR(lock, "Trying to cancel local lock\n");
                        LBUG();
                }
                LDLM_DEBUG(lock, "client-side local cancel");
                ldlm_lock_cancel(lock);
                ldlm_reprocess_all(lock->l_resource);
                LDLM_DEBUG(lock, "client-side local cancel handler END");
        }

        EXIT;
 out:
        LDLM_LOCK_PUT(lock);
        return rc;
}

int ldlm_cancel_lru(struct ldlm_namespace *ns)
{
        struct list_head *tmp, *next, list = LIST_HEAD_INIT(list);
        int count, rc = 0;
        struct ldlm_ast_work *w;
        ENTRY;

        l_lock(&ns->ns_lock);
        count = ns->ns_nr_unused - ns->ns_max_unused;

        if (count <= 0) {
                l_unlock(&ns->ns_lock);
                RETURN(0);
        }

        list_for_each_safe(tmp, next, &ns->ns_unused_list) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_lru);

                LASSERT(!lock->l_readers && !lock->l_writers);

                /* Setting the CBPENDING flag is a little misleading, but
                 * prevents an important race; namely, once CBPENDING is set,
                 * the lock can accumulate no more readers/writers.  Since
                 * readers and writers are already zero here, ldlm_lock_decref
                 * won't see this flag and call l_blocking_ast */
                lock->l_flags |= LDLM_FL_CBPENDING;

                OBD_ALLOC(w, sizeof(*w));
                LASSERT(w);

                w->w_lock = LDLM_LOCK_GET(lock);
                list_add(&w->w_list, &list);
                ldlm_lock_remove_from_lru(lock);

                if (--count == 0)
                        break;
        }
        l_unlock(&ns->ns_lock);

        list_for_each_safe(tmp, next, &list) {
                struct lustre_handle lockh;
                int rc;
                w = list_entry(tmp, struct ldlm_ast_work, w_list);

                ldlm_lock2handle(w->w_lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc != ELDLM_OK)
                        CDEBUG(D_INFO, "ldlm_cli_cancel: %d\n", rc);

                list_del(&w->w_list);
                LDLM_LOCK_PUT(w->w_lock);
                OBD_FREE(w, sizeof(*w));
        }

        RETURN(rc);
}

static int ldlm_cli_cancel_unused_resource(struct ldlm_namespace *ns,
                                           struct ldlm_res_id res_id, int flags,
                                           void *opaque)
{
        struct ldlm_resource *res;
        struct list_head *tmp, *next, list = LIST_HEAD_INIT(list);
        struct ldlm_ast_work *w;
        ENTRY;

        res = ldlm_resource_get(ns, NULL, res_id, 0, 0);
        if (res == NULL) {
                /* This is not a problem. */
                CDEBUG(D_INFO, "No resource "LPU64"\n", res_id.name[0]);
                RETURN(0);
        }

        l_lock(&ns->ns_lock);
        list_for_each(tmp, &res->lr_granted) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (opaque != NULL && lock->l_ast_data != opaque) {
                        LDLM_ERROR(lock, "data %p doesn't match opaque %p",
                                   lock->l_ast_data, opaque);
                        //LBUG();
                        continue;
                }

                if (lock->l_readers || lock->l_writers) {
                        if (flags & LDLM_FL_WARN) {
                                LDLM_ERROR(lock, "lock in use");
                                //LBUG();
                        }
                        continue;
                }

                /* See CBPENDING comment in ldlm_cancel_lru */
                lock->l_flags |= LDLM_FL_CBPENDING;

                OBD_ALLOC(w, sizeof(*w));
                LASSERT(w);

                w->w_lock = LDLM_LOCK_GET(lock);

                /* Prevent the cancel callback from being called by setting
                 * LDLM_FL_CANCEL in the lock.  Very sneaky. -p */
                if (flags & LDLM_FL_NO_CALLBACK)
                        w->w_lock->l_flags |= LDLM_FL_CANCEL;

                list_add(&w->w_list, &list);
        }
        l_unlock(&ns->ns_lock);

        list_for_each_safe(tmp, next, &list) {
                struct lustre_handle lockh;
                int rc;
                w = list_entry(tmp, struct ldlm_ast_work, w_list);

                if (flags & LDLM_FL_LOCAL_ONLY) {
                        ldlm_lock_cancel(w->w_lock);
                } else {
                        ldlm_lock2handle(w->w_lock, &lockh);
                        rc = ldlm_cli_cancel(&lockh);
                        if (rc != ELDLM_OK)
                                CERROR("ldlm_cli_cancel: %d\n", rc);
                }
                list_del(&w->w_list);
                LDLM_LOCK_PUT(w->w_lock);
                OBD_FREE(w, sizeof(*w));
        }

        ldlm_resource_putref(res);

        RETURN(0);
}

/* Cancel all locks on a namespace (or a specific resource, if given)
 * that have 0 readers/writers.
 *
 * If flags & LDLM_FL_LOCAL_ONLY, throw the locks away without trying
 * to notify the server.
 * If flags & LDLM_FL_NO_CALLBACK, don't run the cancel callback.
 * If flags & LDLM_FL_WARN, print a warning if some locks are still in use. */
int ldlm_cli_cancel_unused(struct ldlm_namespace *ns,
                           struct ldlm_res_id *res_id, int flags, void *opaque)
{
        int i;
        ENTRY;

        if (ns == NULL)
                RETURN(ELDLM_OK);

        if (res_id)
                RETURN(ldlm_cli_cancel_unused_resource(ns, *res_id, flags,
                                                       opaque));

        l_lock(&ns->ns_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                struct list_head *tmp, *pos;
                list_for_each_safe(tmp, pos, &(ns->ns_hash[i])) {
                        int rc;
                        struct ldlm_resource *res;
                        res = list_entry(tmp, struct ldlm_resource, lr_hash);
                        ldlm_resource_getref(res);

                        rc = ldlm_cli_cancel_unused_resource(ns, res->lr_name,
                                                             flags, opaque);

                        if (rc)
                                CERROR("cancel_unused_res ("LPU64"): %d\n",
                                       res->lr_name.name[0], rc);
                        ldlm_resource_putref(res);
                }
        }
        l_unlock(&ns->ns_lock);

        RETURN(ELDLM_OK);
}

/* Lock iterators. */

int ldlm_resource_foreach(struct ldlm_resource *res, ldlm_iterator_t iter,
                          void *closure)
{
        struct list_head *tmp, *next;
        struct ldlm_lock *lock;
        int rc = LDLM_ITER_CONTINUE;
        struct ldlm_namespace *ns = res->lr_namespace;

        ENTRY;

        if (!res)
                RETURN(LDLM_ITER_CONTINUE);

        l_lock(&ns->ns_lock);
        list_for_each_safe(tmp, next, &res->lr_granted) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (iter(lock, closure) == LDLM_ITER_STOP)
                        GOTO(out, rc = LDLM_ITER_STOP);
        }

        list_for_each_safe(tmp, next, &res->lr_converting) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (iter(lock, closure) == LDLM_ITER_STOP)
                        GOTO(out, rc = LDLM_ITER_STOP);
        }

        list_for_each_safe(tmp, next, &res->lr_waiting) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (iter(lock, closure) == LDLM_ITER_STOP)
                        GOTO(out, rc = LDLM_ITER_STOP);
        }
 out:
        l_unlock(&ns->ns_lock);
        RETURN(rc);
}

struct iter_helper_data {
        ldlm_iterator_t iter;
        void *closure;
};

static int ldlm_iter_helper(struct ldlm_lock *lock, void *closure)
{
        struct iter_helper_data *helper = closure;
        return helper->iter(lock, helper->closure);
}

static int ldlm_res_iter_helper(struct ldlm_resource *res, void *closure)
{
        return ldlm_resource_foreach(res, ldlm_iter_helper, closure);
}

int ldlm_namespace_foreach(struct ldlm_namespace *ns, ldlm_iterator_t iter,
                           void *closure)
{
        struct iter_helper_data helper = { iter: iter, closure: closure };
        return ldlm_namespace_foreach_res(ns, ldlm_res_iter_helper, &helper);
}

int ldlm_namespace_foreach_res(struct ldlm_namespace *ns,
                               ldlm_res_iterator_t iter, void *closure)
{
        int i, rc = LDLM_ITER_CONTINUE;

        l_lock(&ns->ns_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                struct list_head *tmp, *next;
                list_for_each_safe(tmp, next, &(ns->ns_hash[i])) {
                        struct ldlm_resource *res =
                                list_entry(tmp, struct ldlm_resource, lr_hash);

                        ldlm_resource_getref(res);
                        rc = iter(res, closure);
                        ldlm_resource_putref(res);
                        if (rc == LDLM_ITER_STOP)
                                GOTO(out, rc);
                }
        }
 out:
        l_unlock(&ns->ns_lock);
        RETURN(rc);
}

/* non-blocking function to manipulate a lock whose cb_data is being put away.*/
void ldlm_change_cbdata(struct ldlm_namespace *ns, struct ldlm_res_id *res_id,
                        ldlm_iterator_t iter, void *data)
{
        struct ldlm_resource *res;
        ENTRY;

        if (ns == NULL) {
                CERROR("must pass in namespace");
                LBUG();
        }

        res = ldlm_resource_get(ns, NULL, *res_id, 0, 0);
        if (res == NULL) {
                EXIT;
                return;
        }

        l_lock(&ns->ns_lock);
        ldlm_resource_foreach(res, iter, data);
        l_unlock(&ns->ns_lock);
        ldlm_resource_putref(res);
        EXIT;
}

/* Lock replay */

static int ldlm_chain_lock_for_replay(struct ldlm_lock *lock, void *closure)
{
        struct list_head *list = closure;

        /* we use l_pending_chain here, because it's unused on clients. */
        list_add(&lock->l_pending_chain, list);
        return LDLM_ITER_CONTINUE;
}

static int replay_lock_interpret(struct ptlrpc_request *req,
                                    void * data, int rc)
{
        struct ldlm_lock *lock;
        struct ldlm_reply *reply;

        atomic_dec(&req->rq_import->imp_replay_inflight);
        if (rc != ELDLM_OK)
                GOTO(out, rc);

        lock = req->rq_async_args.pointer_arg[0];
        LASSERT(lock != NULL);

        reply = lustre_swab_repbuf(req, 0, sizeof (*reply),
                                   lustre_swab_ldlm_reply);
        if (reply == NULL) {
                CERROR("Can't unpack ldlm_reply\n");
                GOTO (out, rc = -EPROTO);
        }

        memcpy(&lock->l_remote_handle, &reply->lock_handle,
               sizeof(lock->l_remote_handle));
        LDLM_DEBUG(lock, "replayed lock:");
        ptlrpc_import_recovery_state_machine(req->rq_import);
 out:
        RETURN(rc);
}

static int replay_one_lock(struct obd_import *imp, struct ldlm_lock *lock)
{
        struct ptlrpc_request *req;
        struct ldlm_request *body;
        struct ldlm_reply *reply;
        int size;
        int flags;

        /*
         * If granted mode matches the requested mode, this lock is granted.
         *
         * If they differ, but we have a granted mode, then we were granted
         * one mode and now want another: ergo, converting.
         *
         * If we haven't been granted anything and are on a resource list,
         * then we're blocked/waiting.
         *
         * If we haven't been granted anything and we're NOT on a resource list,
         * then we haven't got a reply yet and don't have a known disposition.
         * This happens whenever a lock enqueue is the request that triggers
         * recovery.
         */
        if (lock->l_granted_mode == lock->l_req_mode)
                flags = LDLM_FL_REPLAY | LDLM_FL_BLOCK_GRANTED;
        else if (lock->l_granted_mode)
                flags = LDLM_FL_REPLAY | LDLM_FL_BLOCK_CONV;
        else if (!list_empty(&lock->l_res_link))
                flags = LDLM_FL_REPLAY | LDLM_FL_BLOCK_WAIT;
        else
                flags = LDLM_FL_REPLAY;

        size = sizeof(*body);
        req = ptlrpc_prep_req(imp, LDLM_ENQUEUE, 1, &size, NULL);
        if (!req)
                RETURN(-ENOMEM);

        /* We're part of recovery, so don't wait for it. */
        req->rq_send_state = LUSTRE_IMP_REPLAY_LOCKS;

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
        ldlm_lock2desc(lock, &body->lock_desc);
        body->lock_flags = flags;

        ldlm_lock2handle(lock, &body->lock_handle1);
        size = sizeof(*reply);
        req->rq_replen = lustre_msg_size(1, &size);

        LDLM_DEBUG(lock, "replaying lock:");

        atomic_inc(&req->rq_import->imp_replay_inflight);
        req->rq_async_args.pointer_arg[0] = lock;
        req->rq_interpret_reply = replay_lock_interpret;
        ptlrpcd_add_req(req);

        RETURN(0);
}

int ldlm_replay_locks(struct obd_import *imp)
{
        struct ldlm_namespace *ns = imp->imp_obd->obd_namespace;
        struct list_head list, *pos, *next;
        struct ldlm_lock *lock;
        int rc = 0;

        ENTRY;
        INIT_LIST_HEAD(&list);

        LASSERT(atomic_read(&imp->imp_replay_inflight) == 0);

        /* ensure this doesn't fall to 0 before all have been queued */
        atomic_inc(&imp->imp_replay_inflight);

        l_lock(&ns->ns_lock);
        (void)ldlm_namespace_foreach(ns, ldlm_chain_lock_for_replay, &list);

        list_for_each_safe(pos, next, &list) {
                lock = list_entry(pos, struct ldlm_lock, l_pending_chain);
                rc = replay_one_lock(imp, lock);
                if (rc)
                        break; /* or try to do the rest? */
        }
        l_unlock(&ns->ns_lock);

        atomic_dec(&imp->imp_replay_inflight);

        RETURN(rc);
}
