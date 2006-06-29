/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/fid/fid_handler.c
 *  Lustre Sequence Manager
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
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
#include <obd_class.h>
#include <dt_object.h>
#include <md_object.h>
#include <obd_support.h>
#include <lustre_req_layout.h>
#include <lustre_fid.h>
#include "fid_internal.h"

#ifdef __KERNEL__
/* sequence space, starts from 0x400 to have first 0x400 sequences used for
 * special purposes. */
const struct lu_range LUSTRE_SEQ_SPACE_RANGE = {
        (0x400),
        ((__u64)~0ULL)
};
EXPORT_SYMBOL(LUSTRE_SEQ_SPACE_RANGE);

/* zero range, used for init and other purposes */
const struct lu_range LUSTRE_SEQ_ZERO_RANGE = {
        0,
        0
};
EXPORT_SYMBOL(LUSTRE_SEQ_ZERO_RANGE);

/* assigns client to sequence controller node */
int
seq_server_init_ctlr(struct lu_server_seq *seq,
                     struct lu_client_seq *cli,
                     const struct lu_context *ctx)
{
        int rc = 0;
        ENTRY;
        
        LASSERT(cli != NULL);

        if (seq->seq_cli) {
                CERROR("SEQ-MGR(srv): sequence-controller "
                       "is already assigned\n");
                RETURN(-EINVAL);
        }

        CDEBUG(D_INFO|D_WARNING, "SEQ-MGR(srv): assign "
               "sequence controller client %s\n",
               cli->seq_exp->exp_client_uuid.uuid);

        down(&seq->seq_sem);
        
        /* assign controller */
        seq->seq_cli = cli;

        /* get new range from controller only if super-sequence is not yet
         * initialized from backing store or something else. */
        if (range_is_zero(&seq->seq_super)) {
                rc = seq_client_alloc_super(cli);
                if (rc) {
                        CERROR("can't allocate super-sequence, "
                               "rc %d\n", rc);
                        RETURN(rc);
                }

                /* take super-seq from client seq mgr */
                LASSERT(range_is_sane(&cli->seq_range));

                seq->seq_super = cli->seq_range;

                /* save init seq to backing store. */
                rc = seq_store_write(seq, ctx);
                if (rc) {
                        CERROR("can't write sequence state, "
                               "rc = %d\n", rc);
                }
        }
        up(&seq->seq_sem);
        RETURN(rc);
}
EXPORT_SYMBOL(seq_server_init_ctlr);

void
seq_server_fini_ctlr(struct lu_server_seq *seq)
{
        ENTRY;

        down(&seq->seq_sem);
        seq->seq_cli = NULL;
        up(&seq->seq_sem);
        
        EXIT;
}
EXPORT_SYMBOL(seq_server_fini_ctlr);

/* on controller node, allocate new super sequence for regular sequnece
 * server. */
static int
__seq_server_alloc_super(struct lu_server_seq *seq,
                         struct lu_range *range,
                         const struct lu_context *ctx)
{
        struct lu_range *space = &seq->seq_space;
        int rc;
        ENTRY;

        LASSERT(range_is_sane(space));
        
        if (range_space(space) < seq->seq_super_width) {
                CWARN("sequences space is going to exhaust soon. "
                      "Only can allocate "LPU64" sequences\n",
                      space->lr_end - space->lr_start);
                *range = *space;
                space->lr_start = space->lr_end;
                rc = 0;
        } else if (range_is_exhausted(space)) {
                CERROR("sequences space is exhausted\n");
                rc = -ENOSPC;
        } else {
                range_alloc(range, space, seq->seq_super_width);
                rc = 0;
        }

        rc = seq_store_write(seq, ctx);
        if (rc) {
                CERROR("can't save state, rc = %d\n",
		       rc);
        }

        if (rc == 0) {
                CDEBUG(D_INFO, "SEQ-MGR(srv): allocated super-sequence "
                       "["LPX64"-"LPX64"]\n", range->lr_start, range->lr_end);
        }
        
        RETURN(rc);
}

static int
seq_server_alloc_super(struct lu_server_seq *seq,
                       struct lu_range *range,
                       const struct lu_context *ctx)
{
        int rc;
        ENTRY;

        down(&seq->seq_sem);
        rc = __seq_server_alloc_super(seq, range, ctx);
        up(&seq->seq_sem);
        
        RETURN(rc);
}

static int
__seq_server_alloc_meta(struct lu_server_seq *seq,
                        struct lu_range *range,
                        const struct lu_context *ctx)
{
        struct lu_range *super = &seq->seq_super;
        int rc = 0;
        ENTRY;

        LASSERT(range_is_sane(super));

        /* XXX: here we should avoid cascading RPCs using kind of async
         * preallocation when meta-sequence is close to exhausting. */
        if (range_is_exhausted(super)) {
                if (!seq->seq_cli) {
                        CERROR("no seq-controller client is setup\n");
                        RETURN(-EOPNOTSUPP);
                }

                rc = seq_client_alloc_super(seq->seq_cli);
                if (rc) {
                        CERROR("can't allocate new super-sequence, "
                               "rc %d\n", rc);
                        RETURN(rc);
                }

                /* saving new range into allocation space. */
                *super = seq->seq_cli->seq_range;
                LASSERT(range_is_sane(super));
        }
        range_alloc(range, super, seq->seq_meta_width);

        rc = seq_store_write(seq, ctx);
        if (rc) {
                CERROR("can't save state, rc = %d\n",
		       rc);
        }

        if (rc == 0) {
                CDEBUG(D_INFO, "SEQ-MGR(srv): allocated meta-sequence "
                       "["LPX64"-"LPX64"]\n", range->lr_start, range->lr_end);
        }

        RETURN(rc);
}

static int
seq_server_alloc_meta(struct lu_server_seq *seq,
                      struct lu_range *range,
                      const struct lu_context *ctx)
{
        int rc;
        ENTRY;

        down(&seq->seq_sem);
        rc = __seq_server_alloc_meta(seq, range, ctx);
        up(&seq->seq_sem);
        
        RETURN(rc);
}

static int
seq_server_handle(struct lu_server_seq *seq,
                  const struct lu_context *ctx, 
                  struct lu_range *range,
                  __u32 opc)
{
        int rc;
        ENTRY;

        switch (opc) {
        case SEQ_ALLOC_SUPER:
                rc = seq_server_alloc_super(seq, range, ctx);
                break;
        case SEQ_ALLOC_META:
                rc = seq_server_alloc_meta(seq, range, ctx);
                break;
        default:
                CERROR("wrong opc 0x%x\n", opc);
                rc = -EINVAL;
                break;
        }
        RETURN(rc);
}

static int
seq_req_handle0(const struct lu_context *ctx,
                struct ptlrpc_request *req) 
{
        int rep_buf_size[2] = { 0, };
        struct obd_device *obd;
        struct req_capsule pill;
        struct lu_site *site;
        struct lu_range *out;
        int rc = -EPROTO;
        __u32 *opc;
        ENTRY;

        obd = req->rq_export->exp_obd;
        site = obd->obd_lu_dev->ld_site;
        LASSERT(site != NULL);
			
        req_capsule_init(&pill, req, RCL_SERVER,
                         rep_buf_size);

        req_capsule_set(&pill, &RQF_SEQ_QUERY);
        req_capsule_pack(&pill);

        opc = req_capsule_client_get(&pill, &RMF_SEQ_OPC);
        if (opc != NULL) {
                out = req_capsule_server_get(&pill, &RMF_SEQ_RANGE);
                if (out == NULL) {
                        CERROR("can't get range buffer\n");
                        GOTO(out_pill, rc= -EPROTO);
                }
                
                if (*opc == SEQ_ALLOC_META) {
                        if (!site->ls_server_seq) {
                                CERROR("sequence-server is not initialized\n");
                                GOTO(out_pill, rc == -EINVAL);
                        }
                        rc = seq_server_handle(site->ls_server_seq,
                                               ctx, out, *opc);
                } else {
                        if (!site->ls_ctlr_seq) {
                                CERROR("sequence-controller is not initialized\n");
                                GOTO(out_pill, rc == -EINVAL);
                        }
                        rc = seq_server_handle(site->ls_ctlr_seq,
                                               ctx, out, *opc);
                }
        } else {
                CERROR("cannot unpack client request\n");
        }

out_pill:
        EXIT;
        req_capsule_fini(&pill);
        return rc;
}

static int 
seq_req_handle(struct ptlrpc_request *req) 
{
        int fail = OBD_FAIL_SEQ_ALL_REPLY_NET;
        const struct lu_context *ctx;
        int rc = -EPROTO;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_SEQ_ALL_REPLY_NET | OBD_FAIL_ONCE, 0);
        
        ctx = req->rq_svc_thread->t_ctx;
        LASSERT(ctx != NULL);
        LASSERT(ctx->lc_thread == req->rq_svc_thread);
        if (req->rq_reqmsg->opc == SEQ_QUERY) {
                if (req->rq_export != NULL) {
                        rc = seq_req_handle0(ctx, req);
                } else {
                        CERROR("Unconnected request\n");
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }
        } else {
                CERROR("Wrong opcode: %d\n",
                       req->rq_reqmsg->opc);
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        EXIT;
out:
        target_send_reply(req, rc, fail);
        return 0;
} 

#ifdef LPROCFS
static int
seq_server_proc_init(struct lu_server_seq *seq)
{
        int rc;
        ENTRY;

        seq->seq_proc_dir = lprocfs_register(seq->seq_name,
                                             proc_lustre_root,
                                             NULL, NULL);
        if (IS_ERR(seq->seq_proc_dir)) {
                CERROR("LProcFS failed in seq-init\n");
                rc = PTR_ERR(seq->seq_proc_dir);
                GOTO(err, rc);
        }

        seq->seq_proc_entry = lprocfs_register("services",
                                               seq->seq_proc_dir,
                                               NULL, NULL);
        if (IS_ERR(seq->seq_proc_entry)) {
                CERROR("LProcFS failed in seq-init\n");
                rc = PTR_ERR(seq->seq_proc_entry);
                GOTO(err_type, rc);
        }

        rc = lprocfs_add_vars(seq->seq_proc_dir,
                              seq_server_proc_list, seq);
        if (rc) {
                CERROR("can't init sequence manager "
                       "proc, rc %d\n", rc);
                GOTO(err_type, rc);
        }

        RETURN(0);

err_type:
        lprocfs_remove(seq->seq_proc_dir);
err:
        seq->seq_proc_dir = NULL;
        seq->seq_proc_entry = NULL;
        return rc;
}

static void
seq_server_proc_fini(struct lu_server_seq *seq)
{
        ENTRY;
        if (seq->seq_proc_entry) {
                lprocfs_remove(seq->seq_proc_entry);
                seq->seq_proc_entry = NULL;
        }

        if (seq->seq_proc_dir) {
                lprocfs_remove(seq->seq_proc_dir);
                seq->seq_proc_dir = NULL;
        }
        EXIT;
}
#endif

int
seq_server_init(struct lu_server_seq *seq,
                struct dt_device *dev,
                const char *uuid,
                lu_server_type_t type,
                const struct lu_context *ctx) 
{
        int rc, portal = (type == LUSTRE_SEQ_SRV) ?
                SEQ_SRV_PORTAL : SEQ_CTLR_PORTAL;
        
        struct ptlrpc_service_conf seq_conf = { 
                .psc_nbufs = MDS_NBUFS, 
                .psc_bufsize = MDS_BUFSIZE, 
                .psc_max_req_size = MDS_MAXREQSIZE,
                .psc_max_reply_size = MDS_MAXREPSIZE,
                .psc_req_portal = portal,
                .psc_rep_portal = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = SEQ_SERVICE_WATCHDOG_TIMEOUT, 
                .psc_num_threads = SEQ_NUM_THREADS
        };
        ENTRY;

	LASSERT(dev != NULL);
        LASSERT(uuid != NULL);

        seq->seq_dev = dev;
        seq->seq_cli = NULL;
        seq->seq_type = type;
        sema_init(&seq->seq_sem, 1);

        seq->seq_super_width = LUSTRE_SEQ_SUPER_WIDTH;
        seq->seq_meta_width = LUSTRE_SEQ_META_WIDTH;

        snprintf(seq->seq_name, sizeof(seq->seq_name), "%s-%s-%s",
                 LUSTRE_SEQ_NAME, (type == LUSTRE_SEQ_SRV ? "srv" : "ctlr"),
                 uuid);
        
        seq->seq_space = LUSTRE_SEQ_SPACE_RANGE;
        seq->seq_super = LUSTRE_SEQ_ZERO_RANGE;
        
        lu_device_get(&seq->seq_dev->dd_lu_dev);

        rc = seq_store_init(seq, ctx);
        if (rc)
                GOTO(out, rc);
        
        /* request backing store for saved sequence info */
        rc = seq_store_read(seq, ctx);
        if (rc == -ENODATA) {
                if (type == LUSTRE_SEQ_SRV) {
                        CDEBUG(D_INFO|D_WARNING, "SEQ-MGR(srv): no data on "
                               "disk found, waiting for controller assign\n");
                } else {
                        CDEBUG(D_INFO|D_WARNING, "SEQ-MGR(ctlr): no data on "
                               "disk found, this is first controller run\n");
                }
        } else if (rc) {
		CERROR("can't read sequence state, rc = %d\n",
		       rc);
		GOTO(out, rc);
	}
        
#ifdef LPROCFS
        rc  = seq_server_proc_init(seq);
        if (rc)
		GOTO(out, rc);
#endif

        seq->seq_service =  ptlrpc_init_svc_conf(&seq_conf,
						 seq_req_handle,
                                                 LUSTRE_SEQ_NAME,
						 seq->seq_proc_entry, 
						 NULL); 
	if (seq->seq_service != NULL)
		rc = ptlrpc_start_threads(NULL, seq->seq_service,
                                          LUSTRE_SEQ_NAME);
	else 
		rc = -ENOMEM; 

	EXIT;

out:
	if (rc) {
		seq_server_fini(seq, ctx);
        } else {
                CDEBUG(D_INFO|D_WARNING, "%s Sequence Manager\n",
                       (type == LUSTRE_SEQ_SRV ? "Server" : "Controller"));
        }
	return rc;
} 
EXPORT_SYMBOL(seq_server_init);

void
seq_server_fini(struct lu_server_seq *seq,
                const struct lu_context *ctx) 
{
        ENTRY;

        if (seq->seq_service != NULL) {
                ptlrpc_unregister_service(seq->seq_service);
                seq->seq_service = NULL;
        }

#ifdef LPROCFS
        seq_server_proc_fini(seq);
#endif

        seq_store_fini(seq, ctx);

        if (seq->seq_dev != NULL) {
                lu_device_put(&seq->seq_dev->dd_lu_dev);
                seq->seq_dev = NULL;
        }
        
        CDEBUG(D_INFO|D_WARNING, "Server Sequence "
               "Manager\n");
        EXIT;
}
EXPORT_SYMBOL(seq_server_fini);

static int fid_init(void)
{
	ENTRY;
	RETURN(0);
}

static int fid_fini(void)
{
	ENTRY;
	RETURN(0);
}

static int 
__init fid_mod_init(void) 

{
        /* init caches if any */
        fid_init();
        return 0;
}

static void 
__exit fid_mod_exit(void) 
{
        /* free caches if any */
        fid_fini();
        return;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre FID Module");
MODULE_LICENSE("GPL");

cfs_module(fid, "0.0.4", fid_mod_init, fid_mod_exit);
#endif
