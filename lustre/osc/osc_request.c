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

# include <linux/lustre_dlm.h>
#include <linux/kp30.h>
#include <linux/lustre_net.h>
#include <linux/lustre_user.h>
#include <linux/obd_ost.h>
#include <linux/obd_lov.h>

#ifdef  __CYGWIN__
# include <ctype.h>
#endif

#include <linux/lustre_ha.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_log.h>
#include "osc_internal.h"


static int osc_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        lprocfs_init_vars(osc,&lvars);
        rc = lprocfs_obd_attach(dev, lvars.obd_vars);
        if (rc < 0)
                RETURN(rc);

        rc = lproc_osc_attach_seqstat(dev);
        if (rc < 0) {
                lprocfs_obd_detach(dev);
                RETURN(rc);
        }

        ptlrpc_lprocfs_register_obd(dev);
        RETURN(0);
}

static int osc_detach(struct obd_device *dev)
{
        ptlrpc_lprocfs_unregister_obd(dev);
        return lprocfs_obd_detach(dev);
}


/* Pack OSC object metadata for disk storage (LE byte order). */
static int osc_packmd(struct obd_export *exp, struct lov_mds_md **lmmp,
                      struct lov_stripe_md *lsm)
{
        int lmm_size;
        ENTRY;

        lmm_size = sizeof(**lmmp);
        if (!lmmp)
                RETURN(lmm_size);

        if (*lmmp && !lsm) {
                OBD_FREE(*lmmp, lmm_size);
                *lmmp = NULL;
                RETURN(0);
        }

        if (!*lmmp) {
                OBD_ALLOC(*lmmp, lmm_size);
                if (!*lmmp)
                        RETURN(-ENOMEM);
        }

        if (lsm) {
                LASSERT(lsm->lsm_object_id);
                (*lmmp)->lmm_object_id = cpu_to_le64(lsm->lsm_object_id);
        }

        RETURN(lmm_size);
}

/* Unpack OSC object metadata from disk storage (LE byte order). */
static int osc_unpackmd(struct obd_export *exp, struct lov_stripe_md **lsmp,
                        struct lov_mds_md *lmm, int lmm_bytes)
{
        int lsm_size;
        ENTRY;

        if (lmm != NULL) {
                if (lmm_bytes < sizeof (*lmm)) {
                        CERROR("lov_mds_md too small: %d, need %d\n",
                               lmm_bytes, (int)sizeof(*lmm));
                        RETURN(-EINVAL);
                }
                /* XXX LOV_MAGIC etc check? */

                if (lmm->lmm_object_id == 0) {
                        CERROR("lov_mds_md: zero lmm_object_id\n");
                        RETURN(-EINVAL);
                }
        }

        lsm_size = lov_stripe_md_size(1);
        if (lsmp == NULL)
                RETURN(lsm_size);

        if (*lsmp != NULL && lmm == NULL) {
                OBD_FREE(*lsmp, lsm_size);
                *lsmp = NULL;
                RETURN(0);
        }

        if (*lsmp == NULL) {
                OBD_ALLOC(*lsmp, lsm_size);
                if (*lsmp == NULL)
                        RETURN(-ENOMEM);
                loi_init((*lsmp)->lsm_oinfo);
        }

        if (lmm != NULL) {
                /* XXX zero *lsmp? */
                (*lsmp)->lsm_object_id = le64_to_cpu (lmm->lmm_object_id);
                LASSERT((*lsmp)->lsm_object_id);
        }

        (*lsmp)->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES;

        RETURN(lsm_size);
}

static int osc_getattr_interpret(struct ptlrpc_request *req,
                                 struct osc_getattr_async_args *aa, int rc)
{
        struct ost_body *body;
        ENTRY;

        if (rc != 0)
                RETURN(rc);

        body = lustre_swab_repbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body) {
                CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
                memcpy(aa->aa_oa, &body->oa, sizeof(*aa->aa_oa));

                /* This should really be sent by the OST */
                aa->aa_oa->o_blksize = PTLRPC_MAX_BRW_SIZE;
                aa->aa_oa->o_valid |= OBD_MD_FLBLKSZ;
        } else {
                CERROR("can't unpack ost_body\n");
                rc = -EPROTO;
                aa->aa_oa->o_valid = 0;
        }

        RETURN(rc);
}

static int osc_getattr_async(struct obd_export *exp, struct obdo *oa,
                             struct lov_stripe_md *md,
                             struct ptlrpc_request_set *set)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int size = sizeof(*body);
        struct osc_getattr_async_args *aa;
        ENTRY;

        request = ptlrpc_prep_req(class_exp2cliimp(exp), OST_GETATTR, 1,
                                  &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);
        request->rq_interpret_reply = osc_getattr_interpret;

        LASSERT (sizeof (*aa) <= sizeof (request->rq_async_args));
        aa = (struct osc_getattr_async_args *)&request->rq_async_args;
        aa->aa_oa = oa;

        ptlrpc_set_add_req (set, request);
        RETURN (0);
}

static int osc_getattr(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *md)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        request = ptlrpc_prep_req(class_exp2cliimp(exp), OST_GETATTR, 1,
                                  &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc) {
                CERROR("%s failed: rc = %d\n", __FUNCTION__, rc);
                GOTO(out, rc);
        }

        body = lustre_swab_repbuf(request, 0, sizeof (*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                GOTO (out, rc = -EPROTO);
        }

        CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
        memcpy(oa, &body->oa, sizeof(*oa));

        /* This should really be sent by the OST */
        oa->o_blksize = PTLRPC_MAX_BRW_SIZE;
        oa->o_valid |= OBD_MD_FLBLKSZ;

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_setattr(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        request = ptlrpc_prep_req(class_exp2cliimp(exp), OST_SETATTR, 1, &size,
                                  NULL);
        if (!request)
		RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof(*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_swab_repbuf(request, 0, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL)
                GOTO(out, rc = -EPROTO);

        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
out:
        ptlrpc_req_finished(request);
        RETURN(0);
}

int osc_real_create(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        struct lov_stripe_md *lsm;
        int rc, size = sizeof(*body);
        ENTRY;

        LASSERT(oa);
        LASSERT(ea);

        lsm = *ea;
        if (!lsm) {
                rc = obd_alloc_memmd(exp, &lsm);
                if (rc < 0)
                        RETURN(rc);
        }

        request = ptlrpc_prep_req(class_exp2cliimp(exp), OST_CREATE, 1, &size,
                                  NULL);
        if (!request)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(body->oa));

        request->rq_replen = lustre_msg_size(1, &size);
        if (oa->o_valid & OBD_MD_FLINLINE) {
                LASSERT((oa->o_valid & OBD_MD_FLFLAGS) &&
                        oa->o_flags == OBD_FL_DELORPHAN);
                DEBUG_REQ(D_HA, request,
                          "delorphan from OST integration");
        }

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_req, rc);

        body = lustre_swab_repbuf(request, 0, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                GOTO (out_req, rc = -EPROTO);
        }

        memcpy(oa, &body->oa, sizeof(*oa));

        /* This should really be sent by the OST */
        oa->o_blksize = PTLRPC_MAX_BRW_SIZE;
        oa->o_valid |= OBD_MD_FLBLKSZ;

        /* XXX LOV STACKING: the lsm that is passed to us from LOV does not
         * have valid lsm_oinfo data structs, so don't go touching that.
         * This needs to be fixed in a big way.
         */
        lsm->lsm_object_id = oa->o_id;
        *ea = lsm;

        if (oti != NULL) {
                oti->oti_transno = request->rq_repmsg->transno;

                if (oa->o_valid & OBD_MD_FLCOOKIE) {
                        if (!oti->oti_logcookies)
                                oti_alloc_cookies(oti, 1);
                        memcpy(oti->oti_logcookies, obdo_logcookie(oa),
                               sizeof(oti->oti_onecookie));
                }
        }

        CDEBUG(D_HA, "transno: "LPD64"\n", request->rq_repmsg->transno);
        EXIT;
out_req:
        ptlrpc_req_finished(request);
out:
        if (rc && !*ea)
                obd_free_memmd(exp, &lsm);
        return rc;
}

static int osc_punch(struct obd_export *exp, struct obdo *oa,
                     struct lov_stripe_md *md, obd_size start,
                     obd_size end, struct obd_trans_info *oti)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }

        request = ptlrpc_prep_req(class_exp2cliimp(exp), OST_PUNCH, 1, &size,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        /* overload the size and blocks fields in the oa with start/end */
        body->oa.o_size = start;
        body->oa.o_blocks = end;
        body->oa.o_valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_swab_repbuf (request, 0, sizeof (*body),
                                   lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                GOTO (out, rc = -EPROTO);
        }

        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_sync(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *md, obd_size start, obd_size end)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }

        request = ptlrpc_prep_req(class_exp2cliimp(exp), OST_SYNC, 1, &size,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        /* overload the size and blocks fields in the oa with start/end */
        body->oa.o_size = start;
        body->oa.o_blocks = end;
        body->oa.o_valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_swab_repbuf(request, 0, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                GOTO (out, rc = -EPROTO);
        }

        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_destroy(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *ea, struct obd_trans_info *oti)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        if (!oa) {
                CERROR("oa NULL\n");
                RETURN(-EINVAL);
        }

        request = ptlrpc_prep_req(class_exp2cliimp(exp), OST_DESTROY, 1,
                                  &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));

        if (oti != NULL && oa->o_valid & OBD_MD_FLCOOKIE) {
                memcpy(obdo_logcookie(oa), oti->oti_logcookies,
                       sizeof(*oti->oti_logcookies));
                oti->oti_logcookies++;
        }

        memcpy(&body->oa, oa, sizeof(*oa));
        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_swab_repbuf(request, 0, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("Can't unpack body\n");
                GOTO (out, rc = -EPROTO);
        }

        memcpy(oa, &body->oa, sizeof(*oa));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static void osc_announce_cached(struct client_obd *cli, struct obdo *oa,
                                long writing_bytes)
{
        obd_flag bits = OBD_MD_FLBLOCKS|OBD_MD_FLGRANT;

        LASSERT(!(oa->o_valid & bits));

        oa->o_valid |= bits;
        spin_lock(&cli->cl_loi_list_lock);
        oa->o_dirty = cli->cl_dirty;
        oa->o_undirty = cli->cl_dirty_max - oa->o_dirty;
        oa->o_grant = cli->cl_avail_grant;
        oa->o_dropped = cli->cl_lost_grant;
        cli->cl_lost_grant = 0;
        spin_unlock(&cli->cl_loi_list_lock);
        CDEBUG(D_CACHE,"dirty: "LPU64" undirty: %u dropped %u grant: "LPU64"\n",
               oa->o_dirty, oa->o_undirty, oa->o_dropped, oa->o_grant);
}

/* caller must hold loi_list_lock */
static void osc_consume_write_grant(struct client_obd *cli,
                                    struct osc_async_page *oap)
{
        cli->cl_dirty += PAGE_SIZE;
        cli->cl_avail_grant -= PAGE_SIZE;
        oap->oap_brw_flags |= OBD_BRW_FROM_GRANT;
        CDEBUG(D_CACHE, "using %lu grant credits for oap %p\n", PAGE_SIZE, oap);
        LASSERT(cli->cl_avail_grant >= 0);
}

/* caller must hold loi_list_lock */
void osc_wake_cache_waiters(struct client_obd *cli)
{
        struct list_head *l, *tmp;
        struct osc_cache_waiter *ocw;

        list_for_each_safe(l, tmp, &cli->cl_cache_waiters) {
                /* if we can't dirty more, we must wait until some is written */
                if (cli->cl_dirty + PAGE_SIZE > cli->cl_dirty_max) {
                        CDEBUG(D_CACHE, "no dirty room: dirty: %ld max %ld\n",
                               cli->cl_dirty, cli->cl_dirty_max);
                        return;
                }

                /* if still dirty cache but no grant wait for pending RPCs that
                 * may yet return us some grant before doing sync writes */
                if (cli->cl_brw_in_flight && cli->cl_avail_grant < PAGE_SIZE) {
                        CDEBUG(D_CACHE, "%d BRWs in flight, no grant\n",
                               cli->cl_brw_in_flight);
                        return;
                }

                ocw = list_entry(l, struct osc_cache_waiter, ocw_entry);
                list_del_init(&ocw->ocw_entry);
                if (cli->cl_avail_grant < PAGE_SIZE) {
                        /* no more RPCs in flight to return grant, do sync IO */
                        ocw->ocw_rc = -EDQUOT;
                        CDEBUG(D_INODE, "wake oap %p for sync\n", ocw->ocw_oap);
                } else {
                        osc_consume_write_grant(cli, ocw->ocw_oap);
                }

                wake_up(&ocw->ocw_waitq);
        }

        EXIT;
}

static void osc_update_grant(struct client_obd *cli, struct ost_body *body)
{
        spin_lock(&cli->cl_loi_list_lock);
        CDEBUG(D_CACHE, "got "LPU64" extra grant\n", body->oa.o_grant);
        cli->cl_avail_grant += body->oa.o_grant;
        /* waiters are woken in brw_interpret_oap */
        spin_unlock(&cli->cl_loi_list_lock);
}

/* We assume that the reason this OSC got a short read is because it read
 * beyond the end of a stripe file; i.e. lustre is reading a sparse file
 * via the LOV, and it _knows_ it's reading inside the file, it's just that
 * this stripe never got written at or beyond this stripe offset yet. */
static void handle_short_read(int nob_read, obd_count page_count,
                              struct brw_page *pga)
{
        char *ptr;

        /* skip bytes read OK */
        while (nob_read > 0) {
                LASSERT (page_count > 0);

                if (pga->count > nob_read) {
                        /* EOF inside this page */
                        ptr = kmap(pga->pg) + (pga->off & ~PAGE_MASK);
                        memset(ptr + nob_read, 0, pga->count - nob_read);
                        kunmap(pga->pg);
                        page_count--;
                        pga++;
                        break;
                }

                nob_read -= pga->count;
                page_count--;
                pga++;
        }

        /* zero remaining pages */
        while (page_count-- > 0) {
                ptr = kmap(pga->pg) + (pga->off & ~PAGE_MASK);
                memset(ptr, 0, pga->count);
                kunmap(pga->pg);
                pga++;
        }
}

static int check_write_rcs(struct ptlrpc_request *request,
                           int requested_nob, int niocount,
                           obd_count page_count, struct brw_page *pga)
{
        int    *remote_rcs, i;

        /* return error if any niobuf was in error */
        remote_rcs = lustre_swab_repbuf(request, 1,
                                        sizeof(*remote_rcs) * niocount, NULL);
        if (remote_rcs == NULL) {
                CERROR("Missing/short RC vector on BRW_WRITE reply\n");
                return(-EPROTO);
        }
        if (lustre_msg_swabbed(request->rq_repmsg))
                for (i = 0; i < niocount; i++)
                        __swab32s(&remote_rcs[i]);

        for (i = 0; i < niocount; i++) {
                if (remote_rcs[i] < 0)
                        return(remote_rcs[i]);

                if (remote_rcs[i] != 0) {
                        CERROR("rc[%d] invalid (%d) req %p\n",
                                i, remote_rcs[i], request);
                        return(-EPROTO);
                }
        }

        if (request->rq_bulk->bd_nob_transferred != requested_nob) {
                CERROR("Unexpected # bytes transferred: %d (requested %d)\n",
                       requested_nob, request->rq_bulk->bd_nob_transferred);
                return(-EPROTO);
        }

        return (0);
}

static inline int can_merge_pages(struct brw_page *p1, struct brw_page *p2)
{
        if (p1->flag != p2->flag) {
                unsigned mask = ~OBD_BRW_FROM_GRANT;

                /* warn if we try to combine flags that we don't know to be
                 * safe to combine */
                if ((p1->flag & mask) != (p2->flag & mask))
                        CERROR("is it ok to have flags 0x%x and 0x%x in the "
                               "same brw?\n", p1->flag, p2->flag);
                return 0;
        }

        return (p1->off + p1->count == p2->off);
}

#if CHECKSUM_BULK
static obd_count cksum_pages(int nob, obd_count page_count,
                             struct brw_page *pga)
{
        obd_count cksum = 0;
        char *ptr;

        while (nob > 0) {
                LASSERT (page_count > 0);

                ptr = kmap(pga->pg);
                ost_checksum(&cksum, ptr + (pga->off & (PAGE_SIZE - 1)),
                             pga->count > nob ? nob : pga->count);
                kunmap(pga->pg);

                nob -= pga->count;
                page_count--;
                pga++;
        }

        return (cksum);
}
#endif

static int osc_brw_prep_request(int cmd, struct obd_import *imp,struct obdo *oa,
                                struct lov_stripe_md *lsm, obd_count page_count,
                                struct brw_page *pga, int *requested_nobp,
                                int *niocountp, struct ptlrpc_request **reqp)
{
        struct ptlrpc_request   *req;
        struct ptlrpc_bulk_desc *desc;
        struct client_obd       *cli = &imp->imp_obd->u.cli;
        struct ost_body         *body;
        struct obd_ioobj        *ioobj;
        struct niobuf_remote    *niobuf;
        unsigned long            flags;
        int                      niocount;
        int                      size[3];
        int                      i;
        int                      requested_nob;
        int                      opc;
        int                      rc;

        opc = ((cmd & OBD_BRW_WRITE) != 0) ? OST_WRITE : OST_READ;

        for (niocount = i = 1; i < page_count; i++)
                if (!can_merge_pages(&pga[i - 1], &pga[i]))
                        niocount++;

        size[0] = sizeof(*body);
        size[1] = sizeof(*ioobj);
        size[2] = niocount * sizeof(*niobuf);

        req = ptlrpc_prep_req(imp, opc, 3, size, NULL);
        if (req == NULL)
                return (-ENOMEM);

        if (opc == OST_WRITE)
                desc = ptlrpc_prep_bulk_imp (req, page_count,
                                             BULK_GET_SOURCE, OST_BULK_PORTAL);
        else
                desc = ptlrpc_prep_bulk_imp (req, page_count,
                                             BULK_PUT_SINK, OST_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);
        /* NB request now owns desc and will free it when it gets freed */

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*body));
        ioobj = lustre_msg_buf(req->rq_reqmsg, 1, sizeof(*ioobj));
        niobuf = lustre_msg_buf(req->rq_reqmsg, 2, niocount * sizeof(*niobuf));

        memcpy(&body->oa, oa, sizeof(*oa));

        obdo_to_ioobj(oa, ioobj);
        ioobj->ioo_bufcnt = niocount;

        LASSERT (page_count > 0);
        for (requested_nob = i = 0; i < page_count; i++, niobuf++) {
                struct brw_page *pg = &pga[i];
                struct brw_page *pg_prev = pg - 1;

                LASSERT(pg->count > 0);
                LASSERT((pg->off & ~PAGE_MASK) + pg->count <= PAGE_SIZE);
                LASSERTF(i == 0 || pg->off > pg_prev->off,
                         "i %d p_c %u pg %p [pri %lu ind %lu] off "LPU64
                         " prev_pg %p [pri %lu ind %lu] off "LPU64"\n",
                         i, page_count,
                         pg->pg, pg->pg->private, pg->pg->index, pg->off,
                         pg_prev->pg, pg_prev->pg->private, pg_prev->pg->index,
                                 pg_prev->off);

                ptlrpc_prep_bulk_page(desc, pg->pg, pg->off & ~PAGE_MASK,
                                      pg->count);
                requested_nob += pg->count;

                if (i > 0 && can_merge_pages(pg_prev, pg)) {
                        niobuf--;
                        niobuf->len += pg->count;
                } else {
                        niobuf->offset = pg->off;
                        niobuf->len    = pg->count;
                        niobuf->flags  = pg->flag;
                }
        }

        LASSERT((void *)(niobuf - niocount) ==
                lustre_msg_buf(req->rq_reqmsg, 2, niocount * sizeof(*niobuf)));
        osc_announce_cached(cli, &body->oa, opc == OST_WRITE ? requested_nob:0);
        spin_lock_irqsave(&req->rq_lock, flags);
        req->rq_no_resend = 1;
        spin_unlock_irqrestore(&req->rq_lock, flags);

        /* size[0] still sizeof (*body) */
        if (opc == OST_WRITE) {
#if CHECKSUM_BULK
                body->oa.o_valid |= OBD_MD_FLCKSUM;
                body->oa.o_cksum = cksum_pages(requested_nob, page_count, pga);
#endif
                /* 1 RC per niobuf */
                size[1] = sizeof(__u32) * niocount;
                req->rq_replen = lustre_msg_size(2, size);
        } else {
                /* 1 RC for the whole I/O */
                req->rq_replen = lustre_msg_size(1, size);
        }

        *niocountp = niocount;
        *requested_nobp = requested_nob;
        *reqp = req;
        return (0);

 out:
        ptlrpc_req_finished (req);
        return (rc);
}

static int osc_brw_fini_request(struct ptlrpc_request *req, struct obdo *oa,
                                int requested_nob, int niocount,
                                obd_count page_count, struct brw_page *pga,
                                int rc)
{
        struct client_obd *cli = &req->rq_import->imp_obd->u.cli;
        struct ost_body *body;
        ENTRY;

        if (rc < 0)
                RETURN(rc);

        body = lustre_swab_repbuf(req, 0, sizeof(*body), lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("Can't unpack body\n");
                RETURN(-EPROTO);
        }

        osc_update_grant(cli, body);

        if (req->rq_reqmsg->opc == OST_WRITE) {
                if (rc > 0) {
                        CERROR ("Unexpected +ve rc %d\n", rc);
                        RETURN(-EPROTO);
                }
                LASSERT (req->rq_bulk->bd_nob == requested_nob);

                RETURN(check_write_rcs(req, requested_nob, niocount,
                                       page_count, pga));
        }

        if (rc > requested_nob) {
                CERROR("Unexpected rc %d (%d requested)\n", rc, requested_nob);
                RETURN(-EPROTO);
        }

        if (rc != req->rq_bulk->bd_nob_transferred) {
                CERROR ("Unexpected rc %d (%d transferred)\n",
                        rc, req->rq_bulk->bd_nob_transferred);
                return (-EPROTO);
        }

        if (rc < requested_nob)
                handle_short_read(rc, page_count, pga);

        memcpy(oa, &body->oa, sizeof(*oa));

#if CHECKSUM_BULK
        if (oa->o_valid & OBD_MD_FLCKSUM) {
                const struct ptlrpc_peer *peer =
                        &req->rq_import->imp_connection->c_peer;
                static int cksum_counter;
                obd_count server_cksum = oa->o_cksum;
                obd_count cksum = cksum_pages(rc, page_count, pga);
                char str[PTL_NALFMT_SIZE];

                portals_nid2str(peer->peer_ni->pni_number, peer->peer_nid, str);

                cksum_counter++;
                if (server_cksum != cksum) {
                        CERROR("Bad checksum: server %x, client %x, server NID "
                               LPX64" (%s)\n", server_cksum, cksum,
                               peer->peer_nid, str);
                        cksum_counter = 0;
                        oa->o_cksum = cksum;
                } else if ((cksum_counter & (-cksum_counter)) == cksum_counter){
                        CWARN("Checksum %u from "LPX64" (%s) OK: %x\n",
                              cksum_counter, peer->peer_nid, str, cksum);
                }
        } else {
                static int cksum_missed;

                cksum_missed++;
                if ((cksum_missed & (-cksum_missed)) == cksum_missed)
                        CERROR("Request checksum %u from "LPX64", no reply\n",
                               cksum_missed,
                               req->rq_import->imp_connection->c_peer.peer_nid);
        }
#endif
        RETURN(0);
}

static int osc_brw_internal(int cmd, struct obd_export *exp,struct obdo *oa,
                            struct lov_stripe_md *lsm,
                            obd_count page_count, struct brw_page *pga)
{
        int                    requested_nob;
        int                    niocount;
        struct ptlrpc_request *request;
        int                    rc;
        ENTRY;

restart_bulk:
        rc = osc_brw_prep_request(cmd, class_exp2cliimp(exp), oa, lsm,
                                  page_count, pga, &requested_nob, &niocount,
                                  &request);
        /* NB ^ sets rq_no_resend */

        if (rc != 0)
                return (rc);

        rc = ptlrpc_queue_wait(request);

        if (rc == -ETIMEDOUT && request->rq_resend) {
                DEBUG_REQ(D_HA, request,  "BULK TIMEOUT");
                ptlrpc_req_finished(request);
                goto restart_bulk;
        }

        rc = osc_brw_fini_request(request, oa, requested_nob, niocount,
                                  page_count, pga, rc);

        ptlrpc_req_finished(request);
        RETURN (rc);
}

static int brw_interpret(struct ptlrpc_request *request,
                         struct osc_brw_async_args *aa, int rc)
{
        struct obdo *oa      = aa->aa_oa;
        int requested_nob    = aa->aa_requested_nob;
        int niocount         = aa->aa_nio_count;
        obd_count page_count = aa->aa_page_count;
        struct brw_page *pga = aa->aa_pga;
        ENTRY;

        /* XXX bug 937 here */
        if (rc == -ETIMEDOUT && request->rq_resend) {
                DEBUG_REQ(D_HA, request,  "BULK TIMEOUT");
                LBUG(); /* re-send.  later. */
                //goto restart_bulk;
        }

        rc = osc_brw_fini_request(request, oa, requested_nob, niocount,
                                  page_count, pga, rc);
        RETURN (rc);
}

static int async_internal(int cmd, struct obd_export *exp, struct obdo *oa,
                          struct lov_stripe_md *lsm, obd_count page_count,
                          struct brw_page *pga, struct ptlrpc_request_set *set)
{
        struct ptlrpc_request     *request;
        int                        requested_nob;
        int                        nio_count;
        struct osc_brw_async_args *aa;
        int                        rc;
        ENTRY;

        rc = osc_brw_prep_request(cmd, class_exp2cliimp(exp), oa, lsm,
                                  page_count, pga, &requested_nob, &nio_count,
                                  &request);
        /* NB ^ sets rq_no_resend */

        if (rc == 0) {
                LASSERT(sizeof(*aa) <= sizeof(request->rq_async_args));
                aa = (struct osc_brw_async_args *)&request->rq_async_args;
                aa->aa_oa = oa;
                aa->aa_requested_nob = requested_nob;
                aa->aa_nio_count = nio_count;
                aa->aa_page_count = page_count;
                aa->aa_pga = pga;

                request->rq_interpret_reply = brw_interpret;
                ptlrpc_set_add_req(set, request);
        }
        RETURN (rc);
}

#ifndef min_t
#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#endif

/*
 * ugh, we want disk allocation on the target to happen in offset order.  we'll
 * follow sedgewicks advice and stick to the dead simple shellsort -- it'll do
 * fine for our small page arrays and doesn't require allocation.  its an
 * insertion sort that swaps elements that are strides apart, shrinking the
 * stride down until its '1' and the array is sorted.
 */
static void sort_brw_pages(struct brw_page *array, int num)
{
        int stride, i, j;
        struct brw_page tmp;

        if (num == 1)
                return;
        for (stride = 1; stride < num ; stride = (stride * 3) + 1)
                ;

        do {
                stride /= 3;
                for (i = stride ; i < num ; i++) {
                        tmp = array[i];
                        j = i;
                        while (j >= stride && array[j - stride].off > tmp.off) {
                                array[j] = array[j - stride];
                                j -= stride;
                        }
                        array[j] = tmp;
                }
        } while (stride > 1);
}

/* make sure we the regions we're passing to elan don't violate its '4
 * fragments' constraint.  portal headers are a fragment, all full
 * PAGE_SIZE long pages count as 1 fragment, and each partial page
 * counts as a fragment.  I think.  see bug 934. */
static obd_count check_elan_limit(struct brw_page *pg, obd_count pages)
{
        int frags_left = 3;
        int saw_whole_frag = 0;
        int i;

        for (i = 0 ; frags_left && i < pages ; pg++, i++) {
                if (pg->count == PAGE_SIZE) {
                        if (!saw_whole_frag) {
                                saw_whole_frag = 1;
                                frags_left--;
                        }
                } else {
                        frags_left--;
                }
        }
        return i;
}

static int osc_brw(int cmd, struct obd_export *exp, struct obdo *oa,
                   struct lov_stripe_md *md, obd_count page_count,
                   struct brw_page *pga, struct obd_trans_info *oti)
{
        ENTRY;

        if (cmd == OBD_BRW_CHECK) {
                /* The caller just wants to know if there's a chance that this
                 * I/O can succeed */
                struct obd_import *imp = class_exp2cliimp(exp);

                if (imp == NULL || imp->imp_invalid)
                        RETURN(-EIO);
                RETURN(0);
        }

        while (page_count) {
                obd_count pages_per_brw;
                int rc;

                if (page_count > PTLRPC_MAX_BRW_PAGES)
                        pages_per_brw = PTLRPC_MAX_BRW_PAGES;
                else
                        pages_per_brw = page_count;

                sort_brw_pages(pga, pages_per_brw);
                pages_per_brw = check_elan_limit(pga, pages_per_brw);

                rc = osc_brw_internal(cmd, exp, oa, md, pages_per_brw, pga);

                if (rc != 0)
                        RETURN(rc);

                page_count -= pages_per_brw;
                pga += pages_per_brw;
        }
        RETURN(0);
}

static int osc_brw_async(int cmd, struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md *md, obd_count page_count,
                         struct brw_page *pga, struct ptlrpc_request_set *set,
                         struct obd_trans_info *oti)
{
        ENTRY;

        if (cmd == OBD_BRW_CHECK) {
                /* The caller just wants to know if there's a chance that this
                 * I/O can succeed */
                struct obd_import *imp = class_exp2cliimp(exp);

                if (imp == NULL || imp->imp_invalid)
                        RETURN(-EIO);
                RETURN(0);
        }

        while (page_count) {
                obd_count pages_per_brw;
                int rc;

                if (page_count > PTLRPC_MAX_BRW_PAGES)
                        pages_per_brw = PTLRPC_MAX_BRW_PAGES;
                else
                        pages_per_brw = page_count;

                sort_brw_pages(pga, pages_per_brw);
                pages_per_brw = check_elan_limit(pga, pages_per_brw);

                rc = async_internal(cmd, exp, oa, md, pages_per_brw, pga, set);

                if (rc != 0)
                        RETURN(rc);

                page_count -= pages_per_brw;
                pga += pages_per_brw;
        }
        RETURN(0);
}

static void osc_check_rpcs(struct client_obd *cli);
static void osc_exit_cache(struct client_obd *cli, struct osc_async_page *oap,
                           int sent);
static void loi_list_maint(struct client_obd *cli, struct lov_oinfo *loi);
static void lop_update_pending(struct client_obd *cli,
                               struct loi_oap_pages *lop, int cmd, int delta);

/* this is called when a sync waiter receives an interruption.  Its job is to
 * get the caller woken as soon as possible.  If its page hasn't been put in an
 * rpc yet it can dequeue immediately.  Otherwise it has to mark the rpc as
 * desiring interruption which will forcefully complete the rpc once the rpc
 * has timed out */
static void osc_occ_interrupted(struct oig_callback_context *occ)
{
        struct osc_async_page *oap;
        struct loi_oap_pages *lop;
        struct lov_oinfo *loi;
        ENTRY;

        /* XXX member_of() */
        oap = list_entry(occ, struct osc_async_page, oap_occ);

        spin_lock(&oap->oap_cli->cl_loi_list_lock);

        oap->oap_interrupted = 1;

        /* ok, it's been put in an rpc. */
        if (oap->oap_request != NULL) {
                ptlrpc_mark_interrupted(oap->oap_request);
                ptlrpcd_wake(oap->oap_request);
                GOTO(unlock, 0);
        }

        /* we don't get interruption callbacks until osc_trigger_sync_io()
         * has been called and put the sync oaps in the pending/urgent lists.*/
        if (!list_empty(&oap->oap_pending_item)) {
                list_del_init(&oap->oap_pending_item);
                if (oap->oap_async_flags & ASYNC_URGENT)
                        list_del_init(&oap->oap_urgent_item);

                loi = oap->oap_loi;
                lop = (oap->oap_cmd == OBD_BRW_WRITE) ?
                        &loi->loi_write_lop : &loi->loi_read_lop;
                lop_update_pending(oap->oap_cli, lop, oap->oap_cmd, -1);
                loi_list_maint(oap->oap_cli, oap->oap_loi);

                oig_complete_one(oap->oap_oig, &oap->oap_occ, 0);
                oap->oap_oig = NULL;
        }

unlock:
        spin_unlock(&oap->oap_cli->cl_loi_list_lock);
}

/* this must be called holding the loi list lock to give coverage to exit_cache,
 * async_flag maintenance, and oap_request */
static void osc_complete_oap(struct client_obd *cli,
                             struct osc_async_page *oap, int sent, int rc)
{
        osc_exit_cache(cli, oap, sent);
        oap->oap_async_flags = 0;
        oap->oap_interrupted = 0;

        if (oap->oap_request != NULL) {
                ptlrpc_req_finished(oap->oap_request);
                oap->oap_request = NULL;
        }

        if (oap->oap_oig) {
                oig_complete_one(oap->oap_oig, &oap->oap_occ, rc);
                oap->oap_oig = NULL;
                EXIT;
                return;
        }

        oap->oap_caller_ops->ap_completion(oap->oap_caller_data, oap->oap_cmd,
                                           rc);
}

static int brw_interpret_oap(struct ptlrpc_request *request,
                             struct osc_brw_async_args *aa, int rc)
{
        struct osc_async_page *oap;
        struct client_obd *cli;
        struct list_head *pos, *n;
        ENTRY;


        rc = osc_brw_fini_request(request, aa->aa_oa, aa->aa_requested_nob,
                                  aa->aa_nio_count, aa->aa_page_count,
                                  aa->aa_pga, rc);

        CDEBUG(D_INODE, "request %p aa %p rc %d\n", request, aa, rc);

        cli = aa->aa_cli;
        /* in failout recovery we ignore writeback failure and want
         * to just tell llite to unlock the page and continue */
        if (request->rq_reqmsg->opc == OST_WRITE && 
            (cli->cl_import == NULL || cli->cl_import->imp_invalid)) {
                CDEBUG(D_INODE, "flipping to rc 0 imp %p inv %d\n", 
                       cli->cl_import, 
                       cli->cl_import ? cli->cl_import->imp_invalid : -1);
                rc = 0;
        }

        spin_lock(&cli->cl_loi_list_lock);

        /* We need to decrement before osc_complete_oap->osc_wake_cache_waiters
         * is called so we know whether to go to sync BRWs or wait for more
         * RPCs to complete */
        cli->cl_brw_in_flight--;

        /* the caller may re-use the oap after the completion call so
         * we need to clean it up a little */
        list_for_each_safe(pos, n, &aa->aa_oaps) {
                oap = list_entry(pos, struct osc_async_page, oap_rpc_item);

                //CDEBUG(D_INODE, "page %p index %lu oap %p\n",
                       //oap->oap_page, oap->oap_page->index, oap);

                list_del_init(&oap->oap_rpc_item);
                osc_complete_oap(cli, oap, 1, rc);
        }

        osc_wake_cache_waiters(cli);
        osc_check_rpcs(cli);

        spin_unlock(&cli->cl_loi_list_lock);

        obdo_free(aa->aa_oa);
        OBD_FREE(aa->aa_pga, aa->aa_page_count * sizeof(struct brw_page));

        RETURN(0);
}

static struct ptlrpc_request *osc_build_req(struct client_obd *cli,
                                            struct list_head *rpc_list,
                                            int page_count, int cmd)
{
        struct ptlrpc_request *req;
        struct brw_page *pga = NULL;
        int requested_nob, nio_count;
        struct osc_brw_async_args *aa;
        struct obdo *oa = NULL;
        struct obd_async_page_ops *ops = NULL;
        void *caller_data = NULL;
        struct list_head *pos;
        int i, rc;

        LASSERT(!list_empty(rpc_list));

        OBD_ALLOC(pga, sizeof(*pga) * page_count);
        if (pga == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out, req = ERR_PTR(-ENOMEM));

        i = 0;
        list_for_each(pos, rpc_list) {
                struct osc_async_page *oap;

                oap = list_entry(pos, struct osc_async_page, oap_rpc_item);
                if (ops == NULL) {
                        ops = oap->oap_caller_ops;
                        caller_data = oap->oap_caller_data;
                }
                pga[i].off = oap->oap_obj_off + oap->oap_page_off;
                pga[i].pg = oap->oap_page;
                pga[i].count = oap->oap_count;
                pga[i].flag = oap->oap_brw_flags;
                CDEBUG(0, "put page %p index %lu oap %p flg %x to pga\n",
                       pga[i].pg, oap->oap_page->index, oap, pga[i].flag);
                i++;
        }

        /* always get the data for the obdo for the rpc */
        LASSERT(ops != NULL);
        ops->ap_fill_obdo(caller_data, cmd, oa);

        sort_brw_pages(pga, page_count);
        rc = osc_brw_prep_request(cmd, cli->cl_import, oa, NULL, page_count,
                                  pga, &requested_nob, &nio_count, &req);
        if (rc != 0) {
                CERROR("prep_req failed: %d\n", rc);
                GOTO(out, req = ERR_PTR(rc));
        }

        LASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
        aa = (struct osc_brw_async_args *)&req->rq_async_args;
        aa->aa_oa = oa;
        aa->aa_requested_nob = requested_nob;
        aa->aa_nio_count = nio_count;
        aa->aa_page_count = page_count;
        aa->aa_pga = pga;
        aa->aa_cli = cli;

out:
        if (IS_ERR(req)) {
                if (oa)
                        obdo_free(oa);
                if (pga)
                        OBD_FREE(pga, sizeof(*pga) * page_count);
        }
        RETURN(req);
}

static void lop_update_pending(struct client_obd *cli,
                               struct loi_oap_pages *lop, int cmd, int delta)
{
        lop->lop_num_pending += delta;
        if (cmd == OBD_BRW_WRITE)
                cli->cl_pending_w_pages += delta;
        else
                cli->cl_pending_r_pages += delta;
}

/* the loi lock is held across this function but it's allowed to release
 * and reacquire it during its work */
static int osc_send_oap_rpc(struct client_obd *cli, struct lov_oinfo *loi,
                            int cmd, struct loi_oap_pages *lop)
{
        struct ptlrpc_request *request;
        obd_count page_count = 0;
        struct list_head *tmp, *pos;
        struct osc_async_page *oap = NULL;
        struct osc_brw_async_args *aa;
        struct obd_async_page_ops *ops;
        LIST_HEAD(rpc_list);
        ENTRY;

        /* first we find the pages we're allowed to work with */
        list_for_each_safe(pos, tmp, &lop->lop_pending) {
                oap = list_entry(pos, struct osc_async_page, oap_pending_item);
                ops = oap->oap_caller_ops;

                LASSERT(oap->oap_magic == OAP_MAGIC);

                /* in llite being 'ready' equates to the page being locked
                 * until completion unlocks it.  commit_write submits a page
                 * as not ready because its unlock will happen unconditionally
                 * as the call returns.  if we race with commit_write giving
                 * us that page we dont' want to create a hole in the page
                 * stream, so we stop and leave the rpc to be fired by
                 * another dirtier or kupdated interval (the not ready page
                 * will still be on the dirty list).  we could call in
                 * at the end of ll_file_write to process the queue again. */
                if (!(oap->oap_async_flags & ASYNC_READY)) {
                        int rc = ops->ap_make_ready(oap->oap_caller_data, cmd);
                        if (rc < 0)
                                CDEBUG(D_INODE, "oap %p page %p returned %d "
                                                "instead of ready\n", oap,
                                                oap->oap_page, rc);
                        switch (rc) {
                        case -EAGAIN:
                                /* llite is telling us that the page is still
                                 * in commit_write and that we should try
                                 * and put it in an rpc again later.  we
                                 * break out of the loop so we don't create
                                 * a hole in the sequence of pages in the rpc
                                 * stream.*/
                                pos = NULL;
                                break;
                        case -EINTR:
                                /* the io isn't needed.. tell the checks
                                 * below to complete the rpc with EINTR */
                                oap->oap_async_flags |= ASYNC_COUNT_STABLE;
                                oap->oap_count = -EINTR;
                                break;
                        case 0:
                                oap->oap_async_flags |= ASYNC_READY;
                                break;
                        default:
                                LASSERTF(0, "oap %p page %p returned %d "
                                            "from make_ready\n", oap,
                                            oap->oap_page, rc);
                                break;
                        }
                }
                if (pos == NULL)
                        break;

                /* take the page out of our book-keeping */
                list_del_init(&oap->oap_pending_item);
                lop_update_pending(cli, lop, cmd, -1);
                if (!list_empty(&oap->oap_urgent_item))
                        list_del_init(&oap->oap_urgent_item);

                /* ask the caller for the size of the io as the rpc leaves. */
                if (!(oap->oap_async_flags & ASYNC_COUNT_STABLE))
                        oap->oap_count =
                                ops->ap_refresh_count(oap->oap_caller_data,cmd);
                if (oap->oap_count <= 0) {
                        CDEBUG(D_CACHE, "oap %p count %d, completing\n", oap,
                               oap->oap_count);
                        osc_complete_oap(cli, oap, 0, oap->oap_count);
                        continue;
                }

                /* now put the page back in our accounting */
                list_add_tail(&oap->oap_rpc_item, &rpc_list);
                if (++page_count >= cli->cl_max_pages_per_rpc)
                        break;
        }

        osc_wake_cache_waiters(cli);

        if (page_count == 0)
                RETURN(0);

        loi_list_maint(cli, loi);
        spin_unlock(&cli->cl_loi_list_lock);

        request = osc_build_req(cli, &rpc_list, page_count, cmd);
        if (IS_ERR(request)) {
                /* this should happen rarely and is pretty bad, it makes the
                 * pending list not follow the dirty order */
                spin_lock(&cli->cl_loi_list_lock);
                list_for_each_safe(pos, tmp, &rpc_list) {
                        oap = list_entry(pos, struct osc_async_page,
                                         oap_rpc_item);
                        list_del_init(&oap->oap_rpc_item);

                        /* queued sync pages can be torn down while the pages
                         * were between the pending list and the rpc */
                        if (oap->oap_interrupted) {
                                CDEBUG(D_INODE, "oap %p interrupted\n", oap);
                                osc_complete_oap(cli, oap, 0, oap->oap_count);
                                continue;
                        }

                        /* put the page back in the loi/lop lists */
                        list_add_tail(&oap->oap_pending_item,
                                      &lop->lop_pending);
                        lop_update_pending(cli, lop, cmd, 1);
                        if (oap->oap_async_flags & ASYNC_URGENT)
                                list_add(&oap->oap_urgent_item,
                                         &lop->lop_urgent);
                }
                loi_list_maint(cli, loi);
                RETURN(PTR_ERR(request));
        }

        LASSERT(sizeof(*aa) <= sizeof(request->rq_async_args));
        aa = (struct osc_brw_async_args *)&request->rq_async_args;
        INIT_LIST_HEAD(&aa->aa_oaps);
        list_splice(&rpc_list, &aa->aa_oaps);
        INIT_LIST_HEAD(&rpc_list);

#ifdef __KERNEL__
        if (cmd == OBD_BRW_READ) {
                lprocfs_oh_tally_log2(&cli->cl_read_page_hist, page_count);
                lprocfs_oh_tally(&cli->cl_read_rpc_hist, cli->cl_brw_in_flight);
        } else {
                lprocfs_oh_tally_log2(&cli->cl_write_page_hist, page_count);
                lprocfs_oh_tally(&cli->cl_write_rpc_hist,
                                 cli->cl_brw_in_flight);
        }
#endif

        spin_lock(&cli->cl_loi_list_lock);

        cli->cl_brw_in_flight++;
        /* queued sync pages can be torn down while the pages
         * were between the pending list and the rpc */
        list_for_each(pos, &aa->aa_oaps) {
                oap = list_entry(pos, struct osc_async_page, oap_rpc_item);
                if (oap->oap_interrupted) {
                        CDEBUG(D_INODE, "oap %p in req %p interrupted\n",
                               oap, request);
                        ptlrpc_mark_interrupted(request);
                        break;
                }
        }

        CDEBUG(D_INODE, "req %p: %d pages, aa %p.  now %d in flight\n", request,
               page_count, aa, cli->cl_brw_in_flight);

        oap->oap_request = ptlrpc_request_addref(request);
        request->rq_interpret_reply = brw_interpret_oap;
        ptlrpcd_add_req(request);
        RETURN(1);
}

static int lop_makes_rpc(struct client_obd *cli, struct loi_oap_pages *lop,
                         int cmd)
{
        int optimal;
        ENTRY;

        if (lop->lop_num_pending == 0)
                RETURN(0);

        /* if we have an invalid import we want to drain the queued pages
         * by forcing them through rpcs that immediately fail and complete
         * the pages.  recovery relies on this to empty the queued pages
         * before canceling the locks and evicting down the llite pages */
        if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
                RETURN(1);

        /* stream rpcs in queue order as long as as there is an urgent page
         * queued.  this is our cheap solution for good batching in the case
         * where writepage marks some random page in the middle of the file as
         * urgent because of, say, memory pressure */
        if (!list_empty(&lop->lop_urgent))
                RETURN(1);

        /* fire off rpcs when we have 'optimal' rpcs as tuned for the wire. */
        optimal = cli->cl_max_pages_per_rpc;
        if (cmd == OBD_BRW_WRITE) {
                /* trigger a write rpc stream as long as there are dirtiers
                 * waiting for space.  as they're waiting, they're not going to
                 * create more pages to coallesce with what's waiting.. */
                if (!list_empty(&cli->cl_cache_waiters))
                        RETURN(1);

                /* *2 to avoid triggering rpcs that would want to include pages
                 * that are being queued but which can't be made ready until
                 * the queuer finishes with the page. this is a wart for
                 * llite::commit_write() */
                optimal += 16;
        }
        if (lop->lop_num_pending >= optimal)
                RETURN(1);

        RETURN(0);
}

static void on_list(struct list_head *item, struct list_head *list,
                    int should_be_on)
{
        if (list_empty(item) && should_be_on)
                list_add_tail(item, list);
        else if (!list_empty(item) && !should_be_on)
                list_del_init(item);
}

/* maintain the loi's cli list membership invariants so that osc_send_oap_rpc
 * can find pages to build into rpcs quickly */
static void loi_list_maint(struct client_obd *cli, struct lov_oinfo *loi)
{
        on_list(&loi->loi_cli_item, &cli->cl_loi_ready_list,
                lop_makes_rpc(cli, &loi->loi_write_lop, OBD_BRW_WRITE) ||
                lop_makes_rpc(cli, &loi->loi_read_lop, OBD_BRW_READ));

        on_list(&loi->loi_write_item, &cli->cl_loi_write_list,
                loi->loi_write_lop.lop_num_pending);

        on_list(&loi->loi_read_item, &cli->cl_loi_read_list,
                loi->loi_read_lop.lop_num_pending);
}

#define LOI_DEBUG(LOI, STR, args...)                                     \
        CDEBUG(D_INODE, "loi ready %d wr %d:%d rd %d:%d " STR,           \
               !list_empty(&(LOI)->loi_cli_item),                        \
               (LOI)->loi_write_lop.lop_num_pending,                     \
               !list_empty(&(LOI)->loi_write_lop.lop_urgent),            \
               (LOI)->loi_read_lop.lop_num_pending,                      \
               !list_empty(&(LOI)->loi_read_lop.lop_urgent),             \
               args)                                                     \

struct lov_oinfo *osc_next_loi(struct client_obd *cli)
{
        ENTRY;
        /* first return all objects which we already know to have
         * pages ready to be stuffed into rpcs */
        if (!list_empty(&cli->cl_loi_ready_list))
                RETURN(list_entry(cli->cl_loi_ready_list.next,
                                  struct lov_oinfo, loi_cli_item));

        /* then if we have cache waiters, return all objects with queued
         * writes.  This is especially important when many small files
         * have filled up the cache and not been fired into rpcs because
         * they don't pass the nr_pending/object threshhold */
        if (!list_empty(&cli->cl_cache_waiters) &&
            !list_empty(&cli->cl_loi_write_list))
                RETURN(list_entry(cli->cl_loi_write_list.next,
                                  struct lov_oinfo, loi_write_item));

        /* then return all queued objects when we have an invalid import
         * so that they get flushed */
        if (cli->cl_import == NULL || cli->cl_import->imp_invalid) {
                if (!list_empty(&cli->cl_loi_write_list))
                        RETURN(list_entry(cli->cl_loi_write_list.next,
                                          struct lov_oinfo, loi_write_item));
                if (!list_empty(&cli->cl_loi_read_list))
                        RETURN(list_entry(cli->cl_loi_read_list.next,
                                          struct lov_oinfo, loi_read_item));
        }
        RETURN(NULL);
}

/* called with the loi list lock held */
static void osc_check_rpcs(struct client_obd *cli)
{
        struct lov_oinfo *loi;
        int rc = 0, race_counter = 0;
        ENTRY;

        while ((loi = osc_next_loi(cli)) != NULL) {
                LOI_DEBUG(loi, "%d in flight\n", cli->cl_brw_in_flight);

                if (cli->cl_brw_in_flight >= cli->cl_max_rpcs_in_flight)
                        break;

                /* attempt some read/write balancing by alternating between
                 * reads and writes in an object.  The makes_rpc checks here
                 * would be redundant if we were getting read/write work items
                 * instead of objects.  we don't want send_oap_rpc to drain a
                 * partial read pending queue when we're given this object to
                 * do io on writes while there are cache waiters */
                if (lop_makes_rpc(cli, &loi->loi_write_lop, OBD_BRW_WRITE)) {
                        rc = osc_send_oap_rpc(cli, loi, OBD_BRW_WRITE,
                                              &loi->loi_write_lop);
                        if (rc < 0)
                                break;
                        if (rc > 0)
                                race_counter = 0;
                        else
                                race_counter++;
                }
                if (lop_makes_rpc(cli, &loi->loi_read_lop, OBD_BRW_READ)) {
                        rc = osc_send_oap_rpc(cli, loi, OBD_BRW_READ,
                                              &loi->loi_read_lop);
                        if (rc < 0)
                                break;
                        if (rc > 0)
                                race_counter = 0;
                        else
                                race_counter++;
                }

                /* attempt some inter-object balancing by issueing rpcs
                 * for each object in turn */
                if (!list_empty(&loi->loi_cli_item))
                        list_del_init(&loi->loi_cli_item);
                if (!list_empty(&loi->loi_write_item))
                        list_del_init(&loi->loi_write_item);
                if (!list_empty(&loi->loi_read_item))
                        list_del_init(&loi->loi_read_item);

                loi_list_maint(cli, loi);

                /* send_oap_rpc fails with 0 when make_ready tells it to
                 * back off.  llite's make_ready does this when it tries
                 * to lock a page queued for write that is already locked.
                 * we want to try sending rpcs from many objects, but we
                 * don't want to spin failing with 0.  */
                if (race_counter == 10)
                        break;
        }
        EXIT;
}

/* we're trying to queue a page in the osc so we're subject to the
 * 'cl_dirty_max' limit on the number of pages that can be queued in the osc.
 * If the osc's queued pages are already at that limit, then we want to sleep
 * until there is space in the osc's queue for us.  We also may be waiting for
 * write credits from the OST if there are RPCs in flight that may return some
 * before we fall back to sync writes.
 *
 * We need this know our allocation was granted in the presence of signals */
static int ocw_granted(struct client_obd *cli, struct osc_cache_waiter *ocw)
{
        int rc;
        ENTRY;
        spin_lock(&cli->cl_loi_list_lock);
        rc = list_empty(&ocw->ocw_entry) || cli->cl_brw_in_flight == 0;
        spin_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
};

/* Caller must hold loi_list_lock - we drop/regain it if we need to wait for
 * grant or cache space. */
static int osc_enter_cache(struct client_obd *cli, struct lov_oinfo *loi,
                           struct osc_async_page *oap)
{
        struct osc_cache_waiter ocw;
        struct l_wait_info lwi = { 0 };

        CDEBUG(D_CACHE, "dirty: %ld dirty_max: %ld dropped: %lu grant: %lu\n",
               cli->cl_dirty, cli->cl_dirty_max, cli->cl_lost_grant,
               cli->cl_avail_grant);

        if (cli->cl_dirty_max < PAGE_SIZE)
                return(-EDQUOT);

        /* Hopefully normal case - cache space and write credits available */
        if (cli->cl_dirty + PAGE_SIZE <= cli->cl_dirty_max &&
            cli->cl_avail_grant >= PAGE_SIZE) {
                /* account for ourselves */
                osc_consume_write_grant(cli, oap);
                return(0);
        }

        /* Make sure that there are write rpcs in flight to wait for.  This
         * is a little silly as this object may not have any pending but
         * other objects sure might. */
        if (cli->cl_brw_in_flight) {
                list_add_tail(&ocw.ocw_entry, &cli->cl_cache_waiters);
                init_waitqueue_head(&ocw.ocw_waitq);
                ocw.ocw_oap = oap;
                ocw.ocw_rc = 0;

                loi_list_maint(cli, loi);
                osc_check_rpcs(cli);
                spin_unlock(&cli->cl_loi_list_lock);

                CDEBUG(0, "sleeping for cache space\n");
                l_wait_event(ocw.ocw_waitq, ocw_granted(cli, &ocw), &lwi);

                spin_lock(&cli->cl_loi_list_lock);
                if (!list_empty(&ocw.ocw_entry)) {
                        list_del(&ocw.ocw_entry);
                        RETURN(-EINTR);
                }
                RETURN(ocw.ocw_rc);
        }

        RETURN(-EDQUOT);
}

/* the companion to enter_cache, called when an oap is no longer part of the
 * dirty accounting.. so writeback completes or truncate happens before writing
 * starts.  must be called with the loi lock held. */
static void osc_exit_cache(struct client_obd *cli, struct osc_async_page *oap,
                           int sent)
{
        ENTRY;

        if (!(oap->oap_brw_flags & OBD_BRW_FROM_GRANT)) {
                EXIT;
                return;
        }

        oap->oap_brw_flags &= ~OBD_BRW_FROM_GRANT;
        cli->cl_dirty -= PAGE_SIZE;
        if (!sent) {
                cli->cl_lost_grant += PAGE_SIZE;
                CDEBUG(D_CACHE, "lost grant: %lu avail grant: %lu dirty: %lu\n",
                       cli->cl_lost_grant, cli->cl_avail_grant, cli->cl_dirty);
        }

        EXIT;
}

int osc_prep_async_page(struct obd_export *exp, struct lov_stripe_md *lsm,
                        struct lov_oinfo *loi, struct page *page,
                        obd_off offset, struct obd_async_page_ops *ops,
                        void *data, void **res)
{
        struct osc_async_page *oap;
        ENTRY;

        OBD_ALLOC(oap, sizeof(*oap));
        if (oap == NULL)
                return -ENOMEM;

        oap->oap_magic = OAP_MAGIC;
        oap->oap_cli = &exp->exp_obd->u.cli;
        oap->oap_loi = loi;

        oap->oap_caller_ops = ops;
        oap->oap_caller_data = data;

        oap->oap_page = page;
        oap->oap_obj_off = offset;

        INIT_LIST_HEAD(&oap->oap_pending_item);
        INIT_LIST_HEAD(&oap->oap_urgent_item);
        INIT_LIST_HEAD(&oap->oap_rpc_item);

        oap->oap_occ.occ_interrupted = osc_occ_interrupted;

        CDEBUG(D_CACHE, "oap %p page %p obj off "LPU64"\n", oap, page, offset);
        *res = oap;
        RETURN(0);
}

struct osc_async_page *oap_from_cookie(void *cookie)
{
        struct osc_async_page *oap = cookie;
        if (oap->oap_magic != OAP_MAGIC)
                return ERR_PTR(-EINVAL);
        return oap;
};

static int osc_queue_async_io(struct obd_export *exp, struct lov_stripe_md *lsm,
                              struct lov_oinfo *loi, void *cookie,
                              int cmd, obd_off off, int count,
                              obd_flag brw_flags, enum async_flags async_flags)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct osc_async_page *oap;
        struct loi_oap_pages *lop;
        int rc;
        ENTRY;

        oap = oap_from_cookie(cookie);
        if (IS_ERR(oap))
                RETURN(PTR_ERR(oap));

        if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
                RETURN(-EIO);

        if (!list_empty(&oap->oap_pending_item) ||
            !list_empty(&oap->oap_urgent_item) ||
            !list_empty(&oap->oap_rpc_item))
                RETURN(-EBUSY);

        if (loi == NULL)
                loi = &lsm->lsm_oinfo[0];

        spin_lock(&cli->cl_loi_list_lock);

        oap->oap_cmd = cmd;
        oap->oap_async_flags = async_flags;
        oap->oap_page_off = off;
        oap->oap_count = count;
        oap->oap_brw_flags = brw_flags;

        if (cmd == OBD_BRW_WRITE) {
                rc = osc_enter_cache(cli, loi, oap);
                if (rc) {
                        spin_unlock(&cli->cl_loi_list_lock);
                        RETURN(rc);
                }
                lop = &loi->loi_write_lop;
        } else {
                lop = &loi->loi_read_lop;
        }

        if (oap->oap_async_flags & ASYNC_URGENT)
                list_add(&oap->oap_urgent_item, &lop->lop_urgent);
        list_add_tail(&oap->oap_pending_item, &lop->lop_pending);
        lop_update_pending(cli, lop, cmd, 1);

        loi_list_maint(cli, loi);

        LOI_DEBUG(loi, "oap %p page %p added for cmd %d\n", oap, oap->oap_page,
                  cmd);

        osc_check_rpcs(cli);
        spin_unlock(&cli->cl_loi_list_lock);

        RETURN(0);
}

/* aka (~was & now & flag), but this is more clear :) */
#define SETTING(was, now, flag) (!(was & flag) && (now & flag))

static int osc_set_async_flags(struct obd_export *exp,
                               struct lov_stripe_md *lsm,
                               struct lov_oinfo *loi, void *cookie,
                               obd_flag async_flags)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct loi_oap_pages *lop;
        struct osc_async_page *oap;
        int rc = 0;
        ENTRY;

        oap = oap_from_cookie(cookie);
        if (IS_ERR(oap))
                RETURN(PTR_ERR(oap));

        if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
                RETURN(-EIO);

        if (loi == NULL)
                loi = &lsm->lsm_oinfo[0];

        if (oap->oap_cmd == OBD_BRW_WRITE) {
                lop = &loi->loi_write_lop;
        } else {
                lop = &loi->loi_read_lop;
        }

        spin_lock(&cli->cl_loi_list_lock);

        if (list_empty(&oap->oap_pending_item))
                GOTO(out, rc = -EINVAL);

        if ((oap->oap_async_flags & async_flags) == async_flags)
                GOTO(out, rc = 0);

        if (SETTING(oap->oap_async_flags, async_flags, ASYNC_READY))
                oap->oap_async_flags |= ASYNC_READY;

        if (SETTING(oap->oap_async_flags, async_flags, ASYNC_URGENT)) {
                if (list_empty(&oap->oap_rpc_item)) {
                        list_add(&oap->oap_urgent_item, &lop->lop_urgent);
                        loi_list_maint(cli, loi);
                }
        }

        LOI_DEBUG(loi, "oap %p page %p has flags %x\n", oap, oap->oap_page,
                        oap->oap_async_flags);
out:
        osc_check_rpcs(cli);
        spin_unlock(&cli->cl_loi_list_lock);
        RETURN(rc);
}

static int osc_queue_group_io(struct obd_export *exp, struct lov_stripe_md *lsm,
                             struct lov_oinfo *loi,
                             struct obd_io_group *oig, void *cookie,
                             int cmd, obd_off off, int count,
                             obd_flag brw_flags,
                             obd_flag async_flags)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct osc_async_page *oap;
        struct loi_oap_pages *lop;
        ENTRY;

        oap = oap_from_cookie(cookie);
        if (IS_ERR(oap))
                RETURN(PTR_ERR(oap));

        if (cli->cl_import == NULL || cli->cl_import->imp_invalid)
                RETURN(-EIO);

        if (!list_empty(&oap->oap_pending_item) ||
            !list_empty(&oap->oap_urgent_item) ||
            !list_empty(&oap->oap_rpc_item))
                RETURN(-EBUSY);

        if (loi == NULL)
                loi = &lsm->lsm_oinfo[0];

        spin_lock(&cli->cl_loi_list_lock);

        oap->oap_cmd = cmd;
        oap->oap_page_off = off;
        oap->oap_count = count;
        oap->oap_brw_flags = brw_flags;
        oap->oap_async_flags = async_flags;

        if (cmd == OBD_BRW_WRITE)
                lop = &loi->loi_write_lop;
        else
                lop = &loi->loi_read_lop;

        list_add_tail(&oap->oap_pending_item, &lop->lop_pending_group);
        if (oap->oap_async_flags & ASYNC_GROUP_SYNC) {
                oap->oap_oig = oig;
                oig_add_one(oig, &oap->oap_occ);
        }

        LOI_DEBUG(loi, "oap %p page %p on group pending\n", oap, oap->oap_page);

        spin_unlock(&cli->cl_loi_list_lock);

        RETURN(0);
}

static void osc_group_to_pending(struct client_obd *cli, struct lov_oinfo *loi,
                                 struct loi_oap_pages *lop, int cmd)
{
        struct list_head *pos, *tmp;
        struct osc_async_page *oap;

        list_for_each_safe(pos, tmp, &lop->lop_pending_group) {
                oap = list_entry(pos, struct osc_async_page, oap_pending_item);
                list_del(&oap->oap_pending_item);
                list_add_tail(&oap->oap_pending_item, &lop->lop_pending);
                list_add(&oap->oap_urgent_item, &lop->lop_urgent);
                lop_update_pending(cli, lop, cmd, 1);
        }
        loi_list_maint(cli, loi);
}

static int osc_trigger_group_io(struct obd_export *exp,
                                struct lov_stripe_md *lsm,
                                struct lov_oinfo *loi,
                                struct obd_io_group *oig)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        ENTRY;

        if (loi == NULL)
                loi = &lsm->lsm_oinfo[0];

        spin_lock(&cli->cl_loi_list_lock);

        osc_group_to_pending(cli, loi, &loi->loi_write_lop, OBD_BRW_WRITE);
        osc_group_to_pending(cli, loi, &loi->loi_read_lop, OBD_BRW_READ);

        osc_check_rpcs(cli);
        spin_unlock(&cli->cl_loi_list_lock);

        RETURN(0);
}

static int osc_teardown_async_page(struct obd_export *exp,
                                   struct lov_stripe_md *lsm,
                                   struct lov_oinfo *loi, void *cookie)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        struct loi_oap_pages *lop;
        struct osc_async_page *oap;
        int rc = 0;
        ENTRY;

        oap = oap_from_cookie(cookie);
        if (IS_ERR(oap))
                RETURN(PTR_ERR(oap));

        if (loi == NULL)
                loi = &lsm->lsm_oinfo[0];

        if (oap->oap_cmd == OBD_BRW_WRITE) {
                lop = &loi->loi_write_lop;
        } else {
                lop = &loi->loi_read_lop;
        }

        spin_lock(&cli->cl_loi_list_lock);

        if (!list_empty(&oap->oap_rpc_item))
                GOTO(out, rc = -EBUSY);

        osc_exit_cache(cli, oap, 0);
        osc_wake_cache_waiters(cli);

        if (!list_empty(&oap->oap_urgent_item)) {
                list_del_init(&oap->oap_urgent_item);
                oap->oap_async_flags &= ~ASYNC_URGENT;
        }
        if (!list_empty(&oap->oap_pending_item)) {
                list_del_init(&oap->oap_pending_item);
                lop_update_pending(cli, lop, oap->oap_cmd, -1);
        }
        loi_list_maint(cli, loi);

        LOI_DEBUG(loi, "oap %p page %p torn down\n", oap, oap->oap_page);
out:
        spin_unlock(&cli->cl_loi_list_lock);
        if (rc == 0)
                OBD_FREE(oap, sizeof(*oap));
        RETURN(rc);
}

#ifdef __KERNEL__
/* Note: caller will lock/unlock, and set uptodate on the pages */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int sanosc_brw_read(struct obd_export *exp, struct obdo *oa,
                           struct lov_stripe_md *lsm, obd_count page_count,
                           struct brw_page *pga)
{
        struct ptlrpc_request *request = NULL;
        struct ost_body *body;
        struct niobuf_remote *nioptr;
        struct obd_ioobj *iooptr;
        int rc, size[3] = {sizeof(*body)}, mapped = 0;
        int swab;
        ENTRY;

        /* XXX does not handle 'new' brw protocol */

        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(*nioptr);

        request = ptlrpc_prep_req(class_exp2cliimp(exp), OST_SAN_READ, 3,
                                  size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof(*body));
        iooptr = lustre_msg_buf(request->rq_reqmsg, 1, sizeof(*iooptr));
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2,
                                sizeof(*nioptr) * page_count);

        memcpy(&body->oa, oa, sizeof(body->oa));

        obdo_to_ioobj(oa, iooptr);
        iooptr->ioo_bufcnt = page_count;

        for (mapped = 0; mapped < page_count; mapped++, nioptr++) {
                LASSERT(PageLocked(pga[mapped].pg));
                LASSERT(mapped == 0 || pga[mapped].off > pga[mapped - 1].off);

                nioptr->offset = pga[mapped].off;
                nioptr->len    = pga[mapped].count;
                nioptr->flags  = pga[mapped].flag;
        }

        size[1] = page_count * sizeof(*nioptr);
        request->rq_replen = lustre_msg_size(2, size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_req, rc);

        body = lustre_swab_repbuf(request, 0, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL) {
                CERROR("Can't unpack body\n");
                GOTO(out_req, rc = -EPROTO);
        }

        memcpy(oa, &body->oa, sizeof(*oa));

        swab = lustre_msg_swabbed(request->rq_repmsg);
        LASSERT_REPSWAB(request, 1);
        nioptr = lustre_msg_buf(request->rq_repmsg, 1, size[1]);
        if (!nioptr) {
                /* nioptr missing or short */
                GOTO(out_req, rc = -EPROTO);
        }

        /* actual read */
        for (mapped = 0; mapped < page_count; mapped++, nioptr++) {
                struct page *page = pga[mapped].pg;
                struct buffer_head *bh;
                kdev_t dev;

                if (swab)
                        lustre_swab_niobuf_remote (nioptr);

                /* got san device associated */
                LASSERT(exp->exp_obd != NULL);
                dev = exp->exp_obd->u.cli.cl_sandev;

                /* hole */
                if (!nioptr->offset) {
                        CDEBUG(D_PAGE, "hole at ino %lu; index %ld\n",
                                        page->mapping->host->i_ino,
                                        page->index);
                        memset(page_address(page), 0, PAGE_SIZE);
                        continue;
                }

                if (!page->buffers) {
                        create_empty_buffers(page, dev, PAGE_SIZE);
                        bh = page->buffers;

                        clear_bit(BH_New, &bh->b_state);
                        set_bit(BH_Mapped, &bh->b_state);
                        bh->b_blocknr = (unsigned long)nioptr->offset;

                        clear_bit(BH_Uptodate, &bh->b_state);

                        ll_rw_block(READ, 1, &bh);
                } else {
                        bh = page->buffers;

                        /* if buffer already existed, it must be the
                         * one we mapped before, check it */
                        LASSERT(!test_bit(BH_New, &bh->b_state));
                        LASSERT(test_bit(BH_Mapped, &bh->b_state));
                        LASSERT(bh->b_blocknr == (unsigned long)nioptr->offset);

                        /* wait it's io completion */
                        if (test_bit(BH_Lock, &bh->b_state))
                                wait_on_buffer(bh);

                        if (!test_bit(BH_Uptodate, &bh->b_state))
                                ll_rw_block(READ, 1, &bh);
                }


                /* must do syncronous write here */
                wait_on_buffer(bh);
                if (!buffer_uptodate(bh)) {
                        /* I/O error */
                        rc = -EIO;
                        goto out_req;
                }
        }

out_req:
        ptlrpc_req_finished(request);
        RETURN(rc);
}

static int sanosc_brw_write(struct obd_export *exp, struct obdo *oa,
                            struct lov_stripe_md *lsm, obd_count page_count,
                            struct brw_page *pga)
{
        struct ptlrpc_request *request = NULL;
        struct ost_body *body;
        struct niobuf_remote *nioptr;
        struct obd_ioobj *iooptr;
        int rc, size[3] = {sizeof(*body)}, mapped = 0;
        int swab;
        ENTRY;

        size[1] = sizeof(struct obd_ioobj);
        size[2] = page_count * sizeof(*nioptr);

        request = ptlrpc_prep_req(class_exp2cliimp(exp), OST_SAN_WRITE,
                                  3, size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        iooptr = lustre_msg_buf(request->rq_reqmsg, 1, sizeof (*iooptr));
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2,
                                sizeof (*nioptr) * page_count);

        memcpy(&body->oa, oa, sizeof(body->oa));

        obdo_to_ioobj(oa, iooptr);
        iooptr->ioo_bufcnt = page_count;

        /* pack request */
        for (mapped = 0; mapped < page_count; mapped++, nioptr++) {
                LASSERT(PageLocked(pga[mapped].pg));
                LASSERT(mapped == 0 || pga[mapped].off > pga[mapped - 1].off);

                nioptr->offset = pga[mapped].off;
                nioptr->len    = pga[mapped].count;
                nioptr->flags  = pga[mapped].flag;
        }

        size[1] = page_count * sizeof(*nioptr);
        request->rq_replen = lustre_msg_size(2, size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_req, rc);

        swab = lustre_msg_swabbed (request->rq_repmsg);
        LASSERT_REPSWAB (request, 1);
        nioptr = lustre_msg_buf(request->rq_repmsg, 1, size[1]);
        if (!nioptr) {
                CERROR("absent/short niobuf array\n");
                GOTO(out_req, rc = -EPROTO);
        }

        /* actual write */
        for (mapped = 0; mapped < page_count; mapped++, nioptr++) {
                struct page *page = pga[mapped].pg;
                struct buffer_head *bh;
                kdev_t dev;

                if (swab)
                        lustre_swab_niobuf_remote (nioptr);

                /* got san device associated */
                LASSERT(exp->exp_obd != NULL);
                dev = exp->exp_obd->u.cli.cl_sandev;

                if (!page->buffers) {
                        create_empty_buffers(page, dev, PAGE_SIZE);
                } else {
                        /* checking */
                        LASSERT(!test_bit(BH_New, &page->buffers->b_state));
                        LASSERT(test_bit(BH_Mapped, &page->buffers->b_state));
                        LASSERT(page->buffers->b_blocknr ==
                                (unsigned long)nioptr->offset);
                }
                bh = page->buffers;

                LASSERT(bh);

                /* if buffer locked, wait it's io completion */
                if (test_bit(BH_Lock, &bh->b_state))
                        wait_on_buffer(bh);

                clear_bit(BH_New, &bh->b_state);
                set_bit(BH_Mapped, &bh->b_state);

                /* override the block nr */
                bh->b_blocknr = (unsigned long)nioptr->offset;

                /* we are about to write it, so set it
                 * uptodate/dirty
                 * page lock should garentee no race condition here */
                set_bit(BH_Uptodate, &bh->b_state);
                set_bit(BH_Dirty, &bh->b_state);

                ll_rw_block(WRITE, 1, &bh);

                /* must do syncronous write here */
                wait_on_buffer(bh);
                if (!buffer_uptodate(bh) || test_bit(BH_Dirty, &bh->b_state)) {
                        /* I/O error */
                        rc = -EIO;
                        goto out_req;
                }
        }

out_req:
        ptlrpc_req_finished(request);
        RETURN(rc);
}

static int sanosc_brw(int cmd, struct obd_export *exp, struct obdo *oa,
                      struct lov_stripe_md *lsm, obd_count page_count,
                      struct brw_page *pga, struct obd_trans_info *oti)
{
        ENTRY;

        while (page_count) {
                obd_count pages_per_brw;
                int rc;

                if (page_count > PTLRPC_MAX_BRW_PAGES)
                        pages_per_brw = PTLRPC_MAX_BRW_PAGES;
                else
                        pages_per_brw = page_count;

                if (cmd & OBD_BRW_WRITE)
                        rc = sanosc_brw_write(exp, oa, lsm, pages_per_brw,pga);
                else
                        rc = sanosc_brw_read(exp, oa, lsm, pages_per_brw, pga);

                if (rc != 0)
                        RETURN(rc);

                page_count -= pages_per_brw;
                pga += pages_per_brw;
        }
        RETURN(0);
}
#endif
#endif

static void osc_set_data_with_check(struct lustre_handle *lockh, void *data)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);

        LASSERT(lock != NULL);
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
#ifdef __KERNEL__
        if (lock->l_ast_data && lock->l_ast_data != data) {
                struct inode *new_inode = data;
                struct inode *old_inode = lock->l_ast_data;
                LASSERTF(old_inode->i_state & I_FREEING,
                         "Found existing inode %p/%lu/%u state %lu in lock: "
                         "setting data to %p/%lu/%u\n", old_inode,
                         old_inode->i_ino, old_inode->i_generation,
                         old_inode->i_state,
                         new_inode, new_inode->i_ino, new_inode->i_generation);
        }
#endif
        lock->l_ast_data = data;
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        LDLM_LOCK_PUT(lock);
}

static int osc_change_cbdata(struct obd_export *exp, struct lov_stripe_md *lsm,
                             ldlm_iterator_t replace, void *data)
{
        struct ldlm_res_id res_id = { .name = {lsm->lsm_object_id} };
        struct obd_device *obd = class_exp2obd(exp);

        ldlm_change_cbdata(obd->obd_namespace, &res_id, replace, data);
        return 0;
}

static int osc_enqueue(struct obd_export *exp, struct lov_stripe_md *lsm,
                       __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                       int *flags, void *bl_cb, void *cp_cb, void *gl_cb,
                       void *data, __u32 lvb_len, void *lvb_swabber,
                       struct lustre_handle *lockh)
{
        struct ldlm_res_id res_id = { .name = {lsm->lsm_object_id} };
        struct obd_device *obd = exp->exp_obd;
        struct ost_lvb lvb;
        int rc;
        ENTRY;

        /* Filesystem lock extents are extended to page boundaries so that
         * dealing with the page cache is a little smoother.  */
        policy->l_extent.start -= policy->l_extent.start & ~PAGE_MASK;
        policy->l_extent.end |= ~PAGE_MASK;

        if (lsm->lsm_oinfo->loi_kms_valid == 0)
                goto no_match;

        /* Next, search for already existing extent locks that will cover us */
        rc = ldlm_lock_match(obd->obd_namespace, 0, &res_id, type, policy, mode,
                             lockh);
        if (rc == 1) {
                osc_set_data_with_check(lockh, data);
                if (*flags & LDLM_FL_HAS_INTENT) {
                        /* I would like to be able to ASSERT here that rss <=
                         * kms, but I can't, for reasons which are explained in
                         * lov_enqueue() */
                }
                /* We already have a lock, and it's referenced */
                RETURN(ELDLM_OK);
        }

        /* If we're trying to read, we also search for an existing PW lock.  The
         * VFS and page cache already protect us locally, so lots of readers/
         * writers can share a single PW lock.
         *
         * There are problems with conversion deadlocks, so instead of
         * converting a read lock to a write lock, we'll just enqueue a new
         * one.
         *
         * At some point we should cancel the read lock instead of making them
         * send us a blocking callback, but there are problems with canceling
         * locks out from other users right now, too. */

        if (mode == LCK_PR) {
                rc = ldlm_lock_match(obd->obd_namespace, 0, &res_id, type,
                                     policy, LCK_PW, lockh);
                if (rc == 1) {
                        /* FIXME: This is not incredibly elegant, but it might
                         * be more elegant than adding another parameter to
                         * lock_match.  I want a second opinion. */
                        ldlm_lock_addref(lockh, LCK_PR);
                        ldlm_lock_decref(lockh, LCK_PW);
                        osc_set_data_with_check(lockh, data);
                        RETURN(ELDLM_OK);
                }
        }

 no_match:
        rc = ldlm_cli_enqueue(exp, NULL, obd->obd_namespace, res_id, type,
                              policy, mode, flags, bl_cb, cp_cb, gl_cb, data,
                              &lvb, sizeof(lvb), lustre_swab_ost_lvb, lockh);

        if ((*flags & LDLM_FL_HAS_INTENT && rc == ELDLM_LOCK_ABORTED) || !rc) {
                CDEBUG(D_INODE, "received kms == "LPU64"\n", lvb.lvb_size);
                lsm->lsm_oinfo->loi_rss = lvb.lvb_size;
        }

        RETURN(rc);
}

static int osc_match(struct obd_export *exp, struct lov_stripe_md *lsm,
                     __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                     int *flags, void *data, struct lustre_handle *lockh)
{
        struct ldlm_res_id res_id = { .name = {lsm->lsm_object_id} };
        struct obd_device *obd = exp->exp_obd;
        int rc;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_OSC_MATCH, -EIO);

        /* Filesystem lock extents are extended to page boundaries so that
         * dealing with the page cache is a little smoother */
        policy->l_extent.start -= policy->l_extent.start & ~PAGE_MASK;
        policy->l_extent.end |= ~PAGE_MASK;

        /* Next, search for already existing extent locks that will cover us */
        rc = ldlm_lock_match(obd->obd_namespace, *flags, &res_id, type,
                             policy, mode, lockh);
        if (rc) {
                osc_set_data_with_check(lockh, data);
                RETURN(rc);
        }
        /* If we're trying to read, we also search for an existing PW lock.  The
         * VFS and page cache already protect us locally, so lots of readers/
         * writers can share a single PW lock. */
        if (mode == LCK_PR) {
                rc = ldlm_lock_match(obd->obd_namespace, *flags, &res_id, type,
                                     policy, LCK_PW, lockh);
                if (rc == 1 && !(*flags & LDLM_FL_TEST_LOCK)) {
                        /* FIXME: This is not incredibly elegant, but it might
                         * be more elegant than adding another parameter to
                         * lock_match.  I want a second opinion. */
                        osc_set_data_with_check(lockh, data);
                        ldlm_lock_addref(lockh, LCK_PR);
                        ldlm_lock_decref(lockh, LCK_PW);
                }
        }
        RETURN(rc);
}

static int osc_cancel(struct obd_export *exp, struct lov_stripe_md *md,
                      __u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

static int osc_cancel_unused(struct obd_export *exp,
                             struct lov_stripe_md *lsm, int flags, void *opaque)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct ldlm_res_id res_id = { .name = {lsm->lsm_object_id} };

        return ldlm_cli_cancel_unused(obd->obd_namespace, &res_id, flags,
                                      opaque);
}

static int osc_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                      unsigned long max_age)
{
        struct obd_statfs *msfs;
        struct ptlrpc_request *request;
        int rc, size = sizeof(*osfs);
        ENTRY;

        /* We could possibly pass max_age in the request (as an absolute
         * timestamp or a "seconds.usec ago") so the target can avoid doing
         * extra calls into the filesystem if that isn't necessary (e.g.
         * during mount that would help a bit).  Having relative timestamps
         * is not so great if request processing is slow, while absolute
         * timestamps are not ideal because they need time synchronization. */
        request = ptlrpc_prep_req(obd->u.cli.cl_import, OST_STATFS,0,NULL,NULL);
        if (!request)
                RETURN(-ENOMEM);

        request->rq_replen = lustre_msg_size(1, &size);
        request->rq_request_portal = OST_CREATE_PORTAL; //XXX FIXME bug 249

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        msfs = lustre_swab_repbuf(request, 0, sizeof(*msfs),
                                  lustre_swab_obd_statfs);
        if (msfs == NULL) {
                CERROR("Can't unpack obd_statfs\n");
                GOTO(out, rc = -EPROTO);
        }

        memcpy(osfs, msfs, sizeof(*osfs));

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

/* Retrieve object striping information.
 *
 * @lmmu is a pointer to an in-core struct with lmm_ost_count indicating
 * the maximum number of OST indices which will fit in the user buffer.
 * lmm_magic must be LOV_MAGIC (we only use 1 slot here).
 */
static int osc_getstripe(struct lov_stripe_md *lsm, struct lov_user_md *lump)
{
        struct lov_user_md lum, *lumk;
        int rc, lum_size;
        ENTRY;

        if (!lsm)
                RETURN(-ENODATA);

        rc = copy_from_user(&lum, lump, sizeof(lum));
        if (rc)
                RETURN(-EFAULT);

        if (lum.lmm_magic != LOV_USER_MAGIC)
                RETURN(-EINVAL);

        if (lum.lmm_stripe_count > 0) {
                lum_size = sizeof(lum) + sizeof(lum.lmm_objects[0]);
                OBD_ALLOC(lumk, lum_size);
                if (!lumk)
                        RETURN(-ENOMEM);

                lumk->lmm_objects[0].l_object_id = lsm->lsm_object_id;
        } else {
                lum_size = sizeof(lum);
                lumk = &lum;
        }

        lumk->lmm_object_id = lsm->lsm_object_id;
        lumk->lmm_stripe_count = 1;

        if (copy_to_user(lump, lumk, lum_size))
                rc = -EFAULT;

        if (lumk != &lum)
                OBD_FREE(lumk, lum_size);

        RETURN(rc);
}

static int osc_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_ioctl_data *data = karg;
        int err = 0;
        ENTRY;
        
        MOD_INC_USE_COUNT;

        switch (cmd) {
        case OBD_IOC_LOV_GET_CONFIG: {
                char *buf;
                struct lov_desc *desc;
                struct obd_uuid uuid;

                buf = NULL;
                len = 0;
                if (obd_ioctl_getdata(&buf, &len, (void *)uarg))
                        GOTO(out, err = -EINVAL);

                data = (struct obd_ioctl_data *)buf;

                if (sizeof(*desc) > data->ioc_inllen1) {
                        OBD_FREE(buf, len);
                        GOTO(out, err = -EINVAL);
                }

                if (data->ioc_inllen2 < sizeof(uuid)) {
                        OBD_FREE(buf, len);
                        GOTO(out, err = -EINVAL);
                }

                desc = (struct lov_desc *)data->ioc_inlbuf1;
                desc->ld_tgt_count = 1;
                desc->ld_active_tgt_count = 1;
                desc->ld_default_stripe_count = 1;
                desc->ld_default_stripe_size = 0;
                desc->ld_default_stripe_offset = 0;
                desc->ld_pattern = 0;
                memcpy(&desc->ld_uuid, &obd->obd_uuid, sizeof(uuid));

                memcpy(data->ioc_inlbuf2, &obd->obd_uuid, sizeof(uuid));

                err = copy_to_user((void *)uarg, buf, len);
                if (err)
                        err = -EFAULT;
                obd_ioctl_freedata(buf, len);
                GOTO(out, err);
        }
        case LL_IOC_LOV_SETSTRIPE:
                err = obd_alloc_memmd(exp, karg);
                if (err > 0)
                        err = 0;
                GOTO(out, err);
        case LL_IOC_LOV_GETSTRIPE:
                err = osc_getstripe(karg, uarg);
                GOTO(out, err);
        case OBD_IOC_CLIENT_RECOVER:
                err = ptlrpc_recover_import(obd->u.cli.cl_import,
                                            data->ioc_inlbuf1);
                if (err > 0)
                        err = 0;
                GOTO(out, err);
        case IOC_OSC_SET_ACTIVE:
                err = ptlrpc_set_import_active(obd->u.cli.cl_import,
                                               data->ioc_offset);
                GOTO(out, err);
        default:
                CDEBUG(D_INODE, "unrecognised ioctl %#x by %s\n", cmd, current->comm);
                GOTO(out, err = -ENOTTY);
        }
out:
        MOD_DEC_USE_COUNT;
        return err;
}

static int osc_get_info(struct obd_export *exp, obd_count keylen,
                        void *key, __u32 *vallen, void *val)
{
        ENTRY;
        if (!vallen || !val)
                RETURN(-EFAULT);

        if (keylen > strlen("lock_to_stripe") &&
            strcmp(key, "lock_to_stripe") == 0) {
                __u32 *stripe = val;
                *vallen = sizeof(*stripe);
                *stripe = 0;
                RETURN(0);
        } else if (keylen >= strlen("last_id") && strcmp(key, "last_id") == 0) {
                struct ptlrpc_request *req;
                obd_id *reply;
                char *bufs[1] = {key};
                int rc;
                req = ptlrpc_prep_req(class_exp2cliimp(exp), OST_GET_INFO, 1,
                                      &keylen, bufs);
                if (req == NULL)
                        RETURN(-ENOMEM);

                req->rq_replen = lustre_msg_size(1, vallen);
                rc = ptlrpc_queue_wait(req);
                if (rc)
                        GOTO(out, rc);

                reply = lustre_swab_repbuf(req, 0, sizeof(*reply),
                                           lustre_swab_ost_last_id);
                if (reply == NULL) {
                        CERROR("Can't unpack OST last ID\n");
                        GOTO(out, rc = -EPROTO);
                }
                *((obd_id *)val) = *reply;
        out:
                ptlrpc_req_finished(req);
                RETURN(rc);
        }
        RETURN(-EINVAL);
}

static int osc_set_info(struct obd_export *exp, obd_count keylen,
                        void *key, obd_count vallen, void *val)
{
        struct ptlrpc_request *req;
        struct obd_device  *obd = exp->exp_obd;
        struct obd_import *imp = class_exp2cliimp(exp);
        struct llog_ctxt *ctxt;
        int rc, size = keylen;
        char *bufs[1] = {key};
        ENTRY;

        if (keylen == strlen("next_id") &&
            memcmp(key, "next_id", strlen("next_id")) == 0) {
                if (vallen != sizeof(obd_id))
                        RETURN(-EINVAL);
		obd->u.cli.cl_oscc.oscc_next_id = *((obd_id*)val) + 1;
                CDEBUG(D_INODE, "%s: set oscc_next_id = "LPU64"\n",
                       exp->exp_obd->obd_name,
                       obd->u.cli.cl_oscc.oscc_next_id);

                RETURN(0);
        }

        if (keylen == strlen("growth_count") &&
            memcmp(key, "growth_count", strlen("growth_count")) == 0) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
		obd->u.cli.cl_oscc.oscc_grow_count = *((int*)val);
                RETURN(0);
        }

        if (keylen == strlen("unlinked") &&
            memcmp(key, "unlinked", keylen) == 0) {
                struct osc_creator *oscc = &obd->u.cli.cl_oscc;
                spin_lock(&oscc->oscc_lock);
                oscc->oscc_flags &= ~OSCC_FLAG_NOSPC;
                spin_unlock(&oscc->oscc_lock);
                RETURN(0);
        }


        if (keylen == strlen("initial_recov") &&
            memcmp(key, "initial_recov", strlen("initial_recov")) == 0) {
                struct obd_import *imp = exp->exp_obd->u.cli.cl_import;
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                imp->imp_initial_recov = *(int *)val;
                CDEBUG(D_HA, "%s: set imp_no_init_recov = %d\n",
                       exp->exp_obd->obd_name,
                       imp->imp_initial_recov);
                RETURN(0);
        }

        if (keylen < strlen("mds_conn") ||
            memcmp(key, "mds_conn", strlen("mds_conn")) != 0)
                RETURN(-EINVAL);


        req = ptlrpc_prep_req(imp, OST_SET_INFO, 1, &size, bufs);
        if (req == NULL)
                RETURN(-ENOMEM);

        req->rq_replen = lustre_msg_size(0, NULL);
        rc = ptlrpc_queue_wait(req);
        ptlrpc_req_finished(req);

        ctxt = llog_get_context(exp->exp_obd, LLOG_UNLINK_ORIG_CTXT);
        if (ctxt) {
                rc = llog_initiator_connect(ctxt);
                if (rc)
                        RETURN(rc);
        }

        imp->imp_server_timeout = 1;
        CDEBUG(D_HA, "pinging OST %s\n", imp->imp_target_uuid.uuid);
        imp->imp_pingable = 1;

        RETURN(rc);
}


static struct llog_operations osc_size_repl_logops = {
        lop_cancel: llog_obd_repl_cancel
};

static struct llog_operations osc_unlink_orig_logops;
static int osc_llog_init(struct obd_device *obd, struct obd_device *tgt,
                        int count, struct llog_catid *catid)
{
        int rc;
        ENTRY;

        osc_unlink_orig_logops = llog_lvfs_ops;
        osc_unlink_orig_logops.lop_setup = llog_obd_origin_setup;
        osc_unlink_orig_logops.lop_cleanup = llog_obd_origin_cleanup;
        osc_unlink_orig_logops.lop_add = llog_obd_origin_add;
        osc_unlink_orig_logops.lop_connect = llog_origin_connect;

        rc = llog_setup(obd, LLOG_UNLINK_ORIG_CTXT, tgt, count,
                        &catid->lci_logid, &osc_unlink_orig_logops);
        if (rc)
                RETURN(rc);

        rc = llog_setup(obd, LLOG_SIZE_REPL_CTXT, tgt, count, NULL,
                        &osc_size_repl_logops);
        RETURN(rc);
}

static int osc_llog_finish(struct obd_device *obd, int count)
{
        int rc;
        ENTRY;

        rc = llog_cleanup(llog_get_context(obd, LLOG_UNLINK_ORIG_CTXT));
        if (rc)
                RETURN(rc);

        rc = llog_cleanup(llog_get_context(obd, LLOG_SIZE_REPL_CTXT));
        RETURN(rc);
}


static int osc_connect(struct lustre_handle *exph,
                       struct obd_device *obd, struct obd_uuid *cluuid)
{
        int rc;

        rc = client_connect_import(exph, obd, cluuid);

        return rc;
}

static int osc_disconnect(struct obd_export *exp, int flags)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct llog_ctxt *ctxt = llog_get_context(obd, LLOG_SIZE_REPL_CTXT);
        int rc;

        if (obd->u.cli.cl_conn_count == 1)
                /* flush any remaining cancel messages out to the target */
                llog_sync(ctxt, exp);

        rc = client_disconnect_export(exp, flags);
        return rc;
}

static int osc_import_event(struct obd_device *obd,
                            struct obd_import *imp, 
                            enum obd_import_event event)
{
        struct client_obd *cli;
        int rc = 0;

        LASSERT(imp->imp_obd == obd);

        switch (event) {
        case IMP_EVENT_DISCON: {
                /* Only do this on the MDS OSC's */
                if (imp->imp_server_timeout) {
                        struct osc_creator *oscc = &obd->u.cli.cl_oscc;
                        
                        spin_lock(&oscc->oscc_lock);
                        oscc->oscc_flags |= OSCC_FLAG_RECOVERING;
                        spin_unlock(&oscc->oscc_lock);
                }
                break;
        }
        case IMP_EVENT_INACTIVE: {
                if (obd->obd_observer)
                        rc = obd_notify(obd->obd_observer, obd, 0);
                break;
        }
        case IMP_EVENT_INVALIDATE: {
                struct ldlm_namespace *ns = obd->obd_namespace;

                /* Reset grants */
                cli = &obd->u.cli;
                spin_lock(&cli->cl_loi_list_lock);
                cli->cl_avail_grant = 0;
                cli->cl_lost_grant = 0;
                /* all pages go to failing rpcs due to the invalid import */
                osc_check_rpcs(cli);
                spin_unlock(&cli->cl_loi_list_lock);
                
                ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);

                break;
        }
        case IMP_EVENT_ACTIVE: {
                if (obd->obd_observer)
                        rc = obd_notify(obd->obd_observer, obd, 1);
                break;
        }
        default:
                CERROR("Unknown import event %d\n", event);
                LBUG();
        }
        RETURN(rc);
}

int osc_setup(struct obd_device *obd, obd_count len, void *buf)
{
        int rc;

        rc = ptlrpcd_addref();
        if (rc)
                return rc;

        rc = client_obd_setup(obd, len, buf);
        if (rc)
                ptlrpcd_decref();
        else
                oscc_init(obd);

        RETURN(rc);
}

int osc_cleanup(struct obd_device *obd, int flags)
{
        int rc;

        rc = client_obd_cleanup(obd, flags);
        ptlrpcd_decref();
        RETURN(rc);
}


struct obd_ops osc_obd_ops = {
        o_owner:        THIS_MODULE,
        o_attach:       osc_attach,
        o_detach:       osc_detach,
        o_setup:        osc_setup,
        o_cleanup:      osc_cleanup,
        o_connect:      osc_connect,
        o_disconnect:   osc_disconnect,
        o_statfs:       osc_statfs,
        o_packmd:       osc_packmd,
        o_unpackmd:     osc_unpackmd,
        o_create:       osc_create,
        o_destroy:      osc_destroy,
        o_getattr:      osc_getattr,
        o_getattr_async:osc_getattr_async,
        o_setattr:      osc_setattr,
        o_brw:          osc_brw,
        o_brw_async:    osc_brw_async,
        .o_prep_async_page =            osc_prep_async_page,
        .o_queue_async_io =             osc_queue_async_io,
        .o_set_async_flags =            osc_set_async_flags,
        .o_queue_group_io =             osc_queue_group_io,
        .o_trigger_group_io =           osc_trigger_group_io,
        .o_teardown_async_page =        osc_teardown_async_page,
        o_punch:        osc_punch,
        o_sync:         osc_sync,
        o_enqueue:      osc_enqueue,
        o_match:        osc_match,
        o_change_cbdata:osc_change_cbdata,
        o_cancel:       osc_cancel,
        o_cancel_unused:osc_cancel_unused,
        o_iocontrol:    osc_iocontrol,
        o_get_info:     osc_get_info,
        o_set_info:     osc_set_info,
        o_import_event: osc_import_event,
        o_llog_init:    osc_llog_init,
        o_llog_finish:  osc_llog_finish,
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
struct obd_ops sanosc_obd_ops = {
        o_owner:        THIS_MODULE,
        o_attach:       osc_attach,
        o_detach:       osc_detach,
        o_cleanup:      client_obd_cleanup,
        o_connect:      osc_connect,
        o_disconnect:   client_disconnect_export,
        o_statfs:       osc_statfs,
        o_packmd:       osc_packmd,
        o_unpackmd:     osc_unpackmd,
        o_create:       osc_real_create,
        o_destroy:      osc_destroy,
        o_getattr:      osc_getattr,
        o_getattr_async:osc_getattr_async,
        o_setattr:      osc_setattr,
        o_setup:        client_sanobd_setup,
        o_brw:          sanosc_brw,
        o_punch:        osc_punch,
        o_sync:         osc_sync,
        o_enqueue:      osc_enqueue,
        o_match:        osc_match,
        o_change_cbdata:osc_change_cbdata,
        o_cancel:       osc_cancel,
        o_cancel_unused:osc_cancel_unused,
        o_iocontrol:    osc_iocontrol,
        o_import_event: osc_import_event,
        o_llog_init:    osc_llog_init,
        o_llog_finish:  osc_llog_finish,
};
#endif

int __init osc_init(void)
{
        struct lprocfs_static_vars lvars, sanlvars;
        int rc;
        ENTRY;

        lprocfs_init_vars(osc, &lvars);
        lprocfs_init_vars(osc, &sanlvars);

        rc = class_register_type(&osc_obd_ops, lvars.module_vars,
                                 LUSTRE_OSC_NAME);
        if (rc)
                RETURN(rc);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        rc = class_register_type(&sanosc_obd_ops, sanlvars.module_vars,
                                 LUSTRE_SANOSC_NAME);
        if (rc)
                class_unregister_type(LUSTRE_OSC_NAME);
#endif

        RETURN(rc);
}

static void /*__exit*/ osc_exit(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        class_unregister_type(LUSTRE_SANOSC_NAME);
#endif
        class_unregister_type(LUSTRE_OSC_NAME);
}

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC)");
MODULE_LICENSE("GPL");

module_init(osc_init);
module_exit(osc_exit);
#endif
