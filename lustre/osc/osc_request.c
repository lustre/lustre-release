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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
#include <linux/version.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/lustre_dlm.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <linux/workqueue.h>
#include <linux/smp_lock.h>
#else
#include <linux/locks.h>
#endif
#else
#include <liblustre.h>
#endif

#include <linux/kp30.h>
#include <linux/lustre_mds.h> /* for mds_objid */
#include <linux/obd_ost.h>

#ifndef  __CYGWIN__
#include <linux/ctype.h>
#include <linux/init.h>
#else
#include <ctype.h>
#endif

#include <linux/lustre_ha.h>
#include <linux/obd_support.h> /* for OBD_FAIL_CHECK */
#include <linux/lustre_lite.h> /* for ll_i2info */
#include <portals/lib-types.h> /* for PTL_MD_MAX_IOV */
#include <linux/lprocfs_status.h>

static int osc_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(&lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

static int osc_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

/* Pack OSC object metadata for disk storage (LE byte order). */
static int osc_packmd(struct lustre_handle *conn, struct lov_mds_md **lmmp,
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
                (*lmmp)->lmm_object_id = cpu_to_le64 (lsm->lsm_object_id);
        }

        RETURN(lmm_size);
}

/* Unpack OSC object metadata from disk storage (LE byte order). */
static int osc_unpackmd(struct lustre_handle *conn, struct lov_stripe_md **lsmp,
                        struct lov_mds_md *lmm, int lmm_bytes)
{
        int lsm_size;
        ENTRY;

        if (lmm != NULL) {
                if (lmm_bytes < sizeof (*lmm)) {
                        CERROR("lov_mds_md too small: %d, need %d\n",
                               lmm_bytes, (int)sizeof(*lmm));
                        RETURN (-EINVAL);
                }
                /* XXX LOV_MAGIC etc check? */

                if (lmm->lmm_object_id == cpu_to_le64 (0)) {
                        CERROR ("lov_mds_md: zero lmm_object_id\n");
                        RETURN (-EINVAL);
                }
        }

        lsm_size = sizeof(**lsmp);
        if (!lsmp)
                RETURN(lsm_size);

        if (*lsmp && !lmm) {
                OBD_FREE(*lsmp, lsm_size);
                *lsmp = NULL;
                RETURN(0);
        }

        if (!*lsmp) {
                OBD_ALLOC(*lsmp, lsm_size);
                if (!*lsmp)
                        RETURN(-ENOMEM);
        }

        if (lmm) {
                /* XXX zero *lsmp? */
                (*lsmp)->lsm_object_id = le64_to_cpu (lmm->lmm_object_id);
                (*lsmp)->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES;
                LASSERT((*lsmp)->lsm_object_id);
        }

        RETURN(lsm_size);
}

#warning "FIXME: make this be sent from OST"
#define OSC_BRW_MAX_SIZE 65536
#define OSC_BRW_MAX_IOV min_t(int, PTL_MD_MAX_IOV, OSC_BRW_MAX_SIZE/PAGE_SIZE)

static int osc_getattr_interpret(struct ptlrpc_request *req,
                                 struct osc_getattr_async_args *aa, int rc)
{
        struct obdo     *oa = aa->aa_oa;
        struct ost_body *body;
        ENTRY;

        if (rc != 0) {
                CERROR("failed: rc = %d\n", rc);
                RETURN (rc);
        }

        body = lustre_swab_repbuf (req, 0, sizeof (*body),
                                   lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                RETURN (-EPROTO);
        }

        CDEBUG(D_INODE, "mode: %o\n", body->oa.o_mode);
        memcpy(oa, &body->oa, sizeof(*oa));

        /* This should really be sent by the OST */
        oa->o_blksize = OSC_BRW_MAX_SIZE;
        oa->o_valid |= OBD_MD_FLBLKSZ;

        RETURN (0);
}

static int osc_getattr_async(struct lustre_handle *conn, struct obdo *oa,
                             struct lov_stripe_md *md,
                             struct ptlrpc_request_set *set)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int size = sizeof(*body);
        struct osc_getattr_async_args *aa;
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_GETATTR, 1,
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

static int osc_getattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *md)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_GETATTR, 1,
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
        oa->o_blksize = OSC_BRW_MAX_SIZE;
        oa->o_valid |= OBD_MD_FLBLKSZ;

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

/* The import lock must already be held. */
static inline void osc_update_body_handle(struct list_head *head,
                                          struct lustre_handle *old,
                                          struct lustre_handle *new, int op)
{
        struct list_head *tmp;
        struct ost_body *body;
        struct ptlrpc_request *req;
        struct ptlrpc_request *last_req = NULL; /* temporary fire escape */

        list_for_each(tmp, head) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);

                /* XXX ok to remove when bug 1303 resolved - rread 05/27/03  */
                LASSERT (req != last_req);
                last_req = req;

                if (req->rq_reqmsg->opc != op)
                        continue;
                body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof (*body));
                if (memcmp(obdo_handle(&body->oa), old, sizeof(*old)))
                        continue;

                DEBUG_REQ(D_HA, req, "updating close body with new fh");
                memcpy(obdo_handle(&body->oa), new, sizeof(*new));
        }
}

static void osc_replay_open(struct ptlrpc_request *req)
{
        struct lustre_handle old;
        struct ost_body *body;
        struct obd_client_handle *och = req->rq_replay_data;
        struct lustre_handle *oa_handle;
        ENTRY;

        body = lustre_swab_repbuf (req, 0, sizeof (*body),
                                   lustre_swab_ost_body);
        LASSERT (body != NULL);

        oa_handle = obdo_handle(&body->oa);

        memcpy(&old, &och->och_fh, sizeof(old));
        CDEBUG(D_HA, "updating cookie from "LPD64" to "LPD64"\n",
               och->och_fh.cookie, oa_handle->cookie);
        memcpy(&och->och_fh, oa_handle, sizeof(och->och_fh));

        /* A few frames up, ptlrpc_replay holds the lock, so this is safe. */
        osc_update_body_handle(&req->rq_import->imp_sending_list, &old,
                              &och->och_fh, OST_CLOSE);
        osc_update_body_handle(&req->rq_import->imp_delayed_list, &old,
                              &och->och_fh, OST_CLOSE);
        EXIT;
}


static int osc_open(struct lustre_handle *conn, struct obdo *oa,
                    struct lov_stripe_md *md, struct obd_trans_info *oti,
                    struct obd_client_handle *och)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        unsigned long flags;
        int rc, size = sizeof(*body);
        ENTRY;
        LASSERT(och != NULL);

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_OPEN, 1, &size,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        spin_lock_irqsave (&request->rq_lock, flags);
        request->rq_replay = 1;
        spin_unlock_irqrestore (&request->rq_lock, flags);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_swab_repbuf (request, 0, sizeof (*body),
                                   lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("Can't unpack ost_body\n");
                GOTO (out, rc = -EPROTO);
        }

        memcpy(oa, &body->oa, sizeof(*oa));

        /* If the open succeeded, we better have a handle */
        /* BlueArc OSTs don't send back (o_valid | FLHANDLE).  sigh.
         * Temporary workaround until fixed. -phil 24 Feb 03 */
        // if ((oa->o_valid & OBD_MD_FLHANDLE) == 0) {
        //         CERROR ("No file handle\n");
        //         GOTO (out, rc = -EPROTO);
        // }
        oa->o_valid |= OBD_MD_FLHANDLE;

        /* This should really be sent by the OST */
        oa->o_blksize = OSC_BRW_MAX_SIZE;
        oa->o_valid |= OBD_MD_FLBLKSZ;

        memcpy(&och->och_fh, obdo_handle(oa), sizeof(och->och_fh));
        request->rq_replay_cb = osc_replay_open;
        request->rq_replay_data = och;
        och->och_req = ptlrpc_request_addref(request);
        och->och_magic = OBD_CLIENT_HANDLE_MAGIC;

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return rc;
}

static int osc_close(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        struct obd_import *import = class_conn2cliimp(conn);
        struct ptlrpc_request *request;
        struct ost_body *body;
        struct obd_client_handle *och;
        unsigned long flags;
        int rc, size = sizeof(*body);
        ENTRY;

        LASSERT(oa != NULL);
        och = (struct obd_client_handle *)&oa->o_inline;
        if (och->och_magic == 0) {
                /* Zero magic means that this file was never opened on this
                 * OST--almost certainly because the OST was inactive at
                 * open-time */
                RETURN(0);
        }
        LASSERT(och->och_magic == OBD_CLIENT_HANDLE_MAGIC);

        request = ptlrpc_prep_req(import, OST_CLOSE, 1, &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                CDEBUG(D_HA, "Suppressing close error %d\n", rc); // bug 1036

        /* och_req == NULL can't happen any more, right? --phik */
        if (och->och_req != NULL) {
                spin_lock_irqsave(&import->imp_lock, flags);
                spin_lock (&och->och_req->rq_lock);
                och->och_req->rq_replay = 0;
                spin_unlock (&och->och_req->rq_lock);
                /* see comments in llite/file.c:ll_mdc_close() */
                if (och->och_req->rq_transno) {
                        /* this can't happen yet, because the OSTs don't yet
                         * issue transnos for OPEN requests -phik 21 Apr 2003 */
                        LBUG();
                        if (!request->rq_transno && import->imp_replayable) {
                                request->rq_transno = och->och_req->rq_transno;
                                ptlrpc_retain_replayable_request(request,
                                                                 import);
                        }
                        spin_unlock_irqrestore(&import->imp_lock, flags);
                } else {
                        spin_unlock_irqrestore(&import->imp_lock, flags);
                }

                ptlrpc_req_finished(och->och_req);
        }

        if (!rc) {
                body = lustre_swab_repbuf (request, 0, sizeof (*body),
                                           lustre_swab_ost_body);
                if (body == NULL) {
                        rc = -EPROTO;
                        CDEBUG(D_HA, "Suppressing close error %d\n", rc); // bug 1036
                } else
                        memcpy(oa, &body->oa, sizeof(*oa));
        }

        ptlrpc_req_finished(request);
        RETURN(0);
}

static int osc_setattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *md, struct obd_trans_info *oti)
{
        struct ptlrpc_request *request;
        struct ost_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_SETATTR, 1,
                                  &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);

        ptlrpc_req_finished(request);
        return rc;
}

static int osc_create(struct lustre_handle *conn, struct obdo *oa,
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
                rc = obd_alloc_memmd(conn, &lsm);
                if (rc < 0)
                        RETURN(rc);
        }

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_CREATE, 1, &size,
                                  NULL);
        if (!request)
                GOTO(out, rc = -ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out_req, rc);

        body = lustre_swab_repbuf (request, 0, sizeof (*body),
                                   lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("can't unpack ost_body\n");
                GOTO (out_req, rc = -EPROTO);
        }

        memcpy(oa, &body->oa, sizeof(*oa));

        /* This should really be sent by the OST */
        oa->o_blksize = OSC_BRW_MAX_SIZE;
        oa->o_valid |= OBD_MD_FLBLKSZ;

        lsm->lsm_object_id = oa->o_id;
        lsm->lsm_stripe_count = 0;
        lsm->lsm_maxbytes = LUSTRE_STRIPE_MAXBYTES;
        *ea = lsm;

        if (oti != NULL)
                oti->oti_transno = request->rq_repmsg->transno;

        CDEBUG(D_HA, "transno: "LPD64"\n", request->rq_repmsg->transno);
        EXIT;
out_req:
        ptlrpc_req_finished(request);
out:
        if (rc && !*ea)
                obd_free_memmd(conn, &lsm);
        return rc;
}

static int osc_punch(struct lustre_handle *conn, struct obdo *oa,
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

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_PUNCH, 1, &size,
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

static int osc_destroy(struct lustre_handle *conn, struct obdo *oa,
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
        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_DESTROY, 1,
                                  &size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        memcpy(&body->oa, oa, sizeof(*oa));

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc)
                GOTO(out, rc);

        body = lustre_swab_repbuf (request, 0, sizeof (*body),
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

static int check_write_rcs (struct ptlrpc_request *request,
                            int niocount, obd_count page_count,
                            struct brw_page *pga)
{
        int    i;
        __u32 *remote_rcs;

        /* return error if any niobuf was in error */
        remote_rcs = lustre_swab_repbuf(request, 1,
                                        sizeof(*remote_rcs) * niocount, NULL);
        if (remote_rcs == NULL) {
                CERROR ("Missing/short RC vector on BRW_WRITE reply\n");
                return (-EPROTO);
        }
        if (lustre_msg_swabbed (request->rq_repmsg))
                for (i = 0; i < niocount; i++)
                        __swab32s (&remote_rcs[i]);

        for (i = 0; i < niocount; i++) {
                if (remote_rcs[i] < 0)
                        return (remote_rcs[i]);

                if (remote_rcs[i] != 0) {
                        CERROR ("rc[%d] invalid (%d) req %p\n",
                                i, remote_rcs[i], request);
                        return (-EPROTO);
                }
        }

        return (0);
}

static inline int can_merge_pages (struct brw_page *p1, struct brw_page *p2)
{
        if (p1->flag != p2->flag) {
                /* XXX we don't make much use of 'flag' right now
                 * but this will warn about usage when we do */
                CERROR ("different flags set %d, %d\n",
                        p1->flag, p2->flag);
                return (0);
        }

        return (p1->off + p1->count == p2->off);
}

#if CHECKSUM_BULK
static __u64 cksum_pages(int nob, obd_count page_count, struct brw_page *pga)
{
        __u64 cksum = 0;
        char *ptr;
        int   i;

        while (nob > 0) {
                LASSERT (page_count > 0);

                ptr = kmap (pga->pg);
                ost_checksum (&cksum, ptr + (pga->off & (PAGE_SIZE - 1)),
                              pga->count > nob ? nob : pga->count);
                kunmap (pga->pg);

                nob -= pga->count;
                page_count--;
                pga++;
        }

        return (cksum);
}
#endif

static int osc_brw_prep_request(struct obd_import *imp,
                                struct lov_stripe_md *lsm, obd_count page_count,
                                struct brw_page *pga, int cmd,
                                int *requested_nobp, int *niocountp,
                                struct ptlrpc_request **reqp)
{
        struct ptlrpc_request   *req;
        struct ptlrpc_bulk_desc *desc;
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
                if (!can_merge_pages (&pga[i - 1], &pga[i]))
                        niocount++;

        size[0] = sizeof (*body);
        size[1] = sizeof (*ioobj);
        size[2] = niocount * sizeof (*niobuf);

        req = ptlrpc_prep_req (imp, opc, 3, size, NULL);
        if (req == NULL)
                return (-ENOMEM);

        if (opc == OST_WRITE)
                desc = ptlrpc_prep_bulk_imp(req, BULK_GET_SOURCE,
                                            OST_BULK_PORTAL);
        else
                desc = ptlrpc_prep_bulk_imp(req, BULK_PUT_SINK,
                                            OST_BULK_PORTAL);
        if (desc == NULL)
                GOTO (out, rc = -ENOMEM);
        /* NB request now owns desc and will free it when it gets freed */

        body = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*body));
        ioobj = lustre_msg_buf(req->rq_reqmsg, 1, sizeof(*ioobj));
        niobuf = lustre_msg_buf(req->rq_reqmsg, 2, niocount * sizeof(*niobuf));

        ioobj->ioo_id = lsm->lsm_object_id;
        ioobj->ioo_gr = 0;
        ioobj->ioo_type = S_IFREG;
        ioobj->ioo_bufcnt = niocount;

        LASSERT (page_count > 0);
        for (requested_nob = i = 0; i < page_count; i++, niobuf++) {
                struct brw_page *pg = &pga[i];
                struct brw_page *pg_prev = pg - 1;

                LASSERT (pg->count > 0);
                LASSERT ((pg->off & (PAGE_SIZE - 1)) + pg->count <= PAGE_SIZE);
                LASSERT (i == 0 || pg->off > pg_prev->off);

                rc = ptlrpc_prep_bulk_page (desc, pg->pg,
                                            pg->off & (PAGE_SIZE - 1),
                                            pg->count);
                if (rc != 0)
                        GOTO (out, rc);

                requested_nob += pg->count;

                if (i > 0 &&
                    can_merge_pages (pg_prev, pg)) {
                        niobuf--;
                        niobuf->len += pg->count;
                } else {
                        niobuf->offset = pg->off;
                        niobuf->len    = pg->count;
                        niobuf->flags  = pg->flag;
                }
        }

        LASSERT ((void *)(niobuf - niocount) ==
                 lustre_msg_buf(req->rq_reqmsg, 2, niocount * sizeof(*niobuf)));
#if CHECKSUM_BULK
        body->oa.o_valid |= OBD_MD_FLCKSUM;
        if (opc == OST_BRW_WRITE)
                body->oa.o_rdev = cksum_pages (requested_nob, page_count, pga);
#endif
        spin_lock_irqsave (&req->rq_lock, flags);
        req->rq_no_resend = 1;
        spin_unlock_irqrestore (&req->rq_lock, flags);

        /* size[0] still sizeof (*body) */
        if (opc == OST_WRITE) {
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

static int osc_brw_fini_request (struct ptlrpc_request *req,
                                 int requested_nob, int niocount,
                                 obd_count page_count, struct brw_page *pga,
                                 int rc)
{
        if (rc < 0)
                return (rc);

        if (req->rq_reqmsg->opc == OST_WRITE) {
                if (rc > 0) {
                        CERROR ("Unexpected +ve rc %d\n", rc);
                        return (-EPROTO);
                }

                return (check_write_rcs(req, niocount, page_count, pga));
        }

        if (rc > requested_nob) {
                CERROR ("Unexpected rc %d (%d requested)\n",
                        rc, requested_nob);
                return (-EPROTO);
        }

        if (rc < requested_nob)
                handle_short_read (rc, page_count, pga);

#if CHECKSUM_BULK
        imp = req->rq_import;
        body = lustre_swab_repmsg (req, 0, sizeof (*body),
                                   lustre_swab_ost_body);
        if (body == NULL) {
                CERROR ("Can't unpack body\n");
        } else if (body->oa.o_valid & OBD_MD_FLCKSUM) {
                static int cksum_counter;
                __u64 server_cksum = body->oa.o_rdev;
                __u64 cksum = cksum_pages (rc, page_count, pga);

                cksum_counter++;
                if (server_cksum != cksum) {
                        CERROR("Bad checksum: server "LPX64", client "LPX64
                               ", server NID "LPX64"\n", server_cksum, cksum,
                               imp->imp_connection->c_peer.peer_nid);
                        cksum_counter = 0;
                } else if ((cksum_counter & (-cksum_counter)) == cksum_counter)
                        CERROR("Checksum %u from "LPX64" OK: "LPX64"\n",
                               cksum_counter,
                               imp->imp_connection->c_peer.peer_nid, cksum);
        } else {
                static int cksum_missed;
                cksum_missed++;
                if ((cksum_missed & (-cksum_missed)) == cksum_missed)
                        CERROR("Request checksum %u from "LPX64", no reply\n",
                               cksum_missed,
                               imp->imp_connection->c_peer.peer_nid);
        }
#endif
        return (0);
}

static int osc_brw_internal(struct lustre_handle *conn,
                            struct lov_stripe_md *lsm,
                            obd_count page_count, struct brw_page *pga, int cmd)
{
        int                    requested_nob;
        int                    niocount;
        struct ptlrpc_request *request;
        int                    rc;
        ENTRY;

restart_bulk:
        rc = osc_brw_prep_request(class_conn2cliimp(conn), lsm, page_count, pga,
                                  cmd, &requested_nob, &niocount, &request);
        /* NB ^ sets rq_no_resend */

        if (rc != 0)
                return (rc);

        rc = ptlrpc_queue_wait(request);

        if (rc == -ETIMEDOUT && request->rq_resend) {
                DEBUG_REQ(D_HA, request,  "BULK TIMEOUT");
                ptlrpc_req_finished(request);
                goto restart_bulk;
        }

        rc = osc_brw_fini_request (request, requested_nob, niocount,
                                   page_count, pga, rc);

        ptlrpc_req_finished(request);
        RETURN (rc);
}

static int brw_interpret(struct ptlrpc_request *request,
                         struct osc_brw_async_args *aa, int rc)
{
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

        rc = osc_brw_fini_request (request, requested_nob, niocount,
                                   page_count, pga, rc);
        RETURN (rc);
}

static int async_internal(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                          obd_count page_count, struct brw_page *pga,
                          struct ptlrpc_request_set *set, int cmd)
{
        struct ptlrpc_request     *request;
        int                        requested_nob;
        int                        nio_count;
        struct osc_brw_async_args *aa;
        int                        rc;
        ENTRY;

        rc = osc_brw_prep_request (class_conn2cliimp(conn),
                                   lsm, page_count, pga, cmd,
                                   &requested_nob, &nio_count, &request);
        /* NB ^ sets rq_no_resend */

        if (rc == 0) {
                LASSERT (sizeof (*aa) <= sizeof (request->rq_async_args));
                aa = (struct osc_brw_async_args *)&request->rq_async_args;
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

static int osc_brw(int cmd, struct lustre_handle *conn,
                   struct lov_stripe_md *md, obd_count page_count,
                   struct brw_page *pga, struct obd_trans_info *oti)
{
        ENTRY;

        if (cmd == OBD_BRW_CHECK) {
                /* The caller just wants to know if there's a chance that this
                 * I/O can succeed */
                struct obd_import *imp = class_conn2cliimp(conn);

                if (imp == NULL || imp->imp_invalid)
                        RETURN(-EIO);
                RETURN(0);
        }

        while (page_count) {
                obd_count pages_per_brw;
                int rc;

                if (page_count > OSC_BRW_MAX_IOV)
                        pages_per_brw = OSC_BRW_MAX_IOV;
                else
                        pages_per_brw = page_count;

                sort_brw_pages(pga, pages_per_brw);
                pages_per_brw = check_elan_limit(pga, pages_per_brw);

                rc = osc_brw_internal(conn, md, pages_per_brw, pga, cmd);

                if (rc != 0)
                        RETURN(rc);

                page_count -= pages_per_brw;
                pga += pages_per_brw;
        }
        RETURN(0);
}

static int osc_brw_async(int cmd, struct lustre_handle *conn,
                         struct lov_stripe_md *md, obd_count page_count,
                         struct brw_page *pga, struct ptlrpc_request_set *set,
                         struct obd_trans_info *oti)
{
        ENTRY;

        if (cmd == OBD_BRW_CHECK) {
                /* The caller just wants to know if there's a chance that this
                 * I/O can succeed */
                struct obd_import *imp = class_conn2cliimp(conn);

                if (imp == NULL || imp->imp_invalid)
                        RETURN(-EIO);
                RETURN(0);
        }

        while (page_count) {
                obd_count pages_per_brw;
                int rc;

                if (page_count > OSC_BRW_MAX_IOV)
                        pages_per_brw = OSC_BRW_MAX_IOV;
                else
                        pages_per_brw = page_count;

                sort_brw_pages(pga, pages_per_brw);
                pages_per_brw = check_elan_limit(pga, pages_per_brw);

                rc = async_internal(conn, md, pages_per_brw, pga, set, cmd);

                if (rc != 0)
                        RETURN(rc);

                page_count -= pages_per_brw;
                pga += pages_per_brw;
        }
        RETURN(0);
}

#ifdef __KERNEL__
/* Note: caller will lock/unlock, and set uptodate on the pages */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int sanosc_brw_read(struct lustre_handle *conn,
                           struct lov_stripe_md *lsm,
                           obd_count page_count,
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

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_SAN_READ, 3,
                                  size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        iooptr = lustre_msg_buf(request->rq_reqmsg, 1, sizeof (*iooptr));
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2,
                                sizeof (*nioptr) * page_count);

        iooptr->ioo_id = lsm->lsm_object_id;
        iooptr->ioo_gr = 0;
        iooptr->ioo_type = S_IFREG;
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

        swab = lustre_msg_swabbed (request->rq_repmsg);
        LASSERT_REPSWAB (request, 1);
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
                LASSERT(class_conn2obd(conn));
                dev = class_conn2obd(conn)->u.cli.cl_sandev;

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

static int sanosc_brw_write(struct lustre_handle *conn,
                            struct lov_stripe_md *lsm,
                            obd_count page_count,
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

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_SAN_WRITE,
                                  3, size, NULL);
        if (!request)
                RETURN(-ENOMEM);

        body = lustre_msg_buf(request->rq_reqmsg, 0, sizeof (*body));
        iooptr = lustre_msg_buf(request->rq_reqmsg, 1, sizeof (*iooptr));
        nioptr = lustre_msg_buf(request->rq_reqmsg, 2,
                                sizeof (*nioptr) * page_count);

        iooptr->ioo_id = lsm->lsm_object_id;
        iooptr->ioo_gr = 0;
        iooptr->ioo_type = S_IFREG;
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
                LASSERT(class_conn2obd(conn));
                dev = class_conn2obd(conn)->u.cli.cl_sandev;

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

static int sanosc_brw(int cmd, struct lustre_handle *conn,
                      struct lov_stripe_md *lsm, obd_count page_count,
                      struct brw_page *pga, struct obd_trans_info *oti)
{
        ENTRY;

        while (page_count) {
                obd_count pages_per_brw;
                int rc;

                if (page_count > OSC_BRW_MAX_IOV)
                        pages_per_brw = OSC_BRW_MAX_IOV;
                else
                        pages_per_brw = page_count;

                if (cmd & OBD_BRW_WRITE)
                        rc = sanosc_brw_write(conn, lsm, pages_per_brw, pga);
                else
                        rc = sanosc_brw_read(conn, lsm, pages_per_brw, pga);

                if (rc != 0)
                        RETURN(rc);

                page_count -= pages_per_brw;
                pga += pages_per_brw;
        }
        RETURN(0);
}
#endif
#endif

static int osc_enqueue(struct lustre_handle *connh, struct lov_stripe_md *lsm,
                       struct lustre_handle *parent_lock,
                       __u32 type, void *extentp, int extent_len, __u32 mode,
                       int *flags, void *callback, void *data,
                       struct lustre_handle *lockh)
{
        struct ldlm_res_id res_id = { .name = {lsm->lsm_object_id} };
        struct obd_device *obddev = class_conn2obd(connh);
        struct ldlm_extent *extent = extentp;
        int rc;
        ENTRY;

        /* Filesystem lock extents are extended to page boundaries so that
         * dealing with the page cache is a little smoother.  */
        extent->start -= extent->start & ~PAGE_MASK;
        extent->end |= ~PAGE_MASK;

        /* Next, search for already existing extent locks that will cover us */
        rc = ldlm_lock_match(obddev->obd_namespace, LDLM_FL_MATCH_DATA, &res_id,
                             type, extent, sizeof(extent), mode, data, lockh);
        if (rc == 1)
                /* We already have a lock, and it's referenced */
                RETURN(ELDLM_OK);

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
                rc = ldlm_lock_match(obddev->obd_namespace, LDLM_FL_MATCH_DATA,
                                     &res_id, type, extent, sizeof(extent),
                                     LCK_PW, data, lockh);
                if (rc == 1) {
                        /* FIXME: This is not incredibly elegant, but it might
                         * be more elegant than adding another parameter to
                         * lock_match.  I want a second opinion. */
                        ldlm_lock_addref(lockh, LCK_PR);
                        ldlm_lock_decref(lockh, LCK_PW);

                        RETURN(ELDLM_OK);
                }
        }

        rc = ldlm_cli_enqueue(connh, NULL, obddev->obd_namespace, parent_lock,
                              res_id, type, extent, sizeof(extent), mode, flags,
                              ldlm_completion_ast, callback, data, lockh);
        RETURN(rc);
}

static int osc_match(struct lustre_handle *connh, struct lov_stripe_md *lsm,
                       __u32 type, void *extentp, int extent_len, __u32 mode,
                       int *flags, void *data, struct lustre_handle *lockh)
{
        struct ldlm_res_id res_id = { .name = {lsm->lsm_object_id} };
        struct obd_device *obddev = class_conn2obd(connh);
        struct ldlm_extent *extent = extentp;
        int rc;
        ENTRY;

        /* Filesystem lock extents are extended to page boundaries so that
         * dealing with the page cache is a little smoother */
        extent->start -= extent->start & ~PAGE_MASK;
        extent->end |= ~PAGE_MASK;

        /* Next, search for already existing extent locks that will cover us */
        rc = ldlm_lock_match(obddev->obd_namespace, *flags, &res_id, type,
                             extent, sizeof(extent), mode, data, lockh);
        if (rc)
                RETURN(rc);

        /* If we're trying to read, we also search for an existing PW lock.  The
         * VFS and page cache already protect us locally, so lots of readers/
         * writers can share a single PW lock. */
        if (mode == LCK_PR) {
                rc = ldlm_lock_match(obddev->obd_namespace, *flags, &res_id,
                                     type, extent, sizeof(extent), LCK_PW,
                                     data, lockh);
                if (rc == 1) {
                        /* FIXME: This is not incredibly elegant, but it might
                         * be more elegant than adding another parameter to
                         * lock_match.  I want a second opinion. */
                        ldlm_lock_addref(lockh, LCK_PR);
                        ldlm_lock_decref(lockh, LCK_PW);
                }
        }
        RETURN(rc);
}

static int osc_cancel(struct lustre_handle *oconn, struct lov_stripe_md *md,
                      __u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

static int osc_cancel_unused(struct lustre_handle *connh,
                             struct lov_stripe_md *lsm, int flags, void *opaque)
{
        struct obd_device *obddev = class_conn2obd(connh);
        struct ldlm_res_id res_id = { .name = {lsm->lsm_object_id} };

        return ldlm_cli_cancel_unused(obddev->obd_namespace, &res_id, flags,
                                      opaque);
}

static int osc_statfs(struct lustre_handle *conn, struct obd_statfs *osfs)
{
        struct obd_statfs *msfs;
        struct ptlrpc_request *request;
        int rc, size = sizeof(*osfs);
        ENTRY;

        request = ptlrpc_prep_req(class_conn2cliimp(conn), OST_STATFS, 0, NULL,
                                  NULL);
        if (!request)
                RETURN(-ENOMEM);

        request->rq_replen = lustre_msg_size(1, &size);

        rc = ptlrpc_queue_wait(request);
        if (rc) {
                CERROR("%s failed: rc = %d\n", __FUNCTION__, rc);
                GOTO(out, rc);
        }

        msfs = lustre_swab_repbuf (request, 0, sizeof (*msfs),
                                   lustre_swab_obd_statfs);
        if (msfs == NULL) {
                CERROR ("Can't unpack obd_statfs\n");
                GOTO (out, rc = -EPROTO);
        }

        memcpy (osfs, msfs, sizeof (*msfs));

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
static int osc_getstripe(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                         struct lov_mds_md *lmmu)
{
        struct lov_mds_md lmm, *lmmk;
        int rc, lmm_size;
        ENTRY;

        if (!lsm)
                RETURN(-ENODATA);

        rc = copy_from_user(&lmm, lmmu, sizeof(lmm));
        if (rc)
                RETURN(-EFAULT);

        if (lmm.lmm_magic != LOV_MAGIC)
                RETURN(-EINVAL);

        if (lmm.lmm_ost_count < 1)
                RETURN(-EOVERFLOW);

        lmm_size = sizeof(lmm) + sizeof(lmm.lmm_objects[0]);
        OBD_ALLOC(lmmk, lmm_size);
        if (rc < 0)
                RETURN(rc);

        lmmk->lmm_stripe_count = 1;
        lmmk->lmm_ost_count = 1;
        lmmk->lmm_object_id = lsm->lsm_object_id;
        lmmk->lmm_objects[0].l_object_id = lsm->lsm_object_id;

        if (copy_to_user(lmmu, lmmk, lmm_size))
                rc = -EFAULT;

        OBD_FREE(lmmk, lmm_size);

        RETURN(rc);
}

static int osc_iocontrol(unsigned int cmd, struct lustre_handle *conn, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct obd_ioctl_data *data = karg;
        int err = 0;
        ENTRY;

        switch (cmd) {
        case IOC_OSC_REGISTER_LOV: {
                if (obddev->u.cli.cl_containing_lov)
                        GOTO(out, err = -EALREADY);
                obddev->u.cli.cl_containing_lov = (struct obd_device *)karg;
                GOTO(out, err);
        }
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
                memcpy(&desc->ld_uuid, &obddev->obd_uuid, sizeof(uuid));

                memcpy(data->ioc_inlbuf2, &obddev->obd_uuid, sizeof(uuid));

                err = copy_to_user((void *)uarg, buf, len);
                if (err)
                        err = -EFAULT;
                obd_ioctl_freedata(buf, len);
                GOTO(out, err);
        }
        case LL_IOC_LOV_SETSTRIPE:
                err = obd_alloc_memmd(conn, karg);
                if (err > 0)
                        err = 0;
                GOTO(out, err);
        case LL_IOC_LOV_GETSTRIPE:
                err = osc_getstripe(conn, karg, uarg);
                GOTO(out, err);
        case OBD_IOC_CLIENT_RECOVER:
                err = ptlrpc_recover_import(obddev->u.cli.cl_import,
                                            data->ioc_inlbuf1);
                GOTO(out, err);
        case IOC_OSC_SET_ACTIVE:
                err = ptlrpc_set_import_active(obddev->u.cli.cl_import,
                                               data->ioc_offset);
                GOTO(out, err);
        default:
                CERROR ("osc_ioctl(): unrecognised ioctl %#x\n", cmd);
                GOTO(out, err = -ENOTTY);
        }
out:
        return err;
}

static int osc_get_info(struct lustre_handle *conn, obd_count keylen,
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
        }
        RETURN(-EINVAL);
}

struct obd_ops osc_obd_ops = {
        o_owner:        THIS_MODULE,
        o_attach:       osc_attach,
        o_detach:       osc_detach,
        o_setup:        client_obd_setup,
        o_cleanup:      client_obd_cleanup,
        o_connect:      client_import_connect,
        o_disconnect:   client_import_disconnect,
        o_statfs:       osc_statfs,
        o_packmd:       osc_packmd,
        o_unpackmd:     osc_unpackmd,
        o_create:       osc_create,
        o_destroy:      osc_destroy,
        o_getattr:      osc_getattr,
        o_getattr_async: osc_getattr_async,
        o_setattr:      osc_setattr,
        o_open:         osc_open,
        o_close:        osc_close,
        o_brw:          osc_brw,
        o_brw_async:    osc_brw_async,
        o_punch:        osc_punch,
        o_enqueue:      osc_enqueue,
        o_match:        osc_match,
        o_cancel:       osc_cancel,
        o_cancel_unused: osc_cancel_unused,
        o_iocontrol:    osc_iocontrol,
        o_get_info:     osc_get_info
};

struct obd_ops sanosc_obd_ops = {
        o_owner:        THIS_MODULE,
        o_attach:       osc_attach,
        o_detach:       osc_detach,
        o_cleanup:      client_obd_cleanup,
        o_connect:      client_import_connect,
        o_disconnect:   client_import_disconnect,
        o_statfs:       osc_statfs,
        o_packmd:       osc_packmd,
        o_unpackmd:     osc_unpackmd,
        o_create:       osc_create,
        o_destroy:      osc_destroy,
        o_getattr:      osc_getattr,
        o_getattr_async: osc_getattr_async,
        o_setattr:      osc_setattr,
        o_open:         osc_open,
        o_close:        osc_close,
#ifdef __KERNEL__
        o_setup:        client_sanobd_setup,
        o_brw:          sanosc_brw,
#endif
        o_punch:        osc_punch,
        o_enqueue:      osc_enqueue,
        o_match:        osc_match,
        o_cancel:       osc_cancel,
        o_cancel_unused: osc_cancel_unused,
        o_iocontrol:    osc_iocontrol,
};

int __init osc_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        LASSERT(sizeof(struct obd_client_handle) <= FD_OSTDATA_SIZE);
        LASSERT(sizeof(struct obd_client_handle) <= OBD_INLINESZ);

        lprocfs_init_vars(&lvars);

        rc = class_register_type(&osc_obd_ops, lvars.module_vars,
                                 LUSTRE_OSC_NAME);
        if (rc)
                RETURN(rc);

        rc = class_register_type(&sanosc_obd_ops, lvars.module_vars,
                                 LUSTRE_SANOSC_NAME);
        if (rc)
                class_unregister_type(LUSTRE_OSC_NAME);

        RETURN(rc);
}

static void __exit osc_exit(void)
{
        class_unregister_type(LUSTRE_SANOSC_NAME);
        class_unregister_type(LUSTRE_OSC_NAME);
}

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Object Storage Client (OSC)");
MODULE_LICENSE("GPL");

module_init(osc_init);
module_exit(osc_exit);
#endif
