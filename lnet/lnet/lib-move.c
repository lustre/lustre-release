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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/lnet/lib-move.c
 *
 * Data movement routines
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lib-lnet.h>

static int local_nid_dist_zero = 1;
CFS_MODULE_PARM(local_nid_dist_zero, "i", int, 0444,
                "Reserved");

/* forward ref */
static void lnet_commit_md (lnet_libmd_t *md, lnet_msg_t *msg);

#define LNET_MATCHMD_NONE     0   /* Didn't match */
#define LNET_MATCHMD_OK       1   /* Matched OK */
#define LNET_MATCHMD_DROP     2   /* Must be discarded */

static int
lnet_try_match_md (int index, int op_mask, lnet_process_id_t src,
                   unsigned int rlength, unsigned int roffset,
                   __u64 match_bits, lnet_libmd_t *md, lnet_msg_t *msg,
                   unsigned int *mlength_out, unsigned int *offset_out)
{
        /* ALWAYS called holding the LNET_LOCK, and can't LNET_UNLOCK;
         * lnet_match_blocked_msg() relies on this to avoid races */
        unsigned int  offset;
        unsigned int  mlength;
        lnet_me_t    *me = md->md_me;

        /* mismatched MD op */
        if ((md->md_options & op_mask) == 0)
                return LNET_MATCHMD_NONE;

        /* MD exhausted */
        if (lnet_md_exhausted(md))
                return LNET_MATCHMD_NONE;

        /* mismatched ME nid/pid? */
        if (me->me_match_id.nid != LNET_NID_ANY &&
            me->me_match_id.nid != src.nid)
                return LNET_MATCHMD_NONE;

        if (me->me_match_id.pid != LNET_PID_ANY &&
            me->me_match_id.pid != src.pid)
                return LNET_MATCHMD_NONE;

        /* mismatched ME matchbits? */
        if (((me->me_match_bits ^ match_bits) & ~me->me_ignore_bits) != 0)
                return LNET_MATCHMD_NONE;

        /* Hurrah! This _is_ a match; check it out... */

        if ((md->md_options & LNET_MD_MANAGE_REMOTE) == 0)
                offset = md->md_offset;
        else
                offset = roffset;

        if ((md->md_options & LNET_MD_MAX_SIZE) != 0) {
                mlength = md->md_max_size;
                LASSERT (md->md_offset + mlength <= md->md_length);
        } else {
                mlength = md->md_length - offset;
        }

        if (rlength <= mlength) {        /* fits in allowed space */
                mlength = rlength;
        } else if ((md->md_options & LNET_MD_TRUNCATE) == 0) {
                /* this packet _really_ is too big */
                CERROR("Matching packet from %s, match "LPU64
                       " length %d too big: %d left, %d allowed\n",
                       libcfs_id2str(src), match_bits, rlength,
                       md->md_length - offset, mlength);

                return LNET_MATCHMD_DROP;
        }

        /* Commit to this ME/MD */
        CDEBUG(D_NET, "Incoming %s index %x from %s of "
               "length %d/%d into md "LPX64" [%d] + %d\n",
               (op_mask == LNET_MD_OP_PUT) ? "put" : "get",
               index, libcfs_id2str(src), mlength, rlength,
               md->md_lh.lh_cookie, md->md_niov, offset);

        lnet_commit_md(md, msg);
        md->md_offset = offset + mlength;

        /* NB Caller will set ev.type and ev.hdr_data */
        msg->msg_ev.initiator = src;
        msg->msg_ev.pt_index = index;
        msg->msg_ev.match_bits = match_bits;
        msg->msg_ev.rlength = rlength;
        msg->msg_ev.mlength = mlength;
        msg->msg_ev.offset = offset;

        lnet_md_deconstruct(md, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, md);

        *offset_out = offset;
        *mlength_out = mlength;

        /* Auto-unlink NOW, so the ME gets unlinked if required.
         * We bumped md->md_refcount above so the MD just gets flagged
         * for unlink when it is finalized. */
        if ((md->md_flags & LNET_MD_FLAG_AUTO_UNLINK) != 0 &&
            lnet_md_exhausted(md)) {
                lnet_md_unlink(md);
        }

        return LNET_MATCHMD_OK;
}

static int
lnet_match_md(int index, int op_mask, lnet_process_id_t src,
              unsigned int rlength, unsigned int roffset,
              __u64 match_bits, lnet_msg_t *msg,
              unsigned int *mlength_out, unsigned int *offset_out,
              lnet_libmd_t **md_out)
{
        lnet_portal_t    *ptl = &the_lnet.ln_portals[index];
        struct list_head *head;
        lnet_me_t        *me;
        lnet_me_t        *tmp;
        lnet_libmd_t     *md;
        int               rc;

        CDEBUG (D_NET, "Request from %s of length %d into portal %d "
                "MB="LPX64"\n", libcfs_id2str(src), rlength, index, match_bits);

        if (index < 0 || index >= the_lnet.ln_nportals) {
                CERROR("Invalid portal %d not in [0-%d]\n",
                       index, the_lnet.ln_nportals);
                return LNET_MATCHMD_DROP;
        }

        head = lnet_portal_me_head(index, src, match_bits);
        if (head == NULL) /* nobody posted anything on this portal */
                goto out;

        list_for_each_entry_safe (me, tmp, head, me_list) {
                md = me->me_md;

                /* ME attached but MD not attached yet */
                if (md == NULL)
                        continue;

                LASSERT (me == md->md_me);

                rc = lnet_try_match_md(index, op_mask, src, rlength,
                                       roffset, match_bits, md, msg,
                                       mlength_out, offset_out);
                switch (rc) {
                default:
                        LBUG();

                case LNET_MATCHMD_NONE:
                        continue;

                case LNET_MATCHMD_OK:
                        *md_out = md;
                        return LNET_MATCHMD_OK;

                case LNET_MATCHMD_DROP:
                        return LNET_MATCHMD_DROP;
                }
                /* not reached */
        }

 out:
        if (op_mask == LNET_MD_OP_GET ||
            !lnet_portal_is_lazy(ptl))
                return LNET_MATCHMD_DROP;

        return LNET_MATCHMD_NONE;
}

int
lnet_fail_nid (lnet_nid_t nid, unsigned int threshold)
{
        lnet_test_peer_t   *tp;
        struct list_head  *el;
        struct list_head  *next;
        struct list_head   cull;

        LASSERT (the_lnet.ln_init);

        if (threshold != 0) {
                /* Adding a new entry */
                LIBCFS_ALLOC(tp, sizeof(*tp));
                if (tp == NULL)
                        return -ENOMEM;

                tp->tp_nid = nid;
                tp->tp_threshold = threshold;

                LNET_LOCK();
                list_add_tail (&tp->tp_list, &the_lnet.ln_test_peers);
                LNET_UNLOCK();
                return 0;
        }

        /* removing entries */
        CFS_INIT_LIST_HEAD (&cull);

        LNET_LOCK();

        list_for_each_safe (el, next, &the_lnet.ln_test_peers) {
                tp = list_entry (el, lnet_test_peer_t, tp_list);

                if (tp->tp_threshold == 0 ||    /* needs culling anyway */
                    nid == LNET_NID_ANY ||       /* removing all entries */
                    tp->tp_nid == nid)          /* matched this one */
                {
                        list_del (&tp->tp_list);
                        list_add (&tp->tp_list, &cull);
                }
        }

        LNET_UNLOCK();

        while (!list_empty (&cull)) {
                tp = list_entry (cull.next, lnet_test_peer_t, tp_list);

                list_del (&tp->tp_list);
                LIBCFS_FREE(tp, sizeof (*tp));
        }
        return 0;
}

static int
fail_peer (lnet_nid_t nid, int outgoing)
{
        lnet_test_peer_t  *tp;
        struct list_head *el;
        struct list_head *next;
        struct list_head  cull;
        int               fail = 0;

        CFS_INIT_LIST_HEAD (&cull);

        LNET_LOCK();

        list_for_each_safe (el, next, &the_lnet.ln_test_peers) {
                tp = list_entry (el, lnet_test_peer_t, tp_list);

                if (tp->tp_threshold == 0) {
                        /* zombie entry */
                        if (outgoing) {
                                /* only cull zombies on outgoing tests,
                                 * since we may be at interrupt priority on
                                 * incoming messages. */
                                list_del (&tp->tp_list);
                                list_add (&tp->tp_list, &cull);
                        }
                        continue;
                }

                if (tp->tp_nid == LNET_NID_ANY || /* fail every peer */
                    nid == tp->tp_nid) {        /* fail this peer */
                        fail = 1;

                        if (tp->tp_threshold != LNET_MD_THRESH_INF) {
                                tp->tp_threshold--;
                                if (outgoing &&
                                    tp->tp_threshold == 0) {
                                        /* see above */
                                        list_del (&tp->tp_list);
                                        list_add (&tp->tp_list, &cull);
                                }
                        }
                        break;
                }
        }

        LNET_UNLOCK ();

        while (!list_empty (&cull)) {
                tp = list_entry (cull.next, lnet_test_peer_t, tp_list);
                list_del (&tp->tp_list);

                LIBCFS_FREE(tp, sizeof (*tp));
        }

        return (fail);
}

unsigned int
lnet_iov_nob (unsigned int niov, struct iovec *iov)
{
        unsigned int nob = 0;

        while (niov-- > 0)
                nob += (iov++)->iov_len;

        return (nob);
}

void
lnet_copy_iov2iov (unsigned int ndiov, struct iovec *diov, unsigned int doffset,
                   unsigned int nsiov, struct iovec *siov, unsigned int soffset,
                   unsigned int nob)
{
        /* NB diov, siov are READ-ONLY */
        unsigned int  this_nob;

        if (nob == 0)
                return;

        /* skip complete frags before 'doffset' */
        LASSERT (ndiov > 0);
        while (doffset >= diov->iov_len) {
                doffset -= diov->iov_len;
                diov++;
                ndiov--;
                LASSERT (ndiov > 0);
        }

        /* skip complete frags before 'soffset' */
        LASSERT (nsiov > 0);
        while (soffset >= siov->iov_len) {
                soffset -= siov->iov_len;
                siov++;
                nsiov--;
                LASSERT (nsiov > 0);
        }

        do {
                LASSERT (ndiov > 0);
                LASSERT (nsiov > 0);
                this_nob = MIN(diov->iov_len - doffset,
                               siov->iov_len - soffset);
                this_nob = MIN(this_nob, nob);

                memcpy ((char *)diov->iov_base + doffset,
                        (char *)siov->iov_base + soffset, this_nob);
                nob -= this_nob;

                if (diov->iov_len > doffset + this_nob) {
                        doffset += this_nob;
                } else {
                        diov++;
                        ndiov--;
                        doffset = 0;
                }

                if (siov->iov_len > soffset + this_nob) {
                        soffset += this_nob;
                } else {
                        siov++;
                        nsiov--;
                        soffset = 0;
                }
        } while (nob > 0);
}

int
lnet_extract_iov (int dst_niov, struct iovec *dst,
                  int src_niov, struct iovec *src,
                  unsigned int offset, unsigned int len)
{
        /* Initialise 'dst' to the subset of 'src' starting at 'offset',
         * for exactly 'len' bytes, and return the number of entries.
         * NB not destructive to 'src' */
        unsigned int    frag_len;
        unsigned int    niov;

        if (len == 0)                           /* no data => */
                return (0);                     /* no frags */

        LASSERT (src_niov > 0);
        while (offset >= src->iov_len) {      /* skip initial frags */
                offset -= src->iov_len;
                src_niov--;
                src++;
                LASSERT (src_niov > 0);
        }

        niov = 1;
        for (;;) {
                LASSERT (src_niov > 0);
                LASSERT (niov <= dst_niov);

                frag_len = src->iov_len - offset;
                dst->iov_base = ((char *)src->iov_base) + offset;

                if (len <= frag_len) {
                        dst->iov_len = len;
                        return (niov);
                }

                dst->iov_len = frag_len;

                len -= frag_len;
                dst++;
                src++;
                niov++;
                src_niov--;
                offset = 0;
        }
}

#ifndef __KERNEL__
unsigned int
lnet_kiov_nob (unsigned int niov, lnet_kiov_t *kiov)
{
        LASSERT (0);
        return (0);
}

void
lnet_copy_kiov2kiov (unsigned int ndkiov, lnet_kiov_t *dkiov, unsigned int doffset,
                     unsigned int nskiov, lnet_kiov_t *skiov, unsigned int soffset,
                     unsigned int nob)
{
        LASSERT (0);
}

void
lnet_copy_kiov2iov (unsigned int niov, struct iovec *iov, unsigned int iovoffset,
                    unsigned int nkiov, lnet_kiov_t *kiov, unsigned int kiovoffset,
                    unsigned int nob)
{
        LASSERT (0);
}

void
lnet_copy_iov2kiov (unsigned int nkiov, lnet_kiov_t *kiov, unsigned int kiovoffset,
                    unsigned int niov, struct iovec *iov, unsigned int iovoffset,
                    unsigned int nob)
{
        LASSERT (0);
}

int
lnet_extract_kiov (int dst_niov, lnet_kiov_t *dst,
                   int src_niov, lnet_kiov_t *src,
                   unsigned int offset, unsigned int len)
{
        LASSERT (0);
}

#else /* __KERNEL__ */

unsigned int
lnet_kiov_nob (unsigned int niov, lnet_kiov_t *kiov)
{
        unsigned int  nob = 0;

        while (niov-- > 0)
                nob += (kiov++)->kiov_len;

        return (nob);
}

void
lnet_copy_kiov2kiov (unsigned int ndiov, lnet_kiov_t *diov, unsigned int doffset,
                     unsigned int nsiov, lnet_kiov_t *siov, unsigned int soffset,
                     unsigned int nob)
{
        /* NB diov, siov are READ-ONLY */
        unsigned int    this_nob;
        char           *daddr = NULL;
        char           *saddr = NULL;

        if (nob == 0)
                return;

        LASSERT (!in_interrupt ());

        LASSERT (ndiov > 0);
        while (doffset >= diov->kiov_len) {
                doffset -= diov->kiov_len;
                diov++;
                ndiov--;
                LASSERT (ndiov > 0);
        }

        LASSERT (nsiov > 0);
        while (soffset >= siov->kiov_len) {
                soffset -= siov->kiov_len;
                siov++;
                nsiov--;
                LASSERT (nsiov > 0);
        }

        do {
                LASSERT (ndiov > 0);
                LASSERT (nsiov > 0);
                this_nob = MIN(diov->kiov_len - doffset,
                               siov->kiov_len - soffset);
                this_nob = MIN(this_nob, nob);

                if (daddr == NULL)
                        daddr = ((char *)cfs_kmap(diov->kiov_page)) + 
                                diov->kiov_offset + doffset;
                if (saddr == NULL)
                        saddr = ((char *)cfs_kmap(siov->kiov_page)) + 
                                siov->kiov_offset + soffset;

                /* Vanishing risk of kmap deadlock when mapping 2 pages.
                 * However in practice at least one of the kiovs will be mapped
                 * kernel pages and the map/unmap will be NOOPs */

                memcpy (daddr, saddr, this_nob);
                nob -= this_nob;

                if (diov->kiov_len > doffset + this_nob) {
                        daddr += this_nob;
                        doffset += this_nob;
                } else {
                        cfs_kunmap(diov->kiov_page);
                        daddr = NULL;
                        diov++;
                        ndiov--;
                        doffset = 0;
                }

                if (siov->kiov_len > soffset + this_nob) {
                        saddr += this_nob;
                        soffset += this_nob;
                } else {
                        cfs_kunmap(siov->kiov_page);
                        saddr = NULL;
                        siov++;
                        nsiov--;
                        soffset = 0;
                }
        } while (nob > 0);

        if (daddr != NULL)
                cfs_kunmap(diov->kiov_page);
        if (saddr != NULL)
                cfs_kunmap(siov->kiov_page);
}

void
lnet_copy_kiov2iov (unsigned int niov, struct iovec *iov, unsigned int iovoffset,
                    unsigned int nkiov, lnet_kiov_t *kiov, unsigned int kiovoffset,
                    unsigned int nob)
{
        /* NB iov, kiov are READ-ONLY */
        unsigned int    this_nob;
        char           *addr = NULL;

        if (nob == 0)
                return;

        LASSERT (!in_interrupt ());

        LASSERT (niov > 0);
        while (iovoffset >= iov->iov_len) {
                iovoffset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT (niov > 0);
        }

        LASSERT (nkiov > 0);
        while (kiovoffset >= kiov->kiov_len) {
                kiovoffset -= kiov->kiov_len;
                kiov++;
                nkiov--;
                LASSERT (nkiov > 0);
        }

        do {
                LASSERT (niov > 0);
                LASSERT (nkiov > 0);
                this_nob = MIN(iov->iov_len - iovoffset,
                               kiov->kiov_len - kiovoffset);
                this_nob = MIN(this_nob, nob);

                if (addr == NULL)
                        addr = ((char *)cfs_kmap(kiov->kiov_page)) + 
                                kiov->kiov_offset + kiovoffset;

                memcpy ((char *)iov->iov_base + iovoffset, addr, this_nob);
                nob -= this_nob;

                if (iov->iov_len > iovoffset + this_nob) {
                        iovoffset += this_nob;
                } else {
                        iov++;
                        niov--;
                        iovoffset = 0;
                }

                if (kiov->kiov_len > kiovoffset + this_nob) {
                        addr += this_nob;
                        kiovoffset += this_nob;
                } else {
                        cfs_kunmap(kiov->kiov_page);
                        addr = NULL;
                        kiov++;
                        nkiov--;
                        kiovoffset = 0;
                }

        } while (nob > 0);

        if (addr != NULL)
                cfs_kunmap(kiov->kiov_page);
}

void
lnet_copy_iov2kiov (unsigned int nkiov, lnet_kiov_t *kiov, unsigned int kiovoffset,
                    unsigned int niov, struct iovec *iov, unsigned int iovoffset,
                    unsigned int nob)
{
        /* NB kiov, iov are READ-ONLY */
        unsigned int    this_nob;
        char           *addr = NULL;

        if (nob == 0)
                return;

        LASSERT (!in_interrupt ());

        LASSERT (nkiov > 0);
        while (kiovoffset >= kiov->kiov_len) {
                kiovoffset -= kiov->kiov_len;
                kiov++;
                nkiov--;
                LASSERT (nkiov > 0);
        }

        LASSERT (niov > 0);
        while (iovoffset >= iov->iov_len) {
                iovoffset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT (niov > 0);
        }

        do {
                LASSERT (nkiov > 0);
                LASSERT (niov > 0);
                this_nob = MIN(kiov->kiov_len - kiovoffset,
                               iov->iov_len - iovoffset);
                this_nob = MIN(this_nob, nob);

                if (addr == NULL)
                        addr = ((char *)cfs_kmap(kiov->kiov_page)) + 
                                kiov->kiov_offset + kiovoffset;

                memcpy (addr, (char *)iov->iov_base + iovoffset, this_nob);
                nob -= this_nob;

                if (kiov->kiov_len > kiovoffset + this_nob) {
                        addr += this_nob;
                        kiovoffset += this_nob;
                } else {
                        cfs_kunmap(kiov->kiov_page);
                        addr = NULL;
                        kiov++;
                        nkiov--;
                        kiovoffset = 0;
                }

                if (iov->iov_len > iovoffset + this_nob) {
                        iovoffset += this_nob;
                } else {
                        iov++;
                        niov--;
                        iovoffset = 0;
                }
        } while (nob > 0);

        if (addr != NULL)
                cfs_kunmap(kiov->kiov_page);
}

int
lnet_extract_kiov (int dst_niov, lnet_kiov_t *dst,
                   int src_niov, lnet_kiov_t *src,
                   unsigned int offset, unsigned int len)
{
        /* Initialise 'dst' to the subset of 'src' starting at 'offset',
         * for exactly 'len' bytes, and return the number of entries.
         * NB not destructive to 'src' */
        unsigned int    frag_len;
        unsigned int    niov;

        if (len == 0)                           /* no data => */
                return (0);                     /* no frags */

        LASSERT (src_niov > 0);
        while (offset >= src->kiov_len) {      /* skip initial frags */
                offset -= src->kiov_len;
                src_niov--;
                src++;
                LASSERT (src_niov > 0);
        }

        niov = 1;
        for (;;) {
                LASSERT (src_niov > 0);
                LASSERT (niov <= dst_niov);

                frag_len = src->kiov_len - offset;
                dst->kiov_page = src->kiov_page;
                dst->kiov_offset = src->kiov_offset + offset;

                if (len <= frag_len) {
                        dst->kiov_len = len;
                        LASSERT (dst->kiov_offset + dst->kiov_len <= CFS_PAGE_SIZE);
                        return (niov);
                }

                dst->kiov_len = frag_len;
                LASSERT (dst->kiov_offset + dst->kiov_len <= CFS_PAGE_SIZE);

                len -= frag_len;
                dst++;
                src++;
                niov++;
                src_niov--;
                offset = 0;
        }
}
#endif

void
lnet_ni_recv(lnet_ni_t *ni, void *private, lnet_msg_t *msg, int delayed,
             unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        unsigned int  niov = 0;
        struct iovec *iov = NULL;
        lnet_kiov_t  *kiov = NULL;
        int           rc;

        LASSERT (!in_interrupt ());
        LASSERT (mlen == 0 || msg != NULL);

        if (msg != NULL) {
                LASSERT(msg->msg_receiving);
                LASSERT(!msg->msg_sending);
                LASSERT(rlen == msg->msg_len);
                LASSERT(mlen <= msg->msg_len);

                msg->msg_wanted = mlen;
                msg->msg_offset = offset;
                msg->msg_receiving = 0;

                if (mlen != 0) {
                        niov = msg->msg_niov;
                        iov  = msg->msg_iov;
                        kiov = msg->msg_kiov;

                        LASSERT (niov > 0);
                        LASSERT ((iov == NULL) != (kiov == NULL));
                }
        }

        rc = (ni->ni_lnd->lnd_recv)(ni, private, msg, delayed,
                                    niov, iov, kiov, offset, mlen, rlen);
        if (rc < 0)
                lnet_finalize(ni, msg, rc);
}

int
lnet_compare_routes(lnet_route_t *r1, lnet_route_t *r2)
{
        lnet_peer_t *p1 = r1->lr_gateway;
        lnet_peer_t *p2 = r2->lr_gateway;

        if (r1->lr_hops < r2->lr_hops)
                return 1;

        if (r1->lr_hops > r2->lr_hops)
                return -1;

        if (p1->lp_txqnob < p2->lp_txqnob)
                return 1;

        if (p1->lp_txqnob > p2->lp_txqnob)
                return -1;

        if (p1->lp_txcredits > p2->lp_txcredits)
                return 1;

        if (p1->lp_txcredits < p2->lp_txcredits)
                return -1;

        return 0;
}


void
lnet_setpayloadbuffer(lnet_msg_t *msg)
{
        lnet_libmd_t *md = msg->msg_md;

        LASSERT (msg->msg_len > 0);
        LASSERT (!msg->msg_routing);
        LASSERT (md != NULL);
        LASSERT (msg->msg_niov == 0);
        LASSERT (msg->msg_iov == NULL);
        LASSERT (msg->msg_kiov == NULL);

        msg->msg_niov = md->md_niov;
        if ((md->md_options & LNET_MD_KIOV) != 0)
                msg->msg_kiov = md->md_iov.kiov;
        else
                msg->msg_iov = md->md_iov.iov;
}

void
lnet_prep_send(lnet_msg_t *msg, int type, lnet_process_id_t target,
               unsigned int offset, unsigned int len) 
{
        msg->msg_type = type;
        msg->msg_target = target;
        msg->msg_len = len;
        msg->msg_offset = offset;

        if (len != 0)
                lnet_setpayloadbuffer(msg);

        memset (&msg->msg_hdr, 0, sizeof (msg->msg_hdr));
        msg->msg_hdr.type           = cpu_to_le32(type);
        msg->msg_hdr.dest_nid       = cpu_to_le64(target.nid);
        msg->msg_hdr.dest_pid       = cpu_to_le32(target.pid);
        /* src_nid will be set later */
        msg->msg_hdr.src_pid        = cpu_to_le32(the_lnet.ln_pid);
        msg->msg_hdr.payload_length = cpu_to_le32(len);
}

void
lnet_ni_send(lnet_ni_t *ni, lnet_msg_t *msg)
{
        void   *priv = msg->msg_private;
        int     rc;

        LASSERT (!in_interrupt ());
        LASSERT (LNET_NETTYP(LNET_NIDNET(ni->ni_nid)) == LOLND ||
                 (msg->msg_txcredit && msg->msg_peertxcredit));

        rc = (ni->ni_lnd->lnd_send)(ni, priv, msg);
        if (rc < 0)
                lnet_finalize(ni, msg, rc);
}

int
lnet_eager_recv_locked(lnet_msg_t *msg)
{
        lnet_peer_t *peer;
        lnet_ni_t   *ni;
        int          rc = 0;

        LASSERT (!msg->msg_delayed);
        msg->msg_delayed = 1;

        LASSERT (msg->msg_receiving);
        LASSERT (!msg->msg_sending);

        peer = msg->msg_rxpeer;
        ni   = peer->lp_ni;

        if (ni->ni_lnd->lnd_eager_recv != NULL) {
                LNET_UNLOCK();

                rc = (ni->ni_lnd->lnd_eager_recv)(ni, msg->msg_private, msg,
                                                  &msg->msg_private);
                if (rc != 0) {
                        CERROR("recv from %s / send to %s aborted: "
                               "eager_recv failed %d\n",
                               libcfs_nid2str(peer->lp_nid),
                               libcfs_id2str(msg->msg_target), rc);
                        LASSERT (rc < 0); /* required by my callers */
                }

                LNET_LOCK();
        }

        return rc;
}

/* NB: caller shall hold a ref on 'lp' as I'd drop LNET_LOCK */
void
lnet_ni_peer_alive(lnet_peer_t *lp)
{
        cfs_time_t  last_alive = 0;
        lnet_ni_t  *ni = lp->lp_ni;

        LASSERT (lnet_peer_aliveness_enabled(lp));
        LASSERT (ni->ni_lnd->lnd_query != NULL);
        LASSERT (the_lnet.ln_routing == 1);

        LNET_UNLOCK();
        (ni->ni_lnd->lnd_query)(ni, lp->lp_nid, &last_alive);
        LNET_LOCK();

        lp->lp_last_query = cfs_time_current();

        if (last_alive != 0) /* NI has updated timestamp */
                lp->lp_last_alive = last_alive;
}

/* NB: always called with LNET_LOCK held */
static inline int
lnet_peer_is_alive (lnet_peer_t *lp, cfs_time_t now)
{
        int        alive;
        cfs_time_t deadline;

        LASSERT (lnet_peer_aliveness_enabled(lp));
        LASSERT (the_lnet.ln_routing == 1);

        /* Trust lnet_notify() if it has more recent aliveness news, but
         * ignore the initial assumed death (see lnet_peers_start_down()).
         */
        if (!lp->lp_alive && lp->lp_alive_count > 0 &&
            cfs_time_aftereq(lp->lp_timestamp, lp->lp_last_alive))
                return 0;

        deadline = cfs_time_add(lp->lp_last_alive,
                                cfs_time_seconds(lp->lp_ni->ni_peertimeout));
        alive = cfs_time_after(deadline, now);

        /* Update obsolete lp_alive except for routers assumed to be dead
         * initially, because router checker would update aliveness in this
         * case, and moreover lp_last_alive at peer creation is assumed.
         */
        if (alive && !lp->lp_alive &&
            !(lnet_isrouter(lp) && lp->lp_alive_count == 0))
                lnet_notify_locked(lp, 0, 1, lp->lp_last_alive);

        return alive;
}


/* NB: returns 1 when alive, 0 when dead, negative when error;
 *     may drop the LNET_LOCK */
int
lnet_peer_alive_locked (lnet_peer_t *lp)
{
        cfs_time_t now = cfs_time_current();

        /* LU-630: only router checks peer health. */
        if (the_lnet.ln_routing == 0)
                return 1;

        if (!lnet_peer_aliveness_enabled(lp))
                return -ENODEV;

        if (lnet_peer_is_alive(lp, now))
                return 1;

        /* Peer appears dead, but we should avoid frequent NI queries (at
         * most once per lnet_queryinterval seconds). */
        if (lp->lp_last_query != 0) {
                static const int lnet_queryinterval = 1;

                cfs_time_t next_query =
                           cfs_time_add(lp->lp_last_query,
                                        cfs_time_seconds(lnet_queryinterval));

                if (cfs_time_before(now, next_query)) {
                        if (lp->lp_alive)
                                CWARN("Unexpected aliveness of peer %s: "
                                      "%d < %d (%d/%d)\n",
                                      libcfs_nid2str(lp->lp_nid),
                                      (int)now, (int)next_query,
                                      lnet_queryinterval,
                                      lp->lp_ni->ni_peertimeout);
                        return 0;
                }
        }

        /* query NI for latest aliveness news */
        lnet_ni_peer_alive(lp);

        if (lnet_peer_is_alive(lp, now))
                return 1;

        lnet_notify_locked(lp, 0, 0, lp->lp_last_alive);
        return 0;
}

int
lnet_post_send_locked (lnet_msg_t *msg, int do_send)
{
        /* lnet_send is going to LNET_UNLOCK immediately after this, so it sets
         * do_send FALSE and I don't do the unlock/send/lock bit.  I return
         * EAGAIN if msg blocked, EHOSTUNREACH if msg_txpeer appears dead, and
         * 0 if sent or OK to send */
        lnet_peer_t *lp = msg->msg_txpeer;
        lnet_ni_t   *ni = lp->lp_ni;

        /* non-lnet_send() callers have checked before */
        LASSERT (!do_send || msg->msg_delayed);
        LASSERT (!msg->msg_receiving);

        /* NB 'lp' is always the next hop */
        if ((msg->msg_target.pid & LNET_PID_USERFLAG) == 0 &&
            lnet_peer_alive_locked(lp) == 0) {
                LNET_UNLOCK();

                CNETERR("Dropping message for %s: peer not alive\n",
                        libcfs_id2str(msg->msg_target));
                if (do_send)
                        lnet_finalize(ni, msg, -EHOSTUNREACH);

                LNET_LOCK();
                return EHOSTUNREACH;
        }

        if (!msg->msg_peertxcredit) {
                LASSERT ((lp->lp_txcredits < 0) == !list_empty(&lp->lp_txq));

                msg->msg_peertxcredit = 1;
                lp->lp_txqnob += msg->msg_len + sizeof(lnet_hdr_t);
                lp->lp_txcredits--;

                if (lp->lp_txcredits < lp->lp_mintxcredits)
                        lp->lp_mintxcredits = lp->lp_txcredits;

                if (lp->lp_txcredits < 0) {
                        msg->msg_delayed = 1;
                        list_add_tail (&msg->msg_list, &lp->lp_txq);
                        return EAGAIN;
                }
        }

        if (!msg->msg_txcredit) {
                LASSERT ((ni->ni_txcredits < 0) == !list_empty(&ni->ni_txq));

                msg->msg_txcredit = 1;
                ni->ni_txcredits--;

                if (ni->ni_txcredits < ni->ni_mintxcredits)
                        ni->ni_mintxcredits = ni->ni_txcredits;

                if (ni->ni_txcredits < 0) {
                        msg->msg_delayed = 1;
                        list_add_tail (&msg->msg_list, &ni->ni_txq);
                        return EAGAIN;
                }
        }

        if (do_send) {
                LNET_UNLOCK();
                lnet_ni_send(ni, msg);
                LNET_LOCK();
        }
        return 0;
}

#ifdef __KERNEL__
static void
lnet_commit_routedmsg (lnet_msg_t *msg)
{
        /* ALWAYS called holding the LNET_LOCK */
        LASSERT (msg->msg_routing);

        the_lnet.ln_counters.msgs_alloc++;
        if (the_lnet.ln_counters.msgs_alloc >
            the_lnet.ln_counters.msgs_max)
                the_lnet.ln_counters.msgs_max =
                        the_lnet.ln_counters.msgs_alloc;

        the_lnet.ln_counters.route_count++;
        the_lnet.ln_counters.route_length += msg->msg_len;

        LASSERT (!msg->msg_onactivelist);
        msg->msg_onactivelist = 1;
        list_add (&msg->msg_activelist, &the_lnet.ln_active_msgs);
}

lnet_rtrbufpool_t *
lnet_msg2bufpool(lnet_msg_t *msg)
{
        lnet_rtrbufpool_t *rbp = &the_lnet.ln_rtrpools[0];

        LASSERT (msg->msg_len <= LNET_MTU);
        while (msg->msg_len > rbp->rbp_npages * CFS_PAGE_SIZE) {
                rbp++;
                LASSERT (rbp < &the_lnet.ln_rtrpools[LNET_NRBPOOLS]);
        }

        return rbp;
}

int
lnet_post_routed_recv_locked (lnet_msg_t *msg, int do_recv)
{
        /* lnet_parse is going to LNET_UNLOCK immediately after this, so it
         * sets do_recv FALSE and I don't do the unlock/send/lock bit.  I
         * return EAGAIN if msg blocked and 0 if received or OK to receive */
        lnet_peer_t         *lp = msg->msg_rxpeer;
        lnet_rtrbufpool_t   *rbp;
        lnet_rtrbuf_t       *rb;

        LASSERT (msg->msg_iov == NULL);
        LASSERT (msg->msg_kiov == NULL);
        LASSERT (msg->msg_niov == 0);
        LASSERT (msg->msg_routing);
        LASSERT (msg->msg_receiving);
        LASSERT (!msg->msg_sending);

        /* non-lnet_parse callers only send delayed messages */
        LASSERT (!do_recv || msg->msg_delayed);

        if (!msg->msg_peerrtrcredit) {
                LASSERT ((lp->lp_rtrcredits < 0) == !list_empty(&lp->lp_rtrq));

                msg->msg_peerrtrcredit = 1;
                lp->lp_rtrcredits--;
                if (lp->lp_rtrcredits < lp->lp_minrtrcredits)
                        lp->lp_minrtrcredits = lp->lp_rtrcredits;

                if (lp->lp_rtrcredits < 0) {
                        /* must have checked eager_recv before here */
                        LASSERT (msg->msg_delayed);
                        list_add_tail(&msg->msg_list, &lp->lp_rtrq);
                        return EAGAIN;
                }
        }

        rbp = lnet_msg2bufpool(msg);

        if (!msg->msg_rtrcredit) {
                LASSERT ((rbp->rbp_credits < 0) == !list_empty(&rbp->rbp_msgs));

                msg->msg_rtrcredit = 1;
                rbp->rbp_credits--;
                if (rbp->rbp_credits < rbp->rbp_mincredits)
                        rbp->rbp_mincredits = rbp->rbp_credits;

                if (rbp->rbp_credits < 0) {
                        /* must have checked eager_recv before here */
                        LASSERT (msg->msg_delayed);
                        list_add_tail(&msg->msg_list, &rbp->rbp_msgs);
                        return EAGAIN;
                }
        }

        LASSERT (!list_empty(&rbp->rbp_bufs));
        rb = list_entry(rbp->rbp_bufs.next, lnet_rtrbuf_t, rb_list);
        list_del(&rb->rb_list);

        msg->msg_niov = rbp->rbp_npages;
        msg->msg_kiov = &rb->rb_kiov[0];

        if (do_recv) {
                LNET_UNLOCK();
                lnet_ni_recv(lp->lp_ni, msg->msg_private, msg, 1,
                             0, msg->msg_len, msg->msg_len);
                LNET_LOCK();
        }
        return 0;
}
#endif

void
lnet_return_credits_locked (lnet_msg_t *msg)
{
        lnet_peer_t       *txpeer = msg->msg_txpeer;
        lnet_peer_t       *rxpeer = msg->msg_rxpeer;
        lnet_msg_t        *msg2;
        lnet_ni_t         *ni;

        if (msg->msg_txcredit) {
                /* give back NI txcredits */
                msg->msg_txcredit = 0;
                ni = txpeer->lp_ni;

                LASSERT((ni->ni_txcredits < 0) == !list_empty(&ni->ni_txq));

                ni->ni_txcredits++;
                if (ni->ni_txcredits <= 0) {
                        msg2 = list_entry(ni->ni_txq.next, lnet_msg_t, msg_list);
                        list_del(&msg2->msg_list);

                        LASSERT(msg2->msg_txpeer->lp_ni == ni);
                        LASSERT(msg2->msg_delayed);

                        (void) lnet_post_send_locked(msg2, 1);
                }
        }

        if (msg->msg_peertxcredit) {
                /* give back peer txcredits */
                msg->msg_peertxcredit = 0;

                LASSERT((txpeer->lp_txcredits < 0) == !list_empty(&txpeer->lp_txq));

                txpeer->lp_txqnob -= msg->msg_len + sizeof(lnet_hdr_t);
                LASSERT (txpeer->lp_txqnob >= 0);

                txpeer->lp_txcredits++;
                if (txpeer->lp_txcredits <= 0) {
                        msg2 = list_entry(txpeer->lp_txq.next,
                                          lnet_msg_t, msg_list);
                        list_del(&msg2->msg_list);

                        LASSERT (msg2->msg_txpeer == txpeer);
                        LASSERT (msg2->msg_delayed);

                        (void) lnet_post_send_locked(msg2, 1);
                }
        }

        if (txpeer != NULL) {
                msg->msg_txpeer = NULL;
                lnet_peer_decref_locked(txpeer);
        }

#ifdef __KERNEL__
        if (msg->msg_rtrcredit) {
                /* give back global router credits */
                lnet_rtrbuf_t     *rb;
                lnet_rtrbufpool_t *rbp;

                /* NB If a msg ever blocks for a buffer in rbp_msgs, it stays
                 * there until it gets one allocated, or aborts the wait
                 * itself */
                LASSERT (msg->msg_kiov != NULL);

                rb = list_entry(msg->msg_kiov, lnet_rtrbuf_t, rb_kiov[0]);
                rbp = rb->rb_pool;
                LASSERT (rbp == lnet_msg2bufpool(msg));

                msg->msg_kiov = NULL;
                msg->msg_rtrcredit = 0;

                LASSERT((rbp->rbp_credits < 0) == !list_empty(&rbp->rbp_msgs));
                LASSERT((rbp->rbp_credits > 0) == !list_empty(&rbp->rbp_bufs));

                list_add(&rb->rb_list, &rbp->rbp_bufs);
                rbp->rbp_credits++;
                if (rbp->rbp_credits <= 0) {
                        msg2 = list_entry(rbp->rbp_msgs.next,
                                          lnet_msg_t, msg_list);
                        list_del(&msg2->msg_list);

                        (void) lnet_post_routed_recv_locked(msg2, 1);
                }
        }

        if (msg->msg_peerrtrcredit) {
                /* give back peer router credits */
                msg->msg_peerrtrcredit = 0;

                LASSERT((rxpeer->lp_rtrcredits < 0) == !list_empty(&rxpeer->lp_rtrq));

                rxpeer->lp_rtrcredits++;
                if (rxpeer->lp_rtrcredits <= 0) {
                        msg2 = list_entry(rxpeer->lp_rtrq.next,
                                          lnet_msg_t, msg_list);
                        list_del(&msg2->msg_list);

                        (void) lnet_post_routed_recv_locked(msg2, 1);
                }
        }
#else
        LASSERT (!msg->msg_rtrcredit);
        LASSERT (!msg->msg_peerrtrcredit);
#endif
        if (rxpeer != NULL) {
                msg->msg_rxpeer = NULL;
                lnet_peer_decref_locked(rxpeer);
        }
}

int
lnet_send(lnet_nid_t src_nid, lnet_msg_t *msg)
{
        lnet_nid_t        dst_nid = msg->msg_target.nid;
        lnet_ni_t        *src_ni;
        lnet_ni_t        *local_ni;
        lnet_remotenet_t *rnet;
        lnet_route_t     *route;
        lnet_route_t     *best_route;
        struct list_head *tmp;
        lnet_peer_t      *lp;
        lnet_peer_t      *lp2;
        int               rc;

        LASSERT (msg->msg_txpeer == NULL);
        LASSERT (!msg->msg_sending);
        LASSERT (!msg->msg_target_is_router);
        LASSERT (!msg->msg_receiving);

        msg->msg_sending = 1;

        /* NB! ni != NULL == interface pre-determined (ACK/REPLY) */

        LNET_LOCK();

        if (the_lnet.ln_shutdown) {
                LNET_UNLOCK();
                return -ESHUTDOWN;
        }

        if (src_nid == LNET_NID_ANY) {
                src_ni = NULL;
        } else {
                src_ni = lnet_nid2ni_locked(src_nid);
                if (src_ni == NULL) {
                        LNET_UNLOCK();
                        LCONSOLE_WARN("Can't send to %s: src %s is not a "
                                      "local nid\n", libcfs_nid2str(dst_nid),
                                      libcfs_nid2str(src_nid));
                        return -EINVAL;
                }
                LASSERT (!msg->msg_routing);
        }

        /* Is this for someone on a local network? */
        local_ni = lnet_net2ni_locked(LNET_NIDNET(dst_nid));

        if (local_ni != NULL) {
                if (src_ni == NULL) {
                        src_ni = local_ni;
                        src_nid = src_ni->ni_nid;
                } else if (src_ni == local_ni) {
                        lnet_ni_decref_locked(local_ni);
                } else {
                        lnet_ni_decref_locked(local_ni);
                        lnet_ni_decref_locked(src_ni);
                        LNET_UNLOCK();
                        LCONSOLE_WARN("No route to %s via from %s\n",
                                      libcfs_nid2str(dst_nid),
                                      libcfs_nid2str(src_nid));
                        return -EINVAL;
                }

                LASSERT (src_nid != LNET_NID_ANY);

                if (!msg->msg_routing) {
                        src_nid = lnet_ptlcompat_srcnid(src_nid, dst_nid);
                        msg->msg_hdr.src_nid = cpu_to_le64(src_nid);
                }

                if (src_ni == the_lnet.ln_loni) {
                        /* No send credit hassles with LOLND */
                        LNET_UNLOCK();
                        lnet_ni_send(src_ni, msg);
                        lnet_ni_decref(src_ni);
                        return 0;
                }

                rc = lnet_nid2peer_locked(&lp, dst_nid);
                lnet_ni_decref_locked(src_ni);  /* lp has ref on src_ni; lose mine */
                if (rc != 0) {
                        LNET_UNLOCK();
                        LCONSOLE_WARN("Error %d finding peer %s\n", rc,
                                      libcfs_nid2str(dst_nid));
                        /* ENOMEM or shutting down */
                        return rc;
                }
                LASSERT (lp->lp_ni == src_ni);
        } else {
#ifndef __KERNEL__
                LNET_UNLOCK();

                /* NB
                 * - once application finishes computation, check here to update
                 *   router states before it waits for pending IO in LNetEQPoll
                 * - recursion breaker: router checker sends no message
                 *   to remote networks */
                if (the_lnet.ln_rc_state == LNET_RC_STATE_RUNNING)
                        lnet_router_checker();

                LNET_LOCK();
#endif
                /* sending to a remote network */
                rnet = lnet_find_net_locked(LNET_NIDNET(dst_nid));
                if (rnet == NULL) {
                        if (src_ni != NULL)
                                lnet_ni_decref_locked(src_ni);
                        LNET_UNLOCK();
                        LCONSOLE_WARN("No route to %s\n",
                                      libcfs_id2str(msg->msg_target));
                        return -EHOSTUNREACH;
                }

                /* Find the best gateway I can use */
                lp = NULL;
                best_route = NULL;
                list_for_each(tmp, &rnet->lrn_routes) {
                        route = list_entry(tmp, lnet_route_t, lr_list);
                        lp2 = route->lr_gateway;

                        if (lp2->lp_alive &&
                            lnet_router_down_ni(lp2, rnet->lrn_net) <= 0 &&
                            (src_ni == NULL || lp2->lp_ni == src_ni) &&
                            (lp == NULL ||
                             lnet_compare_routes(route, best_route) > 0)) {
                                best_route = route;
                                lp = lp2;
                        }
                }

                if (lp == NULL) {
                        if (src_ni != NULL)
                                lnet_ni_decref_locked(src_ni);
                        LNET_UNLOCK();

                        LCONSOLE_WARN("No route to %s via %s "
                                      "(all routers down)\n",
                                      libcfs_id2str(msg->msg_target),
                                      libcfs_nid2str(src_nid));
                        return -EHOSTUNREACH;
                }

                /* Place selected route at the end of the route list to ensure
                 * fairness; everything else being equal... */
                list_del(&best_route->lr_list);
                list_add_tail(&best_route->lr_list, &rnet->lrn_routes);

                if (src_ni == NULL) {
                        src_ni = lp->lp_ni;
                        src_nid = src_ni->ni_nid;
                } else {
                        LASSERT (src_ni == lp->lp_ni);
                        lnet_ni_decref_locked(src_ni);
                }

                lnet_peer_addref_locked(lp);

                LASSERT (src_nid != LNET_NID_ANY);

                if (!msg->msg_routing) {
                        /* I'm the source and now I know which NI to send on */
                        src_nid = lnet_ptlcompat_srcnid(src_nid, dst_nid);
                        msg->msg_hdr.src_nid = cpu_to_le64(src_nid);
                }

                msg->msg_target_is_router = 1;
                msg->msg_target.nid = lp->lp_nid;
                msg->msg_target.pid = LUSTRE_SRV_LNET_PID;
        }

        /* 'lp' is our best choice of peer */

        LASSERT (!msg->msg_peertxcredit);
        LASSERT (!msg->msg_txcredit);
        LASSERT (msg->msg_txpeer == NULL);

        msg->msg_txpeer = lp;                   /* msg takes my ref on lp */

        rc = lnet_post_send_locked(msg, 0);
        LNET_UNLOCK();

        if (rc == EHOSTUNREACH)
                return -EHOSTUNREACH;

        if (rc == 0)
                lnet_ni_send(src_ni, msg);

        return 0;
}

static void
lnet_commit_md (lnet_libmd_t *md, lnet_msg_t *msg)
{
        /* ALWAYS called holding the LNET_LOCK */
        /* Here, we commit the MD to a network OP by marking it busy and
         * decrementing its threshold.  Come what may, the network "owns"
         * the MD until a call to lnet_finalize() signals completion. */
        LASSERT (!msg->msg_routing);

        msg->msg_md = md;

        md->md_refcount++;
        if (md->md_threshold != LNET_MD_THRESH_INF) {
                LASSERT (md->md_threshold > 0);
                md->md_threshold--;
        }

        the_lnet.ln_counters.msgs_alloc++;
        if (the_lnet.ln_counters.msgs_alloc > 
            the_lnet.ln_counters.msgs_max)
                the_lnet.ln_counters.msgs_max = 
                        the_lnet.ln_counters.msgs_alloc;

        LASSERT (!msg->msg_onactivelist);
        msg->msg_onactivelist = 1;
        list_add (&msg->msg_activelist, &the_lnet.ln_active_msgs);
}

static void
lnet_drop_message (lnet_ni_t *ni, void *private, unsigned int nob)
{
        LNET_LOCK();
        the_lnet.ln_counters.drop_count++;
        the_lnet.ln_counters.drop_length += nob;
        LNET_UNLOCK();

        lnet_ni_recv(ni, private, NULL, 0, 0, 0, nob);
}

static void
lnet_drop_delayed_put(lnet_msg_t *msg, char *reason)
{
        LASSERT (msg->msg_md == NULL);
        LASSERT (msg->msg_delayed);
        LASSERT (msg->msg_rxpeer != NULL);
        LASSERT (msg->msg_hdr.type == LNET_MSG_PUT);

        CWARN("Dropping delayed PUT from %s portal %d match "LPU64
              " offset %d length %d: %s\n", 
              libcfs_id2str((lnet_process_id_t){
                      .nid = msg->msg_hdr.src_nid,
                      .pid = msg->msg_hdr.src_pid}),
              msg->msg_hdr.msg.put.ptl_index,
              msg->msg_hdr.msg.put.match_bits,
              msg->msg_hdr.msg.put.offset,
              msg->msg_hdr.payload_length,
              reason);

        /* NB I can't drop msg's ref on msg_rxpeer until after I've
         * called lnet_drop_message(), so I just hang onto msg as well
         * until that's done */

        lnet_drop_message(msg->msg_rxpeer->lp_ni,
                          msg->msg_private, msg->msg_len);

        LNET_LOCK();

        lnet_peer_decref_locked(msg->msg_rxpeer);
        msg->msg_rxpeer = NULL;

        lnet_msg_free(msg);

        LNET_UNLOCK();
}

int
LNetSetLazyPortal(int portal)
{
        lnet_portal_t *ptl = &the_lnet.ln_portals[portal];

        if (portal < 0 || portal >= the_lnet.ln_nportals)
                return -EINVAL;

        CDEBUG(D_NET, "Setting portal %d lazy\n", portal);

        LNET_LOCK();
        lnet_portal_setopt(ptl, LNET_PTL_LAZY);
        LNET_UNLOCK();

        return 0;
}

int
LNetClearLazyPortal(int portal)
{
        struct list_head  zombies;
        lnet_portal_t    *ptl = &the_lnet.ln_portals[portal];
        lnet_msg_t       *msg;

        if (portal < 0 || portal >= the_lnet.ln_nportals)
                return -EINVAL;

        LNET_LOCK();

        if (!lnet_portal_is_lazy(ptl)) {
                LNET_UNLOCK();
                return 0;
        }

        if (the_lnet.ln_shutdown)
                CWARN ("Active lazy portal %d on exit\n", portal);
        else
                CDEBUG (D_NET, "clearing portal %d lazy\n", portal);

        /* grab all the blocked messages atomically */
        list_add(&zombies, &ptl->ptl_msgq);
        list_del_init(&ptl->ptl_msgq);

        ptl->ptl_msgq_version++;
        lnet_portal_unsetopt(ptl, LNET_PTL_LAZY);

        LNET_UNLOCK();

        while (!list_empty(&zombies)) {
                msg = list_entry(zombies.next, lnet_msg_t, msg_list);
                list_del(&msg->msg_list);

                lnet_drop_delayed_put(msg, "Clearing lazy portal attr");
        }

        return 0;
}

static void
lnet_recv_put(lnet_libmd_t *md, lnet_msg_t *msg, int delayed,
              unsigned int offset, unsigned int mlength)
{
        lnet_hdr_t       *hdr = &msg->msg_hdr;

        LNET_LOCK();

        the_lnet.ln_counters.recv_count++;
        the_lnet.ln_counters.recv_length += mlength;

        LNET_UNLOCK();

        if (mlength != 0)
                lnet_setpayloadbuffer(msg);

        msg->msg_ev.type       = LNET_EVENT_PUT;
        msg->msg_ev.target.pid = hdr->dest_pid;
        msg->msg_ev.target.nid = hdr->dest_nid;
        msg->msg_ev.hdr_data   = hdr->msg.put.hdr_data;

        /* Must I ACK?  If so I'll grab the ack_wmd out of the header and put
         * it back into the ACK during lnet_finalize() */
        msg->msg_ack = (!lnet_is_wire_handle_none(&hdr->msg.put.ack_wmd) &&
                        (md->md_options & LNET_MD_ACK_DISABLE) == 0);

        lnet_ni_recv(msg->msg_rxpeer->lp_ni,
                     msg->msg_private,
                     msg, delayed, offset, mlength,
                     hdr->payload_length);
}

/* called with LNET_LOCK held */
void
lnet_match_blocked_msg(lnet_libmd_t *md)
{
        CFS_LIST_HEAD    (drops);
        CFS_LIST_HEAD    (matches);
        struct list_head *tmp;
        struct list_head *entry;
        lnet_msg_t       *msg;
        lnet_portal_t    *ptl;
        lnet_me_t        *me  = md->md_me;

        LASSERT (me->me_portal < the_lnet.ln_nportals);

        ptl = &the_lnet.ln_portals[me->me_portal];
        if (!lnet_portal_is_lazy(ptl)) {
                LASSERT (list_empty(&ptl->ptl_msgq));
                return;
        }

        LASSERT (md->md_refcount == 0); /* a brand new MD */

        list_for_each_safe (entry, tmp, &ptl->ptl_msgq) {
                int               rc;
                int               index;
                unsigned int      mlength;
                unsigned int      offset;
                lnet_hdr_t       *hdr;
                lnet_process_id_t src;

                msg = list_entry(entry, lnet_msg_t, msg_list);

                LASSERT (msg->msg_delayed);

                hdr   = &msg->msg_hdr;
                index = hdr->msg.put.ptl_index;

                src.nid = hdr->src_nid;
                src.pid = hdr->src_pid;

                rc = lnet_try_match_md(index, LNET_MD_OP_PUT, src,
                                       hdr->payload_length,
                                       hdr->msg.put.offset,
                                       hdr->msg.put.match_bits,
                                       md, msg, &mlength, &offset);

                if (rc == LNET_MATCHMD_NONE)
                        continue;

                /* Hurrah! This _is_ a match */
                list_del(&msg->msg_list);
                ptl->ptl_msgq_version++;

                if (rc == LNET_MATCHMD_OK) {
                        list_add_tail(&msg->msg_list, &matches);

                        CDEBUG(D_NET, "Resuming delayed PUT from %s portal %d "
                               "match "LPU64" offset %d length %d.\n",
                               libcfs_id2str(src),
                               hdr->msg.put.ptl_index,
                               hdr->msg.put.match_bits,
                               hdr->msg.put.offset,
                               hdr->payload_length);
                } else {
                        LASSERT (rc == LNET_MATCHMD_DROP);

                        list_add_tail(&msg->msg_list, &drops);
                }

                if (lnet_md_exhausted(md))
                        break;
        }

        LNET_UNLOCK();

        list_for_each_safe (entry, tmp, &drops) {
                msg = list_entry(entry, lnet_msg_t, msg_list);

                list_del(&msg->msg_list);

                lnet_drop_delayed_put(msg, "Bad match");
        }

        list_for_each_safe (entry, tmp, &matches) {
                msg = list_entry(entry, lnet_msg_t, msg_list);

                list_del(&msg->msg_list);

                /* md won't disappear under me, since each msg
                 * holds a ref on it */
                lnet_recv_put(md, msg, 1,
                              msg->msg_ev.offset,
                              msg->msg_ev.mlength);
        }

        LNET_LOCK();
}

static int
lnet_parse_put(lnet_ni_t *ni, lnet_msg_t *msg)
{
        int               rc;
        int               index;
        __u64             version;
        lnet_hdr_t       *hdr = &msg->msg_hdr;
        unsigned int      rlength = hdr->payload_length;
        unsigned int      mlength = 0;
        unsigned int      offset = 0;
        lnet_process_id_t src = {/* .nid = */ hdr->src_nid,
                                 /* .pid = */ hdr->src_pid};
        lnet_libmd_t     *md;
        lnet_portal_t    *ptl;

        /* Convert put fields to host byte order */
        hdr->msg.put.match_bits = le64_to_cpu(hdr->msg.put.match_bits);
        hdr->msg.put.ptl_index = le32_to_cpu(hdr->msg.put.ptl_index);
        hdr->msg.put.offset = le32_to_cpu(hdr->msg.put.offset);

        index = hdr->msg.put.ptl_index;

        LNET_LOCK();

 again:
        rc = lnet_match_md(index, LNET_MD_OP_PUT, src,
                           rlength, hdr->msg.put.offset,
                           hdr->msg.put.match_bits, msg,
                           &mlength, &offset, &md);
        switch (rc) {
        default:
                LBUG();

        case LNET_MATCHMD_OK:
                LNET_UNLOCK();
                lnet_recv_put(md, msg, msg->msg_delayed, offset, mlength);
                return 0;

        case LNET_MATCHMD_NONE:
                ptl = &the_lnet.ln_portals[index];
                version = ptl->ptl_ml_version;

                rc = 0;
                if (!msg->msg_delayed)
                        rc = lnet_eager_recv_locked(msg);

                if (rc == 0 &&
                    !the_lnet.ln_shutdown &&
                    lnet_portal_is_lazy(ptl)) {
                        if (version != ptl->ptl_ml_version)
                                goto again;

                        list_add_tail(&msg->msg_list, &ptl->ptl_msgq);
                        ptl->ptl_msgq_version++;
                        LNET_UNLOCK();

                        CDEBUG(D_NET, "Delaying PUT from %s portal %d match "
                               LPU64" offset %d length %d: no match \n",
                               libcfs_id2str(src), index,
                               hdr->msg.put.match_bits,
                               hdr->msg.put.offset, rlength);
                        return 0;
                }
                /* fall through */

        case LNET_MATCHMD_DROP:
                CNETERR("Dropping PUT from %s portal %d match "LPU64
                        " offset %d length %d: %d\n",
                        libcfs_id2str(src), index,
                        hdr->msg.put.match_bits,
                        hdr->msg.put.offset, rlength, rc);
                LNET_UNLOCK();

                return ENOENT;          /* +ve: OK but no match */
        }
}

static int
lnet_parse_get(lnet_ni_t *ni, lnet_msg_t *msg, int rdma_get)
{
        lnet_hdr_t        *hdr = &msg->msg_hdr;
        unsigned int       mlength = 0;
        unsigned int       offset = 0;
        lnet_process_id_t  src = {/* .nid = */ hdr->src_nid,
                                  /* .pid = */ hdr->src_pid};
        lnet_handle_wire_t reply_wmd;
        lnet_libmd_t      *md;
        int                rc;

        /* Convert get fields to host byte order */
        hdr->msg.get.match_bits = le64_to_cpu(hdr->msg.get.match_bits);
        hdr->msg.get.ptl_index = le32_to_cpu(hdr->msg.get.ptl_index);
        hdr->msg.get.sink_length = le32_to_cpu(hdr->msg.get.sink_length);
        hdr->msg.get.src_offset = le32_to_cpu(hdr->msg.get.src_offset);

        LNET_LOCK();

        rc = lnet_match_md(hdr->msg.get.ptl_index, LNET_MD_OP_GET, src,
                           hdr->msg.get.sink_length, hdr->msg.get.src_offset,
                           hdr->msg.get.match_bits, msg,
                           &mlength, &offset, &md);
        if (rc == LNET_MATCHMD_DROP) {
                CNETERR("Dropping GET from %s portal %d match "LPU64
                        " offset %d length %d\n",
                        libcfs_id2str(src),
                        hdr->msg.get.ptl_index,
                        hdr->msg.get.match_bits,
                        hdr->msg.get.src_offset,
                        hdr->msg.get.sink_length);
                LNET_UNLOCK();
                return ENOENT;                  /* +ve: OK but no match */
        }

        LASSERT (rc == LNET_MATCHMD_OK);

        the_lnet.ln_counters.send_count++;
        the_lnet.ln_counters.send_length += mlength;

        LNET_UNLOCK();

        msg->msg_ev.type = LNET_EVENT_GET;
        msg->msg_ev.target.pid = hdr->dest_pid;
        msg->msg_ev.target.nid = hdr->dest_nid;
        msg->msg_ev.hdr_data = 0;

        reply_wmd = hdr->msg.get.return_wmd;

        lnet_prep_send(msg, LNET_MSG_REPLY, src, offset, mlength);

        msg->msg_hdr.msg.reply.dst_wmd = reply_wmd;

        if (rdma_get) {
                /* The LND completes the REPLY from her recv procedure */
                lnet_ni_recv(ni, msg->msg_private, msg, 0,
                             msg->msg_offset, msg->msg_len, msg->msg_len);
                return 0;
        }

        lnet_ni_recv(ni, msg->msg_private, NULL, 0, 0, 0, 0);
        msg->msg_receiving = 0;

        rc = lnet_send(ni->ni_nid, msg);
        if (rc < 0) {
                /* didn't get as far as lnet_ni_send() */
                CERROR("%s: Unable to send REPLY for GET from %s: %d\n",
                       libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), rc);

                lnet_finalize(ni, msg, rc);
        }

        return 0;
}

static int
lnet_parse_reply(lnet_ni_t *ni, lnet_msg_t *msg)
{
        void             *private = msg->msg_private;
        lnet_hdr_t       *hdr = &msg->msg_hdr;
        lnet_process_id_t src = {/* .nid = */ hdr->src_nid,
                                 /* .pid = */ hdr->src_pid};
        lnet_libmd_t     *md;
        int               rlength;
        int               mlength;

        LNET_LOCK();

        /* NB handles only looked up by creator (no flips) */
        md = lnet_wire_handle2md(&hdr->msg.reply.dst_wmd);
        if (md == NULL || md->md_threshold == 0 || md->md_me != NULL) {
                CNETERR("%s: Dropping REPLY from %s for %s "
                        "MD "LPX64"."LPX64"\n",
                        libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
                        (md == NULL) ? "invalid" : "inactive",
                        hdr->msg.reply.dst_wmd.wh_interface_cookie,
                        hdr->msg.reply.dst_wmd.wh_object_cookie);
                if (md != NULL && md->md_me != NULL)
                        CERROR("REPLY MD also attached to portal %d\n",
                               md->md_me->me_portal);

                LNET_UNLOCK();
                return ENOENT;                  /* +ve: OK but no match */
        }

        LASSERT (md->md_offset == 0);

        rlength = hdr->payload_length;
        mlength = MIN(rlength, md->md_length);

        if (mlength < rlength &&
            (md->md_options & LNET_MD_TRUNCATE) == 0) {
                CNETERR("%s: Dropping REPLY from %s length %d "
                        "for MD "LPX64" would overflow (%d)\n",
                        libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
                        rlength, hdr->msg.reply.dst_wmd.wh_object_cookie,
                        mlength);
                LNET_UNLOCK();
                return ENOENT;          /* +ve: OK but no match */
        }

        CDEBUG(D_NET, "%s: Reply from %s of length %d/%d into md "LPX64"\n",
               libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), 
               mlength, rlength, hdr->msg.reply.dst_wmd.wh_object_cookie);

        lnet_commit_md(md, msg);

        if (mlength != 0)
                lnet_setpayloadbuffer(msg);

        msg->msg_ev.type = LNET_EVENT_REPLY;
        msg->msg_ev.target.pid = hdr->dest_pid;
        msg->msg_ev.target.nid = hdr->dest_nid;
        msg->msg_ev.initiator = src;
        msg->msg_ev.rlength = rlength;
        msg->msg_ev.mlength = mlength;
        msg->msg_ev.offset = 0;

        lnet_md_deconstruct(md, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, md);

        the_lnet.ln_counters.recv_count++;
        the_lnet.ln_counters.recv_length += mlength;

        LNET_UNLOCK();

        lnet_ni_recv(ni, private, msg, 0, 0, mlength, rlength);
        return 0;
}

static int
lnet_parse_ack(lnet_ni_t *ni, lnet_msg_t *msg)
{
        lnet_hdr_t       *hdr = &msg->msg_hdr;
        lnet_process_id_t src = {/* .nid = */ hdr->src_nid,
                                 /* .pid = */ hdr->src_pid};
        lnet_libmd_t    *md;

        /* Convert ack fields to host byte order */
        hdr->msg.ack.match_bits = le64_to_cpu(hdr->msg.ack.match_bits);
        hdr->msg.ack.mlength = le32_to_cpu(hdr->msg.ack.mlength);

        LNET_LOCK();

        /* NB handles only looked up by creator (no flips) */
        md = lnet_wire_handle2md(&hdr->msg.ack.dst_wmd);
        if (md == NULL || md->md_threshold == 0 || md->md_me != NULL) {
                /* Don't moan; this is expected */
                CDEBUG(D_NET,
                       "%s: Dropping ACK from %s to %s MD "LPX64"."LPX64"\n",
                       libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
                       (md == NULL) ? "invalid" : "inactive",
                       hdr->msg.ack.dst_wmd.wh_interface_cookie,
                       hdr->msg.ack.dst_wmd.wh_object_cookie);
                if (md != NULL && md->md_me != NULL)
                        CERROR("Source MD also attached to portal %d\n",
                               md->md_me->me_portal);

                LNET_UNLOCK();
                return ENOENT;                  /* +ve! */
        }

        CDEBUG(D_NET, "%s: ACK from %s into md "LPX64"\n",
               libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), 
               hdr->msg.ack.dst_wmd.wh_object_cookie);

        lnet_commit_md(md, msg);

        msg->msg_ev.type = LNET_EVENT_ACK;
        msg->msg_ev.target.pid = hdr->dest_pid;
        msg->msg_ev.target.nid = hdr->dest_nid;
        msg->msg_ev.initiator = src;
        msg->msg_ev.mlength = hdr->msg.ack.mlength;
        msg->msg_ev.match_bits = hdr->msg.ack.match_bits;

        lnet_md_deconstruct(md, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, md);

        the_lnet.ln_counters.recv_count++;

        LNET_UNLOCK();

        lnet_ni_recv(ni, msg->msg_private, msg, 0, 0, 0, msg->msg_len);
        return 0;
}

char *
lnet_msgtyp2str (int type)
{
        switch (type) {
        case LNET_MSG_ACK:
                return ("ACK");
        case LNET_MSG_PUT:
                return ("PUT");
        case LNET_MSG_GET:
                return ("GET");
        case LNET_MSG_REPLY:
                return ("REPLY");
        case LNET_MSG_HELLO:
                return ("HELLO");
        default:
                return ("<UNKNOWN>");
        }
}

void
lnet_print_hdr(lnet_hdr_t * hdr)
{
        lnet_process_id_t src = {/* .nid = */ hdr->src_nid,
                                 /* .pid = */ hdr->src_pid};
        lnet_process_id_t dst = {/* .nid = */ hdr->dest_nid,
                                 /* .pid = */ hdr->dest_pid};
        char *type_str = lnet_msgtyp2str (hdr->type);

        CWARN("P3 Header at %p of type %s\n", hdr, type_str);
        CWARN("    From %s\n", libcfs_id2str(src));
        CWARN("    To   %s\n", libcfs_id2str(dst));

        switch (hdr->type) {
        default:
                break;

        case LNET_MSG_PUT:
                CWARN("    Ptl index %d, ack md "LPX64"."LPX64", "
                      "match bits "LPU64"\n",
                      hdr->msg.put.ptl_index,
                      hdr->msg.put.ack_wmd.wh_interface_cookie,
                      hdr->msg.put.ack_wmd.wh_object_cookie,
                      hdr->msg.put.match_bits);
                CWARN("    Length %d, offset %d, hdr data "LPX64"\n",
                      hdr->payload_length, hdr->msg.put.offset,
                      hdr->msg.put.hdr_data);
                break;

        case LNET_MSG_GET:
                CWARN("    Ptl index %d, return md "LPX64"."LPX64", "
                      "match bits "LPU64"\n", hdr->msg.get.ptl_index,
                      hdr->msg.get.return_wmd.wh_interface_cookie,
                      hdr->msg.get.return_wmd.wh_object_cookie,
                      hdr->msg.get.match_bits);
                CWARN("    Length %d, src offset %d\n",
                      hdr->msg.get.sink_length,
                      hdr->msg.get.src_offset);
                break;

        case LNET_MSG_ACK:
                CWARN("    dst md "LPX64"."LPX64", "
                      "manipulated length %d\n",
                      hdr->msg.ack.dst_wmd.wh_interface_cookie,
                      hdr->msg.ack.dst_wmd.wh_object_cookie,
                      hdr->msg.ack.mlength);
                break;

        case LNET_MSG_REPLY:
                CWARN("    dst md "LPX64"."LPX64", "
                      "length %d\n",
                      hdr->msg.reply.dst_wmd.wh_interface_cookie,
                      hdr->msg.reply.dst_wmd.wh_object_cookie,
                      hdr->payload_length);
        }

}

int
lnet_parse(lnet_ni_t *ni, lnet_hdr_t *hdr, lnet_nid_t from_nid, 
           void *private, int rdma_req)
{
        int            rc = 0;
        int            for_me;
        lnet_msg_t    *msg;
        lnet_pid_t     dest_pid;
        lnet_nid_t     dest_nid;
        lnet_nid_t     src_nid;
        __u32          payload_length;
        __u32          type;

        LASSERT (!in_interrupt ());

        type = le32_to_cpu(hdr->type);
        src_nid = le64_to_cpu(hdr->src_nid);
        dest_nid = le64_to_cpu(hdr->dest_nid);
        dest_pid = le32_to_cpu(hdr->dest_pid);
        payload_length = le32_to_cpu(hdr->payload_length);

        for_me = lnet_ptlcompat_matchnid(ni->ni_nid, dest_nid);

        switch (type) {
        case LNET_MSG_ACK:
        case LNET_MSG_GET:
                if (payload_length > 0) {
                        CERROR("%s, src %s: bad %s payload %d (0 expected)\n",
                               libcfs_nid2str(from_nid),
                               libcfs_nid2str(src_nid),
                               lnet_msgtyp2str(type), payload_length);
                        return -EPROTO;
                }
                break;

        case LNET_MSG_PUT:
        case LNET_MSG_REPLY:
                if (payload_length > (for_me ? LNET_MAX_PAYLOAD : LNET_MTU)) {
                        CERROR("%s, src %s: bad %s payload %d "
                               "(%d max expected)\n",
                               libcfs_nid2str(from_nid),
                               libcfs_nid2str(src_nid),
                               lnet_msgtyp2str(type),
                               payload_length,
                               for_me ? LNET_MAX_PAYLOAD : LNET_MTU);
                        return -EPROTO;
                }
                break;

        default:
                CERROR("%s, src %s: Bad message type 0x%x\n",
                       libcfs_nid2str(from_nid),
                       libcfs_nid2str(src_nid), type);
                return -EPROTO;
        }

        if (the_lnet.ln_routing) {
                cfs_time_t now = cfs_time_current();

                LNET_LOCK();

                ni->ni_last_alive = now;
                if (ni->ni_status != NULL &&
                    ni->ni_status->ns_status == LNET_NI_STATUS_DOWN)
                        ni->ni_status->ns_status = LNET_NI_STATUS_UP;

                LNET_UNLOCK();
        }

        /* Regard a bad destination NID as a protocol error.  Senders should
         * know what they're doing; if they don't they're misconfigured, buggy
         * or malicious so we chop them off at the knees :) */

        if (!for_me) {
                if (the_lnet.ln_ptlcompat > 0) {
                        /* portals compatibility is single-network */
                        CERROR ("%s, src %s: Bad dest nid %s "
                                "(routing not supported)\n",
                                libcfs_nid2str(from_nid),
                                libcfs_nid2str(src_nid),
                                libcfs_nid2str(dest_nid));
                        return -EPROTO;
                }

                if (the_lnet.ln_ptlcompat == 0 &&
                    LNET_NIDNET(dest_nid) == LNET_NIDNET(ni->ni_nid)) {
                        /* should have gone direct */
                        CERROR ("%s, src %s: Bad dest nid %s "
                                "(should have been sent direct)\n",
                                libcfs_nid2str(from_nid),
                                libcfs_nid2str(src_nid),
                                libcfs_nid2str(dest_nid));
                        return -EPROTO;
                }

                if (the_lnet.ln_ptlcompat == 0 &&
                    lnet_islocalnid(dest_nid)) {
                        /* dest is another local NI; sender should have used
                         * this node's NID on its own network */
                        CERROR ("%s, src %s: Bad dest nid %s "
                                "(it's my nid but on a different network)\n",
                                libcfs_nid2str(from_nid),
                                libcfs_nid2str(src_nid),
                                libcfs_nid2str(dest_nid));
                        return -EPROTO;
                }

                if (rdma_req && type == LNET_MSG_GET) {
                        CERROR ("%s, src %s: Bad optimized GET for %s "
                                "(final destination must be me)\n",
                                libcfs_nid2str(from_nid),
                                libcfs_nid2str(src_nid),
                                libcfs_nid2str(dest_nid));
                        return -EPROTO;
                }

                if (!the_lnet.ln_routing) {
                        CERROR ("%s, src %s: Dropping message for %s "
                                "(routing not enabled)\n",
                                libcfs_nid2str(from_nid),
                                libcfs_nid2str(src_nid),
                                libcfs_nid2str(dest_nid));
                        goto drop;
                }
        }

        /* Message looks OK; we're not going to return an error, so we MUST
         * call back lnd_recv() come what may... */

        if (!list_empty (&the_lnet.ln_test_peers) && /* normally we don't */
            fail_peer (src_nid, 0))             /* shall we now? */
        {
                CERROR("%s, src %s: Dropping %s to simulate failure\n",
                       libcfs_nid2str(from_nid), libcfs_nid2str(src_nid),
                       lnet_msgtyp2str(type));
                goto drop;
        }

        msg = lnet_msg_alloc();
        if (msg == NULL) {
                CERROR("%s, src %s: Dropping %s (out of memory)\n",
                       libcfs_nid2str(from_nid), libcfs_nid2str(src_nid), 
                       lnet_msgtyp2str(type));
                goto drop;
        }

        /* msg zeroed in lnet_msg_alloc; i.e. flags all clear, pointers NULL etc */

        msg->msg_type = type;
        msg->msg_private = private;
        msg->msg_receiving = 1;
        msg->msg_len = msg->msg_wanted = payload_length;
        msg->msg_offset = 0;
        msg->msg_hdr = *hdr;

        LNET_LOCK();
        rc = lnet_nid2peer_locked(&msg->msg_rxpeer, from_nid);
        if (rc != 0) {
                LNET_UNLOCK();
                CERROR("%s, src %s: Dropping %s "
                       "(error %d looking up sender)\n",
                       libcfs_nid2str(from_nid), libcfs_nid2str(src_nid),
                       lnet_msgtyp2str(type), rc);
                goto free_drop;
        }
        LNET_UNLOCK();

#ifndef __KERNEL__
        LASSERT (for_me);
#else
        if (!for_me) {
                msg->msg_target.pid = dest_pid;
                msg->msg_target.nid = dest_nid;
                msg->msg_routing = 1;
                msg->msg_offset = 0;

                LNET_LOCK();
                if (msg->msg_rxpeer->lp_rtrcredits <= 0 ||
                    lnet_msg2bufpool(msg)->rbp_credits <= 0) {
                        rc = lnet_eager_recv_locked(msg);
                        if (rc != 0) {
                                LNET_UNLOCK();
                                goto free_drop;
                        }
                }
                lnet_commit_routedmsg(msg);
                rc = lnet_post_routed_recv_locked(msg, 0);
                LNET_UNLOCK();

                if (rc == 0)
                        lnet_ni_recv(ni, msg->msg_private, msg, 0,
                                     0, payload_length, payload_length);
                return 0;
        }
#endif
        /* convert common msg->hdr fields to host byteorder */
        msg->msg_hdr.type = type;
        msg->msg_hdr.src_nid = src_nid;
        msg->msg_hdr.src_pid = le32_to_cpu(msg->msg_hdr.src_pid);
        msg->msg_hdr.dest_nid = dest_nid;
        msg->msg_hdr.dest_pid = dest_pid;
        msg->msg_hdr.payload_length = payload_length;

        msg->msg_ev.sender = from_nid;

        switch (type) {
        case LNET_MSG_ACK:
                rc = lnet_parse_ack(ni, msg);
                break;
        case LNET_MSG_PUT:
                rc = lnet_parse_put(ni, msg);
                break;
        case LNET_MSG_GET:
                rc = lnet_parse_get(ni, msg, rdma_req);
                break;
        case LNET_MSG_REPLY:
                rc = lnet_parse_reply(ni, msg);
                break;
        default:
                LASSERT(0);
                goto free_drop;  /* prevent an unused label if !kernel */
        }

        if (rc == 0)
                return 0;

        LASSERT (rc == ENOENT);

 free_drop:
        LASSERT (msg->msg_md == NULL);
        LNET_LOCK();
        if (msg->msg_rxpeer != NULL) {
                lnet_peer_decref_locked(msg->msg_rxpeer);
                msg->msg_rxpeer = NULL;
        }
        lnet_msg_free(msg);                     /* expects LNET_LOCK held */
        LNET_UNLOCK();

 drop:
        lnet_drop_message(ni, private, payload_length);
        return 0;
}

int
LNetPut(lnet_nid_t self, lnet_handle_md_t mdh, lnet_ack_req_t ack,
        lnet_process_id_t target, unsigned int portal,
        __u64 match_bits, unsigned int offset,
        __u64 hdr_data)
{
        lnet_msg_t       *msg;
        lnet_libmd_t     *md;
        int               rc;

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);

        if (!list_empty (&the_lnet.ln_test_peers) && /* normally we don't */
            fail_peer (target.nid, 1))          /* shall we now? */
        {
                CERROR("Dropping PUT to %s: simulated failure\n",
                       libcfs_id2str(target));
                return -EIO;
        }

        msg = lnet_msg_alloc();
        if (msg == NULL) {
                CERROR("Dropping PUT to %s: ENOMEM on lnet_msg_t\n",
                       libcfs_id2str(target));
                return -ENOMEM;
        }
        msg->msg_vmflush = !!libcfs_memory_pressure_get();

        LNET_LOCK();

        md = lnet_handle2md(&mdh);
        if (md == NULL || md->md_threshold == 0 || md->md_me != NULL) {
                lnet_msg_free(msg);

                CERROR("Dropping PUT ("LPU64":%d:%s): MD (%d) invalid\n",
                       match_bits, portal, libcfs_id2str(target),
                       md == NULL ? -1 : md->md_threshold);
                if (md != NULL && md->md_me != NULL)
                        CERROR("Source MD also attached to portal %d\n",
                               md->md_me->me_portal);

                LNET_UNLOCK();
                return -ENOENT;
        }

        CDEBUG(D_NET, "LNetPut -> %s\n", libcfs_id2str(target));

        lnet_commit_md(md, msg);

        lnet_prep_send(msg, LNET_MSG_PUT, target, 0, md->md_length);

        msg->msg_hdr.msg.put.match_bits = cpu_to_le64(match_bits);
        msg->msg_hdr.msg.put.ptl_index = cpu_to_le32(portal);
        msg->msg_hdr.msg.put.offset = cpu_to_le32(offset);
        msg->msg_hdr.msg.put.hdr_data = hdr_data;

        /* NB handles only looked up by creator (no flips) */
        if (ack == LNET_ACK_REQ) {
                msg->msg_hdr.msg.put.ack_wmd.wh_interface_cookie = 
                        the_lnet.ln_interface_cookie;
                msg->msg_hdr.msg.put.ack_wmd.wh_object_cookie = 
                        md->md_lh.lh_cookie;
        } else {
                msg->msg_hdr.msg.put.ack_wmd = LNET_WIRE_HANDLE_NONE;
        }

        msg->msg_ev.type = LNET_EVENT_SEND;
        msg->msg_ev.initiator.nid = LNET_NID_ANY;
        msg->msg_ev.initiator.pid = the_lnet.ln_pid;
        msg->msg_ev.target = target;
        msg->msg_ev.sender = LNET_NID_ANY;
        msg->msg_ev.pt_index = portal;
        msg->msg_ev.match_bits = match_bits;
        msg->msg_ev.rlength = md->md_length;
        msg->msg_ev.mlength = md->md_length;
        msg->msg_ev.offset = offset;
        msg->msg_ev.hdr_data = hdr_data;

        lnet_md_deconstruct(md, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, md);

        the_lnet.ln_counters.send_count++;
        the_lnet.ln_counters.send_length += md->md_length;

        LNET_UNLOCK();

        rc = lnet_send(self, msg);
        if (rc != 0) {
                CNETERR("Error sending PUT to %s: %d\n",
                       libcfs_id2str(target), rc);
                lnet_finalize (NULL, msg, rc);
        }

        /* completion will be signalled by an event */
        return 0;
}

lnet_msg_t *
lnet_create_reply_msg (lnet_ni_t *ni, lnet_msg_t *getmsg)
{
        /* The LND can DMA direct to the GET md (i.e. no REPLY msg).  This
         * returns a msg for the LND to pass to lnet_finalize() when the sink
         * data has been received.
         *
         * CAVEAT EMPTOR: 'getmsg' is the original GET, which is freed when
         * lnet_finalize() is called on it, so the LND must call this first */

        lnet_msg_t        *msg = lnet_msg_alloc();
        lnet_libmd_t      *getmd = getmsg->msg_md;
        lnet_process_id_t  peer_id = getmsg->msg_target;

        LASSERT (!getmsg->msg_target_is_router);
        LASSERT (!getmsg->msg_routing);

        LNET_LOCK();

        LASSERT (getmd->md_refcount > 0);

        if (msg == NULL) {
                CERROR ("%s: Dropping REPLY from %s: can't allocate msg\n",
                        libcfs_nid2str(ni->ni_nid), libcfs_id2str(peer_id));
                goto drop;
        }

        if (getmd->md_threshold == 0) {
                CERROR ("%s: Dropping REPLY from %s for inactive MD %p\n",
                        libcfs_nid2str(ni->ni_nid), libcfs_id2str(peer_id), 
                        getmd);
                goto drop_msg;
        }

        LASSERT (getmd->md_offset == 0);

        CDEBUG(D_NET, "%s: Reply from %s md %p\n", 
               libcfs_nid2str(ni->ni_nid), libcfs_id2str(peer_id), getmd);

        lnet_commit_md (getmd, msg);

        msg->msg_type = LNET_MSG_GET; /* flag this msg as an "optimized" GET */

        msg->msg_ev.type = LNET_EVENT_REPLY;
        msg->msg_ev.initiator = peer_id;
        msg->msg_ev.sender = peer_id.nid;  /* optimized GETs can't be routed */
        msg->msg_ev.rlength = msg->msg_ev.mlength = getmd->md_length;
        msg->msg_ev.offset = 0;

        lnet_md_deconstruct(getmd, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, getmd);

        the_lnet.ln_counters.recv_count++;
        the_lnet.ln_counters.recv_length += getmd->md_length;

        LNET_UNLOCK();

        return msg;

 drop_msg:
        lnet_msg_free(msg);
 drop:
        the_lnet.ln_counters.drop_count++;
        the_lnet.ln_counters.drop_length += getmd->md_length;

        LNET_UNLOCK ();

        return NULL;
}

void
lnet_set_reply_msg_len(lnet_ni_t *ni, lnet_msg_t *reply, unsigned int len)
{
        /* Set the REPLY length, now the RDMA that elides the REPLY message has
         * completed and I know it. */
        LASSERT (reply != NULL);
        LASSERT (reply->msg_type == LNET_MSG_GET);
        LASSERT (reply->msg_ev.type == LNET_EVENT_REPLY);

        /* NB I trusted my peer to RDMA.  If she tells me she's written beyond
         * the end of my buffer, I might as well be dead. */
        LASSERT (len <= reply->msg_ev.mlength);

        reply->msg_ev.mlength = len;
}

int
LNetGet(lnet_nid_t self, lnet_handle_md_t mdh, 
        lnet_process_id_t target, unsigned int portal, 
        __u64 match_bits, unsigned int offset)
{
        lnet_msg_t       *msg;
        lnet_libmd_t     *md;
        int               rc;

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);

        if (!list_empty (&the_lnet.ln_test_peers) && /* normally we don't */
            fail_peer (target.nid, 1))          /* shall we now? */
        {
                CERROR("Dropping GET to %s: simulated failure\n",
                       libcfs_id2str(target));
                return -EIO;
        }

        msg = lnet_msg_alloc();
        if (msg == NULL) {
                CERROR("Dropping GET to %s: ENOMEM on lnet_msg_t\n",
                       libcfs_id2str(target));
                return -ENOMEM;
        }

        LNET_LOCK();

        md = lnet_handle2md(&mdh);
        if (md == NULL || md->md_threshold == 0 || md->md_me != NULL) {
                lnet_msg_free(msg);

                CERROR("Dropping GET ("LPU64":%d:%s): MD (%d) invalid\n",
                       match_bits, portal, libcfs_id2str(target),
                       md == NULL ? -1 : md->md_threshold);
                if (md != NULL && md->md_me != NULL)
                        CERROR("REPLY MD also attached to portal %d\n",
                               md->md_me->me_portal);

                LNET_UNLOCK();
                return -ENOENT;
        }

        CDEBUG(D_NET, "LNetGet -> %s\n", libcfs_id2str(target));

        lnet_commit_md(md, msg);

        lnet_prep_send(msg, LNET_MSG_GET, target, 0, 0);

        msg->msg_hdr.msg.get.match_bits = cpu_to_le64(match_bits);
        msg->msg_hdr.msg.get.ptl_index = cpu_to_le32(portal);
        msg->msg_hdr.msg.get.src_offset = cpu_to_le32(offset);
        msg->msg_hdr.msg.get.sink_length = cpu_to_le32(md->md_length);

        /* NB handles only looked up by creator (no flips) */
        msg->msg_hdr.msg.get.return_wmd.wh_interface_cookie = 
                the_lnet.ln_interface_cookie;
        msg->msg_hdr.msg.get.return_wmd.wh_object_cookie = 
                md->md_lh.lh_cookie;

        msg->msg_ev.type = LNET_EVENT_SEND;
        msg->msg_ev.initiator.nid = LNET_NID_ANY;
        msg->msg_ev.initiator.pid = the_lnet.ln_pid;
        msg->msg_ev.target = target;
        msg->msg_ev.sender = LNET_NID_ANY;
        msg->msg_ev.pt_index = portal;
        msg->msg_ev.match_bits = match_bits;
        msg->msg_ev.rlength = md->md_length;
        msg->msg_ev.mlength = md->md_length;
        msg->msg_ev.offset = offset;
        msg->msg_ev.hdr_data = 0;

        lnet_md_deconstruct(md, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, md);

        the_lnet.ln_counters.send_count++;

        LNET_UNLOCK();

        rc = lnet_send(self, msg);
        if (rc < 0) {
                CNETERR( "Error sending GET to %s: %d\n",
                       libcfs_id2str(target), rc);
                lnet_finalize (NULL, msg, rc);
        }

        /* completion will be signalled by an event */
        return 0;
}

int
LNetDist (lnet_nid_t dstnid, lnet_nid_t *srcnidp, __u32 *orderp)
{
        struct list_head *e;
        lnet_ni_t        *ni;
        lnet_remotenet_t *rnet;
        __u32             dstnet = LNET_NIDNET(dstnid);
        int               hops;
        __u32             order = 2;

        /* if !local_nid_dist_zero, I don't return a distance of 0 ever
         * (when lustre sees a distance of 0, it substitutes 0@lo), so I
         * keep order 0 free for 0@lo and order 1 free for a local NID
         * match */

        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);

        LNET_LOCK();

        list_for_each (e, &the_lnet.ln_nis) {
                ni = list_entry(e, lnet_ni_t, ni_list);

                if (ni->ni_nid == dstnid ||
                    (the_lnet.ln_ptlcompat > 0 &&
                     LNET_NIDNET(dstnid) == 0 &&
                     LNET_NIDADDR(dstnid) == LNET_NIDADDR(ni->ni_nid) &&
                     LNET_NETTYP(LNET_NIDNET(ni->ni_nid)) != LOLND)) {
                        if (srcnidp != NULL)
                                *srcnidp = dstnid;
                        if (orderp != NULL) {
                                if (LNET_NETTYP(LNET_NIDNET(dstnid)) == LOLND)
                                        *orderp = 0;
                                else
                                        *orderp = 1;
                        }
                        LNET_UNLOCK();

                        return local_nid_dist_zero ? 0 : 1;
                }

                if (LNET_NIDNET(ni->ni_nid) == dstnet ||
                    (the_lnet.ln_ptlcompat > 0 &&
                     dstnet == 0 &&
                     LNET_NETTYP(LNET_NIDNET(ni->ni_nid)) != LOLND)) {
                        if (srcnidp != NULL)
                                *srcnidp = ni->ni_nid;
                        if (orderp != NULL)
                                *orderp = order;
                        LNET_UNLOCK();
                        return 1;
                }

                order++;
        }

        list_for_each (e, &the_lnet.ln_remote_nets) {
                rnet = list_entry(e, lnet_remotenet_t, lrn_list);

                if (rnet->lrn_net == dstnet) {
                        lnet_route_t *route;
                        lnet_route_t *shortest = NULL;

                        LASSERT (!list_empty(&rnet->lrn_routes));

                        list_for_each_entry(route, &rnet->lrn_routes, lr_list) {
                                if (shortest == NULL ||
                                    route->lr_hops < shortest->lr_hops)
                                        shortest = route;
                        }

                        LASSERT (shortest != NULL);
                        hops = shortest->lr_hops;
                        if (srcnidp != NULL)
                                *srcnidp = shortest->lr_gateway->lp_ni->ni_nid;
                        if (orderp != NULL)
                                *orderp = order;
                        LNET_UNLOCK();
                        return hops + 1;
                }
                order++;
        }

        LNET_UNLOCK();
        return -EHOSTUNREACH;
}

int
LNetSetAsync(lnet_process_id_t id, int nasync)
{
#ifdef __KERNEL__
        return 0;
#else
        lnet_ni_t        *ni;
        lnet_remotenet_t *rnet;
        struct list_head *tmp;
        lnet_route_t     *route;
        lnet_nid_t       *nids;
        int               nnids;
        int               maxnids = 256;
        int               rc = 0;
        int               rc2;

        /* Target on a local network? */ 

        ni = lnet_net2ni(LNET_NIDNET(id.nid));
        if (ni != NULL) {
                if (ni->ni_lnd->lnd_setasync != NULL) 
                        rc = (ni->ni_lnd->lnd_setasync)(ni, id, nasync);
                lnet_ni_decref(ni);
                return rc;
        }

        /* Target on a remote network: apply to routers */
 again:
        LIBCFS_ALLOC(nids, maxnids * sizeof(*nids));
        if (nids == NULL)
                return -ENOMEM;
        nnids = 0;

        /* Snapshot all the router NIDs */
        LNET_LOCK();
        rnet = lnet_find_net_locked(LNET_NIDNET(id.nid));
        if (rnet != NULL) {
                list_for_each(tmp, &rnet->lrn_routes) {
                        if (nnids == maxnids) {
                                LNET_UNLOCK();
                                LIBCFS_FREE(nids, maxnids * sizeof(*nids));
                                maxnids *= 2;
                                goto again;
                        }

                        route = list_entry(tmp, lnet_route_t, lr_list);
                        nids[nnids++] = route->lr_gateway->lp_nid;
                }
        }
        LNET_UNLOCK();

        /* set async on all the routers */
        while (nnids-- > 0) {
                id.pid = LUSTRE_SRV_LNET_PID;
                id.nid = nids[nnids];

                ni = lnet_net2ni(LNET_NIDNET(id.nid));
                if (ni == NULL)
                        continue;

                if (ni->ni_lnd->lnd_setasync != NULL) {
                        rc2 = (ni->ni_lnd->lnd_setasync)(ni, id, nasync);
                        if (rc2 != 0)
                                rc = rc2;
                }
                lnet_ni_decref(ni);
        }

        LIBCFS_FREE(nids, maxnids * sizeof(*nids));
        return rc;
#endif
}
