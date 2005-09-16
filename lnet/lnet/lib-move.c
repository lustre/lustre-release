/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-move.c
 * Data movement routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org
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

#define DEBUG_SUBSYSTEM S_PORTALS

#include <lnet/lib-lnet.h>

#if 1
/* Enforce the rule that the target NID must be that of the receiving NI */
const int allow_destination_aliases = 0;
#else
/* Allow NID aliasing experiments */
static int allow_destination_aliases = 0;
CFS_MODULE_PARM(allow_destination_aliases, "i", int, 0644,
                "Boolean: don't require strict destination NIDs");
#endif

static int implicit_loopback = 1;
CFS_MODULE_PARM(implicit_loopback, "i", int, 0644,
                "Boolean: substitute 0@lo when sending to any local NID");

/* forward ref */
static void lnet_commit_md (lnet_libmd_t *md, lnet_msg_t *msg);

static lnet_libmd_t *
lnet_match_md(int index, int op_mask, lnet_process_id_t src,
              unsigned int rlength, unsigned int roffset,
              __u64 match_bits, lnet_msg_t *msg,
              unsigned int *mlength_out, unsigned int *offset_out)
{
        struct list_head *match_list = &the_lnet.ln_portals[index];
        struct list_head *tmp;
        lnet_me_t        *me;
        lnet_libmd_t     *md;
        unsigned int      mlength;
        unsigned int      offset;
        ENTRY;

        CDEBUG (D_NET, "Request from %s of length %d into portal %d "
                "MB="LPX64"\n", libcfs_id2str(src), rlength, index, match_bits);

        if (index < 0 || index >= the_lnet.ln_nportals) {
                CERROR("Invalid portal %d not in [0-%d]\n",
                       index, the_lnet.ln_nportals);
                goto failed;
        }

        list_for_each (tmp, match_list) {
                me = list_entry(tmp, lnet_me_t, me_list);
                md = me->me_md;

                 /* ME attached but MD not attached yet */
                if (md == NULL)
                        continue;

                LASSERT (me == md->md_me);

                /* mismatched MD op */
                if ((md->md_options & op_mask) == 0)
                        continue;

                /* MD exhausted */
                if (lnet_md_exhausted(md))
                        continue;

                /* mismatched ME nid/pid? */
                if (me->me_match_id.nid != LNET_NID_ANY &&
                    me->me_match_id.nid != src.nid)
                        continue;

                if (me->me_match_id.pid != LNET_PID_ANY &&
                    me->me_match_id.pid != src.pid)
                        continue;

                /* mismatched ME matchbits? */
                if (((me->me_match_bits ^ match_bits) & ~me->me_ignore_bits) != 0)
                        continue;

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
                        CERROR("Matching packet %d too big: %d left, "
                               "%d allowed\n", rlength, md->md_length - offset,
                               mlength);
                        goto failed;
                }

                /* Commit to this ME/MD */
                CDEBUG(D_NET, "Incoming %s index %x from %s of "
                       "length %d/%d into md "LPX64" [%d] + %d\n",
                       (op_mask == LNET_MD_OP_PUT) ? "put" : "get",
                       index, libcfs_id2str(src), mlength, rlength,
                       md->md_lh.lh_cookie, md->md_niov, offset);

                lnet_commit_md(md, msg);
                md->md_offset = offset + mlength;

                /* NB Caller sets ev.type and ev.hdr_data */
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
                 * We bumped md->pending above so the MD just gets flagged
                 * for unlink when it is finalized. */
                if ((md->md_flags & LNET_MD_FLAG_AUTO_UNLINK) != 0 &&
                    lnet_md_exhausted(md))
                        lnet_md_unlink(md);

                RETURN (md);
        }

 failed:
        CERROR ("Dropping %s from %s portal %d match "LPX64
                " offset %d length %d: no match\n",
                (op_mask == LNET_MD_OP_GET) ? "GET" : "PUT",
                libcfs_id2str(src), index, match_bits, roffset, rlength);
        RETURN(NULL);
}

int
lnet_fail_nid (lnet_nid_t nid, unsigned int threshold)
{
        lnet_test_peer_t   *tp;
        unsigned long      flags;
        struct list_head  *el;
        struct list_head  *next;
        struct list_head   cull;

        LASSERT (the_lnet.ln_init);
        
        if (threshold != 0) {
                /* Adding a new entry */
                PORTAL_ALLOC(tp, sizeof(*tp));
                if (tp == NULL)
                        return -ENOMEM;

                tp->tp_nid = nid;
                tp->tp_threshold = threshold;

                LNET_LOCK(flags);
                list_add_tail (&tp->tp_list, &the_lnet.ln_test_peers);
                LNET_UNLOCK(flags);
                return 0;
        }

        /* removing entries */
        CFS_INIT_LIST_HEAD (&cull);

        LNET_LOCK(flags);

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

        LNET_UNLOCK(flags);

        while (!list_empty (&cull)) {
                tp = list_entry (cull.next, lnet_test_peer_t, tp_list);

                list_del (&tp->tp_list);
                PORTAL_FREE(tp, sizeof (*tp));
        }
        return 0;
}

static int
fail_peer (lnet_nid_t nid, int outgoing)
{
        lnet_test_peer_t  *tp;
        struct list_head *el;
        struct list_head *next;
        unsigned long     flags;
        struct list_head  cull;
        int               fail = 0;

        CFS_INIT_LIST_HEAD (&cull);

        LNET_LOCK(flags);

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

        LNET_UNLOCK (flags);

        while (!list_empty (&cull)) {
                tp = list_entry (cull.next, lnet_test_peer_t, tp_list);
                list_del (&tp->tp_list);

                PORTAL_FREE(tp, sizeof (*tp));
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

                memcpy (diov->iov_base + doffset,
                        siov->iov_base + soffset, this_nob);
                nob -= this_nob;

                if (diov->iov_len < doffset + this_nob) {
                        doffset += this_nob;
                } else {
                        diov++;
                        doffset = 0;
                }
                
                if (siov->iov_len < soffset + this_nob) {
                        soffset += this_nob;
                } else {
                        siov++;
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
        while (doffset > diov->kiov_len) {
                doffset -= diov->kiov_len;
                diov++;
                ndiov--;
                LASSERT (ndiov > 0);
        }

        LASSERT (nsiov > 0);
        while (soffset > siov->kiov_len) {
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
                        doffset = 0;
                }

                if (siov->kiov_len > soffset + this_nob) {
                        saddr += this_nob;
                        soffset += this_nob;
                } else {
                        cfs_kunmap(siov->kiov_page);
                        saddr = NULL;
                        siov++;
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
        while (iovoffset > iov->iov_len) {
                iovoffset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT (niov > 0);
        }

        LASSERT (nkiov > 0);
        while (kiovoffset > kiov->kiov_len) {
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

                memcpy (iov->iov_base + iovoffset, addr, this_nob);
                nob -= this_nob;

                if (iov->iov_len < iovoffset + this_nob) {
                        iovoffset += this_nob;
                } else {
                        iov++;
                        iovoffset = 0;
                }

                if (kiov->kiov_len < kiovoffset + this_nob) {
                        addr += this_nob;
                        kiovoffset += this_nob;
                } else {
                        cfs_kunmap(kiov->kiov_page);
                        addr = NULL;
                        kiov++;
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
        while (kiovoffset > kiov->kiov_len) {
                kiovoffset -= kiov->kiov_len;
                kiov++;
                nkiov--;
                LASSERT (nkiov > 0);
        }

        LASSERT (niov > 0);
        while (iovoffset > iov->iov_len) {
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

                memcpy (addr, iov->iov_base + iovoffset, this_nob);
                nob -= this_nob;

                if (kiov->kiov_len < kiovoffset + this_nob) {
                        addr += this_nob;
                        kiovoffset += this_nob;
                } else {
                        cfs_kunmap(kiov->kiov_page);
                        addr = NULL;
                        kiov++;
                        kiovoffset = 0;
                }

                if (iov->iov_len < iovoffset + this_nob) {
                        iovoffset += this_nob;
                } else {
                        iov++;
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
                        LASSERT (dst->kiov_offset + dst->kiov_len <= PAGE_SIZE);
                        return (niov);
                }

                dst->kiov_len = frag_len;
                LASSERT (dst->kiov_offset + dst->kiov_len <= PAGE_SIZE);

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
lnet_recv(lnet_ni_t *ni, void *private, lnet_msg_t *msg, int delayed,
          unsigned int offset, unsigned int mlen, unsigned int rlen)
{
        unsigned int  niov = 0;
        struct iovec *iov = NULL;
        lnet_kiov_t  *kiov = NULL;
        int           rc;

        if (mlen != 0) {
                lnet_libmd_t *md = msg->msg_md;
                
                niov = md->md_niov;
                if ((md->md_options & LNET_MD_KIOV) != 0)
                        kiov = md->md_iov.kiov;
                else
                        iov = md->md_iov.iov;
        }
        
        rc = (ni->ni_lnd->lnd_recv)(ni, private, msg, delayed,
                                    niov, iov, kiov, offset, mlen, rlen);
        if (rc != 0)
                lnet_finalize(ni, private, msg, rc);
}

int
lnet_send(lnet_ni_t *ni, void *private, lnet_msg_t *msg,
          int type, lnet_process_id_t target,
          lnet_libmd_t *md, unsigned int offset, unsigned int len)
{
        unsigned long flags;
        lnet_nid_t    gw_nid;
        lnet_nid_t    src_nid;
        int           rc;

        /* CAVEAT EMPTOR! ni != NULL == interface pre-determined (ACK) */

        gw_nid = lnet_lookup (&ni, target.nid, sizeof(lnet_hdr_t) + len);
        if (gw_nid == LNET_NID_ANY) {
                CERROR("No route to %s\n", libcfs_id2str(target));
                LCONSOLE_ERROR("Cannot send to %s: %s is not a local network "
                               "and I can't route to it. Is lustre configured "
                               "correctly?\n", libcfs_nid2str(target.nid),
                               libcfs_net2str(PTL_NIDNET(target.nid)));
                               
                return -EIO;
        }

        /* set the completion event's initiator.nid now we know it */
        if (type == LNET_MSG_PUT || type == LNET_MSG_GET)
                msg->msg_ev.initiator.nid = ni->ni_nid;

        src_nid = lnet_ptlcompat_srcnid(ni->ni_nid, target.nid);

        msg->msg_type               = type;
        msg->msg_target             = target;
        msg->msg_target_is_router   = 0;
        msg->msg_routing            = 0;
                
        msg->msg_hdr.type           = cpu_to_le32(type);
        msg->msg_hdr.dest_nid       = cpu_to_le64(target.nid);
        msg->msg_hdr.dest_pid       = cpu_to_le32(target.pid);
        msg->msg_hdr.src_nid        = cpu_to_le64(src_nid);
        msg->msg_hdr.src_pid        = cpu_to_le64(the_lnet.ln_pid);
        msg->msg_hdr.payload_length = cpu_to_le32(len);

        if (PTL_NETTYP(PTL_NIDNET(ni->ni_nid)) != LOLND) {
                if (!lnet_ptlcompat_matchnid(ni->ni_nid, gw_nid)) {
                        /* it's not for me: will the gateway have to forward? */
                        if (gw_nid != target.nid &&
                            the_lnet.ln_ptlcompat == 0) {
                                msg->msg_target_is_router = 1;
                                msg->msg_target.pid = LUSTRE_SRV_PTL_PID;
                                msg->msg_target.nid = gw_nid;
                        }
                } else if (implicit_loopback) { /* its for me: force lonal? */
                        LNET_LOCK(flags);
                        lnet_ni_decref_locked(ni);
                        ni = lnet_loni;
                        if (ni != NULL)
                                lnet_ni_addref_locked(ni);
                        LNET_UNLOCK(flags);
                        
                        if (ni == NULL)         /* shutdown in progress */
                                return -ENETDOWN;
                }
        }

        msg->msg_len = len;
        msg->msg_offset = offset;
        msg->msg_niov = 0;
        msg->msg_iov = NULL;
        msg->msg_kiov = NULL;
        
        if (len > 0) {
                msg->msg_niov = md->md_niov;

                if (((md->md_options) & LNET_MD_KIOV) != 0)
                        msg->msg_kiov = md->md_iov.kiov;
                else
                        msg->msg_iov = md->md_iov.iov;
        }
        
        rc = (ni->ni_lnd->lnd_send)(ni, private, msg);

        lnet_ni_decref(ni);                     /* lose ref from lnet_lookup */
        return rc;
}

static void
lnet_commit_md (lnet_libmd_t *md, lnet_msg_t *msg)
{
        /* ALWAYS called holding the LNET_LOCK */
        /* Here, we commit the MD to a network OP by marking it busy and
         * decrementing its threshold.  Come what may, the network "owns"
         * the MD until a call to lnet_finalize() signals completion. */
        msg->msg_md = md;

        md->md_pending++;
        if (md->md_threshold != LNET_MD_THRESH_INF) {
                LASSERT (md->md_threshold > 0);
                md->md_threshold--;
        }

        the_lnet.ln_counters.msgs_alloc++;
        if (the_lnet.ln_counters.msgs_alloc > 
            the_lnet.ln_counters.msgs_max)
                the_lnet.ln_counters.msgs_max = 
                        the_lnet.ln_counters.msgs_alloc;

        list_add (&msg->msg_activelist, &the_lnet.ln_active_msgs);
}

void
lnet_drop_message (lnet_ni_t *ni, void *private, unsigned int nob)
{
        unsigned long flags;

        LNET_LOCK(flags);
        the_lnet.ln_counters.drop_count++;
        the_lnet.ln_counters.drop_length += nob;
        LNET_UNLOCK(flags);
        
        lnet_recv(ni, private, NULL, 0, 0, 0, nob);
}

static int
lnet_parse_put(lnet_ni_t *ni, lnet_hdr_t *hdr, void *private, lnet_msg_t *msg)
{
        unsigned int      rlength = hdr->payload_length;
        unsigned int      mlength = 0;
        unsigned int      offset = 0;
        lnet_process_id_t src = {.nid = hdr->src_nid,
                                 .pid = hdr->src_pid};
        lnet_libmd_t     *md;
        unsigned long     flags;

        /* Convert put fields to host byte order */
        hdr->msg.put.match_bits = le64_to_cpu(hdr->msg.put.match_bits);
        hdr->msg.put.ptl_index = le32_to_cpu(hdr->msg.put.ptl_index);
        hdr->msg.put.offset = le32_to_cpu(hdr->msg.put.offset);

        LNET_LOCK(flags);

        md = lnet_match_md(hdr->msg.put.ptl_index, LNET_MD_OP_PUT, src,
                           rlength, hdr->msg.put.offset,
                           hdr->msg.put.match_bits, msg,
                           &mlength, &offset);
        if (md == NULL) {
                LNET_UNLOCK(flags);
                return ENOENT;                  /* +ve: OK but no match */
        }

        msg->msg_ev.type = LNET_EVENT_PUT;
        msg->msg_ev.hdr_data = hdr->msg.put.hdr_data;

        if (!lnet_is_wire_handle_none(&hdr->msg.put.ack_wmd) &&
            !(md->md_options & LNET_MD_ACK_DISABLE)) {
                msg->msg_ack_wmd = hdr->msg.put.ack_wmd;
        }

        the_lnet.ln_counters.recv_count++;
        the_lnet.ln_counters.recv_length += mlength;

        LNET_UNLOCK(flags);

        lnet_recv(ni, private, msg, 0, offset, mlength, rlength);
        return 0;
}

static int
lnet_parse_get(lnet_ni_t *ni, lnet_hdr_t *hdr, void *private, lnet_msg_t *msg)
{
        unsigned int      mlength = 0;
        unsigned int      offset = 0;
        lnet_process_id_t src = {.nid = hdr->src_nid,
                                 .pid = hdr->src_pid};
        lnet_libmd_t     *md;
        unsigned long     flags;
        int               rc;

        /* Convert get fields to host byte order */
        hdr->msg.get.match_bits = le64_to_cpu(hdr->msg.get.match_bits);
        hdr->msg.get.ptl_index = le32_to_cpu(hdr->msg.get.ptl_index);
        hdr->msg.get.sink_length = le32_to_cpu(hdr->msg.get.sink_length);
        hdr->msg.get.src_offset = le32_to_cpu(hdr->msg.get.src_offset);

        LNET_LOCK(flags);

        md = lnet_match_md(hdr->msg.get.ptl_index, LNET_MD_OP_GET, src,
                           hdr->msg.get.sink_length, hdr->msg.get.src_offset,
                           hdr->msg.get.match_bits, msg,
                           &mlength, &offset);
        if (md == NULL) {
                LNET_UNLOCK(flags);
                return ENOENT;                  /* +ve: OK but no match */
        }

        msg->msg_ev.type = LNET_EVENT_GET;
        msg->msg_ev.hdr_data = 0;

        the_lnet.ln_counters.send_count++;
        the_lnet.ln_counters.send_length += mlength;

        LNET_UNLOCK(flags);

        memset (&msg->msg_hdr, 0, sizeof (msg->msg_hdr));
        msg->msg_hdr.msg.reply.dst_wmd = hdr->msg.get.return_wmd;

        /* NB call lnet_send() _BEFORE_ lnet_recv() completes the incoming
         * message.  Some NALs _require_ this to implement optimized GET */

        rc = lnet_send(ni, private, msg, LNET_MSG_REPLY, src,
                       md, offset, mlength);
        if (rc != 0) {
                /* LND won't lnet_finalize()... */
                CERROR("%s: Unable to send REPLY for GET from %s: %d\n",
                       libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), rc);
                lnet_finalize(ni, private, msg, rc);
        }

        lnet_recv(ni, private, NULL, 0, 0, 0, 0);
        return 0;
}

static int
lnet_parse_reply(lnet_ni_t *ni, lnet_hdr_t *hdr, void *private, lnet_msg_t *msg)
{
        lnet_process_id_t src = {.nid = hdr->src_nid,
                                 .pid = hdr->src_pid};
        lnet_libmd_t     *md;
        int               rlength;
        int               mlength;
        unsigned long     flags;

        LNET_LOCK(flags);

        /* NB handles only looked up by creator (no flips) */
        md = lnet_wire_handle2md(&hdr->msg.reply.dst_wmd);
        if (md == NULL || md->md_threshold == 0) {
                CERROR ("%s: Dropping REPLY from %s for %s "
                        "MD "LPX64"."LPX64"\n", 
                        libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
                        (md == NULL) ? "invalid" : "inactive",
                        hdr->msg.reply.dst_wmd.wh_interface_cookie,
                        hdr->msg.reply.dst_wmd.wh_object_cookie);

                LNET_UNLOCK(flags);
                return ENOENT;                  /* +ve: OK but no match */
        }

        LASSERT (md->md_offset == 0);

        rlength = hdr->payload_length;
        mlength = MIN(rlength, md->md_length);

        if (mlength < rlength &&
            (md->md_options & LNET_MD_TRUNCATE) == 0) {
                CERROR ("%s: Dropping REPLY from %s length %d "
                        "for MD "LPX64" would overflow (%d)\n",
                        libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
                        rlength, hdr->msg.reply.dst_wmd.wh_object_cookie,
                        mlength);
                LNET_UNLOCK(flags);
                return ENOENT;          /* +ve: OK but no match */
        }

        CDEBUG(D_NET, "%s: Reply from %s of length %d/%d into md "LPX64"\n",
               libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), 
               mlength, rlength, hdr->msg.reply.dst_wmd.wh_object_cookie);

        lnet_commit_md(md, msg);

        msg->msg_ev.type = LNET_EVENT_REPLY;
        msg->msg_ev.initiator = src;
        msg->msg_ev.rlength = rlength;
        msg->msg_ev.mlength = mlength;
        msg->msg_ev.offset = 0;

        lnet_md_deconstruct(md, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, md);

        the_lnet.ln_counters.recv_count++;
        the_lnet.ln_counters.recv_length += mlength;

        LNET_UNLOCK(flags);

        lnet_recv(ni, private, msg, 0, 0, mlength, rlength);
        return 0;
}

static int
lnet_parse_ack(lnet_ni_t *ni, lnet_hdr_t *hdr, void *private, lnet_msg_t *msg)
{
        lnet_process_id_t src = {.nid = hdr->src_nid,
                                 .pid = hdr->src_pid};
        lnet_libmd_t    *md;
        unsigned long    flags;

        /* Convert ack fields to host byte order */
        hdr->msg.ack.match_bits = le64_to_cpu(hdr->msg.ack.match_bits);
        hdr->msg.ack.mlength = le32_to_cpu(hdr->msg.ack.mlength);

        LNET_LOCK(flags);

        /* NB handles only looked up by creator (no flips) */
        md = lnet_wire_handle2md(&hdr->msg.ack.dst_wmd);
        if (md == NULL || md->md_threshold == 0) {
#if 0
                /* Don't moan; this is expected */
                CERROR ("%s: Dropping ACK from %s to %s MD "LPX64"."LPX64"\n",
                        libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
                        (md == NULL) ? "invalid" : "inactive",
                        hdr->msg.ack.dst_wmd.wh_interface_cookie,
                        hdr->msg.ack.dst_wmd.wh_object_cookie);
#endif
                LNET_UNLOCK(flags);
                return ENOENT;                  /* +ve! */
        }

        CDEBUG(D_NET, "%s: ACK from %s into md "LPX64"\n",
               libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), 
               hdr->msg.ack.dst_wmd.wh_object_cookie);

        lnet_commit_md(md, msg);

        msg->msg_ev.type = LNET_EVENT_ACK;
        msg->msg_ev.initiator = src;
        msg->msg_ev.mlength = hdr->msg.ack.mlength;
        msg->msg_ev.match_bits = hdr->msg.ack.match_bits;

        lnet_md_deconstruct(md, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, md);

        the_lnet.ln_counters.recv_count++;

        LNET_UNLOCK(flags);

        lnet_finalize(ni, private, msg, 0);

        lnet_recv(ni, private, NULL, 0, 0, 0, 0);
        return 0;
}

static char *
hdr_type_string (lnet_hdr_t *hdr)
{
        switch (hdr->type) {
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
        lnet_process_id_t src = {.nid = hdr->src_nid,
                                 .pid = hdr->src_pid};
        lnet_process_id_t dst = {.nid = hdr->dest_nid,
                                 .pid = hdr->dest_pid};
        char *type_str = hdr_type_string (hdr);

        CWARN("P3 Header at %p of type %s\n", hdr, type_str);
        CWARN("    From %s\n", libcfs_id2str(src));
        CWARN("    To   %s\n", libcfs_id2str(dst));

        switch (hdr->type) {
        default:
                break;

        case LNET_MSG_PUT:
                CWARN("    Ptl index %d, ack md "LPX64"."LPX64", "
                      "match bits "LPX64"\n",
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
                      "match bits "LPX64"\n", hdr->msg.get.ptl_index,
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
lnet_parse(lnet_ni_t *ni, lnet_hdr_t *hdr, void *private)
{
        unsigned long  flags;
        int            rc = 0;
        int            for_me;
        lnet_msg_t    *msg;
        lnet_nid_t     dest_nid;
        __u32          type = le32_to_cpu(hdr->type);

        /* NB we return 0 if we manage to parse the header and believe
         * it looks OK.  Anything that goes wrong with receiving the
         * message after that point is the responsibility of the LND.
         * If we don't think the packet is for us, return 1 */

        dest_nid = le64_to_cpu(hdr->dest_nid);

        for_me = (PTL_NETTYP(PTL_NIDNET(ni->ni_nid)) == LOLND ||
                  lnet_ptlcompat_matchnid(ni->ni_nid, dest_nid));

        if (!for_me) {
                if (the_lnet.ln_ptlcompat > 0) {
                        CERROR ("%s: Dropping message from %s: wrong nid %s\n",
                                libcfs_nid2str(ni->ni_nid),
                                libcfs_nid2str(le64_to_cpu(hdr->src_nid)),
                                libcfs_nid2str(dest_nid));
                        return -EPROTO;
                }

                if (!lnet_islocalnid(dest_nid)) /* tell LND to use the router */
                        return 1;               /* to forward */

                /* dest_nid is one of my NIs */
                
                if (!allow_destination_aliases) {
                        /* dest is another local NI; sender should have used
                         * this node's NID on its own network */
                        CERROR ("%s: Dropping message from %s: nid %s "
                                "is a local alias\n",
                                libcfs_nid2str(ni->ni_nid),
                                libcfs_nid2str(le64_to_cpu(hdr->src_nid)),
                                libcfs_nid2str(dest_nid));
                        return -EPROTO;
                }
        }
        
        /* convert common fields to host byte order */
        hdr->type = type;
        hdr->src_nid = le64_to_cpu(hdr->src_nid);
        hdr->src_pid = le32_to_cpu(hdr->src_pid);
        hdr->dest_nid = dest_nid;
        hdr->dest_pid = le32_to_cpu(hdr->dest_pid);
        hdr->payload_length = le32_to_cpu(hdr->payload_length);

        switch (type) {
        case LNET_MSG_ACK:
        case LNET_MSG_GET:
                if (hdr->payload_length > 0) {
                        CERROR("%s: Bad %s from %s: "
                               "payload size %d sent (0 expected)\n", 
                               libcfs_nid2str(ni->ni_nid),
                               hdr_type_string(hdr),
                               libcfs_nid2str(hdr->src_nid),
                               hdr->payload_length);
                        return -EPROTO;
                }
                break;
                               
        case LNET_MSG_PUT:
        case LNET_MSG_REPLY:
                if (hdr->payload_length > PTL_MTU) {
                        CERROR("%s: Bad %s from %s: "
                               "payload size %d sent (%d max expected)\n", 
                               libcfs_nid2str(ni->ni_nid),
                               hdr_type_string(hdr),
                               libcfs_nid2str(hdr->src_nid),
                               hdr->payload_length, PTL_MTU);
                        return -EPROTO;
                }
                break;

        default:
                CERROR("%s: Bad message type 0x%x from %s\n",
                       libcfs_nid2str(ni->ni_nid), hdr->type, 
                       libcfs_nid2str(hdr->src_nid));
                return -EPROTO;
        }

        if (!list_empty (&the_lnet.ln_test_peers) && /* normally we don't */
            fail_peer (hdr->src_nid, 0))        /* shall we now? */
        {
                CERROR("%s: Dropping incoming %s from %s: simulated failure\n",
                       libcfs_nid2str(ni->ni_nid), hdr_type_string(hdr),
                       libcfs_nid2str(hdr->src_nid));
                goto drop;
        }

        msg = lnet_msg_alloc();
        if (msg == NULL) {
                CERROR("%s: Dropping incoming %s from %s: "
                       "can't allocate a lnet_msg_t\n",
                       libcfs_nid2str(ni->ni_nid), hdr_type_string(hdr),
                       libcfs_nid2str(hdr->src_nid));
                goto drop;
        }

        switch (hdr->type) {
        case LNET_MSG_ACK:
                rc = lnet_parse_ack(ni, hdr, private, msg);
                break;
        case LNET_MSG_PUT:
                rc = lnet_parse_put(ni, hdr, private, msg);
                break;
        case LNET_MSG_GET:
                rc = lnet_parse_get(ni, hdr, private, msg);
                break;
        case LNET_MSG_REPLY:
                rc = lnet_parse_reply(ni, hdr, private, msg);
                break;
        default:
                LASSERT(0);
                break;
        }

        if (rc == 0)
                return 0;
        
        LASSERT (rc == ENOENT);
        LASSERT (msg->msg_md == NULL);
        
        LNET_LOCK(flags);
        lnet_msg_free(msg);                     /* expects LNET_LOCK held */
        LNET_UNLOCK(flags);
 drop:
        lnet_drop_message(ni, private, hdr->payload_length);
        return ENOENT;
}

int
LNetPut(lnet_handle_md_t mdh, lnet_ack_req_t ack,
        lnet_process_id_t target, unsigned int portal,
        __u64 match_bits, unsigned int offset, 
        __u64 hdr_data)
{
        lnet_msg_t       *msg;
        lnet_libmd_t     *md;
        unsigned long     flags;
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

        LNET_LOCK(flags);

        md = lnet_handle2md(&mdh);
        if (md == NULL || md->md_threshold == 0) {
                lnet_msg_free(msg);
                LNET_UNLOCK(flags);

                CERROR("Dropping PUT to %s: MD invalid\n", 
                       libcfs_id2str(target));
                return -ENOENT;
        }

        CDEBUG(D_NET, "LNetPut -> %s\n", libcfs_id2str(target));

        memset (&msg->msg_hdr, 0, sizeof (msg->msg_hdr));

        /* NB handles only looked up by creator (no flips) */
        if (ack == LNET_ACK_REQ) {
                msg->msg_hdr.msg.put.ack_wmd.wh_interface_cookie = 
                        the_lnet.ln_interface_cookie;
                msg->msg_hdr.msg.put.ack_wmd.wh_object_cookie = 
                        md->md_lh.lh_cookie;
        } else {
                msg->msg_hdr.msg.put.ack_wmd = LNET_WIRE_HANDLE_NONE;
        }

        msg->msg_hdr.msg.put.match_bits = cpu_to_le64(match_bits);
        msg->msg_hdr.msg.put.ptl_index = cpu_to_le32(portal);
        msg->msg_hdr.msg.put.offset = cpu_to_le32(offset);
        msg->msg_hdr.msg.put.hdr_data = hdr_data;

        lnet_commit_md(md, msg);

        msg->msg_ev.type = LNET_EVENT_SEND;
        msg->msg_ev.initiator.nid = LNET_NID_ANY;
        msg->msg_ev.initiator.pid = the_lnet.ln_pid;
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

        LNET_UNLOCK(flags);

        rc = lnet_send(NULL, NULL, msg, LNET_MSG_PUT, target, 
                       md, 0, md->md_length);
        if (rc != 0) {
                CERROR("Error sending PUT to %s: %d\n",
                       libcfs_id2str(target), rc);
                lnet_finalize (NULL, NULL, msg, rc);
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

        lnet_msg_t      *msg = lnet_msg_alloc();
        lnet_libmd_t    *getmd = getmsg->msg_md;
        lnet_nid_t       peer_nid = getmsg->msg_target.nid;
        unsigned long    flags;

        LASSERT (!getmsg->msg_target_is_router);
        LASSERT (!getmsg->msg_routing);

        LNET_LOCK(flags);

        LASSERT (getmd->md_pending > 0);

        if (msg == NULL) {
                CERROR ("%s: Dropping REPLY from %s: can't allocate msg\n",
                        libcfs_nid2str(ni->ni_nid), libcfs_nid2str(peer_nid));
                goto drop;
        }

        if (getmd->md_threshold == 0) {
                CERROR ("%s: Dropping REPLY from %s for inactive MD %p\n",
                        libcfs_nid2str(ni->ni_nid), libcfs_nid2str(peer_nid), 
                        getmd);
                goto drop_msg;
        }

        LASSERT (getmd->md_offset == 0);

        CDEBUG(D_NET, "%s: Reply from %s md %p\n", 
               libcfs_nid2str(ni->ni_nid), libcfs_nid2str(peer_nid), getmd);

        lnet_commit_md (getmd, msg);

        msg->msg_ev.type = LNET_EVENT_REPLY;
        msg->msg_ev.initiator.nid = peer_nid;
        msg->msg_ev.initiator.pid = 0;      /* XXX FIXME!!! */
        msg->msg_ev.rlength = msg->msg_ev.mlength = getmd->md_length;
        msg->msg_ev.offset = 0;

        lnet_md_deconstruct(getmd, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, getmd);

        the_lnet.ln_counters.recv_count++;
        the_lnet.ln_counters.recv_length += getmd->md_length;

        LNET_UNLOCK(flags);

        return msg;

 drop_msg:
        lnet_msg_free(msg);
 drop:
        the_lnet.ln_counters.drop_count++;
        the_lnet.ln_counters.drop_length += getmd->md_length;

        LNET_UNLOCK (flags);

        return NULL;
}

int
LNetGet(lnet_handle_md_t mdh, 
        lnet_process_id_t target, unsigned int portal, 
        __u64 match_bits, unsigned int offset)
{
        lnet_msg_t       *msg;
        lnet_libmd_t     *md;
        unsigned long     flags;
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

        LNET_LOCK(flags);

        md = lnet_handle2md(&mdh);
        if (md == NULL || md->md_threshold == 0) {
                lnet_msg_free(msg);
                LNET_UNLOCK(flags);

                CERROR("Dropping GET to %s: MD invalid\n",
                       libcfs_id2str(target));
                return -ENOENT;
        }

        CDEBUG(D_NET, "LNetGet -> %s\n", libcfs_id2str(target));

        memset (&msg->msg_hdr, 0, sizeof (msg->msg_hdr));

        /* NB handles only looked up by creator (no flips) */
        msg->msg_hdr.msg.get.return_wmd.wh_interface_cookie = 
                the_lnet.ln_interface_cookie;
        msg->msg_hdr.msg.get.return_wmd.wh_object_cookie = 
                md->md_lh.lh_cookie;

        msg->msg_hdr.msg.get.match_bits = cpu_to_le64(match_bits);
        msg->msg_hdr.msg.get.ptl_index = cpu_to_le32(portal);
        msg->msg_hdr.msg.get.src_offset = cpu_to_le32(offset);
        msg->msg_hdr.msg.get.sink_length = cpu_to_le32(md->md_length);

        lnet_commit_md(md, msg);

        msg->msg_ev.type = LNET_EVENT_SEND;
        msg->msg_ev.initiator.nid = LNET_NID_ANY;
        msg->msg_ev.initiator.pid = the_lnet.ln_pid;
        msg->msg_ev.pt_index = portal;
        msg->msg_ev.match_bits = match_bits;
        msg->msg_ev.rlength = md->md_length;
        msg->msg_ev.mlength = md->md_length;
        msg->msg_ev.offset = offset;
        msg->msg_ev.hdr_data = 0;

        lnet_md_deconstruct(md, &msg->msg_ev.md);
        lnet_md2handle(&msg->msg_ev.md_handle, md);

        the_lnet.ln_counters.send_count++;

        LNET_UNLOCK(flags);

        rc = lnet_send(NULL, NULL, msg, LNET_MSG_GET, target, 
                       NULL, 0, 0);
        if (rc != 0) {
                CERROR("error sending GET to %s: %d\n",
                       libcfs_id2str(target), rc);
                lnet_finalize (NULL, NULL, msg, rc);
        }

        /* completion will be signalled by an event */
        return 0;
}

int
LNetDist (lnet_nid_t nid, int *order)
{
        LASSERT (the_lnet.ln_init);
        LASSERT (the_lnet.ln_refcount > 0);
        
        return kpr_distance(nid, order);
}
