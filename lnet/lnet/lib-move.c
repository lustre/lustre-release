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
static void ptl_commit_md (ptl_libmd_t *md, ptl_msg_t *msg);

static ptl_libmd_t *
ptl_match_md(int index, int op_mask, lnet_process_id_t src,
             lnet_size_t rlength, lnet_size_t roffset,
             lnet_match_bits_t match_bits, ptl_msg_t *msg,
             lnet_size_t *mlength_out, lnet_size_t *offset_out)
{
        struct list_head *match_list = &lnet_apini.apini_portals[index];
        struct list_head *tmp;
        ptl_me_t         *me;
        ptl_libmd_t      *md;
        lnet_size_t       mlength;
        lnet_size_t       offset;
        ENTRY;

        CDEBUG (D_NET, "Request from %s of length %d into portal %d "
                "MB="LPX64"\n", libcfs_id2str(src), rlength, index, match_bits);

        if (index < 0 || index >= lnet_apini.apini_nportals) {
                CERROR("Invalid portal %d not in [0-%d]\n",
                       index, lnet_apini.apini_nportals);
                goto failed;
        }

        list_for_each (tmp, match_list) {
                me = list_entry(tmp, ptl_me_t, me_list);
                md = me->me_md;

                 /* ME attached but MD not attached yet */
                if (md == NULL)
                        continue;

                LASSERT (me == md->md_me);

                /* mismatched MD op */
                if ((md->md_options & op_mask) == 0)
                        continue;

                /* MD exhausted */
                if (ptl_md_exhausted(md))
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

                ptl_commit_md(md, msg);
                md->md_offset = offset + mlength;

                /* NB Caller sets ev.type and ev.hdr_data */
                msg->msg_ev.initiator = src;
                msg->msg_ev.pt_index = index;
                msg->msg_ev.match_bits = match_bits;
                msg->msg_ev.rlength = rlength;
                msg->msg_ev.mlength = mlength;
                msg->msg_ev.offset = offset;

                ptl_md_deconstruct(md, &msg->msg_ev.md);
                ptl_md2handle(&msg->msg_ev.md_handle, md);

                *offset_out = offset;
                *mlength_out = mlength;

                /* Auto-unlink NOW, so the ME gets unlinked if required.
                 * We bumped md->pending above so the MD just gets flagged
                 * for unlink when it is finalized. */
                if ((md->md_flags & PTL_MD_FLAG_AUTO_UNLINK) != 0 &&
                    ptl_md_exhausted(md))
                        ptl_md_unlink(md);

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
ptl_fail_nid (lnet_nid_t nid, unsigned int threshold)
{
        ptl_test_peer_t   *tp;
        unsigned long      flags;
        struct list_head  *el;
        struct list_head  *next;
        struct list_head   cull;

        LASSERT (lnet_apini.apini_init);
        
        if (threshold != 0) {
                /* Adding a new entry */
                PORTAL_ALLOC(tp, sizeof(*tp));
                if (tp == NULL)
                        return -ENOMEM;

                tp->tp_nid = nid;
                tp->tp_threshold = threshold;

                PTL_LOCK(flags);
                list_add_tail (&tp->tp_list, &lnet_apini.apini_test_peers);
                PTL_UNLOCK(flags);
                return 0;
        }

        /* removing entries */
        CFS_INIT_LIST_HEAD (&cull);

        PTL_LOCK(flags);

        list_for_each_safe (el, next, &lnet_apini.apini_test_peers) {
                tp = list_entry (el, ptl_test_peer_t, tp_list);

                if (tp->tp_threshold == 0 ||    /* needs culling anyway */
                    nid == LNET_NID_ANY ||       /* removing all entries */
                    tp->tp_nid == nid)          /* matched this one */
                {
                        list_del (&tp->tp_list);
                        list_add (&tp->tp_list, &cull);
                }
        }

        PTL_UNLOCK(flags);

        while (!list_empty (&cull)) {
                tp = list_entry (cull.next, ptl_test_peer_t, tp_list);

                list_del (&tp->tp_list);
                PORTAL_FREE(tp, sizeof (*tp));
        }
        return 0;
}

static int
fail_peer (lnet_nid_t nid, int outgoing)
{
        ptl_test_peer_t  *tp;
        struct list_head *el;
        struct list_head *next;
        unsigned long     flags;
        struct list_head  cull;
        int               fail = 0;

        CFS_INIT_LIST_HEAD (&cull);

        PTL_LOCK(flags);

        list_for_each_safe (el, next, &lnet_apini.apini_test_peers) {
                tp = list_entry (el, ptl_test_peer_t, tp_list);

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

        PTL_UNLOCK (flags);

        while (!list_empty (&cull)) {
                tp = list_entry (cull.next, ptl_test_peer_t, tp_list);
                list_del (&tp->tp_list);

                PORTAL_FREE(tp, sizeof (*tp));
        }

        return (fail);
}

lnet_size_t
lnet_iov_nob (int niov, struct iovec *iov)
{
        lnet_size_t nob = 0;

        while (niov-- > 0)
                nob += (iov++)->iov_len;

        return (nob);
}

void
lnet_copy_iov2buf (char *dest, int niov, struct iovec *iov,
                  lnet_size_t offset, lnet_size_t len)
{
        lnet_size_t nob;

        if (len == 0)
                return;

        /* skip complete frags before 'offset' */
        LASSERT (niov > 0);
        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT (niov > 0);
        }

        do {
                LASSERT (niov > 0);
                nob = MIN (iov->iov_len - offset, len);
                memcpy (dest, iov->iov_base + offset, nob);

                len -= nob;
                dest += nob;
                niov--;
                iov++;
                offset = 0;
        } while (len > 0);
}

void
lnet_copy_buf2iov (int niov, struct iovec *iov, lnet_size_t offset,
                  char *src, lnet_size_t len)
{
        lnet_size_t nob;

        if (len == 0)
                return;

        /* skip complete frags before 'offset' */
        LASSERT (niov > 0);
        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT (niov > 0);
        }

        do {
                LASSERT (niov > 0);
                nob = MIN (iov->iov_len - offset, len);
                memcpy (iov->iov_base + offset, src, nob);

                len -= nob;
                src += nob;
                niov--;
                iov++;
                offset = 0;
        } while (len > 0);
}

int
lnet_extract_iov (int dst_niov, struct iovec *dst,
                 int src_niov, struct iovec *src,
                 lnet_size_t offset, lnet_size_t len)
{
        /* Initialise 'dst' to the subset of 'src' starting at 'offset',
         * for exactly 'len' bytes, and return the number of entries.
         * NB not destructive to 'src' */
        lnet_size_t     frag_len;
        int             niov;

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
lnet_size_t
lnet_kiov_nob (int niov, lnet_kiov_t *kiov)
{
        LASSERT (0);
        return (0);
}

void
lnet_copy_kiov2buf (char *dest, int niov, lnet_kiov_t *kiov,
                   lnet_size_t offset, lnet_size_t len)
{
        LASSERT (0);
}

void
lnet_copy_buf2kiov (int niov, lnet_kiov_t *kiov, lnet_size_t offset,
                   char *src, lnet_size_t len)
{
        LASSERT (0);
}

int
lnet_extract_kiov (int dst_niov, lnet_kiov_t *dst,
                  int src_niov, lnet_kiov_t *src,
                  lnet_size_t offset, lnet_size_t len)
{
        LASSERT (0);
}

#else /* __KERNEL__ */

lnet_size_t
lnet_kiov_nob (int niov, lnet_kiov_t *kiov)
{
        lnet_size_t  nob = 0;

        while (niov-- > 0)
                nob += (kiov++)->kiov_len;

        return (nob);
}

void
lnet_copy_kiov2buf (char *dest, int niov, lnet_kiov_t *kiov,
                   lnet_size_t offset, lnet_size_t len)
{
        lnet_size_t  nob;
        char       *addr;

        if (len == 0)
                return;

        LASSERT (!in_interrupt ());

        LASSERT (niov > 0);
        while (offset > kiov->kiov_len) {
                offset -= kiov->kiov_len;
                kiov++;
                niov--;
                LASSERT (niov > 0);
        }

        do {
                LASSERT (niov > 0);
                nob = MIN (kiov->kiov_len - offset, len);

                addr = ((char *)cfs_kmap(kiov->kiov_page)) + kiov->kiov_offset +
                        offset;
                memcpy (dest, addr, nob);
                cfs_kunmap (kiov->kiov_page);

                len -= nob;
                dest += nob;
                niov--;
                kiov++;
                offset = 0;
        } while (len > 0);
}

void
lnet_copy_buf2kiov (int niov, lnet_kiov_t *kiov, lnet_size_t offset,
                   char *src, lnet_size_t len)
{
        lnet_size_t  nob;
        char       *addr;

        if (len == 0)
                return;

        LASSERT (!in_interrupt ());

        LASSERT (niov > 0);
        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                kiov++;
                niov--;
                LASSERT (niov > 0);
        }

        do {
                LASSERT (niov > 0);
                nob = MIN (kiov->kiov_len - offset, len);

                addr = ((char *)cfs_kmap(kiov->kiov_page)) + kiov->kiov_offset +
                        offset;
                memcpy (addr, src, nob);
                cfs_kunmap (kiov->kiov_page);

                len -= nob;
                src += nob;
                niov--;
                kiov++;
                offset = 0;
        } while (len > 0);
}

int
lnet_extract_kiov (int dst_niov, lnet_kiov_t *dst,
                  int src_niov, lnet_kiov_t *src,
                  lnet_size_t offset, lnet_size_t len)
{
        /* Initialise 'dst' to the subset of 'src' starting at 'offset',
         * for exactly 'len' bytes, and return the number of entries.
         * NB not destructive to 'src' */
        lnet_size_t     frag_len;
        int             niov;

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

int
ptl_recv (ptl_ni_t *ni, void *private, ptl_msg_t *msg, ptl_libmd_t *md,
          lnet_size_t offset, lnet_size_t mlen, lnet_size_t rlen)
{
        if (mlen == 0)
                return ((ni->ni_nal->nal_recv)(ni, private, msg,
                                               0, NULL,
                                               offset, mlen, rlen));

        if ((md->md_options & LNET_MD_KIOV) == 0)
                return ((ni->ni_nal->nal_recv)(ni, private, msg,
                                               md->md_niov, md->md_iov.iov,
                                               offset, mlen, rlen));

        return ((ni->ni_nal->nal_recv_pages)(ni, private, msg,
                                             md->md_niov, md->md_iov.kiov,
                                             offset, mlen, rlen));
}

int
ptl_send (ptl_ni_t *ni, void *private, ptl_msg_t *msg,
          ptl_hdr_t *hdr, int type, lnet_process_id_t target,
          ptl_libmd_t *md, lnet_size_t offset, lnet_size_t len)
{
        unsigned long flags;
        lnet_nid_t    gw_nid;
        int           routing = 0;
        int           rc;

        /* CAVEAT EMPTOR! ni != NULL == interface pre-determined (ACK) */

        gw_nid = lnet_lookup (&ni, target.nid, sizeof(*hdr) + len);
        if (gw_nid == LNET_NID_ANY) {
                CERROR("No route to %s\n", libcfs_id2str(target));
                LCONSOLE_ERROR("Cannot send to %s: %s is not a local network "
                               "and I can't route to it. Is lustre configured "
                               "correctly?\n", libcfs_nid2str(target.nid),
                               libcfs_net2str(PTL_NIDNET(target.nid)));
                               
                return -EIO;
        }

        /* set the completion event's initiator.nid now we know it */
        if (type == PTL_MSG_PUT || type == PTL_MSG_GET)
                msg->msg_ev.initiator.nid = ni->ni_nid;
                
        hdr->type           = cpu_to_le32(type);
        hdr->dest_nid       = cpu_to_le64(target.nid);
        hdr->dest_pid       = cpu_to_le32(target.pid);
        hdr->src_nid        = cpu_to_le64(ni->ni_nid);
        hdr->src_pid        = cpu_to_le64(lnet_apini.apini_pid);
        hdr->payload_length = cpu_to_le32(len);

        if (PTL_NETNAL(PTL_NIDNET(ni->ni_nid)) != LONAL) {
                if (gw_nid != ni->ni_nid) {         /* it's not for me */
                        routing = gw_nid != target.nid; /* will gateway have to forward? */
                } else if (implicit_loopback) {    /* force lonal? */
                        PTL_LOCK(flags);
                        ptl_ni_decref_locked(ni);
                        ni = ptl_loni;
                        if (ni != NULL)
                                ptl_ni_addref_locked(ni);
                        PTL_UNLOCK(flags);
                        
                        if (ni == NULL)         /* shutdown in progress */
                                return -ENETDOWN;
                }
        }
        
        target.nid = gw_nid;
        
        if (len == 0)
                rc = (ni->ni_nal->nal_send)(ni, private, msg, hdr, 
                                            type, target, routing,
                                            0, NULL, offset, len);
        else if ((md->md_options & LNET_MD_KIOV) == 0)
                rc = (ni->ni_nal->nal_send)(ni, private, msg, hdr, 
                                            type, target, routing,
                                            md->md_niov, md->md_iov.iov,
                                            offset, len);
        else
                rc = (ni->ni_nal->nal_send_pages)(ni, private, msg, hdr, 
                                                  type, target, routing,
                                                  md->md_niov, md->md_iov.kiov,
                                                  offset, len);

        ptl_ni_decref(ni);                      /* lose ref from lnet_lookup */
        return rc;
}

static void
ptl_commit_md (ptl_libmd_t *md, ptl_msg_t *msg)
{
        /* ALWAYS called holding the PTL_LOCK */
        /* Here, we commit the MD to a network OP by marking it busy and
         * decrementing its threshold.  Come what may, the network "owns"
         * the MD until a call to lnet_finalize() signals completion. */
        msg->msg_md = md;

        md->md_pending++;
        if (md->md_threshold != LNET_MD_THRESH_INF) {
                LASSERT (md->md_threshold > 0);
                md->md_threshold--;
        }

        lnet_apini.apini_counters.msgs_alloc++;
        if (lnet_apini.apini_counters.msgs_alloc > 
            lnet_apini.apini_counters.msgs_max)
                lnet_apini.apini_counters.msgs_max = 
                        lnet_apini.apini_counters.msgs_alloc;

        list_add (&msg->msg_list, &lnet_apini.apini_active_msgs);
}

static void
ptl_drop_message (ptl_ni_t *ni, void *private, ptl_hdr_t *hdr)
{
        unsigned long flags;

        /* CAVEAT EMPTOR: this only drops messages that we've not committed
         * to receive (init_msg() not called) and therefore can't cause an
         * event. */

        PTL_LOCK(flags);
        lnet_apini.apini_counters.drop_count++;
        lnet_apini.apini_counters.drop_length += hdr->payload_length;
        PTL_UNLOCK(flags);

        /* NULL msg => if NAL calls lnet_finalize it will be a noop */
        (void) ptl_recv(ni, private, NULL, NULL, 0, 0,
                        hdr->payload_length);
}

/*
 * Incoming messages have a ptl_msg_t object associated with them
 * by the library.  This object encapsulates the state of the
 * message and allows the NAL to do non-blocking receives or sends
 * of long messages.
 *
 */
static int
lnet_parse_put(ptl_ni_t *ni, ptl_hdr_t *hdr, void *private, ptl_msg_t *msg)
{
        lnet_size_t       mlength = 0;
        lnet_size_t       offset = 0;
        lnet_process_id_t src = {.nid = hdr->src_nid,
                                .pid = hdr->src_pid};
        int              rc;
        ptl_libmd_t     *md;
        unsigned long    flags;

        /* Convert put fields to host byte order */
        hdr->msg.put.match_bits = le64_to_cpu(hdr->msg.put.match_bits);
        hdr->msg.put.ptl_index = le32_to_cpu(hdr->msg.put.ptl_index);
        hdr->msg.put.offset = le32_to_cpu(hdr->msg.put.offset);

        PTL_LOCK(flags);

        md = ptl_match_md(hdr->msg.put.ptl_index, LNET_MD_OP_PUT, src,
                          hdr->payload_length, hdr->msg.put.offset,
                          hdr->msg.put.match_bits, msg,
                          &mlength, &offset);
        if (md == NULL) {
                PTL_UNLOCK(flags);
                return (-ENOENT);
        }

        msg->msg_ev.type = LNET_EVENT_PUT;
        msg->msg_ev.hdr_data = hdr->msg.put.hdr_data;

        if (!ptl_is_wire_handle_none(&hdr->msg.put.ack_wmd) &&
            !(md->md_options & LNET_MD_ACK_DISABLE)) {
                msg->msg_ack_wmd = hdr->msg.put.ack_wmd;
        }

        lnet_apini.apini_counters.recv_count++;
        lnet_apini.apini_counters.recv_length += mlength;

        PTL_UNLOCK(flags);

        rc = ptl_recv(ni, private, msg, md, offset, mlength,
                      hdr->payload_length);

        if (rc != 0)
                CERROR("%s: error on receiving PUT from %s: %d\n",
                       libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), rc);

        return (rc);
}

static int
lnet_parse_get(ptl_ni_t *ni, ptl_hdr_t *hdr, void *private, ptl_msg_t *msg)
{
        lnet_size_t       mlength = 0;
        lnet_size_t       offset = 0;
        lnet_process_id_t src = {.nid = hdr->src_nid,
                                .pid = hdr->src_pid};
        ptl_libmd_t     *md;
        ptl_hdr_t        reply;
        unsigned long    flags;
        int              rc;

        /* Convert get fields to host byte order */
        hdr->msg.get.match_bits = le64_to_cpu(hdr->msg.get.match_bits);
        hdr->msg.get.ptl_index = le32_to_cpu(hdr->msg.get.ptl_index);
        hdr->msg.get.sink_length = le32_to_cpu(hdr->msg.get.sink_length);
        hdr->msg.get.src_offset = le32_to_cpu(hdr->msg.get.src_offset);

        PTL_LOCK(flags);

        md = ptl_match_md(hdr->msg.get.ptl_index, LNET_MD_OP_GET, src,
                          hdr->msg.get.sink_length, hdr->msg.get.src_offset,
                          hdr->msg.get.match_bits, msg,
                          &mlength, &offset);
        if (md == NULL) {
                PTL_UNLOCK(flags);
                return (-ENOENT);
        }

        msg->msg_ev.type = LNET_EVENT_GET;
        msg->msg_ev.hdr_data = 0;

        lnet_apini.apini_counters.send_count++;
        lnet_apini.apini_counters.send_length += mlength;

        PTL_UNLOCK(flags);

        memset (&reply, 0, sizeof (reply));
        reply.msg.reply.dst_wmd = hdr->msg.get.return_wmd;

        /* NB call ptl_send() _BEFORE_ ptl_recv() completes the incoming
         * message.  Some NALs _require_ this to implement optimized GET */

        rc = ptl_send (ni, private, msg, &reply, PTL_MSG_REPLY, src,
                       md, offset, mlength);
        if (rc != 0)
                CERROR("%s: Unable to send REPLY for GET from %s: %d\n",
                       libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), rc);

        /* Discard any junk after the hdr */
        (void) ptl_recv(ni, private, NULL, NULL, 0, 0,
                        hdr->payload_length);
        return (rc);
}

static int
lnet_parse_reply(ptl_ni_t *ni, ptl_hdr_t *hdr, void *private, ptl_msg_t *msg)
{
        lnet_process_id_t src = {.nid = hdr->src_nid,
                                .pid = hdr->src_pid};
        ptl_libmd_t     *md;
        int              rlength;
        int              length;
        unsigned long    flags;
        int              rc;

        PTL_LOCK(flags);

        /* NB handles only looked up by creator (no flips) */
        md = ptl_wire_handle2md(&hdr->msg.reply.dst_wmd);
        if (md == NULL || md->md_threshold == 0) {
                CERROR ("%s: Dropping REPLY from %s for %s "
                        "MD "LPX64"."LPX64"\n", 
                        libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
                        (md == NULL) ? "invalid" : "inactive",
                        hdr->msg.reply.dst_wmd.wh_interface_cookie,
                        hdr->msg.reply.dst_wmd.wh_object_cookie);

                PTL_UNLOCK(flags);
                return (-EIO);
        }

        LASSERT (md->md_offset == 0);

        length = rlength = hdr->payload_length;

        if (length > md->md_length) {
                if ((md->md_options & LNET_MD_TRUNCATE) == 0) {
                        CERROR ("%s: Dropping REPLY from %s length %d "
                                "for MD "LPX64" would overflow (%d)\n",
                                libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
                                length, hdr->msg.reply.dst_wmd.wh_object_cookie,
                                md->md_length);
                        PTL_UNLOCK(flags);
                        return (-EIO);
                }
                length = md->md_length;
        }

        CDEBUG(D_NET, "%s: Reply from %s of length %d/%d into md "LPX64"\n",
               libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), 
               length, rlength, hdr->msg.reply.dst_wmd.wh_object_cookie);

        ptl_commit_md(md, msg);

        msg->msg_ev.type = LNET_EVENT_REPLY;
        msg->msg_ev.initiator = src;
        msg->msg_ev.rlength = rlength;
        msg->msg_ev.mlength = length;
        msg->msg_ev.offset = 0;

        ptl_md_deconstruct(md, &msg->msg_ev.md);
        ptl_md2handle(&msg->msg_ev.md_handle, md);

        lnet_apini.apini_counters.recv_count++;
        lnet_apini.apini_counters.recv_length += length;

        PTL_UNLOCK(flags);

        rc = ptl_recv(ni, private, msg, md, 0, length, rlength);
        if (rc != 0)
                CERROR("%s: error on receiving REPLY from %s: %d\n",
                       libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), rc);

        return (rc);
}

static int
lnet_parse_ack(ptl_ni_t *ni, ptl_hdr_t *hdr, void *private, ptl_msg_t *msg)
{
        lnet_process_id_t src = {.nid = hdr->src_nid,
                                .pid = hdr->src_pid};
        ptl_libmd_t     *md;
        unsigned long    flags;

        /* Convert ack fields to host byte order */
        hdr->msg.ack.match_bits = le64_to_cpu(hdr->msg.ack.match_bits);
        hdr->msg.ack.mlength = le32_to_cpu(hdr->msg.ack.mlength);

        PTL_LOCK(flags);

        /* NB handles only looked up by creator (no flips) */
        md = ptl_wire_handle2md(&hdr->msg.ack.dst_wmd);
        if (md == NULL || md->md_threshold == 0) {
                CERROR ("%s: Dropping ACK from %s to %s MD "LPX64"."LPX64"\n",
                        libcfs_nid2str(ni->ni_nid), libcfs_id2str(src),
                        (md == NULL) ? "invalid" : "inactive",
                        hdr->msg.ack.dst_wmd.wh_interface_cookie,
                        hdr->msg.ack.dst_wmd.wh_object_cookie);

                PTL_UNLOCK(flags);
                return (-EIO);
        }

        CDEBUG(D_NET, "%s: ACK from %s into md "LPX64"\n",
               libcfs_nid2str(ni->ni_nid), libcfs_id2str(src), 
               hdr->msg.ack.dst_wmd.wh_object_cookie);

        ptl_commit_md(md, msg);

        msg->msg_ev.type = LNET_EVENT_ACK;
        msg->msg_ev.initiator = src;
        msg->msg_ev.mlength = hdr->msg.ack.mlength;
        msg->msg_ev.match_bits = hdr->msg.ack.match_bits;

        ptl_md_deconstruct(md, &msg->msg_ev.md);
        ptl_md2handle(&msg->msg_ev.md_handle, md);

        lnet_apini.apini_counters.recv_count++;

        PTL_UNLOCK(flags);

        /* We have received and matched up the ack OK, create the
         * completion event now... */
        lnet_finalize(ni, private, msg, 0);

        /* ...and now discard any junk after the hdr */
        (void) ptl_recv(ni, private, NULL, NULL, 0, 0, hdr->payload_length);

       return (0);
}

static char *
hdr_type_string (ptl_hdr_t *hdr)
{
        switch (hdr->type) {
        case PTL_MSG_ACK:
                return ("ACK");
        case PTL_MSG_PUT:
                return ("PUT");
        case PTL_MSG_GET:
                return ("GET");
        case PTL_MSG_REPLY:
                return ("REPLY");
        case PTL_MSG_HELLO:
                return ("HELLO");
        default:
                return ("<UNKNOWN>");
        }
}

void
ptl_print_hdr(ptl_hdr_t * hdr)
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

        case PTL_MSG_PUT:
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

        case PTL_MSG_GET:
                CWARN("    Ptl index %d, return md "LPX64"."LPX64", "
                      "match bits "LPX64"\n", hdr->msg.get.ptl_index,
                      hdr->msg.get.return_wmd.wh_interface_cookie,
                      hdr->msg.get.return_wmd.wh_object_cookie,
                      hdr->msg.get.match_bits);
                CWARN("    Length %d, src offset %d\n",
                      hdr->msg.get.sink_length,
                      hdr->msg.get.src_offset);
                break;

        case PTL_MSG_ACK:
                CWARN("    dst md "LPX64"."LPX64", "
                      "manipulated length %d\n",
                      hdr->msg.ack.dst_wmd.wh_interface_cookie,
                      hdr->msg.ack.dst_wmd.wh_object_cookie,
                      hdr->msg.ack.mlength);
                break;

        case PTL_MSG_REPLY:
                CWARN("    dst md "LPX64"."LPX64", "
                      "length %d\n",
                      hdr->msg.reply.dst_wmd.wh_interface_cookie,
                      hdr->msg.reply.dst_wmd.wh_object_cookie,
                      hdr->payload_length);
        }

}


int
lnet_parse(ptl_ni_t *ni, ptl_hdr_t *hdr, void *private)
{
        unsigned long  flags;
        int            rc;
        ptl_msg_t     *msg;
        lnet_nid_t     dest_nid;
        __u32          type = le32_to_cpu(hdr->type);

        /* NB we return 0 if we manage to parse the header and believe
         * it looks OK.  Anything that goes wrong with receiving the
         * message after that point is the responsibility of the NAL.
         * If we don't think the packet is for us, return 1 */

        dest_nid = le64_to_cpu(hdr->dest_nid);
        if (PTL_NETNAL(PTL_NIDNET(ni->ni_nid)) != LONAL &&
            dest_nid != ni->ni_nid) {

                if (!ptl_islocalnid(dest_nid))  /* tell NAL to use the router */
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
                        return -EIO;
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
        case PTL_MSG_ACK:
        case PTL_MSG_PUT:
        case PTL_MSG_GET:
        case PTL_MSG_REPLY:
                break;

        default:
                CERROR("%s: Bad message type 0x%x from %s\n",
                       libcfs_nid2str(ni->ni_nid), hdr->type, 
                       libcfs_nid2str(hdr->src_nid));

                return -EIO;
        }

        /* We've decided we're not receiving garbage since we can parse the
         * header.  We will return 0 come what may... */

        if (!list_empty (&lnet_apini.apini_test_peers) && /* normally we don't */
            fail_peer (hdr->src_nid, 0))        /* shall we now? */
        {
                CERROR("%s: Dropping incoming %s from %s: simulated failure\n",
                       libcfs_nid2str(ni->ni_nid), hdr_type_string (hdr),
                       libcfs_nid2str(hdr->src_nid));
                ptl_drop_message(ni, private, hdr);
                return 0;
        }

        msg = ptl_msg_alloc();
        if (msg == NULL) {
                CERROR("%s: Dropping incoming %s from %s: "
                       "can't allocate a ptl_msg_t\n",
                       libcfs_nid2str(ni->ni_nid), hdr_type_string (hdr),
                       libcfs_nid2str(hdr->src_nid));
                ptl_drop_message(ni, private, hdr);
                return 0;
        }

        switch (hdr->type) {
        case PTL_MSG_ACK:
                rc = lnet_parse_ack(ni, hdr, private, msg);
                break;
        case PTL_MSG_PUT:
                rc = lnet_parse_put(ni, hdr, private, msg);
                break;
        case PTL_MSG_GET:
                rc = lnet_parse_get(ni, hdr, private, msg);
                break;
        case PTL_MSG_REPLY:
                rc = lnet_parse_reply(ni, hdr, private, msg);
                break;
        default:
                LASSERT(0);
                rc = -EIO;                  /* no compiler warning please */
                break;
        }

        if (rc != 0) {
                if (msg->msg_md != NULL) {
                        /* committed... */
                        lnet_finalize(ni, private, msg, rc);
                } else {
                        PTL_LOCK(flags);
                        ptl_msg_free(msg); /* expects PTL_LOCK held */
                        PTL_UNLOCK(flags);

                        ptl_drop_message(ni, private, hdr);
                }
        }

        return 0;
        /* That's "OK I can parse it", not "OK I like it" :) */
}

int
LNetPut(lnet_handle_md_t mdh, lnet_ack_req_t ack,
       lnet_process_id_t target, lnet_pt_index_t portal,
       lnet_ac_index_t ac, lnet_match_bits_t match_bits,
       lnet_size_t offset, lnet_hdr_data_t hdr_data)
{
        ptl_msg_t        *msg;
        ptl_hdr_t         hdr;
        ptl_libmd_t      *md;
        unsigned long     flags;
        int               rc;

        LASSERT (lnet_apini.apini_init);
        LASSERT (lnet_apini.apini_refcount > 0);
        
        if (!list_empty (&lnet_apini.apini_test_peers) && /* normally we don't */
            fail_peer (target.nid, 1))          /* shall we now? */
        {
                CERROR("Dropping PUT to %s: simulated failure\n",
                       libcfs_id2str(target));
                return -EIO;
        }

        msg = ptl_msg_alloc();
        if (msg == NULL) {
                CERROR("Dropping PUT to %s: ENOMEM on ptl_msg_t\n",
                       libcfs_id2str(target));
                return -ENOMEM;
        }

        PTL_LOCK(flags);

        md = ptl_handle2md(&mdh);
        if (md == NULL || md->md_threshold == 0) {
                ptl_msg_free(msg);
                PTL_UNLOCK(flags);

                CERROR("Dropping PUT to %s: MD invalid\n", 
                       libcfs_id2str(target));
                return -ENOENT;
        }

        CDEBUG(D_NET, "LNetPut -> %s\n", libcfs_id2str(target));

        memset (&hdr, 0, sizeof (hdr));

        /* NB handles only looked up by creator (no flips) */
        if (ack == LNET_ACK_REQ) {
                hdr.msg.put.ack_wmd.wh_interface_cookie = 
                        lnet_apini.apini_interface_cookie;
                hdr.msg.put.ack_wmd.wh_object_cookie = md->md_lh.lh_cookie;
        } else {
                hdr.msg.put.ack_wmd = PTL_WIRE_HANDLE_NONE;
        }

        hdr.msg.put.match_bits = cpu_to_le64(match_bits);
        hdr.msg.put.ptl_index = cpu_to_le32(portal);
        hdr.msg.put.offset = cpu_to_le32(offset);
        hdr.msg.put.hdr_data = hdr_data;

        ptl_commit_md(md, msg);

        msg->msg_ev.type = LNET_EVENT_SEND;
        msg->msg_ev.initiator.nid = LNET_NID_ANY;
        msg->msg_ev.initiator.pid = lnet_apini.apini_pid;
        msg->msg_ev.pt_index = portal;
        msg->msg_ev.match_bits = match_bits;
        msg->msg_ev.rlength = md->md_length;
        msg->msg_ev.mlength = md->md_length;
        msg->msg_ev.offset = offset;
        msg->msg_ev.hdr_data = hdr_data;

        ptl_md_deconstruct(md, &msg->msg_ev.md);
        ptl_md2handle(&msg->msg_ev.md_handle, md);

        lnet_apini.apini_counters.send_count++;
        lnet_apini.apini_counters.send_length += md->md_length;

        PTL_UNLOCK(flags);

        rc = ptl_send (NULL, NULL, msg, &hdr, PTL_MSG_PUT, target, 
                       md, 0, md->md_length);
        if (rc != 0) {
                CERROR("Error sending PUT to %s: %d\n",
                       libcfs_id2str(target), rc);
                lnet_finalize (NULL, NULL, msg, rc);
        }

        /* completion will be signalled by an event */
        return 0;
}

ptl_msg_t *
lnet_create_reply_msg (ptl_ni_t *ni, lnet_nid_t peer_nid, ptl_msg_t *getmsg)
{
        /* The NAL can DMA direct to the GET md (i.e. no REPLY msg).  This
         * returns a msg for the NAL to pass to lnet_finalize() when the sink
         * data has been received.
         *
         * CAVEAT EMPTOR: 'getmsg' is the original GET, which is freed when
         * lnet_finalize() is called on it, so the NAL must call this first */

        ptl_msg_t       *msg = ptl_msg_alloc();
        ptl_libmd_t     *getmd = getmsg->msg_md;
        unsigned long    flags;

        PTL_LOCK(flags);

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

        ptl_commit_md (getmd, msg);

        msg->msg_ev.type = LNET_EVENT_REPLY;
        msg->msg_ev.initiator.nid = peer_nid;
        msg->msg_ev.initiator.pid = 0;      /* XXX FIXME!!! */
        msg->msg_ev.rlength = msg->msg_ev.mlength = getmd->md_length;
        msg->msg_ev.offset = 0;

        ptl_md_deconstruct(getmd, &msg->msg_ev.md);
        ptl_md2handle(&msg->msg_ev.md_handle, getmd);

        lnet_apini.apini_counters.recv_count++;
        lnet_apini.apini_counters.recv_length += getmd->md_length;

        PTL_UNLOCK(flags);

        return msg;

 drop_msg:
        ptl_msg_free(msg);
 drop:
        lnet_apini.apini_counters.drop_count++;
        lnet_apini.apini_counters.drop_length += getmd->md_length;

        PTL_UNLOCK (flags);

        return NULL;
}

int
LNetGet(lnet_handle_md_t mdh, lnet_process_id_t target,
       lnet_pt_index_t portal, lnet_ac_index_t ac,
       lnet_match_bits_t match_bits, lnet_size_t offset)
{
        ptl_msg_t        *msg;
        ptl_hdr_t         hdr;
        ptl_libmd_t      *md;
        unsigned long     flags;
        int               rc;

        LASSERT (lnet_apini.apini_init);
        LASSERT (lnet_apini.apini_refcount > 0);
        
        if (!list_empty (&lnet_apini.apini_test_peers) && /* normally we don't */
            fail_peer (target.nid, 1))          /* shall we now? */
        {
                CERROR("Dropping GET to %s: simulated failure\n",
                       libcfs_id2str(target));
                return -EIO;
        }

        msg = ptl_msg_alloc();
        if (msg == NULL) {
                CERROR("Dropping GET to %s: ENOMEM on ptl_msg_t\n",
                       libcfs_id2str(target));
                return -ENOMEM;
        }

        PTL_LOCK(flags);

        md = ptl_handle2md(&mdh);
        if (md == NULL || md->md_threshold == 0) {
                ptl_msg_free(msg);
                PTL_UNLOCK(flags);

                CERROR("Dropping GET to %s: MD invalid\n",
                       libcfs_id2str(target));
                return -ENOENT;
        }

        CDEBUG(D_NET, "LNetGet -> %s\n", libcfs_id2str(target));

        memset (&hdr, 0, sizeof (hdr));

        /* NB handles only looked up by creator (no flips) */
        hdr.msg.get.return_wmd.wh_interface_cookie = 
                lnet_apini.apini_interface_cookie;
        hdr.msg.get.return_wmd.wh_object_cookie = md->md_lh.lh_cookie;

        hdr.msg.get.match_bits = cpu_to_le64(match_bits);
        hdr.msg.get.ptl_index = cpu_to_le32(portal);
        hdr.msg.get.src_offset = cpu_to_le32(offset);
        hdr.msg.get.sink_length = cpu_to_le32(md->md_length);

        ptl_commit_md(md, msg);

        msg->msg_ev.type = LNET_EVENT_SEND;
        msg->msg_ev.initiator.nid = LNET_NID_ANY;
        msg->msg_ev.initiator.pid = lnet_apini.apini_pid;
        msg->msg_ev.pt_index = portal;
        msg->msg_ev.match_bits = match_bits;
        msg->msg_ev.rlength = md->md_length;
        msg->msg_ev.mlength = md->md_length;
        msg->msg_ev.offset = offset;
        msg->msg_ev.hdr_data = 0;

        ptl_md_deconstruct(md, &msg->msg_ev.md);
        ptl_md2handle(&msg->msg_ev.md_handle, md);

        lnet_apini.apini_counters.send_count++;

        PTL_UNLOCK(flags);

        rc = ptl_send (NULL, NULL, msg, &hdr, PTL_MSG_GET, target, 
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
LNetDist (lnet_handle_ni_t interface, lnet_nid_t nid)
{
        LASSERT (lnet_apini.apini_init);
        LASSERT (lnet_apini.apini_refcount > 0);
        
        return kpr_distance(nid);
}
