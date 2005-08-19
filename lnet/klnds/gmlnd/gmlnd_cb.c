/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 *
 *   This file is part of Lustre, http://www.lustre.org/
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


/*
 *	This file implements the nal cb functions
 */


#include "gmnal.h"

ptl_err_t 
gmnal_cb_recv(lib_nal_t *libnal, void *private, 
              lib_msg_t *libmsg,
              unsigned int niov, struct iovec *iov, 
              size_t offset, size_t mlen, size_t rlen)
{
	gmnal_rx_t	*rx = (gmnal_rx_t*)private;
        gmnal_msg_t     *msg = rx->rx_msg;
        size_t           nobleft = mlen;
        int              rxnob;
        char            *buffer;
        size_t           nob;

	CDEBUG(D_TRACE, "gmnal_cb_recv libnal [%p], private[%p], libmsg[%p], "
	       "niov[%d], iov [%p], offset["LPSZ"], mlen["LPSZ"], rlen["LPSZ"]\n",
	       libnal, private, libmsg, niov, iov, offset, mlen, rlen);

	LASSERT (msg->gmm_type == GMNAL_MSG_IMMEDIATE);
        
        buffer = &msg->gmm_u.immediate.gmim_payload[0];
        rxnob = offsetof(gmnal_msg_t, gmm_u.immediate.gmim_payload[nobleft]);
        
        if (rx->rx_recv_nob < rxnob) {
                CERROR("Short message from nid "LPD64": got %d, need %d\n",
                       msg->gmm_srcnid, rx->rx_recv_nob, rxnob);
                return PTL_FAIL;
        }
        
        while (nobleft > 0) {
                LASSERT (niov > 0);

                if (offset >= iov->iov_len) {
                        offset -= iov->iov_len;
                } else {
                        nob = MIN (iov->iov_len - offset, nobleft);

                        gm_bcopy(buffer, iov->iov_base + offset, nob);

                        buffer += nob;
                        nobleft -= nob;
                        offset = 0;
                }
                niov--;
                iov++;
        }

        lib_finalize(libnal, private, libmsg, PTL_OK);
	return PTL_OK;
}

ptl_err_t 
gmnal_cb_recv_pages(lib_nal_t *libnal, void *private, 
                    lib_msg_t *libmsg, 
                    unsigned int nkiov, ptl_kiov_t *kiov, 
                    size_t offset, size_t mlen, size_t rlen)
{
	gmnal_rx_t	*rx = (gmnal_rx_t*)private;
        gmnal_msg_t     *msg = rx->rx_msg;
        size_t           nobleft = mlen;
        int              rxnob;
        size_t           nob;
	char            *ptr;
	void            *buffer;

	CDEBUG(D_TRACE, "gmnal_cb_recv_pages libnal [%p],private[%p], "
	       "libmsg[%p], kniov[%d], kiov [%p], "
               "offset["LPSZ"], mlen["LPSZ"], rlen["LPSZ"]\n",
	       libnal, private, libmsg, nkiov, kiov, offset, mlen, rlen);

	LASSERT (msg->gmm_type == GMNAL_MSG_IMMEDIATE);

        buffer = &msg->gmm_u.immediate.gmim_payload[0];
        rxnob = offsetof(gmnal_msg_t, gmm_u.immediate.gmim_payload[nobleft]);

        if (rx->rx_recv_nob < rxnob) {
                CERROR("Short message from nid "LPD64": got %d, need %d\n",
                       msg->gmm_srcnid, rx->rx_recv_nob, rxnob);
                return PTL_FAIL;
        }
        
        while (nobleft > 0) {
                LASSERT (nkiov > 0);

                if (offset >= kiov->kiov_len) {
                        offset -= kiov->kiov_len;
                } else {
                        nob = MIN (kiov->kiov_len - offset, nobleft);

                        ptr = ((char *)kmap(kiov->kiov_page)) +
                              kiov->kiov_offset;

                        gm_bcopy(buffer, ptr + offset, nob);

                        kunmap(kiov->kiov_page);

                        buffer += nob;
                        nobleft -= nob;
                        offset = 0;
		}
                kiov++;
                nkiov--;
	}

        lib_finalize(libnal, private, libmsg, PTL_OK);
	return PTL_OK;
}

ptl_err_t
gmnal_cb_send(lib_nal_t *libnal, void *private, 
              lib_msg_t *libmsg, ptl_hdr_t *hdr, int type, 
              ptl_nid_t nid, ptl_pid_t pid,
              unsigned int niov, struct iovec *iov, 
              size_t offset, size_t len)
{

	gmnal_ni_t	*gmnalni = libnal->libnal_data;
        size_t           nobleft = len;
	void            *buffer;
	gmnal_tx_t      *tx;
        size_t           nob;

	CDEBUG(D_TRACE, "gmnal_cb_send niov[%d] offset["LPSZ"] "
               "len["LPSZ"] nid["LPU64"]\n", niov, offset, len, nid);

        if ((nid >> 32) != 0) {
                CERROR("Illegal nid: "LPU64"\n", nid);
                return PTL_FAIL;
        }

        tx = gmnal_get_tx(gmnalni, 1);

        gmnal_pack_msg(gmnalni, tx, nid, GMNAL_MSG_IMMEDIATE);
        gm_bcopy(hdr, &tx->tx_msg->gmm_u.immediate.gmim_hdr, sizeof(*hdr));

        buffer = &tx->tx_msg->gmm_u.immediate.gmim_payload[0];
        while (nobleft > 0) {
                LASSERT (niov > 0);
                
                if (offset >= iov->iov_len) {
                        offset -= iov->iov_len;
                } else {
                        nob = MIN (iov->iov_len - offset, nobleft);

                        gm_bcopy(iov->iov_base + offset, buffer, nob);

                        buffer += nob;
                        nobleft -= nob;
                        offset = 0;
                }
                niov--;
                iov++;
        }
        
        nob = offsetof(gmnal_msg_t, gmm_u.immediate.gmim_payload[len]);
        return gmnal_post_tx(gmnalni, tx, libmsg, nid, nob);
}

ptl_err_t
gmnal_cb_send_pages(lib_nal_t *libnal, void *private,
                    lib_msg_t *libmsg, ptl_hdr_t *hdr, int type,
                    ptl_nid_t nid, ptl_pid_t pid, 
                    unsigned int nkiov, ptl_kiov_t *kiov, 
                    size_t offset, size_t len)
{

	gmnal_ni_t	*gmnalni = libnal->libnal_data;
        size_t           nobleft = len;
	void            *buffer;
	gmnal_tx_t      *tx;
	char            *ptr;
        size_t           nob;

	CDEBUG(D_TRACE, "gmnal_cb_send_pages nid ["LPU64"] niov[%d] offset["
               LPSZ"] len["LPSZ"]\n", nid, nkiov, offset, len);

        if ((nid >> 32) != 0) {
                CERROR("Illegal nid: "LPU64"\n", nid);
                return PTL_FAIL;
        }

	tx = gmnal_get_tx(gmnalni, 1);

        gmnal_pack_msg(gmnalni, tx, nid, GMNAL_MSG_IMMEDIATE);
        gm_bcopy(hdr, &tx->tx_msg->gmm_u.immediate.gmim_hdr, sizeof(*hdr));

	buffer = &tx->tx_msg->gmm_u.immediate.gmim_payload[0];
        while (nobleft > 0) {
                LASSERT (nkiov > 0);

                if (offset >= kiov->kiov_len) {
                        offset -= kiov->kiov_len;
                } else {
                        nob = MIN (kiov->kiov_len - offset, nobleft);

                        ptr = ((char *)kmap(kiov->kiov_page)) +
                              kiov->kiov_offset;

                        gm_bcopy(ptr + offset, buffer, nob);

                        kunmap(kiov->kiov_page);

                        buffer += nob;
                        nobleft -= nob;
                        offset = 0;
                }
                nkiov--;
                kiov++;
        }

        nob = offsetof(gmnal_msg_t, gmm_u.immediate.gmim_payload[len]);
        return gmnal_post_tx(gmnalni, tx, libmsg, nid, nob);
}

int
gmnal_cb_dist(lib_nal_t *libnal, ptl_nid_t nid, unsigned long *dist)
{
	CDEBUG(D_TRACE, "gmnal_cb_dist\n");

	if (dist != NULL)
		*dist = 1;

	return PTL_OK;
}
