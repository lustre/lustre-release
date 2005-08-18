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

ptl_err_t gmnal_cb_recv(lib_nal_t *libnal, void *private, lib_msg_t *cookie,
		   unsigned int niov, struct iovec *iov, size_t offset,
		   size_t mlen, size_t rlen)
{
	gmnal_srxd_t	*srxd = (gmnal_srxd_t*)private;
        size_t           nobleft = mlen;
        void            *buffer = NULL;
        size_t           nob;

	CDEBUG(D_TRACE, "gmnal_cb_recv libnal [%p], private[%p], cookie[%p], "
	       "niov[%d], iov [%p], offset["LPSZ"], mlen["LPSZ"], rlen["LPSZ"]\n",
	       libnal, private, cookie, niov, iov, offset, mlen, rlen);

	LASSERT (srxd->rx_type == GMNAL_SMALL_MESSAGE);
        
        buffer = srxd->rx_buffer;
        buffer += sizeof(gmnal_msghdr_t);
        buffer += sizeof(ptl_hdr_t);

        while(nobleft > 0) {
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

        lib_finalize(libnal, private, cookie, PTL_OK);
	return PTL_OK;
}

ptl_err_t gmnal_cb_recv_pages(lib_nal_t *libnal, void *private,
                              lib_msg_t *cookie, unsigned int nkiov,
                              ptl_kiov_t *kiov, size_t offset, size_t mlen,
                              size_t rlen)
{
	gmnal_srxd_t	*srxd = (gmnal_srxd_t*)private;
        size_t           nobleft = mlen;
        size_t           nob;
	char            *ptr;
	void            *buffer;

	CDEBUG(D_TRACE, "gmnal_cb_recv_pages libnal [%p],private[%p], "
	       "cookie[%p], kniov[%d], kiov [%p], "
               "offset["LPSZ"], mlen["LPSZ"], rlen["LPSZ"]\n",
	       libnal, private, cookie, nkiov, kiov, offset, mlen, rlen);

	LASSERT (srxd->rx_type == GMNAL_SMALL_MESSAGE);

        buffer = srxd->rx_buffer;
        buffer += sizeof(gmnal_msghdr_t);
        buffer += sizeof(ptl_hdr_t);

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

        lib_finalize(libnal, private, cookie, PTL_OK);

	return PTL_OK;
}


ptl_err_t gmnal_cb_send(lib_nal_t *libnal, void *private, lib_msg_t *cookie,
                        ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
                        unsigned int niov, struct iovec *iov, 
                        size_t offset, size_t len)
{

	gmnal_ni_t	*gmnalni = libnal->libnal_data;
	void            *buffer = NULL;
	gmnal_stxd_t    *stxd = NULL;
        size_t           nobleft = len;
        size_t           nob;
        ptl_err_t        rc;

	CDEBUG(D_TRACE, "gmnal_cb_send niov[%d] offset["LPSZ"] "
               "len["LPSZ"] nid["LPU64"]\n", niov, offset, len, nid);

        if ((nid >> 32) != 0) {
                CERROR("Illegal nid: "LPU64"\n", nid);
                return PTL_FAIL;
        }

        stxd = gmnal_get_stxd(gmnalni, 1);
        CDEBUG(D_NET, "stxd [%p]\n", stxd);

        /* Set the offset of the data to copy into the buffer */
        buffer = stxd->tx_buffer + sizeof(gmnal_msghdr_t) + sizeof(ptl_hdr_t);

        while(nobleft > 0) {
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

        rc = gmnal_small_tx(libnal, private, cookie, hdr, type, 
                            nid, stxd,  len);
        if (rc != PTL_OK)
                gmnal_return_stxd(gmnalni, stxd);

	return rc;
}

ptl_err_t gmnal_cb_send_pages(lib_nal_t *libnal, void *private,
                              lib_msg_t *cookie, ptl_hdr_t *hdr, int type,
                              ptl_nid_t nid, ptl_pid_t pid, unsigned int nkiov,
                              ptl_kiov_t *kiov, size_t offset, size_t len)
{

	gmnal_ni_t	*gmnalni = libnal->libnal_data;
	void            *buffer = NULL;
	gmnal_stxd_t    *stxd = NULL;
        size_t           nobleft = len;
	char            *ptr;
	ptl_err_t        rc;
        size_t           nob;

	CDEBUG(D_TRACE, "gmnal_cb_send_pages nid ["LPU64"] niov[%d] offset["
               LPSZ"] len["LPSZ"]\n", nid, nkiov, offset, len);

        if ((nid >> 32) != 0) {
                CERROR("Illegal nid: "LPU64"\n", nid);
                return PTL_FAIL;
        }

	stxd = gmnal_get_stxd(gmnalni, 1);
	CDEBUG(D_NET, "stxd [%p]\n", stxd);

	/* Set the offset of the data to copy into the buffer */
	buffer = stxd->tx_buffer + sizeof(gmnal_msghdr_t) + sizeof(ptl_hdr_t);

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

        rc = gmnal_small_tx(libnal, private, cookie, hdr, type, 
                                nid, stxd, len);

        if (rc != PTL_OK)
                gmnal_return_stxd(gmnalni, stxd);
        
	return rc;
}

int gmnal_cb_dist(lib_nal_t *libnal, ptl_nid_t nid, unsigned long *dist)
{
	CDEBUG(D_TRACE, "gmnal_cb_dist\n");

	if (dist != NULL)
		*dist = 1;

	return PTL_OK;
}
