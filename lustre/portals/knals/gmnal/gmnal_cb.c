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
	int		status = PTL_OK;


	CDEBUG(D_TRACE, "gmnal_cb_recv libnal [%p], private[%p], cookie[%p], "
	       "niov[%d], iov [%p], offset["LPSZ"], mlen["LPSZ"], rlen["LPSZ"]\n", 
	       libnal, private, cookie, niov, iov, offset, mlen, rlen);

	switch(srxd->type) {
	case(GMNAL_SMALL_MESSAGE):
		CDEBUG(D_INFO, "gmnal_cb_recv got small message\n");
		status = gmnal_small_rx(libnal, private, cookie, niov, 
				         iov, offset, mlen, rlen);
	break;
	case(GMNAL_LARGE_MESSAGE_INIT):
		CDEBUG(D_INFO, "gmnal_cb_recv got large message init\n");
		status = gmnal_large_rx(libnal, private, cookie, niov, 
					 iov, offset, mlen, rlen);
	}
		

	CDEBUG(D_INFO, "gmnal_cb_recv gmnal_return status [%d]\n", status);
	return(status);
}

ptl_err_t gmnal_cb_recv_pages(lib_nal_t *libnal, void *private, lib_msg_t *cookie, 
			 unsigned int kniov, ptl_kiov_t *kiov, size_t offset, 
			 size_t mlen, size_t rlen)
{
	gmnal_srxd_t	*srxd = (gmnal_srxd_t*)private;
	int		status = PTL_OK;
	struct iovec	*iovec = NULL, *iovec_dup = NULL;
	int		i = 0;
	ptl_kiov_t	*kiov_dup = kiov;;


	CDEBUG(D_TRACE, "gmnal_cb_recv_pages libnal [%p],private[%p], "
	       "cookie[%p], kniov[%d], kiov [%p], offset["LPSZ"], mlen["LPSZ"], rlen["LPSZ"]\n",
	       libnal, private, cookie, kniov, kiov, offset, mlen, rlen);

	if (srxd->type == GMNAL_SMALL_MESSAGE) {
		PORTAL_ALLOC(iovec, sizeof(struct iovec)*kniov);
		if (!iovec) {
			CDEBUG(D_ERROR, "Can't malloc\n");
			return(GMNAL_STATUS_FAIL);
		}
                iovec_dup = iovec;

		/*
		 *	map each page and create an iovec for it
		 */
		for (i=0; i<kniov; i++) {
			CDEBUG(D_INFO, "processing kniov [%d] [%p]\n", i, kiov);
			CDEBUG(D_INFO, "kniov page [%p] len [%d] offset[%d]\n",
		 	       kiov->kiov_page, kiov->kiov_len, 
			       kiov->kiov_offset);
			iovec->iov_len = kiov->kiov_len;
			CDEBUG(D_INFO, "Calling kmap[%p]", kiov->kiov_page);

			iovec->iov_base = kmap(kiov->kiov_page) + 
					          kiov->kiov_offset;

			CDEBUG(D_INFO, "iov_base is [%p]\n", iovec->iov_base);
                        iovec++;
                        kiov++;
		}
		CDEBUG(D_INFO, "calling gmnal_small_rx\n");
		status = gmnal_small_rx(libnal, private, cookie, kniov, 
				         iovec_dup, offset, mlen, rlen);
		for (i=0; i<kniov; i++) {
			kunmap(kiov_dup->kiov_page);
			kiov_dup++;
		}
		PORTAL_FREE(iovec_dup, sizeof(struct iovec)*kniov);
	}
		

	CDEBUG(D_INFO, "gmnal_return status [%d]\n", status);
	return(status);
}


ptl_err_t gmnal_cb_send(lib_nal_t *libnal, void *private, lib_msg_t *cookie, 
		   ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid, 
		   unsigned int niov, struct iovec *iov, size_t offset, size_t len)
{

	gmnal_data_t	*nal_data;


	CDEBUG(D_TRACE, "gmnal_cb_send niov[%d] offset["LPSZ"] len["LPSZ"] nid["LPU64"]\n", 
	       niov, offset, len, nid);
	nal_data = libnal->libnal_data;
	
	if (GMNAL_IS_SMALL_MESSAGE(nal_data, niov, iov, len)) {
		CDEBUG(D_INFO, "This is a small message send\n");
		gmnal_small_tx(libnal, private, cookie, hdr, type, nid, pid, 
			       	niov, iov, offset,  len);
	} else {
		CDEBUG(D_ERROR, "Large message send it is not supported\n");
		lib_finalize(libnal, private, cookie, PTL_FAIL);
		return(PTL_FAIL);
		gmnal_large_tx(libnal, private, cookie, hdr, type, nid, pid, 
				niov, iov, offset, len);
	}
	return(PTL_OK);
}

ptl_err_t gmnal_cb_send_pages(lib_nal_t *libnal, void *private, lib_msg_t *cookie, 
			 ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
                         unsigned int kniov, ptl_kiov_t *kiov, size_t offset, size_t len)
{

	int	i = 0;
	gmnal_data_t	*nal_data;
	struct	iovec 	*iovec = NULL, *iovec_dup = NULL;
	ptl_kiov_t	*kiov_dup = kiov;

	CDEBUG(D_TRACE, "gmnal_cb_send_pages nid ["LPU64"] niov[%d] offset["LPSZ"] len["LPSZ"]\n", 
               nid, kniov, offset, len);
	nal_data = libnal->libnal_data;
	PORTAL_ALLOC(iovec, kniov*sizeof(struct iovec));
        iovec_dup = iovec;
	if (GMNAL_IS_SMALL_MESSAGE(nal_data, 0, NULL, len)) {
		CDEBUG(D_INFO, "This is a small message send\n");
		
		for (i=0; i<kniov; i++) {
			CDEBUG(D_INFO, "processing kniov [%d] [%p]\n", i, kiov);
			CDEBUG(D_INFO, "kniov page [%p] len [%d] offset[%d]\n",
			       kiov->kiov_page, kiov->kiov_len, 
			       kiov->kiov_offset);

			iovec->iov_base = kmap(kiov->kiov_page) 
					        + kiov->kiov_offset;

			iovec->iov_len = kiov->kiov_len;
                        iovec++;
                        kiov++;
		}
		gmnal_small_tx(libnal, private, cookie, hdr, type, nid, 
				pid, kniov, iovec_dup, offset, len);
	} else {
		CDEBUG(D_ERROR, "Large message send it is not supported yet\n");
		return(PTL_FAIL);
		for (i=0; i<kniov; i++) {
			CDEBUG(D_INFO, "processing kniov [%d] [%p]\n", i, kiov);
			CDEBUG(D_INFO, "kniov page [%p] len [%d] offset[%d]\n",
			       kiov->kiov_page, kiov->kiov_len, 
			       kiov->kiov_offset);

			iovec->iov_base = kmap(kiov->kiov_page) 
					         + kiov->kiov_offset;
			iovec->iov_len = kiov->kiov_len;
                        iovec++;
                        kiov++;
		}
		gmnal_large_tx(libnal, private, cookie, hdr, type, nid, 
				pid, kniov, iovec, offset, len);
	}
	for (i=0; i<kniov; i++) {
		kunmap(kiov_dup->kiov_page);
		kiov_dup++;
	}
	PORTAL_FREE(iovec_dup, kniov*sizeof(struct iovec));
	return(PTL_OK);
}

int gmnal_cb_dist(lib_nal_t *libnal, ptl_nid_t nid, unsigned long *dist)
{
	CDEBUG(D_TRACE, "gmnal_cb_dist\n");
	if (dist)
		*dist = 27;
	return(PTL_OK);
}
