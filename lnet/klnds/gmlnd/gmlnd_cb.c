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

ptl_err_t gmnal_cb_recv(ptl_ni_t *ni, void *private, ptl_msg_t *cookie,
		   unsigned int niov, struct iovec *iov, size_t offset,
		   size_t mlen, size_t rlen)
{
        void            *buffer = NULL;
	gmnal_srxd_t	*srxd = (gmnal_srxd_t*)private;
	int		status = PTL_OK;

	CDEBUG(D_TRACE, "gmnal_cb_recv ni [%p], private[%p], cookie[%p], "
	       "niov[%d], iov [%p], offset["LPSZ"], mlen["LPSZ"], rlen["LPSZ"]\n",
	       ni, private, cookie, niov, iov, offset, mlen, rlen);

	switch(srxd->type) {
	case(GMNAL_SMALL_MESSAGE):
		CDEBUG(D_INFO, "gmnal_cb_recv got small message\n");
		/* HP SFS 1380: Proactively change receives to avoid a receive
		 *  side occurrence of filling pkmap_count[].
		 */
		buffer = srxd->buffer;
		buffer += sizeof(gmnal_msghdr_t);
		buffer += sizeof(ptl_hdr_t);

		while(niov--) {
			if (offset >= iov->iov_len) {
				offset -= iov->iov_len;
			} else if (offset > 0) {
				CDEBUG(D_INFO, "processing [%p] base [%p] "
                                       "len %d, offset %d, len ["LPSZ"]\n", iov,
                                       iov->iov_base + offset, iov->iov_len,
                                       offset, iov->iov_len - offset);
				gm_bcopy(buffer, iov->iov_base + offset,
					 iov->iov_len - offset);
				buffer += iov->iov_len - offset;
				offset = 0;
			} else {
				CDEBUG(D_INFO, "processing [%p] len ["LPSZ"]\n",
                                       iov, iov->iov_len);
				gm_bcopy(buffer, iov->iov_base, iov->iov_len);
				buffer += iov->iov_len;
			}
			iov++;
		}
		status = gmnal_small_rx(ni, private, cookie);
	break;
	case(GMNAL_LARGE_MESSAGE_INIT):
		CDEBUG(D_INFO, "gmnal_cb_recv got large message init\n");
		status = gmnal_large_rx(ni, private, cookie, niov, 
					 iov, offset, mlen, rlen);
	}

	CDEBUG(D_INFO, "gmnal_cb_recv gmnal_return status [%d]\n", status);
	return(status);
}

ptl_err_t gmnal_cb_recv_pages(ptl_ni_t *ni, void *private,
                              ptl_msg_t *cookie, unsigned int kniov,
                              ptl_kiov_t *kiov, size_t offset, size_t mlen,
                              size_t rlen)
{
	gmnal_srxd_t	*srxd = (gmnal_srxd_t*)private;
	int		status = PTL_OK;
	char            *ptr = NULL;
	void            *buffer = NULL;


	CDEBUG(D_TRACE, "gmnal_cb_recv_pages ni [%p],private[%p], "
	       "cookie[%p], kniov[%d], kiov [%p], offset["LPSZ"], mlen["LPSZ"], rlen["LPSZ"]\n",
	       ni, private, cookie, kniov, kiov, offset, mlen, rlen);

	if (srxd->type == GMNAL_SMALL_MESSAGE) {
		buffer = srxd->buffer;
		buffer += sizeof(gmnal_msghdr_t);
		buffer += sizeof(ptl_hdr_t);

		/*
		 *	map each page and create an iovec for it
		 */
		while (kniov--) {
			/* HP SFS 1380: Proactively change receives to avoid a
			 *  receive side occurrence of filling pkmap_count[].
			 */
			CDEBUG(D_INFO, "processing kniov [%d] [%p]\n",
                               kniov, kiov);

			if (offset >= kiov->kiov_len) {
				offset -= kiov->kiov_len;
			} else {
				CDEBUG(D_INFO, "kniov page [%p] len [%d] "
                                       "offset[%d]\n", kiov->kiov_page,
                                       kiov->kiov_len, kiov->kiov_offset);
				CDEBUG(D_INFO, "Calling kmap[%p]", kiov->kiov_page);
				ptr = ((char *)kmap(kiov->kiov_page)) +
                                        kiov->kiov_offset;

				if (offset > 0) {
					CDEBUG(D_INFO, "processing [%p] base "
                                               "[%p] len %d, offset %d, len ["
                                               LPSZ"]\n", ptr, ptr + offset,
                                               kiov->kiov_len, offset,
					       kiov->kiov_len - offset);
					gm_bcopy(buffer, ptr + offset,
                                                 kiov->kiov_len - offset);
					buffer += kiov->kiov_len - offset;
					offset = 0;
				} else {
					CDEBUG(D_INFO, "processing [%p] len ["
                                               LPSZ"]\n", ptr, kiov->kiov_len);
					gm_bcopy(buffer, ptr, kiov->kiov_len);
					buffer += kiov->kiov_len;
				}
				kunmap(kiov->kiov_page);
				CDEBUG(D_INFO, "Stored in [%p]\n", ptr);
                        }
                        kiov++;
		}
		CDEBUG(D_INFO, "calling gmnal_small_rx\n");
		status = gmnal_small_rx(ni, private, cookie);
	}

	CDEBUG(D_INFO, "gmnal_return status [%d]\n", status);
	return(status);
}


ptl_err_t gmnal_cb_send(ptl_ni_t *ni, void *private, ptl_msg_t *cookie,
                        ptl_hdr_t *hdr, int type, ptl_process_id_t target,
                        int routing, unsigned int niov, struct iovec *iov, 
                        size_t offset, size_t len)
{

	gmnal_data_t	*nal_data;
	void            *buffer = NULL;
	gmnal_stxd_t    *stxd = NULL;


	CDEBUG(D_TRACE, "gmnal_cb_send niov[%d] offset["LPSZ"] len["LPSZ
               "] target %s\n", niov, offset, len, libcfs_id2str(target));
	nal_data = ni->ni_data;
        CDEBUG(D_INFO, "nal_data [%p]\n", nal_data);
        LASSERT (nal_data != NULL);

        if (routing) {
                CERROR ("Can't route\n");
                return PTL_FAIL;
        }

	if (GMNAL_IS_SMALL_MESSAGE(nal_data, niov, iov, len)) {
		CDEBUG(D_INFO, "This is a small message send\n");
		/*
		 * HP SFS 1380: With the change to gmnal_small_tx, need to get
		 * the stxd and do relevant setup here
		 */
		stxd = gmnal_get_stxd(nal_data, 1);
		CDEBUG(D_INFO, "stxd [%p]\n", stxd);
		/* Set the offset of the data to copy into the buffer */
		buffer = stxd->buffer +sizeof(gmnal_msghdr_t)+sizeof(ptl_hdr_t);
		while(niov--) {
			if (offset >= iov->iov_len) {
				offset -= iov->iov_len;
			} else if (offset > 0) {
				CDEBUG(D_INFO, "processing iov [%p] base [%p] "
                                       "len ["LPSZ"] to [%p]\n",
                                       iov, iov->iov_base + offset,
                                       iov->iov_len - offset, buffer);
				gm_bcopy(iov->iov_base + offset, buffer,
                                         iov->iov_len - offset);
				buffer+= iov->iov_len - offset;
				offset = 0;
			} else {
				CDEBUG(D_INFO, "processing iov [%p] len ["LPSZ
                                       "] to [%p]\n", iov, iov->iov_len,buffer);
				gm_bcopy(iov->iov_base, buffer, iov->iov_len);
				buffer+= iov->iov_len;
			}
			iov++;
		}
		gmnal_small_tx(ni, private, cookie, hdr, type, target.nid, target.pid,
			       stxd,  len);
	} else {
		CDEBUG(D_ERROR, "Large message send is not supported\n");
		ptl_finalize(ni, private, cookie, PTL_FAIL);
		return(PTL_FAIL);
		gmnal_large_tx(ni, private, cookie, hdr, type, target.nid, target.pid,
				niov, iov, offset, len);
	}
	return(PTL_OK);
}

ptl_err_t gmnal_cb_send_pages(ptl_ni_t *ni, void *private,
                              ptl_msg_t *cookie, ptl_hdr_t *hdr, int type,
                              ptl_process_id_t target, int routing,
                              unsigned int kniov, ptl_kiov_t *kiov, 
                              size_t offset, size_t len)
{

	gmnal_data_t	*nal_data;
	char            *ptr;
	void            *buffer = NULL;
	gmnal_stxd_t    *stxd = NULL;
	ptl_err_t       status = PTL_OK;

	CDEBUG(D_TRACE, "gmnal_cb_send_pages target %s niov[%d] offset["
               LPSZ"] len["LPSZ"]\n", libcfs_id2str(target), kniov, offset, len);
	nal_data = ni->ni_data;
        CDEBUG(D_INFO, "nal_data [%p]\n", nal_data);
        LASSERT (nal_data != NULL);

        if (routing) {
                CERROR ("Can't route\n");
                return PTL_FAIL;
        }

	/* HP SFS 1380: Need to do the gm_bcopy after the kmap so we can kunmap
	 * more aggressively.  This is the fix for a livelock situation under
	 * load on ia32 that occurs when there are no more available entries in
	 * the pkmap_count array.  Just fill the buffer and let gmnal_small_tx
	 * put the headers in after we pass it the stxd pointer.
	 */
	stxd = gmnal_get_stxd(nal_data, 1);
	CDEBUG(D_INFO, "stxd [%p]\n", stxd);
	/* Set the offset of the data to copy into the buffer */
	buffer = stxd->buffer + sizeof(gmnal_msghdr_t) + sizeof(ptl_hdr_t);

	if (GMNAL_IS_SMALL_MESSAGE(nal_data, 0, NULL, len)) {
		CDEBUG(D_INFO, "This is a small message send\n");

		while(kniov--) {
			CDEBUG(D_INFO, "processing kniov [%d] [%p]\n", kniov, kiov);
			if (offset >= kiov->kiov_len) {
				offset -= kiov->kiov_len;
			} else {
				CDEBUG(D_INFO, "kniov page [%p] len [%d] offset[%d]\n",
				       kiov->kiov_page, kiov->kiov_len, 
				       kiov->kiov_offset);

				ptr = ((char *)kmap(kiov->kiov_page)) +
                                        kiov->kiov_offset;

				if (offset > 0) {
					CDEBUG(D_INFO, "processing [%p] base "
                                               "[%p] len ["LPSZ"] to [%p]\n",
					       ptr, ptr + offset,
                                               kiov->kiov_len - offset, buffer);
					gm_bcopy(ptr + offset, buffer,
                                                 kiov->kiov_len - offset);
					buffer+= kiov->kiov_len - offset;
					offset = 0;
				} else {
					CDEBUG(D_INFO, "processing kmapped [%p]"
                                               " len ["LPSZ"] to [%p]\n",
					       ptr, kiov->kiov_len, buffer);
					gm_bcopy(ptr, buffer, kiov->kiov_len);

					buffer += kiov->kiov_len;
				}
				kunmap(kiov->kiov_page);
			}
                        kiov++;
		}
		status = gmnal_small_tx(ni, private, cookie, hdr, type, target.nid,
					target.pid, stxd, len);
	} else {
		int	i = 0;
		struct  iovec   *iovec = NULL, *iovec_dup = NULL;
		ptl_kiov_t *kiov_dup = kiov;

		PORTAL_ALLOC(iovec, kniov*sizeof(struct iovec));
		iovec_dup = iovec;
		CDEBUG(D_ERROR, "Large message send it is not supported yet\n");
		PORTAL_FREE(iovec, kniov*sizeof(struct iovec));
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
		gmnal_large_tx(ni, private, cookie, hdr, type, target.nid, 
				target.pid, kniov, iovec, offset, len);
		for (i=0; i<kniov; i++) {
			kunmap(kiov_dup->kiov_page);
			kiov_dup++;
		}
		PORTAL_FREE(iovec_dup, kniov*sizeof(struct iovec));
	}
	return(status);
}
