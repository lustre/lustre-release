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


#include "lgmnal.h"

int lgmnal_cb_recv(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, unsigned int niov, struct iovec *iov, size_t mlen, size_t rlen)
{
	lgmnal_srxd_t	*srxd = (lgmnal_srxd_t*)private;
	int		status = PTL_OK;


	CDEBUG(D_TRACE, "lgmnal_cb_recv nal_cb [%p], private[%p], cookie[%p], niov[%d], iov [%p], mlen["LPSZ"], rlen["LPSZ"]\n", nal_cb, private, cookie, niov, iov, mlen, rlen);

	if (niov == 0) {
		CDEBUG(D_INFO, "lgmnal_cb_recv Context [%p] nriov is ZERO\n", private);
	}
	switch(srxd->type) {
	case(LGMNAL_SMALL_MESSAGE):
		CDEBUG(D_INFO, "lgmnal_cb_recv got small message\n");
		status = lgmnal_small_rx(nal_cb, private, cookie, niov, iov, mlen, rlen);
	break;
	case(LGMNAL_LARGE_MESSAGE_INIT):
		CDEBUG(D_INFO, "lgmnal_cb_recv got large message init\n");
		status = lgmnal_large_rx(nal_cb, private, cookie, niov, iov, mlen, rlen);
	}
		

	CDEBUG(D_INFO, "lgmnal_cb_recv lgmnal_return status [%d]\n", status);
	return(status);
}

int lgmnal_cb_recv_pages(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, unsigned int kniov, ptl_kiov_t *kiov, size_t mlen, size_t rlen)
{
	lgmnal_srxd_t	*srxd = (lgmnal_srxd_t*)private;
	int		status = PTL_OK;
	struct iovec	*iovec = NULL, *iovec_dup = NULL;
	int		i = 0;


	CDEBUG(D_TRACE, "lgmnal_cb_recv_pages nal_cb [%p],private[%p], cookie[%p], kniov[%d], kiov [%p], mlen["LPSZ"], rlen["LPSZ"]\n", nal_cb, private, cookie, kniov, kiov, mlen, rlen);

	if (srxd->type == LGMNAL_SMALL_MESSAGE) {
		PORTAL_ALLOC(iovec, sizeof(struct iovec)*kniov);
		if (!iovec) {
			CDEBUG(D_ERROR, "Can't malloc\n");
			return(LGMNAL_STATUS_FAIL);
		}
                iovec_dup = iovec;

		/*
		 *	map each page and create an iovec for it
		 */
		for (i=0; i<kniov; i++) {
			CDEBUG(D_INFO, "processing kniov [%d] [%p]\n", i, kiov);
			CDEBUG(D_INFO, "kniov page [%p] len [%d] offset[%d]\n", kiov->kiov_page, kiov->kiov_len, kiov->kiov_offset);
			iovec->iov_len = kiov->kiov_len;
			CDEBUG(D_INFO, "Calling kmap[%p]", kiov->kiov_page);
			iovec->iov_base = kmap(kiov->kiov_page) + kiov->kiov_offset;
			CDEBUG(D_INFO, "iov_base is [%p]\n", iovec->iov_base);
                        iovec++;
                        kiov++;
		}
		CDEBUG(D_INFO, "calling lgmnal_small_rx\n");
		status = lgmnal_small_rx(nal_cb, private, cookie, kniov, iovec_dup, mlen, rlen);
		PORTAL_FREE(iovec_dup, sizeof(struct iovec)*kniov);
	}
		

	CDEBUG(D_INFO, "lgmnal_return status [%d]\n", status);
	return(status);
}


int lgmnal_cb_send(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, ptl_hdr_t *hdr,
	int type, ptl_nid_t nid, ptl_pid_t pid, unsigned int niov, struct iovec *iov, size_t len)
{

	lgmnal_data_t	*nal_data;


	CDEBUG(D_TRACE, "lgmnal_cb_send niov[%d] len["LPSZ"] nid["LPU64"]\n", niov, len, nid);
	nal_data = nal_cb->nal_data;
	
	if (LGMNAL_IS_SMALL_MESSAGE(nal_data, niov, iov, len)) {
		CDEBUG(D_INFO, "This is a small message send\n");
		lgmnal_small_tx(nal_cb, private, cookie, hdr, type, nid, pid, niov, iov, len);
	} else {
		CDEBUG(D_ERROR, "This is a large message send it is not supported yet\n");
		lib_finalize(nal_cb, private, cookie);
		return(PTL_FAIL);
		lgmnal_large_tx(nal_cb, private, cookie, hdr, type, nid, pid, niov, iov, len);
	}
	return(PTL_OK);
}

int lgmnal_cb_send_pages(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, ptl_hdr_t *hdr,
	int type, ptl_nid_t nid, ptl_pid_t pid, unsigned int kniov, ptl_kiov_t *kiov, size_t len)
{

	int	i = 0;
	lgmnal_data_t	*nal_data;
	struct	iovec 	*iovec = NULL, *iovec_dup = NULL;

	CDEBUG(D_TRACE, "lgmnal_cb_send_pages nid ["LPU64"] niov[%d] len["LPSZ"]\n", nid, kniov, len);
	nal_data = nal_cb->nal_data;
	PORTAL_ALLOC(iovec, kniov*sizeof(struct iovec));
        iovec_dup = iovec;
	if (LGMNAL_IS_SMALL_MESSAGE(nal_data, 0, NULL, len)) {
		CDEBUG(D_INFO, "This is a small message send\n");
		
		for (i=0; i<kniov; i++) {
			CDEBUG(D_INFO, "processing kniov [%d] [%p]\n", i, kiov);
			CDEBUG(D_INFO, "kniov page [%p] len [%d] offset[%d]\n", kiov->kiov_page, kiov->kiov_len, kiov->kiov_offset);
			iovec->iov_len = kiov->kiov_len;
			iovec->iov_base = kmap(kiov->kiov_page) + kiov->kiov_offset;
			iovec->iov_len = kiov->kiov_len;
                        iovec++;
                        kiov++;
		}
		lgmnal_small_tx(nal_cb, private, cookie, hdr, type, nid, pid, kniov, iovec_dup, len);
	} else {
		CDEBUG(D_ERROR, "lgmnal_cb_send_pages This is a large message send it is not supported yet\n");
		return(PTL_FAIL);
		for (i=0; i<kniov; i++) {
			CDEBUG(D_INFO, "processing kniov [%d] [%p]\n", i, kiov);
			CDEBUG(D_INFO, "kniov page [%p] len [%d] offset[%d]\n", kiov->kiov_page, kiov->kiov_len, kiov->kiov_offset);
			iovec->iov_len = kiov->kiov_len;
			iovec->iov_base = kmap(kiov->kiov_page) + kiov->kiov_offset;
			iovec->iov_len = kiov->kiov_len;
                        iovec++;
                        kiov++;
		}
		lgmnal_large_tx(nal_cb, private, cookie, hdr, type, nid, pid, kniov, iovec, len);
	}
	PORTAL_FREE(iovec_dup, kniov*sizeof(struct iovec));
	return(PTL_OK);
}

int lgmnal_cb_read(nal_cb_t *nal_cb, void *private, void *dst, user_ptr src, size_t len)
{
	CDEBUG(D_TRACE, "lgmnal_cb_read dst [%p] src [%p] len["LPSZ"]\n", dst, src, len);
	gm_bcopy(src, dst, len);
	return(PTL_OK);
}

int lgmnal_cb_write(nal_cb_t *nal_cb, void *private, user_ptr dst, void *src, size_t len)
{
	CDEBUG(D_TRACE, "lgmnal_cb_write :: dst [%p] src [%p] len["LPSZ"]\n", dst, src, len);
	gm_bcopy(src, dst, len);
	return(PTL_OK);
}

int lgmnal_cb_callback(nal_cb_t *nal_cb, void *private, lib_eq_t *eq, ptl_event_t *ev)
{
	CDEBUG(D_TRACE, "lgmnal_cb_callback nal_cb[%p], private[%p], eq[%p], ev[%p]\n", nal_cb, private, eq, ev);

	if (eq->event_callback != NULL) {
		CDEBUG(D_INFO, "found callback\n");
		eq->event_callback(ev);
	}
	
	return(PTL_OK);
}

void *lgmnal_cb_malloc(nal_cb_t *nal_cb, size_t len)
{
	void *ptr = NULL;
	CDEBUG(D_TRACE, "lgmnal_cb_malloc len["LPSZ"]\n", len);
	PORTAL_ALLOC(ptr, len);
	return(ptr);
}

void lgmnal_cb_free(nal_cb_t *nal_cb, void *buf, size_t len)
{
	CDEBUG(D_TRACE, "lgmnal_cb_free :: buf[%p] len["LPSZ"]\n", buf, len);
	PORTAL_FREE(buf, len);
	return;
}

void lgmnal_cb_unmap(nal_cb_t *nal_cb, unsigned int niov, struct iovec *iov, void **addrkey)
{
	CDEBUG(D_TRACE, "lgmnal_cb_unmap niov[%d] iov[%p], addrkey[%p]\n", niov, iov, addrkey);
	return;
}

int  lgmnal_cb_map(nal_cb_t *nal_cb, unsigned int niov, struct iovec *iov, void**addrkey)
{
	CDEBUG(D_TRACE, "lgmnal_cb_map niov[%d], iov[%p], addrkey[%p]\n", niov, iov, addrkey);
	return(PTL_OK);
}

void lgmnal_cb_printf(nal_cb_t *nal_cb, const char *fmt, ...)
{
	CDEBUG(D_TRACE, "lgmnal_cb_printf\n");
	printk(fmt);
	return;
}

void lgmnal_cb_cli(nal_cb_t *nal_cb, unsigned long *flags)
{
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)nal_cb->nal_data;

	spin_lock_irqsave(&nal_data->cb_lock, *flags);
	return;
}

void lgmnal_cb_sti(nal_cb_t *nal_cb, unsigned long *flags)
{
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)nal_cb->nal_data;

	spin_unlock_irqrestore(&nal_data->cb_lock, *flags);
	return;
}

int lgmnal_cb_dist(nal_cb_t *nal_cb, ptl_nid_t nid, unsigned long *dist)
{
	CDEBUG(D_TRACE, "lgmnal_cb_dist\n");
	if (dist)
		*dist = 27;
	return(PTL_OK);
}




EXPORT_SYMBOL(lgmnal_cb_send);
EXPORT_SYMBOL(lgmnal_cb_send_pages);
EXPORT_SYMBOL(lgmnal_cb_recv);
EXPORT_SYMBOL(lgmnal_cb_recv_pages);
EXPORT_SYMBOL(lgmnal_cb_read);
EXPORT_SYMBOL(lgmnal_cb_write);
EXPORT_SYMBOL(lgmnal_cb_cli);
EXPORT_SYMBOL(lgmnal_cb_sti);
EXPORT_SYMBOL(lgmnal_cb_dist);
EXPORT_SYMBOL(lgmnal_cb_printf);
EXPORT_SYMBOL(lgmnal_cb_map);
EXPORT_SYMBOL(lgmnal_cb_unmap);
EXPORT_SYMBOL(lgmnal_cb_callback);
EXPORT_SYMBOL(lgmnal_cb_free);
EXPORT_SYMBOL(lgmnal_cb_malloc);
