/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
  * vim:expandtab:shiftwidth=8:tabstop=8:
  *
  *  Copyright (c) 2003 Los Alamos National Laboratory (LANL)
  *
  *   This file is part of Lustre, http://www.lustre.org/
  *
  *   This file is free software; you can redistribute it and/or
  *   modify it under the terms of version 2.1 of the GNU Lesser General
  *   Public License as published by the Free Software Foundation.
  *
  *   Lustre is distributed in the hope that it will be useful,
  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *   GNU Lesser General Public License for more details.
  *
  *   You should have received a copy of the GNU Lesser General Public
  *   License along with Portals; if not, write to the Free Software
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
	lgmnal_data_t	*nal_data = nal_cb->nal_data;


	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_recv nal_cb [%p],private[%p], cookie[%p], niov[%d], iov [%p], mlen[%d], rlen[%d]\n", nal_cb, private, cookie, niov, iov, mlen, rlen));

	if (srxd->type == LGMNAL_SMALL_MESSAGE) {
		if (!LGMNAL_IS_SMALL_MESSAGE(nal_data, niov, iov, mlen)) {
			LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("lgmnal_cb_recv. This is not a small message\n"));
		}
		status = lgmnal_small_receive2(nal_cb, private, cookie, niov, iov, mlen, rlen);
	}
		

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_return status [%d]\n", status));
	return(status);
}

int lgmnal_cb_recv_pages(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, unsigned int kniov, ptl_kiov_t *kiov, size_t mlen, size_t rlen)
{
	lgmnal_srxd_t	*srxd = (lgmnal_srxd_t*)private;
	int		status = PTL_OK;
	struct iovec	*iovec = NULL;
	int		i = 0;


	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_recv_pages nal_cb [%p],private[%p], cookie[%p], kniov[%d], kiov [%p], mlen[%d], rlen[%d]\n", nal_cb, private, cookie, kniov, kiov, mlen, rlen));

	if (srxd->type == LGMNAL_SMALL_MESSAGE) {
		PORTAL_ALLOC(iovec, sizeof(struct iovec)*kniov);
		if (!iovec) {
			LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("Can't malloc\n"));
			return(LGMNAL_STATUS_FAIL);
		}

		/*
		 *	map each page and create an iovec for it
		 */
		for (i=0; i<kniov; i++) {
			LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing kniov [%d] [%p]\n", i, kiov));
			LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("kniov page [%p] len [%d] offset[%d]\n", kiov->kiov_page, kiov->kiov_len, kiov->kiov_offset));
			iovec->iov_len = kiov->kiov_len;
			LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Calling kmap", kiov->kiov_page));
			iovec->iov_base = kmap(kiov->kiov_page) + kiov->kiov_offset;
			LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("Calling iov_base is [%p]", iovec->iov_base));
			iovec->iov_len = kiov->kiov_len;
		}
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("calling lgmnal_small_receive2\n"));
		status = lgmnal_small_receive2(nal_cb, private, cookie, kniov, iovec, mlen, rlen);
		PORTAL_FREE(iovec, sizeof(struct iovec)*kniov);
	}
		

	LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("lgmnal_return status [%d]\n", status));
	return(status);
}


int lgmnal_cb_send(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, ptl_hdr_t *hdr,
	int type, ptl_nid_t nid, ptl_pid_t pid, unsigned int niov, struct iovec *iov, size_t len)
{

	lgmnal_data_t	*nal_data;


	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_sendnid [%lu] niov[%d] len[%d]\n", nid, niov, len));
	nal_data = nal_cb->nal_data;
	
	if (LGMNAL_IS_SMALL_MESSAGE(nal_data, niov, iov, len)) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("This is a small message send\n"));
		lgmnal_small_transmit(nal_cb, private, cookie, hdr, type, nid, pid, niov, iov, len);
	} else {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("This is a large message send it is not supported yet\n"));
/*
		lgmnal_large_transmit1(nal_cb, private, cookie, hdr, type, nid, pid, niov, iov, len);
*/
		return(LGMNAL_STATUS_FAIL);
	}
	return(PTL_OK);
}

int lgmnal_cb_send_pages(nal_cb_t *nal_cb, void *private, lib_msg_t *cookie, ptl_hdr_t *hdr,
	int type, ptl_nid_t nid, ptl_pid_t pid, unsigned int kniov, ptl_kiov_t *kiov, size_t len)
{

	int	i = 0;
	lgmnal_data_t	*nal_data;
	struct	iovec 	*iovec;

	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_send_pages nid [%lu] niov[%d] len[%d]\n", nid, kniov, len));
	nal_data = nal_cb->nal_data;
	if (LGMNAL_IS_SMALL_MESSAGE(nal_data, 0, NULL, len)) {
		/* TO DO fix small message for send pages */
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("This is a small message send\n"));
		PORTAL_ALLOC(iovec, kniov*sizeof(struct iovec));
		
		for (i=0; i<kniov; i++) {
			LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("processing kniov [%d] [%p]\n", i, kiov));
			LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("kniov page [%p] len [%d] offset[%d]\n", kiov->kiov_page, kiov->kiov_len, kiov->kiov_offset));
			iovec->iov_len = kiov->kiov_len;
			iovec->iov_base = kmap(kiov->kiov_page) + kiov->kiov_offset;
			iovec->iov_len = kiov->kiov_len;
		}
		lgmnal_small_transmit(nal_cb, private, cookie, hdr, type, nid, pid, kniov, iovec, len);
		PORTAL_FREE(iovec, kniov*sizeof(struct iovec));
	} else {
		LGMNAL_PRINT(LGMNAL_DEBUG_ERR, ("This is a large message send it is not supported yet\n"));
/*
		lgmnal_large_transmit1(nal_cb, private, cookie, hdr, type, nid, pid, niov, iov, len);
*/
		return(LGMNAL_STATUS_FAIL);
	}
	return(PTL_OK);
}

int lgmnal_cb_read(nal_cb_t *nal_cb, void *private, void *dst, user_ptr src, size_t len)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_read dst [%p] src [%p] len[%d]\n", dst, src, len));
	gm_bcopy(src, dst, len);
	return(PTL_OK);
}

int lgmnal_cb_write(nal_cb_t *nal_cb, void *private, user_ptr dst, void *src, size_t len)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_write :: dst [%p] src [%p] len[%d]\n", dst, src, len));
	gm_bcopy(src, dst, len);
	return(PTL_OK);
}

int lgmnal_cb_callback(nal_cb_t *nal_cb, void *private, lib_eq_t *eq, ptl_event_t *ev)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_callback nal_cb[%p], private[%p], eq[%p], ev[%p]\n", nal_cb, private, eq, ev));

	if (eq->event_callback != NULL) {
		LGMNAL_PRINT(LGMNAL_DEBUG_VV, ("found callback\n"));
		eq->event_callback(ev);
	}
	
	return(PTL_OK);
}

void *lgmnal_cb_malloc(nal_cb_t *nal_cb, size_t len)
{
	void *ptr = NULL;
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_malloc len[%d]\n", len));
	PORTAL_ALLOC(ptr, len);
	return(ptr);
}

void lgmnal_cb_free(nal_cb_t *nal_cb, void *buf, size_t len)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_free :: buf[%p] len[%d]\n", buf, len));
	PORTAL_FREE(buf, len);
	return;
}

void lgmnal_cb_unmap(nal_cb_t *nal_cb, unsigned int niov, struct iovec *iov, void **addrkey)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_unmap niov[%d] iov[%], addrkey[%p]\n", niov, iov, addrkey));
	return;
}

int  lgmnal_cb_map(nal_cb_t *nal_cb, unsigned int niov, struct iovec *iov, void**addrkey)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_map niov[%d], iov[%p], addrkey[%p], niov, iov, addrkey\n"));
	return(PTL_OK);
}

void lgmnal_cb_printf(nal_cb_t *nal_cb, const char *fmt, ...)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_printf\n"));
	lgmnal_print(fmt);
	return;
}

void lgmnal_cb_cli(nal_cb_t *nal_cb, unsigned long *flags)
{
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)nal_cb->nal_data;
	spinlock_t	cb_lock = nal_data->cb_lock;
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_cli\n"));
/*
	local_irq_save(*flags);
	spin_lock_irqsave(&cb_lock, *flags);
*/
	spin_lock(&cb_lock);
	return;
}

void lgmnal_cb_sti(nal_cb_t *nal_cb, unsigned long *flags)
{
	lgmnal_data_t	*nal_data = (lgmnal_data_t*)nal_cb->nal_data;
	spinlock_t	cb_lock = nal_data->cb_lock;

/*
	local_irq_restore(*flags);
	spin_unlock_irqrestore(&cb_lock, *flags);
*/
	spin_unlock(&cb_lock);
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_sti\n"));
	return;
}

int lgmnal_cb_dist(nal_cb_t *nal_cb, ptl_nid_t nid, unsigned long *dist)
{
	LGMNAL_PRINT(LGMNAL_DEBUG_TRACE, ("lgmnal_cb_dist\n"));
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
