/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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
 */

#include <lnet/lib-lnet.h>

int
lonal_send (ptl_ni_t        *ni,
	    void            *private,
	    ptl_msg_t       *ptlmsg,
	    ptl_hdr_t       *hdr,
	    int              type,
	    lnet_process_id_t target,
	    int              routing,
	    unsigned int     payload_niov,
	    struct iovec    *payload_iov,
	    size_t           payload_offset,
	    size_t           payload_nob)
{
        lo_desc_t lod = {
                .lod_type    = LOD_IOV,
                .lod_niov    = payload_niov,
                .lod_offset  = payload_offset,
                .lod_nob     = payload_nob,
                .lod_iov     = { .iov = payload_iov } };
        int rc;

        LASSERT (!routing);

        rc = ptl_parse(ni, hdr, &lod);
        if (rc == 0)
                ptl_finalize(ni, private, ptlmsg, 0);
        
        return rc;
}

int
lonal_recv(ptl_ni_t     *ni,
	   void         *private,
	   ptl_msg_t    *ptlmsg,
	   unsigned int  niov,
	   struct iovec *iov,
	   size_t        offset,
	   size_t        mlen,
	   size_t        rlen)
{
        lo_desc_t *lod = (lo_desc_t *)private;

        /* I only handle mapped->mapped matches */
        LASSERT(mlen == 0 || lod->lod_type == LOD_IOV);

        if (mlen == 0)
                goto out;

        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT(niov > 0);
        }
        
        while (lod->lod_offset >= lod->lod_iov.iov->iov_len) {
                lod->lod_offset -= lod->lod_iov.iov->iov_len;
                lod->lod_iov.iov++;
                lod->lod_niov--;
                LASSERT(lod->lod_niov > 0);
        }
        
        do {
                int fraglen = MIN(iov->iov_len - offset,
                                  lod->lod_iov.iov->iov_len - lod->lod_offset);

                LASSERT(niov > 0);
                LASSERT(lod->lod_niov > 0);

                if (fraglen > mlen)
                        fraglen = mlen;
                
                memcpy((void *)((unsigned long)iov->iov_base + offset),
                       (void *)((unsigned long)lod->lod_iov.iov->iov_base +
                                lod->lod_offset),
                       fraglen);

                if (offset + fraglen < iov->iov_len) {
                        offset += fraglen;
                } else {
                        offset = 0;
                        iov++;
                        niov--;
                }

                if (lod->lod_offset + fraglen < lod->lod_iov.iov->iov_len ) {
                        lod->lod_offset += fraglen;
                } else {
                        lod->lod_offset = 0;
                        lod->lod_iov.iov++;
                        lod->lod_niov--;
                }

                mlen -= fraglen;
        } while (mlen > 0);
        
 out:
        ptl_finalize(ni, private, ptlmsg, 0);
        return 0;
}

#ifdef __KERNEL__
int
lonal_send_pages (ptl_ni_t        *ni,
		  void            *private,
		  ptl_msg_t       *ptlmsg,
		  ptl_hdr_t       *hdr,
		  int              type,
		  lnet_process_id_t target,
		  int              routing,
		  unsigned int     payload_niov,
		  lnet_kiov_t      *payload_kiov,
		  size_t           payload_offset,
		  size_t           payload_nob)
{
        lo_desc_t lod = {
                .lod_type     = LOD_KIOV,
                .lod_niov     = payload_niov,
                .lod_offset   = payload_offset,
                .lod_nob      = payload_nob,
                .lod_iov      = { .kiov = payload_kiov } };
        int   rc;

        LASSERT (!routing);

        rc = ptl_parse(ni, hdr, &lod);
        if (rc == 0)
                ptl_finalize(ni, private, ptlmsg, 0);
        
        return rc;
}

int
lonal_recv_pages(ptl_ni_t     *ni,
		 void         *private,
		 ptl_msg_t    *ptlmsg,
		 unsigned int  niov,
		 lnet_kiov_t   *kiov,
		 size_t        offset,
		 size_t        mlen,
		 size_t        rlen)
{
        void          *srcaddr = NULL;
        void          *dstaddr = NULL;
        unsigned long  srcfrag = 0;
        unsigned long  dstfrag = 0;
        unsigned long  fraglen;
        lo_desc_t    *lod = (lo_desc_t *)private;

        /* I only handle unmapped->unmapped matches */
        LASSERT(mlen == 0 || lod->lod_type == LOD_KIOV);

        if (mlen == 0)
                goto out;

        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                kiov++;
                niov--;
                LASSERT(niov > 0);
        }

        while (lod->lod_offset >= lod->lod_iov.kiov->kiov_len) {
                lod->lod_offset -= lod->lod_iov.kiov->kiov_len;
                lod->lod_iov.kiov++;
                lod->lod_niov--;
                LASSERT(lod->lod_niov > 0);
        }

        do {
        /* CAVEAT EMPTOR: I kmap 2 pages at once == slight risk of deadlock */
                LASSERT(niov > 0);
                if (dstaddr == NULL) {
                        dstaddr = (void *)((unsigned long)kmap(kiov->kiov_page) +
                                           kiov->kiov_offset + offset);
                        dstfrag = kiov->kiov_len -  offset;
                }

                LASSERT(lod->lod_niov > 0);
                if (srcaddr == NULL) {
                        srcaddr = (void *)((unsigned long)kmap(lod->lod_iov.kiov->kiov_page) +
                                           lod->lod_iov.kiov->kiov_offset + lod->lod_offset);
                        srcfrag = lod->lod_iov.kiov->kiov_len - lod->lod_offset;
                }
                
                fraglen = MIN(srcfrag, dstfrag);
                if (fraglen > mlen)
                        fraglen = mlen;
                
                memcpy(dstaddr, srcaddr, fraglen);
                
                if (fraglen < dstfrag) {
                        dstfrag -= fraglen;
                        dstaddr = (void *)((unsigned long)dstaddr + fraglen);
                } else {
                        kunmap(kiov->kiov_page);
                        dstaddr = NULL;
                        offset = 0;
                        kiov++;
                        niov--;
                }

                if (fraglen < srcfrag) {
                        srcfrag -= fraglen;
                        srcaddr = (void *)((unsigned long)srcaddr + fraglen);
                } else {
                        kunmap(lod->lod_iov.kiov->kiov_page);
                        srcaddr = NULL;
                        lod->lod_offset = 0;
                        lod->lod_iov.kiov++;
                        lod->lod_niov--;
                }

                mlen -= fraglen;
        } while (mlen > 0);

        if (dstaddr != NULL)
                kunmap(kiov->kiov_page);

        if (srcaddr != NULL)
                kunmap(lod->lod_iov.kiov->kiov_page);

 out:
        ptl_finalize(ni, private, ptlmsg, 0);
        return 0;
}
#endif

static int lonal_instanced;

void
lonal_shutdown(ptl_ni_t *ni)
{
	CDEBUG (D_NET, "shutdown\n");
        LASSERT (lonal_instanced);
        
        lonal_instanced = 0;
}

int
lonal_startup (ptl_ni_t *ni)
{
	LASSERT (ni->ni_nal == &ptl_lonal);
	LASSERT (!lonal_instanced);
        lonal_instanced = 1;

	return (0);
}

ptl_nal_t ptl_lonal = {
        .nal_type       = LONAL,
        .nal_startup    = lonal_startup,
        .nal_shutdown   = lonal_shutdown,
        .nal_send       = lonal_send,
        .nal_recv       = lonal_recv,
#ifdef __KERNEL__
        .nal_send_pages = lonal_send_pages,
        .nal_recv_pages = lonal_recv_pages,
#endif
};

ptl_ni_t *ptl_loni;
