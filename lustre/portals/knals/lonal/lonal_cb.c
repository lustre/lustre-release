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

#include "lonal.h"

/*
 *  LIB functions follow
 *
 */
static int
klonal_dist(lib_nal_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        *dist = 0;                      /* it's me */
        return (0);
}

static ptl_err_t
klonal_send (lib_nal_t    *nal,
             void         *private,
             lib_msg_t    *libmsg,
             ptl_hdr_t    *hdr,
             int           type,
             ptl_nid_t     nid,
             ptl_pid_t     pid,
             unsigned int  payload_niov,
             struct iovec *payload_iov,
             size_t        payload_offset,
             size_t        payload_nob)
{
        klo_desc_t klod = {
                .klod_type    = KLOD_IOV,
                .klod_niov    = payload_niov,
                .klod_offset  = payload_offset,
                .klod_nob     = payload_nob,
                .klod_iov.iov = payload_iov};
        ptl_err_t rc;

        LASSERT(nid == klonal_lib.libnal_ni.ni_pid.nid);

        rc = lib_parse(&klonal_lib, hdr, &klod);
        if (rc == PTL_OK)
                lib_finalize(&klonal_lib, private, libmsg, PTL_OK);
        
        return rc;
}

static ptl_err_t
klonal_send_pages (lib_nal_t    *nal,
                   void         *private,
                   lib_msg_t    *libmsg,
                   ptl_hdr_t    *hdr,
                   int           type,
                   ptl_nid_t     nid,
                   ptl_pid_t     pid,
                   unsigned int  payload_niov,
                   ptl_kiov_t   *payload_kiov,
                   size_t        payload_offset,
                   size_t        payload_nob)
{
        klo_desc_t klod = {
                .klod_type     = KLOD_KIOV,
                .klod_niov     = payload_niov,
                .klod_offset   = payload_offset,
                .klod_nob      = payload_nob,
                .klod_iov.kiov = payload_kiov};
        ptl_err_t   rc;

        LASSERT(nid == klonal_lib.libnal_ni.ni_pid.nid);
        
        rc = lib_parse(&klonal_lib, hdr, &klod);
        if (rc == PTL_OK)
                lib_finalize(&klonal_lib, private, libmsg, PTL_OK);
        
        return rc;
}

static ptl_err_t
klonal_recv(lib_nal_t    *nal,
            void         *private,
            lib_msg_t    *libmsg,
            unsigned int  niov,
            struct iovec *iov,
            size_t        offset,
            size_t        mlen,
            size_t        rlen)
{
        klo_desc_t *klod = (klo_desc_t *)private;

        /* I only handle mapped->mapped matches */
        LASSERT(klod->klod_type == KLOD_IOV);

        if (mlen == 0)
                return PTL_OK;

        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT(niov > 0);
        }
        
        while (klod->klod_offset >= klod->klod_iov.iov->iov_len) {
                klod->klod_offset -= klod->klod_iov.iov->iov_len;
                klod->klod_iov.iov++;
                klod->klod_niov--;
                LASSERT(klod->klod_niov > 0);
        }
        
        do {
                int fraglen = MIN(iov->iov_len - offset,
                                  klod->klod_iov.iov->iov_len - klod->klod_offset);

                LASSERT(niov > 0);
                LASSERT(klod->klod_niov > 0);

                if (fraglen > mlen)
                        fraglen = mlen;
                
                memcpy((void *)((unsigned long)iov->iov_base + offset),
                       (void *)((unsigned long)klod->klod_iov.iov->iov_base +
                                klod->klod_offset),
                       fraglen);

                if (offset + fraglen < iov->iov_len) {
                        offset += fraglen;
                } else {
                        offset = 0;
                        iov++;
                        niov--;
                }

                if (klod->klod_offset + fraglen < klod->klod_iov.iov->iov_len ) {
                        klod->klod_offset += fraglen;
                } else {
                        klod->klod_offset = 0;
                        klod->klod_iov.iov++;
                        klod->klod_niov--;
                }

                mlen -= fraglen;
        } while (mlen > 0);
        
        lib_finalize(&klonal_lib, private, libmsg, PTL_OK);
        return PTL_OK;
}

static ptl_err_t
klonal_recv_pages(lib_nal_t    *nal,
                  void         *private,
                  lib_msg_t    *libmsg,
                  unsigned int  niov,
                  ptl_kiov_t   *kiov,
                  size_t        offset,
                  size_t        mlen,
                  size_t        rlen)
{
        void          *srcaddr = NULL;
        void          *dstaddr = NULL;
        unsigned long  srcfrag = 0;
        unsigned long  dstfrag = 0;
        unsigned long  fraglen;
        klo_desc_t    *klod = (klo_desc_t *)private;

        /* I only handle unmapped->unmapped matches */
        LASSERT(klod->klod_type == KLOD_KIOV);

        if (mlen == 0)
                return PTL_OK;

        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                kiov++;
                niov--;
                LASSERT(niov > 0);
        }

        while (klod->klod_offset >= klod->klod_iov.kiov->kiov_len) {
                klod->klod_offset -= klod->klod_iov.kiov->kiov_len;
                klod->klod_iov.kiov++;
                klod->klod_niov--;
                LASSERT(klod->klod_niov > 0);
        }

        do {
        /* CAVEAT EMPTOR: I kmap 2 pages at once == slight risk of deadlock */
                LASSERT(niov > 0);
                if (dstaddr == NULL) {
                        dstaddr = (void *)((unsigned long)kmap(kiov->kiov_page) +
                                           kiov->kiov_offset + offset);
                        dstfrag = kiov->kiov_len -  offset;
                }

                LASSERT(klod->klod_niov > 0);
                if (srcaddr == NULL) {
                        srcaddr = (void *)((unsigned long)kmap(klod->klod_iov.kiov->kiov_page) +
                                           klod->klod_iov.kiov->kiov_offset + klod->klod_offset);
                        srcfrag = klod->klod_iov.kiov->kiov_len - klod->klod_offset;
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
                        kunmap(klod->klod_iov.kiov->kiov_page);
                        srcaddr = NULL;
                        klod->klod_offset = 0;
                        klod->klod_iov.kiov++;
                        klod->klod_niov--;
                }

                mlen -= fraglen;
        } while (mlen > 0);

        if (dstaddr != NULL)
                kunmap(kiov->kiov_page);

        if (srcaddr != NULL)
                kunmap(klod->klod_iov.kiov->kiov_page);

        lib_finalize(&klonal_lib, private, libmsg, PTL_OK);
        return PTL_OK;
}

lib_nal_t klonal_lib =
{
        libnal_data:       &klonal_data,         /* NAL private data */
        libnal_send:        klonal_send,
        libnal_send_pages:  klonal_send_pages,
        libnal_recv:        klonal_recv,
        libnal_recv_pages:  klonal_recv_pages,
        libnal_dist:        klonal_dist
};
