/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 * Copyright (C) 2002, Lawrence Livermore National Labs (LLNL)
 * W. Marcus Miller - Based on ksocknal
 *
 * This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 * Portals is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Portals is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portals; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "lbnal.h"

/*
 *  LIB functions follow
 *
 */
static int
klbnal_dist(lib_nal_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        *dist = 0;                      /* it's me */
        return (0);
}

static ptl_err_t
klbnal_send (lib_nal_t    *nal,
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
        klb_desc_t klbd = {
                .klbd_type    = KLBD_IOV,
                .klbd_niov    = payload_niov,
                .klbd_offset  = payload_offset,
                .klbd_nob     = payload_nob,
                .klbd_iov.iov = payload_iov};
        ptl_err_t rc;

        LASSERT(nid == klbnal_lib.libnal_ni.ni_pid.nid);

        rc = lib_parse(&klbnal_lib, hdr, &klbd);
        if (rc == PTL_OK)
                lib_finalize(&klbnal_lib, private, libmsg, PTL_OK);
        
        return rc;
}

static ptl_err_t
klbnal_send_pages (lib_nal_t    *nal,
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
        klb_desc_t klbd = {
                .klbd_type     = KLBD_KIOV,
                .klbd_niov     = payload_niov,
                .klbd_offset   = payload_offset,
                .klbd_nob      = payload_nob,
                .klbd_iov.kiov = payload_kiov};
        ptl_err_t   rc;

        LASSERT(nid == klbnal_lib.libnal_ni.ni_pid.nid);
        
        rc = lib_parse(&klbnal_lib, hdr, &klbd);
        if (rc == PTL_OK)
                lib_finalize(&klbnal_lib, private, libmsg, PTL_OK);
        
        return rc;
}

static ptl_err_t
klbnal_recv(lib_nal_t    *nal,
            void         *private,
            lib_msg_t    *libmsg,
            unsigned int  niov,
            struct iovec *iov,
            size_t        offset,
            size_t        mlen,
            size_t        rlen)
{
        klb_desc_t *klbd = (klb_desc_t *)private;

        /* I only handle mapped->mapped matches */
        LASSERT(klbd->klbd_type == KLBD_IOV);

        if (mlen == 0)
                return PTL_OK;

        while (offset >= iov->iov_len) {
                offset -= iov->iov_len;
                iov++;
                niov--;
                LASSERT(niov > 0);
        }
        
        while (klbd->klbd_offset >= klbd->klbd_iov.iov->iov_len) {
                klbd->klbd_offset -= klbd->klbd_iov.iov->iov_len;
                klbd->klbd_iov.iov++;
                klbd->klbd_niov--;
                LASSERT(klbd->klbd_niov > 0);
        }
        
        do {
                int fraglen = MIN(iov->iov_len - offset,
                                  klbd->klbd_iov.iov->iov_len - klbd->klbd_offset);

                LASSERT(niov > 0);
                LASSERT(klbd->klbd_niov > 0);

                if (fraglen > mlen)
                        fraglen = mlen;
                
                memcpy((void *)((unsigned long)iov->iov_base + offset),
                       (void *)((unsigned long)klbd->klbd_iov.iov->iov_base +
                                klbd->klbd_offset),
                       fraglen);

                if (offset + fraglen < iov->iov_len) {
                        offset += fraglen;
                } else {
                        offset = 0;
                        iov++;
                        niov--;
                }

                if (klbd->klbd_offset + fraglen < klbd->klbd_iov.iov->iov_len ) {
                        klbd->klbd_offset += fraglen;
                } else {
                        klbd->klbd_offset = 0;
                        klbd->klbd_iov.iov++;
                        klbd->klbd_niov--;
                }

                mlen -= fraglen;
        } while (mlen > 0);
        
        lib_finalize(&klbnal_lib, private, libmsg, PTL_OK);
        return PTL_OK;
}

static ptl_err_t
klbnal_recv_pages(lib_nal_t    *nal,
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
        klb_desc_t    *klbd = (klb_desc_t *)private;

        /* I only handle unmapped->unmapped matches */
        LASSERT(klbd->klbd_type == KLBD_KIOV);

        if (mlen == 0)
                return PTL_OK;

        while (offset >= kiov->kiov_len) {
                offset -= kiov->kiov_len;
                kiov++;
                niov--;
                LASSERT(niov > 0);
        }

        while (klbd->klbd_offset >= klbd->klbd_iov.kiov->kiov_len) {
                klbd->klbd_offset -= klbd->klbd_iov.kiov->kiov_len;
                klbd->klbd_iov.kiov++;
                klbd->klbd_niov--;
                LASSERT(klbd->klbd_niov > 0);
        }

        do {
        /* CAVEAT EMPTOR: I kmap 2 pages at once == slight risk of deadlock */
                LASSERT(niov > 0);
                if (dstaddr == NULL) {
                        dstaddr = (void *)((unsigned long)kmap(kiov->kiov_page) +
                                           kiov->kiov_offset + offset);
                        dstfrag = kiov->kiov_len -  offset;
                }

                LASSERT(klbd->klbd_niov > 0);
                if (srcaddr == NULL) {
                        srcaddr = (void *)((unsigned long)kmap(klbd->klbd_iov.kiov->kiov_page) +
                                           klbd->klbd_iov.kiov->kiov_offset + klbd->klbd_offset);
                        srcfrag = klbd->klbd_iov.kiov->kiov_len - klbd->klbd_offset;
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
                        kunmap(klbd->klbd_iov.kiov->kiov_page);
                        srcaddr = NULL;
                        klbd->klbd_offset = 0;
                        klbd->klbd_iov.kiov++;
                        klbd->klbd_niov--;
                }

                mlen -= fraglen;
        } while (mlen > 0);

        if (dstaddr != NULL)
                kunmap(kiov->kiov_page);

        if (srcaddr != NULL)
                kunmap(klbd->klbd_iov.kiov->kiov_page);

        lib_finalize(&klbnal_lib, private, libmsg, PTL_OK);
        return PTL_OK;
}

lib_nal_t klbnal_lib =
{
        libnal_data:       &klbnal_data,         /* NAL private data */
        libnal_send:        klbnal_send,
        libnal_send_pages:  klbnal_send_pages,
        libnal_recv:        klbnal_recv,
        libnal_recv_pages:  klbnal_recv_pages,
        libnal_dist:        klbnal_dist
};
