/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
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

#ifndef _LONAL_H
#define _LONAL_H
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/uio.h>
#include <linux/init.h>

#define DEBUG_SUBSYSTEM S_NAL

#include <libcfs/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>

#define KLOD_IOV        153401
#define KLOD_KIOV       153402

typedef struct
{
        unsigned int     klod_type;
        unsigned int     klod_niov;
        size_t           klod_offset;
        size_t           klod_nob;
        union {
                struct iovec  *iov;
                ptl_kiov_t    *kiov;
        }                klod_iov;
} klo_desc_t;

ptl_err_t klonal_startup (ptl_ni_t *ni);
void klonal_shutdown (ptl_ni_t *ni);
ptl_err_t klonal_send (ptl_ni_t *ni, void *private,
                       ptl_msg_t *ptlmsg, ptl_hdr_t *hdr,
                       int type, ptl_process_id_t tgt, int routing,
                       unsigned int payload_niov, 
                       struct iovec *payload_iov,
                       size_t payload_offset, size_t payload_nob);
ptl_err_t klonal_send_pages (ptl_ni_t *ni, void *private,
                             ptl_msg_t *ptlmsg, ptl_hdr_t *hdr,
                             int type, ptl_process_id_t tgt, int routing,
                             unsigned int payload_niov, 
                             ptl_kiov_t *payload_kiov,
                             size_t payload_offset, size_t payload_nob);
ptl_err_t klonal_recv(ptl_ni_t *ni, void *private,
                      ptl_msg_t *ptlmsg, unsigned int niov,
                      struct iovec *iov, size_t offset,
                      size_t mlen, size_t rlen);
ptl_err_t klonal_recv_pages(ptl_ni_t *ni, void *private,
                            ptl_msg_t *ptlmsg, unsigned int niov,
                            ptl_kiov_t *kiov, size_t offset,
                            size_t mlen, size_t rlen);

#endif /* _LONAL_H */
