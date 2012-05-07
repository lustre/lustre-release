/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/darwin/darwin-tcpip.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_DARWIN_TCPIP_H__
#define __LIBCFS_DARWIN_TCPIP_H__

#ifdef __KERNEL__
#include <sys/socket.h>

#ifdef __DARWIN8__

struct socket;

typedef void    (*so_upcall)(socket_t sock, void* arg, int waitf);

#define CFS_SOCK_UPCALL         0x1
#define CFS_SOCK_DOWN           0x2

#define CFS_SOCK_MAGIC          0xbabeface

typedef struct cfs_socket {
        socket_t        s_so;
        int             s_magic;
        int             s_flags;
        so_upcall       s_upcall;
        void           *s_upcallarg;
} cfs_socket_t;


/* cfs_socket_t to bsd socket */
#define C2B_SOCK(s)             ((s)->s_so)     

static inline int get_sock_intopt(socket_t so, int opt)
{
        int     val, len;
        int     rc;

        /*
         * sock_getsockopt will take a lock(mutex) for socket,
         * so it can be blocked. So be careful while using 
         * them.
         */
        len = sizeof(val);
        rc = sock_getsockopt(so, SOL_SOCKET, opt, &val, &len);
        assert(rc == 0);
        return val;
}

#define SOCK_ERROR(s)           get_sock_intopt(C2B_SOCK(s), SO_ERROR)        
/* #define SOCK_WMEM_QUEUED(s)     (0) */
#define SOCK_WMEM_QUEUED(s)     get_sock_intopt(C2B_SOCK(s), SO_NWRITE)
/* XXX Liang: no reliable way to get it in Darwin8.x */
#define SOCK_TEST_NOSPACE(s)    (0)

void libcfs_sock_set_cb(cfs_socket_t *sock, so_upcall callback, void *arg);
void libcfs_sock_reset_cb(cfs_socket_t *sock);

#else /* !__DARWIN8__ */

#define SOCK_WMEM_QUEUED(so)    ((so)->so_snd.sb_cc)
#define SOCK_ERROR(so)          ((so)->so_error)

#define SOCK_TEST_NOSPACE(so)   (sbspace(&(so)->so_snd) < (so)->so_snd.sb_lowat)

#endif /* !__DARWIN8__ */

#endif	/* __KERNEL END */

#endif  /* __XNU_CFS_TYPES_H__ */
