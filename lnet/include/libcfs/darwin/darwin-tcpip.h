/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 *
 * Basic library routines. 
 *
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
