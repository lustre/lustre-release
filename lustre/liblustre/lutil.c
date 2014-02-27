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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <libcfs/libcfs.h>
#include <lustre/lustre_idl.h>
#include <liblustre.h>
#include <lnet/lnet.h>
#include <lustre_dlm.h>
#include "lutil.h"

struct task_struct *current;

/*
 * random number generator stuff
 */

#ifdef HAVE_GETHOSTBYNAME
static int get_ipv4_addr()
{
        struct utsname myname;
        struct hostent *hptr;
        int ip;

        if (uname(&myname) < 0)
                return 0;

        hptr = gethostbyname(myname.nodename);
        if (hptr == NULL ||
            hptr->h_addrtype != AF_INET ||
            *hptr->h_addr_list == NULL) {
                CWARN("Warning: fail to get local IPv4 address\n");
                return 0;
        }

        ip = ntohl(*((int *) *hptr->h_addr_list));

        return ip;
}
#endif

void liblustre_init_random()
{
        int seed[2];
        struct timeval tv;

#ifdef LIBLUSTRE_USE_URANDOM
        int _rand_dev_fd;
        _rand_dev_fd = syscall(SYS_open, "/dev/urandom", O_RDONLY);
        if (_rand_dev_fd >= 0) {
                if (syscall(SYS_read, _rand_dev_fd,
                            &seed, sizeof(seed)) == sizeof(seed)) {
                        cfs_srand(seed[0], seed[1]);
                        syscall(SYS_close, _rand_dev_fd);
                        return;
                }
                syscall(SYS_close, _rand_dev_fd);
        }
#endif /* LIBLUSTRE_USE_URANDOM */

#ifdef HAVE_GETHOSTBYNAME
        seed[0] = get_ipv4_addr();
#else
        seed[0] = _my_pnid;
#endif
        gettimeofday(&tv, NULL);
        cfs_srand(tv.tv_sec ^ __swab32(seed[0]), tv.tv_usec ^__swab32(getpid()));
}

static void init_capability(__u32 *res)
{
#ifdef HAVE_LIBCAP
        cap_t syscap;
        cap_flag_value_t capval;
        int i;

        *res = 0;

        syscap = cap_get_proc();
        if (!syscap) {
                CWARN("Warning: failed to get system capability, "
                      "set to minimal\n");
                return;
        }

        for (i = 0; i < sizeof(cap_value_t) * 8; i++) {
                if (!cap_get_flag(syscap, i, CAP_EFFECTIVE, &capval)) {
                        if (capval == CAP_SET) {
                                *res |= 1 << i;
                        }
                }
        }
#else
	/*
	 * set fake cap flags to ship to linux server
	 * from client platforms that have none (eg. catamount)
	 *  full capability for root
	 *  no capability for anybody else
	 */
#define FAKE_ROOT_CAP 0x1ffffeff
#define FAKE_USER_CAP 0

	*res = (current->fsuid == 0) ? FAKE_ROOT_CAP: FAKE_USER_CAP;
#endif
}

int in_group_p(gid_t gid)
{
        int i;

        if (gid == current->fsgid)
                return 1;

        for (i = 0; i < current->ngroups; i++) {
                if (gid == current->groups[i])
                        return 1;
        }

        return 0;
}

int liblustre_init_current(char *comm)
{
        current = malloc(sizeof(*current));
        if (!current) {
                CERROR("Not enough memory\n");
                return -ENOMEM;
        }

        strncpy(current->comm, comm, sizeof(current->comm));
        current->pid = getpid();
        current->gid = getgid();
        current->fsuid = geteuid();
        current->fsgid = getegid();

        current->max_groups = sysconf(_SC_NGROUPS_MAX);
        current->groups = malloc(sizeof(gid_t) * current->max_groups);
        if (!current->groups) {
                CERROR("Not enough memory\n");
                return -ENOMEM;
        }
        current->ngroups = getgroups(current->max_groups, current->groups);
        if (current->ngroups < 0) {
                perror("Error getgroups");
                return -EINVAL;
        }

        init_capability(&current->cap_effective);

        return 0;
}

void cfs_cap_raise(cfs_cap_t cap)
{
        current->cap_effective |= (1 << cap);
}

void cfs_cap_lower(cfs_cap_t cap)
{
        current->cap_effective &= ~(1 << cap);
}

int cfs_cap_raised(cfs_cap_t cap)
{
        return current->cap_effective & (1 << cap);
}

cfs_cap_t cfs_curproc_cap_pack(void) {
	return current->cap_effective;
}

void cfs_curproc_cap_unpack(cfs_cap_t cap) {
	current->cap_effective = cap;
}

int cfs_capable(cfs_cap_t cap)
{
        return cfs_cap_raised(cap);
}

int init_lib_portals()
{
        int rc;
        ENTRY;

        rc = libcfs_debug_init(5 * 1024 * 1024);
        if (rc != 0) {
                CERROR("libcfs_debug_init() failed: %d\n", rc);
                RETURN (-ENXIO);
        }

        rc = LNetInit();
        if (rc != 0) {
                CERROR("LNetInit() failed: %d\n", rc);
                RETURN (-ENXIO);
        }
        RETURN(0);
}

extern void ptlrpc_exit_portals(void);
void cleanup_lib_portals()
{
        libcfs_debug_cleanup();
        ptlrpc_exit_portals();
}
