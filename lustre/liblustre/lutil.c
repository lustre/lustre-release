/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2004 Cluster File Systems, Inc.
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

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>

#include <fcntl.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <syscall.h>
#include <sys/utsname.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <sys/socket.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_CATAMOUNT_DATA_H
#include <catamount/data.h>
#endif

#include "lutil.h"


unsigned int libcfs_subsystem_debug = ~0 - (S_PORTALS | S_NAL);
unsigned int libcfs_debug = 0;

struct task_struct     *current;

void *inter_module_get(char *arg)
{
        if (!strcmp(arg, "ldlm_cli_cancel_unused"))
                return ldlm_cli_cancel_unused;
        else if (!strcmp(arg, "ldlm_namespace_cleanup"))
                return ldlm_namespace_cleanup;
        else if (!strcmp(arg, "ldlm_replay_locks"))
                return ldlm_replay_locks;
        else
                return NULL;
}

/*
 * random number generator stuff
 */
#ifdef LIBLUSTRE_USE_URANDOM
static int _rand_dev_fd = -1;
#endif

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
        int seed;
        struct timeval tv;

#ifdef LIBLUSTRE_USE_URANDOM
        _rand_dev_fd = syscall(SYS_open, "/dev/urandom", O_RDONLY);
        if (_rand_dev_fd >= 0) {
                if (syscall(SYS_read, _rand_dev_fd,
                            &seed, sizeof(int)) == sizeof(int)) {
                        srand(seed);
                        return;
                }
                syscall(SYS_close, _rand_dev_fd);
                _rand_dev_fd = -1;
        }
#endif /* LIBLUSTRE_USE_URANDOM */

#ifdef HAVE_GETHOSTBYNAME
        seed = get_ipv4_addr();
#else
        seed = _my_pnid;
#endif
        gettimeofday(&tv, NULL);
        srand(tv.tv_sec + tv.tv_usec + getpid() + __swab32(seed));
}

void get_random_bytes(void *buf, int size)
{
        char *p = buf;
        LASSERT(size >= 0);

#ifdef LIBLUSTRE_USE_URANDOM
        if (_rand_dev_fd >= 0) {
                if (syscall(SYS_read, _rand_dev_fd, buf, size) == size)
                        return;
                syscall(SYS_close, _rand_dev_fd);
                _rand_dev_fd = -1;
        }
#endif

        while (size--) 
                *p++ = rand();
}

static void init_capability(int *res)
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
        current->fsuid = geteuid();
        current->fsgid = getegid();
        memset(&current->pending, 0, sizeof(current->pending));

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

void generate_random_uuid(unsigned char uuid_out[16])
{
        get_random_bytes(uuid_out, sizeof(uuid_out));
}

int init_lib_portals()
{
        int rc;
        ENTRY;

        rc = LNetInit();
        if (rc != 0) {
                CERROR("LNetInit failed: %d\n", rc);
                RETURN (-ENXIO);
        }
        RETURN(0);
}

extern void ptlrpc_exit_portals(void);
void cleanup_lib_portals()
{
        ptlrpc_exit_portals();
}
