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

#ifndef REDSTORM
#include <fcntl.h>
#include <netdb.h>
#include <syscall.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#else
#include <sys/socket.h>
#include <catamount/data.h>
#endif

#include "lutil.h"

#ifdef CRAY_PORTALS
void portals_debug_dumplog(void){};
#endif

unsigned int portal_subsystem_debug = ~0 - (S_PORTALS | S_QSWNAL | S_SOCKNAL |
                                            S_GMNAL | S_OPENIBNAL);
unsigned int portal_debug = 0;

struct task_struct     *current;
ptl_handle_ni_t         tcpnal_ni;
ptl_nid_t               tcpnal_mynid;

void *inter_module_get(char *arg)
{
        if (!strcmp(arg, "tcpnal_ni"))
                return &tcpnal_ni;
        else if (!strcmp(arg, "ldlm_cli_cancel_unused"))
                return ldlm_cli_cancel_unused;
        else if (!strcmp(arg, "ldlm_namespace_cleanup"))
                return ldlm_namespace_cleanup;
        else if (!strcmp(arg, "ldlm_replay_locks"))
                return ldlm_replay_locks;
        else
                return NULL;
}

char *portals_nid2str(int nal, ptl_nid_t nid, char *str)
{
        if (nid == PTL_NID_ANY) {
                snprintf(str, PTL_NALFMT_SIZE - 1, "%s",
                         "PTL_NID_ANY");
                return str;
        }

        switch(nal){
#ifndef CRAY_PORTALS
        case TCPNAL:
                /* userspace NAL */
        case OPENIBNAL:
        case SOCKNAL:
                snprintf(str, PTL_NALFMT_SIZE - 1, "%u:%u.%u.%u.%u",
                         (__u32)(nid >> 32), HIPQUAD(nid));
                break;
        case QSWNAL:
        case GMNAL:
                snprintf(str, PTL_NALFMT_SIZE - 1, "%u:%u",
                         (__u32)(nid >> 32), (__u32)nid);
                break;
#endif
        default:
                snprintf(str, PTL_NALFMT_SIZE - 1, "?%d? %llx",
                         nal, (long long)nid);
                break;
        }
        return str;
}

char *portals_id2str(int nal, ptl_process_id_t id, char *str)
{
        switch(nal){
#ifndef CRAY_PORTALS
        case TCPNAL:
                /* userspace NAL */
        case OPENIBNAL:
        case SOCKNAL:
                snprintf(str, PTL_NALFMT_SIZE - 1, "%u:%u.%u.%u.%u,%u",
                         (__u32)(id.nid >> 32), HIPQUAD((id.nid)) , id.pid);
                break;
        case QSWNAL:
        case GMNAL:
                snprintf(str, PTL_NALFMT_SIZE - 1, "%u:%u,%u",
                         (__u32)(id.nid >> 32), (__u32)id.nid, id.pid);
                break;
#endif
        default:
                snprintf(str, PTL_NALFMT_SIZE - 1, "?%d? %llx,%lx",
                         nal, (long long)id.nid, (long)id.pid );
                break;
        }
        return str;
}

#ifndef REDSTORM
/*
 * random number generator stuff
 */
static int _rand_dev_fd = -1;

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
                printf("LibLustre: Warning: fail to get local IPv4 address\n");
                return 0;
        }

        ip = ntohl(*((int *) *hptr->h_addr_list));

        return ip;
}

void liblustre_init_random()
{
        int seed;
        struct timeval tv;

        _rand_dev_fd = syscall(SYS_open, "/dev/urandom", O_RDONLY);
        if (_rand_dev_fd >= 0) {
                if (syscall(SYS_read, _rand_dev_fd, &seed, sizeof(int)) ==
                    sizeof(int)) {
                        srand(seed);
                        return;
                }
                syscall(SYS_close, _rand_dev_fd);
                _rand_dev_fd = -1;
        }

        gettimeofday(&tv, NULL);
        srand(tv.tv_sec + tv.tv_usec + getpid() + __swab32(get_ipv4_addr()));
}

void get_random_bytes(void *buf, int size)
{
        char *p = buf;
        LASSERT(size >= 0);

        if (_rand_dev_fd >= 0) {
                if (syscall(SYS_read, _rand_dev_fd, buf, size) == size)
                        return;
                syscall(SYS_close, _rand_dev_fd);
                _rand_dev_fd = -1;
        }

        while (size--) 
                *p++ = rand();
}

static void init_capability(int *res)
{
        cap_t syscap;
        cap_flag_value_t capval;
        int i;

        *res = 0;

        syscap = cap_get_proc();
        if (!syscap) {
                printf("Liblustre: Warning: failed to get system capability, "
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
}

void liblustre_set_nal_nid()
{
        pid_t pid;
        uint32_t ip;
        struct in_addr in;

        /* need to setup mynid before tcpnal initialization */
        /* a meaningful nid could help debugging */
        ip = get_ipv4_addr();
        if (ip == 0)
                get_random_bytes(&ip, sizeof(ip));
        pid = getpid() & 0xffffffff;
        tcpnal_mynid = ((uint64_t)ip << 32) | pid;

        in.s_addr = htonl(ip);
        printf("LibLustre: TCPNAL NID: %016llx (%s:%u)\n", 
               tcpnal_mynid, inet_ntoa(in), pid);
}

#else /* REDSTORM */

void liblustre_init_random()
{
        struct timeval tv;
        UINT32 nodeid;

        gettimeofday(&tv, NULL);
        nodeid = _my_pnid;
        srand(tv.tv_sec + tv.tv_usec + getpid() + __swab32(nodeid));
}

void get_random_bytes(void *buf, int size)
{
        char *p = buf;
        LASSERT(size >= 0);

        while (size--) 
                *p++ = rand();
}

static void init_capability(int *res)
{
        *res = 0;
}

void liblustre_set_nal_nid()
{
        pid_t pid;
        uint32_t ip;

        ip = _my_pnid;
        if (ip & 0xFF)
                ip <<= 8;
        pid = getpid() & 0xFF;
        tcpnal_mynid = ip | pid;
        printf("LibLustre: NAL NID: %08x (%u)\n", 
               tcpnal_mynid, pid);
}

#endif /* REDSOTRM */

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
        current->fs = &current->__fs;
        current->fs->umask = umask(0777);
        umask(current->fs->umask);

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
        int max_interfaces;
        int rc;
        ENTRY;

        rc = PtlInit(&max_interfaces);
        if (rc != PTL_OK) {
                CERROR("PtlInit failed: %d\n", rc);
                RETURN (-ENXIO);
        }
        RETURN(0);
}

extern void ptlrpc_exit_portals(void);
void cleanup_lib_portals()
{
        ptlrpc_exit_portals();
}

int
libcfs_nal_cmd(struct portals_cfg *pcfg)
{
        /* handle portals command if we want */
        return 0;
}
