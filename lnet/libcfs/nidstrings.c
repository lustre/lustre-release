/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

# define DEBUG_SUBSYSTEM S_PORTALS

#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>

/* CAVEAT EMPTOR! Racey temporary buffer allocation!
 * Choose the number of nidstrings to support the MAXIMUM expected number of
 * concurrent users.  If there are more, the returned string will be volatile.
 * NB this number must allow for a process to be descheduled for a timeslice
 * between getting its string and using it.
 */

static char        libcfs_nidstrings[128][PTL_NALFMT_SIZE];
static int         libcfs_nidstring_idx;
static spinlock_t  libcfs_nidstring_lock;

void
libcfs_init_nidstrings (void)
{
        spin_lock_init(&libcfs_nidstring_lock);
}

static char *
libcfs_next_nidstring (void)
{
	unsigned long  flags;
	char          *str;
	
	spin_lock_irqsave(&libcfs_nidstring_lock, flags);
	
	str = libcfs_nidstrings[libcfs_nidstring_idx++];
	if (libcfs_nidstring_idx ==
	    sizeof(libcfs_nidstrings)/sizeof(libcfs_nidstrings[0]))
		libcfs_nidstring_idx = 0;

	spin_unlock_irqrestore(&libcfs_nidstring_lock, flags);

	return str;
}

#if !CRAY_PORTALS
static void libcfs_lo_addr2str(__u32 addr, char *str);
static int  libcfs_lo_str2addr(char *str, int nob, __u32 *addr);
static void libcfs_ip_addr2str(__u32 addr, char *str);
static int  libcfs_ip_str2addr(char *str, int nob, __u32 *addr);
static void libcfs_num_addr2str(__u32 addr, char *str);
static int  libcfs_num_str2addr(char *str, int nob, __u32 *addr);

struct nettype {
        int          type;
        char        *name;
        void       (*addr2str)(__u32 addr, char *str);
        int        (*str2addr)(char *str, int nob, __u32 *addr);
};

static struct nettype  libcfs_nettypes[] = {
        {LONAL,     "lo",     libcfs_lo_addr2str,  libcfs_lo_str2addr},
        {SOCKNAL,   "tcp",    libcfs_ip_addr2str,  libcfs_ip_str2addr},
        {OPENIBNAL, "openib", libcfs_ip_addr2str,  libcfs_ip_str2addr},
        {IIBNAL,    "iib",    libcfs_ip_addr2str,  libcfs_ip_str2addr},
        {VIBNAL,    "vib",    libcfs_ip_addr2str,  libcfs_ip_str2addr},
        {RANAL,     "ra",     libcfs_ip_addr2str,  libcfs_ip_str2addr},
        {QSWNAL,    "elan",   libcfs_num_addr2str, libcfs_num_str2addr},
        {GMNAL,     "gm",     libcfs_num_addr2str, libcfs_num_str2addr},
};

const int libcfs_nnettypes = sizeof(libcfs_nettypes)/sizeof(libcfs_nettypes[0]);

void
libcfs_lo_addr2str(__u32 addr, char *str)
{
        /* don't print anything */
}

int
libcfs_lo_str2addr(char *str, int nob, __u32 *addr)
{
        if (nob != 0)                           /* expecting the empty string */
                return 0;
        
        *addr = 0;
        return 1;
}

void
libcfs_ip_addr2str(__u32 addr, char *str)
{
        snprintf(str, PTL_NALFMT_SIZE, "%u.%u.%u.%u", HIPQUAD(addr));
}

int
libcfs_ip_str2addr(char *str, int nob, __u32 *addr)
{
        int   a;
        int   b;
        int   c;
        int   d;
        int   n;
        
        if (sscanf(str, "%u.%u.%u.%u%n", &a, &b, &c, &d, &n) < 4 ||
            n != nob)
                return 0;

        if ((a & ~0xff) != 0 || (b & ~0xff) != 0 ||
            (c & ~0xff) != 0 || (d & ~0xff) != 0)
                return 0;
        
        *addr = ((a<<24)|(b<<16)|(c<<8)|d);
        return 1;
}

void
libcfs_num_addr2str(__u32 addr, char *str)
{
        snprintf(str, PTL_NALFMT_SIZE, "%u", addr);
}

int
libcfs_num_str2addr(char *str, int nob, __u32 *addr)
{
        __u32   a;
        int     n;
        
        if (sscanf(str, "%u%n", &a, &n) < 1 ||
            n != nob)
                return 0;
        
        *addr = a;
        return 1;
}

struct nettype *
libcfs_get_nettype(int type) 
{
        int    i;
        
        for (i = 0; i < libcfs_nnettypes; i++)
                if (type == libcfs_nettypes[i].type)
                        return &libcfs_nettypes[i];

        return NULL;
}

int
libcfs_isknown_nettype(int type)
{
        return libcfs_get_nettype(type) != NULL;
}

char *
libcfs_nettype2str(int type) 
{
        char           *str;
        struct nettype *nt = libcfs_get_nettype(type);
        
        if (nt != NULL)
                return nt->name;
        
        str = libcfs_next_nidstring();
        snprintf(str, PTL_NALFMT_SIZE, "?%u?", type);
        return str;
}

char *
libcfs_nid2str(ptl_nid_t nid)
{
	char           *str = libcfs_next_nidstring();
	__u32           lo  = (__u32)nid;
	__u32           hi  = (__u32)(nid>>32);
        int             nnum  = hi & 0xffff;
        int             ntype = (hi >> 16) & 0xffff;
        struct nettype *nettype = libcfs_get_nettype(ntype);
        int             nob;

        if (nid == PTL_NID_ANY) {
                snprintf(str, PTL_NALFMT_SIZE, "%s", "PTL_NID_ANY");
        } else if (nettype == NULL) {
                snprintf(str, PTL_NALFMT_SIZE, "%x@%u.%u", lo, nnum, ntype);
        } else {
	        nettype->addr2str(lo, str);
		nob = strlen(str);
		if (nnum == 0)
			snprintf(str + nob, PTL_NALFMT_SIZE - nob,
				 "@%s", nettype->name);
		else
			snprintf(str + nob, PTL_NALFMT_SIZE - nob,
				 "@%s%u", nettype->name, nnum);
        }

        return str;
}

ptl_nid_t
libcfs_str2nid(char *str)
{
        char           *sep = strchr(str, '@');
        struct nettype *nettype;
        int             nob;
        int             net;
        __u32           addr;
        int             i;

        if (sep == NULL) {
                sep = str + strlen(str);
                net = 0;
                nettype = libcfs_get_nettype(SOCKNAL);
                LASSERT (nettype != NULL);
        } else {
                for (i = 0; i < libcfs_nnettypes; i++) {
                        nettype = &libcfs_nettypes[i];

                        if (!strncmp(sep + 1, nettype->name, 
				     strlen(nettype->name)))
                                break;
                }
                if (i == libcfs_nnettypes)
                        return PTL_NID_ANY;

                nob = strlen(nettype->name);

                if (strlen(sep + 1) == nob)
                        net = 0;
                else if (nettype->type == LONAL || /* net number not allowed */
			 sscanf(sep + 1 + nob, "%u%n", &net, &i) < 1 ||
                         i != strlen(sep + 1 + nob) ||
                         (net & ~0xffff) != 0)
                        return PTL_NID_ANY;
        }
        
        if (!nettype->str2addr(str, sep - str, &addr))
                return PTL_NID_ANY;
        
        return (((__u64)((nettype->type<<16)|net))<<32)|addr;
}
#else  /* CRAY_PORTALS */
int
libcfs_isknown_nettype(int type)
{
        return 1;
}

char *
libcfs_nettype2str(int type)
{
        return "cray";
}

char *
libcfs_nid2str(ptl_nid_t nid)
{
        char    *str = libcfs_next_nidstring();
        
	snprintf(str, PTL_NALFMT_SIZE, "%llx", (unsigned long long)nid);
}

ptl_nid_t
libcfs_str2nid(char *str)
{
        long long nid;
        long long mask;
        int       n;
        
        if (sscanf(str,"%llx%n", &nid, &n) >= 1 &&
            n == strlen(str))
                goto out;
        
        if (sscanf(str,"%llu%n", &nid, &n) >= 1 &&
            n = strlen(str))
                goto out;
        
        return PTL_NID_ANY;
        
 out:
        /* overflow check in case ptl_nid_t smaller than __u64 */
        mask = 0;
        mask = (~mask)<<(sizeof(nid)*8);
        
        if ((nid & mask) != 0)
                return PTL_NID_ANY;

        return nid;
}
#endif

char *
libcfs_id2str(ptl_process_id_t id)
{
        char *str = libcfs_nid2str(id.nid);
	int   len = strlen(str);

        snprintf(str + len, PTL_NALFMT_SIZE - len, "-%u", id.pid);
        return str;
}

EXPORT_SYMBOL(libcfs_isknown_nettype);
EXPORT_SYMBOL(libcfs_nettype2str);
EXPORT_SYMBOL(libcfs_nid2str);
EXPORT_SYMBOL(libcfs_id2str);
