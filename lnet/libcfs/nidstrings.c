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

#define DEBUG_SUBSYSTEM S_PORTALS

#include <portals/p30.h>
#include <libcfs/kp30.h>
#ifndef __KERNEL__
#include <netdb.h>
#endif

/* CAVEAT VENDITOR! Keep the canonical string representation of nets/nids
 * consistent in all conversion functions.  Some code fragments are copied
 * around for the sake of clarity...
 */

/* CAVEAT EMPTOR! Racey temporary buffer allocation!
 * Choose the number of nidstrings to support the MAXIMUM expected number of
 * concurrent users.  If there are more, the returned string will be volatile.
 * NB this number must allow for a process to be descheduled for a timeslice
 * between getting its string and using it.
 */

#define PTL_NIDSTR_COUNT  128     /* # of nidstrings */
#define PTL_NIDSTR_SIZE   32      /* size of each one (see below for usage) */

static char      libcfs_nidstrings[PTL_NIDSTR_COUNT][PTL_NIDSTR_SIZE];
static int       libcfs_nidstring_idx = 0;

#ifdef __KERNEL__
static spinlock_t libcfs_nidstring_lock;

void libcfs_init_nidstrings (void)
{
        spin_lock_init(&libcfs_nidstring_lock);
}

# define NIDSTR_LOCK(f)   spin_lock_irqsave(&libcfs_nidstring_lock, f)
# define NIDSTR_UNLOCK(f) spin_unlock_irqrestore(&libcfs_nidstring_lock, f)
#else
# define NIDSTR_LOCK(f)   (f)                   /* avoid unused var warnings */
# define NIDSTR_UNLOCK(f) (f)
#endif

static char *
libcfs_next_nidstring (void)
{
	char          *str;
	unsigned long  flags;

	NIDSTR_LOCK(flags);

	str = libcfs_nidstrings[libcfs_nidstring_idx++];
	if (libcfs_nidstring_idx ==
	    sizeof(libcfs_nidstrings)/sizeof(libcfs_nidstrings[0]))
		libcfs_nidstring_idx = 0;

        NIDSTR_UNLOCK(flags);
	return str;
}

#if !CRAY_PORTALS
static int  libcfs_lo_str2addr(char *str, int nob, __u32 *addr);
static void libcfs_ip_addr2str(__u32 addr, char *str);
static int  libcfs_ip_str2addr(char *str, int nob, __u32 *addr);
static void libcfs_num_addr2str(__u32 addr, char *str);
static int  libcfs_num_str2addr(char *str, int nob, __u32 *addr);

struct nalstrfns {
        int          nf_nal;
        char        *nf_name;
        char        *nf_modname;
        void       (*nf_addr2str)(__u32 addr, char *str);
        int        (*nf_str2addr)(char *str, int nob, __u32 *addr);
};

static struct nalstrfns  libcfs_nalstrfns[] = {
        {.nf_nal      = LONAL,     
         .nf_name     = "lo",         
         .nf_modname  = "klonal",  
         .nf_addr2str = libcfs_num_addr2str,  
         .nf_str2addr = libcfs_lo_str2addr},
        {.nf_nal      = SOCKNAL,    
         .nf_name     = "tcp",     
         .nf_modname  = "ksocknal",  
         .nf_addr2str = libcfs_ip_addr2str,  
         .nf_str2addr = libcfs_ip_str2addr},
        {.nf_nal      = OPENIBNAL, 
         .nf_name     = "openib", 
         .nf_modname  = "kopenibnal",  
         .nf_addr2str = libcfs_ip_addr2str,  
         .nf_str2addr = libcfs_ip_str2addr},
        {.nf_nal      = IIBNAL,    
         .nf_name     = "iib",       
         .nf_modname  = "kiibnal",  
         .nf_addr2str = libcfs_ip_addr2str,  
         .nf_str2addr = libcfs_ip_str2addr},
        {.nf_nal      = VIBNAL,    
         .nf_name     = "vib",       
         .nf_modname  = "kvibnal",  
         .nf_addr2str = libcfs_ip_addr2str,  
         .nf_str2addr = libcfs_ip_str2addr},
        {.nf_nal      = RANAL,     
         .nf_name     = "ra",         
         .nf_modname  = "kranal",  
         .nf_addr2str = libcfs_ip_addr2str,  
         .nf_str2addr = libcfs_ip_str2addr},
        {.nf_nal      = QSWNAL,   
         .nf_name     = "elan",       
         .nf_modname  = "kqswnal", 
         .nf_addr2str = libcfs_num_addr2str, 
         .nf_str2addr = libcfs_num_str2addr},
        {.nf_nal      = GMNAL,     
         .nf_name     = "gm",         
         .nf_modname  = "kgmnal", 
         .nf_addr2str = libcfs_num_addr2str, 
         .nf_str2addr = libcfs_num_str2addr},
};

const int libcfs_nnalstrfns = sizeof(libcfs_nalstrfns)/sizeof(libcfs_nalstrfns[0]);

int
libcfs_lo_str2addr(char *str, int nob, __u32 *addr)
{
        *addr = 0;
        return 1;
}

void
libcfs_ip_addr2str(__u32 addr, char *str)
{
#if !defined(__KERNEL__) && defined HAVE_GETHOSTBYNAME
        __u32           netip = htonl(addr);
        struct hostent *he = gethostbyaddr(&netip, sizeof(netip), AF_INET);
        
        if (he != NULL) {
                snprintf(str, PTL_NIDSTR_SIZE, "%s", he->h_name);
                return;
        }
#endif
        snprintf(str, PTL_NIDSTR_SIZE, "%u.%u.%u.%u",
                 (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                 (addr >> 8) & 0xff, addr & 0xff);
}

/* CAVEAT EMPTOR XscanfX
 * I use "%n" at the end of a sscanf format to detect trailing junk.  However
 * sscanf may return immediately if it sees the terminating '0' in a string, so
 * I initialise the %n variable to the expected length.  If sscanf sets it;
 * fine, if it doesn't, then the scan ended at the end of the string, which is
 * fine too :) */

int
libcfs_ip_str2addr(char *str, int nob, __u32 *addr)
{
        int   a;
        int   b;
        int   c;
        int   d;
        int   n = nob;                          /* XscanfX */

        /* numeric IP? */
        if (sscanf(str, "%u.%u.%u.%u%n", &a, &b, &c, &d, &n) >= 4 &&
            n == nob &&
            (a & ~0xff) == 0 && (b & ~0xff) == 0 &&
            (c & ~0xff) == 0 && (d & ~0xff) == 0) {
                *addr = ((a<<24)|(b<<16)|(c<<8)|d);
                return 1;
        }

#if !defined(__KERNEL__) && defined HAVE_GETHOSTBYNAME
        /* known hostname? */
        if (('a' <= str[0] && str[0] <= 'z') ||
            ('A' <= str[0] && str[0] <= 'Z')) {
                char *tmp;

                PORTAL_ALLOC(tmp, nob + 1);
                if (tmp != NULL) {
                        struct hostent *he;

                        memcpy(tmp, str, nob);
                        tmp[nob] = 0;

                        he = gethostbyname(tmp);

                        PORTAL_FREE(tmp, nob);

                        if (he != NULL) {
                                __u32 ip = *(__u32 *)he->h_addr;
                                
                                *addr = ntohl(ip);
                                return 1;
                        }
                }
        }
#endif
        return 0;
}

void
libcfs_num_addr2str(__u32 addr, char *str)
{
        snprintf(str, PTL_NIDSTR_SIZE, "%u", addr);
}

int
libcfs_num_str2addr(char *str, int nob, __u32 *addr)
{
        __u32   a;
        int     n = nob;
        
        if (sscanf(str, "%u%n", &a, &n) < 1 ||
            n != nob)
                return 0;
        
        *addr = a;
        return 1;
}

struct nalstrfns *
libcfs_nal2nalstrfns(int nal) 
{
        int    i;
        
        for (i = 0; i < libcfs_nnalstrfns; i++)
                if (nal == libcfs_nalstrfns[i].nf_nal)
                        return &libcfs_nalstrfns[i];

        return NULL;
}

struct nalstrfns *
libcfs_name2nalstrfns(char *name)
{
        int    i;
        
        for (i = 0; i < libcfs_nnalstrfns; i++)
                if (!strcmp(libcfs_nalstrfns[i].nf_name, name))
                        return &libcfs_nalstrfns[i];

        return NULL;
}

int
libcfs_isknown_nal(int nal)
{
        return libcfs_nal2nalstrfns(nal) != NULL;
}

char *
libcfs_nal2modname(int nal) 
{
        struct nalstrfns *nf = libcfs_nal2nalstrfns(nal);

        return (nf == NULL) ? NULL : nf->nf_modname;
}

char *
libcfs_nal2str(int nal) 
{
        char           *str;
        struct nalstrfns *nf = libcfs_nal2nalstrfns(nal);
        
        if (nf != NULL)
                return nf->nf_name;
        
        str = libcfs_next_nidstring();
        snprintf(str, PTL_NIDSTR_SIZE, "?%u?", nal);
        return str;
}

int
libcfs_str2nal(char *str)
{
        struct nalstrfns *nf = libcfs_name2nalstrfns(str);
        
        if (nf != NULL)
                return nf->nf_nal;
        
        return -1;
}

char *
libcfs_net2str(__u32 net)
{
        int             nal = PTL_NETNAL(net);
        int             num = PTL_NETNUM(net);
        struct nalstrfns *nf = libcfs_nal2nalstrfns(nal);
	char           *str = libcfs_next_nidstring();

        if (nf == NULL) 
                snprintf(str, PTL_NIDSTR_SIZE, "<%u:%u>", nal, num);
        else if (num == 0)
                snprintf(str, PTL_NIDSTR_SIZE, "%s", nf->nf_name);
        else
                snprintf(str, PTL_NIDSTR_SIZE, "%s%u", nf->nf_name, num);

        return str;
}

char *
libcfs_nid2str(ptl_nid_t nid)
{
        __u32           addr = PTL_NIDADDR(nid);
        __u32           net = PTL_NIDNET(nid);
        int             nal = PTL_NETNAL(net);
        int             nnum = PTL_NETNUM(net);
        struct nalstrfns *nf;
	char           *str;
        int             nob;

        if (nid == PTL_NID_ANY)
                return "PTL_NID_ANY";

        nf = libcfs_nal2nalstrfns(PTL_NETNAL(net));
	str = libcfs_next_nidstring();

        if (nf == NULL)
                snprintf(str, PTL_NIDSTR_SIZE, "%x@<%u:%u>", addr, nal, nnum);
        else {
                nf->nf_addr2str(addr, str);
                nob = strlen(str);
                if (nnum == 0)
                        snprintf(str + nob, PTL_NIDSTR_SIZE - nob, "@%s",
                                 nf->nf_name);
                else
                        snprintf(str + nob, PTL_NIDSTR_SIZE - nob, "@%s%u",
                                 nf->nf_name, nnum);
        }

        return str;
}

static struct nalstrfns *
libcfs_str2net_internal(char *str, __u32 *net)
{
        struct nalstrfns *nf;
        int               nob;
        int               netnum;
        unsigned int      i;

        for (i = 0; i < libcfs_nnalstrfns; i++) {
                nf = &libcfs_nalstrfns[i];

                if (!strncmp(str, nf->nf_name, strlen(nf->nf_name)))
                        break;
        }

        if (i == libcfs_nnalstrfns)
                return NULL;
        
        nob = strlen(nf->nf_name);

        if (strlen(str) == nob) {
                netnum = 0;
        } else {
                if (nf->nf_nal == LONAL) /* net number not allowed */
                        return NULL;
          
                str += nob;
                i = strlen(str);
                if (sscanf(str, "%u%n", &netnum, &i) < 1 ||
                    i != strlen(str))
                        return NULL;
        }
        
        *net = PTL_MKNET(nf->nf_nal, netnum);
        return nf;
}

__u32
libcfs_str2net(char *str)
{
        __u32  net;
        
        if (libcfs_str2net_internal(str, &net) != NULL)
                return net;
        
        return PTL_NIDNET(PTL_NID_ANY);
}

ptl_nid_t
libcfs_str2nid(char *str)
{
        char             *sep = strchr(str, '@');
        struct nalstrfns *nf;
        __u32             net;
        __u32             addr;

        if (sep != NULL) {
                nf = libcfs_str2net_internal(sep + 1, &net);
                if (nf == NULL)
                        return PTL_NID_ANY;
        } else {
                sep = str + strlen(str);
                net = PTL_MKNET(SOCKNAL, 0);
                nf = libcfs_nal2nalstrfns(SOCKNAL);
                LASSERT (nf != NULL);
        }

        if (!nf->nf_str2addr(str, sep - str, &addr))
                return PTL_NID_ANY;
        
        return PTL_MKNID(net, addr);
}
#else  /* CRAY_PORTALS */
int
libcfs_isknown_nal(int nal)
{
        return 1;
}

char *
libcfs_nal2modname(int nal)
{
        return "cray";
}

char *
libcfs_nal2str(int nal)
{
        return "cray";
}

int
libcfs_str2nal(char *str)
{
        return 0;
}

char *
libcfs_net2str(__u32 net)
{
        return "cray";
}

char *
libcfs_nid2str(ptl_nid_t nid)
{
        char    *str = libcfs_next_nidstring();
        
	snprintf(str, PTL_NIDSTR_SIZE, "%llx", (unsigned long long)nid);
}

__u32
libcfs_str2net(char *str)
{
        return 0;
}

ptl_nid_t
libcfs_str2nid(char *str)
{
        long long nid;
        long long mask;
        int       n = strlen(str);
        
        if (sscanf(str,"%llx%n", &nid, &n) >= 1 &&
            n == strlen(str))
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
        char *str = libcfs_next_nidstring();
        
        snprintf(str, PTL_NIDSTR_SIZE, "%u-%s", id.pid, libcfs_nid2str(id.nid));
        return str;
}

int
libcfs_str2anynid(ptl_nid_t *nidp, char *str)
{
        if (!strcmp(str, "*")) {
                *nidp = PTL_NID_ANY;
                return 1;
        }

        *nidp = libcfs_str2nid(str);
        return *nidp != PTL_NID_ANY;
}

#ifdef __KERNEL__
EXPORT_SYMBOL(libcfs_isknown_nal);
EXPORT_SYMBOL(libcfs_nal2modname);
EXPORT_SYMBOL(libcfs_nal2str);
EXPORT_SYMBOL(libcfs_str2nal);
EXPORT_SYMBOL(libcfs_net2str);
EXPORT_SYMBOL(libcfs_nid2str);
EXPORT_SYMBOL(libcfs_str2net);
EXPORT_SYMBOL(libcfs_str2nid);
EXPORT_SYMBOL(libcfs_id2str);
EXPORT_SYMBOL(libcfs_str2anynid);
#endif
