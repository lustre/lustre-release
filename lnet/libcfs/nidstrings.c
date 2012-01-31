/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/libcfs/nidstrings.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lnet.h>
#include <libcfs/kp30.h>
#ifndef __KERNEL__
#ifdef HAVE_GETHOSTBYNAME
# include <netdb.h>
#endif
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

static char      libcfs_nidstrings[LNET_NIDSTR_COUNT][LNET_NIDSTR_SIZE];
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
# define NIDSTR_LOCK(f)   (f=0)                 /* avoid unused var warnings */
# define NIDSTR_UNLOCK(f) (f=0)
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

static int  libcfs_lo_str2addr(const char *str, int nob, __u32 *addr);
static void libcfs_ip_addr2str(__u32 addr, char *str);
static int  libcfs_ip_str2addr(const char *str, int nob, __u32 *addr);
static void libcfs_decnum_addr2str(__u32 addr, char *str);
static void libcfs_hexnum_addr2str(__u32 addr, char *str);
static int  libcfs_num_str2addr(const char *str, int nob, __u32 *addr);

struct netstrfns {
        int          nf_type;
        char        *nf_name;
        char        *nf_modname;
        void       (*nf_addr2str)(__u32 addr, char *str);
        int        (*nf_str2addr)(const char *str, int nob, __u32 *addr);
};

static struct netstrfns  libcfs_netstrfns[] = {
        {/* .nf_type      */  LOLND,
         /* .nf_name      */  "lo",
         /* .nf_modname   */  "klolnd",
         /* .nf_addr2str  */  libcfs_decnum_addr2str,
         /* .nf_str2addr  */  libcfs_lo_str2addr},
        {/* .nf_type      */  SOCKLND,
         /* .nf_name      */  "tcp",
         /* .nf_modname   */  "ksocklnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr},
        {/* .nf_type      */  O2IBLND,
         /* .nf_name      */  "o2ib",
         /* .nf_modname   */  "ko2iblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr},
        {/* .nf_type      */  CIBLND,
         /* .nf_name      */  "cib",
         /* .nf_modname   */  "kciblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr},
        {/* .nf_type      */  OPENIBLND,
         /* .nf_name      */  "openib",
         /* .nf_modname   */  "kopeniblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr},
        {/* .nf_type      */  IIBLND,
         /* .nf_name      */  "iib",
         /* .nf_modname   */  "kiiblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr},
        {/* .nf_type      */  VIBLND,
         /* .nf_name      */  "vib",
         /* .nf_modname   */  "kviblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr},
        {/* .nf_type      */  RALND,
         /* .nf_name      */  "ra",
         /* .nf_modname   */  "kralnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr},
        {/* .nf_type      */  QSWLND,
         /* .nf_name      */  "elan",
         /* .nf_modname   */  "kqswlnd",
         /* .nf_addr2str  */  libcfs_decnum_addr2str,
         /* .nf_str2addr  */  libcfs_num_str2addr},
        {/* .nf_type      */  GMLND,
         /* .nf_name      */  "gm",
         /* .nf_modname   */  "kgmlnd",
         /* .nf_addr2str  */  libcfs_hexnum_addr2str,
         /* .nf_str2addr  */  libcfs_num_str2addr},
        {/* .nf_type      */  MXLND,
         /* .nf_name      */  "mx",
         /* .nf_modname   */  "kmxlnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr},
        {/* .nf_type      */  PTLLND,
         /* .nf_name      */  "ptl",
         /* .nf_modname   */  "kptllnd",
         /* .nf_addr2str  */  libcfs_decnum_addr2str,
         /* .nf_str2addr  */  libcfs_num_str2addr},
        {/* .nf_type      */  GNILND,
         /* .nf_name      */  "gni",
         /* .nf_modname   */  "kgnilnd",
         /* .nf_addr2str  */  libcfs_decnum_addr2str,
         /* .nf_str2addr  */  libcfs_num_str2addr},
        /* placeholder for net0 alias.  It MUST BE THE LAST ENTRY */
        {/* .nf_type      */  -1},
};

const int libcfs_nnetstrfns = sizeof(libcfs_netstrfns)/sizeof(libcfs_netstrfns[0]);

int
libcfs_lo_str2addr(const char *str, int nob, __u32 *addr)
{
        *addr = 0;
        return 1;
}

void
libcfs_ip_addr2str(__u32 addr, char *str)
{
#if 0   /* never lookup */
#if !defined(__KERNEL__) && defined HAVE_GETHOSTBYNAME
        __u32           netip = htonl(addr);
        struct hostent *he = gethostbyaddr(&netip, sizeof(netip), AF_INET);

        if (he != NULL) {
                snprintf(str, LNET_NIDSTR_SIZE, "%s", he->h_name);
                return;
        }
#endif
#endif
        snprintf(str, LNET_NIDSTR_SIZE, "%u.%u.%u.%u",
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
libcfs_ip_str2addr(const char *str, int nob, __u32 *addr)
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

                LIBCFS_ALLOC(tmp, nob + 1);
                if (tmp != NULL) {
                        struct hostent *he;

                        memcpy(tmp, str, nob);
                        tmp[nob] = 0;

                        he = gethostbyname(tmp);

                        LIBCFS_FREE(tmp, nob);

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
libcfs_decnum_addr2str(__u32 addr, char *str)
{
        snprintf(str, LNET_NIDSTR_SIZE, "%u", addr);
}

void
libcfs_hexnum_addr2str(__u32 addr, char *str)
{
        snprintf(str, LNET_NIDSTR_SIZE, "0x%x", addr);
}

int
libcfs_num_str2addr(const char *str, int nob, __u32 *addr)
{
        int     n;

        n = nob;
        if (sscanf(str, "0x%x%n", addr, &n) >= 1 && n == nob)
                return 1;

        n = nob;
        if (sscanf(str, "0X%x%n", addr, &n) >= 1 && n == nob)
                return 1;

        n = nob;
        if (sscanf(str, "%u%n", addr, &n) >= 1 && n == nob)
                return 1;

        return 0;
}

struct netstrfns *
libcfs_lnd2netstrfns(int lnd)
{
        int    i;

        if (lnd >= 0)
                for (i = 0; i < libcfs_nnetstrfns; i++)
                        if (lnd == libcfs_netstrfns[i].nf_type)
                                return &libcfs_netstrfns[i];

        return NULL;
}

struct netstrfns *
libcfs_name2netstrfns(const char *name)
{
        int    i;

        for (i = 0; i < libcfs_nnetstrfns; i++)
                if (libcfs_netstrfns[i].nf_type >= 0 &&
                    !strcmp(libcfs_netstrfns[i].nf_name, name))
                        return &libcfs_netstrfns[i];

        return NULL;
}

int
libcfs_isknown_lnd(int type)
{
        return libcfs_lnd2netstrfns(type) != NULL;
}

char *
libcfs_lnd2modname(int lnd)
{
        struct netstrfns *nf = libcfs_lnd2netstrfns(lnd);

        return (nf == NULL) ? NULL : nf->nf_modname;
}

char *
libcfs_lnd2str(int lnd)
{
        char           *str;
        struct netstrfns *nf = libcfs_lnd2netstrfns(lnd);

        if (nf != NULL)
                return nf->nf_name;

        str = libcfs_next_nidstring();
        snprintf(str, LNET_NIDSTR_SIZE, "?%u?", lnd);
        return str;
}

int
libcfs_str2lnd(const char *str)
{
        struct netstrfns *nf = libcfs_name2netstrfns(str);

        if (nf != NULL)
                return nf->nf_type;

        return -1;
}

char *
libcfs_net2str(__u32 net)
{
        int               lnd = LNET_NETTYP(net);
        int               num = LNET_NETNUM(net);
        struct netstrfns *nf  = libcfs_lnd2netstrfns(lnd);
        char             *str = libcfs_next_nidstring();

        if (nf == NULL)
                snprintf(str, LNET_NIDSTR_SIZE, "<%u:%u>", lnd, num);
        else if (num == 0)
                snprintf(str, LNET_NIDSTR_SIZE, "%s", nf->nf_name);
        else
                snprintf(str, LNET_NIDSTR_SIZE, "%s%u", nf->nf_name, num);

        return str;
}

char *
libcfs_nid2str(lnet_nid_t nid)
{
        __u32             addr = LNET_NIDADDR(nid);
        __u32             net = LNET_NIDNET(nid);
        int               lnd = LNET_NETTYP(net);
        int               nnum = LNET_NETNUM(net);
        struct netstrfns *nf;
        char             *str;
        int               nob;

        if (nid == LNET_NID_ANY)
                return "LNET_NID_ANY";

        nf = libcfs_lnd2netstrfns(lnd);
        str = libcfs_next_nidstring();

        if (nf == NULL)
                snprintf(str, LNET_NIDSTR_SIZE, "%x@<%u:%u>", addr, lnd, nnum);
        else {
                nf->nf_addr2str(addr, str);
                nob = strlen(str);
                if (nnum == 0)
                        snprintf(str + nob, LNET_NIDSTR_SIZE - nob, "@%s",
                                 nf->nf_name);
                else
                        snprintf(str + nob, LNET_NIDSTR_SIZE - nob, "@%s%u",
                                 nf->nf_name, nnum);
        }

        return str;
}

static struct netstrfns *
libcfs_str2net_internal(const char *str, __u32 *net)
{
        struct netstrfns *nf = NULL;
        int               nob;
        int               netnum;
        int               i;

        for (i = 0; i < libcfs_nnetstrfns; i++) {
                nf = &libcfs_netstrfns[i];
                if (nf->nf_type >= 0 &&
                    !strncmp(str, nf->nf_name, strlen(nf->nf_name)))
                        break;
        }

        if (i == libcfs_nnetstrfns)
                return NULL;

        nob = strlen(nf->nf_name);

        if (strlen(str) == (unsigned int)nob) {
                netnum = 0;
        } else {
                if (nf->nf_type == LOLND) /* net number not allowed */
                        return NULL;

                str += nob;
                i = strlen(str);
                if (sscanf(str, "%u%n", &netnum, &i) < 1 ||
                    i != (int)strlen(str))
                        return NULL;
        }

        *net = LNET_MKNET(nf->nf_type, netnum);
        return nf;
}

__u32
libcfs_str2net(const char *str)
{
        __u32  net;

        if (libcfs_str2net_internal(str, &net) != NULL)
                return net;

        return LNET_NIDNET(LNET_NID_ANY);
}

lnet_nid_t
libcfs_str2nid(const char *str)
{
        const char       *sep = strchr(str, '@');
        struct netstrfns *nf;
        __u32             net;
        __u32             addr;

        if (sep != NULL) {
                nf = libcfs_str2net_internal(sep + 1, &net);
                if (nf == NULL)
                        return LNET_NID_ANY;
        } else {
                sep = str + strlen(str);
                net = LNET_MKNET(SOCKLND, 0);
                nf = libcfs_lnd2netstrfns(SOCKLND);
                LASSERT (nf != NULL);
        }

        if (!nf->nf_str2addr(str, sep - str, &addr))
                return LNET_NID_ANY;

        return LNET_MKNID(net, addr);
}

char *
libcfs_id2str(lnet_process_id_t id)
{
        char *str = libcfs_next_nidstring();

        if (id.pid == LNET_PID_ANY) {
                snprintf(str, LNET_NIDSTR_SIZE,
                         "LNET_PID_ANY-%s", libcfs_nid2str(id.nid));
                return str;
        }

        snprintf(str, LNET_NIDSTR_SIZE, "%s%u-%s",
                 ((id.pid & LNET_PID_USERFLAG) != 0) ? "U" : "",
                 (id.pid & ~LNET_PID_USERFLAG), libcfs_nid2str(id.nid));
        return str;
}

int
libcfs_str2anynid(lnet_nid_t *nidp, const char *str)
{
        if (!strcmp(str, "*")) {
                *nidp = LNET_NID_ANY;
                return 1;
        }

        *nidp = libcfs_str2nid(str);
        return *nidp != LNET_NID_ANY;
}

#ifdef __KERNEL__
void
libcfs_setnet0alias(int lnd)
{
        struct netstrfns *nf = libcfs_lnd2netstrfns(lnd);
        struct netstrfns *nf0 = &libcfs_netstrfns[libcfs_nnetstrfns - 1];

        /* Ghastly hack to allow LNET to inter-operate with portals.
         * NET type 0 becomes an alias for whatever local network we have, and
         * this assignment here means we can parse and print its NIDs */

        LASSERT (nf != NULL);
        LASSERT (nf0->nf_type < 0);

        nf0->nf_name = "zero";//nf->nf_name;
        nf0->nf_modname = nf->nf_modname;
        nf0->nf_addr2str = nf->nf_addr2str;
        nf0->nf_str2addr = nf->nf_str2addr;
        mb();
        nf0->nf_type = 0;
}

EXPORT_SYMBOL(libcfs_isknown_lnd);
EXPORT_SYMBOL(libcfs_lnd2modname);
EXPORT_SYMBOL(libcfs_lnd2str);
EXPORT_SYMBOL(libcfs_str2lnd);
EXPORT_SYMBOL(libcfs_net2str);
EXPORT_SYMBOL(libcfs_nid2str);
EXPORT_SYMBOL(libcfs_str2net);
EXPORT_SYMBOL(libcfs_str2nid);
EXPORT_SYMBOL(libcfs_id2str);
EXPORT_SYMBOL(libcfs_str2anynid);
EXPORT_SYMBOL(libcfs_setnet0alias);
#else  /* __KERNEL__ */
void
libcfs_setnet0alias(int lnd)
{
        LCONSOLE_ERROR_MSG(0x125, "Liblustre cannot interoperate with old "
                           "Portals.\nportals_compatibility must be set to "
                           "'none'.\n");
}
#endif
