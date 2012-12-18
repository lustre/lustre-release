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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/nidstrings.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include <lnet/lnet.h>
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
static cfs_spinlock_t libcfs_nidstring_lock;

void libcfs_init_nidstrings (void)
{
        cfs_spin_lock_init(&libcfs_nidstring_lock);
}

# define NIDSTR_LOCK(f)   cfs_spin_lock_irqsave(&libcfs_nidstring_lock, f)
# define NIDSTR_UNLOCK(f) cfs_spin_unlock_irqrestore(&libcfs_nidstring_lock, f)
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
static int  libcfs_ip_parse(char *str, int len, cfs_list_t *list);
static int  libcfs_num_parse(char *str, int len, cfs_list_t *list);
static int  libcfs_ip_match(__u32 addr, cfs_list_t *list);
static int  libcfs_num_match(__u32 addr, cfs_list_t *list);

struct netstrfns {
        int          nf_type;
        char        *nf_name;
        char        *nf_modname;
        void       (*nf_addr2str)(__u32 addr, char *str);
        int        (*nf_str2addr)(const char *str, int nob, __u32 *addr);
        int        (*nf_parse_addrlist)(char *str, int len,
                                        cfs_list_t *list);
        int        (*nf_match_addr)(__u32 addr, cfs_list_t *list);
};

static struct netstrfns  libcfs_netstrfns[] = {
        {/* .nf_type      */  LOLND,
         /* .nf_name      */  "lo",
         /* .nf_modname   */  "klolnd",
         /* .nf_addr2str  */  libcfs_decnum_addr2str,
         /* .nf_str2addr  */  libcfs_lo_str2addr,
         /* .nf_parse_addr*/  libcfs_num_parse,
         /* .nf_match_addr*/  libcfs_num_match},
        {/* .nf_type      */  SOCKLND,
         /* .nf_name      */  "tcp",
         /* .nf_modname   */  "ksocklnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr,
         /* .nf_parse_addrlist*/  libcfs_ip_parse,
         /* .nf_match_addr*/  libcfs_ip_match},
        {/* .nf_type      */  O2IBLND,
         /* .nf_name      */  "o2ib",
         /* .nf_modname   */  "ko2iblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr,
         /* .nf_parse_addrlist*/  libcfs_ip_parse,
         /* .nf_match_addr*/  libcfs_ip_match},
        {/* .nf_type      */  CIBLND,
         /* .nf_name      */  "cib",
         /* .nf_modname   */  "kciblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr,
         /* .nf_parse_addrlist*/  libcfs_ip_parse,
         /* .nf_match_addr*/  libcfs_ip_match},
        {/* .nf_type      */  OPENIBLND,
         /* .nf_name      */  "openib",
         /* .nf_modname   */  "kopeniblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr,
         /* .nf_parse_addrlist*/  libcfs_ip_parse,
         /* .nf_match_addr*/  libcfs_ip_match},
        {/* .nf_type      */  IIBLND,
         /* .nf_name      */  "iib",
         /* .nf_modname   */  "kiiblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr,
         /* .nf_parse_addrlist*/  libcfs_ip_parse,
         /* .nf_match_addr*/  libcfs_ip_match},
        {/* .nf_type      */  VIBLND,
         /* .nf_name      */  "vib",
         /* .nf_modname   */  "kviblnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr,
         /* .nf_parse_addrlist*/  libcfs_ip_parse,
         /* .nf_match_addr*/  libcfs_ip_match},
        {/* .nf_type      */  RALND,
         /* .nf_name      */  "ra",
         /* .nf_modname   */  "kralnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr,
         /* .nf_parse_addrlist*/  libcfs_ip_parse,
         /* .nf_match_addr*/  libcfs_ip_match},
        {/* .nf_type      */  QSWLND,
         /* .nf_name      */  "elan",
         /* .nf_modname   */  "kqswlnd",
         /* .nf_addr2str  */  libcfs_decnum_addr2str,
         /* .nf_str2addr  */  libcfs_num_str2addr,
         /* .nf_parse_addrlist*/  libcfs_num_parse,
         /* .nf_match_addr*/  libcfs_num_match},
        {/* .nf_type      */  GMLND,
         /* .nf_name      */  "gm",
         /* .nf_modname   */  "kgmlnd",
         /* .nf_addr2str  */  libcfs_hexnum_addr2str,
         /* .nf_str2addr  */  libcfs_num_str2addr,
         /* .nf_parse_addrlist*/  libcfs_num_parse,
         /* .nf_match_addr*/  libcfs_num_match},
        {/* .nf_type      */  MXLND,
         /* .nf_name      */  "mx",
         /* .nf_modname   */  "kmxlnd",
         /* .nf_addr2str  */  libcfs_ip_addr2str,
         /* .nf_str2addr  */  libcfs_ip_str2addr,
         /* .nf_parse_addrlist*/  libcfs_ip_parse,
         /* .nf_match_addr*/  libcfs_ip_match},
        {/* .nf_type      */  PTLLND,
         /* .nf_name      */  "ptl",
         /* .nf_modname   */  "kptllnd",
         /* .nf_addr2str  */  libcfs_decnum_addr2str,
         /* .nf_str2addr  */  libcfs_num_str2addr,
         /* .nf_parse_addrlist*/  libcfs_num_parse,
         /* .nf_match_addr*/  libcfs_num_match},
        {/* .nf_type      */  GNILND,
         /* .nf_name      */  "gni",
         /* .nf_modname   */  "kgnilnd",
         /* .nf_addr2str  */  libcfs_decnum_addr2str,
         /* .nf_str2addr  */  libcfs_num_str2addr,
         /* .nf_parse_addrlist*/  libcfs_num_parse,
         /* .nf_match_addr*/  libcfs_num_match},
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
libcfs_namenum2netstrfns(const char *name)
{
        struct netstrfns *nf;
        int               i;

        for (i = 0; i < libcfs_nnetstrfns; i++) {
                nf = &libcfs_netstrfns[i];
                if (nf->nf_type >= 0 &&
                    !strncmp(name, nf->nf_name, strlen(nf->nf_name)))
                        return nf;
        }
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
                return "<?>";

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
        struct netstrfns *nf;
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

        if (!nf->nf_str2addr(str, (int)(sep - str), &addr))
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

/**
 * Nid range list syntax.
 * \verbatim
 *
 * <nidlist>         :== <nidrange> [ ' ' <nidrange> ]
 * <nidrange>        :== <addrrange> '@' <net>
 * <addrrange>       :== '*' |
 *                       <ipaddr_range> |
 *                       <numaddr_range>
 * <ipaddr_range>    :== <numaddr_range>.<numaddr_range>.<numaddr_range>.
 *                       <numaddr_range>
 * <numaddr_range>   :== <number> |
 *                       <expr_list>
 * <expr_list>       :== '[' <range_expr> [ ',' <range_expr>] ']'
 * <range_expr>      :== <number> |
 *                       <number> '-' <number> |
 *                       <number> '-' <number> '/' <number>
 * <net>             :== <netname> | <netname><number>
 * <netname>         :== "lo" | "tcp" | "o2ib" | "cib" | "openib" | "iib" |
 *                       "vib" | "ra" | "elan" | "mx" | "ptl"
 * \endverbatim
 */

/**
 * Structure to represent NULL-less strings.
 */
struct lstr {
        char *ls_str;
        int ls_len;
};

/**
 * Structure to represent \<nidrange\> token of the syntax.
 *
 * One of this is created for each \<net\> parsed.
 */
struct nidrange {
        /**
         * Link to list of this structures which is built on nid range
         * list parsing.
         */
        cfs_list_t nr_link;
        /**
         * List head for addrrange::ar_link.
         */
        cfs_list_t nr_addrranges;
        /**
         * Flag indicating that *@<net> is found.
         */
        int nr_all;
        /**
         * Pointer to corresponding element of libcfs_netstrfns.
         */
        struct netstrfns *nr_netstrfns;
        /**
         * Number of network. E.g. 5 if \<net\> is "elan5".
         */
        int nr_netnum;
};

/**
 * Structure to represent \<addrrange\> token of the syntax.
 */
struct addrrange {
        /**
         * Link to nidrange::nr_addrranges.
         */
        cfs_list_t ar_link;
        /**
         * List head for numaddr_range::nar_link.
         */
        cfs_list_t ar_numaddr_ranges;
};

/**
 * Structure to represent \<numaddr_range\> token of the syntax.
 */
struct numaddr_range {
        /**
         * Link to addrrange::ar_numaddr_ranges.
         */
        cfs_list_t nar_link;
        /**
         * List head for range_expr::re_link.
         */
        cfs_list_t nar_range_exprs;
};

/**
 * Structure to represent \<range_expr\> token of the syntax.
 */
struct range_expr {
        /**
         * Link to numaddr_range::nar_range_exprs.
         */
        cfs_list_t re_link;
        __u32 re_lo;
        __u32 re_hi;
        __u32 re_stride;
};

int
cfs_iswhite(char c)
{
        switch (c) {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
                return 1;
        default:
                break;
        }
        return 0;
}

/*
 * Extracts tokens from strings.
 *
 * Looks for \a delim in string \a next, sets \a res to point to
 * substring before the delimiter, sets \a next right after the found
 * delimiter.
 *
 * \retval 1 if \a res points to a string of non-whitespace characters
 * \retval 0 otherwise
 */
static int
gettok(struct lstr *next, char delim, struct lstr *res)
{
        char *end;

        if (next->ls_str == NULL)
                return 0;

        /* skip leading white spaces */
        while (next->ls_len) {
                if (!cfs_iswhite(*next->ls_str))
                        break;
                next->ls_str ++;
                next->ls_len --;
        }
        if (next->ls_len == 0)
                /* whitespaces only */
                return 0;

        if (*next->ls_str == delim)
                /* first non-writespace is the delimiter */
                return 0;

        res->ls_str = next->ls_str;
        end = memchr(next->ls_str, delim, next->ls_len);
        if (end == NULL) {
                /* there is no the delimeter in the string */
                end = next->ls_str + next->ls_len;
                next->ls_str = NULL;
        } else {
                next->ls_str = end + 1;
                next->ls_len -= (end - res->ls_str + 1);
        }

        /* skip ending whitespaces */
        while (--end != res->ls_str)
                if (!cfs_iswhite(*end))
                        break;

        res->ls_len = end - res->ls_str + 1;
        return 1;
}

/**
 * Converts string to integer.
 *
 * Accepts decimal and hexadecimal number recordings.
 *
 * \retval 1 if first \a nob chars of \a str convert to decimal or
 * hexadecimal integer in the range [\a min, \a max]
 * \retval 0 otherwise
 */
static int
libcfs_str2num_check(const char *str, int nob, unsigned *num,
                     unsigned min, unsigned max)
{
        int n;
        char nstr[12];

        n = nob;
        if (sscanf(str, "%u%n", num, &n) != 1 || n != nob)
                if (sscanf(str, "0x%x%n", num, &n) != 1 || n != nob)
                        if (sscanf(str, "0X%x%n", num, &n) != 1 || n != nob)
                                return 0;
        sprintf(nstr, "%u", *num);
        if (n != strlen(nstr) || memcmp(nstr, str, n)) {
                sprintf(nstr, "0x%x", *num);
                if (n != strlen(nstr) || memcmp(nstr, str, n)) {
                        sprintf(nstr, "0X%x", *num);
                        if (n != strlen(nstr) || memcmp(nstr, str, n))
                                return 0;
                }
        }
        if (*num < min || *num > max)
                return 0;
        return 1;
}

/**
 * Parses \<range_expr\> token of the syntax.
 *
 * \retval pointer to allocated range_expr and initialized
 * range_expr::re_lo, range_expr::re_hi and range_expr:re_stride if \a
 `* src parses to
 * \<number\> |
 * \<number\> '-' \<number\> |
 * \<number\> '-' \<number\> '/' \<number\>
 * \retval NULL othersize
 */
static struct range_expr *
parse_range_expr(struct lstr *src, unsigned min, unsigned max)
{
        struct lstr tok;
        struct range_expr *expr;

        LIBCFS_ALLOC(expr, sizeof(struct range_expr));
        if (expr == NULL)
                return NULL;

        if (libcfs_str2num_check(src->ls_str, src->ls_len, &expr->re_lo,
                                 min, max)) {
                /* <number> is parsed */
                expr->re_hi = expr->re_lo;
                expr->re_stride = 1;
                return expr;
        }

        if (!gettok(src, '-', &tok))
                goto failed;
        if (!libcfs_str2num_check(tok.ls_str, tok.ls_len, &expr->re_lo,
                                  min, max))
                goto failed;
        /* <number> - */
        if (libcfs_str2num_check(src->ls_str, src->ls_len, &expr->re_hi,
                                 min, max)) {
                /* <number> - <number> is parsed */
                expr->re_stride = 1;
                return expr;
        }

        /* go to check <number> '-' <number> '/' <number> */
        if (gettok(src, '/', &tok)) {
                if (!libcfs_str2num_check(tok.ls_str, tok.ls_len,
                                          &expr->re_hi, min, max))
                        goto failed;
                /* <number> - <number> / ... */
                if (libcfs_str2num_check(src->ls_str, src->ls_len,
                                         &expr->re_stride, min, max))
                        /* <number> - <number> / <number> is parsed */
                        return expr;
        }

failed:
        LIBCFS_FREE(expr, sizeof(struct range_expr));
        return NULL;
}

/**
 * Parses \<expr_list\> token of the syntax.
 *
 * \retval 1 if \a str parses to '[' \<range_expr\> [ ',' \<range_expr\>] ']'
 * \retval 0 otherwise
 */
static int
parse_expr_list(struct lstr *str, cfs_list_t *list,
                unsigned min, unsigned max)
{
        struct lstr res;
        struct range_expr *range;

        if (str->ls_str[0] != '[' || str->ls_str[str->ls_len - 1] != ']')
                return 0;
        str->ls_str ++;
        str->ls_len -= 2;

        while (str->ls_str) {
                if (gettok(str, ',', &res) == 0)
                        return 0;
                range = parse_range_expr(&res, min, max);
                if (range == NULL)
                        return 0;
                cfs_list_add_tail(&range->re_link, list);
        }
        return 1;
}

/**
 * Parses \<numaddr_range\> token of the syntax.
 *
 * \retval 1 if \a str parses to \<number\> | \<expr_list\>
 * \retval 0 otherwise
 */
static int
num_parse(char *str, int len,
          cfs_list_t *list, unsigned min, unsigned max)
{
        __u32 num;
        struct lstr src;
        struct numaddr_range *numaddr;

        src.ls_str = str;
        src.ls_len = len;

        LIBCFS_ALLOC(numaddr, sizeof(struct numaddr_range));
        if (numaddr == NULL)
                return 0;
        cfs_list_add_tail(&numaddr->nar_link, list);
        CFS_INIT_LIST_HEAD(&numaddr->nar_range_exprs);

        if (libcfs_str2num_check(src.ls_str, src.ls_len, &num, min, max)) {
                /* <number> */
                struct range_expr *expr;

                LIBCFS_ALLOC(expr, sizeof(struct range_expr));
                if (expr == NULL)
                        return 0;

                expr->re_lo = expr->re_hi = num;
                expr->re_stride = 1;
                cfs_list_add_tail(&expr->re_link, &numaddr->nar_range_exprs);
                return 1;
        }

        return parse_expr_list(&src, &numaddr->nar_range_exprs, min, max);
}

/**
 * Nf_parse_addrlist method for networks using numeric addresses.
 *
 * Examples of such networks are gm and elan.
 *
 * \retval 1 if \a str parsed to numeric address
 * \retval 0 otherwise
 */
static int
libcfs_num_parse(char *str, int len, cfs_list_t *list)
{
        return num_parse(str, len, list, 0, MAX_NUMERIC_VALUE);
}

/**
 * Nf_parse_addrlist method for networks using ip addresses.
 *
 * Examples of such networks are tcp and o2ib.
 *
 * \retval 1 if \a str parsed to ip address
 * \retval 0 otherwise
 */
static int
libcfs_ip_parse(char *str, int len,
                cfs_list_t *list)
{
        struct lstr src, res;
        int i;

        src.ls_str = str;
        src.ls_len = len;
        i = 0;
        while (src.ls_str) {
                if (gettok(&src, '.', &res) == 0)
                        return 0;
                if (!num_parse(res.ls_str, res.ls_len, list, 0, 255))
                        return 0;
                i ++;
        }

        return (i == 4) ? 1 : 0;
}

/**
 * Parses \<addrrange\> token on the syntax.
 *
 * Allocates struct addrrange and links to \a nidrange via
 * (nidrange::nr_addrranges)
 *
 * \retval 1 if \a src parses to '*' | \<ipaddr_range\> | \<numaddr_range\>
 * \retval 0 otherwise
 */
static int
parse_addrange(const struct lstr *src, struct nidrange *nidrange)
{
        struct addrrange *addrrange;

        if (src->ls_len == 1 && src->ls_str[0] == '*') {
                nidrange->nr_all = 1;
                return 1;
        }

        LIBCFS_ALLOC(addrrange, sizeof(struct addrrange));
        if (addrrange == NULL)
                return 0;
        cfs_list_add_tail(&addrrange->ar_link, &nidrange->nr_addrranges);
        CFS_INIT_LIST_HEAD(&addrrange->ar_numaddr_ranges);

        return nidrange->nr_netstrfns->nf_parse_addrlist(src->ls_str,
                                                src->ls_len,
                                                &addrrange->ar_numaddr_ranges);
}

/**
 * Finds or creates struct nidrange.
 *
 * Checks if \a src is a valid network name, looks for corresponding
 * nidrange on the ist of nidranges (\a nidlist), creates new struct
 * nidrange if it is not found.
 *
 * \retval pointer to struct nidrange matching network specified via \a src
 * \retval NULL if \a src does not match any network
 */
static struct nidrange *
add_nidrange(const struct lstr *src,
             cfs_list_t *nidlist)
{
        struct netstrfns *nf;
        struct nidrange *nr;
        int endlen;
        unsigned netnum;

        if (src->ls_len >= LNET_NIDSTR_SIZE)
                return NULL;

        nf = libcfs_namenum2netstrfns(src->ls_str);
        if (nf == NULL)
                return NULL;
        endlen = src->ls_len - strlen(nf->nf_name);
        if (endlen == 0)
                /* network name only, e.g. "elan" or "tcp" */
                netnum = 0;
        else {
                /* e.g. "elan25" or "tcp23", refuse to parse if
                 * network name is not appended with decimal or
                 * hexadecimal number */
                if (!libcfs_str2num_check(src->ls_str + strlen(nf->nf_name),
                                          endlen, &netnum,
                                          0, MAX_NUMERIC_VALUE))
                        return NULL;
        }

        cfs_list_for_each_entry(nr, nidlist, nr_link) {
                if (nr->nr_netstrfns != nf)
                        continue;
                if (nr->nr_netnum != netnum)
                        continue;
                return nr;
        }

        LIBCFS_ALLOC(nr, sizeof(struct nidrange));
        if (nr == NULL)
                return NULL;
        cfs_list_add_tail(&nr->nr_link, nidlist);
        CFS_INIT_LIST_HEAD(&nr->nr_addrranges);
        nr->nr_netstrfns = nf;
        nr->nr_all = 0;
        nr->nr_netnum = netnum;

        return nr;
}

/**
 * Parses \<nidrange\> token of the syntax.
 *
 * \retval 1 if \a src parses to \<addrrange\> '@' \<net\>
 * \retval 0 otherwise
 */
static int
parse_nidrange(struct lstr *src, cfs_list_t *nidlist)
{
        struct lstr addrrange, net, tmp;
        struct nidrange *nr;

        tmp = *src;
        if (gettok(src, '@', &addrrange) == 0)
                goto failed;

        if (gettok(src, '@', &net) == 0 || src->ls_str != NULL)
                goto failed;

        nr = add_nidrange(&net, nidlist);
        if (nr == NULL)
                goto failed;

        if (!parse_addrange(&addrrange, nr))
                goto failed;

        return 1;
 failed:
        CWARN("can't parse nidrange: \"%.*s\"\n", tmp.ls_len, tmp.ls_str);
        return 0;
}

/**
 * Frees range_expr structures of \a list.
 *
 * \retval none
 */
static void
free_range_exprs(cfs_list_t *list)
{
        cfs_list_t *pos, *next;

        cfs_list_for_each_safe(pos, next, list) {
                cfs_list_del(pos);
                LIBCFS_FREE(cfs_list_entry(pos, struct range_expr, re_link),
                            sizeof(struct range_expr));
        }
}

/**
 * Frees numaddr_range structures of \a list.
 *
 * For each struct numaddr_range structure found on \a list it frees
 * range_expr list attached to it and frees the numddr_range itself.
 *
 * \retval none
 */
static void
free_numaddr_ranges(cfs_list_t *list)
{
        cfs_list_t *pos, *next;
        struct numaddr_range *numaddr;

        cfs_list_for_each_safe(pos, next, list) {
                numaddr = cfs_list_entry(pos, struct numaddr_range, nar_link);
                free_range_exprs(&numaddr->nar_range_exprs);
                cfs_list_del(pos);
                LIBCFS_FREE(numaddr, sizeof(struct numaddr_range));
        }
}

/**
 * Frees addrrange structures of \a list.
 *
 * For each struct addrrange structure found on \a list it frees
 * numaddr_range list attached to it and frees the addrrange itself.
 *
 * \retval none
 */
static void
free_addrranges(cfs_list_t *list)
{
        cfs_list_t *pos, *next;
        struct addrrange *ar;

        cfs_list_for_each_safe(pos, next, list) {
                ar = cfs_list_entry(pos, struct addrrange, ar_link);
                free_numaddr_ranges(&ar->ar_numaddr_ranges);
                cfs_list_del(pos);
                LIBCFS_FREE(ar, sizeof(struct addrrange));
        }
}

/**
 * Frees nidrange strutures of \a list.
 *
 * For each struct nidrange structure found on \a list it frees
 * addrrange list attached to it and frees the nidrange itself.
 *
 * \retval none
 */
void
cfs_free_nidlist(cfs_list_t *list)
{
        cfs_list_t *pos, *next;
        struct nidrange *nr;

        cfs_list_for_each_safe(pos, next, list) {
                nr = cfs_list_entry(pos, struct nidrange, nr_link);
                free_addrranges(&nr->nr_addrranges);
                cfs_list_del(pos);
                LIBCFS_FREE(nr, sizeof(struct nidrange));
        }
}

/**
 * Parses nid range list.
 *
 * Parses with rigorous syntax and overflow checking \a str into
 * \<nidrange\> [ ' ' \<nidrange\> ], compiles \a str into set of
 * structures and links that structure to \a nidlist. The resulting
 * list can be used to match a NID againts set of NIDS defined by \a
 * str.
 * \see cfs_match_nid
 *
 * \retval 1 on success
 * \retval 0 otherwise
 */
int
cfs_parse_nidlist(char *str, int len, cfs_list_t *nidlist)
{
        struct lstr src, res;
        int rc;
        ENTRY;

        src.ls_str = str;
        src.ls_len = len;
        CFS_INIT_LIST_HEAD(nidlist);
        while (src.ls_str) {
                rc = gettok(&src, ' ', &res);
                if (rc == 0) {
                        cfs_free_nidlist(nidlist);
                        RETURN(0);
                }
                rc = parse_nidrange(&res, nidlist);
                if (rc == 0) {
                        cfs_free_nidlist(nidlist);
                        RETURN(0);
                }
        }
        RETURN(1);
}

/**
 * Matches address (\a addr) against address set encoded in \a list.
 *
 * \see libcfs_num_match(), libcfs_ip_match()
 *
 * \retval 1 if \a addr matches
 * \retval 0 otherwise
 */
static int
match_numaddr(__u32 addr, cfs_list_t *list, int shift, __u32 mask)
{
        struct numaddr_range *numaddr;
        struct range_expr *expr;
        int ip, ok;
        ENTRY;

        cfs_list_for_each_entry(numaddr, list, nar_link) {
                ip = (addr >> shift) & mask;
                shift -= 8;
                ok = 0;
                cfs_list_for_each_entry(expr, &numaddr->nar_range_exprs,
                                        re_link) {
                        if (ip >= expr->re_lo &&
                            ip <= expr->re_hi &&
                            ((ip - expr->re_lo) % expr->re_stride) == 0) {
                                ok = 1;
                                break;
                        }
                }
                if (!ok)
                        RETURN(0);
        }
        RETURN(1);
}

/*
 * Nf_match_addr method for networks using numeric addresses
 *
 * \retval 1 on match
 * \retval 0 otherwise
 */
static int
libcfs_num_match(__u32 addr, cfs_list_t *numaddr)
{
        return match_numaddr(addr, numaddr, 0, 0xffffffff);
}

/*
 * Nf_match_addr method for networks using ip addresses
 *
 * \retval 1 on match
 * \retval 0 otherwise
 */
static int
libcfs_ip_match(__u32 addr, cfs_list_t *numaddr)
{
        return match_numaddr(addr, numaddr, 24, 0xff);
}

/**
 * Matches a nid (\a nid) against the compiled list of nidranges (\a nidlist).
 *
 * \see cfs_parse_nidlist()
 *
 * \retval 1 on match
 * \retval 0  otherwises
 */
int cfs_match_nid(lnet_nid_t nid, cfs_list_t *nidlist)
{
        struct nidrange *nr;
        struct addrrange *ar;
        ENTRY;

        cfs_list_for_each_entry(nr, nidlist, nr_link) {
                if (nr->nr_netstrfns->nf_type != LNET_NETTYP(LNET_NIDNET(nid)))
                        continue;
                if (nr->nr_netnum != LNET_NETNUM(LNET_NIDNET(nid)))
                        continue;
                if (nr->nr_all)
                        RETURN(1);
                cfs_list_for_each_entry(ar, &nr->nr_addrranges, ar_link)
                        if (nr->nr_netstrfns->nf_match_addr(LNET_NIDADDR(nid),
                                                       &ar->ar_numaddr_ranges))
                                RETURN(1);
        }
        RETURN(0);
}

#ifdef __KERNEL__

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
EXPORT_SYMBOL(cfs_iswhite);
EXPORT_SYMBOL(cfs_free_nidlist);
EXPORT_SYMBOL(cfs_parse_nidlist);
EXPORT_SYMBOL(cfs_match_nid);

#endif
