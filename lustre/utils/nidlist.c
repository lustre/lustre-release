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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/nidlist.c
 *
 * Author: Jim Garlick <garlick@llnl.gov>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "nidlist.h"

struct nl_struct {
	char **nids;
	int len;
	int count;
};
#define NL_CHUNK	64

extern char *prog;

static void nl_oom(void)
{
	fprintf(stderr, "%s: out of memory\n", prog);
	exit(1);
}

NIDList nl_create(void)
{
	struct nl_struct *nl;

	if (!(nl = malloc(sizeof(struct nl_struct))))
		nl_oom();
	nl->len = NL_CHUNK;
	if (!(nl->nids = malloc(nl->len * sizeof(char *))))
		nl_oom();
	nl->count = 0;

	return nl;
}

void nl_destroy(NIDList nl)
{
	int i;

	for (i = 0; i < nl->count; i++)
		free(nl->nids[i]);
	free(nl->nids);
	free(nl);
}

static void nl_grow(NIDList nl, int n)
{
	nl->len += n;
	if (!(nl->nids = realloc(nl->nids, nl->len * sizeof(char *))))
		nl_oom();
}

void nl_add(NIDList nl, char *nid)
{
	char *cp;

	if (!(cp = strdup(nid)))
		nl_oom();
	if (nl->count == nl->len)
		nl_grow(nl, NL_CHUNK);
	nl->nids[nl->count++] = cp;
}

int nl_count(NIDList nl)
{
        return nl->count;
}

static char *nl_nid_addr(char *nid)
{
	char *addr, *p;

	if (!(addr = strdup(nid)))
		nl_oom();
	if ((p = strchr(addr, '@')))
		*p = '\0';

	return addr;
}

static int nl_nid_parse_addr(char *addr)
{
	int o;

	for (o = strlen(addr); o > 0; o--)
                if (!isdigit(addr[o - 1]))
			break;

	return o;
}

static int nl_cmp_addr(char *nid1, char *nid2, int *cflagp)
{
	char *p1 = nl_nid_addr(nid1);
	char *p2 = nl_nid_addr(nid2);
	int res, o1, o2, cflag = 0;

	o1 = nl_nid_parse_addr(p1);
	o2 = nl_nid_parse_addr(p2);

	if (o1 == o2 && (res = strncmp(p1, p2, o1)) == 0) {
		res = strtoul(&p1[o1], NULL, 10) - strtoul(&p2[o2], NULL, 10);
                if (cflagp && strlen(&p1[o1]) > 0 && strlen(&p2[o2]) > 0)
                        cflag = 1;
	} else
                res = strcmp(p1, p2);
	free(p1);
	free(p2);
	if (cflagp)
		*cflagp = cflag;
	return res;
}

static int nl_cmp_lnet(char *nid1, char *nid2)
{
	char *s1 = strchr(nid1, '@');
	char *s2 = strchr(nid2, '@');

	return strcmp(s1 ? s1 + 1 : "", s2 ? s2 + 1 : "");
}

static int nl_cmp(const void *p1, const void *p2)
{
	int res;

	if ((res = nl_cmp_lnet(*(char **)p1, *(char **)p2)) == 0)
		res = nl_cmp_addr(*(char **)p1, *(char **)p2, NULL);
	return res;
}

void nl_sort(NIDList nl)
{
	qsort(nl->nids, nl->count, sizeof(char *), nl_cmp);
}

void nl_uniq(NIDList nl)
{
	int i, j;

	for (i = 1; i < nl->count; i++) {
		if (!strcmp(nl->nids[i], nl->nids[i - 1])) {
			free(nl->nids[i]);
			for (j = i; j < nl->count - 1; j++)
				nl->nids[j] = nl->nids[j + 1];
			nl->count--;
			i--;
		}
	}
}

static char *nl_nid_lookup_ipaddr(char *nid)
{
        struct addrinfo *ai, *aip;
        char name[NI_MAXHOST] = "";
        char *p, *addr, *lnet = NULL, *res = NULL;
        int len, x;

        addr = nl_nid_addr(nid);
        if (sscanf(addr, "%d.%d.%d.%d", &x, &x, &x, &x) == 4) {
                if ((p = strchr(nid, '@')))
                        lnet = p + 1;
                if (getaddrinfo(addr, NULL, NULL, &ai) == 0) {
                        for (aip = ai; aip != NULL; aip = aip->ai_next) {
                                if (getnameinfo(aip->ai_addr, aip->ai_addrlen,
                                    name, sizeof(name), NULL, 0,
                                    NI_NAMEREQD | NI_NOFQDN) == 0) {
                                        if ((p = strchr(name, '.')))
                                                *p = '\0';
					len = strlen(name) + 2;
					if (lnet != NULL)
						len += strlen(lnet);
					if (!(res = malloc(len)))
						nl_oom();
					if (lnet != NULL)
						snprintf(res, len, "%s@%s",
							 name, lnet);
					else
						snprintf(res, len, "%s", name);
					break;
				}
			}
			freeaddrinfo(ai);
		}
	}
	free(addr);

	return res;
}

void nl_lookup_ip(NIDList nl)
{
	int i;
        char *new;

	for (i = 0; i < nl->count; i++) {
                if ((new = nl_nid_lookup_ipaddr(nl->nids[i]))) {
                        free(nl->nids[i]);
                        nl->nids[i] = new;
                }
        }
}

char *nl_string(NIDList nl, char *sep)
{
	int seplen = strlen(sep);
	int i, len = 1;
	char *s;

	for (i = 0; i < nl->count; i++)
		len += strlen(nl->nids[i]) + seplen;
	if (!(s = malloc(len)))
		nl_oom();
	s[0] = '\0';
	for (i = 0; i < nl->count; i++) {
		if (i > 0)
			strcat(s, sep);
		strcat(s, nl->nids[i]);
	}
	return s;
}

static void nl_strxcat(char *s, char **nids, int len)
{
	int i, o, lastn = 0;
	char *base, *p, *lnet = NULL, *savedn = NULL;

	if ((p = strchr(nids[0], '@')))
		lnet = p + 1;
        base = nl_nid_addr(nids[0]);
        o = nl_nid_parse_addr(base);
	base[o] = '\0';
	for (i = 0; i < len; i++) {
		char *addr = nl_nid_addr(nids[i]);
		int n = strtoul(&addr[o], NULL, 10);

		if (i == 0)
			sprintf(s + strlen(s), "%s[%s", base, &addr[o]);
		else if (i < len) {
			if (n == lastn + 1) {
				if (savedn)
					free(savedn);
				if (!(savedn = strdup(&addr[o])))
					nl_oom();
			} else {
				if (savedn) {
					sprintf(s + strlen(s), "-%s", savedn);
					free(savedn);
					savedn = NULL;
				}
				sprintf(s + strlen(s), ",%s", &addr[o]);
			}
		}
		if (i == len - 1) {
			if (savedn) {
				sprintf(s + strlen(s), "-%s", savedn);
				free(savedn);
			}
			strcat(s, "]");
			if (lnet)
				sprintf(s + strlen(s), "@%s", lnet);
		}
		free(addr);
		lastn = n;
	}
	free(base);
}

char *nl_xstring(NIDList nl, char *sep)
{
	int seplen = strlen(sep);
	int cflag, i, j, len = 1;
	char *s;

	for (i = 0; i < nl->count; i++)
		len += strlen(nl->nids[i]) + seplen;
	if (!(s = malloc(len)))
		nl_oom();
	s[0] = '\0';
	for (i = 0; i < nl->count; i++) {
		if (i > 0)
			strcat(s, sep);
		for (j = i + 1; j < nl->count; j++) {
			if (nl_cmp_lnet(nl->nids[i], nl->nids[j]) != 0)
				break;
			(void)nl_cmp_addr(nl->nids[i], nl->nids[j], &cflag);
			if (!cflag)
				break;
		}
		if (j - i > 1)
			nl_strxcat(s, &nl->nids[i], j - i);
		else
			strcat(s, nl->nids[i]);
		i += j - i - 1;
	}
	return s;
}
