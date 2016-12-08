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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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

static void nl_oom(void)
{
	fprintf(stderr, "%s: out of memory\n", prog);
	exit(1);
}

NIDList nl_create(void)
{
	struct nl_struct *nl;

	nl = malloc(sizeof(struct nl_struct));
	if (!nl)
		nl_oom();
	nl->len = NL_CHUNK;
	nl->nids = malloc(nl->len * sizeof(char *));
	if (!nl->nids)
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
	nl->nids = realloc(nl->nids, nl->len * sizeof(char *));
	if (!nl->nids)
		nl_oom();
}

void nl_add(NIDList nl, char *nid)
{
	char *cp;

	cp = strdup(nid);
	if (!cp)
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

	addr = strdup(nid);
	if (!addr)
		nl_oom();
	p = strchr(addr, '@');
	if (p)
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

	res = strncmp(p1, p2, o1);
	if (o1 == o2 && res == 0) {
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

	res = nl_cmp_lnet(*(char **)p1, *(char **)p2);
	if (res == 0)
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
		p = strchr(nid, '@');
		if (p)
			lnet = p + 1;
		if (getaddrinfo(addr, NULL, NULL, &ai) == 0) {
			for (aip = ai; aip != NULL; aip = aip->ai_next) {
				if (getnameinfo(aip->ai_addr, aip->ai_addrlen,
				    name, sizeof(name), NULL, 0,
				    NI_NAMEREQD | NI_NOFQDN) == 0) {
					p = strchr(name, '.');
					if (p)
						*p = '\0';
					len = strlen(name) + 2;
					if (lnet != NULL)
						len += strlen(lnet);
					res = malloc(len);
					if (!res)
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
		new = nl_nid_lookup_ipaddr(nl->nids[i]);
		if (new) {
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
	s = malloc(len);
	if (!s)
		nl_oom();
	s[0] = '\0';
	for (i = 0; i < nl->count; i++) {
		if (i > 0)
			strncat(s, sep, len);
		strncat(s, nl->nids[i], len);
	}
	return s;
}

static void nl_strxcat(char *s, char **nids, int len, const int max_len)
{
	int i, o, lastn = 0;
	char *base, *p, *lnet = NULL, *savedn = NULL;

	p = strchr(nids[0], '@');
	if (p)
		lnet = p + 1;
	base = nl_nid_addr(nids[0]);
	o = nl_nid_parse_addr(base);
	base[o] = '\0';
	for (i = 0; i < len; i++) {
		char *addr = nl_nid_addr(nids[i]);
		int n = strtoul(&addr[o], NULL, 10);

		if (i == 0)
			snprintf(s + strlen(s), max_len, "%s[%s", base,
				 &addr[o]);
		else if (i < len) {
			if (n == lastn + 1) {
				if (savedn)
					free(savedn);
				savedn = strdup(&addr[o]);
				if (!savedn)
					nl_oom();
			} else {
				if (savedn) {
					snprintf(s + strlen(s),
						 max_len - strlen(s),
						 "-%s", savedn);
					free(savedn);
					savedn = NULL;
				}
				snprintf(s + strlen(s), max_len - strlen(s),
					 ",%s", &addr[o]);
			}
		}
		if (i == len - 1) {
			if (savedn) {
				snprintf(s + strlen(s), max_len - strlen(s),
					 "-%s", savedn);
				free(savedn);
			}
			strncat(s, "]", 1);
			if (lnet)
				snprintf(s + strlen(s), max_len - strlen(s),
					 "@%s", lnet);
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
	s = malloc(len);
	if (!s)
		nl_oom();
	s[0] = '\0';
	for (i = 0; i < nl->count; i++) {
		if (i > 0)
			strncat(s, sep, len);
		for (j = i + 1; j < nl->count; j++) {
			if (nl_cmp_lnet(nl->nids[i], nl->nids[j]) != 0)
				break;
			(void)nl_cmp_addr(nl->nids[i], nl->nids[j], &cflag);
			if (!cflag)
				break;
		}
		if (j - i > 1)
			nl_strxcat(s, &nl->nids[i], j - i, len);
		else
			strncat(s, nl->nids[i], len);
		i += j - i - 1;
	}
	return s;
}
