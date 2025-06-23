/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/nidlist.h
 *
 * Author: Jim Garlick <garlick@llnl.gov>
 */

#ifndef NIDLIST_H
#define NIDLIST_H

extern char *prog;

typedef struct nl_struct *NIDList;

NIDList nl_create(void);
void nl_destroy(NIDList nl);
void nl_add(NIDList nl, char *nid);
int nl_count(NIDList nl);
void nl_lookup_ip(NIDList nl);
void nl_sort(NIDList nl);
void nl_uniq(NIDList nl);
char *nl_string(NIDList nl, char *sep);
char *nl_xstring(NIDList nl, char *sep);

#endif
