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
 * lustre/utils/nidlist.h
 *
 * Author: Jim Garlick <garlick@llnl.gov>
 */

#ifndef NIDLIST_H
#define NIDLIST_H

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
