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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <liblustre.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lustre_disk.h>

#undef LASSERT
#undef LASSERTF
#define LASSERT(cond) if (!(cond)) { printf("failed " #cond "\n"); ret = 1; }
#define LASSERTF(cond, fmt, ...) if (!(cond)) { printf("failed '" #cond "'" fmt, ## __VA_ARGS__);ret = 1;}

int ret;

void lustre_assert_wire_constants(void);

int main()
{
        lustre_assert_wire_constants();

        if (ret == 0)
                printf("wire constants OK\n");

        return ret;
}
