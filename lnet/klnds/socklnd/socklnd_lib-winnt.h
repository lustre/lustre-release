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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_PORTAL_ALLOC
#ifndef __WINNT_TDILND_LIB_H__
#define __WINNT_TDILND_LIB_H__

#include <libcfs/libcfs.h>

#ifndef CONFIG_SMP

static inline
int ksocknal_nsched(void)
{
        return 1;
}

#else

static inline int
ksocknal_nsched(void)
{
        return cfs_num_online_cpus();
}

static inline int
ksocknal_sched2cpu(int i)
{
        return i;
}

static inline int
ksocknal_irqsched2cpu(int i)
{
        return i;
}

#endif

static inline __u32 ksocknal_csum(__u32 crc, unsigned char const *p, size_t len)
{
        while (len-- > 0)
                crc = ((crc + 0x100) & ~0xff) | ((crc + *p++) & 0xff) ;
        return crc;
}


#endif
