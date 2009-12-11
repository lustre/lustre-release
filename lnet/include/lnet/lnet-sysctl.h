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
 */

#ifndef __LNET_SYSCTL_H__
#define __LNET_SYSCTL_H__

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM

#ifndef HAVE_SYSCTL_UNNUMBERED

#define CTL_KRANAL      201
#define CTL_GMLND       202
#define CTL_KIBNAL      203
#define CTL_IIBBLND     204
#define CTL_O2IBLND     205
#define CTL_PTLLND      206
#define CTL_QSWNAL      207
#define CTL_SOCKLND     208
#define CTL_VIBLND      209

#else

#define CTL_KRANAL      CTL_UNNUMBERED
#define CTL_GMLND       CTL_UNNUMBERED
#define CTL_KIBNAL      CTL_UNNUMBERED
#define CTL_IIBLND      CTL_UNNUMBERED
#define CTL_O2IBLND     CTL_UNNUMBERED
#define CTL_PTLLND      CTL_UNNUMBERED
#define CTL_QSWNAL	CTL_UNNUMBERED
#define CTL_SOCKLND     CTL_UNNUMBERED
#define CTL_VIBLND      CTL_UNNUMBERED

#endif /* sysctl id */

#endif

#endif
