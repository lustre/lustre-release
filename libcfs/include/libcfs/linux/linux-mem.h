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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/linux/linux-mem.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_MEM_H__
#define __LIBCFS_LINUX_CFS_MEM_H__

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#ifdef HAVE_MM_INLINE
# include <linux/mm_inline.h>
#endif

#ifndef SLAB_TYPESAFE_BY_RCU
#define SLAB_TYPESAFE_BY_RCU SLAB_DESTROY_BY_RCU
#endif

/*
 * Shrinker
 */
# define SHRINKER_ARGS(sc, nr_to_scan, gfp_mask)  \
                       struct shrinker *shrinker, \
                       struct shrink_control *sc
# define shrink_param(sc, var) ((sc)->var)

#ifdef HAVE_SHRINKER_COUNT
struct shrinker_var {
	unsigned long (*count)(struct shrinker *,
			       struct shrink_control *sc);
	unsigned long (*scan)(struct shrinker *,
			      struct shrink_control *sc);
};
# define DEF_SHRINKER_VAR(name, shrink, count_obj, scan_obj) \
	    struct shrinker_var name = { .count = count_obj, .scan = scan_obj }
#else
struct shrinker_var {
	int (*shrink)(SHRINKER_ARGS(sc, nr_to_scan, gfp_mask));
};
# define DEF_SHRINKER_VAR(name, shrinker, count, scan) \
	    struct shrinker_var name = { .shrink = shrinker }
# define SHRINK_STOP (~0UL)
#endif

static inline
struct shrinker *set_shrinker(int seek, struct shrinker_var *var)
{
        struct shrinker *s;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
        if (s == NULL)
                return (NULL);

#ifdef HAVE_SHRINKER_COUNT
	s->count_objects = var->count;
	s->scan_objects = var->scan;
#else
	s->shrink = var->shrink;
#endif
        s->seeks = seek;

        register_shrinker(s);

        return s;
}

static inline
void remove_shrinker(struct shrinker *shrinker)
{
        if (shrinker == NULL)
                return;

        unregister_shrinker(shrinker);
        kfree(shrinker);
}

#endif /* __LINUX_CFS_MEM_H__ */
