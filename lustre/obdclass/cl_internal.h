/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Internal cl interfaces.
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#ifndef _CL_INTERNAL_H
#define _CL_INTERNAL_H

/**
 * Thread local state internal for generic cl-code.
 */
struct cl_thread_info {
	/**
	 * Used for submitting a sync I/O.
	 */
	struct cl_sync_io clt_anchor;
};

extern struct kmem_cache *cl_dio_aio_kmem;
extern struct kmem_cache *cl_sub_dio_kmem;
extern struct kmem_cache *cl_page_kmem_array[16];
extern unsigned short cl_page_kmem_size_array[16];

struct cl_thread_info *cl_env_info(const struct lu_env *env);
void __cl_page_disown(const struct lu_env *env, struct cl_page *pg);

#endif /* _CL_INTERNAL_H */
