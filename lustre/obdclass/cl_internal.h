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
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Internal cl interfaces.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
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

struct cl_thread_info *cl_env_info(const struct lu_env *env);
void cl_page_disown0(const struct lu_env *env,
		     struct cl_io *io, struct cl_page *pg);

#endif /* _CL_INTERNAL_H */
