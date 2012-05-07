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
 *
 * lustre/obdclass/lu_time.c
 *
 * Lustre Time Tracking.
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices.
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <obd_class.h>
/* OBD_{ALLOC,FREE}_PTR() */
#include <obd_support.h>
#include <lprocfs_status.h>
#include <lu_object.h>
#include <lu_time.h>

enum {
        LU_TIME_DEPTH_MAX = 16
};

struct lu_time_data {
        int                ltd_tos; /* top of the stack */
        unsigned long long ltd_timestamp[LU_TIME_DEPTH_MAX];
};

/* context key constructor/destructor: lu_time_key_init, lu_time_key_fini */
LU_KEY_INIT_FINI(lu_time, struct lu_time_data);

void lu_time_key_exit(const struct lu_context *ctx,
                      struct lu_context_key *key, void *data)
{
        struct lu_time_data *value = data;
        LASSERT(value->ltd_tos == 0);
}

/*
 * Key, holding temporary buffer. This key is registered very early by
 * lu_global_init().
 */
static struct lu_context_key lu_time_key = {
        .lct_tags = LCT_MD_THREAD|LCT_DT_THREAD|LCT_CL_THREAD,
        .lct_init = lu_time_key_init,
        .lct_fini = lu_time_key_fini,
        .lct_exit = lu_time_key_exit
};

int lu_time_global_init(void)
{
        LU_CONTEXT_KEY_INIT(&lu_time_key);
        return lu_context_key_register(&lu_time_key);
}

void lu_time_global_fini(void)
{
        lu_context_key_degister(&lu_time_key);
}

int lu_time_named_init(struct lprocfs_stats **stats, const char *name,
                       cfs_proc_dir_entry_t *entry,
                       const char **names, int nr)
{
        int result;
        int i;

        ENTRY;

        *stats = NULL;
        if (nr == 0)
                RETURN(0);

        *stats = lprocfs_alloc_stats(nr, 0);
        if (*stats != NULL) {
                result = lprocfs_register_stats(entry, name, *stats);
                if (result == 0) {
                        for (i = 0; i < nr; ++i) {
                                lprocfs_counter_init(*stats, i,
                                                     LPROCFS_CNTR_AVGMINMAX,
                                                     names[i], "usec");
                        }
                }
        } else
                result = -ENOMEM;

        if (result != 0)
                lu_time_fini(stats);

        RETURN(result);
}
EXPORT_SYMBOL(lu_time_named_init);

int lu_time_init(struct lprocfs_stats **stats, cfs_proc_dir_entry_t *entry,
                 const char **names, int nr)
{
        return lu_time_named_init(stats, "lu_stats", entry, names, nr);
}
EXPORT_SYMBOL(lu_time_init);

void lu_time_fini(struct lprocfs_stats **stats)
{
        if (*stats != NULL) {
                lprocfs_free_stats(stats);
                *stats = NULL;
        }
}
EXPORT_SYMBOL(lu_time_fini);

static inline struct lu_time_data *lu_time_data_get(const struct lu_env *env)
{
        return lu_context_key_get(&env->le_ctx, &lu_time_key);
}

int lu_time_is_clean(const struct lu_env *env)
{
        return lu_time_data_get(env)->ltd_tos == 0;
}
EXPORT_SYMBOL(lu_time_is_clean);

/* from sleepometer by Andrew Morton */
unsigned long long lu_time_stamp_get(void)
{
        /*
         * Return timestamp with microsecond precision. This has to be cheap.
         */
//#ifdef CONFIG_X86
#if defined(CONFIG_X86) && !defined(CONFIG_X86_64)
	/*
	 * do_gettimeofday() goes backwards sometimes :(.  Usethe TSC
	 */
	unsigned long long ret;

	rdtscll(ret);
	do_div(ret, cpu_khz / 1000);
	return ret;
#else
	struct timeval now;
	unsigned long long ret;

	cfs_gettimeofday(&now);
	ret = now.tv_sec;
	ret *= 1000000;
	ret += now.tv_usec;
	return ret;
#endif
}
/*
 * Export it, but do not advertise in headers. This is limited use only.
 */
EXPORT_SYMBOL(lu_time_stamp_get);

void lu_lprocfs_time_start(const struct lu_env *env)
{
        struct lu_time_data *ltd = lu_time_data_get(env);

        LASSERT(0 <= ltd->ltd_tos);
        LASSERT(ltd->ltd_tos < ARRAY_SIZE(ltd->ltd_timestamp));
        ltd->ltd_timestamp[ltd->ltd_tos++] = lu_time_stamp_get();
}
EXPORT_SYMBOL(lu_lprocfs_time_start);

void lu_lprocfs_time_end(const struct lu_env *env,
                         struct lprocfs_stats *stats, int idx)
{
        struct lu_time_data *ltd = lu_time_data_get(env);
        long long diff;

        --ltd->ltd_tos;
        LASSERT(0 <= ltd->ltd_tos);
        LASSERT(ltd->ltd_tos < ARRAY_SIZE(ltd->ltd_timestamp));
        diff = lu_time_stamp_get() - ltd->ltd_timestamp[ltd->ltd_tos];
        if (diff >= 0 && stats != NULL)
                lprocfs_counter_add(stats, idx, diff);
}
EXPORT_SYMBOL(lu_lprocfs_time_end);
