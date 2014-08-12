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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/libcfsutil.h
 *
 * A portability layer for multi-threaded userspace applications.
 *
 */

#ifndef __LUSTRE_UTILS_PLATFORM_H
#define __LUSTRE_UTILS_PLATFORM_H

#ifdef __linux__

#ifdef HAVE_LIBREADLINE
#define READLINE_LIBRARY
#include <readline/readline.h>

/* completion_matches() is #if 0-ed out in modern glibc */

#ifndef completion_matches
#  define completion_matches rl_completion_matches
#endif
extern void using_history(void);
extern void stifle_history(int);
extern void add_history(char *);
#endif /* HAVE_LIBREADLINE */

#include <errno.h>
#include <string.h>
#if HAVE_LIBPTHREAD
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>

typedef pthread_mutex_t	l_mutex_t;
typedef pthread_cond_t	l_cond_t;
#define l_mutex_init(s)		pthread_mutex_init(s, NULL)
#define l_mutex_lock(s)		pthread_mutex_lock(s)
#define l_mutex_unlock(s)	pthread_mutex_unlock(s)
#define l_cond_init(c)		pthread_cond_init(c, NULL)
#define l_cond_broadcast(c)	pthread_cond_broadcast(c)
#define l_cond_wait(c, s)	pthread_cond_wait(c, s)
#endif

#else /* other platform */

#ifdef HAVE_LIBREADLINE
#define READLINE_LIBRARY
#include <readline/readline.h>
#endif /* HAVE_LIBREADLINE */
#include <errno.h>
#include <string.h>
#if HAVE_LIBPTHREAD
#include <sys/ipc.h>
#include <sys/shm.h>
#include <pthread.h>

typedef pthread_mutex_t	l_mutex_t;
typedef pthread_cond_t	l_cond_t;
#define l_mutex_init(s)		pthread_mutex_init(s, NULL)
#define l_mutex_lock(s)		pthread_mutex_lock(s)
#define l_mutex_unlock(s)	pthread_mutex_unlock(s)
#define l_cond_init(c)		pthread_cond_init(c, NULL)
#define l_cond_broadcast(c)	pthread_cond_broadcast(c)
#define l_cond_wait(c, s)	pthread_cond_wait(c, s)
#endif /* HAVE_LIBPTHREAD */

#endif /* __linux__  */

#endif
