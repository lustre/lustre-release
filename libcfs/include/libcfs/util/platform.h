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

#elif __APPLE__

#ifdef HAVE_LIBREADLINE
#define READLINE_LIBRARY
#include <readline/readline.h>
typedef VFunction       rl_vintfunc_t;
typedef VFunction       rl_voidfunc_t;
#endif /* HAVE_LIBREADLINE */

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/shm.h>
#include <sys/semaphore.h>

/*
 * POSIX compliant inter-process synchronization aren't supported well
 * in Darwin, pthread_mutex_t and pthread_cond_t can only work as
 * inter-thread synchronization, they wouldn't work even being put in
 * shared memory for multi-process. PTHREAD_PROCESS_SHARED is not 
 * supported by Darwin also (pthread_mutexattr_setpshared() with the 
 * PTHREAD_PROCESS_SHARED attribute will return EINVAL). 
 *
 * The only inter-process sychronization mechanism can be used in Darwin
 * is POSIX NAMED semaphores and file lock, here we use NAMED semaphore
 * to implement mutex and condition. 
 *
 * XXX Liang:
 * They are just proto-type now, more tests are needed. 
 */
#define L_LOCK_DEBUG 		(0)		

#define L_SEM_NAMESIZE		32

typedef struct {
	sem_t           *s_sem;
#if L_LOCK_DEBUG
	char            s_name[L_SEM_NAMESIZE];
#endif
} l_sem_t;

typedef l_sem_t         l_mutex_t;

typedef struct {
	l_mutex_t	c_guard;
	int             c_count;
	l_sem_t         c_waiter;
} l_cond_t;

static inline int l_sem_init(l_sem_t *sem, int val)
{
	char *s_name;
#if L_LOCK_DEBUG
	s_name = sem->s_name;
#else
	char buf[L_SEM_NAMESIZE];
	s_name = buf;
#endif
	/* get an unique name for named semaphore */
	snprintf(s_name, L_SEM_NAMESIZE, "%d-%p", (int)getpid(), sem);
	sem->s_sem = sem_open(s_name, O_CREAT, 0600, val);
	if ((int)sem->s_sem == SEM_FAILED) {
		fprintf(stderr, "lock %s creating fail: %d, %d!\n",
				s_name, (int)sem->s_sem, errno);
		return -1;
	} else {
#if L_LOCK_DEBUG
		printf("open lock: %s\n", s_name);
#endif
	}
	return 0;
}

static inline void l_sem_done(l_sem_t *sem)
{
#if L_LOCK_DEBUG
	printf("close lock: %s.\n", sem->s_name);
#endif
	sem_close(sem->s_sem);
}

static inline void l_sem_down(l_sem_t *sem)
{
#if L_LOCK_DEBUG
	printf("sem down :%s\n", sem->s_name);
#endif
	sem_wait(sem->s_sem);
}

static inline void l_sem_up(l_sem_t *sem)
{
#if L_LOCK_DEBUG
	printf("sem up	:%s\n", sem->s_name);
#endif
	sem_post(sem->s_sem);
}

static inline void l_mutex_init(l_mutex_t *mutex)
{
	l_sem_init((l_sem_t *)mutex, 1);
}

static inline void l_mutex_init_locked(l_mutex_t *mutex)
{
	l_sem_init((l_sem_t *)mutex, 0);
}

static inline void l_mutex_done(l_mutex_t *mutex)
{
	l_sem_done((l_sem_t *)mutex);
}

static inline void l_mutex_lock(l_mutex_t *mutex)
{
#if L_LOCK_DEBUG
	printf("lock cfs_mutex  :%s\n", mutex->s_name);
#endif
	sem_wait(mutex->s_sem);
}

static inline void l_mutex_unlock(l_mutex_t *mutex)
{
#if L_LOCK_DEBUG
	printf("unlock cfs_mutex: %s\n", mutex->s_name);
#endif
	sem_post(mutex->s_sem);
}

static inline void l_cond_init(l_cond_t *cond)
{
	l_mutex_init(&cond->c_guard);
	l_sem_init(&cond->c_waiter, 0);
	cond->c_count = 0;
}

static inline void l_cond_done(l_cond_t *cond)
{
	if (cond->c_count != 0)
		fprintf(stderr, "your waiter list is not empty: %d!\n", cond->c_count);
	l_mutex_done(&cond->c_guard);
	l_sem_done(&cond->c_waiter);
}

static inline void l_cond_wait(l_cond_t *cond, l_mutex_t *lock)
{
	l_mutex_lock(&cond->c_guard);
	cond->c_count --;
	l_mutex_unlock(&cond->c_guard);
	l_mutex_unlock(lock);
	l_sem_down(&cond->c_waiter);
	l_mutex_lock(lock);
}

static inline void l_cond_broadcast(l_cond_t *cond)
{
	l_mutex_lock(&cond->c_guard);
	while (cond->c_count < 0) {
		l_sem_up(&cond->c_waiter);
		cond->c_count ++;
	}
	l_mutex_unlock(&cond->c_guard);
}

#else /* other platform */

#ifdef HAVE_LIBREADLINE
#define READLINE_LIBRARY
#include <readline/readline.h>
#endif /* HAVE_LIBREADLINE */
#include <errno.h>
#include <string.h>
#if HAVE_LIBPTHREAD
#ifndef __WINNT__
#include <sys/ipc.h>
#include <sys/shm.h>
#endif
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
