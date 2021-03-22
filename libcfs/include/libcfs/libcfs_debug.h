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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * libcfs/include/libcfs/libcfs_debug.h
 *
 * Debug messages and assertions
 *
 */

#ifndef __LIBCFS_DEBUG_H__
#define __LIBCFS_DEBUG_H__

#include <linux/limits.h>
#include <uapi/linux/lnet/libcfs_debug.h>

/*
 *  Debugging
 */
extern unsigned int libcfs_subsystem_debug;
extern unsigned int libcfs_stack;
extern unsigned int libcfs_debug;
extern unsigned int libcfs_printk;
extern unsigned int libcfs_watchdog_ratelimit;
extern unsigned int libcfs_console_ratelimit;
extern unsigned int libcfs_console_max_delay;
extern unsigned int libcfs_console_min_delay;
extern unsigned int libcfs_console_backoff;
extern unsigned int libcfs_debug_binary;
extern char *libcfs_debug_file_path;

struct task_struct;

int libcfs_debug_mask2str(char *str, int size, int mask, int is_subsys);
int libcfs_debug_str2mask(int *mask, const char *str, int is_subsys);
void libcfs_debug_dumpstack(struct task_struct *tsk);

/* Has there been an LBUG? */
extern unsigned int libcfs_catastrophe;
extern unsigned int libcfs_panic_on_lbug;

#ifndef DEBUG_SUBSYSTEM
# define DEBUG_SUBSYSTEM S_UNDEFINED
#endif

#define CDEBUG_DEFAULT_MAX_DELAY (cfs_time_seconds(600))         /* jiffies */
#define CDEBUG_DEFAULT_MIN_DELAY ((cfs_time_seconds(1) + 1) / 2) /* jiffies */
#define CDEBUG_DEFAULT_BACKOFF   2
struct cfs_debug_limit_state {
	unsigned long	cdls_next;
	unsigned int	cdls_delay;
	int		cdls_count;
};

struct libcfs_debug_msg_data {
	const char			*msg_file;
	const char			*msg_fn;
	int				 msg_subsys;
	int				 msg_line;
	int				 msg_mask;
	struct cfs_debug_limit_state	*msg_cdls;
};

#define LIBCFS_DEBUG_MSG_DATA_INIT(file, func, line, msgdata, mask, cdls)\
do {									\
	(msgdata)->msg_subsys = DEBUG_SUBSYSTEM;			\
	(msgdata)->msg_file   = (file);					\
	(msgdata)->msg_fn     = (func);					\
	(msgdata)->msg_line   = (line);					\
	(msgdata)->msg_mask   = (mask);					\
	(msgdata)->msg_cdls   = (cdls);					\
} while (0)

#define LIBCFS_DEBUG_MSG_DATA_DECL_LOC(file, func, line, msgdata, mask, cdls)\
	static struct libcfs_debug_msg_data msgdata = {			\
		.msg_subsys = DEBUG_SUBSYSTEM,				\
		.msg_file   = (file),					\
		.msg_fn     = (func),					\
		.msg_line   = (line),					\
		.msg_cdls   = (cdls) };					\
	msgdata.msg_mask   = (mask)

#define LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, mask, cdls)			\
	LIBCFS_DEBUG_MSG_DATA_DECL_LOC(__FILE__, __func__, __LINE__,	\
				       msgdata, mask, cdls)

#ifdef CDEBUG_ENABLED

#if !defined(__x86_64__)
# ifdef __ia64__
#  define CDEBUG_STACK() (THREAD_SIZE -					\
			  ((unsigned long)__builtin_dwarf_cfa() &	\
			   (THREAD_SIZE - 1)))
# else
#  define CDEBUG_STACK() (THREAD_SIZE -					\
			  ((unsigned long)__builtin_frame_address(0) &	\
			   (THREAD_SIZE - 1)))
# endif /* __ia64__ */

#define __CHECK_STACK_WITH_LOC(file, func, line, msgdata, mask, cdls)	\
do {									\
	if (unlikely(CDEBUG_STACK() > libcfs_stack)) {			\
		LIBCFS_DEBUG_MSG_DATA_INIT(file, func, line, msgdata,	\
					   D_WARNING, NULL);		\
		libcfs_stack = CDEBUG_STACK();				\
		libcfs_debug_msg(msgdata, "maximum lustre stack %u\n",	\
				 libcfs_stack);				\
		(msgdata)->msg_mask = mask;				\
		(msgdata)->msg_cdls = cdls;				\
		dump_stack();						\
		/*panic("LBUG");*/					\
	}								\
} while (0)
#else /* __x86_64__ */
#define CDEBUG_STACK() (0L)
#define __CHECK_STACK_WITH_LOC(file, func, line, msgdata, mask, cdls)	\
	do {} while (0)
#endif /* __x86_64__ */

#define CFS_CHECK_STACK(msgdata, mask, cdls)				\
	__CHECK_STACK_WITH_LOC(__FILE__, __func__, __LINE__,		\
			       msgdata, mask, cdls)
/**
 * Filters out logging messages based on mask and subsystem.
 */
static inline int cfs_cdebug_show(unsigned int mask, unsigned int subsystem)
{
	return mask & D_CANTMASK ||
	       ((libcfs_debug & mask) && (libcfs_subsystem_debug & subsystem));
}

#  define __CDEBUG_WITH_LOC(file, func, line, mask, cdls, format, ...)	\
do {									\
	static struct libcfs_debug_msg_data msgdata;			\
									\
	__CHECK_STACK_WITH_LOC(file, func, line, &msgdata, mask, cdls);	\
									\
	if (cfs_cdebug_show(mask, DEBUG_SUBSYSTEM)) {			\
		LIBCFS_DEBUG_MSG_DATA_INIT(file, func, line,		\
					   &msgdata, mask, cdls);	\
		libcfs_debug_msg(&msgdata, format, ## __VA_ARGS__);	\
	}								\
} while (0)

#  define CDEBUG(mask, format, ...)					\
	__CDEBUG_WITH_LOC(__FILE__, __func__, __LINE__,			\
			  mask, NULL, format, ## __VA_ARGS__)

#  define CDEBUG_LIMIT(mask, format, ...)				\
do {									\
	static struct cfs_debug_limit_state cdls;			\
									\
	__CDEBUG_WITH_LOC(__FILE__, __func__, __LINE__,			\
			  mask, &cdls, format, ## __VA_ARGS__);		\
} while (0)

# else /* !CDEBUG_ENABLED */
static inline int cfs_cdebug_show(unsigned int mask, unsigned int subsystem)
{
	return 0;
}
#  define CDEBUG(mask, format, ...) (void)(0)
#  define CDEBUG_LIMIT(mask, format, ...) (void)(0)
#  warning "CDEBUG IS DISABLED. THIS SHOULD NEVER BE DONE FOR PRODUCTION!"
# endif /* CDEBUG_ENABLED */

/*
 * Lustre Error Checksum: calculates checksum
 * of Hex number by XORing each bit.
 */
#define LERRCHKSUM(hexnum) (((hexnum) & 0xf) ^ ((hexnum) >> 4 & 0xf) ^ \
			   ((hexnum) >> 8 & 0xf))

#define CWARN(format, ...)          CDEBUG_LIMIT(D_WARNING, format, ## __VA_ARGS__)
#define CERROR(format, ...)         CDEBUG_LIMIT(D_ERROR, format, ## __VA_ARGS__)
#define CNETERR(format, a...)       CDEBUG_LIMIT(D_NETERROR, format, ## a)
#define CEMERG(format, ...)         CDEBUG_LIMIT(D_EMERG, format, ## __VA_ARGS__)

#define LCONSOLE(mask, format, ...) CDEBUG(D_CONSOLE | (mask), format, ## __VA_ARGS__)
#define LCONSOLE_INFO(format, ...)  CDEBUG_LIMIT(D_CONSOLE, format, ## __VA_ARGS__)
#define LCONSOLE_WARN(format, ...)  CDEBUG_LIMIT(D_CONSOLE | D_WARNING, format, ## __VA_ARGS__)
#define LCONSOLE_ERROR_MSG(errnum, format, ...) CDEBUG_LIMIT(D_CONSOLE | D_ERROR, \
                           "%x-%x: " format, errnum, LERRCHKSUM(errnum), ## __VA_ARGS__)
#define LCONSOLE_ERROR(format, ...) LCONSOLE_ERROR_MSG(0x00, format, ## __VA_ARGS__)

#define LCONSOLE_EMERG(format, ...) \
	CDEBUG(D_CONSOLE | D_EMERG, format, ## __VA_ARGS__)

#if defined(CDEBUG_ENTRY_EXIT)

void libcfs_log_goto(struct libcfs_debug_msg_data *goto_data,
		     const char *label, long rc);

# define GOTO(label, rc)						      \
do {									      \
	if (cfs_cdebug_show(D_TRACE, DEBUG_SUBSYSTEM)) {		      \
		LIBCFS_DEBUG_MSG_DATA_DECL(_goto_data, D_TRACE, NULL);	      \
		libcfs_log_goto(&_goto_data, #label, (long)(rc));	      \
	} else {							      \
		(void)(rc);						      \
	}								      \
									      \
	goto label;							      \
} while (0)


long libcfs_log_return(struct libcfs_debug_msg_data *, long rc);
# if BITS_PER_LONG > 32
#  define RETURN(rc)							      \
do {									      \
	if (cfs_cdebug_show(D_TRACE, DEBUG_SUBSYSTEM)) {		      \
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_TRACE, NULL);	      \
		return (typeof(rc))libcfs_log_return(&msgdata,		      \
						     (long)(rc));	      \
	}								      \
									      \
	return rc;							      \
} while (0)
# else /* BITS_PER_LONG == 32 */
/* We need an on-stack variable, because we cannot case a 32-bit pointer
 * directly to (long long) without generating a complier warning/error, yet
 * casting directly to (long) will truncate 64-bit return values. The log
 * values will print as 32-bit values, but they always have been. LU-1436
 */
#  define RETURN(rc)							      \
do {									      \
	if (cfs_cdebug_show(D_TRACE, DEBUG_SUBSYSTEM)) {		      \
		typeof(rc) __rc = (rc);					      \
		LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, D_TRACE, NULL);	      \
		libcfs_log_return(&msgdata, (long)__rc);		      \
		return __rc;						      \
	}								      \
									      \
	return rc;							      \
} while (0)

# endif /* BITS_PER_LONG > 32 */

# define ENTRY	CDEBUG(D_TRACE, "Process entered\n")
# define EXIT	CDEBUG(D_TRACE, "Process leaving\n")

#else /* !CDEBUG_ENTRY_EXIT */

# define GOTO(label, rc)						\
	do {								\
		((void)(rc));						\
		goto label;						\
	} while (0)

# define RETURN(rc) return (rc)
# define ENTRY	do { } while (0)
# define EXIT	do { } while (0)

#endif /* CDEBUG_ENTRY_EXIT */

#define RETURN_EXIT							\
do {									\
	EXIT;								\
	return;								\
} while (0)

int libcfs_debug_msg(struct libcfs_debug_msg_data *msgdata,
		     const char *format1, ...)
	__printf(2, 3);

/* other external symbols that tracefile provides: */
int cfs_trace_copyout_string(char __user *usr_buffer, int usr_buffer_nob,
			     const char *knl_buffer, char *append);

#define LIBCFS_DEBUG_FILE_PATH_DEFAULT "/tmp/lustre-log"

void cfs_debug_init(void);

#endif	/* __LIBCFS_DEBUG_H__ */
