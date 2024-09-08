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
 * Debug messages and assertions
 */

#ifndef __LIBCFS_DEBUG_H__
#define __LIBCFS_DEBUG_H__

#include <linux/tty.h>
#include <linux/limits.h>
#include <uapi/linux/lnet/libcfs_debug.h>

/*
 *  Debugging
 */
extern unsigned int libcfs_subsystem_debug;
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
extern bool libcfs_debug_raw_pointers;

int debug_format_buffer_alloc_buffers(void);
void debug_format_buffer_free_buffers(void);
bool get_debug_raw_pointers(void);
void set_debug_raw_pointers(bool value);

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

#  define CDEBUG_LIMIT_LOC(file, func, line, mask, format, ...)		\
do {									\
	static struct cfs_debug_limit_state cdls;			\
									\
	__CDEBUG_WITH_LOC(file, func, line,				\
			  mask, &cdls, format, ## __VA_ARGS__);		\
} while (0)

#  define CDEBUG_SLOW(delay, mask, format, ...)				\
do {									\
	static struct cfs_debug_limit_state cdls = {			\
	.cdls_count = -delay,						\
	.cdls_delay = delay,						\
	};								\
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
#  define CDEBUG_LIMIT_LOC(file, func, line, mask, format, ...) (void)(0)
#  define CDEBUG_SLOW(delay, mask, format, ...) (void)(0)
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

#define CWARN_SLOW(delay, format, ...)  CDEBUG_SLOW(delay, D_WARNING, format, \
		   ## __VA_ARGS__)
#define CERROR_SLOW(delay, format, ...) CDEBUG_SLOW(delay, D_ERROR, format, \
		    ## __VA_ARGS__)

#define LCONSOLE(mask, format, ...) CDEBUG(D_CONSOLE | (mask), format, ## __VA_ARGS__)
#define LCONSOLE_INFO(format, ...)  CDEBUG_LIMIT(D_CONSOLE, format, ## __VA_ARGS__)
#define LCONSOLE_WARN(format, ...)  CDEBUG_LIMIT(D_CONSOLE | D_WARNING, format, ## __VA_ARGS__)
#define LCONSOLE_ERROR(format, ...) CDEBUG_LIMIT(D_CONSOLE | D_ERROR, format, ## __VA_ARGS__)
#define LCONSOLE_EMERG(format, ...) CDEBUG(D_CONSOLE | D_EMERG, format, ## __VA_ARGS__)

void libcfs_debug_msg(struct libcfs_debug_msg_data *msgdata,
		      const char *format1, ...)
	__printf(2, 3);

/* other external symbols that tracefile provides: */
int cfs_trace_copyout_string(char __user *usr_buffer, int usr_buffer_nob,
			     const char *knl_buffer, char *append);

#define LIBCFS_DEBUG_FILE_PATH_DEFAULT "/tmp/lustre-log"

#if defined(CDEBUG_ENTRY_EXIT)

static inline long libcfs_log_return(struct libcfs_debug_msg_data *msgdata, long rc)
{
	libcfs_debug_msg(msgdata, "Process leaving (rc=%lu : %ld : %lx)\n",
			 rc, rc, rc);
	return rc;
}

static inline void libcfs_log_goto(struct libcfs_debug_msg_data *msgdata,
				   const char *label, long rc)
{
	libcfs_debug_msg(msgdata,
			 "Process leaving via %s (rc=%lu : %ld : %#lx)\n",
			 label, rc, rc, rc);
}

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

static inline void cfs_tty_write_msg(const char *msg)
{
	struct tty_struct *tty;

	tty = get_current_tty();
	if (!tty)
		return;
	mutex_lock(&tty->atomic_write_lock);
	tty_lock(tty);
	if (tty->ops->write && tty->count > 0)
		tty->ops->write(tty, msg, strlen(msg));
	tty_unlock(tty);
	mutex_unlock(&tty->atomic_write_lock);
	wake_up_interruptible_poll(&tty->write_wait, POLL_OUT);
	tty_kref_put(tty);
}

#endif	/* __LIBCFS_DEBUG_H__ */
