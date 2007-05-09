/*
 *    This Cplant(TM) source code is the property of Sandia National
 *    Laboratories.
 *
 *    This Cplant(TM) source code is copyrighted by Sandia National
 *    Laboratories.
 *
 *    The redistribution of this Cplant(TM) source code is subject to the
 *    terms of the GNU Lesser General Public License
 *    (see cit/LGPL or http://www.gnu.org/licenses/lgpl.html)
 *
 *    Cplant(TM) Copyright 1998-2006 Sandia Corporation. 
 *    Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 *    license for use of this work by or on behalf of the US Government.
 *    Export of this program may require a license from the United States
 *    Government.
 */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Questions or comments about this library should be sent to:
 *
 * Lee Ward
 * Sandia National Laboratories, New Mexico
 * P.O. Box 5800
 * Albuquerque, NM 87185-1110
 *
 * lee@sandia.gov
 */

/*
 * System IO common information.
 */

#if !defined(__IS_UNUSED) && defined(__GNUC__)
#define __IS_UNUSED	__attribute__ ((unused))
#else
#define __IS_UNUSED
#endif

/*
 * Define internal file-offset type and it's maximum value.
 */
#ifdef _LARGEFILE64_SOURCE
#define _SYSIO_OFF_T			off64_t
#ifdef LLONG_MAX
#define _SYSIO_OFF_T_MAX		(LLONG_MAX)
#else
/*
 * Don't have LLONG_MAX before C99. We'll need to define it ourselves.
 */
#define _SYSIO_OFF_T_MAX		(9223372036854775807LL)
#endif
#else
#define _SYSIO_OFF_T			off_t
#define _SYSIO_OFF_T_MAX		LONG_MAX
#endif

/*
 * Internally, all file status is carried in the 64-bit capable
 * structure.
 */
#ifdef _LARGEFILE64_SOURCE
#define intnl_xtvec xtvec64
#else
#define intnl_xtvec xtvec
#endif
struct intnl_xtvec;

struct iovec;

/*
 * Symbol composition.
 */
#define _PREPEND_HELPER(p, x) \
	p ## x
#define PREPEND(p, x) \
	_PREPEND_HELPER(p, x)

/*
 * SYSIO name label macros
 */
#ifndef SYSIO_INTERFACE_NAME
#ifdef SYSIO_LABEL_NAMES
#define SYSIO_INTERFACE_NAME(x) \
	PREPEND(SYSIO_LABEL_NAMES, x)
#else
#define SYSIO_INTERFACE_NAME(x) x
#endif /* SYSIO_LABEL_NAMES */
#endif /* !SYSIO_INTERFACE_NAME */

/* for debugging */
#if 0
#define ASSERT(cond)							\
	if (!(cond)) {							\
		printf("ASSERTION(" #cond ") failed: " __FILE__ ":"	\
			__FUNCTION__ ":%d\n", __LINE__);		\
		abort();						\
	}

#define ERROR(fmt, a...)						\
	do {								\
		printf("ERROR(" __FILE__ ":%d):" fmt, __LINE__, ##a);	\
	while(0)

#else
#define ERROR(fmt) 	do{}while(0)
#define ASSERT		do{}while(0)
#endif

/*
 * SYSIO interface frame macros
 *
 * + DISPLAY_BLOCK; Allocates storage on the stack for use by the set of
 *	macros.
 * + ENTER; Performs entry point work
 * + RETURN; Returns a value and performs exit point work
 *
 * NB: For RETURN, the arguments are the return value and value for errno.
 * If the value for errno is non-zero then that value, *negated*, is set
 * into errno.
 */
#define SYSIO_INTERFACE_DISPLAY_BLOCK \
	int _saved_errno;
#define SYSIO_INTERFACE_ENTER \
	do { \
		_saved_errno = errno; \
		SYSIO_ENTER; \
	} while (0)
#define SYSIO_INTERFACE_RETURN(rtn, err) \
	do { \
		SYSIO_LEAVE; \
		errno = (err) ? -(err) : _saved_errno; \
		return (rtn); \
	} while(0) 

/* Interface enter/leave hook functions  */
#ifdef SYSIO_TRACING
extern void *_sysio_entry_trace_q;
extern void *_sysio_exit_trace_q;

extern void *_sysio_register_trace(void *q,
				   void (*)(const char *file,
					    const char *func,
					    int line,
					    void *data),
				   void *data,
				   void (*destructor)(void *data));
extern void _sysio_remove_trace(void *q, void *p);
extern void _sysio_run_trace_q(void *q,
			       const char *file,
			       const char *func,
			       int line);
#define SYSIO_ENTER							\
	do { \
		_sysio_run_trace_q(_sysio_entry_trace_q,		\
				   __FILE__, __func__, __LINE__);	\
	} while (0)


#define SYSIO_LEAVE							\
	do { \
		_sysio_run_trace_q(_sysio_exit_trace_q,			\
				   __FILE__, __func__, __LINE__);	\
	} while (0)
#else
#define SYSIO_ENTER							\
	do { } while (0)
#define SYSIO_LEAVE							\
	do { } while (0)
#endif

/* Accounting for IO stats; Read and write character count. */
#if defined(REDSTORM)
#define _SYSIO_UPDACCT(w, cc) \
	do { \
		if ((cc) < 0) \
			break; \
		if (w) \
			_add_iostats(0, (size_t )(cc)); \
		else \
			_add_iostats((size_t )(cc), 0); \
	} while(0)
#else
#define _SYSIO_UPDACCT(w, cc)
#endif

extern ssize_t _sysio_validx(const struct intnl_xtvec *xtv, size_t xtvlen,
			     const struct iovec *iov, size_t iovlen,
			     _SYSIO_OFF_T limit);
extern ssize_t _sysio_enumerate_extents(const struct intnl_xtvec *xtv,
					size_t xtvlen,
					const struct iovec *iov,
					size_t iovlen,
					ssize_t (*f)(const struct iovec *,
						     int,
						     _SYSIO_OFF_T,
						     ssize_t,
						     void *),
					void *arg);
extern ssize_t _sysio_enumerate_iovec(const struct iovec *iov,
				      size_t count,
				      _SYSIO_OFF_T off,
				      ssize_t limit,
				      ssize_t (*f)(void *,
						   size_t,
						   _SYSIO_OFF_T,
						   void *),
				      void *arg);
extern ssize_t _sysio_doio(const struct intnl_xtvec *xtv, size_t xtvlen,
			   const struct iovec *iov, size_t iovlen,
			   ssize_t (*f)(void *, size_t, _SYSIO_OFF_T, void *),
			   void *arg);
