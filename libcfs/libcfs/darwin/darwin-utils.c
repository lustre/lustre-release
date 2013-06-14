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
 * libcfs/libcfs/darwin/darwin-utils.c
 *
 * Darwin porting library
 * Make things easy to port
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <mach/mach_types.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <lnet/types.h>

#include <libcfs/libcfs.h>

#ifndef isspace
inline int
isspace(char c)
{
        return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}
#endif

char * strpbrk(const char * cs,const char * ct)
{
	const char *sc1,*sc2;
	
	for( sc1 = cs; *sc1 != '\0'; ++sc1) {
		for( sc2 = ct; *sc2 != '\0'; ++sc2) {
			if (*sc1 == *sc2)
				return (char *) sc1;
		}
	}
	return NULL;
}

char * strsep(char **s, const char *ct)
{
	char *sbegin = *s, *end;
	
	if (sbegin == NULL)
		return NULL;
	end = strpbrk(sbegin, ct);
	if (end != NULL)
		*end++ = '\0';
	*s = end;

	return sbegin;
}

size_t strnlen(const char * s, size_t count)
{
	const char *sc;

	for (sc = s; count-- && *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}

char *
strstr(const char *in, const char *str)
{
	char c;
	size_t len;
	
	c = *str++;
	if (!c)
		return (char *) in;     // Trivial empty string case
	len = strlen(str);
	do {
		char sc;
		do {
			sc = *in++;
			if (!sc)
				return (char *) 0;
		} while (sc != c);
	} while (strncmp(in, str, len) != 0);
	return (char *) (in - 1);
}

char *
strrchr(const char *p, int ch)
{
        const char *end = p + strlen(p);
        do {
                if (*end == (char)ch)
                        return (char *)end;
        } while (--end >= p);
        return NULL;
}

char *
ul2dstr(unsigned long address, char *buf, int len)
{
        char *pos = buf + len - 1;

        if (len <= 0 || !buf)
                return NULL;
        *pos = 0;
        while (address) {
                if (!--len) break;
                *--pos = address % 10 + '0';
                address /= 10;
        }
        return pos;
}

/*
 * miscellaneous libcfs stuff
 */

/*
 * Convert server error code to client format.
 * Linux errno.h.
 */

/* obtained by
 *
 *     cc /usr/include/asm/errno.h -E -dM | grep '#define E' | sort -n -k3,3
 *
 */
enum linux_errnos {
	LINUX_EPERM		 = 1,
	LINUX_ENOENT		 = 2,
	LINUX_ESRCH		 = 3,
	LINUX_EINTR		 = 4,
	LINUX_EIO		 = 5,
	LINUX_ENXIO		 = 6,
	LINUX_E2BIG		 = 7,
	LINUX_ENOEXEC		 = 8,
	LINUX_EBADF		 = 9,
	LINUX_ECHILD		 = 10,
	LINUX_EAGAIN		 = 11,
	LINUX_ENOMEM		 = 12,
	LINUX_EACCES		 = 13,
	LINUX_EFAULT		 = 14,
	LINUX_ENOTBLK		 = 15,
	LINUX_EBUSY		 = 16,
	LINUX_EEXIST		 = 17,
	LINUX_EXDEV		 = 18,
	LINUX_ENODEV		 = 19,
	LINUX_ENOTDIR		 = 20,
	LINUX_EISDIR		 = 21,
	LINUX_EINVAL		 = 22,
	LINUX_ENFILE		 = 23,
	LINUX_EMFILE		 = 24,
	LINUX_ENOTTY		 = 25,
	LINUX_ETXTBSY		 = 26,
	LINUX_EFBIG		 = 27,
	LINUX_ENOSPC		 = 28,
	LINUX_ESPIPE		 = 29,
	LINUX_EROFS		 = 30,
	LINUX_EMLINK		 = 31,
	LINUX_EPIPE		 = 32,
	LINUX_EDOM		 = 33,
	LINUX_ERANGE		 = 34,
	LINUX_EDEADLK		 = 35,
	LINUX_ENAMETOOLONG	 = 36,
	LINUX_ENOLCK		 = 37,
	LINUX_ENOSYS		 = 38,
	LINUX_ENOTEMPTY		 = 39,
	LINUX_ELOOP		 = 40,
	LINUX_ENOMSG		 = 42,
	LINUX_EIDRM		 = 43,
	LINUX_ECHRNG		 = 44,
	LINUX_EL2NSYNC		 = 45,
	LINUX_EL3HLT		 = 46,
	LINUX_EL3RST		 = 47,
	LINUX_ELNRNG		 = 48,
	LINUX_EUNATCH		 = 49,
	LINUX_ENOCSI		 = 50,
	LINUX_EL2HLT		 = 51,
	LINUX_EBADE		 = 52,
	LINUX_EBADR		 = 53,
	LINUX_EXFULL		 = 54,
	LINUX_ENOANO		 = 55,
	LINUX_EBADRQC		 = 56,
	LINUX_EBADSLT		 = 57,
	LINUX_EBFONT		 = 59,
	LINUX_ENOSTR		 = 60,
	LINUX_ENODATA		 = 61,
	LINUX_ETIME		 = 62,
	LINUX_ENOSR		 = 63,
	LINUX_ENONET		 = 64,
	LINUX_ENOPKG		 = 65,
	LINUX_EREMOTE		 = 66,
	LINUX_ENOLINK		 = 67,
	LINUX_EADV		 = 68,
	LINUX_ESRMNT		 = 69,
	LINUX_ECOMM		 = 70,
	LINUX_EPROTO		 = 71,
	LINUX_EMULTIHOP		 = 72,
	LINUX_EDOTDOT		 = 73,
	LINUX_EBADMSG		 = 74,
	LINUX_EOVERFLOW		 = 75,
	LINUX_ENOTUNIQ	 	 = 76,
	LINUX_EBADFD		 = 77,
	LINUX_EREMCHG		 = 78,
	LINUX_ELIBACC		 = 79,
	LINUX_ELIBBAD		 = 80,
	LINUX_ELIBSCN		 = 81,
	LINUX_ELIBMAX		 = 82,
	LINUX_ELIBEXEC	 	 = 83,
	LINUX_EILSEQ		 = 84,
	LINUX_ERESTART		 = 85,
	LINUX_ESTRPIPE		 = 86,
	LINUX_EUSERS		 = 87,
	LINUX_ENOTSOCK	 	 = 88,
	LINUX_EDESTADDRREQ	 = 89,
	LINUX_EMSGSIZE		 = 90,
	LINUX_EPROTOTYPE	 = 91,
	LINUX_ENOPROTOOPT	 = 92,
	LINUX_EPROTONOSUPPORT	 = 93,
	LINUX_ESOCKTNOSUPPORT	 = 94,
	LINUX_EOPNOTSUPP	 = 95,
	LINUX_EPFNOSUPPORT	 = 96,
	LINUX_EAFNOSUPPORT	 = 97,
	LINUX_EADDRINUSE	 = 98,
	LINUX_EADDRNOTAVAIL	 = 99,
	LINUX_ENETDOWN		 = 100,
	LINUX_ENETUNREACH	 = 101,
	LINUX_ENETRESET		 = 102,
	LINUX_ECONNABORTED	 = 103,
	LINUX_ECONNRESET	 = 104,
	LINUX_ENOBUFS		 = 105,
	LINUX_EISCONN		 = 106,
	LINUX_ENOTCONN		 = 107,
	LINUX_ESHUTDOWN		 = 108,
	LINUX_ETOOMANYREFS	 = 109,
	LINUX_ETIMEDOUT		 = 110,
	LINUX_ECONNREFUSED	 = 111,
	LINUX_EHOSTDOWN		 = 112,
	LINUX_EHOSTUNREACH	 = 113,
	LINUX_EALREADY		 = 114,
	LINUX_EINPROGRESS	 = 115,
	LINUX_ESTALE		 = 116,
	LINUX_EUCLEAN		 = 117,
	LINUX_ENOTNAM		 = 118,
	LINUX_ENAVAIL		 = 119,
	LINUX_EISNAM		 = 120,
	LINUX_EREMOTEIO		 = 121,
	LINUX_EDQUOT		 = 122,
	LINUX_ENOMEDIUM		 = 123,
	LINUX_EMEDIUMTYPE	 = 124,

	/*
	 * we don't need these, but for completeness..
	 */
	LINUX_EDEADLOCK		 = LINUX_EDEADLK,
	LINUX_EWOULDBLOCK	 = LINUX_EAGAIN
};

int convert_server_error(__u64 ecode)
{
	int sign;
	int code;

	static int errno_xlate[] = {
		/* success is always success */
		[0]                     = 0,
		[LINUX_EPERM]		= EPERM,
		[LINUX_ENOENT]		= ENOENT,
		[LINUX_ESRCH]		= ESRCH,
		[LINUX_EINTR]		= EINTR,
		[LINUX_EIO]		= EIO,
		[LINUX_ENXIO]		= ENXIO,
		[LINUX_E2BIG]		= E2BIG,
		[LINUX_ENOEXEC]		= ENOEXEC,
		[LINUX_EBADF]		= EBADF,
		[LINUX_ECHILD]		= ECHILD,
		[LINUX_EAGAIN]		= EAGAIN,
		[LINUX_ENOMEM]		= ENOMEM,
		[LINUX_EACCES]		= EACCES,
		[LINUX_EFAULT]		= EFAULT,
		[LINUX_ENOTBLK]		= ENOTBLK,
		[LINUX_EBUSY]		= EBUSY,
		[LINUX_EEXIST]		= EEXIST,
		[LINUX_EXDEV]		= EXDEV,
		[LINUX_ENODEV]		= ENODEV,
		[LINUX_ENOTDIR]		= ENOTDIR,
		[LINUX_EISDIR]		= EISDIR,
		[LINUX_EINVAL]		= EINVAL,
		[LINUX_ENFILE]		= ENFILE,
		[LINUX_EMFILE]		= EMFILE,
		[LINUX_ENOTTY]		= ENOTTY,
		[LINUX_ETXTBSY]		= ETXTBSY,
		[LINUX_EFBIG]		= EFBIG,
		[LINUX_ENOSPC]		= ENOSPC,
		[LINUX_ESPIPE]		= ESPIPE,
		[LINUX_EROFS]		= EROFS,
		[LINUX_EMLINK]		= EMLINK,
		[LINUX_EPIPE]		= EPIPE,
		[LINUX_EDOM]		= EDOM,
		[LINUX_ERANGE]		= ERANGE,
		[LINUX_EDEADLK]		= EDEADLK,
		[LINUX_ENAMETOOLONG]	= ENAMETOOLONG,
		[LINUX_ENOLCK]		= ENOLCK,
		[LINUX_ENOSYS]		= ENOSYS,
		[LINUX_ENOTEMPTY]	= ENOTEMPTY,
		[LINUX_ELOOP]		= ELOOP,
		[LINUX_ENOMSG]		= ENOMSG,
		[LINUX_EIDRM]		= EIDRM,
		[LINUX_ECHRNG]		= EINVAL /* ECHRNG */,
		[LINUX_EL2NSYNC]	= EINVAL /* EL2NSYNC */,
		[LINUX_EL3HLT]		= EINVAL /* EL3HLT */,
		[LINUX_EL3RST]		= EINVAL /* EL3RST */,
		[LINUX_ELNRNG]		= EINVAL /* ELNRNG */,
		[LINUX_EUNATCH]		= EINVAL /* EUNATCH */,
		[LINUX_ENOCSI]		= EINVAL /* ENOCSI */,
		[LINUX_EL2HLT]		= EINVAL /* EL2HLT */,
		[LINUX_EBADE]		= EINVAL /* EBADE */,
		[LINUX_EBADR]		= EBADRPC,
		[LINUX_EXFULL]		= EINVAL /* EXFULL */,
		[LINUX_ENOANO]		= EINVAL /* ENOANO */,
		[LINUX_EBADRQC]		= EINVAL /* EBADRQC */,
		[LINUX_EBADSLT]		= EINVAL /* EBADSLT */,
		[LINUX_EBFONT]		= EINVAL /* EBFONT */,
		[LINUX_ENOSTR]		= EINVAL /* ENOSTR */,
		[LINUX_ENODATA]		= EINVAL /* ENODATA */,
		[LINUX_ETIME]		= EINVAL /* ETIME */,
		[LINUX_ENOSR]		= EINVAL /* ENOSR */,
		[LINUX_ENONET]		= EINVAL /* ENONET */,
		[LINUX_ENOPKG]		= EINVAL /* ENOPKG */,
		[LINUX_EREMOTE]		= EREMOTE,
		[LINUX_ENOLINK]		= EINVAL /* ENOLINK */,
		[LINUX_EADV]		= EINVAL /* EADV */,
		[LINUX_ESRMNT]		= EINVAL /* ESRMNT */,
		[LINUX_ECOMM]		= EINVAL /* ECOMM */,
		[LINUX_EPROTO]		= EPROTOTYPE,
		[LINUX_EMULTIHOP]	= EINVAL /* EMULTIHOP */,
		[LINUX_EDOTDOT]		= EINVAL /* EDOTDOT */,
		[LINUX_EBADMSG]		= EINVAL /* EBADMSG */,
		[LINUX_EOVERFLOW]	= EOVERFLOW,
		[LINUX_ENOTUNIQ]	= EINVAL /* ENOTUNIQ */,
		[LINUX_EBADFD]		= EINVAL /* EBADFD */,
		[LINUX_EREMCHG]		= EINVAL /* EREMCHG */,
		[LINUX_ELIBACC]		= EINVAL /* ELIBACC */,
		[LINUX_ELIBBAD]		= EINVAL /* ELIBBAD */,
		[LINUX_ELIBSCN]		= EINVAL /* ELIBSCN */,
		[LINUX_ELIBMAX]		= EINVAL /* ELIBMAX */,
		[LINUX_ELIBEXEC]	= EINVAL /* ELIBEXEC */,
		[LINUX_EILSEQ]		= EILSEQ,
		[LINUX_ERESTART]	= EINVAL /* because ERESTART is
                                                  * negative in XNU */,
		[LINUX_ESTRPIPE]	= EINVAL /* ESTRPIPE */,
		[LINUX_EUSERS]		= EUSERS,
		[LINUX_ENOTSOCK]	= ENOTSOCK,
		[LINUX_EDESTADDRREQ]	= EDESTADDRREQ,
		[LINUX_EMSGSIZE]	= EMSGSIZE,
		[LINUX_EPROTOTYPE]	= EPROTOTYPE,
		[LINUX_ENOPROTOOPT]	= ENOPROTOOPT,
		[LINUX_EPROTONOSUPPORT]	= EPROTONOSUPPORT,
		[LINUX_ESOCKTNOSUPPORT]	= ESOCKTNOSUPPORT,
		[LINUX_EOPNOTSUPP]	= EOPNOTSUPP,
		[LINUX_EPFNOSUPPORT]	= EPFNOSUPPORT,
		[LINUX_EAFNOSUPPORT]	= EAFNOSUPPORT,
		[LINUX_EADDRINUSE]	= EADDRINUSE,
		[LINUX_EADDRNOTAVAIL]	= EADDRNOTAVAIL,
		[LINUX_ENETDOWN]	= ENETDOWN,
		[LINUX_ENETUNREACH]	= ENETUNREACH,
		[LINUX_ENETRESET]	= ENETRESET,
		[LINUX_ECONNABORTED]	= ECONNABORTED,
		[LINUX_ECONNRESET]	= ECONNRESET,
		[LINUX_ENOBUFS]		= ENOBUFS,
		[LINUX_EISCONN]		= EISCONN,
		[LINUX_ENOTCONN]	= ENOTCONN,
		[LINUX_ESHUTDOWN]	= ESHUTDOWN,
		[LINUX_ETOOMANYREFS]	= ETOOMANYREFS,
		[LINUX_ETIMEDOUT]	= ETIMEDOUT,
		[LINUX_ECONNREFUSED]	= ECONNREFUSED,
		[LINUX_EHOSTDOWN]	= EHOSTDOWN,
		[LINUX_EHOSTUNREACH]	= EHOSTUNREACH,
		[LINUX_EALREADY]	= EALREADY,
		[LINUX_EINPROGRESS]	= EINPROGRESS,
		[LINUX_ESTALE]		= ESTALE,
		[LINUX_EUCLEAN]		= EINVAL /* EUCLEAN */,
		[LINUX_ENOTNAM]		= EINVAL /* ENOTNAM */,
		[LINUX_ENAVAIL]		= EINVAL /* ENAVAIL */,
		[LINUX_EISNAM]		= EINVAL /* EISNAM */,
		[LINUX_EREMOTEIO]	= EINVAL /* EREMOTEIO */,
		[LINUX_EDQUOT]		= EDQUOT,
		[LINUX_ENOMEDIUM]	= EINVAL /* ENOMEDIUM */,
		[LINUX_EMEDIUMTYPE]	= EINVAL /* EMEDIUMTYPE */,
	};
	code = (int)ecode;
	if (code >= 0) {
		sign = +1;
	} else {
		sign = -1;
		code = -code;
	}
	if (code < (sizeof errno_xlate) / (sizeof errno_xlate[0])) {
		code = errno_xlate[code];
		LASSERT(code >= 0);
        }
	return sign * code;
}

enum {
	LINUX_O_RDONLY   =	     00,
	LINUX_O_WRONLY   =	     01,
	LINUX_O_RDWR     =	     02,
	LINUX_O_CREAT    =	   0100,
	LINUX_O_EXCL	 =	   0200,
	LINUX_O_NOCTTY   =	   0400,
	LINUX_O_TRUNC    =	  01000,
	LINUX_O_APPEND   =	  02000,
	LINUX_O_NONBLOCK =	  04000,
	LINUX_O_NDELAY	 =	       LINUX_O_NONBLOCK,
	LINUX_O_SYNC     =	 010000,
	LINUX_O_FSYNC    =	       LINUX_O_SYNC,
	LINUX_O_ASYNC    =	 020000,
	LINUX_O_DIRECT   =	 040000,
	LINUX_O_NOFOLLOW =	0400000
};

static inline void obit_convert(int *cflag, int *sflag,
				unsigned cmask, unsigned smask)
{
	if (*cflag & cmask != 0) {
		*sflag |= smask;
		*cflag &= ~cmask;
	}
}

/*
 * convert <fcntl.h> flag from XNU client to Linux _i386_ server.
 */
int convert_client_oflag(int cflag, int *result)
{
	int sflag = 0;

	cflag = 0;
	obit_convert(&cflag, &sflag, O_RDONLY,   LINUX_O_RDONLY);
	obit_convert(&cflag, &sflag, O_WRONLY,   LINUX_O_WRONLY);
	obit_convert(&cflag, &sflag, O_RDWR,     LINUX_O_RDWR);
	obit_convert(&cflag, &sflag, O_NONBLOCK, LINUX_O_NONBLOCK);
	obit_convert(&cflag, &sflag, O_APPEND,   LINUX_O_APPEND);
	obit_convert(&cflag, &sflag, O_ASYNC,    LINUX_O_ASYNC);
	obit_convert(&cflag, &sflag, O_FSYNC,    LINUX_O_FSYNC);
	obit_convert(&cflag, &sflag, O_NOFOLLOW, LINUX_O_NOFOLLOW);
	obit_convert(&cflag, &sflag, O_CREAT,    LINUX_O_CREAT);
	obit_convert(&cflag, &sflag, O_TRUNC,    LINUX_O_TRUNC);
	obit_convert(&cflag, &sflag, O_EXCL,     LINUX_O_EXCL);
	obit_convert(&cflag, &sflag, O_CREAT,    LINUX_O_CREAT);
	obit_convert(&cflag, &sflag, O_NDELAY,   LINUX_O_NDELAY);
	obit_convert(&cflag, &sflag, O_NOCTTY,   LINUX_O_NOCTTY);
	/*
	 * Some more obscure BSD flags have no Linux counterparts:
	 *
	 * O_SHLOCK	0x0010
	 * O_EXLOCK	0x0020
	 * O_EVTONLY	0x8000
	 * O_POPUP   	0x80000000
	 * O_ALERT   	0x20000000
	 */
	if (cflag == 0) {
		*result = sflag;
		return 0;
	} else
		return -EINVAL;
}

#ifdef __DARWIN8__
#else /* !__DARWIN8__ */
extern int unix_syscall();
extern int unix_syscall_return();

extern int ktrsysret();
extern int ktrace();

extern int ast_taken();
extern int ast_check();

extern int trap();
extern int syscall_trace();

static int is_addr_in_range(void *addr, void *start, void *end)
{
	return start <= addr && addr <= end;
}

extern void cfs_thread_agent (void);

static int is_last_frame(void *addr)
{
	if (addr == NULL)
		return 1;
	else if (is_addr_in_range(addr, unix_syscall, unix_syscall_return))
		return 1;
	else if (is_addr_in_range(addr, ktrsysret, ktrace))
		return 1;
	else if (is_addr_in_range(addr, ast_taken, ast_check))
		return 1;
	else if (is_addr_in_range(addr, trap, syscall_trace))
		return 1;
	else if (is_addr_in_range(addr, cfs_thread_agent, kthread_run))
		return 1;
	else
		return 0;
}

static void *get_frame(int i)
{
	void *result;

#define CASE(i) case (i): result = __builtin_return_address(i); break
	switch (i + 1) {
		CASE(1);
		CASE(2);
		CASE(3);
		CASE(4);
		CASE(5);
		CASE(6);
		CASE(7);
		CASE(8);
		CASE(9);
		CASE(10);
		CASE(11);
		CASE(12);
		CASE(13);
		CASE(14);
		CASE(15);
		CASE(16);
		CASE(17);
		CASE(18);
		CASE(19);
		CASE(20);
	default:
		panic("impossible frame number: %d\n", i);
		result = NULL;
	}
	return result;
}

void cfs_stack_trace_fill(struct cfs_stack_trace *trace)
{
	int i;

	memset(trace, 0, sizeof *trace);
	for (i = 0; i < ARRAY_SIZE(trace->frame); ++ i) {
		void *addr;

		addr = get_frame(i);
		trace->frame[i] = addr;
		if (is_last_frame(addr))
			break;
	}
}

void *cfs_stack_trace_frame(struct cfs_stack_trace *trace, int frame_no)
{
        if (0 <= frame_no && frame_no < ARRAY_SIZE(trace->frame))
                return trace->frame[frame_no];
        else
                return NULL;
}
#endif /* !__DARWIN8__ */
