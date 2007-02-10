#ifndef __LINUX_API_SUPPORT_H__
#define __LINUX_API_SUPPORT_H__

#ifndef __LNET_API_SUPPORT_H__
#error Do not #include this file directly. #include <lnet /api-support.h> instead
#endif

#ifndef __KERNEL__
# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <time.h>

/* Lots of POSIX dependencies to support PtlEQWait_timeout */
# include <signal.h>
# include <setjmp.h>
# include <time.h>

#ifdef HAVE_LIBREADLINE
#define READLINE_LIBRARY
#include <readline/readline.h>

/* readline.h pulls in a #define that conflicts with one in libcfs.h */
#undef RETURN

/* completion_matches() is #if 0-ed out in modern glibc */
#ifndef completion_matches
#  define completion_matches rl_completion_matches
#endif

#endif /* HAVE_LIBREADLINE */

extern void using_history(void);
extern void stifle_history(int);
extern void add_history(char *);

#endif /* !__KERNEL__ */

#endif
