#ifndef __DARWIN_API_SUPPORT_H__
#define __DARWIN_API_SUPPORT_H__

#ifndef __LNET_API_SUPPORT_H__
#error Do not #include this file directly. #include <portals/api-support.h> instead
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

# ifdef HAVE_LIBREADLINE
#  include <readline/readline.h>
typedef VFunction	rl_vintfunc_t;
typedef VFunction	rl_voidfunc_t;
# endif
#endif


#endif
