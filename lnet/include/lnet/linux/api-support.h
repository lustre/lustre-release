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
#endif

#endif
