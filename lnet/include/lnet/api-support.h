#ifndef __API_SUPPORT_H__
#define __API_SUPPORT_H__
#include "build_check.h"

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

#include <portals/types.h>
#include <libcfs/kp30.h>
#include <portals/p30.h>

#include <portals/internal.h>
#include <portals/nal.h>

#endif
