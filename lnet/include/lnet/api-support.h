# define DEBUG_SUBSYSTEM S_PORTALS
# define PORTAL_DEBUG

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
#include <linux/kp30.h>
#include <portals/p30.h>

#include <portals/internal.h>
#include <portals/nal.h>
#include <portals/arg-blocks.h>

/* Hack for 2.4.18 macro name collision */
#ifdef yield
#undef yield
#endif
