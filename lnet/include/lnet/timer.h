#ifndef _PORTALS_TIMER_H
#define _PORTALS_TIMER_H

/* same as linux/timer.h, but for user space */

#define time_after(a,b)         ((long)(b) - (long)(a) < 0)

#endif
