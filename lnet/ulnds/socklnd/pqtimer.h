/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2002 Eric Hoffman
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

typedef unsigned long long when;
when now(void);
typedef struct timer *timer;
timer register_timer(when interval,
		     void (*function)(void *),
		     void *argument);
timer register_timer_wait(void);
void remove_timer(timer);
void timer_loop(void);
void initialize_timer(void (*block)(when));
void timer_fire(void);


#define HZ 0x100000000ull


