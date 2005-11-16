/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2002 Eric Hoffman
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 */

/* TODO: make this an explicit type when they become available */
typedef unsigned long long when;

typedef struct timer {
  void (*function)(void *);
  void *arg;
  when w;
  int interval;
  int disable;
} *timer;

timer register_timer(when, void (*f)(void *), void *a);
void remove_timer(timer t);
void timer_loop(void);
void initialize_timer(void);
void register_thunk(void (*f)(void *),void *a);


#define HZ 0x100000000ull


