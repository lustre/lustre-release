/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cray Inc.
 *  Copyright (c) 2002 Eric Hoffman
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2.1 of the GNU Lesser General
 *   Public License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* timer.c:
 *   this file implements a simple priority-queue based timer system. when
 * combined with a file which implements now() and block(), it can
 * be used to provide course-grained time-based callbacks.
 */

#include <pqtimer.h>
#include <stdlib.h>
#include <string.h>

struct timer {
  void (*function)(void *);
  void *arg;
  when w;
  int interval;
  int disable;
};

typedef struct thunk *thunk;
struct thunk {
    void (*f)(void *);
    void *a;
    thunk next;
};

extern when now(void);

static thunk thunks;
static int internal;
static void (*block_function)(when);
static int number_of_timers;
static int size_of_pqueue;
static timer *timers;


static void heal(int where)
{
    int left=(where<<1);
    int right=(where<<1)+1;
    int min=where;
    timer temp;
  
    if (left <= number_of_timers)
	if (timers[left]->w < timers[min]->w) min=left;
    if (right <= number_of_timers)
	if (timers[right]->w < timers[min]->w) min=right;
    if (min != where){
	temp=timers[where];
	timers[where]=timers[min];
	timers[min]=temp;
	heal(min);
    }
}

static void add_pqueue(int i)
{
    timer temp;
    int parent=(i>>1);
    if ((i>1) && (timers[i]->w< timers[parent]->w)){
	temp=timers[i];
	timers[i]=timers[parent];
	timers[parent]=temp;
	add_pqueue(parent);
    }
}

static void add_timer(timer t)
{
    if (size_of_pqueue<(number_of_timers+2)){
	int oldsize=size_of_pqueue;
	timer *new=(void *)malloc(sizeof(struct timer)*(size_of_pqueue+=10));
	memcpy(new,timers,sizeof(timer)*oldsize);
	timers=new;
    }
    timers[++number_of_timers]=t;
    add_pqueue(number_of_timers);
}

/* Function: register_timer
 * Arguments: interval: the time interval from the current time when
 *                      the timer function should be called
 *            function: the function to call when the time has expired
 *            argument: the argument to call it with.
 * Returns: a pointer to a timer structure
 */
timer register_timer(when interval,
		     void (*function)(void *),
		     void *argument)
{
    timer t=(timer)malloc(sizeof(struct timer));

    t->arg=argument;
    t->function=function;
    t->interval=interval;
    t->disable=0;
    t->w=now()+interval;
    add_timer(t);
    if (!internal && (number_of_timers==1))
        block_function(t->w);
    return(t);
}

/* Function: remove_timer
 * Arguments: t: 
 * Returns: nothing
 *
 * remove_timer removes a timer from the system, insuring
 * that it will never be called. It does not actually
 * free the timer due to reentrancy issues.
 */

void remove_timer(timer t)
{
    t->disable=1;
}



void timer_fire()
{
    timer current;

    current=timers[1];
    timers[1]=timers[number_of_timers--];
    heal(1);
    if (!current->disable) {
        (*current->function)(current->arg);
    }
    free(current);
}

when next_timer(void)
{
    when here=now();

    while (number_of_timers && (timers[1]->w <= here)) timer_fire();
    if (number_of_timers) return(timers[1]->w);
    return(0);
}

/* Function: timer_loop
 * Arguments: none
 * Returns: never
 * 
 * timer_loop() is the blocking dispatch function for the timer.
 * Is calls the block() function registered with init_timer,
 * and handles associated with timers that have been registered.
 */
void timer_loop()
{
    when here;

    while (1){
	thunk z;
	here=now();

	for (z=thunks;z;z=z->next) (*z->f)(z->a);

	if (number_of_timers){
	    if (timers[1]->w > here){
		(*block_function)(timers[1]->w);
	    } else {
                timer_fire();
	    }
	} else {
	    thunk z;
	    for (z=thunks;z;z=z->next) (*z->f)(z->a);
	    (*block_function)(0);
	}
    }
}


/* Function: register_thunk
 * Arguments: f: the function to call
 *            a: the single argument to call it with
 *
 * Thunk functions get called at irregular intervals, they
 * should not assume when, or take a particularily long
 * amount of time. Thunks are for background cleanup tasks.
 */
void register_thunk(void (*f)(void *),void *a)
{
    thunk t=(void *)malloc(sizeof(struct thunk));
    t->f=f;
    t->a=a;
    t->next=thunks;
    thunks=t;
}

/* Function: initialize_timer
 * Arguments: block: the function to call to block for the specified interval 
 *
 * initialize_timer() must be called before any other timer function,
 * including timer_loop.
 */
void initialize_timer(void (*block)(when))
{
    block_function=block;
    number_of_timers=0;
    size_of_pqueue=10;
    timers=(timer *)malloc(sizeof(timer)*size_of_pqueue);
    thunks=0;
}
