#ifndef _P30_INTERNAL_H_
#define _P30_INTERNAL_H_

#include "build_check.h"
/*
 * p30/internal.h
 *
 * Internals for the API level library that are not needed
 * by the user application
 */

#include <portals/p30.h>

extern int ptl_init;		/* Has the library been initialized */

extern int ptl_ni_init(void);
extern void ptl_ni_fini(void);

static inline ptl_eq_t *
ptl_handle2usereq (ptl_handle_eq_t *handle)
{
        /* EQ handles are a little wierd.  On the "user" side, the cookie
         * is just a pointer to a queue of events in shared memory.  It's
         * cb_eq_handle is the "real" handle which we pass when we
         * call do_forward(). */
        return (ptl_eq_t *)((unsigned long)handle->cookie);
}

#endif
