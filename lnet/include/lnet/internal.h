/*
** $Id: internal.h,v 1.1.2.1 2003/05/19 04:25:31 braam Exp $
*/
#ifndef _P30_INTERNAL_H_
#define _P30_INTERNAL_H_

/*
 * p30/internal.h
 *
 * Internals for the API level library that are not needed
 * by the user application
 */

#include <portals/p30.h>

extern int ptl_init;		/* Has the library be initialized */

extern int ptl_ni_init(void);
extern int ptl_me_init(void);
extern int ptl_md_init(void);
extern int ptl_eq_init(void);

extern int ptl_me_ni_init(nal_t * nal);
extern int ptl_md_ni_init(nal_t * nal);
extern int ptl_eq_ni_init(nal_t * nal);

extern void ptl_ni_fini(void);
extern void ptl_me_fini(void);
extern void ptl_md_fini(void);
extern void ptl_eq_fini(void);

extern void ptl_me_ni_fini(nal_t * nal);
extern void ptl_md_ni_fini(nal_t * nal);
extern void ptl_eq_ni_fini(nal_t * nal);

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
