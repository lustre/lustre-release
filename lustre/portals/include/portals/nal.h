#ifndef _NAL_H_
#define _NAL_H_

#include "build_check.h"

/*
 * p30/nal.h
 *
 * The API side NAL declarations
 */

#include <portals/types.h>

#ifdef yield
#undef yield
#endif

typedef struct nal_t nal_t;

struct nal_t {
	int              nal_refct;
	void            *nal_data;

	int (*startup) (nal_t *nal, ptl_pid_t requested_pid,
			ptl_ni_limits_t *req, ptl_ni_limits_t *actual);
	
	void (*shutdown) (nal_t *nal);

	int (*forward) (nal_t *nal, int index,	/* Function ID */
			void *args, size_t arg_len, void *ret, size_t ret_len);

	int (*yield) (nal_t *nal, unsigned long *flags, int milliseconds);

	void (*lock) (nal_t *nal, unsigned long *flags);

	void (*unlock) (nal_t *nal, unsigned long *flags);
};

extern nal_t *ptl_hndl2nal(ptl_handle_any_t * any);

#ifdef __KERNEL__
extern int ptl_register_nal(ptl_interface_t interface, nal_t *nal);
extern void ptl_unregister_nal(ptl_interface_t interface);
#endif

#endif
