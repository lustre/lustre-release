/*
** $Id: nal.h,v 1.1.8.1 2003/05/23 07:02:36 adilger Exp $
*/
#ifndef _NAL_H_
#define _NAL_H_

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
	ptl_ni_t ni;
	int refct;
	void *nal_data;
	int *timeout;		/* for libp30api users */
	int (*forward) (nal_t * nal, int index,	/* Function ID */
			void *args, size_t arg_len, void *ret, size_t ret_len);

	int (*shutdown) (nal_t * nal, int interface);

	int (*validate) (nal_t * nal, void *base, size_t extent);

	void (*yield) (nal_t * nal);

	void (*lock) (nal_t * nal, unsigned long *flags);

	void (*unlock) (nal_t * nal, unsigned long *flags);
};

typedef nal_t *(ptl_interface_t) (int, ptl_pt_index_t, ptl_ac_index_t, ptl_pid_t requested_pid);
extern nal_t *PTL_IFACE_IP(int, ptl_pt_index_t, ptl_ac_index_t, ptl_pid_t requested_pid);
extern nal_t *PTL_IFACE_MYR(int, ptl_pt_index_t, ptl_ac_index_t, ptl_pid_t requested_pid);

extern nal_t *ptl_hndl2nal(ptl_handle_any_t * any);

#ifndef PTL_IFACE_DEFAULT
#define PTL_IFACE_DEFAULT (PTL_IFACE_IP)
#endif

#endif
