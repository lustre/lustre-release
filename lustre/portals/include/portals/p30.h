/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _P30_H_
#define _P30_H_

/*
 * p30.h
 *
 * User application interface file
 */

#if defined (__KERNEL__)
#include <linux/uio.h>
#include <linux/types.h>
#else
#include <sys/types.h>
#include <sys/uio.h>
#endif

#include <portals/types.h>
#include <portals/nal.h>
#include <portals/api.h>
#include <portals/errno.h>
#include <portals/nalids.h>

extern int __p30_initialized;	/* for libraries & test codes  */
extern int __p30_myr_initialized;	/*   that don't know if p30    */
extern int __p30_ip_initialized;	/*   had been initialized yet  */
extern ptl_handle_ni_t __myr_ni_handle, __ip_ni_handle;

extern int __p30_myr_timeout;	/* in seconds, for PtlNIBarrier,     */
extern int __p30_ip_timeout;	/* PtlReduce_all, & PtlBroadcast_all */

/*
 * Debugging flags reserved for the Portals reference library.
 * These are not part of the API as described in the SAND report
 * but are for the use of the maintainers of the reference implementation.
 *
 * It is not expected that the real implementations will export
 * this functionality.
 */
#define PTL_DEBUG_NONE          0ul
#define PTL_DEBUG_ALL           (0x0FFFul)	/* Only the Portals flags */

#define __bit(x)                ((unsigned long) 1<<(x))
#define PTL_DEBUG_PUT           __bit(0)
#define PTL_DEBUG_GET           __bit(1)
#define PTL_DEBUG_REPLY         __bit(2)
#define PTL_DEBUG_ACK           __bit(3)
#define PTL_DEBUG_DROP          __bit(4)
#define PTL_DEBUG_REQUEST       __bit(5)
#define PTL_DEBUG_DELIVERY      __bit(6)
#define PTL_DEBUG_UNLINK        __bit(7)
#define PTL_DEBUG_THRESHOLD     __bit(8)
#define PTL_DEBUG_API           __bit(9)

/*
 * These eight are reserved for the NAL to define
 * It should probably give them better names...
 */
#define PTL_DEBUG_NI_ALL        (0xF000ul)	/* Only the NAL flags */
#define PTL_DEBUG_NI0           __bit(24)
#define PTL_DEBUG_NI1           __bit(25)
#define PTL_DEBUG_NI2           __bit(26)
#define PTL_DEBUG_NI3           __bit(27)
#define PTL_DEBUG_NI4           __bit(28)
#define PTL_DEBUG_NI5           __bit(29)
#define PTL_DEBUG_NI6           __bit(30)
#define PTL_DEBUG_NI7           __bit(31)

#endif
