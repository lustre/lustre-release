#ifndef _P30_ERRNO_H_
#define _P30_ERRNO_H_

#include "build_check.h"
/*
 * include/portals/errno.h
 *
 * Shared error number lists
 */

/* If you change these, you must update the string table in api-errno.c */
typedef enum {
        PTL_OK			= 0,
        PTL_SEGV		= 1,

        PTL_NO_SPACE		= 2,
        PTL_ME_IN_USE		= 3,
        PTL_VAL_FAILED		= 4,

        PTL_NAL_FAILED		= 5,
        PTL_NO_INIT		= 6,
        PTL_IFACE_DUP		= 7,
        PTL_IFACE_INVALID	= 8,

        PTL_HANDLE_INVALID	= 9,
        PTL_MD_INVALID		= 10,
        PTL_ME_INVALID		= 11,
/* If you change these, you must update the string table in api-errno.c */
        PTL_PROCESS_INVALID	= 12,
        PTL_PT_INDEX_INVALID	= 13,

        PTL_SR_INDEX_INVALID	= 14,
        PTL_EQ_INVALID		= 15,
        PTL_EQ_DROPPED		= 16,

        PTL_EQ_EMPTY		= 17,
        PTL_MD_NO_UPDATE	= 18,
        PTL_FAIL		= 19,

        PTL_IOV_INVALID 	= 20,

	PTL_EQ_IN_USE		= 21,

        PTL_MAX_ERRNO		= 22
} ptl_err_t;
/* If you change these, you must update the string table in api-errno.c */

extern const char *ptl_err_str[];

#endif
