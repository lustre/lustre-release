#ifndef _P30_ERRNO_H_
#define _P30_ERRNO_H_

/*
 * include/portals/errno.h
 *
 * Shared error number lists
 */

/* If you change these, you must update the string table in api-errno.c */
typedef enum {
        PTL_OK              = 0,
        PTL_SEGV            = 1,

        PTL_NOSPACE         = 2,
        PTL_INUSE           = 3,
        PTL_VAL_FAILED      = 4,

        PTL_NAL_FAILED      = 5,
        PTL_NOINIT          = 6,
        PTL_INIT_DUP        = 7,
        PTL_INIT_INV        = 8,
        PTL_AC_INV_INDEX    = 9,

        PTL_INV_ASIZE       = 10,
        PTL_INV_HANDLE      = 11,
        PTL_INV_MD          = 12,
        PTL_INV_ME          = 13,
        PTL_INV_NI          = 14,
/* If you change these, you must update the string table in api-errno.c */
        PTL_ILL_MD          = 15,
        PTL_INV_PROC        = 16,
        PTL_INV_PSIZE       = 17,
        PTL_INV_PTINDEX     = 18,
        PTL_INV_REG         = 19,

        PTL_INV_SR_INDX     = 20,
        PTL_ML_TOOLONG      = 21,
        PTL_ADDR_UNKNOWN    = 22,
        PTL_INV_EQ          = 23,
        PTL_EQ_DROPPED      = 24,

        PTL_EQ_EMPTY        = 25,
        PTL_NOUPDATE        = 26,
        PTL_FAIL            = 27,
        PTL_NOT_IMPLEMENTED = 28,
        PTL_NO_ACK          = 29,

        PTL_IOV_TOO_MANY    = 30,
        PTL_IOV_TOO_SMALL   = 31,

	PTL_EQ_INUSE        = 32,
	PTL_MD_INUSE        = 33,

        PTL_MAX_ERRNO       = 33
} ptl_err_t;
/* If you change these, you must update the string table in api-errno.c */

extern const char *ptl_err_str[];

#endif
