/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * api/api-errno.c
 * Instantiate the string table of errors
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
 */

/* If you change these, you must update the number table in portals/errno.h */
const char *ptl_err_str[] = {
        "PTL_OK",
        "PTL_SEGV",

        "PTL_NO_SPACE",
        "PTL_ME_IN_USE",
        "PTL_VAL_FAILED",

        "PTL_NAL_FAILED",
        "PTL_NO_INIT",
        "PTL_IFACE_DUP",
        "PTL_IFACE_INVALID",

        "PTL_HANDLE_INVALID",
        "PTL_MD_INVALID",
        "PTL_ME_INVALID",
/* If you change these, you must update the number table in portals/errno.h */
        "PTL_PROCESS_INVALID",
        "PTL_PT_INDEX_INVALID",

        "PTL_SR_INDEX_INVALID",
        "PTL_EQ_INVALID",
        "PTL_EQ_DROPPED",

        "PTL_EQ_EMPTY",
        "PTL_MD_NO_UPDATE",
        "PTL_FAIL",

        "PTL_IOV_TOO_MANY",
        "PTL_IOV_TOO_SMALL",

        "PTL_EQ_IN_USE",

        "PTL_MAX_ERRNO"
};
/* If you change these, you must update the number table in portals/errno.h */
