/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * api/api-errno.c
 * Instantiate the string table of errors
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *  Copyright (c) 2001-2002 Sandia National Laboratories
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

#include <portals/api-support.h>

/* If you change these, you must update the number table in portals/errno.h */
const char *ptl_err_str[] = {
        "PTL_OK",
        "PTL_SEGV",

        "PTL_NOSPACE",
        "PTL_INUSE",
        "PTL_VAL_FAILED",

        "PTL_NAL_FAILED",
        "PTL_NOINIT",
        "PTL_INIT_DUP",
        "PTL_INIT_INV",
        "PTL_AC_INV_INDEX",

        "PTL_INV_ASIZE",
        "PTL_INV_HANDLE",
        "PTL_INV_MD",
        "PTL_INV_ME",
        "PTL_INV_NI",
/* If you change these, you must update the number table in portals/errno.h */
        "PTL_ILL_MD",
        "PTL_INV_PROC",
        "PTL_INV_PSIZE",
        "PTL_INV_PTINDEX",
        "PTL_INV_REG",

        "PTL_INV_SR_INDX",
        "PTL_ML_TOOLONG",
        "PTL_ADDR_UNKNOWN",
        "PTL_INV_EQ",
        "PTL_EQ_DROPPED",

        "PTL_EQ_EMPTY",
        "PTL_NOUPDATE",
        "PTL_FAIL",
        "PTL_NOT_IMPLEMENTED",
        "PTL_NO_ACK",

        "PTL_IOV_TOO_MANY",
        "PTL_IOV_TOO_SMALL",

        "PTL_EQ_INUSE",
        "PTL_MD_INUSE"
};
/* If you change these, you must update the number table in portals/errno.h */
