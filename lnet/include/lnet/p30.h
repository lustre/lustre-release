/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _P30_H_
#define _P30_H_

#include "build_check.h"

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
#include <portals/api.h>

#endif
