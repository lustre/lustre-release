/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LIBCFS_PORTALS_UTILS_H__
#define __LIBCFS_PORTALS_UTILS_H__

/*
 * portals_utils.h
 *
 */
#if defined(__linux__)
#include <libcfs/linux/portals_utils.h>
#elif defined(__APPLE__)
#include <libcfs/darwin/portals_utils.h>
#elif defined(__WINNT__)
#include <libcfs/winnt/portals_utils.h>
#else
#error Unsupported Operating System
#endif

#endif
