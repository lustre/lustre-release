/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __PORTALS_LINUX_P30_H__
#define __PORTALS_LINUX_P30_H__

#ifndef __PORTALS_P30_H__
#error Do not #include this file directly. #include <portals/p30.h> instead
#endif

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

#endif
