/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LNET_LINUX_LNET_H__
#define __LNET_LINUX_LNET_H__

#ifndef __LNET_H__
#error Do not #include this file directly. #include <lnet/lnet.h> instead
#endif

/*
 * lnet.h
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
