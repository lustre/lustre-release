/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LNET_H__
#define __LNET_H__

/*
 * lnet.h
 *
 * User application interface file
 */
#if defined(__linux__)
#include <lnet/linux/lnet.h>
#elif defined(__APPLE__)
#include <lnet/darwin/lnet.h>
#elif defined(__WINNT__)
#include <lnet/winnt/lnet.h>
#else
#error Unsupported Operating System
#endif

#include <lnet/types.h>
#include <lnet/api.h>

#endif
