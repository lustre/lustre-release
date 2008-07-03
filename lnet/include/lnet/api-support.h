#ifndef __LNET_API_SUPPORT_H__
#define __LNET_API_SUPPORT_H__

#if defined(__linux__)
#include <lnet/linux/api-support.h>
#elif defined(__APPLE__)
#include <lnet/darwin/api-support.h>
#elif defined(__WINNT__)
#include <lnet/winnt/api-support.h>
#else
#error Unsupported Operating System
#endif

#include <libcfs/libcfs.h>
#include <lnet/types.h>
#include <lnet/lnet.h>

#endif
