#ifndef _LUSTRE_TYPES_H
#define _LUSTRE_TYPES_H

#if defined(__linux__)
#include <linux/types.h>
#elif defined(__APPLE__)
#include <darwin/types.h>
#elif defined(__WINNT__)
#include <winnt/types.h>
#else
#error Unsupported operating system.
#endif

#endif
