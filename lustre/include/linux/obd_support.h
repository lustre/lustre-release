#ifndef _OBD_SUPPORT
#define _OBD_SUPPORT
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#include <linux/autoconf.h>
#include <linux/slab.h>
#include <linux/kp30.h>

/* global variables */
extern int obd_debug_level;
extern unsigned long obd_memory;

#define OBD_ALLOC(ptr, size)                                    \
do {                                                            \
        long s = (size);                                        \
        (ptr) = kmalloc(s, GFP_KERNEL);                         \
        if ((ptr) == NULL) {                                    \
                CERROR("kernel malloc of %ld bytes failed at "  \
                       "%s:%d\n", s, __FILE__, __LINE__);       \
        } else {                                                \
                memset((ptr), 0, s);                            \
                obd_memory += s;                                \
        }                                                       \
        CDEBUG(D_MALLOC, "kmalloced: %ld at %x (tot %ld).\n",   \
               s, (int)(ptr), obd_memory);                      \
} while (0)

#define OBD_FREE(ptr, size)                                     \
do {                                                            \
        int s = (size);                                         \
        kfree((ptr));                                           \
        CDEBUG(D_MALLOC, "kfreed: %d at %x (tot %ld).\n",       \
               s, (int)(ptr), obd_memory);                      \
        obd_memory -= s;                                        \
} while (0)

#endif
