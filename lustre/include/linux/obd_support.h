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
extern int obd_print_entry;
extern unsigned long obd_memory;

#define OBD_ALLOC(ptr, size)                                    \
do {                                                            \
        (ptr) = kmalloc((unsigned long)(size), GFP_KERNEL);     \
        obd_memory += (size);                                   \
        CDEBUG(D_MALLOC, "kmalloced: %ld at %x (tot %ld).\n",   \
               (long)(size), (int)(ptr), obd_memory);           \
        if (ptr == NULL) {                                      \
                CERROR("kernel malloc failed at %s:%d\n",       \
                       __FILE__, __LINE__);                     \
        } else {                                                \
                memset((ptr), 0, (size));                       \
        }                                                       \
} while (0)

#define OBD_FREE(ptr, size)                                  \
do {                                                         \
        kfree((ptr));                                        \
        obd_memory -= (size);                                \
        CDEBUG(D_MALLOC, "kfreed: %d at %x (tot %ld).\n",    \
               (int)(size), (int)(ptr), obd_memory);         \
} while (0)

#endif
