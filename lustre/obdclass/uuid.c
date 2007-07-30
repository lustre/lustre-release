/*
 * Public include file for the UUID library
 * 
 * Copyright (C) 1996, 1997, 1998 Theodore Ts'o.
 * Copyright (C) 2002 Cluster File System
 * - changed for use in lustre
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the GNU 
 * Library General Public License.
 * %End-Header%
 */
#define DEBUG_SUBSYSTEM S_CLASS

#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <obd_support.h>
#include <obd_class.h>

struct uuid {
        __u32   time_low;
        __u16   time_mid;
        __u16   time_hi_and_version;
        __u16   clock_seq;
        __u8    node[6];
};

static void uuid_unpack(class_uuid_t in, struct uuid *uu)
{
        __u8    *ptr = in;
        __u32   tmp;

        tmp = *ptr++;
        tmp = (tmp << 8) | *ptr++;
        tmp = (tmp << 8) | *ptr++;
        tmp = (tmp << 8) | *ptr++;
        uu->time_low = tmp;

        tmp = *ptr++;
        tmp = (tmp << 8) | *ptr++;
        uu->time_mid = tmp;

        tmp = *ptr++;
        tmp = (tmp << 8) | *ptr++;
        uu->time_hi_and_version = tmp;

        tmp = *ptr++;
        tmp = (tmp << 8) | *ptr++;
        uu->clock_seq = tmp;

        memcpy(uu->node, ptr, 6);
}

void generate_random_uuid(unsigned char uuid_out[16]);

void class_uuid_unparse(class_uuid_t uu, struct obd_uuid *out)
{
        struct uuid uuid;

        uuid_unpack(uu, &uuid);
        sprintf(out->uuid,
                "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
                uuid.clock_seq >> 8, uuid.clock_seq & 0xFF,
                uuid.node[0], uuid.node[1], uuid.node[2],
                uuid.node[3], uuid.node[4], uuid.node[5]);
}
