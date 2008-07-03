/*
 * Public include file for the UUID library
 *
 * Copyright (C) 2007 Cluster File System
 */

#define DEBUG_SUBSYSTEM S_CLASS

#ifndef __KERNEL__
# include <liblustre.h>
#else
# include <libcfs/libcfs.h>
#endif

#include <obd_support.h>
#include <obd_class.h>


static inline __u32 consume(int nob, __u8 **ptr)
{
	__u32 value;

	LASSERT(nob <= sizeof value);

	for (value = 0; nob > 0; --nob)
		value = (value << 8) | *((*ptr)++);
	return value;
}

#define CONSUME(val, ptr) (val) = consume(sizeof(val), (ptr))

static void uuid_unpack(class_uuid_t in, __u16 *uu, int nr)
{
        __u8 *ptr = in;

	LASSERT(nr * sizeof *uu == sizeof(class_uuid_t));

	while (nr-- > 0)
		CONSUME(uu[nr], &ptr);
}

void class_uuid_unparse(class_uuid_t uu, struct obd_uuid *out)
{
	/* uu as an array of __u16's */
        __u16 uuid[sizeof(class_uuid_t) / sizeof(__u16)];

	CLASSERT(ARRAY_SIZE(uuid) == 8);

        uuid_unpack(uu, uuid, ARRAY_SIZE(uuid));
        sprintf(out->uuid, "%04x%04x-%04x-%04x-%04x-%04x%04x%04x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5], uuid[6], uuid[7]);
}
