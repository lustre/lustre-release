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
#include <linux/ctype.h>
#include <linux/kernel.h>

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/smp_lock.h>

struct uuid {
	__u32	time_low;
	__u16	time_mid;
	__u16	time_hi_and_version;
	__u16	clock_seq;
	__u8	node[6];
};

static void uuid_unpack(class_uuid_t in, struct uuid *uu)
{
	__u8	*ptr = in;
	__u32	tmp;

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

#if 0
static void uuid_pack(struct uuid *uu, class_uuid_t ptr)
{
	__u32	tmp;
	unsigned char	*out = ptr;

	tmp = uu->time_low;
	out[3] = (unsigned char) tmp;
	tmp >>= 8;
	out[2] = (unsigned char) tmp;
	tmp >>= 8;
	out[1] = (unsigned char) tmp;
	tmp >>= 8;
	out[0] = (unsigned char) tmp;

	tmp = uu->time_mid;
	out[5] = (unsigned char) tmp;
	tmp >>= 8;
	out[4] = (unsigned char) tmp;

	tmp = uu->time_hi_and_version;
	out[7] = (unsigned char) tmp;
	tmp >>= 8;
	out[6] = (unsigned char) tmp;

	tmp = uu->clock_seq;
	out[9] = (unsigned char) tmp;
	tmp >>= 8;
	out[8] = (unsigned char) tmp;

	memcpy(out+10, uu->node, 6);
}

int class_uuid_parse(struct obd_uuid in, class_uuid_t uu)
{
	struct uuid uuid;
	int i;
	char *cp, buf[3];

	if (strlen(in) != 36)
		return -1;
	for (i=0, cp = in; i <= 36; i++,cp++) {
		if ((i == 8) || (i == 13) || (i == 18) ||
		    (i == 23))
			if (*cp == '-')
				continue;
		if (i== 36)
			if (*cp == 0)
				continue;
		if (!isxdigit(*cp))
			return -1;
	}
	uuid.time_low = simple_strtoul(in, NULL, 16);
	uuid.time_mid = simple_strtoul(in+9, NULL, 16);
	uuid.time_hi_and_version = simple_strtoul(in+14, NULL, 16);
	uuid.clock_seq = simple_strtoul(in+19, NULL, 16);
	cp = in+24;
	buf[2] = 0;
	for (i=0; i < 6; i++) {
		buf[0] = *cp++;
		buf[1] = *cp++;
		uuid.node[i] = simple_strtoul(buf, NULL, 16);
	}

	uuid_pack(&uuid, uu);
	return 0;
}
#endif

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
