#ifndef _LUSTRE_USER_H
#define _LUSTRE_USER_H
#include <asm/types.h>

#define LL_IOC_GETFLAGS                 _IOR ('f', 151, long)
#define LL_IOC_SETFLAGS                 _IOW ('f', 152, long)
#define LL_IOC_CLRFLAGS                 _IOW ('f', 153, long)
#define LL_IOC_LOV_SETSTRIPE            _IOW ('f', 154, long)
#define LL_IOC_LOV_GETSTRIPE            _IOW ('f', 155, long)

#define O_LOV_DELAY_CREATE 0100000000  /* hopefully this does not conflict */

#define LL_FILE_IGNORE_LOCK             0x00000001

struct lov_osc_data {             /* per-child structure */
        __u64 l_object_id;
        __u32 l_reserved1;
        __u16 l_ost_idx;
        __u16 l_reserved2;
} __attribute__((packed));

#define LOV_USER_MAGIC  0x0BD10BD0

struct lov_user_md {
        __u32 lmm_magic;
        __u32 lmm_pattern;         /* RAID pattern (0,1,...) */
        __u64 lmm_object_id;       /* lov object id */
        __u32 lmm_stripe_size;     /* size of the stripe (unused in RAID1) */
        __u16 lmm_stripe_count;    /* num stripes in use for this object */
        __u16 lmm_stripe_offset;   /* starting stripe offset in lmm_objects */
        struct lov_osc_data lmm_objects[0];
} __attribute__((packed));

#endif /* _LUSTRE_USER_H */
