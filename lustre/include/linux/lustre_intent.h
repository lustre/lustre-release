#ifndef LUSTRE_INTENT_H
#define LUSTRE_INTENT_H

#include <linux/lustre_version.h>

#ifndef HAVE_VFS_INTENT_PATCHES

#define IT_OPEN     (1 << 0)
#define IT_CREAT    (1 << 1)
#define IT_READDIR  (1 << 2)
#define IT_GETATTR  (1 << 3)
#define IT_LOOKUP   (1 << 4)
#define IT_UNLINK   (1 << 5)
#define IT_TRUNC    (1 << 6)
#define IT_GETXATTR (1 << 7)

struct lustre_intent_data {
        int       it_disposition;
        int       it_status;
        __u64     it_lock_handle;
        void     *it_data;
        int       it_lock_mode;
};

struct lookup_intent {
        int     it_op;
        int     it_flags;
	int     it_create_mode;
        union {
                struct lustre_intent_data lustre;
        } d;
};

#endif
#endif
