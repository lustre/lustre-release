#ifndef _LUSTRE_ACCESS_LOG_H
# define _LUSTRE_ACCESS_LOG_H

#include <linux/types.h>
#include <asm/ioctl.h>
/*
 * This is due to us being out of kernel and the way the OpenSFS branch
 * handles CFLAGS.
 */
#ifdef __KERNEL__
# include <uapi/linux/lustre/lustre_user.h>
#else
# include <linux/lustre/lustre_user.h>
#endif

enum ofd_access_flags {
	OFD_ACCESS_READ = 0x1,
	OFD_ACCESS_WRITE = 0x2,
};

struct ofd_access_entry_v1 {
	struct lu_fid	oae_parent_fid; /* 16 */
	__u64		oae_begin; /* 24 */
	__u64		oae_end; /* 32 */
	__u64		oae_time; /* 40 */
	__u32		oae_size; /* 44 */
	__u32		oae_segment_count; /* 48 */
	__u32		oae_flags; /* 52 enum ofd_access_flags */
	__u32		oae_reserved1; /* 56 */
	__u32		oae_reserved2; /* 60 */
	__u32		oae_reserved3; /* 64 */
};

/* The name of the subdirectory of devtmpfs (/dev) containing the
 * control and access log char devices. */
#define LUSTRE_ACCESS_LOG_DIR_NAME "lustre-access-log"

enum {
	LUSTRE_ACCESS_LOG_VERSION_1 = 0x00010000,
	LUSTRE_ACCESS_LOG_TYPE_OFD = 0x1,
	LUSTRE_ACCESS_LOG_NAME_SIZE = 128,
};

struct lustre_access_log_info_v1 {
	__u32	lali_version; /* LUSTRE_ACCESS_LOG_VERSION_1 */
	__u32	lali_type; /* LUSTRE_ACCESS_LOG_TYPE_OFD */
	char	lali_name[LUSTRE_ACCESS_LOG_NAME_SIZE]; /* obd_name */
	__u32	lali_log_size;
	__u32	lali_entry_size;
	/* Underscore prefixed members are intended for test and debug
	 * purposes only. */
	__u32	_lali_head;
	__u32	_lali_tail;
	__u32	_lali_entry_space;
	__u32	_lali_entry_count;
	__u32	_lali_drop_count;
	__u32	_lali_is_closed;
};

enum {
	/* /dev/lustre-access-log/control ioctl: return lustre access log
	 * interface version. */
	LUSTRE_ACCESS_LOG_IOCTL_VERSION = _IO('O', 0x81),

	/* /dev/lustre-access-log/control ioctl: return device major
	 * used for access log devices. (The major is dynamically
	 * allocated during ofd module initialization. */
	LUSTRE_ACCESS_LOG_IOCTL_MAJOR = _IO('O', 0x82),

	/* /dev/lustre-access-log/control ioctl: get global control event
	 * count and store it into file private_data. */
	LUSTRE_ACCESS_LOG_IOCTL_PRESCAN = _IO('O', 0x83),

	/* /dev/lustre-access-log/OBDNAME ioctl: populate struct
	 * lustre_access_log_info_v1 for the current device. */
	LUSTRE_ACCESS_LOG_IOCTL_INFO = _IOR('O', 0x84, struct lustre_access_log_info_v1),

	/* /dev/lustre-access-log/OBDNAME ioctl: only entries whose
	 * PFID MDT index is equal to arg will be added to the log. A
	 * value of 0xfffffffff ((__u32)-1) will disable filtering
	 * which is the default.  Added in V2. */
	LUSTRE_ACCESS_LOG_IOCTL_FILTER = _IOW('O', 0x85, __u32),
};

#endif /* _LUSTRE_ACCESS_LOG_H */
