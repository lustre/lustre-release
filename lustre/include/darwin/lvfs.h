#ifndef __DARWIN_LVFS_H__
#define __DARWIN_LVFS_H__

#ifndef __LVFS_H__
#error Do not #include this file directly. #include <lvfs.h> instead
#endif

#ifdef LLOG_LVFS
#undef LLOG_LVFS
#endif

struct lvfs_ucred { 
	__u32 luc_fsuid; 
	__u32 luc_fsgid; 
	__u32 luc_cap; 
	__u32 luc_uid; 
	__u32 luc_umask;
};

struct lvfs_run_ctxt {
	int	pid;
};

#endif
