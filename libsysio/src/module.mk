#
# Note; Remove statvfs{,64}.c until we decide what to do with them.
# Lee; Tue Feb 24 09:37:32 EST 2004
#

if WITH_LUSTRE_HACK
FILE_SUPPORT = src/file_hack.c
else
FILE_SUPPORT = src/file.c
endif

if WITH_LUSTRE_HACK
LUSTRE_SRCDIR_SRCS = src/stdlib.c
else
LUSTRE_SRCDIR_SRCS =
endif

SRCDIR_SRCS = src/access.c src/chdir.c src/chmod.c \
	src/chown.c src/dev.c src/dup.c src/fcntl.c \
	src/fs.c src/fsync.c \
	src/getdirentries.c src/init.c src/inode.c \
	src/ioctl.c src/ioctx.c src/iowait.c \
	src/link.c src/lseek.c src/mkdir.c \
	src/mknod.c src/mount.c src/namei.c \
	src/open.c src/rw.c src/reconcile.c src/rename.c \
	src/rmdir.c src/stat64.c src/stat.c \
	src/stddir.c src/readdir.c src/readdir64.c \
	src/symlink.c src/readlink.c \
	src/truncate.c src/unlink.c src/utime.c \
	$(FILE_SUPPORT) $(LUSTRE_SRCDIR_SRCS)

SRCDIR_EXTRA = src/module.mk
