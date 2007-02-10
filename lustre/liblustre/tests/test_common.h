#ifndef __TEST_COMMON__H
#define __TEST_COMMON__H

#define ENV_LUSTRE_MNTPNT               "LIBLUSTRE_MOUNT_POINT"
#define ENV_LUSTRE_MNTTGT               "LIBLUSTRE_MOUNT_TARGET"
#define ENV_LUSTRE_TIMEOUT              "LIBLUSTRE_TIMEOUT"
#define ENV_LUSTRE_DUMPFILE             "LIBLUSTRE_DUMPFILE"

extern int exit_on_err;

#include <utime.h> /* for utimbuf */

void t_touch(const char *path);
void t_create(const char *path);
void t_link(const char *src, const char *dst);
void t_unlink(const char *path);
void t_mkdir(const char *path);
void t_rmdir(const char *path);
void t_symlink(const char *src, const char *new);
void t_mknod(const char *path, mode_t mode, int major, int minor);
void t_chmod_raw(const char *path, mode_t mode);
void t_chmod(const char *path, const char *format, ...);
void t_rename(const char *oldpath, const char *newpath);
int t_open_readonly(const char *path);
int t_open(const char *path);
int t_chdir(const char *path);
int t_utime(const char *path, const struct utimbuf *buf);
int t_opendir(const char *path);
void t_close(int fd);
int t_check_stat(const char *name, struct stat *buf);
int t_check_stat_fail(const char *name);
void t_echo_create(const char *path, const char *str);
void t_grep(const char *path, char *str);
void t_grep_v(const char *path, char *str);
void t_ls(int fd, char *buf, int size);
int t_fcntl(int fd, int cmd, ...);

char *safe_strncpy(char *dst, char *src, int max_size);

#endif
