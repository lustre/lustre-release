#ifndef __TEST_COMMON__H
#define __TEST_COMMON__H

extern int exit_on_err;

void t_touch(const char *path);
void t_create(const char *path);
void t_unlink(const char *path);
void t_mkdir(const char *path);
void t_rmdir(const char *path);
void t_symlink(const char *src, const char *new);
void t_mknod(const char *path, mode_t mode, int major, int minor);
void t_chmod_raw(const char *path, mode_t mode);
void t_chmod(const char *path, const char *format, ...);
int t_open_readonly(const char *path);
int t_open(const char *path);
void t_close(int fd);
int t_check_stat(const char *name, struct stat *buf);

#endif
