#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "test_common.h"

int exit_on_err = 1;

/******************************************************************
 * util functions
 ******************************************************************/

#define EXIT(err)					\
	do {						\
		if (exit_on_err)			\
			exit(err);			\
	} while (0)

#define EXIT_RET(err)					\
	do {						\
		if (exit_on_err)			\
			exit(err);			\
		else					\
			return (err);			\
	} while (0)


void t_touch(const char *path)
{
        int fd, rc;

        fd = open(path, O_RDWR|O_CREAT, 0644);
        if (fd < 0) {
                printf("open(%s) error: %s\n", path, strerror(errno));
                EXIT(fd);
        }

        rc = close(fd);
        if (rc) {
                printf("close(%s) error: %s\n", path, strerror(errno));
                EXIT(rc);
        }
}

/* XXX Now libsysio don't support mcreate */
void t_create(const char *path)
{
        return t_touch(path);
#if 0
        int rc;

        rc = mknod(path, S_IFREG | 0644, 0);
        if (rc) {
                printf("mknod(%s) error: %s\n", path, strerror(errno));
                exit(-1);
        }
#endif
}

void t_link(const char *src, const char *dst)
{
	int rc;

	rc = link(src, dst);
	if (rc) {
		printf("link(%s -> %s) error: %s\n", src, dst, strerror(errno));
		EXIT(1);
	}
}

void t_unlink(const char *path)
{
        int rc;

        rc = unlink(path);
        if (rc) {
                printf("unlink(%s) error: %s\n", path, strerror(errno));
                EXIT(-1);
        }
}

void t_mkdir(const char *path)
{
        int rc;

        rc = mkdir(path, 00644);
        if (rc < 0) {
                printf("mkdir(%s) error: %s\n", path, strerror(errno));
                EXIT(1);
        }
}

void t_rmdir(const char *path)
{
        int rc;

        rc = rmdir(path);
        if (rc) {
                printf("rmdir(%s) error: %s\n", path, strerror(errno));
                EXIT(1);
        }
}

void t_symlink(const char *src, const char *new)
{
	int rc;

	rc = symlink(src, new);
	if (rc) {
		printf("symlink(%s<-%s) error: %s\n", src, new, strerror(errno));
		EXIT(1);
	}
}

#define MKDEV(a,b) (((a) << 8) | (b))
void t_mknod(const char *path, mode_t mode, int major, int minor)
{
	int rc;

        rc = mknod(path, mode, MKDEV(5, 4));
        if (rc) {
                printf("mknod(%s) error: %s\n", path, strerror(errno));
                EXIT(1);
        }
}

void t_chmod_raw(const char *path, mode_t mode)
{
	int rc;
	
	rc = chmod(path, mode);
	if (rc) {
                printf("chmod(%s) error: %s\n", path, strerror(errno));
                EXIT(1);
        }
}

void t_chmod(const char *path, const char *format, ...)
{
}

void t_rename(const char *oldpath, const char *newpath)
{
        int rc;

        rc = rename(oldpath, newpath);
        if (rc) {
                printf("rename(%s -> %s) error: %s\n",
		       oldpath, newpath, strerror(errno));
                EXIT(1);
        }
}

int t_open_readonly(const char *path)
{
        int fd;

        fd = open(path, O_RDONLY);
        if (fd < 0) {
                printf("open(%s) error: %s\n", path, strerror(errno));
                EXIT_RET(fd);
        }
        return fd;
}

int t_open(const char *path)
{
        int fd;

        fd = open(path, O_RDWR);
        if (fd < 0) {
                printf("open(%s) error: %s\n", path, strerror(errno));
                EXIT_RET(fd);
        }
        return fd;
}

void t_close(int fd)
{
        int rc;

        rc = close(fd);
        if (rc < 0) {
                printf("close(%d) error: %s\n", fd, strerror(errno));
                EXIT(1);
        }
}

int t_check_stat(const char *name, struct stat *buf)
{
	struct stat stat;
        int rc;

	rc = lstat(name, &stat);
        if (rc) {
		printf("error %d stat %s\n", rc, name);
		EXIT_RET(rc);
	}
        if (buf)
                memcpy(buf, &stat, sizeof(*buf));

	return 0;
}

void t_echo_create(const char *path, const char *str)
{
        int fd, rc;

        fd = open(path, O_RDWR|O_CREAT, 0644);
        if (fd < 0) {
                printf("open(%s) error: %s\n", path, strerror(errno));
                EXIT(fd);
        }

	if (write(fd, str, strlen(str)+1) != strlen(str)+1) {
                printf("write(%s) error: %s\n", path, strerror(errno));
                EXIT(fd);
	}

        rc = close(fd);
        if (rc) {
                printf("close(%s) error: %s\n", path, strerror(errno));
                EXIT(rc);
        }
}

int t_pread_once(const char *path, char *buf, size_t size, off_t offset)
{
	int fd;
	int rc;
	
	memset(buf, 0, size);

	fd = t_open_readonly(path);
	if (lseek(fd, offset, SEEK_SET) == -1) {
		printf("pread_once: seek to %lu error: %s\n",
			offset, strerror(errno));
		EXIT(fd);
	}

	rc = read(fd, buf, size);
	close(fd);
	return rc;
}
