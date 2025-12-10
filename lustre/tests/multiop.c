// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* pull in O_DIRECTORY in bits/fcntl.h */
#endif
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <malloc.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <lustre/lustreapi.h>

#define T1 "write data before unlink\n"
#define T2 "write data after unlink\n"
char msg[] = "yabba dabba doo, I'm coming for you, I live in a shoe, I don't know what to do.\n'Bigger, bigger,and bigger yet!' cried the Creator.  'You are not yet substantial enough for my boundless intents!'  And ever greater and greater the object became, until all was lost 'neath its momentus bulk.\n";
char *buf, *buf_align;
char *command_buf;
int bufsize;
sem_t sem;
#define ALIGN_LEN 65535
#define XATTR "user.multiop"

char usage[] =
"Usage: %s [-i command_file] target_file [command-sequence] [path...]\n"
"    command_file replaces command-sequence if provided\n"
"    command-sequence items:\n"
"	 A  fsetxattr(\"user.multiop\")\n"
"	 a[num] fgetxattr(\"user.multiop\") [optional buffer size, default 0]\n"
"	 c  close\n"
"	 B[num] call setstripe ioctl to create stripes\n"
"	 C[num] create with optional stripes\n"
"	 d  mkdir\n"
"	 D  open(O_DIRECTORY)\n"
"	 e[R|W|U] apply lease. R: Read; W: Write; U: Unlock\n"
"	 E[+|-] get lease. +/-: expect lease to (not) exist\n"
"	 f  statfs\n"
"	 F  print FID\n"
"	 G gid get grouplock\n"
"	 g gid put grouplock\n"
"	 H[num] create HSM released file with num stripes\n"
"	 I  fiemap\n"
"	 i  random fadvise\n"
"	 J  madvise(MADV_HUGEPAGE)\n"
"	 K  link path to filename\n"
"	 L  link\n"
"	 l  symlink filename to path\n"
"	 m  mknod\n"
"	 M  rw mmap to EOF (must open and stat prior)\n"
"	 n  rename path to filename\n"
"	 N  rename filename to path\n"
"	 o  open(O_RDONLY)\n"
"	 O  open(O_CREAT|O_RDWR)\n"
"	 p  print return value of last command\n"
"	 Q  open filename (should be dir), stat first entry to init statahead"
"	 r[num] read [optional length]\n"
"	 R  reference entire mmap-ed region\n"
"	 s  stat\n"
"	 S  fstat\n"
"	 t  fchmod\n"
"	 T[num] ftruncate [optional position, default 0]\n"
"	 u  unlink\n"
"	 U  munmap\n"
"	 v  verbose\n"
"	 V  open a volatile file\n"
"	 w[num] write optional length\n"
"	 P[num] like w, but only one write call\n"
"	 x  get file data version\n"
"	 W  write entire mmap-ed region\n"
"	 y  fsync\n"
"	 Y  fdatasync\n"
"	 z[num] lseek(SEEK_SET) [optional offset, default 0]\n"
"	 Z[num] lseek(SEEK_CUR) [optional offset, default 0]\n"
"	 _  wait for signal\n";

static void usr1_handler(int unused)
{
	int saved_errno = errno;

	/*
	 * signal(7): POSIX.1-2004 ...requires an implementation to guarantee
	 * that the following functions can be safely called inside a signal
	 * handler:
	 *            sem_post()
	 */
	sem_post(&sem);

	errno = saved_errno;
}

static const char *
pop_arg(int argc, char *argv[])
{
	static int cur_arg;

	/* if we have an input file, that adds two args, but there's no
	 * command sequence, so in total there's 1 more arg before the paths
	 */
	if (!command_buf)
		cur_arg = 3;
	else
		cur_arg = 4;

	if (cur_arg >= argc)
		return NULL;

	return argv[cur_arg++];
}

struct flag_mapping {
	const char *string;
	const int  flag;
} flag_table[] = {
	{"O_RDONLY", O_RDONLY},
	{"O_WRONLY", O_WRONLY},
	{"O_RDWR", O_RDWR},
	{"O_CREAT", O_CREAT},
	{"O_EXCL", O_EXCL},
	{"O_NOCTTY", O_NOCTTY},
	{"O_TRUNC", O_TRUNC},
	{"O_APPEND", O_APPEND},
	{"O_NONBLOCK", O_NONBLOCK},
	{"O_NDELAY", O_NDELAY},
	{"O_SYNC", O_SYNC},
#ifdef O_DIRECT
	{"O_DIRECT", O_DIRECT},
#endif
#ifdef O_NOATIME
	{"O_NOATIME", O_NOATIME},
#endif
	{"O_LARGEFILE", O_LARGEFILE},
	{"O_DIRECTORY", O_DIRECTORY},
	{"O_NOFOLLOW", O_NOFOLLOW},
	{"O_LOV_DELAY_CREATE", O_LOV_DELAY_CREATE},
	{"", -1}
};

static int get_flags(char *data, int *rflags)
{
	char *cloned_flags;
	char *tmp;
	int flag_set = 0;
	int flags = 0;
	int size = 0;

	cloned_flags = strdup(data);
	if (!cloned_flags) {
		fprintf(stderr, "Insufficient memory.\n");
		exit(-1);
	}

	for (tmp = strtok(cloned_flags, ":"); tmp;
	     tmp = strtok(NULL, ":")) {
		int i;

		size = tmp - cloned_flags;
		for (i = 0; flag_table[i].flag != -1; i++) {
			if (!strcmp(tmp, flag_table[i].string)) {
				flags |= flag_table[i].flag;
				size += strlen(flag_table[i].string);
				flag_set = 1;
				break;
			}
		}
	}
	free(cloned_flags);

	if (!flag_set) {
		*rflags = O_RDONLY;
		return 0;
	}

	*rflags = flags;
	return size;
}

static int statahead(char *dname)
{
	DIR *d;
	struct dirent *dent;
	struct stat st;
	char *buf;
	int rc;

	rc = 0;
	d = opendir(dname);
	if (!d)
		return errno;
	dent = readdir(d);
	if (!dent) {
		rc = errno;
		goto out_closedir;
	}
	if (asprintf(&buf, "%s/%s", dname, dent->d_name) == -1) {
		rc = errno;
		goto out_closedir;
	}
	if (stat(buf, &st))
		rc = errno;
	free(buf);
out_closedir:
	closedir(d);
	return rc;
}

static int do_fiemap(int fd)
{
	struct fiemap *pf;
	int extents;
	int save_errno;
	int i;

	extents = 0;
	for (i = 0; i < 2; i++) {
		if ((pf = malloc(sizeof(struct fiemap) +
			extents * sizeof(struct fiemap_extent))) == NULL) {
			perror("malloc failed");
			exit(1);
		}
		pf->fm_start = 0;
		pf->fm_length = FIEMAP_MAX_OFFSET;
		pf->fm_flags = FIEMAP_FLAG_SYNC;
		pf->fm_extent_count = extents;

		if (ioctl(fd, FS_IOC_FIEMAP, pf) < 0) {
			save_errno = errno;
			if (i == 0)
				perror("probe fiemap failed");
			else
				perror("fiemap failed");
			exit(save_errno);
		}
		extents = pf->fm_mapped_extents;
		free(pf);
	}
	return 0;
}

#define POP_ARG() (pop_arg(argc, argv))

/* 10 MiB is a lot of command text - seems a reasonable limit */
#define CMD_FILE_MAXSIZE (10*1024*1024)

int main(int argc, char **argv)
{
	unsigned char *mmap_ptr = NULL, junk = 1;
	char *fname = NULL, *commands = NULL;
	struct lov_user_md_v3 lum;
	size_t xattr_buf_size = 0;
	int msg_len = strlen(msg);
	long int cmdfile_size = 0;
	struct stat cmdfile_stat;
	size_t mmap_len = 0, i;
	char *xattr_buf = NULL;
	struct stat st = { 0 };
	const char *newfile;
	const char *oldpath;
	struct statfs stfs;
	struct timespec ts;
	size_t total_bytes;
	struct lu_fid fid;
	long long last_rc;
	int len, fd = -1;
	long long rc = 0;
	int verbose = 0;
	int save_errno;
	bool unaligned;
	int cmdfile_fd;
	int gid = 0;
	int flags;
	char c;

	sem_init(&sem, 0, 0);
	/* use sigaction instead of signal to avoid SA_ONESHOT semantics */
	sigaction(SIGUSR1,
		  &(const struct sigaction) {.sa_handler = &usr1_handler}, NULL);

	if (argc < 3) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}

	command_buf = NULL;

	while ((c = getopt(argc, argv, "i:")) != -1) {

		switch (c) {
		case 'i':
			if (*optarg == '-')
				cmdfile_fd = fileno(stdin);
			else
				cmdfile_fd = open(optarg, O_RDONLY);
			if (cmdfile_fd == -1) {
				fprintf(stderr,
				       "Error: open of command file %s failed",
					optarg);
				perror("");
				exit(1);
			}
			if (fstat(cmdfile_fd, &cmdfile_stat) == -1) {
				perror("Error: stat of command file failed");
				exit(1);
			}
			cmdfile_size = cmdfile_stat.st_size;
			if (cmdfile_size > CMD_FILE_MAXSIZE) {
				errno = E2BIG;
				fprintf(stderr,
					"Error: The command file size (%ld) is greater than limit of %d\n",
					cmdfile_size, CMD_FILE_MAXSIZE);
				exit(1);
			}

			command_buf = calloc(1, cmdfile_size);
			if (!command_buf) {
				errno = ENOMEM;
				fprintf(stderr,
					"Error: Not enough memory to allocate command buffer\n");
				exit(1);
			}
			if (read(cmdfile_fd, command_buf, CMD_FILE_MAXSIZE) <
			    cmdfile_size) {
				perror("Unable to read command file");
				exit(1);
			}
			break;
		default:
			fprintf(stderr, usage, argv[0]);
		}
	}

	/* command_buf is set when we have an input file */
	if (command_buf) {
		fname = argv[3];
		commands = command_buf;
	} else {
		fname = argv[1];
		commands = argv[2];
	}

	for (; *commands; commands++) {
		/*
		 * XXX Most commands return 0 or we exit so we only
		 * update rc where really needed.
		 */
		last_rc = rc;
		rc = 0;
		total_bytes = 0;
		unaligned = false;

		switch (*commands) {
		/* ignoring newlines makes it easier to pipe in commands */
		case '\n':
			break;
		case '_':
			if (verbose) {
				printf("PAUSING\n");
				fflush(stdout);
			}
			len = atoi(commands + 1);
			if (len <= 0)
				len = 3600; /* 1 hour */
			ts.tv_sec = time(NULL) + len;
			ts.tv_nsec = 0;
			while (sem_timedwait(&sem, &ts) < 0 && errno == EINTR)
				;
			break;
		case 'A':
			if (fsetxattr(fd, XATTR, "multiop", 8, 0)) {
				save_errno = errno;
				perror("fsetxattr");
				exit(save_errno);
			}
			break;
		case 'a':
			len = atoi(commands + 1);
			if (xattr_buf_size < len) {
				xattr_buf = realloc(xattr_buf, len);
				if (!xattr_buf) {
					save_errno = errno;
					perror("allocating xattr buffer\n");
					exit(save_errno);
				}

				xattr_buf_size = len;
			}

			rc = fgetxattr(fd, XATTR, xattr_buf, len);
			if (rc < 0) {
				save_errno = errno;
				perror("fgetxattr");
				exit(save_errno);
			}
			break;
		case 'c':
			if (close(fd) == -1) {
				save_errno = errno;
				perror("close");
				exit(save_errno);
			}
			fd = -1;
			break;
		case 'B':
			lum = (struct lov_user_md_v3) {
				.lmm_magic = LOV_USER_MAGIC_V3,
				.lmm_stripe_count = atoi(commands + 1),
			};

			if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, &lum) < 0) {
				save_errno = errno;
				perror("LL_IOC_LOV_SETSTRIPE");
				exit(save_errno);
			}
			break;
		case 'C':
			len = atoi(commands + 1);
			fd = llapi_file_open(fname, O_CREAT | O_WRONLY, 0644,
					     0, 0, len, 0);
			if (fd == -1) {
				save_errno = errno;
				perror("create stripe file");
				exit(save_errno);
			}
			rc = fd;
			break;
		case 'd':
			if (mkdir(fname, 0755) == -1) {
				save_errno = errno;
				perror("mkdir(0755)");
				exit(save_errno);
			}
			break;
		case 'D':
			fd = open(fname, O_DIRECTORY);
			if (fd == -1) {
				save_errno = errno;
				perror("open(O_DIRECTORY)");
				exit(save_errno);
			}
			rc = fd;
			break;
		case 'e':
			commands++;
			switch (*commands) {
			case 'U':
				rc = llapi_lease_release(fd);
				break;
			case 'R':
				rc = llapi_lease_acquire(fd, LL_LEASE_RDLCK);
				break;
			case 'W':
				rc = llapi_lease_acquire(fd, LL_LEASE_WRLCK);
				break;
			default:
				errx(-1, "unknown mode: %c", *commands);
			}
			if (rc < 0)
				err(errno, "apply/unlock lease error");

			if (flags != LL_LEASE_UNLCK)
				break;

			/* F_UNLCK, interpret return code */
			if (rc > 0) {
				const char *str = "unknown";

				if (rc == LL_LEASE_RDLCK)
					str = "read";
				else if (rc == LL_LEASE_WRLCK)
					str = "write";
				fprintf(stdout, "%s lease(%lld) released.\n",
					str, rc);
			} else if (rc == 0) {
				fprintf(stdout, "lease already broken.\n");
			}
			break;
		case 'E':
			commands++;
			if (*commands != '-' && *commands != '+')
				errx(-1, "unknown mode: %c\n", *commands);

			rc = llapi_lease_check(fd);
			if (rc > 0) {
				const char *str = "unknown";

				if (rc == LL_LEASE_RDLCK)
					str = "read";
				else if (rc == LL_LEASE_WRLCK)
					str = "write";
				fprintf(stdout, "%s lease(%lld) has applied.\n",
					str, rc);
				if (*commands == '-')
					errx(-1, "expect lease to not exist");
			} else if (rc == 0) {
				fprintf(stdout, "no lease applied.\n");
				if (*commands == '+')
					errx(-1, "expect lease exists");
			} else {
				err(errno, "free lease error");
			}
			break;
		case 'f':
			if (statfs(fname, &stfs) == -1)
				errx(-1, "statfs()");
			break;
		case 'F':
			if (fd == -1)
				rc = llapi_path2fid(fname, &fid);
			else
				rc = llapi_fd2fid(fd, &fid);
			if (rc != 0)
				fprintf(stderr,
					"llapi_path/fd2fid() on %d, rc=%lld\n",
					fd, rc);
			else
				printf(DFID"\n", PFID(&fid));
			fflush(stdout);
			break;
		case 'G':
			gid = atoi(commands + 1);
			if (ioctl(fd, LL_IOC_GROUP_LOCK, gid) == -1) {
				save_errno = errno;
				perror("ioctl(GROUP_LOCK)");
				exit(save_errno);
			}
			break;
		case 'g':
			gid = atoi(commands + 1);
			if (ioctl(fd, LL_IOC_GROUP_UNLOCK, gid) == -1) {
				save_errno = errno;
				perror("ioctl(GROUP_UNLOCK)");
				exit(save_errno);
			}
			break;
		case 'H':
			len = atoi(commands + 1);
			fd = llapi_file_open(fname, O_CREAT | O_WRONLY, 0644,
					     0, 0, len, LOV_PATTERN_RAID0 |
					     LOV_PATTERN_F_RELEASED);
			if (fd == -1) {
				save_errno = errno;
				perror("create stripe file");
				exit(save_errno);
			}
			rc = fd;
			break;
		case 'I':
			do_fiemap(fd);
			break;
		case 'i':
			rc = posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM);
			if (rc) {
				save_errno = errno;
				perror("fadvise");
				exit(save_errno);
			}
			break;
		case 'j':
			if (flock(fd, LOCK_EX) == -1)
				errx(-1, "flock()");
			break;
		case 'J':
			if (madvise(mmap_ptr, mmap_len, MADV_HUGEPAGE)) {
				save_errno = errno;
				perror("madvise()");
				exit(save_errno);
			}
			break;
		case 'K':
			oldpath = POP_ARG();
			if (!oldpath)
				oldpath = fname;

			if (link(oldpath, fname)) {
				save_errno = errno;
				perror("link()");
				exit(save_errno);
			}
			break;
		case 'l':
			newfile = POP_ARG();
			if (!newfile)
				newfile = fname;
			if (symlink(fname, newfile)) {
				save_errno = errno;
				perror("symlink()");
				exit(save_errno);
			}
			break;
		case 'L':
			newfile = POP_ARG();
			if (!newfile)
				newfile = fname;

			if (link(fname, newfile)) {
				save_errno = errno;
				perror("link()");
				exit(save_errno);
			}
			break;
		case 'm':
			if (mknod(fname, S_IFREG | 0644, 0) == -1) {
				save_errno = errno;
				perror("mknod(S_IFREG|0644, 0)");
				exit(save_errno);
			}
			break;
		case 'M':
			if (st.st_size == 0) {
				fprintf(stderr,
					"mmap without preceeding stat, or on zero length file.\n");
				exit(-1);
			}
			mmap_len = st.st_size;
			mmap_ptr = mmap(NULL, mmap_len, PROT_WRITE | PROT_READ,
					MAP_SHARED, fd, 0);
			if (mmap_ptr == MAP_FAILED) {
				save_errno = errno;
				perror("mmap");
				exit(save_errno);
			}
			break;
		case 'n':
			oldpath = POP_ARG();
			if (!oldpath)
				oldpath = fname;

			if (rename(oldpath, fname) < 0) {
				save_errno = errno;
				perror("rename()");
				exit(save_errno);
			}
			break;
		case 'N':
			newfile = POP_ARG();
			if (!newfile)
				newfile = fname;
			if (rename(fname, newfile)) {
				save_errno = errno;
				perror("rename()");
				exit(save_errno);
			}
			break;
		case 'O':
			fd = open(fname, O_CREAT | O_RDWR, 0644);
			if (fd == -1) {
				save_errno = errno;
				perror("open(O_RDWR|O_CREAT)");
				exit(save_errno);
			}
			rc = fd;
			break;
		case 'o':
			len = get_flags(commands + 1, &flags);
			commands += len;
			if (flags & O_CREAT)
				fd = open(fname, flags, 0666);
			else
				fd = open(fname, flags);
			if (fd == -1) {
				save_errno = errno;
				perror("open");
				exit(save_errno);
			}
			rc = fd;
			break;
		case 'p':
			printf("%lld\n", last_rc);
			break;
		case 'Q':
			save_errno = statahead(fname);
			if (save_errno) {
				perror("statahead");
				exit(save_errno);
			}
			break;
		case 'r':
			if (*(commands + 1) == 'u') {
				unaligned = true;
				commands++;
			}
			len = atoi(commands + 1);
			if (len <= 0)
				len = 1;
			/* for unaligned, we realloc every time, so the
			 * buffer alignment is variable
			 *
			 * the last condition is "if buf is unaligned", so when
			 * unaligned is not set, we realloc if the buf is
			 * unaligned to create an aligned buffer
			 */
			if (bufsize < len || unaligned ||
			    buf !=
			    (char *)((long)(buf + ALIGN_LEN) & ~ALIGN_LEN)) {
				void *tmp;

				/* We add a margin of + ALIGN_LEN to let us
				 * unalign and stay in the buffer
				 */
				tmp = realloc(buf, len + ALIGN_LEN*2);
				if (!tmp) {
					free(buf);
					save_errno = errno;
					perror("allocating buf for write\n");
					exit(save_errno);
				}
				buf = tmp;
				bufsize = len;
				buf_align = (char *)((long)(buf + ALIGN_LEN) &
						     ~ALIGN_LEN);
				/* if the original buffer was aligned, we
				 * manually unalign it.  Otherwise, we use
				 * the unalignment from the allocator.
				 *
				 * Add + 1 to avoid ever hitting 0, and use
				 * mod 255 to avoid 255 + 1 = 256
				 */
				if (unaligned && buf_align == buf)
					buf_align += rand() % 255 + 1;
				else if (unaligned)
					buf_align = buf;
			}

			while (len > 0) {
				off_t start, off;

				start = lseek(fd, 0, SEEK_CUR);
				rc = read(fd, buf_align, len);
				if (rc == -1) {
					save_errno = errno;
					perror("read");
					exit(save_errno);
				}
				if (rc < len) {
					off = lseek(fd, 0, SEEK_CUR);
					fprintf(stderr, "short read: %ld ->+ %u -> %ld %lld\n",
						start, len, off, rc);
					if (rc == 0)
						break;
				}
				len -= rc;
				if (verbose >= 2) {
					printf("Buffer address %s: %p\n",
						unaligned ? "(unaligned)" : "",
						buf_align);
					printf("Read this (%lld bytes):\n", rc);
					printf("%.*s\n", (int)rc, buf_align);
				}
			}
			break;
		case 'R':
			for (i = 0; i < mmap_len && mmap_ptr; i += 4096)
				junk += mmap_ptr[i];
			break;
		case 's':
			if (stat(fname, &st) == -1) {
				save_errno = errno;
				perror("stat");
				exit(save_errno);
			}
			break;
		case 'S':
			if (fstat(fd, &st) == -1) {
				save_errno = errno;
				perror("fstat");
				exit(save_errno);
			}
			break;
		case 't':
			if (fchmod(fd, 0) == -1) {
				save_errno = errno;
				perror("fchmod");
				exit(save_errno);
			}
			break;
		case 'T':
			len = atoi(commands + 1);
			if (ftruncate(fd, len) == -1) {
				save_errno = errno;
				printf("ftruncate (%d,%d)\n", fd, len);
				perror("ftruncate");
				exit(save_errno);
			}
			break;
		case 'u':
			if (unlink(fname) == -1) {
				save_errno = errno;
				perror("unlink");
				exit(save_errno);
			}
			break;
		case 'U':
			if (munmap(mmap_ptr, mmap_len)) {
				save_errno = errno;
				perror("munmap");
				exit(save_errno);
			}
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			len = get_flags(commands + 1, &flags);
			commands += len;
			len = -1; /* mdt index */
			if (commands[1] >= '0' && commands[1] <= '9')
				len = atoi(commands + 1);
			fd = llapi_create_volatile_idx(fname, len, flags);
			if (fd < 0) {
				perror("llapi_create_volatile");
				exit(fd);
			}
			rc = fd;
			break;
		case 'w':
		case 'P':
			if (*(commands + 1) == 'u') {
				unaligned = true;
				commands++;
			}
			len = atoi(commands + 1);
			if (len <= 0)
				len = 1;
			/* for unaligned, we realloc every time, so the
			 * buffer alignment is variable
			 *
			 * the last condition is "if buf is unaligned", so when
			 * unaligned is not set, we realloc if the buf is
			 * unaligned to create an aligned buffer
			 */
			if (bufsize < len || unaligned ||
			    buf !=
			    (char *)((long)(buf + ALIGN_LEN) & ~ALIGN_LEN)) {
				void *tmp;

				/* We add a margin of + ALIGN_LEN to let us
				 * unalign and stay in the buffer
				 */
				tmp = realloc(buf, len + ALIGN_LEN*2);
				if (!tmp) {
					free(buf);
					save_errno = errno;
					perror("allocating buf for write\n");
					exit(save_errno);
				}
				buf = tmp;
				bufsize = len;
				buf_align = (char *)((long)(buf + ALIGN_LEN) &
						     ~ALIGN_LEN);
				/* if the original buffer was aligned, we
				 * manually unalign it.  Otherwise, we use
				 * the unalignment from the allocator.
				 *
				 * Add + 1 to avoid ever hitting 0, and use
				 * mod 255 to avoid 255 + 1 = 256
				 */
				if (unaligned && buf_align == buf)
					buf_align += rand() % 255 + 1;
				else if (unaligned)
					buf_align = buf;

				/* fill the buffer with our string */
				while (total_bytes < bufsize) {
					/* msg_len does not include the
					 * terminating nul, deliberately,
					 * so all the additions are one string
					 */
					strncpy(buf_align + total_bytes, msg,
						bufsize - total_bytes);
					total_bytes += msg_len;
				}
			}
			while (len > 0) {
				rc = write(fd, buf_align, len);
				if (rc == -1) {
					save_errno = errno;
					perror("write");
					exit(save_errno);
				}
				if (rc < len)
					fprintf(stderr,
						"short write: %lld/%u\n",
						rc, len);
				if (commands[0] == 'P')
					break;
				len -= rc;
				if (verbose >= 2) {
					printf("Buffer address %s: %p\n",
						unaligned ? "(unaligned)" : "",
						buf_align);
					printf("Wrote this (%lld bytes):\n",
					       rc);
					printf("%.*s\n", (int)rc, buf_align);
				}
			}
			break;
		case 'W':
			for (i = 0; i < mmap_len && mmap_ptr; i += 4096)
				mmap_ptr[i] += junk++;
			break;
		case 'x': {
			__u64 dv;

			rc = llapi_get_data_version(fd, &dv, 0);
			if (rc) {
				fprintf(stderr,
					"cannot get file data version %lld\n",
					rc);
				exit(-rc);
			}
			printf("dataversion is %ju\n", (uintmax_t)dv);
			break;
		}
		case 'X': {
			__u32 layout_version;

			rc = llapi_get_ost_layout_version(fd, &layout_version);
			if (rc) {
				fprintf(stderr,
					"cannot get ost layout version %lld\n",
					rc);
				exit(-rc);
			}
			printf("ostlayoutversion: %u\n", layout_version);
			break;
		}
		case 'y':
			if (fsync(fd) == -1) {
				save_errno = errno;
				perror("fsync");
				exit(save_errno);
			}
			break;
		case 'Y':
			if (fdatasync(fd) == -1) {
				save_errno = errno;
				perror("fdatasync");
				exit(save_errno);
			}
			break;
		case 'z': {
			off_t off;

			len = atoi(commands + 1);
			off = lseek(fd, len, SEEK_SET);
			if (off == (off_t)-1) {
				save_errno = errno;
				perror("lseek");
				exit(save_errno);
			}

			rc = off;
			break;
		}
		case 'Z': {
			off_t off;

			len = atoi(commands + 1);
			off = lseek(fd, len, SEEK_CUR);
			if (off == (off_t)-1) {
				save_errno = errno;
				perror("lseek");
				exit(save_errno);
			}

			rc = off;
			break;
		}
		case '-':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			break;
		default:
			fprintf(stderr, "unknown command \"%c\"\n", *commands);
			fprintf(stderr, usage, argv[0]);
			exit(1);
		}
	}

	if (buf)
		free(buf);

	return 0;
}
