/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* pull in O_DIRECTORY in bits/fcntl.h */
#endif
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <sys/file.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <semaphore.h>
#include <time.h>
#include <err.h>

#include <lustre/lustreapi.h>

#define T1 "write data before unlink\n"
#define T2 "write data after unlink\n"
char msg[] = "yabba dabba doo, I'm coming for you, I live in a shoe, I don't know what to do.\n'Bigger, bigger,and bigger yet!' cried the Creator.  'You are not yet substantial enough for my boundless intents!'  And ever greater and greater the object became, until all was lost 'neath its momentus bulk.\n";
char *buf, *buf_align;
int bufsize = 0;
sem_t sem;
#define ALIGN_LEN 65535
#define XATTR "user.multiop"

char usage[] =
"Usage: %s filename command-sequence [path...]\n"
"    command-sequence items:\n"
"	 A  fsetxattr(\"user.multiop\")\n"
"	 a  fgetxattr(\"user.multiop\")\n"
"	 c  close\n"
"	 B[num] call setstripe ioctl to create stripes\n"
"	 C[num] create with optional stripes\n"
"	 d  mkdir\n"
"	 D  open(O_DIRECTORY)\n"
"	 e[R|W|U] apply lease. R: Read; W: Write; U: Unlock\n"
"	 E[+|-] get lease. +/-: expect lease to (not) exist\n"
"	 f  statfs\n"
"	 F  print FID\n"
"	 H[num] create HSM released file with num stripes\n"
"	 G gid get grouplock\n"
"	 g gid put grouplock\n"
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
"	 x  get file data version\n"
"	 W  write entire mmap-ed region\n"
"	 y  fsync\n"
"	 Y  fdatasync\n"
"	 z[num] lseek(SEEK_SET) [optional offset, default 0]\n"
"	 Z[num] lseek(SEEK_CUR) [optional offset, default 0]\n"
"	 _  wait for signal\n";

void usr1_handler(int unused)
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
        static int cur_arg = 3;

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

int get_flags(char *data, int *rflags)
{
        char *cloned_flags;
        char *tmp;
        int flag_set = 0;
        int flags = 0;
        int size = 0;

        cloned_flags = strdup(data);
        if (cloned_flags == NULL) {
                fprintf(stderr, "Insufficient memory.\n");
                exit(-1);
        }

        for (tmp = strtok(cloned_flags, ":"); tmp;
             tmp = strtok(NULL, ":")) {
                int i;

                size = tmp - cloned_flags;
                for (i = 0; flag_table[i].flag != -1; i++) {
                        if (!strcmp(tmp, flag_table[i].string)){
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

#define POP_ARG() (pop_arg(argc, argv))

int main(int argc, char **argv)
{
	char			*fname, *commands;
	const char		*newfile;
	const char		*oldpath;
	struct stat		 st;
	struct statfs		 stfs;
	size_t			 mmap_len = 0, i;
	unsigned char		*mmap_ptr = NULL, junk = 0;
	int			 len, fd = -1;
	int			 flags;
	int			 save_errno;
	int			 verbose = 0;
	int			 gid = 0;
	struct lu_fid		 fid;
	struct timespec		 ts;
	struct lov_user_md_v3	 lum;
	long long rc = 0;
	long long last_rc;

        if (argc < 3) {
                fprintf(stderr, usage, argv[0]);
                exit(1);
        }

        memset(&st, 0, sizeof(st));
        sem_init(&sem, 0, 0);
        /* use sigaction instead of signal to avoid SA_ONESHOT semantics */
        sigaction(SIGUSR1, &(const struct sigaction){.sa_handler = &usr1_handler},
                  NULL);

        fname = argv[1];

        for (commands = argv[2]; *commands; commands++) {
		/* XXX Most commands return 0 or we exit so we only
		 * update rc where really needed. */
		last_rc = rc;
		rc = 0;

                switch (*commands) {
                case '_':
                        if (verbose) {
                                printf("PAUSING\n");
                                fflush(stdout);
                        }
			len = atoi(commands+1);
			if (len <= 0)
				len = 3600; /* 1 hour */
			ts.tv_sec = time(NULL) + len;
			ts.tv_nsec = 0;
                        while (sem_timedwait(&sem, &ts) < 0 && errno == EINTR);
                        break;
		case 'A':
			if (fsetxattr(fd, XATTR, "multiop", 8, 0)) {
				save_errno = errno;
				perror("fsetxattr");
				exit(save_errno);
			}
			break;
		case 'a':
			rc = fgetxattr(fd, XATTR, NULL, 0);
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
                        len = atoi(commands+1);
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
			break;
                case 'G':
                        gid = atoi(commands+1);
                        if (ioctl(fd, LL_IOC_GROUP_LOCK, gid) == -1) {
                                save_errno = errno;
                                perror("ioctl(GROUP_LOCK)");
                                exit(save_errno);
                        }
                        break;
                case 'g':
                        gid = atoi(commands+1);
                        if (ioctl(fd, LL_IOC_GROUP_UNLOCK, gid) == -1) {
                                save_errno = errno;
                                perror("ioctl(GROUP_UNLOCK)");
                                exit(save_errno);
                        }
                        break;
		case 'H':
			len = atoi(commands+1);
			fd = llapi_file_open(fname, O_CREAT | O_WRONLY,
				0644, 0, 0, len,
				LOV_PATTERN_RAID0 | LOV_PATTERN_F_RELEASED);
			if (fd == -1) {
				save_errno = errno;
				perror("create stripe file");
				exit(save_errno);
			}
			rc = fd;
			break;
		case 'j':
			if (flock(fd, LOCK_EX) == -1)
				errx(-1, "flock()");
			break;
		case 'K':
			oldpath = POP_ARG();
			if (oldpath == NULL)
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
			if (newfile == NULL)
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
                                fprintf(stderr, "mmap without preceeding stat, or on"
                                        " zero length file.\n");
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
			if (oldpath == NULL)
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
                        if (rename (fname, newfile)) {
                                save_errno = errno;
                                perror("rename()");
                                exit(save_errno);
                        }
                        break;
                case 'O':
                        fd = open(fname, O_CREAT|O_RDWR, 0644);
                        if (fd == -1) {
                                save_errno = errno;
                                perror("open(O_RDWR|O_CREAT)");
                                exit(save_errno);
                        }
			rc = fd;
                        break;
                case 'o':
                        len = get_flags(commands+1, &flags);
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
		case 'r':
			len = atoi(commands+1);
			if (len <= 0)
				len = 1;
			if (bufsize < len) {
				void *tmp;
				tmp = realloc(buf, len + ALIGN_LEN);
				if (tmp == NULL) {
					free(buf);
					save_errno = errno;
					perror("allocating buf for read\n");
					exit(save_errno);
				}
				buf = tmp;
				bufsize = len;
				buf_align = (char *)((long)(buf + ALIGN_LEN) &
						     ~ALIGN_LEN);
			}
			while (len > 0) {
				rc = read(fd, buf_align, len);
				if (rc == -1) {
					save_errno = errno;
					perror("read");
					exit(save_errno);
				}
				if (rc < len) {
					fprintf(stderr, "short read: %lld/%u\n",
						rc, len);
					if (rc == 0)
						exit(ENODATA);
				}
				len -= rc;
				if (verbose >= 2)
					printf("%.*s\n", (int)rc, buf_align);
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
                        len = atoi(commands+1);
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
			fd = llapi_create_volatile(fname, flags);
			if (fd < 0) {
				perror("llapi_create_volatile");
				exit(fd);
			}
			rc = fd;
			break;
		case 'w':
			len = atoi(commands+1);
			if (len <= 0)
				len = 1;
			if (bufsize < len) {
				void *tmp;
				tmp = realloc(buf, len + ALIGN_LEN);
				if (tmp == NULL) {
					free(buf);
					save_errno = errno;
					perror("allocating buf for write\n");
					exit(save_errno);
				}
				buf = tmp;
				bufsize = len;
				buf_align = (char *)((long)(buf + ALIGN_LEN) &
						     ~ALIGN_LEN);
				strncpy(buf_align, msg, bufsize);
			}
			while (len > 0) {
				rc = write(fd, buf_align, len);
				if (rc == -1) {
					save_errno = errno;
					perror("write");
					exit(save_errno);
				}
				if (rc < len)
					fprintf(stderr, "short write: %lld/%u\n",
						rc, len);
				len -= rc;
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
				fprintf(stderr, "cannot get file data version"
					" %lld\n", rc);
				exit(-rc);
			}
			printf("dataversion is %ju\n", (uintmax_t)dv);
			break;
		}
		case 'X': {
			__u32 layout_version;

			rc = llapi_get_ost_layout_version(fd, &layout_version);
			if (rc) {
				fprintf(stderr, "cannot get ost layout version"
					" %lld\n", rc);
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
