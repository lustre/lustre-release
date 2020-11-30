/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 * Copyright (c) 2019, DDN Storage Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 *
 * Test for Lustre statx().
 * It uses some code in coreutils ('ls.c' and 'stat.c') for reference.
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */
#define _ATFILE_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <inttypes.h>
#include <fcntl.h>
#include <locale.h>
#include <linux/lustre/lustre_user.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

/* Factor out some of the common --help and --version processing code. */

/* These enum values cannot possibly conflict with the option values
 * ordinarily used by commands, including CHAR_MAX + 1, etc.  Avoid
 * CHAR_MIN - 1, as it may equal -1, the getopt end-of-options value.
 */
enum {
	PRINTF_OPTION = (CHAR_MAX + 1),
	GETOPT_HELP_CHAR = (CHAR_MIN - 2),
	GETOPT_VERSION_CHAR = (CHAR_MIN - 3)
};

static bool o_quiet;

#ifdef __NR_statx
#ifndef HAVE_STATX

#define AT_STATX_SYNC_TYPE	0x6000
#define AT_STATX_FORCE_SYNC	0x2000
#define AT_STATX_DONT_SYNC	0x4000

static __attribute__((unused))
ssize_t statx(int dfd, const char *filename, int flags,
	      unsigned int mask, struct statx *buffer)
{
	return syscall(__NR_statx, dfd, filename, flags, mask, buffer);
}
#endif /* HAVE_STATX */

#define xstrdup(str) strdup(str)
static inline
char *xasprintf(const char *fmt, const char *old_fmt, const char *str)
{
	char *tmp = NULL;

	if (asprintf(&tmp, fmt, old_fmt, str) < 0) {
		fprintf(stderr, "asprintf allocation failed\n");
		exit(1);
	}

	return tmp;
}


/* coreutils/lib/intprops.h */
#define _GL_SIGNED_TYPE_OR_EXPR(t) TYPE_SIGNED(__typeof__(t))

/* Bound on length of the string representing an unsigned integer
 * value representable in B bits.  log10 (2.0) < 146/485.  The
 * smallest value of B where this bound is not tight is 2621.
 */
#define INT_BITS_STRLEN_BOUND(b) (((b) * 146 + 484) / 485)

/* The width in bits of the integer type or expression T.
 * Do not evaluate T.
 * Padding bits are not supported; this is checked at compile-time below.
 */
#define TYPE_WIDTH(t) (sizeof(t) * CHAR_BIT)

/* Bound on length of the string representing an integer type or expression T.
 * Subtract 1 for the sign bit if T is signed, and then add 1 more for
 * a minus sign if needed.
 *
 * Because _GL_SIGNED_TYPE_OR_EXPR sometimes returns 1 when its argument is
 * unsigned, this macro may overestimate the true bound by one byte when
 * applied to unsigned types of size 2, 4, 16, ... bytes.
 */
#define INT_STRLEN_BOUND(t)                                     \
	(INT_BITS_STRLEN_BOUND(TYPE_WIDTH(t) - _GL_SIGNED_TYPE_OR_EXPR(t)) \
	+ _GL_SIGNED_TYPE_OR_EXPR(t))

/* Bound on buffer size needed to represent an integer type or expression T,
 * including the terminating null.
 */
#define INT_BUFSIZE_BOUND(t) (INT_STRLEN_BOUND(t) + 1)

/* The maximum and minimum values for the integer type T.  */
#define TYPE_MINIMUM(t) ((t)~TYPE_MAXIMUM(t))
#define TYPE_MAXIMUM(t)						\
	((t) (!TYPE_SIGNED(t)					\
	? (t)-1						\
	: ((((t)1 << (TYPE_WIDTH(t) - 2)) - 1) * 2 + 1)))

static bool o_dir_list;
static bool long_format; /* use a long listing format */

/* Current time in seconds and nanoseconds since 1970, updated as
 * needed when deciding whether a file is recent.
 */
static struct timespec current_time;

/* FIXME: these are used by printf.c, too */
#define isodigit(c) ('0' <= (c) && (c) <= '7')
#define octtobin(c) ((c) - '0')
#define hextobin(c) ((c) >= 'a' && (c) <= 'f' ? (c) - 'a' + 10 : \
		     (c) >= 'A' && (c) <= 'F' ? (c) - 'A' + 10 : (c) - '0')

#define ISDIGIT(c) ((unsigned int)(c) - '0' <= 9)

/* True if the real type T is signed.  */
#define TYPE_SIGNED(t) (!((t)0 < (t)-1))

static char const digits[] = "0123456789";

/* Flags that are portable for use in printf, for at least one
 * conversion specifier; make_format removes unportable flags as
 * needed for particular specifiers.  The glibc 2.2 extension "I" is
 * listed here; it is removed by make_format because it has undefined
 * behavior elsewhere and because it is incompatible with
 * out_epoch_sec.
 */
static char const printf_flags[] = "'-+ #0I";

/* Formats for the --terse option. */
static char const fmt_terse_fs[] = "%n %i %l %t %s %S %b %f %a %c %d\n";
static char const fmt_terse_regular[] = "%n %s %b %f %u %g %D %i %h %t %T"
					" %X %Y %Z %W %o\n";
#ifdef HAVE_SELINUX
static char const fmt_terse_selinux[] = "%n %s %b %f %u %g %D %i %h %t %T"
					" %X %Y %Z %W %o %C\n";
#endif
static char *format;

/* Whether to follow symbolic links;  True for --dereference (-L).  */
static bool follow_links;

/* Whether to interpret backslash-escape sequences.
 * True for --printf=FMT, not for --format=FMT (-c).
 */
static bool interpret_backslash_escapes;

/* The trailing delimiter string:
 * "" for --printf=FMT, "\n" for --format=FMT (-c).
 */
static char const *trailing_delim = "";

/* The representation of the decimal point in the current locale.  */
static char const *decimal_point;
static size_t decimal_point_len;

/* Convert a possibly-signed character to an unsigned character.  This is
 * a bit safer than casting to unsigned char, since it catches some type
 * errors that the cast doesn't.
 */
static inline unsigned char to_uchar(char ch)
{
	return ch;
}

void usage(char *prog)
{
	printf("Usage: %s [options] <FILE>...\n", prog);
	printf("Display file status via statx() syscall.\n"
	       "List information about the FILE "
	       "(the current diretory by default) via statx() syscall.\n"
	       "options:\n"
	       "\t-L --dereference   follow links\n"
	       "\t--cached=MODE      specify how to use cached attributes;\n"
	       "\t                     See MODE below\n"
	       "\t-c --format=FORMAT use the specified FORMAT instead of the "
	       "default;\n"
	       "\t                     output a newline after each use of "
	       "FORMAT\n"
	       "\t-t, --terse        print the information in terse form\n"
	       "\t-D --dir           list information about the FILE (ls)\n"
	       "\t-l                 use a long listing format\n"
	       "\t-q --quiet         do not display results, test only\n\n"
	       "The --cached MODE argument can be; always, never, or default.\n"
	       "`always` will use cached attributes if available, while\n"
	       "`never` will try to synchronize with the latest attributes,\n"
	       "and `default` will leave it up to the underlying file system.\n"
	       "\n"
	       "The valid format sequences for files (without --file-system):\n"
	       "\n"
	       "\t%%a  access rights in octal (note '#' and '0' printf flags)\n"
	       "\t%%A   access rights in human readable form\n"
	       "\t%%b   number of blocks allocated (see %%B)\n"
	       "\t%%B   the size in bytes of each block reported by %%b\n"
	       "\t%%C   SELinux security context string\n"
	       "\t%%d   device number in decimal\n"
	       "\t%%D   device number in hex\n"
	       "\t%%f   raw mode in hex\n"
	       "\t%%F   file type\n"
	       "\t%%g   group ID of owner\n"
	       "\t%%G   group name of owner\n"
	       "\t%%h   number of hard links\n"
	       "\t%%i   inode number\n"
	       "\t%%m   mount point\n"
	       "\t%%n   file name\n"
	       "\t%%N   quoted file name with dereference if symbolic link\n"
	       "\t%%o   optimal I/O transfer size hint\n"
	       "\t%%p   Mask to show what's supported in stx_attributes\n"
	       "\t%%r   Flags conveying information about the file: "
	       "stx_attributes\n"
	       "\t%%s   total size, in bytes\n"
	       "\t%%t   major device type in hex, for character/block device "
	       "special files\n"
	       "\t%%T   minor device type in hex, for character/block device "
	       "special files\n"
	       "\t%%u   user ID of owner\n"
	       "\t%%U   user name of owner\n"
	       "\t%%w   time of file birth, human-readable; - if unknown\n"
	       "\t%%W   time of file birth, seconds since Epoch; 0 if unknown\n"
	       "\t%%x   time of last access, human-readable\n"
	       "\t%%X   time of last access, seconds since Epoch\n"
	       "\t%%y   time of last data modification, human-readable\n"
	       "\t%%Y   time of last data modification, seconds since Epoch\n"
	       "\t%%z   time of last status change, human-readable\n"
	       "\t%%Z   time of last status change, seconds since Epoch\n");
	exit(0);
}

/* gnulib/lib/filemode.c */
/* Return a character indicating the type of file described by
 * file mode BITS:
 * '-' regular file
 * 'b' block special file
 * 'c' character special file
 * 'C' high performance ("contiguous data") file
 * 'd' directory
 * 'D' door
 * 'l' symbolic link
 * 'm' multiplexed file (7th edition Unix; obsolete)
 * 'n' network special file (HP-UX)
 * 'p' fifo (named pipe)
 * 'P' port
 * 's' socket
 * 'w' whiteout (4.4BSD)
 * '?' some other file type
 */
static char ftypelet(mode_t bits)
{
	/* These are the most common, so test for them first.*/
	if (S_ISREG(bits))
		return '-';
	if (S_ISDIR(bits))
		return 'd';

	/* Other letters standardized by POSIX 1003.1-2004.*/
	if (S_ISBLK(bits))
		return 'b';
	if (S_ISCHR(bits))
		return 'c';
	if (S_ISLNK(bits))
		return 'l';
	if (S_ISFIFO(bits))
		return 'p';

	/* Other file types (though not letters) standardized by POSIX.*/
	if (S_ISSOCK(bits))
		return 's';

	return '?';
}

/* Like filemodestring, but rely only on MODE.*/
static void strmode(mode_t mode, char *str)
{
	str[0] = ftypelet(mode);
	str[1] = mode & S_IRUSR ? 'r' : '-';
	str[2] = mode & S_IWUSR ? 'w' : '-';
	str[3] = (mode & S_ISUID
			? (mode & S_IXUSR ? 's' : 'S')
			: (mode & S_IXUSR ? 'x' : '-'));
	str[4] = mode & S_IRGRP ? 'r' : '-';
	str[5] = mode & S_IWGRP ? 'w' : '-';
	str[6] = (mode & S_ISGID
			? (mode & S_IXGRP ? 's' : 'S')
			: (mode & S_IXGRP ? 'x' : '-'));
	str[7] = mode & S_IROTH ? 'r' : '-';
	str[8] = mode & S_IWOTH ? 'w' : '-';
	str[9] = (mode & S_ISVTX
			? (mode & S_IXOTH ? 't' : 'T')
			: (mode & S_IXOTH ? 'x' : '-'));
	str[10] = ' ';
	str[11] = '\0';
}

/* filemodestring - fill in string STR with an ls-style ASCII
 * representation of the st_mode field of file stats block STATP.
 * 12 characters are stored in STR.
 * The characters stored in STR are:
 *
 * 0    File type, as in ftypelet above, except that other letters are used
 *      for files whose type cannot be determined solely from st_mode:
 *
 *          'F' semaphore
 *          'M' migrated file (Cray DMF)
 *          'Q' message queue
 *          'S' shared memory object
 *          'T' typed memory object
 *
 * 1    'r' if the owner may read, '-' otherwise.
 *
 * 2    'w' if the owner may write, '-' otherwise.
 *
 * 3    'x' if the owner may execute, 's' if the file is
 *      set-user-id, '-' otherwise.
 *      'S' if the file is set-user-id, but the execute
 *      bit isn't set.
 *
 * 4    'r' if group members may read, '-' otherwise.
 *
 * 5    'w' if group members may write, '-' otherwise.
 *
 * 6    'x' if group members may execute, 's' if the file is
 *      set-group-id, '-' otherwise.
 *      'S' if it is set-group-id but not executable.
 *
 * 7    'r' if any user may read, '-' otherwise.
 *
 * 8    'w' if any user may write, '-' otherwise.
 *
 * 9    'x' if any user may execute, 't' if the file is "sticky"
 *      (will be retained in swap space after execution), '-'
 *      otherwise.
 *      'T' if the file is sticky but not executable.
 *
 * 10   ' ' for compatibility with 4.4BSD strmode,
 *      since this interface does not support ACLs.
 *
 * 11   '\0'.
 */
static void filemodestring(struct statx const *stxp, char *str)
{
	strmode(stxp->stx_mode, str);

/*
	if (S_TYPEISSEM(statp))
		str[0] = 'F';
	else if (IS_MIGRATED_FILE (statp))
		str[0] = 'M';
	else if (S_TYPEISMQ (statp))
		str[0] = 'Q';
	else if (S_TYPEISSHM (statp))
		str[0] = 'S';
	else if (S_TYPEISTMO (statp))
		str[0] = 'T';
 */
}

/* gnulib/lib/file-type.c */
static char const *file_type(struct statx const *stx)
{
	/* See POSIX 1003.1-2001 XCU Table 4-8 lines 17093-17107 for some of
	 * these formats.
	 *
	 * To keep diagnostics grammatical in English, the returned string
	 * must start with a consonant.
	 */
	/* Do these three first, as they're the most common.  */
	if (S_ISREG(stx->stx_mode))
		return stx->stx_size == 0 ? "regular empty file" :
					    "regular file";

	if (S_ISDIR(stx->stx_mode))
		return "directory";

	if (S_ISLNK(stx->stx_mode))
		return "symbolic link";

	/* The remaining are in alphabetical order.  */
	if (S_ISBLK(stx->stx_mode))
		return "block special file";

	if (S_ISCHR(stx->stx_mode))
		return "character special file";

	if (S_ISFIFO(stx->stx_mode))
		return "fifo";

	if (S_ISSOCK(stx->stx_mode))
		return "socket";

	return "weird file";
}

/* gnulib/lib/areadlink-with-size.c */
/* SYMLINK_MAX is used only for an initial memory-allocation sanity
 * check, so it's OK to guess too small on hosts where there is no
 * arbitrary limit to symbolic link length.
 */
#ifndef SYMLINK_MAX
#define SYMLINK_MAX 1024
#endif

#define MAXSIZE (SIZE_MAX < SSIZE_MAX ? SIZE_MAX : SSIZE_MAX)

/* Call readlink to get the symbolic link value of FILE.
 * SIZE is a hint as to how long the link is expected to be;
 * typically it is taken from st_size.  It need not be correct.
 * Return a pointer to that NUL-terminated string in malloc'd storage.
 * If readlink fails, malloc fails, or if the link value is longer
 * than SSIZE_MAX, return NULL (caller may use errno to diagnose).
 */
static char *areadlink_with_size(char const *file, size_t size)
{
	/* Some buggy file systems report garbage in st_size.  Defend
	 * against them by ignoring outlandish st_size values in the initial
	 * memory allocation.
	 */
	size_t symlink_max = SYMLINK_MAX;
	size_t INITIAL_LIMIT_BOUND = 8 * 1024;
	size_t initial_limit = (symlink_max < INITIAL_LIMIT_BOUND ?
				symlink_max + 1 : INITIAL_LIMIT_BOUND);
	enum { stackbuf_size = 128 };
	/* The initial buffer size for the link value. */
	size_t buf_size = (size == 0 ? stackbuf_size : size < initial_limit ?
			   size + 1 : initial_limit);

	while (1) {
		ssize_t r;
		size_t link_length;
		char stackbuf[stackbuf_size];
		char *buf = stackbuf;
		char *buffer = NULL;

		if (!(size == 0 && buf_size == stackbuf_size)) {
			buf = buffer = malloc(buf_size);
			if (!buffer)
				return NULL;
		}

		r = readlink(file, buf, buf_size);
		link_length = r;

		/* On AIX 5L v5.3 and HP-UX 11i v2 04/09, readlink returns -1
		 * with errno == ERANGE if the buffer is too small.
		 */
		if (r < 0 && errno != ERANGE) {
			int saved_errno = errno;

			free(buffer);
			errno = saved_errno;
			return NULL;
		}

		if (link_length < buf_size) {
			buf[link_length] = 0;
			if (!buffer) {
				buffer = malloc(link_length + 1);
				if (buffer)
					return memcpy(buffer, buf,
						      link_length + 1);
			} else if (link_length + 1 < buf_size) {
				/* Shrink BUFFER before returning it. */
				char *shrinked_buffer;

				shrinked_buffer = realloc(buffer,
							  link_length + 1);
				if (shrinked_buffer != NULL)
					buffer = shrinked_buffer;
			}
			return buffer;
		}

		free(buffer);
		if (buf_size <= MAXSIZE / 2) {
			buf_size *= 2;
		} else if (buf_size < MAXSIZE) {
			buf_size = MAXSIZE;
		} else {
			errno = ENOMEM;
			return NULL;
		}
	}
}

/* coreutils/src/stat.c */
/* Output a single-character \ escape.  */
static void print_esc_char(char c)
{
	switch (c) {
	case 'a':			/* Alert. */
		c = '\a';
		break;
	case 'b':			/* Backspace. */
		c = '\b';
		break;
	case 'e':			/* Escape. */
		c = '\x1B';
		break;
	case 'f':			/* Form feed. */
		c = '\f';
		break;
	case 'n':			/* New line. */
		c = '\n';
		break;
	case 'r':			/* Carriage return. */
		c = '\r';
		break;
	case 't':			/* Horizontal tab. */
		c = '\t';
		break;
	case 'v':			/* Vertical tab. */
		c = '\v';
		break;
	case '"':
	case '\\':
		break;
	default:
		printf("warning: unrecognized escape '\\%c'", c);
		break;
	}
	putchar (c);
}

static size_t format_code_offset(char const *directive)
{
	size_t len = strspn(directive + 1, printf_flags);
	char const *fmt_char = directive + len + 1;

	fmt_char += strspn(fmt_char, digits);
	if (*fmt_char == '.')
		fmt_char += 1 + strspn(fmt_char + 1, digits);

	return fmt_char - directive;
}

static unsigned int fmt_to_mask(char fmt)
{
	switch (fmt) {
	case 'N':
		return STATX_MODE;
	case 'd':
	case 'D':
		return STATX_MODE;
	case 'i':
		return STATX_INO;
	case 'a':
	case 'A':
		return STATX_MODE;
	case 'f':
		return STATX_MODE|STATX_TYPE;
	case 'F':
		return STATX_TYPE;
	case 'h':
		return STATX_NLINK;
	case 'u':
	case 'U':
		return STATX_UID;
	case 'g':
	case 'G':
		return STATX_GID;
	case 'm':
		return STATX_MODE|STATX_INO;
	case 's':
		return STATX_SIZE;
	case 't':
	case 'T':
		return STATX_MODE;
	case 'b':
		return STATX_BLOCKS;
	case 'w':
	case 'W':
		return STATX_BTIME;
	case 'x':
	case 'X':
		return STATX_ATIME;
	case 'y':
	case 'Y':
		return STATX_MTIME;
	case 'z':
	case 'Z':
		return STATX_CTIME;
	}
	return 0;
}

static unsigned int format_to_mask(char const *format)
{
	unsigned int mask = 0;
	char const *b;

	for (b = format; *b; b++) {
		if (*b != '%')
			continue;

		b += format_code_offset(b);
		if (*b == '\0')
			break;
		mask |= fmt_to_mask(*b);
	}

	return mask;
}

static char *human_access(struct statx const *stxbuf)
{
	static char modebuf[12];

	filemodestring(stxbuf, modebuf);
	modebuf[10] = 0;
	return modebuf;
}

static inline struct timespec
statx_timestamp_to_timespec(struct statx_timestamp tsx)
{
	struct timespec ts;

	ts.tv_sec = tsx.tv_sec;
	ts.tv_nsec = tsx.tv_nsec;

	return ts;
}

static int timespec_cmp(struct timespec a, struct timespec b)
{
	if (a.tv_sec < b.tv_sec)
		return -1;
	if (a.tv_sec > b.tv_sec)
		return 1;

	return a.tv_nsec - b.tv_nsec;
}

static char *human_time(const struct statx_timestamp *ts)
{
	/* STR must be at least INT_BUFSIZE_BOUND (intmax_t) big, either
	 * because localtime_rz fails, or because the time zone is truly
	 * outlandish so that %z expands to a long string.
	 */
	static char str[INT_BUFSIZE_BOUND(intmax_t)
		+ INT_STRLEN_BOUND(int) /* YYYY */
		+ 1 /* because YYYY might equal INT_MAX + 1900 */
		+ sizeof "-MM-DD HH:MM:SS.NNNNNNNNN +"];
	struct tm tm;
	time_t tim;
	int len;
	int len2;

	tim = ts->tv_sec;
	if (!localtime_r(&tim, &tm)) {
		perror("localtime_r");
		exit(EXIT_FAILURE);
	}

	if (o_dir_list && long_format) {
		struct timespec when_timespec;
		struct timespec six_months_ago;
		bool recent;

		when_timespec = statx_timestamp_to_timespec(*ts);
		/* If the file appears to be in the future, update the current
		 * time, in case the file happens to have been modified since
		 * the last time we checked the clock.
		 */
		if (timespec_cmp(current_time, when_timespec) < 0) {
			struct timeval tv;

			gettimeofday(&tv, NULL);
			current_time.tv_sec = tv.tv_sec;
			current_time.tv_nsec = tv.tv_usec * 1000;
		}

		/* Consider a time to be recent if it is within the past six
		 * months.
		 * A Gregorian year has 365.2425 * 24 * 60 * 60 == 31556952
		 * seconds on the average.  Write this value as an integer
		 * constant to avoid floating point hassles.
		 */
		six_months_ago.tv_sec = current_time.tv_sec - 31556952 / 2;
		six_months_ago.tv_nsec = current_time.tv_nsec;

		recent = (timespec_cmp(six_months_ago, when_timespec) < 0 &&
			  (timespec_cmp(when_timespec, current_time) < 0));

		/* We assume here that all time zones are offset from UTC by a
		 * whole number of seconds.
		 */
		len = strftime(str, sizeof(str),
			       recent ? "%b %e %H:%M" : "%b %e %Y", &tm);
		if (len == 0) {
			perror("strftime");
			exit(EXIT_FAILURE);
		}

		return str;
	}

	len = strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S", &tm);
	if (len == 0) {
		perror("strftime");
		exit(EXIT_FAILURE);
	}

	len2 = snprintf(str + len, sizeof(str) - len, ".%09u ", ts->tv_nsec);
	len = strftime(str + len + len2, sizeof(str) - len - len2, "%z", &tm);
	if (len == 0) {
		perror("strftime2");
		exit(1);
	}

	return str;
}

/* PFORMAT points to a '%' followed by a prefix of a format, all of
 * size PREFIX_LEN.  The flags allowed for this format are
 * ALLOWED_FLAGS; remove other printf flags from the prefix, then
 * append SUFFIX.
 */
static void make_format(char *pformat, size_t prefix_len,
			char const *allowed_flags, char const *suffix)
{
	char *dst = pformat + 1;
	char const *src;
	char const *srclim = pformat + prefix_len;

	for (src = dst; src < srclim && strchr(printf_flags, *src); src++)
		if (strchr(allowed_flags, *src))
			*dst++ = *src;
	while (src < srclim)
		*dst++ = *src++;
	strcpy(dst, suffix);
}

static void out_string(char *pformat, size_t prefix_len, char const *arg)
{
	make_format(pformat, prefix_len, "-", "s");
	printf(pformat, arg);
}

static int out_int(char *pformat, size_t prefix_len, intmax_t arg)
{
	make_format(pformat, prefix_len, "'-+ 0", PRIdMAX);
	return printf(pformat, arg);
}

static int out_uint(char *pformat, size_t prefix_len, uintmax_t arg)
{
	make_format(pformat, prefix_len, "'-0", PRIuMAX);
	return printf(pformat, arg);
}

static void out_uint_o(char *pformat, size_t prefix_len, uintmax_t arg)
{
	make_format(pformat, prefix_len, "-#0", PRIoMAX);
	printf(pformat, arg);
}

static void out_uint_x(char *pformat, size_t prefix_len, uintmax_t arg)
{
	make_format(pformat, prefix_len, "-#0", PRIxMAX);
	printf(pformat, arg);
}

static int out_minus_zero(char *pformat, size_t prefix_len)
{
	make_format(pformat, prefix_len, "'-+ 0", ".0f");
	return printf(pformat, -0.25);
}

/* Output the number of seconds since the Epoch, using a format that
 * acts like printf's %f format.
 */
static void out_epoch_sec(char *pformat, size_t prefix_len,
			  struct timespec arg)
{
	char *dot = memchr(pformat, '.', prefix_len);
	size_t sec_prefix_len = prefix_len;
	int width = 0;
	int precision = 0;
	bool frac_left_adjust = false;

	if (dot) {
		sec_prefix_len = dot - pformat;
		pformat[prefix_len] = '\0';

		if (ISDIGIT(dot[1])) {
			long int lprec = strtol(dot + 1, NULL, 10);

			precision = (lprec <= INT_MAX ? lprec : INT_MAX);
		} else {
			precision = 9;
		}

		if (precision && ISDIGIT(dot[-1])) {
			/* If a nontrivial width is given, subtract the width
			 * of the decimal point and PRECISION digits that will
			 * be output later.
			 */
			char *p = dot;

			*dot = '\0';

			do
				--p;
			while (ISDIGIT(p[-1]));

			long int lwidth = strtol(p, NULL, 10);

			width = (lwidth <= INT_MAX ? lwidth : INT_MAX);
			if (width > 1) {
				p += (*p == '0');
				sec_prefix_len = p - pformat;

				int w_d = (decimal_point_len < width ?
					   width - decimal_point_len : 0);

				if (w_d > 1) {
					int w = w_d - precision;

					if (w > 1) {
						char *dst = pformat;
						char const *src = dst;
						for (; src < p; src++) {
							if (*src == '-')
								frac_left_adjust = true;
							else
								*dst++ = *src;
						}
						sec_prefix_len =
							(dst - pformat
			+ (frac_left_adjust ? 0 : sprintf(dst, "%d", w)));
					}
				}
			}
		}
	}

	int divisor = 1;
	int i;

	for (i = precision; i < 9; i++)
		divisor *= 10;

	int frac_sec = arg.tv_nsec / divisor;
	int int_len;


	if (TYPE_SIGNED(time_t)) {
		bool minus_zero = false;

		if (arg.tv_sec < 0 && arg.tv_nsec != 0) {
			int frac_sec_modulus = 1000000000 / divisor;

			frac_sec = (frac_sec_modulus - frac_sec
				    - (arg.tv_nsec % divisor != 0));
			arg.tv_sec += (frac_sec != 0);
			minus_zero = (arg.tv_sec == 0);
		}
		int_len = (minus_zero ?
			   out_minus_zero(pformat, sec_prefix_len) :
			   out_int(pformat, sec_prefix_len, arg.tv_sec));
	} else {
		int_len = out_uint(pformat, sec_prefix_len, arg.tv_sec);
	}

	if (precision) {
		int prec = (precision < 9 ? precision : 9);
		int trailing_prec = precision - prec;
		int ilen = (int_len < 0 ? 0 : int_len);
		int trailing_width = (ilen < width &&
				      decimal_point_len < width - ilen ?
				      width - ilen - decimal_point_len - prec :
				      0);

		printf("%s%.*d%-*.*d", decimal_point, prec, frac_sec,
			trailing_width, trailing_prec, 0);
	}
}

/* Print the context information of FILENAME, and return true iff the
 * context could not be obtained.
 */
static int out_file_context(char *pformat, size_t prefix_len,
			    char const *filename)
{
	char *scontext = NULL;
	int rc = 0;

#ifdef HAVE_SELINUX
	if ((follow_links ? getfilecon(filename, &scontext) :
			    lgetfilecon(filename, &scontext)) < 0) {
		printf("failed to get security context of %s: %s\n",
		       filename, strerror(errno));
		scontext = NULL;
		rc  = -errno;
	}
#endif

	strcpy(pformat + prefix_len, "s");
	printf(pformat, (scontext ? scontext : "?"));
#ifdef HAVE_SELINUX
	if (scontext)
		freecon(scontext);
#endif
	return rc;
}

/* Map a TS with negative TS.tv_nsec to {0,0}.  */
static inline struct timespec neg_to_zero(struct timespec ts)
{
	if (ts.tv_nsec >= 0) {
		return ts;
	} else {
		struct timespec z = {0, 0};

		return z;
	}
}

/* All the mode bits that can be affected by chmod.  */
#define CHMOD_MODE_BITS \
	(S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)

/* Print statx info.  Return zero upon success, nonzero upon failure.  */
static int print_statx(char *pformat, size_t prefix_len, unsigned int m,
		       int fd, char const *filename, struct statx const *stx)
{
	struct passwd *pw_ent;
	struct group *gw_ent;
	int rc = 0;
	int ret;

	switch (m) {
	case 'n':
		out_string(pformat, prefix_len,
			   o_dir_list ? strrchr(filename, '/') + 1 : filename);
		break;
	case 'N':
		out_string(pformat, prefix_len,
			   o_dir_list ? strrchr(filename, '/')  + 1 : filename);
		if (S_ISLNK(stx->stx_mode)) {
			char *linkname;

			linkname = areadlink_with_size(filename, stx->stx_size);
			if (linkname == NULL) {
				printf("cannot read symbolic link %s: %s",
				       filename, strerror(errno));
				return -errno;
			}
			printf(" -> ");
			out_string(pformat, prefix_len, linkname);
			free(linkname);
		}
		break;
	case 'd':
		out_uint(pformat, prefix_len, makedev(stx->stx_dev_major,
						      stx->stx_dev_minor));
		break;
	case 'D':
		out_uint_x(pformat, prefix_len, makedev(stx->stx_dev_major,
							stx->stx_dev_minor));
		break;
	case 'i':
		out_uint(pformat, prefix_len, stx->stx_ino);
		break;
	case 'a':
		out_uint_o(pformat, prefix_len,
			   stx->stx_mode & CHMOD_MODE_BITS);
		break;
	case 'A':
		out_string(pformat, prefix_len, human_access(stx));
		break;
	case 'f':
		out_uint_x(pformat, prefix_len, stx->stx_mode);
		break;
	case 'F':
		out_string(pformat, prefix_len, file_type(stx));
		break;
	case 'h':
		out_uint(pformat, prefix_len, stx->stx_nlink);
		break;
	case 'u':
		out_uint(pformat, prefix_len, stx->stx_uid);
		break;
	case 'U':
		pw_ent = getpwuid(stx->stx_uid);
		out_string(pformat, prefix_len,
			   pw_ent ? pw_ent->pw_name : "UNKNOWN");
		break;
	case 'g':
		out_uint(pformat, prefix_len, stx->stx_gid);
		break;
	case 'G':
		gw_ent = getgrgid(stx->stx_gid);
		out_string(pformat, prefix_len,
			   gw_ent ? gw_ent->gr_name : "UNKNOWN");
		break;
	case 'm':
		/*
		 * fail |= out_mount_point(filename, pformat, prefix_len,
		 *			   statbuf);
		 */
		if (!rc)
			rc = -ENOTSUP;
		break;
	case 's':
		out_int(pformat, prefix_len, stx->stx_size);
		break;
	case 't':
		out_uint_x(pformat, prefix_len,
			   major(makedev(stx->stx_rdev_major,
					 stx->stx_rdev_minor)));
		break;
	case 'T':
		out_uint_x(pformat, prefix_len,
			   minor(makedev(stx->stx_rdev_major,
					 stx->stx_rdev_minor)));
		break;
	case 'B':
		out_uint(pformat, prefix_len, S_BLKSIZE);
		break;
	case 'b':
		out_uint(pformat, prefix_len, stx->stx_blocks);
		break;
	case 'o':
		out_uint(pformat, prefix_len, stx->stx_blksize);
		break;
	case 'p':
		out_uint_x(pformat, prefix_len, stx->stx_attributes_mask);
		break;
	case 'r':
		out_uint_x(pformat, prefix_len, stx->stx_attributes);
		break;
	case 'w':
		if (stx->stx_btime.tv_nsec < 0)
			out_string(pformat, prefix_len, "-");
		else
			out_string(pformat, prefix_len,
				   human_time(&stx->stx_btime));
		break;
	case 'W':
		out_epoch_sec(pformat, prefix_len,
			      neg_to_zero(statx_timestamp_to_timespec(
					      stx->stx_btime)));
		break;
	case 'x':
		out_string(pformat, prefix_len,
			   human_time(&stx->stx_atime));
		break;
	case 'X':
		out_epoch_sec(pformat, prefix_len,
			      neg_to_zero(statx_timestamp_to_timespec(
					      stx->stx_atime)));
		break;
	case 'y':
		out_string(pformat, prefix_len,
			   human_time(&stx->stx_mtime));
		break;
	case 'Y':
		out_epoch_sec(pformat, prefix_len,
			      neg_to_zero(statx_timestamp_to_timespec(
					      stx->stx_mtime)));
		break;
	case 'z':
		out_string(pformat, prefix_len,
			   human_time(&stx->stx_ctime));
		break;
	case 'Z':
		out_epoch_sec(pformat, prefix_len,
			      neg_to_zero(statx_timestamp_to_timespec(
					      stx->stx_ctime)));
		break;
	case 'C':
		ret = out_file_context(pformat, prefix_len, filename);
		if (!rc && ret)
			rc = ret;
		break;
	default:
		fputc('?', stdout);
		break;
	}

	return rc;
}

static int print_it(int fd, char const *filename,
		    int (*print_func)(char *, size_t, unsigned int,
				      int, char const *, struct statx const *),
		    void const *data)
{
	/* Add 2 to accommodate our conversion of the stat '%s' format string
	 * to the longer printf '%llu' one.
	 */
	enum {
		MAX_ADDITIONAL_BYTES = (MAX(sizeof(PRIdMAX),
					MAX(sizeof(PRIoMAX),
					    MAX(sizeof(PRIuMAX),
						sizeof(PRIxMAX)))) - 1)
	};
	size_t n_alloc;
	char *dest;
	char const *b;
	int rc = 0;

	if (o_quiet)
		return 0;

	n_alloc = strlen(format) + MAX_ADDITIONAL_BYTES + 1;
	dest = malloc(n_alloc);
	if (dest == NULL)
		return -ENOMEM;

	for (b = format; *b; b++) {
		switch (*b) {
		case '%': {
			size_t len = format_code_offset(b);
			char const *fmt_char = b + len;
			int ret;

			memcpy(dest, b, len);
			b += len;

			switch (*fmt_char) {
			case '\0':
				--b;
			case '%':
				if (len > 1) {
					dest[len] = *fmt_char;
					dest[len + 1] = '\0';
					printf("%s: invalid directive", dest);
					return -EINVAL;
				}
				putchar('%');
				break;
			default:
				ret = print_func(dest, len, to_uchar(*fmt_char),
						 fd, filename, data);
				if (rc == 0 && ret)
					rc = ret;
				break;
			}
			break;
		}
		case '\\':
			if (!interpret_backslash_escapes) {
				putchar ('\\');
				break;
			}
			++b;
			if (isodigit(*b)) {
				int esc_value = octtobin(*b);
				int esc_length = 1; /* number of octal digits */

				for (++b; esc_length < 3 && isodigit(*b);
				     ++esc_length, ++b) {
					esc_value = esc_value * 8 +
						    octtobin(*b);
				}
				putchar(esc_value);
				--b;
			} else if (*b == 'x' && isxdigit(to_uchar(b[1]))) {
				/* Value of \xhh escape. */
				int esc_value = hextobin(b[1]);
				/* A hexadecimal \xhh escape sequence must have
				 * 1 or 2 hex. digits.
				 */

				++b;
				if (isxdigit(to_uchar(b[1]))) {
					++b;
					esc_value = esc_value * 16 +
						    hextobin(*b);
				}
				putchar(esc_value);
			} else if (*b == '\0') {
				printf("warning: backslash at end of format");
				putchar('\\');
				/* Arrange to exit the loop.  */
				--b;
			} else {
				print_esc_char(*b);
			}
			break;

		default:
			putchar(*b);
			break;
		}
	}
	free(dest);

	fputs(trailing_delim, stdout);

	return rc;
}

/* Return an allocated format string in static storage that
 * corresponds to whether FS and TERSE options were declared.
 */
static char *default_format(bool fs, bool terse, bool device)
{
	char *format;

	if (fs) {
		if (terse) {
			format = xstrdup(fmt_terse_fs);
		} else {
			/* TRANSLATORS: This string uses format specifiers from
			 * 'stat --help' with --file-system, and NOT from
			 * printf.
			 */
			format = xstrdup(
			"  File: \"%n\"\n"
			"    ID: %-8i Namelen: %-7l Type: %T\n"
			"Block size: %-10s Fundamental block size: %S\n"
			"Blocks: Total: %-10b Free: %-10f Available: %a\n"
			"Inodes: Total: %-10c Free: %d\n");
		}
	} else /* ! fs */ {
		if (terse) {
#ifdef HAVE_SELINUX
			if (is_selinux_enabled() > 0)
				format = xstrdup(fmt_terse_selinux);
			else
#endif
				format = xstrdup(fmt_terse_regular);
		} else {
			char *temp;

			/* TRANSLATORS: This string uses format specifiers from
			 * 'stat --help' without --file-system, and NOT from
			 * printf.
			 */
			format = xstrdup("\
  File: %N\n\
  Size: %-10s\tBlocks: %-10b IO Block: %-6o %F\n\
");

			temp = format;
			if (device) {
				/* TRANSLATORS: This string uses format
				 * specifiers from 'stat --help' without
				 * --file-system, and NOT from printf.
				 */
				format = xasprintf("%s%s", format, "\
" "Device: %Dh/%dd\tInode: %-10i  Links: %-5h Device type: %t,%T\n\
");
			} else {
				/* TRANSLATORS: This string uses format
				 * specifiers from 'stat --help' without
				 * --file-system, and NOT from printf.
				 */
				format = xasprintf("%s%s", format, "\
" "Device: %Dh/%dd\tInode: %-10i  Links: %h\n\
");
			}
			free(temp);

			temp = format;
			/* TRANSLATORS: This string uses format specifiers from
			 * 'stat --help' without --file-system, and NOT from
			 * printf.
			 */
			format = xasprintf("%s%s", format, "\
" "Access: (%04a/%10.10A)  Uid: (%5u/%8U)   Gid: (%5g/%8G)\n\
");
			free(temp);

#ifdef HAVE_SELINUX
			if (is_selinux_enabled() > 0) {
				temp = format;
				/* TRANSLATORS: This string uses format
				 * specifiers from 'stat --help' without
				 * --file-system, and NOT from printf.
				 */
				format = xasprintf("%s%s", format,
						   "Context: %C\n");
				free(temp);
			}
#endif
			temp = format;
			/* TRANSLATORS: This string uses format specifiers from
			 * 'stat --help' without --file-system, and NOT from
			 * printf.
			 */
			format = xasprintf("%s%s", format,
					   "Access: %x\n"
					   "Modify: %y\n"
					   "Change: %z\n"
					   " Birth: %w\n");
			free(temp);
		}
	}
	return format;
}

static char *list_long_format(void)
{
	char *format;

	format = xstrdup("\
" "%10.10A %h %8U %8G %-10s %y %N\
");

	return format;
}

static int do_statx(char const *filename, unsigned int request_mask, int flags)
{
	const char *pathname = filename;
	struct statx stx = { 0, };
	int fd;

	if (strcmp(filename, "-") == 0)
		fd = 0;
	else
		fd = AT_FDCWD;

	if (fd != AT_FDCWD) {
		pathname = "";
		flags |= AT_EMPTY_PATH;
	}

	fd = statx(fd, pathname, flags, request_mask, &stx);
	if (fd < 0) {
		if (flags & AT_EMPTY_PATH)
			printf("cannot stat standard input\n");
		else
			printf("cannot statx %s: %s\n",
			       filename, strerror(errno));

		return -errno;
	}

	return print_it(fd, filename, print_statx, &stx);
}

/* Return true if FILE should be ignored. */
static bool file_ignored(char const *name)
{
	return name[0] == '.';
}

static int do_dir_list(char const *dirname, unsigned int request_mask,
		       int flags)
{
	DIR *dir;
	struct dirent *ent;
	char fullname[PATH_MAX];
	int rc = 0;

	dir = opendir(dirname);
	if (!dir) {
		rc = -errno;
		printf("lsx: cannot open directory '%s': %s\n",
		       dirname, strerror(errno));
		return rc;
	}

	while ((ent = readdir(dir)) != NULL) {
		int ret;

		/* skip "." and ".." */
		if (file_ignored(ent->d_name))
			continue;

		/* ls -1 */
		if (!format) {
			if (o_quiet)
				continue;

			printf("%s", ent->d_name);
			putchar('\n');
		} else {
			if (strlen(ent->d_name) + strlen(dirname) + 1 >=
			    sizeof(fullname)) {
				errno = ENAMETOOLONG;
				fprintf(stderr,
					"lsx: ignored too long path: %s/%s\n",
					dirname, ent->d_name);
				if (!rc)
					rc = -ENAMETOOLONG;
				continue;
			}
			snprintf(fullname, PATH_MAX, "%s/%s",
				 dirname, ent->d_name);
			ret = do_statx(fullname, request_mask, flags);
			if (!ret)
				putchar('\n');
			else if (rc == 0)
				rc = ret;
		}
	}

	closedir(dir);
	return rc;
}

int main(int argc, char **argv)
{
	static struct option options[] = {
		{"dereference", no_argument, NULL, 'L'},
		{"format", required_argument, NULL, 'c'},
		{"printf", required_argument, NULL, PRINTF_OPTION},
		{"terse", no_argument, NULL, 't'},
		{"cached", required_argument, NULL, 0},
		{"dir", no_argument, NULL, 'D'},
		{"long-format", no_argument, NULL, 'l'},
		{"quiet", no_argument, NULL, 'q'},
		{"help", no_argument, NULL, GETOPT_HELP_CHAR},
		{"version", no_argument, NULL, GETOPT_VERSION_CHAR},
		{NULL, 0, NULL, 0}
	};
	bool terse = false;
	unsigned int request_mask;
	int flags = AT_SYMLINK_NOFOLLOW;
	struct lconv const *locale = localeconv();
	int c;
	int rc = 0;
	int i = 0;

	decimal_point = locale->decimal_point[0] ? locale->decimal_point : ".";
	decimal_point_len = strlen(decimal_point);
	current_time.tv_sec = TYPE_MINIMUM(time_t);
	current_time.tv_nsec = -1;

	while ((c = getopt_long(argc, argv, "c:DqLlt", options, NULL)) != EOF) {
		switch (c) {
		case 'L':
			flags &= ~AT_SYMLINK_NOFOLLOW;
			follow_links = true;
			break;
		case PRINTF_OPTION:
			format = optarg;
			interpret_backslash_escapes = true;
			trailing_delim = "";
			break;
		case 'c':
			format = optarg;
			interpret_backslash_escapes = false;
			trailing_delim = "\n";
			break;
		case 'q':
			o_quiet = true;
			break;
		case 'l':
			o_dir_list = true;
			long_format = true;
			break;
		case 'D':
			o_dir_list = true;
			break;
		case 't':
			terse = true;
			break;
		case 0:
			if (strcmp(optarg, "never") == 0) {
				flags &= ~AT_STATX_SYNC_TYPE;
				flags |= AT_STATX_FORCE_SYNC;
			} else if (strcmp(optarg, "always") == 0) {
				flags &= ~AT_STATX_SYNC_TYPE;
				flags |= AT_STATX_DONT_SYNC;
			} else if (strcmp(optarg, "default") == 0) {
				flags &= ~AT_STATX_SYNC_TYPE;
				flags |= AT_SYMLINK_NOFOLLOW;
			} else {
				printf("%s: invalid cached mode: %s\n",
				       argv[0], optarg);
				return -EINVAL;
			}
			break;
		case GETOPT_HELP_CHAR:
			usage(argv[0]);
		case GETOPT_VERSION_CHAR:
			if (!o_quiet)
				printf("Lustre statx: version 0.1\n");
			return 0;
		default:
			printf("%s: unknown option '-%c'\n",
			       argv[0], optopt);
			return -EINVAL;
		}
	}

	if (format) {
		request_mask = format_to_mask(format);
	} else {
		request_mask = STATX_ALL;
		if (o_dir_list)
			format = long_format ? list_long_format() : NULL;
		else
			format = default_format(false, terse, false);
	}

	if (optind == argc) {
		if (o_dir_list)
			return do_dir_list(".", request_mask, flags);

		printf("statx: missing operand\n"
		       "Try 'stat --help' for more information.\n");
		return 0;
	}

	for (i = optind; i < argc; i++) {
		int ret;

		if (o_dir_list)
			ret = do_dir_list(argv[i], request_mask, flags);
		else
			ret = do_statx(argv[i], request_mask, flags);

		if (rc == 0 && ret)
			rc = ret;
	}

	return rc;
}
#else
int main(int argc, char **argv)
{
	static struct option options[] = {
		{"version", no_argument, NULL, GETOPT_VERSION_CHAR},
		{"quiet", no_argument, NULL, 'q'},
		{NULL, 0, NULL, 0}
	};
	int c;

	while ((c = getopt_long(argc, argv, "q", options, NULL)) != EOF) {
		switch (c) {
		case 'q':
			o_quiet = true;
			break;
		case GETOPT_VERSION_CHAR:
			if (!o_quiet)
				printf("statx: Not support statx() syscall\n");
			return -ENOTSUP;
		}
	}
	printf("Skip: system does not support statx syscall.\n");
	return 0;
}
#endif /* __NR_statx */
