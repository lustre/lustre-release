#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

// not correctly in the headers yet!!
//#define O_DIRECT 0
#ifndef O_DIRECT
#define O_DIRECT	 040000	/* direct disk access hint */
#endif

#define CERROR(fmt, arg...) fprintf(stderr, fmt, ## arg)
#ifndef __u64
#define __u64 long long
#define cpu_to_le64(v) (v)
#define le64_to_cpu(v) (v)
#endif

#ifndef LPU64
#define LPU64 "%Lu"
#define LPX64 "%#Lx"
#endif

#define READ  1
#define WRITE 2

#define LPDS sizeof(__u64)
int page_debug_setup(void *addr, int len, __u64 off, __u64 id)
{
        off = cpu_to_le64(off);
        id = cpu_to_le64(id);
        memcpy(addr, (char *)&off, LPDS);
        memcpy(addr + LPDS, (char *)&id, LPDS);

        addr += len - LPDS - LPDS;
        memcpy(addr, (char *)&off, LPDS);
        memcpy(addr + LPDS, (char *)&id, LPDS);

        return 0;
}

int page_debug_check(char *who, void *addr, int size, __u64 off, __u64 id)
{
        __u64 ne_off;
        int err = 0;

        ne_off = le64_to_cpu(off);
        id = le64_to_cpu(id);
        if (memcmp(addr, (char *)&ne_off, LPDS)) {
                CERROR("%s: for offset "LPU64" off: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)addr, ne_off);
                err = -EINVAL;
        }
        if (memcmp(addr + LPDS, (char *)&id, LPDS)) {
                CERROR("%s: for offset "LPU64" id: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)(addr + LPDS), id);
                err = -EINVAL;
        }

        addr += size - LPDS - LPDS;
        if (memcmp(addr, (char *)&ne_off, LPDS)) {
                CERROR("%s: for offset "LPU64" end off: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)addr, ne_off);
                err = -EINVAL;
        }
        if (memcmp(addr + LPDS, (char *)&id, LPDS)) {
                CERROR("%s: for offset "LPU64" end id: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)(addr + LPDS), id);
                err = -EINVAL;
        }

        return err;
}
#undef LPDS

void usage(char *prog)
{
	fprintf(stderr,
		"usage: %s file count [[d]{r|w|rw} [pages_per_vec [objid]]]\n",
		prog);
	exit(1);
}

int main(int argc, char **argv)
{
        int fd;
        char *buf;
	long long count, last, offset;
	long pg_vec, len;
	long long objid = 3;
	struct stat st;
	int flags = 0;
	int cmd = 0;
	char *end;
        int rc;

        if (argc < 3 || argc > 6)
		usage(argv[0]);

        count = strtoull(argv[2], &end, 0);
	if (*end) {
		fprintf(stderr, "%s: invalid count '%s'\n", argv[0], argv[2]);
		usage(argv[0]);
	}
	if (argc >= 4) {
		if (strchr(argv[3], 'r')) {
			cmd = READ;
			flags = O_RDONLY;
		}
		if (strchr(argv[3], 'w')) {
			cmd |= WRITE;
			flags = O_RDWR | O_CREAT;
		}
		if (strchr(argv[3], 'd')) {
			flags |= O_DIRECT;
		}
		if (!cmd)
			usage(argv[0]);
	} else {
		cmd = READ | WRITE;
		flags = O_RDWR | O_CREAT | O_DIRECT;
	}

	if (argc >= 5) {
		pg_vec = strtoul(argv[4], &end, 0);
		if (*end) {
			fprintf(stderr, "%s: invalid pages_per_vec '%s'\n",
				argv[0], argv[4]);
			usage(argv[0]);
		}
	}

	if (argc >= 6) {
		objid = strtoull(argv[5], &end, 0);
		if (*end) {
			fprintf(stderr, "%s: invalid objid '%s'\n",
				argv[0], argv[5]);
			usage(argv[0]);
		}
	}

        printf("%s: %s on %s(objid "LPX64") for "LPU64"x%ld pages \n",
	       argv[0], flags & O_DIRECT ? "directio" : "i/o",
	       argv[1], objid, count, pg_vec);

        fd = open(argv[1], flags | O_LARGEFILE);
        if (fd == -1) {
                fprintf(stderr, "%s: cannot open %s:  %s\n", argv[0],
			argv[1], strerror(errno));
                return 3;
        }

	rc = fstat(fd, &st);
	if (rc < 0) {
		fprintf(stderr, "%s: cannot stat %s: %s\n", argv[0],
			argv[1], strerror(errno));
		return 4;
	}

	len = pg_vec * st.st_blksize;
	last = (long long)count * len;

        buf = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);
        if (!buf) {
                fprintf(stderr, "%s: no buffer memory %s\n",
			argv[0], strerror(errno));
                return 2;
        }

	for (offset = 0; offset < last && cmd & WRITE; offset += len) {
		int i;

		for (i = 0; i < len; i += st.st_blksize)
			page_debug_setup(buf + i, st.st_blksize, offset + i,
					 objid);

		rc = write(fd, buf, len);

		for (i = 0; i < len; i += st.st_blksize) {
			if (page_debug_check("write", buf + i, st.st_blksize,
					     offset + i, objid))
				return 10;
		}

		if (rc != len) {
			fprintf(stderr, "%s: write error: %s, rc %d != %ld\n",
				argv[0], strerror(errno), rc, len);
			return 4;
		}
	}

        if (lseek(fd, 0, SEEK_SET) != 0) {
                fprintf(stderr, "%s: cannot seek %s\n",
			argv[0], strerror(errno));
                return 5;
        }

	for (offset = 0; offset < last && cmd && READ; offset += len) {
		int i;

		rc = read(fd, buf, len);
		if (rc != len) {
			fprintf(stderr, "%s: read error: %s, rc %d != %ld\n",
				argv[0], strerror(errno), rc, len);
			return 6;
		}

		for (i = 0; i < len; i += st.st_blksize) {
			if (page_debug_check("read", buf + i, st.st_blksize,
					     offset + i, objid))
				return 11;
		}
	}

        return 0;
}
