#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>

// not correctly in the headers yet!!
//#define O_DIRECT 0
#ifndef O_DIRECT
#define O_DIRECT	 040000	/* direct disk access hint */
#endif

#define BLOCKSIZE 4096
#define CERROR(fmt, arg...) fprintf(stderr, fmt, ## arg)
#define __u64 long long
#define LASSERT(v) do {} while(0)
#define HTON__u64(v) (v)
#define LPU64 "%Lu"
#define LPX64 "%Lx"

#define READ  1
#define WRITE 2

#define LPDS sizeof(__u64)
int page_debug_setup(void *addr, int len, __u64 off, __u64 id)
{
        LASSERT(addr);

        off = HTON__u64(off);
        id = HTON__u64(id);
        memcpy(addr, (char *)&off, LPDS);
        memcpy(addr + LPDS, (char *)&id, LPDS);

        addr += len - LPDS - LPDS;
        memcpy(addr, (char *)&off, LPDS);
        memcpy(addr + LPDS, (char *)&id, LPDS);

        return 0;
}

int page_debug_check(char *who, void *addr, int end, __u64 off, __u64 id)
{
        __u64 ne_off;
        int err = 0;

        LASSERT(addr);

        ne_off = HTON__u64(off);
        id = HTON__u64(id);
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

        addr += end - LPDS - LPDS;
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
	fprintf(stderr, "usage: %s file count [[d]{r|w|rw} [pages_per_vec [objid]]]\n",
		prog);
	exit(1);
}

int main(int argc, char **argv)
{
        int fd;
        char *buf;
        long pg_vec, count;
	long len;
	long long end, offset;
	long long objid = 3;
	int flags = O_RDWR | O_CREAT;
	int cmd = 0;
        int rc;

        if (argc < 3 || argc > 6)
		usage(argv[0]);

        count = strtoul(argv[2], 0, 0);
	if (argc >= 4) {
		if (strchr(argv[3], 'r')) {
			cmd |= READ;
			printf("reading\n");
		}
		if (strchr(argv[3], 'w')) {
			cmd |= WRITE;
			printf("writing\n");
		}
		if (strchr(argv[3], 'd')) {
			flags |= O_DIRECT;
			printf("directing\n");
		}
	}
	if (!cmd)
		usage(argv[0]);
	printf("cmd = %x, flags = %x\n", cmd, flags);

	if (argc >= 5)
		pg_vec = strtoul(argv[4], 0, 0);
	len = pg_vec * BLOCKSIZE;
	end = (long long)count * len;

	if (argc >= 6) {
		objid = strtoull(argv[5], 0, 0);
		printf("objid %s = 0x%Lx\n", argv[5], objid);
	}

        printf("%s: %s on %s(objid 0x"LPX64") for %ldx%ld pages \n",
	       argv[0], flags & O_DIRECT ? "directio" : "i/o",
	       argv[1], objid, count, pg_vec);

        buf = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);
        if (!buf) {
                fprintf(stderr, "%s: no buffer memory %s\n",
			argv[0], strerror(errno));
                return 2;
        }

        fd = open(argv[1], flags);
        if (fd == -1) {
                fprintf(stderr, "%s: cannot open %s:  %s\n", argv[1],
			argv[0], strerror(errno));
                return 3;
        }

	for (offset = 0; offset < end && cmd & WRITE; offset += len) {
		int i;

		for (i = 0; i < len; i += BLOCKSIZE)
			page_debug_setup(buf + i, BLOCKSIZE, offset + i, objid);

		rc = write(fd, buf, len);

		for (i = 0; i < len; i += BLOCKSIZE) {
			if (page_debug_check("write", buf + i, BLOCKSIZE,
					     offset + i, objid))
				return 10;
		}

		if (rc != len) {
			fprintf(stderr, "%s: write error: %s, rc %d\n",
				argv[0], strerror(errno), rc);
			return 4;
		}
	}

        if (lseek(fd, 0, SEEK_SET) != 0) {
                fprintf(stderr, "%s: cannot seek %s\n",
			argv[0], strerror(errno));
                return 5;
        }

	for (offset = 0; offset < end && cmd && READ; offset += len) {
		int i;

		rc = read(fd, buf, len);
		if (rc != len) {
			fprintf(stderr, "%s: read error: %s, rc %d\n",
				argv[0], strerror(errno), rc);
			return 6;
		}

		for (i = 0; i < len; i += BLOCKSIZE) {
			if (page_debug_check("read", buf + i, BLOCKSIZE,
					     offset + i, objid))
				return 11;
		}
	}

        return 0;
}
