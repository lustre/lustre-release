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
#define LPU64 "%Ld"
#define LPX64 "%Lx"

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

int main(int argc, char **argv)
{
        int fd;
        char *buf;
        long pg_vec, count;
	long len;
	long long end, offset;
	long objid = 3;
        int rc;

        if (argc < 4 || argc > 5) {
                fprintf(stderr,
			"usage: %s file pages_per_vec count [objid]\n",
			argv[0]);
                return 1;
        }

        pg_vec = strtoul(argv[2], 0, 0);
        count = strtoul(argv[3], 0, 0);
	len = pg_vec * BLOCKSIZE;
	end = (long long)count * len;

	if (argc == 5)
		objid = strtoul(argv[4], 0, 0);

        printf("directio on %s(%ld) for %ldx%ld pages \n",
	       argv[1], objid, count, pg_vec);

        buf = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);
        if (!buf) {
                fprintf(stderr, "No memory %s\n", strerror(errno));
                return 2;
        }

        fd = open(argv[1], O_DIRECT | O_RDWR | O_CREAT);
        if (fd == -1) {
                fprintf(stderr, "Cannot open %s:  %s\n", argv[1],
			strerror(errno));
                return 3;
        }

	for (offset = 0; offset < end; offset += len) {
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
			fprintf(stderr, "Write error: %s, rc %d\n",
				strerror(errno), rc);
			return 4;
		}
	}

        if ( lseek(fd, 0, SEEK_SET) != 0 ) {
                fprintf(stderr, "Cannot seek %s\n", strerror(errno));
                return 5;
        }

	for (offset = 0; offset < end; offset += len) {
		int i;

		rc = read(fd, buf, len);
		if (rc != len) {
			fprintf(stderr, "Read error: %s, rc %d\n",
				strerror(errno), rc);
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
