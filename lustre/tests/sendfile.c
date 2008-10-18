
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <liblustre.h>
#include <lnet/lnetctl.h>
#include <obd.h>
#include <lustre_lib.h>
#include <obd_lov.h>
#include <lustre/liblustreapi.h>

#define syserr(str) { perror(str); exit(-1); }

int main(int argc, char *argv[])
{
	char *sfile, *tfile;
	struct stat stbuf;
	int size;
	int infd, outfd;
	int sd[2];
	int rc;
	char *buf;
	char cmd[1024];
	int page_size = sysconf(_SC_PAGESIZE);
	loff_t pos;

	if (argc < 3) {
		fprintf(stderr, "%s <source file> <dest file>\n", argv[0]);
		exit(-1);
	}

	sfile = argv[1];
	tfile = argv[2];

	if (stat(sfile, &stbuf) < 0) {
		if (errno == ENOENT) {
			/* assume doing non-object file testing */
			infd = open(sfile, O_LOV_DELAY_CREATE|O_CREAT|O_RDWR,
				    0644);
			if (infd < 0)
				syserr("open source file:");

			size = random() % (1 * 1024 * 1024) + 1024;
			if (ftruncate(infd, (off_t)size) < 0)
				syserr("truncate file error:");
		} else {
			syserr("stat file: ");
		}
	} else if (S_ISREG(stbuf.st_mode)) {
		size = (int)stbuf.st_size;
		infd = open(sfile, O_RDONLY, 0644);
		if (infd < 0)
			syserr("Open an existing file error:");
	} else {
		fprintf(stderr, "%s is not a regular file\n", sfile);
		exit(-1);
	}

	outfd = open(tfile, O_WRONLY|O_TRUNC|O_CREAT, 0666);
	if (outfd < 0)
		syserr("open dest file:");

	rc = socketpair(AF_LOCAL, SOCK_STREAM, 0, sd);
	if (rc < 0)
		syserr("socketpair");

	pos = 0;
	while (size > 0) {
		int rc2;
		size_t seg_size;

		seg_size = (size < page_size) ? size : (random() % size + 1);
		if (seg_size > 4 * page_size)
			seg_size = 4 * page_size;
		rc = sendfile(sd[0], infd, &pos, seg_size);
		if (rc < 0)
			syserr("sendfile:");

		size -= seg_size;
		if (size == 0)
			close(sd[0]);

		buf = malloc(seg_size);
		rc = read(sd[1], buf, seg_size);
		if (rc != seg_size)
			syserr("read from socket:");

		rc2 = write(outfd, buf, rc);
		if (rc2 != rc)
			syserr("write dest file error:");
		free(buf);
	}
	close(sd[1]), close(infd), close(outfd);

	sprintf(cmd, "cmp %s %s\n", sfile, tfile);
	return system(cmd);
}
