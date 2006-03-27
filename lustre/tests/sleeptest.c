#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFSIZE (4096)

#define min(a,b) ((a) < (b) ? (a) : (b))

int main(int argc, char *argv[])
{

	FILE *w_str;
	int read_fd;
	int rc, iter;
	int line, delta, next;
	int sleeptime = 0;
	char *now_time;
	const char ok_chars[] = "MonTueWedThuFriSatSun"
				"JanFebMarAprMayJunJulAugSepOctNovDec"
				"Line 0123456789 of file, written at:\n";

	char buf_r[BUFSIZE];

	char pathname[256] = "/mnt/lustre/linetest_";
	char *host;

	if (argc > 1) {
		strncpy(pathname, argv[1], 255);
		pathname[255] = '\0';
	}

	host = getenv("HOSTNAME");
	if (host)
		strcat(pathname, host);

	if (argc > 2)
		sleeptime = strtoul(argv[2], NULL, 0);

	if (sleeptime == 0)
		sleeptime = 30;

	printf("Test file used is: %s at %ds intervals\n", pathname, sleeptime);

	w_str = fopen(pathname, "wb");
	if (w_str == NULL) {
		perror("fopen");
		exit(1);
	}
	read_fd = open(pathname, O_RDONLY);
	if (read_fd < 0) {
		perror("open");
		exit(1);
	}

	next = 1;
	delta = 17;
	iter = 1;
	while (1) {
		time_t now;
		struct tm *t;
		long offset;

		now = time((time_t *)NULL);
		t = localtime(&now);
		now_time = asctime(t);

		printf("iter: %d\n", iter);

		for (line=next; line<(next+delta); line++) {
			rc = fprintf(w_str, "Line %8d of file, written at: %s",
				     line, now_time);
			/* \n comes from ctime() result */
			if (rc <= 0) {
				perror("fprintf");
				exit(4);
			}
			rc = fflush(w_str);
			if (rc != 0) {
				perror("fflush");
				exit(5);
			}
		}
		next += delta;

		/* Check for corruption */
		offset = ftell(w_str);
		rc = lseek(read_fd, offset & ~4095, SEEK_SET);
		if (rc != (offset & ~4095)) {
			perror("lseek");
			exit(7);
		}

		rc = read(read_fd, buf_r, min(100, offset & 4095));
		if (rc != min(100, offset & 4095)) {
			printf("rc: %d, off %lu buf: '%s'\n", rc,offset,buf_r);
			exit(8);
		}
		buf_r[rc] = 0;
		/* Chars from "C" days/months, and above Line */
		if (strspn(buf_r, ok_chars) != rc) {
			printf("Corruption detected at %lu on %s",
			       offset & ~4095, now_time);
			exit(9);
		}

		sleep(sleeptime);
		iter++;
	}

}
