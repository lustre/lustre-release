#define PATH_LENGTH 35
#include <math.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

int count = 1000;

struct names {
	char from[PATH_LENGTH];
	char to[PATH_LENGTH];
} *names;

int loops = 0;
int stop = 0;
long start;

int creat_errors = 0;
int rename_errors = 0;
int unlink_errors = 0;

void handler(int sig) {
	static long last_time;
	long now = time(0);

	signal(SIGINT, handler);
	signal(SIGALRM, handler);
	printf("%6ld sec %14d iterations errors %d/%d/%d - "
	       "Use SIGQUIT (^\\) to kill\n", now - start, loops,
	       creat_errors, rename_errors, unlink_errors);

	if (sig == SIGQUIT)
		stop = 1;
	else if (sig == SIGALRM)
		alarm(60);
	else if (sig == SIGINT) {
		if (last_time - now < 2)
			stop = 1;
		last_time = now;
	}
}

int main(int argc, char *argv[])
{
	int i;
	unsigned long n;
	int h1, h2;

	names = malloc(sizeof(struct names) * count);
	if (names == NULL) {
		perror("calloc");
		return(1);
	}

	h2 = sprintf(names[0].from, "%x", count); /* just to figure length */
	h1 = (PATH_LENGTH-h2-2)/4;

	n = 1 << h1 * 4;

	printf("h1 = %d, h2 = %d n = %lu\n", h1, h2, n);

	start = time(0);
	srand(start);

	signal(SIGQUIT, handler);
	signal(SIGINT, handler);
	signal(SIGALRM, handler);
	alarm(60);

	while (!stop) {
		int j,k,l,m;

		if (mkdir("tmp", S_IRWXU) == -1) {
			perror("mkdir");
			return(1);
		}
		if (chdir("tmp") == -1) {
			perror("chdir");
			return(1);
		}

		for (i = 0; i < count ; i++) {
			j = random() & (n - 1);
			k = random() & (n - 1);
			l = random() & (n - 1);
			m = random() & (n - 1);
			sprintf(names[i].from, "%0*x%0*x%0*x%0*x0%0*x",
				h1, j, h1, k, h1, l, h1, m, h2, i);
			sprintf(names[i].to, "%0*x%0*x%0*x%0*x1%0*x",
				h1, j, h1, k, h1, l, h1, m, h2, i);

		}

		for (i = 0; i < count; i++) {
			int fd;
			if ((fd = creat(names[i].from, S_IRUSR|S_IWUSR)) == -1){
				char msg[100];
				sprintf(msg, "creat %s", names[i].from);
				perror(msg);
				creat_errors++;
			}
			if (close(fd) == -1) {
				perror("close");
				return(1);
			}
		}

		for (i = 0; i < count; i++) {
			if (rename(names[i].from, names[i].to) == -1) {
				char msg[100];
				sprintf(msg, "rename %s to %s",
					names[i].from, names[i].to);
				perror(msg);
				rename_errors++;
			}
		}

		for (i = 0; i < count; i++) {
			if (unlink(names[i].to) == -1) {
				char msg[100];
				sprintf(msg, "unlink %s", names[i].to);
				perror(msg);
				unlink_errors++;
			}
		}

		if (chdir("..") == -1) {
			perror("chdir");
			return(1);
		}

		if (rmdir("tmp") == -1) {
			if (chdir("tmp") == -1) {
				perror("chdir");
				return(1);
			}
			for (i = 0; i < count; i++) {
				if (unlink(names[i].from) != -1) {
					fprintf(stderr, "Unexpected file %s\n",
						names[i].to);
					unlink_errors++;
				}
			}
			if (chdir("..") == -1) {
				perror("chdir");
				return(1);
			}
			if (rmdir("tmp") == -1) {
				perror("rmdir");
				return(1);
			}
		}

		loops++;
	}

	return(0);
}
