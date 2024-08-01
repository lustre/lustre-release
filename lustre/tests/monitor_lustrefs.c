#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/fanotify.h>


void usage(const char *progname)
{
	const char *base, *msg;

	base = strrchr(progname, '/');
	if (base == NULL)
		base = progname;
	else
		base++;

	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s LUSTRE_MOUNT_DIR\n", base);
	fprintf(stderr, "\n");

	msg =
"Description:\n"
"  Monitor some file operations on a lustre fs. Report the events as below:\n"
"    <events>:<lustre_file>:<pid>:[<command>]\n"
"\n"
"  <events>      is 1 event or multiple events separated by '&'. For example,\n"
"                'open', 'write&close'. Currently only these events are\n"
"                monitored:\n"
"                  - open\n"
"                  - close\n"
"                  - read\n"
"                  - write\n"
"  <lustre_file> is the file to be operated.\n"
"  <pid>         is the process id who operates the file.\n"
"  <command>     is the command who operates the file. It is reported only if\n"
"                the process is still running so it can be found from pid.\n"
"\n";
	fprintf(stderr, "%s", msg);
}

void print_event(struct fanotify_event_metadata *metadata)
{
	bool first = true;
	char procfd_path[PATH_MAX], path[PATH_MAX], cmd_file[PATH_MAX];
	int path_len, cmd_fd, cmd_len;

	// print event type
	if (metadata->mask & FAN_OPEN) {
		printf("open");
		first = false;
	}
	if (metadata->mask & FAN_ACCESS) {
		if (!first)
			printf("&");
		printf("read");
		first = false;
	}
	if (metadata->mask & FAN_MODIFY) {
		if (!first)
			printf("&");
		printf("write");
		first = false;
	}
	if (metadata->mask & FAN_CLOSE) {
		if (!first)
			printf("&");
		printf("close");
		first = false;
	}
	printf(":");

	// print the name of the file
	snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d",
		 metadata->fd);
	path_len = readlink(procfd_path, path, sizeof(path) - 1);
	if (path_len == -1) {
		fprintf(stderr, "failed to read link target of %s. %d:%s\n",
			procfd_path, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
	path[path_len] = '\0';
	printf("%s:", path);
	close(metadata->fd);

	// print the pid
	printf("%d:", metadata->pid);

	// try to print the cmdline of process
	snprintf(cmd_file, sizeof(cmd_file), "/proc/%d/cmdline", metadata->pid);
	cmd_fd = open(cmd_file, O_RDONLY);
	if (cmd_fd >= 0) {
		// reuse cmd_file as buffer
		cmd_len = read(cmd_fd, cmd_file, sizeof(cmd_file) - 1);
		if (cmd_len > 0) {
			cmd_file[cmd_len] = '\0';
			printf("%s", cmd_file);
		}
		close(cmd_fd);
	}
	printf("\n");
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	int fd, rc;
	uint32_t mask;
	struct fanotify_event_metadata buf[256], *metadata;
	int len;

	if (argc != 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		fprintf(stderr, "failed to init fanotify. %d:%s\n", errno,
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	mask = FAN_OPEN | FAN_ACCESS | FAN_MODIFY | FAN_CLOSE;
	rc = fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, mask, AT_FDCWD,
			   argv[1]);
	if (rc < 0) {
		fprintf(stderr,
			"failed to open watch descriptor on %s. %d:%s\n",
			argv[1], errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	while (1) {
		len = read(fd, (void *)&buf[0], sizeof(buf));
		if (len < 0 && errno != EAGAIN) {
			fprintf(stderr,
				"failed to read from fanotify file descriptor."
				" %d:%s",
				errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (len < 0)
			break;

		metadata = &buf[0];
		while (FAN_EVENT_OK(metadata, len)) {
			/* Check run-time and compile-time structures match */
			if (metadata->vers != FANOTIFY_METADATA_VERSION) {
				fprintf(stderr, "Mismatch of fanotify "
					"metadata version.\n");
				exit(EXIT_FAILURE);
			}

			if (metadata->fd >= 0) {
				print_event(metadata);
				close(metadata->fd);
			}
			metadata = FAN_EVENT_NEXT(metadata, len);
		}
	}

	close(fd);
	return EXIT_SUCCESS;
}
