/*
  File: backup-files.c

  Copyright (C) 2003 Andreas Gruenbacher <agruen@suse.de>
  SuSE Labs, SuSE Linux AG

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Library General Public
  License as published by the Free Software Foundation; either
  version 2 of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Library General Public License for more details.

  You should have received a copy of the GNU Library General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/*
 * Create backup files of a list of files similar to GNU patch. A path
 * name prefix and suffix for the backup file can be specified with the
 * -B and -Z options.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

const char *progname;

enum { what_backup, what_restore, what_remove };

const char *opt_prefix="", *opt_suffix="", *opt_file=NULL;
int opt_silent=0, opt_what=what_backup;

#define LINE_LENGTH 1024


void
usage(void)
{
	printf("Usage: %s [-B prefix] [-z suffix] [-f {filelist|-}] [-s] [-r|-x] filename ...\n"
	       "\n"
	       "\tCreate hard linked backup copies of a list of files\n"
	       "\tread from standard input.\n"
	       "\n"
	       "\t-r\tRestore the backup\n"
	       "\t-x\tRemove backup files and empty parent directories\n"
	       "\t-B\tPath name prefix for backup files\n"
	       "\t-z\tPath name suffix for backup files\n"
	       "\t-s\tSilent operation; only print error messages\n\n",
	       progname);
}

void
create_parents(char *filename)
{
	struct stat st;
	char *f = strchr(filename, '/');

	if (f == NULL)
		return;
	*f = '\0';
	if (stat(f, &st) != 0) {
		while (f != NULL) {
			*f = '\0';
			mkdir(filename, 0777);
			*f = '/';
			f = strchr(f+1, '/');
		}
	} else {
		*f = '/';
	}
}

void
remove_parents(char *filename)
{
	char *f, *g = NULL;

	f = strrchr(filename, '/');
	while ((f = strrchr(filename, '/')) != NULL) {
		if (g != NULL)
			*g = '/';
		g = f;
		*f= '\0';
		
		rmdir(filename);
	}
	if (g != NULL)
		*g = '/';
}

static int
link_or_copy(const char *from, const char *to)
{
	char buffer[4096];
	int from_fd, to_fd, error = 1;
	size_t len;

	if (link(from, to) == 0)
		return 0;
	if (errno != EXDEV && errno != EPERM && errno != EMLINK) {
		fprintf(stderr, "Could not link file `%s' to `%s': %s\n",
		       from, to, strerror(errno));
		return 1;
	}

	if ((from_fd = open(from, O_RDONLY)) == -1) {
		perror(from);
		return 1;
	}
	if ((to_fd = open(to, O_WRONLY|O_TRUNC))) {
		perror(to);
		close(from_fd);
		return 1;
	}
	while ((len = read(from_fd, buffer, sizeof(buffer))) > 0) {
		if ((write(to_fd, buffer, len)) == -1) {
			perror(to);
			unlink(to);
			goto out;
		}
	}
	if (len != 0) {
		perror(from);
		unlink(to);
		goto out;
	}

	error = 0;
out:
	close(from_fd);
	close(to_fd);

	return error;
}

int
process_file(char *file)
{
	char backup[LINE_LENGTH];

	if (strlen(opt_prefix) + strlen(file) +
	    strlen(opt_suffix) >= sizeof(backup)) {
		perror("Line buffer too small\n");
		return 1;
	}

	snprintf(backup, sizeof(backup), "%s%s%s",
		 opt_prefix, file, opt_suffix);

	if (opt_what == what_backup) {
		struct stat st;
		int new_file = (stat(file, &st) == -1 && errno == ENOENT);

		unlink(backup);
		create_parents(backup);
		if (new_file) {
			int fd;

			if (!opt_silent)
				printf("New file %s\n", file);
			if ((fd = creat(backup, 0666)) == -1) {
				perror(backup);
				return 1;
			}
			close(fd);
		} else {
			if (!opt_silent)
				printf("Copying %s\n", file);
			if (link_or_copy(file, backup) != 0)
				return 1;
		}
		return 0;
	} else if (opt_what == what_restore) {
		struct stat st;

		create_parents(file);
		if (stat(backup, &st) != 0) {
			perror(backup);
			return 1;
		}
		if (st.st_size == 0) {
			if (unlink(file) == 0 || errno == ENOENT) {
				if (!opt_silent)
					printf("Removing %s\n", file);
				unlink(backup);
				remove_parents(backup);
			} else {
				perror(file);
				return 1;
			}
		} else {
			if (!opt_silent)
				printf("Restoring %s\n", file);
			unlink(file);
			if (link(backup, file) == -1) {
				if (link_or_copy(backup, file) != 0)
					return 1;
				unlink(backup);
				remove_parents(backup);
			}
		}
		return 0;
	} else if (opt_what == what_remove) {
		unlink(backup);
		remove_parents(backup);
		return 0;
	} else
		return 1;
}

int
main(int argc, char *argv[])
{
	int opt, status=0;
	
	progname = argv[0];

	while ((opt = getopt(argc, argv, "rxB:z:f:sh")) != -1) {
		switch(opt) {
			case 'r':
				opt_what = what_restore;
				break;

			case 'x':
				opt_what = what_remove;
				break;

			case 'B':
				opt_prefix = optarg;
				break;
				
			case 'f':
				opt_file = optarg;
				break;

			case 'z':
				opt_suffix = optarg;
				break;

			case 's':
				opt_silent = 1;
				break;

			case 'h':
			default:
				usage();
				return 0;
		}
	}

	if ((*opt_prefix == '\0' && *opt_suffix == '\0') ||
	    (opt_file == NULL && optind == argc)) {
		usage();
		return 1;
	}

	if (opt_file != NULL) {
		FILE *file;
		char line[LINE_LENGTH];

		if (!strcmp(opt_file, "-")) {
			file = stdin;
		} else {
			if ((file = fopen(opt_file, "r")) == NULL) {
				perror(opt_file);
				return 1;
			}
		}

		while (fgets(line, sizeof(line), file)) {
			char *l = strchr(line, '\0');

			if (l > line && *(l-1) == '\n')
				*(l-1) = '\0';
			if (*line == '\0')
				continue;
				
			if ((status = process_file(line)) != 0)
				return status;
		}

		if (file != stdin) {
			fclose(file);
		}
	}
	for (; optind < argc; optind++) {
		if ((status = process_file(argv[optind])) != 0)
			return status;
	}

	return status;
}
