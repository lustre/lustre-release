#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

void
usage (char *argv0, int help)
{
	char *progname = strrchr(argv0, '/');

	if (progname == NULL)
		progname = argv0;
	
	fprintf (help ? stdout : stderr,
		 "Usage: %s [-e] file\n", progname);
	
	if (!help)
	{
		fprintf (stderr, "   or try '-h' for help\n");
		exit (1);
	}
	
	printf ("Create the given file with O_EXCL...\n");
	printf (" -e    expect EEXIST\n");
	printf (" -h    print help");
	printf (" Exit status is 0 on success, 1 on failure\n");
}

int main(int argc, char **argv)
{
        int rc;
	int want_eexist = 0;
	
	while ((rc = getopt (argc, argv, "eh")) != -1)
		switch (rc)
		{
		case 'e':
			want_eexist = 1;
			break;
		case 'h':
			usage (argv[1], 1);
			return (0);
		default:
			usage (argv[0], 0);
		}
	
        if (optind != argc - 1) { 
		usage (argv[0], 0);
                return 1;
        }

        rc = open(argv[optind], O_CREAT|O_EXCL, 0644);
        if (rc == -1)
	{
		if (want_eexist && errno == EEXIST)
		{
			printf("open failed: %s (expected)\n", strerror(errno));
			return (0);
		}
		printf("open failed: %s\n", strerror(errno));
		return (1);
	} else {
		if (want_eexist)
		{
			printf("open success (expecting EEXIST).\n");
			return (1);
		}
		printf("open success.\n");
		return (0);
	}
	
	return ((rc == 0) ? 0 : 1);
}
