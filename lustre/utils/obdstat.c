#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

struct one_stat {
	char       *name;
        int         fd;
	long long   current;
	long long   delta;
};

struct one_stat *read_bytes;
struct one_stat *read_reqs;
struct one_stat *write_bytes;
struct one_stat *write_reqs;
struct one_stat *getattr_reqs;
struct one_stat *setattr_reqs;
struct one_stat *create_reqs;
struct one_stat *destroy_reqs;
struct one_stat *statfs_reqs;
struct one_stat *open_reqs;
struct one_stat *close_reqs;
struct one_stat *punch_reqs;

struct one_stat *
init_one_stat (char *basename, char *name) 
{
	char             fname[1024];
	struct one_stat *stat = (struct one_stat *)malloc (sizeof (*stat));
	
	if (stat == NULL) {
		fprintf (stderr, "Can't allocate stat %s: %s\n", 
			 name, strerror (errno));
		abort ();
	}

	snprintf (fname, sizeof (fname), "%s/%s", basename, name);

	memset (stat, 0, sizeof (*stat));
	stat->name = name;

	stat->fd = open (fname, O_RDONLY);
	if (stat->fd < 0 ) {
		fprintf (stderr, "Can't open stat %s: %s\n", 
			 fname, strerror (errno));
		abort ();
	}

	return (stat);
}

void
update_one_stat (struct one_stat *stat) 
{
        static char buffer[1024];
	long long prev = stat->current;
	int  nob;

	lseek (stat->fd, 0, SEEK_SET);
	nob = read (stat->fd, buffer, sizeof (buffer) - 1);
	if (nob < 0) {
		fprintf (stderr, "Can't read stat %s: %s\n",
			 stat->name, strerror (errno));
		abort ();
	}
	
	buffer[nob] = 0;
	if (sscanf (buffer, "%Ld", &stat->current) != 1) {
		fprintf (stderr, "Can't parse stat %s: %s\n",
			 stat->name, strerror (errno));
		abort ();
	}

	stat->delta = stat->current - prev;
}

double
timenow ()
{
	struct timeval tv;
   
	gettimeofday (&tv, NULL);
	return (tv.tv_sec + tv.tv_usec / 1000000.0);
}

void
do_stat (void)
{
	static double last = 0.0;
	double now;
	double t;
   
	now = timenow();

	update_one_stat (read_bytes);
	update_one_stat (read_reqs);
	update_one_stat (write_bytes);
	update_one_stat (write_reqs);
	update_one_stat (getattr_reqs);
	update_one_stat (setattr_reqs);
	update_one_stat (open_reqs);
	update_one_stat (close_reqs);
	update_one_stat (create_reqs);
	update_one_stat (destroy_reqs);
	update_one_stat (statfs_reqs);
	update_one_stat (punch_reqs);
	
	if (last == 0.0) {
		printf ("R %Ld/%Ld W %Ld/%Ld attr %Ld/%Ld open %Ld/%Ld create %Ld/%Ld stat %Ld punch %Ld\n",
			read_bytes->current, read_reqs->current,
			write_bytes->current, write_reqs->current,
			getattr_reqs->current, setattr_reqs->current,
			open_reqs->current, close_reqs->current,
			create_reqs->current, destroy_reqs->current,
			statfs_reqs->current, punch_reqs->current);
	} else {
		t = now - last;

		printf ("R %6Ld (%5d %6.2fMb)/s W %6Ld (%5d %6.2fMb)/s",
			read_reqs->delta, (int)(read_reqs->delta / t),
			read_bytes->delta / ((1<<20) * t),
			write_reqs->delta, (int)(write_reqs->delta / t),
			write_bytes->delta / ((1<<20) * t));
		
		if (getattr_reqs->delta != 0)
			printf (" ga:%Ld,%d/s", getattr_reqs->delta,
				(int)(getattr_reqs->delta / t));
		
		if (setattr_reqs->delta != 0)
			printf (" sa:%Ld", setattr_reqs->delta);

		if (open_reqs->delta != 0)
			printf (" op:%Ld", open_reqs->delta);
		
		if (close_reqs->delta != 0)
			printf (" cl:%Ld", close_reqs->delta);

		if (create_reqs->delta != 0)
			printf (" cx:%Ld", create_reqs->delta);
		
		if (destroy_reqs->delta != 0)
			printf (" dx:%Ld", destroy_reqs->delta);

		if (statfs_reqs->delta != 0)
			printf (" st:%Ld", statfs_reqs->delta);
		
		if (punch_reqs->delta != 0)
			printf (" pu:%Ld", punch_reqs->delta);
		
		printf ("\n");
	}

	last = timenow();
}

int main (int argc, char **argv)
{
        char basedir[128];
	int  interval = 0;

	if (argc < 2) {
	   fprintf (stderr, "obd type not specified\n");
	   return (1);
	}
	
	snprintf (basedir, sizeof (basedir), "/proc/sys/%s", argv[1]);
   
	if (argc > 2)
		interval = atoi (argv[2]);

	read_bytes = init_one_stat (basedir, "read_bytes");
	read_reqs = init_one_stat (basedir, "read_reqs");
	write_bytes = init_one_stat (basedir, "write_bytes");
	write_reqs = init_one_stat (basedir, "write_reqs");
	getattr_reqs = init_one_stat (basedir, "getattr_reqs");
	setattr_reqs = init_one_stat (basedir, "setattr_reqs");
	create_reqs = init_one_stat (basedir, "create_reqs");
	destroy_reqs = init_one_stat (basedir, "destroy_reqs");
	statfs_reqs = init_one_stat (basedir, "statfs_reqs");
	open_reqs = init_one_stat (basedir, "open_reqs");
	close_reqs = init_one_stat (basedir, "close_reqs");
	punch_reqs = init_one_stat (basedir, "punch_reqs");

	do_stat ();

	if (interval == 0)
		return (0);
   
	for (;;) {
		sleep (interval);
		do_stat ();
	}
}
