#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>

double
timenow ()
{
   struct timeval tv;
   
   gettimeofday (&tv, NULL);
   return (tv.tv_sec + tv.tv_usec / 1000000.0);
}

typedef struct {
        unsigned long        msgs_alloc;
        unsigned long        msgs_max;
        unsigned long        errors;
        unsigned long        send_count;
        unsigned long        recv_count;
        unsigned long        route_count;
        unsigned long        drop_count;
        unsigned long long   send_length;
        unsigned long long   recv_length;
        unsigned long long   route_length;
        unsigned long long   drop_length;
} counters_t;

unsigned long long subull(unsigned long long a, unsigned long long b)
{
	if (a < b)
		return -1ULL - b + a + 1;
	
	return a - b;
}

unsigned long long subul(unsigned long a, unsigned long b)
{
	if (a < b)
		return -1UL - b + a + 1;
	
	return a - b;
}

double rul(unsigned long a, double secs)
{
	return (double)a/secs;
}

double rull(unsigned long long a, double secs)
{
	return (double)a/secs;
}

void
do_stat (int fd)
{
   static char  buffer[1024];
   static double last = 0.0;
   static counters_t old_counter;
   double now;
   double t;
   counters_t new_counter;
   counters_t counter;
   int    n;
   
   lseek (fd, 0, SEEK_SET);
   now = timenow();
   n = read (fd, buffer, sizeof (buffer));
   if (n < 0)
   {
      fprintf (stderr, "Can't read statfile\n");
      exit (1);
   }	 
   buffer[n] = 0;
   
   n = sscanf (buffer, "%u %u %u %u %u %u %u %Lu %Lu %Lu %Lu",
	       &new_counter.msgs_alloc, &new_counter.msgs_max,
	       &new_counter.errors, 
	       &new_counter.send_count, &new_counter.recv_count,
	       &new_counter.route_count, &new_counter.drop_count,
	       &new_counter.send_length, &new_counter.recv_length,
	       &new_counter.route_length, &new_counter.drop_length);
   if (n < 11)
   {
      fprintf (stderr, "Can't parse statfile\n");
      exit (1);
   }
   
   if (last == 0.0) {
	   printf ("M %lu(%lu) E %lu S %lu/%llu R %lu/%llu F %lu/%llu D %lu/%llu\n", 
		   new_counter.msgs_alloc, new_counter.msgs_max,
		   new_counter.errors, 
		   new_counter.send_count, new_counter.send_length,
		   new_counter.recv_count, new_counter.recv_length,
		   new_counter.route_count, new_counter.route_length, 
		   new_counter.drop_count, new_counter.drop_length);
   } else {
	   t = now - last;

	   counter.msgs_alloc = new_counter.msgs_alloc;
	   counter.msgs_max = new_counter.msgs_max;
	   
	   counter.errors = subul(new_counter.errors, old_counter.errors);
	   counter.send_count = subul(new_counter.send_count, old_counter.send_count);
	   counter.recv_count = subul(new_counter.recv_count, old_counter.recv_count);
	   counter.route_count = subul(new_counter.route_count, old_counter.route_count);
	   counter.drop_count = subul(new_counter.drop_count, old_counter.drop_count);
	   counter.send_length = subull(new_counter.send_length, old_counter.send_length);
	   counter.recv_length = subull(new_counter.recv_length, old_counter.recv_length);
	   counter.route_length = subull(new_counter.route_length, old_counter.route_length);
	   counter.drop_length = subull(new_counter.drop_length, old_counter.drop_length);

	   printf ("M %3lu(%3lu) E %0.0f S %7.2f/%6.0f R %7.2f/%6.0f F %7.2f/%6.0f D %4.2f/%0.0f\n",
		   counter.msgs_alloc, counter.msgs_max,
		   rul(counter.errors,t),
		   rull(counter.send_length,t*1024.0*1024.0), rul(counter.send_count, t),
		   rull(counter.recv_length,t*1024.0*1024.0), rul(counter.recv_count, t),
		   rull(counter.route_length,t*1024.0*1024.0), rul(counter.route_count, t),
		   rull(counter.drop_length,t*1024.0*1024.0), rul(counter.drop_count, t));
   }

   old_counter = new_counter;
   fflush (stdout);
   
   lseek (fd, 0, SEEK_SET);
   last = timenow();
}

int main (int argc, char **argv)
{
   int  interval = 0;
   int  fd;
   
   if (argc > 1)
      interval = atoi (argv[1]);

   fd = open ("/proc/sys/lnet/stats", O_RDONLY);
   if (fd < 0)
   {
      fprintf (stderr, "Can't open stat: %s\n", strerror (errno));
      return (1);
   }
   
   do_stat (fd);
   if (interval == 0)
      return (0);
   
   for (;;)
   {
      sleep (interval);
      do_stat (fd);
   }
}
