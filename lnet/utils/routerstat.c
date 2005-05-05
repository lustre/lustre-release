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

void
do_stat (int fd)
{
   static char  buffer[1024];
   static double last = 0.0;
   static unsigned long long old_bytes;
   static unsigned long      old_packets;
   static unsigned long      old_errors;
   double now;
   double t;
   unsigned long long new_bytes, bytes;
   unsigned long      new_packets, packets;
   unsigned long      new_errors, errors;
   unsigned long      depth;
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
   
   n = sscanf (buffer, "%Lu %lu %lu %lu",
	       &new_bytes, &new_packets, &new_errors, &depth);
   
   if (n < 3)
   {
      fprintf (stderr, "Can't parse statfile\n");
      exit (1);
   }
   
   if (last == 0.0)
      printf ("%llu bytes, %lu packets (sz %lld), %lu errors", 
	      new_bytes, new_packets,
	      (long long)((new_packets == 0) ? 0LL : new_bytes/new_packets),
	      new_errors);
   else
   {
      t = now - last;

      if (new_bytes < old_bytes)
	  bytes = -1ULL - old_bytes + new_bytes + 1;
      else
	  bytes = new_bytes - old_bytes;
      if (new_packets < old_packets)
	  packets = -1UL - old_packets + new_packets + 1;
      else
	  packets = new_packets - old_packets;
      if (new_errors < old_errors)
	  errors = -1UL - old_errors + new_errors + 1;
      else
	  errors = new_errors - old_errors;
      
      printf ("%9llu bytes (%7.2fMb/s), %7lu packets (sz %5lld, %5ld/s), %lu errors (%ld/s)", 
	      bytes, ((double)bytes)/((1<<20) * t),
	      packets, (long long)((packets == 0) ? 0LL : bytes/packets), (long)(packets/t),
	      errors, (long)(errors/t));
   }
   old_bytes = new_bytes;
   old_packets = new_packets;
   old_errors = new_errors;

   if (n == 4)
      printf (", depth (%ld)\n", depth);
   else
      printf ("\n");

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

   fd = open ("/proc/sys/portals/router", O_RDONLY);
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
