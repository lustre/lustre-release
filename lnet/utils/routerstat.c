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
   double now;
   double t;
   long long bytes;
   long      packets;
   long      errors;
   long      depth;
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
   
   n = sscanf (buffer, "%Ld %ld %ld %ld", &bytes, &packets, &errors, &depth);
   
   if (n < 3)
   {
      fprintf (stderr, "Can't parse statfile\n");
      exit (1);
   }
   
   if (last == 0.0)
      printf ("%Ld bytes, %ld packets (sz %Ld) %ld errors", 
	      bytes, packets, (long long)((packets == 0) ? 0LL : bytes/packets), errors);
   else
   {
      t = now - last;

      printf ("%9Ld (%7.2fMb/s), %7ld packets (sz %5Ld, %5ld/s) %ld errors (%ld/s)", 
	      bytes, ((double)bytes)/((1<<20) * t),
	      packets, (long long)((packets == 0) ? 0LL : bytes/packets), (long)(packets/t),
	      errors, (long)(errors/t));
   }

   if (n == 4)
      printf (" (%ld)\n", depth);
   else
      printf ("\n");

   fflush (stdout);
   
   lseek (fd, 0, SEEK_SET);
   write (fd, "\n", 1);
   last = timenow();
}

int main (int argc, char **argv)
{
   int  interval = 0;
   int  fd;
   
   if (argc > 1)
      interval = atoi (argv[1]);

   fd = open ("/proc/sys/portals/router", O_RDWR);
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
