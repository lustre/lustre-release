#!/usr/bin/perl -w
use strict;
$|++;

$ENV{PATH}="/bin:/usr/bin";
$ENV{ENV}="";
$ENV{BASH_ENV}="";
use POSIX ":sys_wait_h";

use diagnostics;
use Getopt::Long;

use vars qw(
	    $MAX_THREADS
	    $SCRIPT_NAME
	    );

# Don't try to run more than this many threads concurrently.
$MAX_THREADS = 16;

$SCRIPT_NAME = "create.pl";

# Initialize variables
my $silent = 0;
my $use_mcreate = 1; # should we use mcreate or open?
my $num_files = 5;   # number of files to create
my $iterations = 1;
my $num_threads = 1;
my $mountpt;
my $num_mounts = -1;

# Get options from the command line.
GetOptions("silent!" => \$silent,
           "use_mcreate=i" => \$use_mcreate,
           "num_files=i" => \$num_files,
	   "mountpt=s" => \$mountpt,
	   "num_mounts=i" => \$num_mounts,
	   "iterations=i" => \$iterations,
	   "num_threads=i" => \$num_threads,
	   ) || die &usage;

# Check for mandatory args.
if (!$mountpt || 
    !$num_mounts) {
    die &usage;
}

if ($num_threads > $MAX_THREADS) {
    print "\nMAX_THREADS is currently set to $MAX_THREADS.\n\n";
    print "You will have to change this in the source\n";
    print "if you really want to run with $num_threads threads.\n\n";
    exit 1;
}

# Initialize rand() function.
srand (time ^ $$ ^ unpack "%L*", `ps axww | gzip`);

#########################################################################
### MAIN

for (my $i=1; $i<=$num_threads; $i++) {
    my $status = &fork_and_create($i);
    last if ($status != 0);
}

# Wait for all our threads to finish.
my $child = 0;
do {
    $child = waitpid(-1, WNOHANG);
} until $child > 0;
sleep 1;

exit 0;

#########################################################################
### SUBROUTINES

sub usage () {
    print "\nUsage: $0 [--silent] [--use_mcreate=n] [--num_files=n] [--iterations=n] [--num_threads=n] --mountpt=/path/to/lustre/mount --num_mounts=n\n\n";
    print "\t--silent\tminimal output\n";
    print "\t--use_mcreate=n\tuse mcreate to create files, default=1 (yes)\n";
    print "\t--num_files=n\tnumber of files to create per iteration, default=5\n";
    print "\t--iterations=n\tnumber of iterations to perform, default=1\n";
    print "\t--num_threads=n\tnumber of thread to run, default=1\n";
    print "\t--mountpt\tlocation of lustre mount\n";
    print "\t--num_mounts=n\tnumber of lustre mounts to test across, default=-1 (single mount point without numeric suffix)\n\n";
    print "example: $0 --mountpt=/mnt/lustre --num_mounts=2 --iterations=50\n";
	print "         will perform 50 iterations in /mnt/lustre1 and /mnt/lustre2\n";
    print "         $0 --mountpt=/mnt/lustre --num_mounts=-1 --iterations=50\n";
    print "         will perform 50 iterations in /mnt/lustre only\n\n";
    exit;
}

#########################################################################
sub fork_and_create ($) {
    my ($thread_num) = @_;
    
  FORK: {
      if (my $pid = fork) {
	  # parent here
	  # child process pid is available in $pid
	  return 0;
      } elsif (defined $pid) { # $pid is zero here if defined
	  my $current_iteration=1;
	  while ($current_iteration <= $iterations) {
	      for (my $i=1; $i<=$num_files; $i++) {
		  my $which = "";
		  if ($num_mounts > 0) {
		      $which = int(rand() * $num_mounts) + 1;
		  }
		  my $d = int(rand() * $num_files);
		  do_open("${mountpt}${which}/thread${thread_num}.${d}");
		  
		  if ($num_mounts > 0) {
		      $which = int(rand() * $num_mounts) + 1;
		  }
		  $d = int(rand() * $num_files);
		  my $path = "${mountpt}${which}/thread${thread_num}.${d}";
		  print  "$SCRIPT_NAME - Thread $thread_num: Unlink $path start [" . $$."]...\n" if !$silent;
		  if (unlink($path)) {
		      print "$SCRIPT_NAME - Thread $thread_num: Unlink done [$$] $path: Success\n" if !$silent;
		  } else {
		      print "$SCRIPT_NAME - Thread $thread_num: Unlink done [$$] $path: $!\n"if !$silent;
		  }
	      }
	      if (($current_iteration) % 100 == 0) {
		  print "$SCRIPT_NAME - Thread $thread_num: " . $current_iteration . " operations [" . $$ . "]\n";
	      }
	      $current_iteration++;
	  }
	  
	  my $which = "";
	  if ($num_mounts > 0) {
	      $which = int(rand() * $num_mounts) + 1;
	  }
	  for (my $d = 0; $d < $num_files; $d++) {
	      my $path = "${mountpt}${which}/thread${thread_num}.${d}";
	      unlink("$path") if (-e $path);
	  }
	  
	  print "$SCRIPT_NAME - Thread $thread_num: Done.\n";
	  
	  exit 0;

      } elsif ($! =~ /No more process/) {
          # EAGAIN, supposedly recoverable fork error
	  sleep 5;
	  redo FORK;
      } else {
          # weird fork error
	  die "Can't fork: $!\n";
      }
  }

}

#########################################################################

sub do_open ($) {
    my ($path) = @_;;

    if ($use_mcreate) {
        my $tmp = `./mcreate $path`;
        if ($tmp) {
            print  "$SCRIPT_NAME - Creating $path [" . $$."]...\n" if !$silent;
            $tmp =~ /.*error: (.*)\n/;
            print  "$SCRIPT_NAME - Create done [$$] $path: $!\n" if !$silent;
        } else {
            print  "$SCRIPT_NAME - Create done [$$] $path: Success\n"if !$silent;
        }
    } else {
        print  "$SCRIPT_NAME - Opening $path [" . $$."]...\n"if !$silent;
        open(FH, ">$path") || die "open($path: $!";
        print  "$SCRIPT_NAME - Open done [$$] $path: Success\n"if !$silent;
        close(FH) || die;
    }
}

