#!/usr/bin/perl -w
use strict;
$|++;

$ENV{PATH}="/bin:/usr/bin";
$ENV{ENV}="";
$ENV{BASH_ENV}="";

use diagnostics;
use Getopt::Long;
use POSIX ":sys_wait_h";

use vars qw(
            $MAX_THREADS
	    $SCRIPT_NAME
            );
 
# Don't try to run more than this many threads concurrently.
$MAX_THREADS = 16;

$SCRIPT_NAME = "rename.pl";

# Initialize variables
my $silent = 0;
my $create_files = 1; # should we create files or not?
my $use_mcreate = 1;  # should we use mcreate or open?
my $num_dirs = 3;     # number of directories to create
my $num_files = 6;    # number of files to create
my $iterations = 1;
my $num_threads = 1;
my $mountpt;
my $num_mounts = -1;

GetOptions("silent!"=> \$silent,
	   "use_mcreate=i" => \$use_mcreate,
           "create_files=i" => \$create_files,
	   "use_mcreate=i" => \$use_mcreate,
	   "num_files=i" => \$num_files,
	   "num_dirs=i" => \$num_dirs,
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

my $which = "";
if ($num_mounts > 0) {
    $which = int(rand() * $num_mounts) + 1;
}

# Create files and directories (if necessary)
if ($create_files) {
    for (my $i=1; $i<=$num_threads;$i++) {
	for (my $j=0; $j<$num_dirs;$j++) {
	    my $path = "${mountpt}${which}/${i}.${j}";
	    mkdir $path, 0755 || die "Can't mkdir $path: $!\n";
	    for (my $k=0; $k<$num_files; $k++) {
		my $filepath = "${path}/${k}";
		&create_file($filepath);
		if (! -e $filepath) {
		    die "Error creating $filepath\n";
		}
	    }
	}
    }
}

for (my $i=1; $i<=$num_threads; $i++) {
    my $status = &fork_and_rename($i);
    last if ($status != 0);
}

# Wait for all our threads to finish.
# Wait for all our threads to finish.
my $child = 0;
do {
    $child = waitpid(-1, 0);
} until $child > 0;
sleep 1;

# Unlink files and directories (if necessary)
if ($create_files) {
    for (my $i=1; $i<=$num_threads;$i++) {
	for (my $j=0; $j<$num_dirs;$j++) {
	    my $path = "${mountpt}${which}/${i}.${j}";
	    for (my $k=0; $k<=$num_files; $k++) {
		my $filepath = "${path}/${k}";
		unlink("$filepath") if (-e $filepath);
	    }
	    my $rc = rmdir $path;
	    print "$SCRIPT_NAME - rmdir $path failed: $!\n" if !$rc;	    
	}
    }
}

exit 0;

#########################################################################
### SUBROUTINES

sub usage () {
    print "\nUsage: $0 [--silent] [--create_files=n] [--use_mcreate=n] [--num_dirs=n] [--num_files=n] [--iterations=n] [--num_threads=n] --num_mounts=n --mountpt=/path/to/lustre/mount\n\n";
    print "\t--silent\tminimal output\n";
    print "\t--create_files=n\create files at start, default=1 (yes)\n";
    print "\t--use_mcreate=n\tuse mcreate to create files, default=1 (yes)\n";
    print "\t--num_dirs=n\tnumber of directories to create per iteration, default=3\n";
    print "\t--num_files=n\tnumber of files to create per directory, default=6\n";
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
sub create_file ($) {
    my ($path) = @_;;
    
    if (-e $path) {
	warn "$path already exists!\n";
	return 1;
    }

    if ($use_mcreate) {
        my $tmp = `./mcreate $path`;
	if ($tmp =~ /.*error: (.*)\n/) {
	    die "Error mcreating $path: $!\n";
	}
    } else {
        open(FH, ">$path") || die "Error opening $path: $!\n";
        close(FH) || die;
    }
    return 0;
}

#########################################################################
sub fork_and_rename ($) {
    my ($thread_num) = @_;
    
  FORK: {
      if (my $pid = fork) {
          # parent here
          # child process pid is available in $pid
	  return 0;
      } elsif (defined $pid) { # $pid is zero here if defined
	  
	  my $current_iteration=1;
          while ($current_iteration <= $iterations) {
	      for (my $i=0; $i<$num_files; $i++) {
		  my $which = "";
		  if ($num_mounts > 0) {
		      $which = int(rand() * $num_mounts) + 1;
		  }
		  
		  my $d = int(rand() * $num_dirs);
		  my $f1 = int(rand() * $num_files);
		  my $f2 = int(rand() * $num_files);
		  my $path_f1 = "${mountpt}${which}/${thread_num}.${d}/${f1}";
		  my $path_f2 = "${mountpt}${which}/${thread_num}.${d}/${f2}";
		  
		  print "$SCRIPT_NAME - Thread $thread_num: [$$] $path_f1 $path_f2 ...\n" if !$silent;
		  my $rc = rename $path_f1, $path_f2;
		  print "$SCRIPT_NAME - Thread $thread_num: [$$] done: $rc\n" if !$silent;
	      }
	      if (($current_iteration) % 100 == 0) {
		  print "$SCRIPT_NAME - Thread $thread_num: " . $current_iteration . " operations [" . $$ . "]\n";
		  
	      }
	      $current_iteration++;
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
