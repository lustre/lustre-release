#!/usr/bin/perl -w

use IPC::Open2;

use strict;
use FindBin;
use lib "$FindBin::Bin";
use helper;
use Fcntl ':mode';


sub usage
{
  print "Usage: ./test_getcwd.pl [-alpha] <dir> : Test getcwd by verifying that it \n";
  print "                                       : setting the directory to dir and \n";
  print "                                       : verifying that getcwd reflects \n";
  print "                                       : the change\n";
  exit(-1);
}

sub check_wkdir
{
  my ($wdir, $outfh, $cmdfh) = @_;


  # Get cwd from libsysio
  my $cmdstr = 'CALL getcwd ( $buf = ALLOC 512 ) 512'."\n";
  helper::send_cmd($cmdfh, $outfh, "getcwd", $cmdstr);  
  
  # Verify the system call's output
  helper::verify_cmd($cmdfh, $outfh, "getcwd");  

  # Print out the buffer
  $cmdstr = 'PRINT $buf 0 1 STR'."\n";
  helper::send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);  

  my $iodir = <$outfh>;
  chop($iodir);
	
	# Only compare the last portion of the working directory
	my @iodirs = split(/\//, $iodir);
	my @wdirs = split(/\//, $wdir);

	if ($iodirs[-1]  ne $wdirs[-1]) {
		helper::print_and_exit
				($cmdfh, 
				 $outfh, 0, 
				 "ERROR! topmost wdir ($wdirs[-1]) does not match sysio's ($iodirs[-1])\n");
		}
}

sub process_cmd
{
  my ($dir, $is_alpha) = @_;

  # Get tests directory
  my $testdir = $FindBin::Bin;
  
  eval {
      if ($is_alpha == 0) {
	  open2(\*OUTFILE, \*CMDFILE, "$testdir/test_driver --np");
      } else {
	  open2(\*OUTFILE, \*CMDFILE, 
		"yod -batch -quiet -sz 1 $testdir/test_driver --np");
      }
  };

  if ($@) {
    if ($@ =~ /^open2/) {
      warn "open2 failed: $!\n$@\n";
      return;
    }
    die;

  }

  my $outfh = \*OUTFILE;
  my $cmdfh = \*CMDFILE;

  if ($is_alpha == 0) {
    helper::send_cmd($cmdfh, $outfh, "init", "CALL init\n");

			# Get current working directory from environment
      my $cwd = $ENV{PWD};

     
  }

  # Now change to dir
  helper::send_cmd($cmdfh, $outfh, "chdir", "CALL chdir $dir\n");  

 # Verify the system call's output
  helper::verify_cmd($cmdfh, $outfh, "PRINT");  

  check_wkdir($dir, $outfh, $cmdfh);

  # Clean up
  helper::print_and_exit($cmdfh, $outfh, 0, "getcwd test successful\n");
}


my $currarg = 0;
my $is_alpha = 0;

if (@ARGV < 1) {
  usage;
} elsif (@ARGV > 1) {
  if ($ARGV[$currarg++] eq "-alpha") {
    $is_alpha = 1;
  }
}

my $dir = $ARGV[$currarg];

process_cmd($dir, $is_alpha);

exit 0;




