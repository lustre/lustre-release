#!/usr/bin/perl -w 

#
# path test: reads paths from stdin and prints out the path along with its 
#          : type
#

use IPC::Open2;

use strict;
use FindBin;
use lib "$FindBin::Bin";
use helper;
use POSIX;
use Fcntl ':mode';

sub usage
{
  print "Usage ./test_path.pl [path1 path2...] : Print each path listed and its type\n";
  print "                                      : If no paths are given, stdin is read\n";
  exit(-1);
}

sub get_type
{
  my $mode = $_[0];
  my $t = '?';

  if (S_ISDIR($mode)) {
    $t = 'd';
  } elsif (S_ISCHR($mode)) {
    $t = 'c';
  } elsif (S_ISBLK($mode)) {
    $t = 'b';
  } elsif (S_ISREG($mode)) {
    $t = 'f';
  } elsif (S_ISFIFO($mode)) {
    $t = 'p';
  } elsif (S_ISLNK($mode)) {
    $t = 'S';
  } elsif (S_ISSOCK($mode)) {
    $t = 's';
  }

  return $t;
}

sub print_path
{
  my ($mode, $path) = @_;
  
  my $typechar = get_type($mode);
  print STDOUT "$path: $typechar\n";
}

sub process_path
{
  my ($cmdfh, $outfh, $bits, $path) = @_;

  # Issue the stat command
  my $cmdstr = 'CALL stat "';
  $cmdstr = sprintf("%s%s%s\n", $cmdstr, $path, '" $buf');

  helper::send_cmd($cmdfh, $outfh, "stat", $cmdstr);  
  helper::verify_cmd($cmdfh, $outfh, "stat");

  # Print out the stat buffer
  if ($bits == 32) {
      $cmdstr = 'PRINT $buf 0 8 LONG 12 24 INT 44 8 LONG 52 8 INT 64 24 LONG';
  } else {
      $cmdstr = 'PRINT $buf 0 24 LONG 24 16 INT 48 32 LONG 88 8 LONG 104 8 LONG';
  }
  $cmdstr .= "\n";
  helper::send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);
  
  my $res = <$outfh>;
  chop($res);
  my ( $iodev, $ioino, $iomode, $ionlink, $iouid, $iogid, $iordev, 
       $iosize, $ioblksize, $ioblks, $ioatime, $iomtime, $ioctime ) 
      = split(' ', $res);
   if ($bits == 64) {
      ( $iodev, $ioino, $ionlink, $iomode, $iouid, $iogid, $iordev, 
	   $iosize, $ioblksize, $ioblks, $ioatime, $iomtime, $ioctime ) 
	  = split(' ', $res);
  }
  $iomode = oct($iomode);

  # Print out the path
  print_path($iomode, $path);
}
  
sub process_cmd
{
  my ($usestdin, $isalpha, @paths) = @_;

  my $path;
  
  # Get tests directory
  my $testdir = $FindBin::Bin;
 
  eval {
    if ($isalpha == 0) {
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

  if ($isalpha == 0) {
    helper::send_cmd($cmdfh, $outfh, "init", "CALL init\n");
  }

  # Allocate the stat buffer
  my $cmdstr = '$buf = ALLOC ( $size = CALL sizeof stat )';
  $cmdstr .= "\n";
  helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);  

   # Attempt to determine type
  $cmdstr = 'PRINT $size'."\n";
  helper::send_cmd($cmdfh, $outfh, "print", $cmdstr);  
  my $statsize = <$outfh>;
  chop($statsize);
  $statsize = oct($statsize);
  my $bits = 32;
  if ($statsize == 144) {
      $bits = 64;
  }

  my $i=0;
  if ($usestdin) {
    $path = <STDIN>;
    if (defined($path)) {
      chop($path);
    }
  } else {
    $path = $paths[$i++];
  }

  # Enter a loop, reading a path argument and processing it with each 
  # phase of loop.  
  while (defined($path)) {

    process_path($cmdfh, $outfh, $bits, $path);
    if ($usestdin) {
      $path = <STDIN>;

      if (defined($path)) {
	chop($path);
      }
      if ($path eq "quit") {
	helper::print_and_exit($cmdfh, $outfh, 0, "path test successful\n");
      }
    } else {
      $path = $paths[$i++];
    }
  }
  helper::print_and_exit($cmdfh, $outfh, 0, "path test successful\n");
}


my $usestdin = 0;
my $isalpha = 0;

# The -alpha arg must be before the paths
# (if they exist)
if ( (@ARGV > 0) && ($ARGV[0] eq "-alpha")) {
  $isalpha = 1;
  shift(@ARGV);
}

if (@ARGV == 0) {
  $usestdin = 1;
} 

process_cmd($usestdin, $isalpha, @ARGV);

