#!/usr/bin/perl -w

#
# stdfd test: Verifies that stdin, stdout, and stderr can be opened and 
#             either written to or read from (in the case of stdin)

use IPC::Open2;

use strict;
use FindBin;
use lib "$FindBin::Bin";
use helper;

sub usage
{
  print "Usage ./test_stdfd : Verifies that stdin, stdout, and stderr can be opened and ";
  print "                   : either written to or read from (in the case of stdin)";
  exit(-1);
}

sub mkdev
{
  my ($major, $minor) = @_;
  my $devno = ( (($major & 0xff) << 8) | ($minor & 0xff) );

  return $devno;
}

sub statit
{
  my ($cmdfh, $outfh, $do_print, $name) = @_;

  my $cmd = "CALL stat $name ".'$buf'."\n";

  helper::send_cmd($cmdfh, $outfh, "stat", $cmd);
  helper::verify_cmd($cmdfh, $outfh, "stat $name");

  # Print out the stat buffer
  $cmd = 'PRINT $buf 0 8 LONG 12 24 INT 44 8 LONG 52 8 INT 64 24 LONG';
  $cmd .= "\n";
  helper::send_cmd($cmdfh, $outfh, "PRINT", $cmd);
  
  my $res = <$outfh>;
  chop($res);
  my ( $iodev, $ioino, $iomode, $ionlink, $iouid, $iogid, $iordev, 
       $iosize, $ioblksize, $ioblks, $ioatime, $iomtime, $ioctime ) 
    = split(' ', $res);

  $iomode = oct($iomode);

  if ($do_print == 1) {
    # Print out the path
    my $typechar = helper::get_type($iomode);
    print STDOUT "$name: $typechar\n";
  }
  return 0;
}

sub do_open
{

  my ($cmdfh, $outfh, $name, $mode, $num) = @_;

  helper::send_cmd($cmdfh, $outfh, "open", "CALL open $name $mode\n");
  
  my $res = helper::verify_cmd($cmdfh, $outfh, "open $name");

  #chop($res);
  $res = oct($res);
  if ($res < 0) {
    helper::print_and_exit($cmdfh, $outfh, 1, "Unable to open $name\n");
  }


  if ($res == $num) {
      return $res;
  }

  helper::send_cmd($cmdfh, $outfh, "dup2", "CALL dup2 $res $num\n");
  $res = helper::verify_cmd($cmdfh, $outfh, "dup2");
  $res = oct($res);

  if ($res != $num) {
    helper::print_and_exit($cmdfh, $outfh, 1, "Unable to dup $name (res was $res)\n");
  }
}

sub do_mknod
{

  my ($cmdfh, $outfh, $do_print, $name, $perm_num, $minor) = @_;

  my $perm = 'S_IFCHR|'.$perm_num;
  my $devno = mkdev(0, $minor);

  helper::send_cmd($cmdfh, $outfh, "mknod", "CALL mknod $name $perm $devno\n");
  
  helper::verify_cmd($cmdfh, $outfh, "mknod $name");

  my $statres = statit($cmdfh, $outfh, $do_print, $name);
  if ($statres != 0) {
    helper::print_and_exit($cmdfh, $outfh, 1, "stat on $name failed\n");
  }
}

sub process_cmd
{
  my ($dirname, $do_print, $is_alpha) = @_;
 
# Get tests directory
my $testdir = $0;
$testdir =~ s/\/\w+.pl$//;
 
  eval {
      if ($is_alpha == 1) {
	  open2(\*OUTFILE, \*CMDFILE, "yod -sz 1 -quiet -batch $testdir/test_driver --np");
      } else {
	  open2(\*OUTFILE, \*CMDFILE, "$testdir/test_driver --np");
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
      helper::send_cmd($cmdfh, $outfh, "init", "CALL init incore ".'"0777+0+0"'." 0\n");
      helper::verify_cmd($cmdfh, $outfh, "init incore");
  }


  # Get a stat buffer
  my $cmd = '$buf = ALLOC ( $size = CALL sizeof stat )'."\n";
  helper::send_cmd($cmdfh, $outfh, "alloc", $cmd);

  if ($is_alpha == 0) {
  # Make the test directory
  $cmd = "CALL mkdir $dirname 0777\n";
  helper::send_cmd($cmdfh, $outfh, "mkdir", $cmd);
  helper::verify_cmd($cmdfh, $outfh, "mkdir");


  # Change working dir to test dir
  $cmd = "CALL chdir $dirname\n";
  helper::send_cmd($cmdfh, $outfh, "chdir", $cmd);
  helper::verify_cmd($cmdfh, $outfh, "chdir");


  # Create the 3 special files
  do_mknod($cmdfh, $outfh, $do_print, "stdin", "0444", 0);
  do_mknod($cmdfh, $outfh, $do_print, "stdout", "0222", 1);
  do_mknod($cmdfh, $outfh, $do_print, "stderr", "0222", 2);

  # Open the 3 files
  do_open($cmdfh, $outfh, "stdin", "O_RDONLY", 0);
  do_open($cmdfh, $outfh, "stdout", "O_WRONLY", 1);
  do_open($cmdfh, $outfh, "stderr", "O_WRONLY", 2);
 } 
  #helper::send_cmd($cmdfh, $outfh, "debug", "CALL debug 5\n");

  # Read from stdin, write to stdout and stderr

  # Send "delay" option to read which will give us time to 
  # put something in stdin (since we can't send an eof)
  $cmd = "CALL read 0 ".'$buf 38'." delay\n";
  print $cmdfh $cmd;
  # Give time to process command
  sleep 1;

  # Send random junk...
  print $cmdfh "This message is exactly 38 bytes long\n";
  sleep 0.5;

  # Make sure read was OK
  my $res = <$outfh>;
  chop($res);
  if ($res ne "0000 ") {
    helper::print_and_exit($cmdfh, $outfh, 1, "ERROR! Command $cmd failed with code $res\n");
  }
    
  # See how many bytes we got...
  my $bytes = helper::verify_cmd($cmdfh, $outfh, "read");
  $bytes = oct($bytes);
  if ($bytes == 0) {
    helper::print_and_exit($cmdfh, $outfh, 0, "test_stdfd successful but read nothing\n");
  }

  if ($bytes < 0) {
    helper::print_and_exit($cmdfh, $outfh, 0, "test_stdfd unsuccessful\n");
  }

  $cmd = "CALL write 1 ".'$buf '."$bytes\n";
  print $cmdfh $cmd;

  # Suck up the stdout...
  $res = <$outfh>;
  chop($res);
  
  $res = <$outfh>;
  chop($res);
  $res = oct($res);

  if ($res != 0) {
    helper::print_and_exit($cmdfh, $outfh, 1, "ERROR! Command $cmd failed with code $res\n");
  }

  helper::verify_cmd($cmdfh, $outfh, "write stdout");

  $cmd = "CALL write 2 ".'$buf '."$bytes\n";
  helper::send_cmd($cmdfh, $outfh, "write stderr", $cmd);
  helper::verify_cmd($cmdfh, $outfh, "write stderr");

  helper::print_and_exit($cmdfh, $outfh, 0, "test_stdfd successful\n");
}


my $is_alpha = 0;
my $do_print = 0;
my $i;
for ($i=0; $i < @ARGV; $i++) {
  if ($ARGV[$i] eq "-alpha") {
    $is_alpha =1;
  } elsif ($ARGV[$i] eq "-print") {
    $do_print = 1;
  }
}

$i--;
my $dirname = $ARGV[$i];

process_cmd($dirname, $do_print, $is_alpha);

exit 0;

