#!/usr/bin/perl -w

#
# symlink test: Verify that symbolic links work
#

use IPC::Open2;

use strict;
use FindBin;
use lib "$FindBin::Bin";
use helper;

sub usage
{
  print "Usage: ./test_symlink.pl [-alpha] <src> <dest>: Create a symlink from src to dest\n";
  exit(-1);
}

sub clean_exit
{
  my ($cmdfh, $outfh, $exit_num, $exit_str) = @_;

  print STDOUT "$exit_str";

  # Free buffers
  my $cmdstr =  'FREE $srcbuf'."\n";

  print $cmdfh $cmdstr;

  my $res = <$outfh>;
  chop($res);
  if ($res ne "0000 ") {
    print STDOUT "ERROR! Failed to free srcbuf (code $res)\n";
  }

  $cmdstr =  'FREE $destbuf'."\n";

  print $cmdfh $cmdstr;

  $res = <$outfh>;
  chop($res);
  if ($res ne "0000 ") {
    print STDOUT "ERROR! Failed to free destbuf (code $res)\n";
  }

  print $cmdfh "exit\n";
  close $outfh;

  # Give test_driver time to finish
  sleep 0.000001;

  exit $exit_num;
}

sub process_cmd
{
  my ($src, $dest, $is_alpha) = @_;
  
  # Get tests directory
  my $testdir = $FindBin::Bin;

  eval {
      if ($is_alpha == 0) {
	  open2(\*OUTFILE, \*CMDFILE, "$testdir/test_driver --np");
      } else {
	  open2(\*OUTFILE, \*CMDFILE, "yod -quiet -sz 1 $testdir/test_driver --np");
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
  }
  
  # Get the filesize of src
  my $size = -s $src;
  my $bufsize;

  if ( $size > 1024) { # Arbitrary limit
    $bufsize = 1024;
  } else {
    $bufsize = $size;
  }

  # Create the symbolic link from src to dest
  my $cmdstr = "CALL symlink $src $dest\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);

  helper::verify_cmd($cmdfh, $outfh, "symlink");

  # Open src 
  $cmdstr = '$src = CALL open '."$src O_RDONLY\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);

  # Open dest 
  $cmdstr = '$dest = CALL open '."$dest O_RDONLY\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);
  
  my $res = helper::verify_cmd($cmdfh, $outfh, "open $dest");

  # Allocate buffer for src
  $cmdstr = '$srcbuf = ALLOC '."$bufsize\n";
  helper::send_cmd($cmdfh, $outfh, "ALLOC", $cmdstr);

  # Allocate buffer for dest
  $cmdstr = '$destbuf = ALLOC '."$bufsize\n";
  helper::send_cmd($cmdfh, $outfh, "ALLOC", $cmdstr);


  # Read size bytes from src and dest, then compare them and verify they
  # are the same
  $cmdstr = 'CALL read $src $srcbuf '."$bufsize\n";
  helper::send_cmd($cmdfh, $outfh, "read $src", $cmdstr);
    
  $res = helper::verify_cmd($cmdfh, $outfh, "read $src");
  my $readb = oct($res);

  # Now read $readb from dest
  $cmdstr = 'CALL read $dest $destbuf '."$readb\n";
  helper::send_cmd($cmdfh, $outfh, "read $dest", $cmdstr);
    
  $res = helper::verify_cmd($cmdfh, $outfh, "read $dest");

  my $errstr;
  if ($readb != oct($res)) {
      $errstr = "ERROR!  Read $readb bytes from src but only $res bytes from dest\n";
      clean_exit($cmdfh, $outfh, 1, $errstr);
  }

  # Compare the two buffers
  $cmdstr = 'CALL cmpstr $srcbuf $destbuf'."\n";
  helper::send_cmd($cmdfh, $outfh, "cmpstr", $cmdstr);

  # Verify that it returned an error
  $cmdstr = 'PRINT $$';
  $cmdstr .= "\n";
  helper::send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);  

  $res = <$outfh>;
  chop($res);

  $res = helper::verify_cmd($cmdfh, $outfh, "cmpstr");
  $res = oct($res);
  if ($res != 0) {
      $errstr = "ERROR! Buffers from $src and $dest do not match\n";
      clean_exit($cmdfh, $outfh, 1, $errstr);
  }

  # Clean up
  $cmdstr = 'CALL close $src'."\n";
  helper::send_cmd($cmdfh, $outfh, "close", $cmdstr);
  $cmdstr = 'CALL close $dest'."\n";
  helper::send_cmd($cmdfh, $outfh, "close", $cmdstr);

 # Clear out destbuf
  $cmdstr = 'CALL clear $destbuf'."\n";
  helper::send_cmd($cmdfh, $outfh, "CLEAR", $cmdstr);

  # Now remove the symbolic link and make sure everything stays the same
  
  # Remove the link (this assumes the link is not in incore)
  $cmdstr = "CALL unlink $dest\n";
  helper::send_cmd($cmdfh, $outfh, "unlink", $cmdstr);
  helper::verify_cmd($cmdfh, $outfh, "unlink");

  # Attempt to open the symbolic link.  This should return an error
  $cmdstr = 'CALL open '."$dest O_RDONLY\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);
  
  # Verify that it returned an error
  $cmdstr = 'PRINT $$';
  $cmdstr .= "\n";
  helper::send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);  

  $res = <$outfh>;
  chop($res);

  if ($res ne "0xffffffff") {
      $errstr = "ERROR! Open on $dest succeeded (should have failed)\n";
      clean_exit($cmdfh, $outfh, 1, $errstr);
  }

  # Now read from the src again and make sure it matches the original

  # Open src 
  $cmdstr = '$src2 = CALL open '."$src O_RDONLY\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);
  helper::verify_cmd($cmdfh, $outfh, "open $src(2)");

  $cmdstr = 'CALL read $src2 $destbuf '."$readb\n";
  helper::send_cmd($cmdfh, $outfh, "read $src(2)", $cmdstr);
    
  $res = helper::verify_cmd($cmdfh, $outfh, "read $src(2)");

  if ($readb != oct($res)) {
      $errstr = "ERROR!  Read $readb bytes from src originally but now only $res bytes\n";
      clean_exit($cmdfh, $outfh, 1, $errstr);
  }

  # Compare the two buffers
  $cmdstr = 'CALL cmpstr $srcbuf $destbuf'."\n";
  helper::send_cmd($cmdfh, $outfh, "cmpstr", $cmdstr);
  $res = helper::verify_cmd($cmdfh, $outfh, "cmpstr");
  $res = oct($res);
  if ($res != 0) {
      $errstr = "ERROR! Original buffers from $src and new buf do not match\n";
      clean_exit($cmdfh, $outfh, 1, $errstr);
  }

  # Clean up
  $cmdstr = 'CALL close $src2'."\n";
  helper::send_cmd($cmdfh, $outfh, "close", $cmdstr);

  clean_exit($cmdfh, $outfh, 0, "Symlink test successful\n");
  exit 0;
}

my $currarg = 0;
my $is_alpha = 0;

if (@ARGV < 2) {
  usage;
} elsif (@ARGV > 2 ) {
  if ($ARGV[$currarg++] eq "-alpha") {
    $is_alpha = 1;
  }
}

my $src = $ARGV[$currarg++];
my $dest = $ARGV[$currarg];

process_cmd($src, $dest, $is_alpha);


exit 0;
