#!/usr/bin/perl -w

# Verifies that the contents of a given file produced by producer.pl with the given
# seed are good

use IPC::Open2;

use strict;
use helper;

sub usage
{
  print "Usage: ./verifier.pl <-seed seed> <-file fname> : Verifies that file fname,\n";
  print "                                                : produced with the given \n";
  print "                                                : seed matches\n";
  exit(-1);
}

sub get_buf
{
  my $MAX_SIZE = 2147483648;

  my $str;
  my $num;
  my $len = 0;

  while ($len < 512) {
    $num = rand $MAX_SIZE;
    my $tmpstr = sprintf("%d", $num);
    $str .= $tmpstr;
    $len += length $tmpstr;
  }

  return ($len, $str);
}


sub check_file
{
  my ($cmdfh, $outfh, $filename) = @_;


  # Allocate the read buffer
  my $cmd = '$buf = ALLOC 1024'."\n";
  helper::send_cmd($cmdfh, $outfh, "alloc", $cmd);  
  
  # Open the file
  $cmd = '$fd = CALL open '."$filename O_RDONLY\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmd);  

  # Verify the system call's output
  helper::verify_cmd($cmdfh, $outfh, "open");  

  my $total = 0;
  my $bytes = 0;

  # Read all of the file in 1024 byte chunks
  do {

    # Clear the buffer
    $cmd = 'CALL clear $buf'."\n";
    helper::send_cmd($cmdfh, $outfh, "clear", $cmd);  

    my ($len, $buf) = get_buf;

    $cmd = 'CALL read $fd $buf '."$len\n";
    helper::send_cmd($cmdfh, $outfh, "read", $cmd);  
    $bytes = helper::verify_cmd($cmdfh, $outfh, "read");  
    $bytes = oct($bytes);
    $total += $bytes;
    if ($bytes > 0) {
     
      # Print out the buffer
      $cmd = 'PRINT $buf 0 1 STR'."\n";
      helper::send_cmd($cmdfh, $outfh, "print", $cmd);  
      my $str = <$outfh>;
      chop($str);
      if ($bytes > $len) {
	$str = substr($str, 0, $len-1);
      } elsif ($len > $bytes) {
	$buf = substr($buf, 0, $bytes);
      }
      if ($str ne $buf) {
	my $errstr = "ERROR! Str $str is not equal to str $buf\n";
	helper::print_and_exit($cmdfh, $outfh, 1, $errstr);
      }
    }
  } while ($bytes > 0);

}

sub verify_file
{
  my ($filename, $is_alpha) = @_;
  
  eval {
      if ($is_alpha == 0) {
	  open2(\*OUTFILE, \*CMDFILE, "./test_driver --np");
      } else {
	  open2(\*OUTFILE, \*CMDFILE, 
		"yod -batch -quiet -sz 1 ./test_driver --np");
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

  # Now check the file
  check_file($cmdfh, $outfh, $filename);

  # Close the file
  my $cmd = 'CALL close $fd'."\n";
  helper::send_cmd($cmdfh, $outfh, "close", $cmd);

  helper::verify_cmd($cmdfh, $outfh, "close");

  # All done
  helper::print_and_exit($cmdfh, $outfh, 0, "File $filename valid\n");
}


my $is_alpha = 0;
my $seed = time;
my $filename = "randfile.$seed.$$";
my $bytes = 1024;
for (my $i = 0; $i < @ARGV; $i++) 
{
  if ($ARGV[$i] eq "-file") {
    $i++;
    $filename = $ARGV[$i];
  } elsif ($ARGV[$i] eq "-seed") {
    $i++;
    $seed = $ARGV[$i];
  } elsif ($ARGV[$i] eq "-alpha") {
    $is_alpha = 1;
  } 
}

# seed the randome number generator
srand $seed;

verify_file($filename, $is_alpha);

exit 0;




