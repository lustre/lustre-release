#!/usr/bin/perl -w

use IPC::Open2;

use strict;
use helper;

sub usage
{
  print "Usage: ./populator.pl <-seed seed>     :\n";
  print "                      <-file filename> :\n";
  print "                      <-bytes bytes>   : Create a file, filename, that\n";
  print "                                       : is bytes long and populate with\n";
  print "                                       : random numbers using the given\n";
  print "                                       : seed.  Will use defaults if args\n";
  print "                                       : not given\n";
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

sub write_file
{
  my ($cmdfh, $outfh, $filename, $bytes) = @_;


  # Allocate the read buffer
  my $cmd = '$buf = ALLOC 1024'."\n";
  helper::send_cmd($cmdfh, $outfh, "alloc", $cmd);  
  
  # Open (create) the new file
  $cmd = '$fd = CALL open '."$filename O_RDWR|O_CREAT S_IRWXU\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmd);  

  # Verify the system call's output
  helper::verify_cmd($cmdfh, $outfh, "open");  

  my $left_bytes = $bytes;
  while ($left_bytes > 0) {
    # Get a buffer filled with random numbers
    # Buffer will be no less than 512 bytes
    my ($len, $buf) = get_buf;
    if ($len > $left_bytes) {
      $len = $left_bytes;
    }

    # Need to fill $buf with the buffer 
    $cmd = "CALL fill $buf STR $len 0 ".'$buf'."\n";
    helper::send_cmd($cmdfh, $outfh, "fill", $cmd);

    # Write out $len bytes to $filename
    $cmd = 'CALL write $fd $buf '."$len\n";
   
    helper::send_cmd($cmdfh, $outfh, "write", $cmd);

    my $written_bytes = helper::verify_cmd($cmdfh, $outfh, "write");
    $written_bytes = oct($written_bytes);
    if ($written_bytes != $len) {
       helper::print_and_exit($cmdfh, $outfh, 1, 
			   "ERROR! Meant to print out $len but only printed $written_bytes\n");
     }

    $left_bytes -= $len;
  }
}

sub populate_file
{
  my ($filename, $bytes, $is_alpha) = @_;
  
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

  # Now write the file
  write_file($cmdfh, $outfh, $filename, $bytes);

  # Close the file
  my $cmd = 'CALL close $fd'."\n";
  helper::send_cmd($cmdfh, $outfh, "close", $cmd);

  helper::verify_cmd($cmdfh, $outfh, "close");

  # All done
  helper::print_and_exit($cmdfh, $outfh, 0, "File $filename successfully created\n");
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
  } elsif ($ARGV[$i] eq "-bytes") {
    $i++;
    $bytes = $ARGV[$i];
  }
}

# seed the randome number generator
srand $seed;

populate_file($filename, $bytes, $is_alpha);

exit $seed;




