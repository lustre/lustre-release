#!/usr/bin/perl -w

#
# Provides a set of helper routines for use in the Perl 
# test scripts
#

package helper;
use strict;
use POSIX;

BEGIN{}

# Print out a given error message, close the command file
# and exit
sub print_and_exit
{
  my ($cmdfh, $outfh, $exit_num, $exit_str) = @_;

  print STDOUT "$exit_str";

  # Clean up
  my $cmdstr =  'FREE $buf';
  $cmdstr = $cmdstr."\n";

  print $cmdfh $cmdstr;

  my $res = <$outfh>;
  chop($res);

  print $cmdfh "exit\n";
  close $outfh;

  # Give test_driver time to finish
  sleep 0.000001;

  exit $exit_num;
}


# Output the given command and make sure that the exit
# code for the command was valid
sub send_cmd
{
  my ($cmdfh, $outfh, $cmd, $cmdstr) = @_;

  print $cmdfh $cmdstr;

  my $res = <$outfh>;
  chop($res);
  if ($res ne "0000 ") {
    print_and_exit($cmdfh, $outfh, 1, "ERROR! Command $cmd failed with code $res\n");
  }
}

# Check the return value from the last libsysio call
sub verify_cmd
{

  my ($cmdfh, $outfh, $cmd) = @_;

  # Verify the system call's output
  my $cmdstr = 'PRINT $$';
  $cmdstr .= "\n";
  send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);  

  my $res = <$outfh>;
  chop($res);

  if ($res eq "0xffffffff") {
     
    # Get the errno
    $cmdstr = 'PRINT $errno';
    $cmdstr .= "\n";
    send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);
    
    my $err = <$outfh>;
    chop($err);
    print_and_exit($cmdfh, $outfh, 1, "ERROR!  $cmd returned $err\n");
  }
  return $res;
}

# Compares two numbers.  Output error message and exit if
# they differ
sub cmp_nums
{
  my ($cmdfh, $outfh, $ionum, $pnum, $desc) = @_;

  my $str;
  if (!defined($ionum)) {
      print_and_exit($cmdfh, $outfh, 1, "ERROR! ionum for $desc undefined");
  } elsif (!defined($pnum)) {
      print_and_exit($cmdfh, $outfh, 1, "ERROR! pnum for $desc undefined");
  }
  if ($ionum != $pnum) {
    my $str = sprintf("ERROR!  Sysio's number %x does not match Perl's (%x)\n", 
		      $ionum, $pnum);
    $str = sprintf("%s Numbers were %s\n", $str, $desc);
    print_and_exit($cmdfh, $outfh, 1, $str);
  }
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

END{}

1;
