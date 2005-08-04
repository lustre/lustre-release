#!/usr/bin/perl -w

#
# getdirentries test:  Tests the equivalent of a ls.  Note that this is not
#                      the most robust test in the world; it simply verifies
#                      that libsysio returns all the entries in the directory
#
#

use IPC::Open2;

use strict;

use FindBin;
use lib "$FindBin::Bin";
use helper;

sub usage
{
  print "Usage: ./test_list.pl [-p|-alpha] <dir> \n";
  print "       ./test_list.pl -m [-p|-alpha] fstype:mdir dir\n";
  print "      In the first form, will attempt to verify libsysio's\n";
  print "      getdirentries.  If no dir is given, will use the \n";
  print "      current working directory\n";
  print "      In the second form, will mount the given mdir (of type fstype) in dir.\n";
  print "      It will then verify the output of libsysio's getdirentries. It will \n";
  print "      then umount the directory and verify that the umount worked\n";
  print "      The -p option will print the directory listing\n";
  print "      The -alpha option is for alpha architecture \n";
  exit(-1);
}


sub write_print
{
  my ($offset, $outfh, $cmdfh, $do_print, $is_alpha) = @_;
  my $bytes = 0;
  
  my $intsize = 8;
  my $intcmd = "INT";
  if ($is_alpha == 1) {
      $intsize = 16;
      $intcmd = "LONG"
  }
  my $shortoffset = $offset+$intsize;
  my $charoffset = $shortoffset+2;
  my $stroffset = $charoffset+1;
  my $cmdstr = 'PRINT $buf '. 
    "$offset $intsize $intcmd $shortoffset 2 SHORT $charoffset 1 CHAR $stroffset 1 STR\n";
  helper::send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);

  my $res = <$outfh>;
  chop($res);
  my ($inode, $foffset, $size, $type, @names) = split(' ',$res);
  $size = oct($size);
  if ($size == 0) {
    return -1;
  }
  my $name = join(' ', @names);

  if ($do_print == 1) {
    printf(STDOUT "%-35s %-14s %-14s %-6s %-4s\n", $name, $inode, $foffset, $size, $type);
  }

  return $size;
}

sub do_print_cmds
{
  my ($numbytes, $outfh, $cmdfh, $start, $do_print, $is_alpha) = @_;

  my $offset = 0;
  my $bytes = 0;
  my $numfiles = 0;
  my $i = $start;
  
  if ($numbytes == 0) {
    $numbytes = 8192;
  }
  while ($bytes < $numbytes) {
    my $len = write_print($offset, $outfh, $cmdfh, $do_print, $is_alpha);
    if ($len <= 0) {
      # write_print saw a 0 length record, indicating end of dir
      return $numfiles;
    }
    $numfiles++;
    if ($is_alpha == 0) {
	$len += $len%4;
    } else {
	$len += $len%8;
    }
    $offset += $len;
    $bytes += $len;
    $i++;
  }
  return $numfiles;
}

sub print_dir_cmd
{

  my ($outfh, $cmdfh, $start, $mdir, $do_print, $is_alpha) = @_;

  my $cmdstr = "CALL getdirentries ( ".'$fd = CALL open '."$mdir O_RDONLY ) ( ";
  $cmdstr .= '$buf = ALLOC 8192 ) 8192 $basep'."\n";
  helper::send_cmd($cmdfh, $outfh, "getdirentries", $cmdstr);
  
  # Verify that the sysio call succeeded
  my $res = helper::verify_cmd($cmdfh, $outfh, "getdirentries");
  my $numbytes = oct($res);
  
  while ($numbytes > 0) {

    do_print_cmds($numbytes, $outfh, $cmdfh, $start, $do_print, $is_alpha);

    $cmdstr = "CALL getdirentries ".'$fd $buf 8192 $basep'."\n";
    helper::send_cmd($cmdfh, $outfh, "getdirentries", $cmdstr);

    # Verify that the sysio call succeeded
    my $res = helper::verify_cmd($cmdfh, $outfh, "getdirentries");
    $numbytes = oct($res);
  }
}

sub process_cmd
{
  my ($mdir, $tdir, $do_mount, $is_alpha, $do_print) = @_;
  my $size = 8192;
  my $done_files = 0;

  # Get tests directory
  my $testdir = $FindBin::Bin;
 
  eval {
      if ($is_alpha == 1) {
	  open2(\*OUTFILE, \*CMDFILE, "yod -quiet -sz 1 $testdir/test_driver --np");
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
    helper::send_cmd($cmdfh, $outfh, "init", "CALL init\n");
  }

  my $start = 0;

  if ($do_mount == 1) {
    helper::send_cmd($cmdfh, $outfh, "mount", "CALL mount $mdir $tdir\n");
    print_dir_cmd($outfh, $cmdfh, $start, $tdir, $do_print, $is_alpha);
  } else {
    print_dir_cmd($outfh, $cmdfh, $start, $mdir, $do_print, $is_alpha);
  }  

  # Attempt to unmount and verify the contents
  if ($do_mount == 1) {

    # Close the dir before we umount
    my $cmdstr = 'CALL close $fd'."\n";
    helper::send_cmd($cmdfh, $outfh, "close", $cmdstr);
   
    # umount dir
    helper::send_cmd($cmdfh, $outfh, "umount", "CALL umount $tdir\n");

   
    # Verify it is umounted
    $cmdstr = "CALL getdirentries ( ".'$fd2 = CALL open '."$tdir O_RDONLY ) ";
    $cmdstr .= '$buf 8192 $newp'."\n";
    helper::send_cmd($cmdfh, $outfh, "getdirentries", $cmdstr);
    my $res = helper::verify_cmd($cmdfh, $outfh, "getdirentries");

    my $numbytes = oct($res);
    # The only entries should be . and .., so should return 32
    if ($numbytes != 32) {
      helper::print_and_exit($cmdfh, $outfh, 1, "ERROR! Read in $numbytes bytes\n");
    }
    # Clean up
    $cmdstr = 'CALL close $fd2'."\n";
    helper::send_cmd($cmdfh, $outfh, "close", $cmdstr);

  } else {
    my $cmdstr = 'CALL close $fd'."\n";
    helper::send_cmd($cmdfh, $outfh, "getdirentries", $cmdstr);
  }

  helper::print_and_exit($cmdfh, $outfh, 0, "list test successful\n");
}


# Default dir is cwd
my @mydir;
$mydir[0] = "./";
my $do_mount = 0;
my $is_alpha = 0;
my $do_print = 0;
my $dircnt = 0;
for (my $i = 0; $i < @ARGV; $i++) 
{
  if ($ARGV[$i] eq "-p") {
    $do_print = 1;
  } elsif ($ARGV[$i] eq "-m") {
    $do_mount = 1;
  } elsif ($ARGV[$i] eq "-alpha") {
    $is_alpha = 1;
  } else {
    $mydir[$dircnt] = $ARGV[$i];
    $dircnt++;
  }
}

if (  ($dircnt == 0) || ($dircnt > 2) ||
      (($do_mount==1) && ($dircnt < 2)) ||
      (($do_mount == 0) && ($dircnt > 1)) ) {
  usage();
}

my $dir = $mydir[0];
if ($do_mount == 1) {
  my $fstype;
  ($fstype, $dir) = split(/:/, $mydir[0]);
}

process_cmd($mydir[0], $mydir[1], $do_mount, $is_alpha, $do_print);

exit 0;
