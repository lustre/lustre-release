#!/usr/bin/perl -w

#
# stats test: Verifies that the set of stat calls (stat, fstat, fstatvfs, and 
#             statvfs) return the same items and that the calls return the
#             same items as Perl's stat call (which would use a native library
#             and not libsysio)
#
#

use IPC::Open2;

use strict;
use FindBin;
use lib "$FindBin::Bin";
use helper;

sub usage
{
  print "Usage ./test_stats.pl file : Verifies that the set of stat calls (stat, \n";
  print "                           : fstat, fstatvfs, statvfs) return the same set\n";
  print "                           : of stats for file and that the calls return \n";
  print "                           : the same items as Perl's stat call (which \n";
  print "                           : would use a native library and not libsysio)\n";
  exit(-1);
}

# Compares the output of Perl's stat function with the output
# from libsysio's stat
sub cmp_stats
{

    my ( $cmdfh, $outfh, $is_alpha, $bits, @stats) = @_;


    my ($iodev, $ioino, $iomode, $ionlink, $iouid, $iogid, $iordev, 
	$iosize, $ioblksize, $ioblks, $ioatime, $iomtime, $ioctime, @pstats) =
	    @stats;

    if ($is_alpha == 1) {
	($iodev, $ioino, $iomode, $ionlink, $iouid, $iogid, $iordev, 
	    $iosize, $ioatime, $iomtime, $ioctime, $ioblks, $ioblksize, @pstats) =
		@stats;
    }
    if ($bits == 64) {
	($iodev, $ioino, $ionlink, $iomode,  $iouid, $iogid, $iordev, 
	    $iosize, $ioblksize, $ioblks, $ioatime, $iomtime, $ioctime,@pstats) =
		@stats;
    }
    my ($pdev, $pino, $pmode, $pnlink, $puid, $pgid, $prdev,
	$psize, $patime, $pmtime, $pctime, $pblksize, $pblks) = @pstats;

#  helper::cmp_nums($cmdfh, $outfh, $iodev, $pdev, "device numbers");
  helper::cmp_nums($cmdfh, $outfh, $ioino, $pino, "inode numbers");
  helper::cmp_nums($cmdfh, $outfh, $iomode, $pmode, "file modes");
  helper::cmp_nums($cmdfh, $outfh, $ionlink, $pnlink, "number of links");
  helper::cmp_nums($cmdfh, $outfh, $iouid, $puid, "user ids");
  helper::cmp_nums($cmdfh, $outfh, $iogid, $pgid, "group ids");
  helper::cmp_nums($cmdfh, $outfh, $iordev, $prdev, "device ids");
  helper::cmp_nums($cmdfh, $outfh, $iosize, $psize, "file sizes");
  helper::cmp_nums($cmdfh, $outfh, $ioatime, $patime, "access times");
  helper::cmp_nums($cmdfh, $outfh, $iomtime, $pmtime, "modification times");
  helper::cmp_nums($cmdfh, $outfh, $ioctime, $pctime, "inode change times");
  helper::cmp_nums($cmdfh, $outfh, $ioblksize, $pblksize, "block sizes");
  helper::cmp_nums($cmdfh, $outfh, $ioblks, $pblks, "blocks allocated");
}

  
# Prints out the stat buffer and verifies that it matches
# Perl's output
sub verify_stat
{
  my ($cmdfh, $outfh, $cmd, $is_alpha, $bits, @stats) = @_;
  my $i=0;

  my $cmdstr;
  # Print out the stat buffer
  if ($is_alpha == 1) {
      $cmdstr = 'PRINT $buf 0 16 LONG 16 16 INT 32 8 LONG 40 4 INT 48 40 LONG'."\n";
  } elsif ($bits == 32) {
      $cmdstr = 'PRINT $buf 0 8 LONG 12 24 INT 44 8 LONG 48 8 INT 56 24 LONG'."\n";
  } else {
      $cmdstr = 'PRINT $buf 0 24 LONG 24 16 INT 48 32 LONG 88 8 LONG 104 8 LONG'."\n";     
  }
 
  helper::send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);

  my $res = <$outfh>;
  chop($res);

  my @iostats = split(' ', $res);
  foreach my $iostat (@iostats) {
    $iostats[$i] = oct($iostat);
    $i++;
  }

  cmp_stats($cmdfh, $outfh, $is_alpha, $bits, @iostats, @stats);
 
}

sub process_cmd
{
  my ($file, $use_system, $is_alpha) = @_;
  
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
  }

  my @stats;
  if ($use_system == 1) {
      # Get stats for file
      @stats = stat($file);
  } 
 
  # Allocate the buffer
  my $cmdstr = '$buf = ALLOC ( $size = CALL sizeof stat )'."\n";
  helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);  


  # Issue the stat command
  $cmdstr = 'CALL stat '."$file ".'$buf'."\n";
  helper::send_cmd($cmdfh, $outfh, "stat", $cmdstr);  
  helper::verify_cmd($cmdfh, $outfh, "stat");

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
  
  if ($use_system == 1) {
      # Now print the buffer out and verify that it matches
      # what Perl has
      verify_stat($cmdfh, $outfh, "stat", $is_alpha, $bits, @stats);
  }

  # Open the file
  $cmdstr = '$fd = CALL open '."$file O_RDONLY\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);  
  helper::verify_cmd($cmdfh, $outfh, "open");


  # Now issue an fstat call
  $cmdstr = 'CALL fstat $fd $buf'."\n";
  helper::send_cmd($cmdfh, $outfh, "fstat", $cmdstr);  
  helper::verify_cmd($cmdfh, $outfh, "fstat");

  if ($use_system == 1) {
      verify_stat($cmdfh, $outfh, "fstat", $is_alpha, $bits, @stats);
  }

  # Test lstat
  if ($use_system == 1) {
      @stats = lstat($file);
  }
  
  $cmdstr = 'CALL lstat '."$file ".'$buf'."\n";
  helper::send_cmd($cmdfh, $outfh, "lstat", $cmdstr);  
  helper::verify_cmd($cmdfh, $outfh, "lstat");

  if ($use_system == 1) {
      verify_stat($cmdfh, $outfh, "lstat", $is_alpha, $bits, @stats);
  }

  if (0) {
      # Now do statvfs functions
      $cmdstr = '$buf2 = ALLOC ( $size2 = CALL sizeof statvfs )'."\n";
      helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);
      
      # Clear out the buffer
      $cmdstr = 'CALL clear $buf2'."\n";
      helper::send_cmd($cmdfh, $outfh, "CLEAR", $cmdstr);
      
      $cmdstr = 'CALL statvfs '."$file ".'$buf2'."\n";
      helper::send_cmd($cmdfh, $outfh, "statvfs", $cmdstr);  
      helper::verify_cmd($cmdfh, $outfh, "statvfs");
		
      # Print out the statvfs buffer
      $cmdstr = 'PRINT $buf2 0 16 LONG 16 32 INT 48 16 LONG'."\n";
      helper::send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);
      
      my $res = <$outfh>;
      chop($res);
      my @vfsstats1 = split(' ', $res);
		
      # Clear out the buffer
      $cmdstr = 'CALL clear $buf2'."\n";
      helper::send_cmd($cmdfh, $outfh, "CLEAR", $cmdstr);
		
      # Now do fstatvfs
      $cmdstr = 'CALL fstatvfs $fd $buf2'."\n";
      helper::send_cmd($cmdfh, $outfh, "fstatvfs", $cmdstr);  
      helper::verify_cmd($cmdfh, $outfh, "fstatvfs");
      
      # Print out the statvfs buffer
      $cmdstr = 'PRINT $buf2 0 16 LONG 16 32 INT 48 16 LONG'."\n";
      helper::send_cmd($cmdfh, $outfh, "PRINT", $cmdstr);
      
      $res = <$outfh>;
      chop($res);
      my @vfsstats2 = split(' ', $res);
  
      # Verify the two vfsstats arrays match
      if (@vfsstats1 != @vfsstats2) {
	  helper::print_and_exit($cmdfh, $outfh, 1, "Two vfsstat arrays unequal lengths\n");
	}
      
      my $i=0;

      foreach my $stat1 (@vfsstats1) {
	  if ($stat1 ne $vfsstats2[$i++]) {
	      my $str = sprintf("vfsstats field %d are not equal (%s != %s)\n",
				$i-1, $stat1, $vfsstats2[$i-1]);
	      helper::print_and_exit($cmdfh, $outfh, 1, $str);
      }
      }
  }
  
  helper::print_and_exit($cmdfh, $outfh, 0, "stat test successful\n");
}




my $currarg = 0;
my $is_alpha = 0;
if (@ARGV < 2) {
  usage;
} elsif (@ARGV > 2) {
  if ($ARGV[$currarg++] eq "-alpha") {
    $is_alpha = 1;
  }
}

my $use_system= $ARGV[$currarg++];
my $file = $ARGV[$currarg];

process_cmd($file, $use_system, $is_alpha);

