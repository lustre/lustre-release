#!/usr/bin/perl -w

#
# copy test: Copy a file from src to dest and verify that the new file
#          : is the same as the old
#

use IPC::Open2;

use strict;
use FindBin;
use lib "$FindBin::Bin";
use helper;

sub usage
{
  print "Usage: ./test_copy.pl [-alpha] <src> <dest>: Copy a file from src to dest\n";
  exit(-1);
}

sub process_cmd
{
  my ($src, $dest, $overwrite, $is_alpha) = @_;
  
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

	# If reading from stdin, just read one line
	my $line;
	if ($src eq "/dev/stdin") {
		$line = <STDIN>;
		$size = length($line);
	}

  if ( $size > 1024) { # Arbitrary limit
    $bufsize = 1024;
  } else {
    $bufsize = $size;
  }

  my $cmdstr;
  # Open src 
	if ($src ne "/dev/stdin") {
		$cmdstr = '$src = CALL open '."$src O_RDONLY\n";
		helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);
		helper::verify_cmd($cmdfh, $outfh, "open $src");
	}
	if ($dest ne "/dev/stdout") {
		# Open dest
		my $flags = "O_WRONLY|O_CREAT";
		if ($overwrite == 0) {
			$flags .= "|O_EXCL";
		}
		$cmdstr = '$dest = CALL open '."$dest $flags 0777\n";
		helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);
		my $destfile = helper::verify_cmd($cmdfh, $outfh, "open $dest");
	}

  # Allocate buffer
  $cmdstr = '$buf = ALLOC '."$bufsize\n";
  helper::send_cmd($cmdfh, $outfh, "ALLOC", $cmdstr);

  # Read size bytes from src and write them out to dest
  my $bytes = $size;
  while ($bytes > 0) {

		my $readb;
		my $res;
		if ($src eq "/dev/stdin") {
			 # Send "delay" option to read which will give us time to 
			# put something in stdin (since we can't send an eof)
			my $cmdstr = "CALL read ".'0 $buf '."$bytes delay\n";
			print $cmdfh $cmdstr;
			# Give time to process command
			sleep 1;

			# Send line from stdin
			print $cmdfh $line;
			sleep 0.5;
 
      # Make sure read was OK
			$res = <$outfh>;
			chop($res);
			if ($res ne "0000 ") {
				helper::print_and_exit($cmdfh, $outfh, 1, "ERROR! Read failed with code $res\n");
			}
    
			# See how many bytes we got...
			$readb = helper::verify_cmd($cmdfh, $outfh, "read");
			$readb = oct($readb);
			if ($readb != $bytes) {
				helper::print_and_exit($cmdfh, $outfh, 0, "Short read\n");
			}

			if ($dest eq "/dev/stdout") {
				$cmdstr = "CALL write ".'1 $buf '."$readb\n";
			} else {
				$cmdstr = "CALL write ".'$dest $buf '."$readb\n";
			}
			print $cmdfh $cmdstr;

			# Suck up the stdout...
			$res = <$outfh>;
			chop($res);
  
			$res = <$outfh>;
			chop($res);
			$res = oct($res);

			if ($res != 0) {
				helper::print_and_exit($cmdfh, $outfh, 1, "ERROR! Write failed with code $res\n");
				}
		} else {
			$cmdstr = 'CALL read $src $buf '."$bufsize\n";
			helper::send_cmd($cmdfh, $outfh, "read", $cmdstr);
    
			$res = helper::verify_cmd($cmdfh, $outfh, "read");
			$readb = oct($res);

			# Now write $readb back out to dest
			$cmdstr = 'CALL write $dest $buf '."$readb\n";
			helper::send_cmd($cmdfh, $outfh, "write", $cmdstr);
    }

    $res = helper::verify_cmd($cmdfh, $outfh, "write");

    if ($readb != oct($res)) {
      print STDOUT "ERROR!  Read $readb bytes but got back $res bytes\n";
      exit 1;
    }

    $bytes -= $readb;
  } 
   
  # Clean up
	if ($src ne "/dev/stdin") {
		$cmdstr = 'CALL close $src'."\n";
		helper::send_cmd($cmdfh, $outfh, "close", $cmdstr);
	}
	if ($dest ne "/dev/stdout") {
		$cmdstr = 'CALL close $dest'."\n";
		helper::send_cmd($cmdfh, $outfh, "close", $cmdstr);
	}
	if ($src ne "/dev/stdin") {
		my $cmd = "cmp $src $dest " . '2>&1';
		my $cmpstr = qx($cmd);
		my $exitval = $? >> 8;
		if ($exitval != 0) {
			if ($exitval == 1) {
				print STDOUT "ERROR! File $src differs from $dest\n";
				print STDOUT "Comparison returned $cmpstr";
			} else {
				print STDOUT "ERROR! File comparison failed with msg $cmpstr";
			}
			exit 1;
		}
	}
  helper::print_and_exit($cmdfh, $outfh, 0, "copy test successful\n");
}

my $currarg = 0;
my $is_alpha = 0;
my $overwrite = 0;

my $len = @ARGV-2;

if (@ARGV < 2) {
  usage;
} 

my $i;
for ($i=0; $i < $len; $i++ ) {
  if ($ARGV[$i] eq "-alpha") {
    $is_alpha = 1;
  }
	if ($ARGV[$i] eq "-o") {
		$overwrite = 1;
	}
}

my $src = $ARGV[$i++];
my $dest = $ARGV[$i];


process_cmd($src, $dest, $overwrite, $is_alpha);


exit 0;
