#!/usr/bin/perl -w

#
# strided IO test: Perform a series of different reads/writes
#                  using readx and writex with different buffer
#                  configurations 
#

use IPC::Open2;

use strict;
use FindBin;
use lib "$FindBin::Bin";
use helper;

sub usage
{
  print "Usage: ./test_rw.pl [-alpha] <file>: Write to/read from file\n";
  exit(-1);
}

sub verify_result
{
	my ($cmdfh, $outfh, $cmdstr, $exp_val, $eq_op) = @_;
	my $print_err = 0;

	my $res = helper::verify_cmd($cmdfh, $outfh, $cmdstr);
	$res = oct($res);

	if ($eq_op eq "!=") {
		if ($res != $exp_val) {
			print STDOUT "Error! $cmdstr returned $res insted of $exp_val\n";
			system("killall test_driver");
			exit(1);
		}
	} else {
		if ($eq_op eq ">") {
			if ($res > $exp_val) {
				$print_err = 1;
			}
		} elsif ($eq_op eq "<")  {
			if ($res < $exp_val) {
				$print_err = 1;
			}
		} elsif ($eq_op eq "==") {
			if ($res == $exp_val) {
				$print_err = 1;
			}
		}
		if ($print_err == 1) {
			print STDOUT "Error! $cmdstr returned $res\n";
		}
	}

}

# Initilize the iovec number $vecnum
# in the iovec buffer $vecname with buffer
# pos $buf and using len $veclen
sub set_iovec
{
	my ($cmdfh, $outfh, $vecname, $vecnum, $buf, $veclen) = @_;

	my $cmdstr = 'CALL init_iovec $'.$buf." 0 $veclen ";
	$cmdstr .= "$vecnum ".'$'."$vecname\n";

	helper::send_cmd($cmdfh, $outfh, "init_iovec", $cmdstr);
	helper::verify_cmd($cmdfh, $outfh, "init_iovec");
}


sub setup_xtvecs
{
	my ($cmdfh, $outfh) = @_;

	# Get size of iovecs
	my $cmdstr = '$xtvsize = CALL sizeof xtvec'."\n";
	helper::send_cmd($cmdfh, $outfh, "sizeof", $cmdstr);
	my $size = helper::verify_cmd($cmdfh, $outfh, "sizeof xtvec");
	$size = oct($size);
	$size = $size * 2;

	# Allocate iovec buffer
	$cmdstr = '$xtvbuf'." = ALLOC $size\n";
	helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);
	

	# Now initilize xtvbuf
	$cmdstr = "CALL init_xtvec 0 100 0 ". '$xtvbuf'."\n";
	helper::send_cmd($cmdfh, $outfh, "init_xtvec", $cmdstr);
	helper::verify_cmd($cmdfh, $outfh, "init_xtvec");

	$cmdstr = "CALL init_xtvec 1000 100 1 ". '$xtvbuf'."\n";
	helper::send_cmd($cmdfh, $outfh, "init_xtvec", $cmdstr);
	helper::verify_cmd($cmdfh, $outfh, "init_xtvec");
}

sub check_buf
{

	my ($cmdfh, $outfh, $bufsize, $bufname, 
			$readcmd, $digit, $offset) = @_;
	
	my $cmdstr = 'CALL checkbuf $'. "$bufname $bufsize $digit $offset\n";
	helper::send_cmd($cmdfh, $outfh, "checkbuf", $cmdstr);
	my $res = helper::verify_cmd($cmdfh, $outfh, "checkbuf");
	$res = oct($res);

	if ($res != 0) {
		print STDOUT "$readcmd did not return all $digit 's\n";
} 
}

# Fill given buffer with $digit up to $size
# starting at $offset
sub fill_buf
{
	my ($cmdfh, $outfh, $buf, $digit, $size, $off) = @_;

	my $cmdstr = "CALL setbuf $digit $size ".'$'."$buf $off\n";
	helper::send_cmd($cmdfh, $outfh, "setbuf", $cmdstr);		
}

sub alloc_iovbuf
{
	my ($cmdfh, $outfh, $numbufs, $num) = @_;

	# Get size of iovecs
	my $cmdstr = '$iovsize = CALL sizeof iovec'."\n";
	helper::send_cmd($cmdfh, $outfh, "sizeof", $cmdstr);
	my $size = helper::verify_cmd($cmdfh, $outfh, "sizeof iovec");
	$size = oct($size);
	$size = $size * $numbufs;

	# Allocate iovec buffer
	$cmdstr = '$iovbuf'."$num = ALLOC $size\n";
	helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);

	my $retstr = "iovbuf".$num;
	
	return $retstr;
}

sub do_rwcalls
{
	my ($cmdfh, $outfh, $fh) = @_;

	# Allocate and initilize xtvecs
	setup_xtvecs($cmdfh, $outfh);

	# Allocate 2 different iovecs, one for cases
	# (a) and (d) and one for cases (b) and (c)
	my $iovbuf1 = alloc_iovbuf($cmdfh, $outfh, 3, 0);
	my $iovbuf2 = alloc_iovbuf($cmdfh, $outfh, 1, 1);
	
	# Allocate four buffers, each 200 bytes long
	my $cmdstr = '$buf1 '. "= ALLOC 200\n";
	helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);
	$cmdstr = '$buf2 '. "= ALLOC 200\n";
	helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);
	$cmdstr = '$buf3 '. "= ALLOC 200\n";
	helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);
	$cmdstr = '$buf4 '. "= ALLOC 200\n";
	helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);
	
	# Case (a):
	#  xtvec[] = { { 0, 100 }, {1000, 100} }
	#  iovec[] = { { buf1, 50}, {buf2, 50}, {buf3, 100}

	# Fill each of the 3 buffers of.  They will be filled
	# as follows:
	#  buf1 -->    0- 49:  1
	#       -->   49-200:  2
	#  buf2 -->    0- 49:  3
	#       -->   49-200:  4
	#  buf3 -->    0-100:  5
	#       -->  100-200:  6
	fill_buf($cmdfh, $outfh, "buf1", 1, 50, 0);
	fill_buf($cmdfh, $outfh, "buf1", 2, 150, 50);
	fill_buf($cmdfh, $outfh, "buf2", 3, 50, 0);
	fill_buf($cmdfh, $outfh, "buf2", 4, 150, 50);
	fill_buf($cmdfh, $outfh, "buf3", 5, 100, 0);
	fill_buf($cmdfh, $outfh, "buf3", 6, 100, 100);

	# Initiize iovecs
	set_iovec($cmdfh, $outfh, $iovbuf1, 0, "buf1", 50);
	set_iovec($cmdfh, $outfh, $iovbuf1, 1, "buf2", 50);
	set_iovec($cmdfh, $outfh, $iovbuf1, 2, "buf3", 100);

	# Write out to $fh
	$cmdstr = 'CALL writex $'."$fh $iovbuf1 3 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "writex", $cmdstr);
	verify_result($cmdfh, $outfh, "writex (case a)", 200, "!=");

	# Clear out the buffers
	fill_buf($cmdfh, $outfh, "buf1", 0, 200, 0);
	fill_buf($cmdfh, $outfh, "buf2", 0, 200, 0);
	fill_buf($cmdfh, $outfh, "buf3", 0, 200, 0);

	# Read it back
	$cmdstr = 'CALL readx $'."$fh $iovbuf1 3 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "readx", $cmdstr);
	verify_result($cmdfh, $outfh, "readx (case a)", 200, "!=");

	# Make sure we got what we expected...
	check_buf($cmdfh, $outfh, 50, "buf1", "readx (case a)", 1, 0);
	check_buf($cmdfh, $outfh, 50, "buf2", "readx (case a)", 3, 0);
	check_buf($cmdfh, $outfh, 100, "buf3", "readx (case a)", 5, 0);

  # Case (b):
	#  xtvec[] = { { 0, 100 }, {1000, 100} }
	#  iovec[] = { { buf4, 200} }


	# Fill buf4 with 7's...
	fill_buf($cmdfh, $outfh, "buf4", 7, 200, 0);

	# Initiize iovecs
	set_iovec($cmdfh, $outfh, $iovbuf2, 0, "buf4", 200);

	# Write out to $fh
	$cmdstr = 'CALL writex $'."$fh ".'$'."$iovbuf2 1 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "writex", $cmdstr);
	verify_result($cmdfh, $outfh, "writex (case b)", 200, "!=");

	# Clear out the buffer
	fill_buf($cmdfh, $outfh, "buf4", 0, 200, 0);

	# Read it back
	$cmdstr = 'CALL readx $'."$fh $iovbuf2 1 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "readx", $cmdstr);
	verify_result($cmdfh, $outfh, "readx (case b)", 200, "!=");

	# Make sure we got what we expected...
	check_buf($cmdfh, $outfh, 200, "buf4", "readx (case b)", 7, 0);


	# Case (c):
	#  xtvec[] = { { 0, 100 }, {1000, 100} }
	#  iovec[] = { { buf4, 40} }

	# Fill buf4 with 8's...
	fill_buf($cmdfh, $outfh, "buf4", 8, 200, 0);

	# Initiize iovecs
	set_iovec($cmdfh, $outfh, $iovbuf2, 0, "buf4", 40);

	# Write out to $fh
	$cmdstr = 'CALL writex $'."$fh $iovbuf2 1 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "writex", $cmdstr);
	verify_result($cmdfh, $outfh, "writex (case c)", 40, "!=");

	# Clear out the buffer
	fill_buf($cmdfh, $outfh, "buf4", 0, 200, 0);

	# Read it back
	$cmdstr = 'CALL readx $'."$fh $iovbuf2 1 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "readx", $cmdstr);
	verify_result($cmdfh, $outfh, "readx (case c)", 40, "!=");

	# Make sure we got what we expected...
	check_buf($cmdfh, $outfh, 40, "buf4", "readx (case c)", 8, 0);


	# Case (d):
	#  xtvec[] = { { 0, 100 }, {1000, 100} }
	#  iovec[] = { { buf1, 40}, {buf2, 150}, {buf3, 200} }

	# Fill each of the 3 buffers of.  They will be filled
	# as follows:
	#  buf1 -->    0- 39:  1
	#       -->   39-200:  2
	#  buf2 -->    0-150:  3
	#       -->  150-200:  4
	#  buf3 -->    0-  9:  5
	#       -->   10-200:  6
	fill_buf($cmdfh, $outfh, "buf1", 1, 40, 0);
	fill_buf($cmdfh, $outfh, "buf1", 2, 160, 40);
	fill_buf($cmdfh, $outfh, "buf2", 3, 150, 0);
	fill_buf($cmdfh, $outfh, "buf2", 4, 50, 150);
	fill_buf($cmdfh, $outfh, "buf3", 5, 10, 0);
	fill_buf($cmdfh, $outfh, "buf3", 6, 190, 10);

	# Initiize iovecs
	set_iovec($cmdfh, $outfh, $iovbuf1, 0, "buf1", 40);
	set_iovec($cmdfh, $outfh, $iovbuf1, 1, "buf2", 150);
	set_iovec($cmdfh, $outfh, $iovbuf1, 2, "buf3", 200);

	# Write out to $fh
	$cmdstr = 'CALL writex $'."$fh $iovbuf1 3 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "writex", $cmdstr);
	verify_result($cmdfh, $outfh, "writex (case d)", 200, "!=");

	# Clear out the buffers
	fill_buf($cmdfh, $outfh, "buf1", 0, 200, 0);
	fill_buf($cmdfh, $outfh, "buf2", 0, 200, 0);
	fill_buf($cmdfh, $outfh, "buf3", 0, 200, 0);

	# Read it back
	$cmdstr = 'CALL readx $'."$fh $iovbuf1 3 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "readx", $cmdstr);
	verify_result($cmdfh, $outfh, "readx (case d)", 200, "!=");

	# Make sure we got what we expected...
	check_buf($cmdfh, $outfh, 40, "buf1", "readx (case d)", 1, 0);
	check_buf($cmdfh, $outfh, 150, "buf2", "readx (case d)", 3, 0);
	check_buf($cmdfh, $outfh, 10, "buf3", "readx (case d)", 5, 0);

	# Case (e):
  #  xtvec[] = { { 0, 100 }, {1000, 100} }
  #  iovec[] = { { buf1, 30}, {buf2, 30}, {buf3, 30} }

	# Fill each of the 3 buffers as follows:
	# buf1 -->   0- 30: 1
	#      -->  30-200: 2
	# buf2 -->   0- 30: 3
	#      -->  30-200: 4
	# buf3 -->   0- 30: 5
	#      -->  30-200: 6
	fill_buf($cmdfh, $outfh, "buf1", 1, 30, 0);
	fill_buf($cmdfh, $outfh, "buf1", 2, 170, 30);
	fill_buf($cmdfh, $outfh, "buf2", 3, 30, 0);
	fill_buf($cmdfh, $outfh, "buf2", 4, 170, 30);
	fill_buf($cmdfh, $outfh, "buf3", 5, 30, 0);
	fill_buf($cmdfh, $outfh, "buf3", 6, 170, 30);

		# Initiize iovecs
	set_iovec($cmdfh, $outfh, $iovbuf1, 0, "buf1", 30);
	set_iovec($cmdfh, $outfh, $iovbuf1, 1, "buf2", 30);
	set_iovec($cmdfh, $outfh, $iovbuf1, 2, "buf3", 30);

	# Write out to $fh
	$cmdstr = 'CALL writex $'."$fh $iovbuf1 3 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "writex", $cmdstr);
	verify_result($cmdfh, $outfh, "writex (case e)", 90, "!=");

	# Clear out the buffers
	fill_buf($cmdfh, $outfh, "buf1", 0, 200, 0);
	fill_buf($cmdfh, $outfh, "buf2", 0, 200, 0);
	fill_buf($cmdfh, $outfh, "buf3", 0, 200, 0);

	# Read it back
	$cmdstr = 'CALL readx $'."$fh $iovbuf1 3 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "readx", $cmdstr);
	verify_result($cmdfh, $outfh, "readx (case e)", 90, "!=");

	# Make sure we got what we expected...
	check_buf($cmdfh, $outfh, 30, "buf1", "readx (case e)", 1, 0);
	check_buf($cmdfh, $outfh, 30, "buf2", "readx (case e)", 3, 0);
	check_buf($cmdfh, $outfh, 30, "buf3", "readx (case e)", 5, 0);
	
  # Case (f):
  #  xtvec[] = { { 0, 100 }, {1000, 100} }
  #  iovec[] = { { buf1, 30}, {buf2, 90}, {buf3, 200} }

	# Fill each of the 3 buffers as follows:
	# buf1 -->   0- 30: 1
	#      -->  30-200: 2
	# buf2 -->   0- 70: 3
  #      -->  70- 90: 4
 	#      -->  90-200: 5
	# buf3 -->   0-200: 6
	fill_buf($cmdfh, $outfh, "buf1", 1, 30, 0);
	fill_buf($cmdfh, $outfh, "buf1", 2, 170, 30);
	fill_buf($cmdfh, $outfh, "buf2", 3, 70, 0);
	fill_buf($cmdfh, $outfh, "buf2", 4, 90, 70);
	fill_buf($cmdfh, $outfh, "buf2", 5, 110, 90);
	fill_buf($cmdfh, $outfh, "buf3", 6, 200, 0);

		# Initiize iovecs
	set_iovec($cmdfh, $outfh, $iovbuf1, 0, "buf1", 30);
	set_iovec($cmdfh, $outfh, $iovbuf1, 1, "buf2", 90);
	set_iovec($cmdfh, $outfh, $iovbuf1, 2, "buf3", 200);

	# Write out to $fh
	$cmdstr = 'CALL writex $'."$fh $iovbuf1 3 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "writex", $cmdstr);
	verify_result($cmdfh, $outfh, "writex (case f)", 200, "!=");

	# Clear out the buffers
	fill_buf($cmdfh, $outfh, "buf1", 0, 200, 0);
	fill_buf($cmdfh, $outfh, "buf2", 0, 200, 0);
	fill_buf($cmdfh, $outfh, "buf3", 0, 200, 0);

	# Read it back
	$cmdstr = 'CALL readx $'."$fh $iovbuf1 3 ".'$xtvbuf '."2\n";
	helper::send_cmd($cmdfh, $outfh, "readx", $cmdstr);
	verify_result($cmdfh, $outfh, "readx (case f)", 200, "!=");

	# Make sure we got what we expected...
	check_buf($cmdfh, $outfh, 30, "buf1", "readx (case f)", 1, 0);
	check_buf($cmdfh, $outfh, 70, "buf2", "readx (case f)", 3, 0);
	check_buf($cmdfh, $outfh, 20, "buf2", "readx (case f)", 4, 70);
	check_buf($cmdfh, $outfh, 70, "buf3", "readx (case f)", 6, 0);
	
}


sub process_cmd
{
  my ($file, $is_alpha) = @_;
  
  # Get tests directory
  my $testdir = $FindBin::Bin;

  eval {
      if ($is_alpha == 0) {
					open2(\*OUTFILE, \*CMDFILE, "$testdir/test_driver --np");
      } else {
					open2(\*OUTFILE, \*CMDFILE, 
								"yod -quiet -sz 1 $testdir/test_driver --np");
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
  
  # Open file
  my $cmdstr = '$fd = CALL open '."$file O_RDWR|O_CREAT|O_TRUNC S_IRWXU\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);
	helper::verify_cmd($cmdfh, $outfh, $cmdstr);

   
	do_rwcalls($cmdfh, $outfh, "fd");

  # Clean up
  $cmdstr = 'CALL close $fd'."\n";
  helper::send_cmd($cmdfh, $outfh, "close", $cmdstr);

#	system("rm -f $file");
  helper::print_and_exit($cmdfh, $outfh, 0, "strided IO test successful\n");
}

my $currarg = 0;
my $is_alpha = 0;

if (@ARGV < 1) {
  usage;
} elsif (@ARGV > 1 ) {
  if ($ARGV[$currarg++] eq "-alpha") {
    $is_alpha = 1;
  }
}

my $file = $ARGV[$currarg];

process_cmd($file, $is_alpha);

exit 0;
