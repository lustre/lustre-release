#!/usr/bin/perl -w

#
# rw test: Write a buffer out using all the different writes, read it back
#          and make sure it matches
# 
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
			exit 1;
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
			helper::print_and_exit($cmdfh, $outfh, 1, "Error! $cmdstr returned $res\n");
		}
	}
}
		
sub do_iowait
{
	my ($cmdfh, $outfh, $id, $rwcmd, $exp_size) = @_;

	my $cmdstr = "CALL iowait $id\n";
	helper::send_cmd($cmdfh, $outfh, "iowait", $cmdstr);

	my $descstr = "iowait:$rwcmd";
	verify_result($cmdfh, $outfh, $descstr, $exp_size, "!=");
}

sub set_iovecs
{
	my ($cmdfh, $outfh, $callnum) = @_;
	my $NUMVECS = 8;
	my $VECLEN = $NUMVECS * 1024;

	my $varname = "iovbuf$callnum";

	# Get size of iovecs
	my $cmdstr = '$iovsize = CALL sizeof iovec'."\n";
	helper::send_cmd($cmdfh, $outfh, "sizeof", $cmdstr);
	my $size = helper::verify_cmd($cmdfh, $outfh, "sizeof iovec");
	$size = oct($size);
	$size = $size * $NUMVECS;

	# Allocate iovec buffer
	$cmdstr = '$'."$varname = ALLOC $size\n";
	helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);
	

	# Now initilize all of them
	my $off = 0;
	for (my $i=0; $i < $NUMVECS; $i++) {
		$cmdstr = 'CALL init_iovec $buf '."$off $VECLEN $i ". '$'."$varname\n";
		helper::send_cmd($cmdfh, $outfh, "init_iovec", $cmdstr);
		helper::verify_cmd($cmdfh, $outfh, "init_iovec");
		$off += $VECLEN;
	}

	return $varname;
}


sub set_xtvecs
{
	my ($cmdfh, $outfh, $callnum, $startoff) = @_;
	my $VECLEN = 4 * 8 * 1024;

	my $varname = "xtvbuf$callnum";

	# Get size of iovecs
	my $cmdstr = '$xtvsize = CALL sizeof xtvec'."\n";
	helper::send_cmd($cmdfh, $outfh, "sizeof", $cmdstr);
	my $size = helper::verify_cmd($cmdfh, $outfh, "sizeof xtvec");
	$size = oct($size);
	$size = $size * 2;

	# Allocate iovec buffer
	$cmdstr = '$'."$varname = ALLOC $size\n";
	helper::send_cmd($cmdfh, $outfh, "alloc", $cmdstr);
	

	# Now initilize all of them
	my $off = $startoff;
	for (my $i=0; $i < 2; $i++) {
		$cmdstr = "CALL init_xtvec $off $VECLEN $i ". '$'."$varname\n";
		helper::send_cmd($cmdfh, $outfh, "init_xtvec", $cmdstr);
		helper::verify_cmd($cmdfh, $outfh, "init_xtvec");
		$off += $VECLEN;
	}

	return $varname;
}

sub check_buf
{

	my ($cmdfh, $outfh, $bufsize, $readcmd) = @_;
	my $i;
	my $digit = 0;
	my $offset = 0;
	my $cmdstr;

	for ($i =0; $i < 64; $i++) {
		$cmdstr = 'CALL checkbuf $buf'. " 1024 $digit $offset\n";
		helper::send_cmd($cmdfh, $outfh, "checkbuf", $cmdstr);
		my $res = helper::verify_cmd($cmdfh, $outfh, "checkbuf");
		$res = oct($res);

		if ($res != 0) {
			print STDOUT "Checkbuf returned $res\n";
			helper::print_and_exit($cmdfh, $outfh, 1, "$readcmd did not return all $digit 's\n");
		} 
	
		$offset += 1024;
		$digit++;
		if ($digit == 10) {
			$digit = 0;
		}
	}

	# Now fill the buffer with 0s
	$cmdstr = '$buf = CALL setbuf 0 '."$bufsize ".'$buf'." 0\n";
  helper::send_cmd($cmdfh, $outfh, "setbuf", $cmdstr);
	
}

sub fill_buf
{
	my ($cmdfh, $outfh) = @_;
	my $i;
	my $digit=0;
	my $cmdstr;
	my $offset = 0;

	# Fill up the buffer with alternating digits
	# from 0-9

	for ($i=0; $i < 64 ; $i++) {
		my $cmdstr = "CALL setbuf $digit 1024 ".'$buf'." $offset\n";
		helper::send_cmd($cmdfh, $outfh, "setbuf", $cmdstr);		
		$offset += 1024;
		$digit++;
		if ($digit == 10) {
			$digit = 0;
		}
	}
}

sub do_rwcalls
{
		my ($cmdfh, $outfh, $bufsize) = @_;
		my $IOID_FAIL = 0;
		my $NUMVECS = 8;

		# Initilize buffer
		fill_buf($cmdfh, $outfh);

		# write 64K bytes at pos 0
		my $cmdstr = 'CALL write $fd $buf '."$bufsize\n";
		helper::send_cmd($cmdfh, $outfh, "write", $cmdstr);
		verify_result($cmdfh, $outfh, "write", $bufsize, "!=");

		# Initilize buffer
		fill_buf($cmdfh, $outfh);

		# iwrite 64K bytes at pos 64K
		$cmdstr = '$id1 = CALL iwrite $fd $buf '."$bufsize\n";
		helper::send_cmd($cmdfh, $outfh, "iwrite", $cmdstr);
		verify_result($cmdfh, $outfh, "iwrite", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id1', "iwrite", $bufsize);
		
		# Set up the iovecs
		my $iovcnt = 0;
		my $iovname = set_iovecs($cmdfh, $outfh, $iovcnt);

		# Initilize buffer
		fill_buf($cmdfh, $outfh);
		
		# writev 64K bytes using 8 iovecs at pos 128K
		$cmdstr = 'CALL writev $fd $'."$iovname $NUMVECS\n";
		helper::send_cmd($cmdfh, $outfh, "writev", $cmdstr);
		verify_result($cmdfh, $outfh, "writev", $bufsize, "!=");

		# Initilize buffer
		fill_buf($cmdfh, $outfh);
		
		# iwritev 64K bytes using 8 iovecs at pos 192K
		$cmdstr = '$id2 = CALL iwritev $fd $'."$iovname $NUMVECS\n";
		helper::send_cmd($cmdfh, $outfh, "iwritev", $cmdstr);
		verify_result($cmdfh, $outfh, "iwritev", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id2', "iwritev", $bufsize);

		# Initilize buffer
		fill_buf($cmdfh, $outfh);

		# pwrite 64K bytes starting at pos 256K
		my $offset = 256 * 1024;
		$cmdstr = 'CALL pwrite $fd $buf '."$bufsize $offset\n";
		helper::send_cmd($cmdfh, $outfh, "pwrite", $cmdstr);
		verify_result($cmdfh, $outfh, "pwrite", $bufsize, "!=");
		
		# Initilize buffer
		fill_buf($cmdfh, $outfh);

		# ipwrite 64K bytes starting at pos 320K
		$offset = 320 * 1024;
		$cmdstr = '$id3 = CALL ipwrite $fd $buf '."$bufsize $offset\n";
		helper::send_cmd($cmdfh, $outfh, "ipwrite", $cmdstr);
		verify_result($cmdfh, $outfh, "ipwrite", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id3', "ipwrite", $bufsize);

		$iovcnt++;

		# Initilize buffer
		fill_buf($cmdfh, $outfh);

		# pwritev using 8 8K buffers at offset 384
		$offset = 384 * 1024;
		$cmdstr = 'CALL pwritev $fd $'."$iovname $NUMVECS $offset\n";
		helper::send_cmd($cmdfh, $outfh, "pwritev", $cmdstr);
		verify_result($cmdfh, $outfh, "pwritev", $bufsize, "!=");	

		# Initilize buffer
		fill_buf($cmdfh, $outfh);

		# ipwritev using 8 8k buffers at offset 448
		$offset = 448 * 1024;
		$cmdstr = '$id4 = CALL ipwritev $fd $'."$iovname $NUMVECS $offset\n";
		helper::send_cmd($cmdfh, $outfh, "ipwritev", $cmdstr);
		verify_result($cmdfh, $outfh, "ipwritev", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id4', "ipwritev", $bufsize);

		# Set up the xtvecs.  Starting offset is 512K
		my $xtvcnt = 0;
		my $xtvname = set_xtvecs($cmdfh, $outfh, $xtvcnt, 512 * 1024);

		$iovcnt++;

		# Initilize buffer
		fill_buf($cmdfh, $outfh);
		
		# Call writex using 8 8k buffers at offset 512
		$cmdstr = 'CALL writex $fd $'."$iovname $NUMVECS ".'$'."$xtvname 2\n";
		helper::send_cmd($cmdfh, $outfh, "writex", $cmdstr);
		verify_result($cmdfh, $outfh, "writex", $bufsize, "!=");

		# Call iwritex using 8 8k buffers starting at offset 576
		# Re-setup xtvs since I am lazy.  This is leaking memory like
		# a seive...
		$xtvcnt++;
		$xtvname = set_xtvecs($cmdfh, $outfh, $xtvcnt, 576 * 1024);

		$iovcnt++;

		# Initilize buffer
		fill_buf($cmdfh, $outfh);

		$cmdstr = '$id5 = CALL iwritex $fd $'."$iovname $NUMVECS ".'$'."$xtvname 2\n";
		helper::send_cmd($cmdfh, $outfh, "iwritex", $cmdstr);
		verify_result($cmdfh, $outfh, "iwritex", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id5', "iwritex", $bufsize);

		# Now do the reads

		# Lseek back to pos 0
		$cmdstr = 'CALL lseek $fd 0 SEEK_SET'."\n";
		helper::send_cmd($cmdfh, $outfh, "sizeof", $cmdstr);
		helper::verify_cmd($cmdfh, $outfh, "sizeof xtvec");

		# fill the buffer with 0's
		$cmdstr = '$buf = CALL setbuf 0 '."$bufsize ".'$buf'." 0\n";
		helper::send_cmd($cmdfh, $outfh, "setbuf", $cmdstr);

		# read 64K bytes from pos 0
		$cmdstr = 'CALL read $fd $buf '."$bufsize\n";
		helper::send_cmd($cmdfh, $outfh, "read", $cmdstr);
		verify_result($cmdfh, $outfh, "read", $bufsize, "!=");

		# Check the buffer to make sure it matches
		check_buf($cmdfh, $outfh, $bufsize, "read");

		# iread 64K bytes at pos 64K
		$cmdstr = '$id6 = CALL iread $fd $buf '."$bufsize\n";
		helper::send_cmd($cmdfh, $outfh, "iread", $cmdstr);
		verify_result($cmdfh, $outfh, "iread", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id6', "iread", $bufsize);
		check_buf($cmdfh, $outfh, $bufsize, "iread");

		$iovcnt++;

		# readv 64K bytes using 8 iovecs at pos 128K
		$cmdstr = 'CALL readv $fd $'."$iovname $NUMVECS\n";
		helper::send_cmd($cmdfh, $outfh, "readv", $cmdstr);
		verify_result($cmdfh, $outfh, "readv", $bufsize, "!=");
		check_buf($cmdfh, $outfh, $bufsize, "readv");		

		# ireadv 64K bytes using 8 iovecs at pos 192K
		$cmdstr = '$id7 = CALL ireadv $fd $'."$iovname $NUMVECS\n";
		helper::send_cmd($cmdfh, $outfh, "ireadv", $cmdstr);
		verify_result($cmdfh, $outfh, "ireadv", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id7', "ireadv", $bufsize);
		check_buf($cmdfh, $outfh, $bufsize, "ireadv");

		# pread64K bytes starting at pos 256K
		$offset = 256 * 1024;
		$cmdstr = 'CALL pread $fd $buf '."$bufsize $offset\n";
		helper::send_cmd($cmdfh, $outfh, "pread", $cmdstr);
		verify_result($cmdfh, $outfh, "pread", $bufsize, "!=");
		check_buf($cmdfh, $outfh, $bufsize, "pread");
		
		# ipread 64K bytes starting at pos 320K
		$offset = 320 * 1024;
		$cmdstr = '$id8 = CALL ipread $fd $buf '."$bufsize $offset\n";
		helper::send_cmd($cmdfh, $outfh, "ipread", $cmdstr);
		verify_result($cmdfh, $outfh, "ipread", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id8', "ipread", $bufsize);
		check_buf($cmdfh, $outfh, $bufsize, "ipread");


		$iovcnt++;

		# preadv using 8 8K buffers at offset 384
		$offset = 384 * 1024;
		$cmdstr = 'CALL preadv $fd $'."$iovname $NUMVECS $offset\n";
		helper::send_cmd($cmdfh, $outfh, "preadv", $cmdstr);
		verify_result($cmdfh, $outfh, "preadv", $bufsize, "!=");	
		check_buf($cmdfh, $outfh, $bufsize, "preadv");
		
		# ipreadv using 8 8k buffers at offset 448
		$offset = 448 * 1024;
		$cmdstr = '$id9 = CALL ipreadv $fd $'."$iovname $NUMVECS $offset\n";
		helper::send_cmd($cmdfh, $outfh, "ipreadv", $cmdstr);
		verify_result($cmdfh, $outfh, "ipreadv", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id9', "ipreadv", $bufsize);
		check_buf($cmdfh, $outfh, $bufsize, "ipreadv");

		# Set up the xtvecs.  Starting offset is 512K
		$xtvcnt++;
		$xtvname = set_xtvecs($cmdfh, $outfh, $xtvcnt, 512 * 1024);

		$iovcnt++;
		
		# Call readx using 8 8k buffers at offset 512
		$cmdstr = 'CALL readx $fd $'."$iovname $NUMVECS ".'$'."$xtvname 2\n";
		helper::send_cmd($cmdfh, $outfh, "readx", $cmdstr);
		verify_result($cmdfh, $outfh, "readx", $bufsize, "!=");
		check_buf($cmdfh, $outfh, $bufsize, "readx");

		# Call ireadx using 8 8k buffers starting at offset 576
		# Re-setup xtvs since I am lazy.  This is leaking memory like
		# a seive...
		$xtvcnt++;
		$xtvname = set_xtvecs($cmdfh, $outfh, $xtvcnt, 576 * 1024);

		$iovcnt++;

		$cmdstr = '$id10 = CALL ireadx $fd $'."$iovname $NUMVECS ".'$'."$xtvname 2\n";
		helper::send_cmd($cmdfh, $outfh, "ireadx", $cmdstr);
		verify_result($cmdfh, $outfh, "ireadx", $IOID_FAIL, "==");
		do_iowait($cmdfh, $outfh, '$id10', "ireadx", $bufsize);
		check_buf($cmdfh, $outfh, $bufsize, "ireadx");
}


sub check_array
{
	my ($exp_digit, @arr) = @_;
	my $exp_char;
	my $pos = 0;

	if ($exp_digit == 0) {
		$exp_char = "\\0";
	} elsif ($exp_digit < 7) {
		$exp_char = "00".$exp_digit;
	} elsif ($exp_digit == 7) {
		$exp_char = "\\a";
	} elsif ($exp_digit == 8) {
		$exp_char = "\\b";
	} elsif ($exp_digit == 9) {
		$exp_char = "\\t";
	} else {
		print STDERR "Invalid expected digit $exp_digit\n";
		return(1);
	}

	foreach my $str (@arr) {
		if ($str ne $exp_char) {
			print STDERR "At pos $pos got digit $str instead of $exp_char\n";
			return(1);
		}
		$pos++;
	}

	return(0);
}

# Perform an od on the output and verify that the output makes
# sense
sub od_verify
{
	my ($cmdfh, $outfh, $file) = @_;
	my $exp_digit = 0;

	# Do an od in order to verify the contents of the file
	system("od -c $file > tmp.out.$$");
	open(ODFILE, "<tmp.out.$$") || 
			helper::print_and_exit($cmdfh, $outfh, 1, "Unable to open tmp.out.$$\n");

	while (<ODFILE>) {
		if (/^\*/) {
			# Do nothing...
		} else {
			my ($lineno, @nums) = split($_);
			if (check_array($exp_digit, @nums) != 0) {
				helper::print_and_exit($cmdfh, $outfh, 1, "At line $lineno, got unexpected result\n");
			}
			if ($exp_digit < 9) {
				$exp_digit ++;
			} else {
				$exp_digit = 0;
			}
		}
	}

	close(ODFILE);
	system("rm -f tmp.out.$$");
}

sub process_cmd
{
  my ($file, $is_alpha) = @_;
  
  # Get tests directory
  my $testdir = $FindBin::Bin;
	my $bufsize = 65536;

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
  
  # Open file
  my $cmdstr = '$fd = CALL open '."$file O_RDWR|O_CREAT 0777\n";
  helper::send_cmd($cmdfh, $outfh, "open", $cmdstr);
	helper::verify_cmd($cmdfh, $outfh, $cmdstr);

   
  # Allocate buffer
  $cmdstr = '$buf = ALLOC '."$bufsize\n";
  helper::send_cmd($cmdfh, $outfh, "ALLOC", $cmdstr);


	do_rwcalls($cmdfh, $outfh, $bufsize);

  # Clean up
  $cmdstr = 'CALL close $fd'."\n";
  helper::send_cmd($cmdfh, $outfh, "close", $cmdstr);

	# Verify it worked
	od_verify($cmdfh, $outfh, $file);

	system("rm -f $file");
  helper::print_and_exit($cmdfh, $outfh, 0, "rw test successful\n");
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
