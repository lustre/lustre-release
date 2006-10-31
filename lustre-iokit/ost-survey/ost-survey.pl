#!/usr/bin/perl
# This script is to be run on a client machine and will test all the
# OSTs to determine which is the fastest and slowest
# The current test method is as follows:
#   -Create a directory for each OST
#   -Use 'lfs setstripe' to set the Lustre striping such that IO goes to
#     only one OST
#   -Use 'dd' to write and read a file of a specified size
#   -Compute the average, and Standard deviation 
#   -Find the slowest OST for read and write
#   -Find the Fastest OST for read and write

# GLOBALS
$pname = $0;			 # to hold program name
$OSTS = 0;                       # Number of OSTS we will loop over
$BSIZE = 1024 * 1024;            # Size of i/o block
$MNT = "/mnt/lustre";            # Location of Lustre file system
$FSIZE = 30;			 # Number of i/o blocks

# Usage
sub usage () {
	print "Usage: $pname [-s <size>] [-h] <Lustre_Path>\n";
	print "[OPTIONS]\n";
	print "  -s: size of test file in MB (default $FSIZE MB)\n";
	print "  -h: To display this help\n";
	print "example : $pname /mnt/lustre\n";
	exit 1;
}

# ost_count subroutine ets globle variable $OST with Number of OST's
# Also fills 1 for active OST indexes in ACTIVEOST_INX array.
sub ost_count () {
	# numobd gives number of ost's and activeobd gives number of active ost's
	my $tempfile = glob ("/proc/fs/lustre/lov/*-clilov-*/activeobd"); 
	open(PTR, $tempfile) || die "Cannot open $tempfile: $!\n";    
	$OSTS = <PTR>;
	close PTR;
	print "Number of Active OST devices : $OSTS";
	my $tempfile = glob ("/proc/fs/lustre/lov/*-clilov-*/numobd"); 
	open(PTR, $tempfile) || die "Cannot open $tempfile: $!\n";    
	$numost = <PTR>;
	close PTR;
	if ( $numost != $OSTS ) {
		printf "Number of non active ots(s): %d\n", ( $numost - $OSTS );
		$OSTS = $numost;
	}
	my $tempfile = glob ("/proc/fs/lustre/lov/*-clilov-*/target_obd");
	open(PTR, $tempfile) || die "Cannot open $tempfile: $!\n";
	my $count = 0;
	my $temp;
	while (<PTR>) {
		chop;
		my ($ost_num, $ost_name, $ost_status) = split(/\s+/, $_);
		if ( $ost_status eq "ACTIVE" ) {
			$ACTIVEOST_INX[$count] = 1;
		}
		$count++;
	}
}

sub cache_off () {
	$CACHEFILE = glob ("/proc/fs/lustre/llite/*/max_cached_mb"); 
	open(PTR, $CACHEFILE) || die "Cannot open $tempfile: $!\n";    
	$CACHESZ = 0 + <PTR>;
	close PTR;
	system("echo 0 >> $CACHEFILE");
}

sub cache_on () {
	system("echo $CACHESZ >> $CACHEFILE");
}

# make_dummy subroutine creates a dummy file that will be used for read operation.
sub make_dummy () {
	my $SIZE = $_[0];
	my $tempfile = $_[1];
	system ("dd of=$tempfile if=/dev/zero count=$SIZE bs=$BSIZE 2> /dev/null");
}

# run_test subroutine actually writes and reads data to/from dummy file
# and compute corresponding time taken for read and write operation and 
# byte transfer for the both operations.
# This subroutine also fill corresponding globle arrays with above information.
sub run_test () {
	my $SIZE = $_[0];
	my $INX=$_[1];
	my $ACTION=$_[2];
	my $tempfile = $_[3];

	if ( !(-f $tempfile) && $ACTION eq "read" ) {
		&make_dummy($SIZE, $tempfile);
	}
	system("sync");
	my ($ts0, $tu0) = gettimeofday();
	$tu0 = $ts0 + ($tu0 / 1000000);
	if ( $ACTION eq "write" ) {
		system("dd of=$tempfile if=/dev/zero count=$SIZE bs=$BSIZE 2> /dev/null");
	} elsif ( $ACTION eq "read" ) {
		system("dd if=$tempfile of=/dev/null count=$SIZE bs=$BSIZE 2> /dev/null");
	} else {
		print "Action is neither read nor write\n";
		exit 1;
	}
	system("sync");
	my ($ts1, $tu1) = gettimeofday();
	$tu1 = $ts1 + ($tu1/1000000);
	my $tdelta = $tu1 - $tu0;
	my $delta = ($SIZE * $BSIZE / ( $tu1 - $tu0 )) / (1024 * 1024);
	if ( $ACTION eq "write" ) {
		$wTime[$INX] = $tdelta;
		$wMBs[$INX] = $delta;
	} else {
		$rTime[$INX] = $tdelta;
		$rMBs[$INX] = $delta;
	}
}

# calculate subroutine compute following things and displays them.
#  - Finds worst and best OST for both read and write operations.
#  - Compute average of read and write rate from all OSTS
#  - Compute Standard deviation for read and write form all OST's
sub calculate () {
	my ($op, $MBs);
	$op = $_[0];
	@MBs = @_[1..$#_]; 
	my $count = 0;
	my $total = 0;
	my $avg = 0;
	my $sd = 0;
	my $best_OST = 0;
	my $worst_OST = 0;
	my $max_mb = 0;
	my $min_mb = 999999999;
	while ($count < $OSTS ) {
		if ( $ACTIVEOST_INX[$count] ) {
			$total = $total + $MBs[$count];
			if ($max_mb < $MBs[$count] ) {
				$max_mb = $MBs[$count];
				$best_OST = $count; 
			}
			if ($min_mb > $MBs[$count] ) {
				$min_mb = $MBs[$count];
				$worst_OST = $count; 
			}
		}
		$count++;
	}
	$avg = $total/$OSTS;
	$total = 0;
	$count = 0;
	while ($count < $OSTS ) {
		if ( $ACTIVEOST_INX[$count] ) {
			$total = $total + ($MBs[$count] - $avg) * ($MBs[$count] - $avg);
		}
		$count++;
	}
	$sd = sqrt($total/$OSTS);
	printf "Worst  %s OST indx: %d speed: %f\n", $op, $worst_OST, $min_mb;
	printf "Best   %s OST indx: %d speed: %f\n", $op, $best_OST, $max_mb;
	printf "%s Average: %f +/- %f MB/s\n", $op, $avg, $sd;
}

# output_all_data subroutine displays speed and time information 
# for all OST's for both read and write operations.
sub output_all_data () {
	my $count = 0;
	print "Ost#  Read(MB/s)  Write(MB/s)  Read-time  Write-time\n";
	print "----------------------------------------------------\n";
	while ( $count < $OSTS ) {
		if ( $ACTIVEOST_INX[$count] ) { 
			printf "%d     %.3f       %.3f        %.3f      %.3f\n",$count, 
			$rMBs[$count], $wMBs[$count], $rTime[$count], $wTime[$count];
		} else {
			printf "%d     Inactive ost\n",$count; 
		}
		$count = $count + 1;
	}
}

@rTime = ();
@wTime = ();
@rMBs = ();
@wMBs = ();
@ACTIVEOST_INX;

# Locals
my $filename = "";
my $dirpath = "";
my $flag = 0;

# Command line parameter parsing
use Getopt::Std;
getopts('s:h') or usage();
usage() if $opt_h;
$FSIZE = $opt_s if $opt_s;

my $i = 0;
foreach (@ARGV) {
	$MNT = $_;
	$i++;
	if ($i > 1) {
		print "ERROR: extra argument $_\n";
		usage();
	}	
}
#Check for Time::HiRes module 
my $CheckTimeHiRes = "require Time::HiRes";
eval ($CheckTimeHiRes) or die "You need to install the perl-Time-HiRes package to use this script\n";
my $LoadTimeHiRes = "use Time::HiRes qw(gettimeofday)";
eval ($LoadTimeHiRes);

use POSIX qw(strftime);
my $time_v = time();
my $hostname = `lctl list_nids | head -1` or die "You need to install lctl to use this script\n";
chop($hostname);
print "$pname: ", strftime("%D", localtime($time_v));
print " OST speed survey on $MNT from $hostname\n";

# get OST count
ost_count ();
# turn off local cache
cache_off ();

$dirpath = "$MNT/ost_survey_tmp";
eval { mkpath($dirpath) };
if ($@) {
	print "Couldn't create $dirpath: $@";
	exit 1;
}

use File::Path;
$CNT = 0;
while ($CNT < $OSTS) {
	$filename = "$dirpath/file$CNT";
	if ( $ACTIVEOST_INX[$CNT] ) {
		# set stripe for OST number $CNT
		system ("lfs setstripe $filename 0 $CNT 1");
		# Perform write for OST number $CNT
		&run_test($FSIZE,$CNT,"write",$filename);
		$flag++;
	}
	$CNT = $CNT + 1;
}
$CNT = 0;
while ($CNT < $OSTS) {
	$filename = "$dirpath/file$CNT";
	if ( $ACTIVEOST_INX[$CNT] ) {
		# Perform read for OST number $CNT
		&run_test($FSIZE,$CNT,"read",$filename);
		$flag++;
	}
	$CNT = $CNT + 1;
}

# if read or write performed on any OST then display information. 
if ( $flag ) {
	if ( $flag > 1 ) {
		&calculate("Read",@rMBs);
		&calculate("Write",@wMBs);
	}
	output_all_data ();
} else {
	print "There is no active OST's found\n";
}

cache_on ();

eval { rmtree($dirpath) };
if ($@) {
	print "Warning: Couldn't remove $dirpath: $@";
}
