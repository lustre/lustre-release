#!/usr/bin/perl
# llstat.pl is a utility that takes stats files as input with optional clear-flag. 
# The clear-flag is used to clear the stats file before printing stats information.
# The lustre stats files generally located inside proc/fs/lustre/
# llstat.pl first reads the required statistics information from specified stat file,
# process the information and prints the output after every interval specified by user.
 
my $pname = $0;

my $defaultpath = "/proc/fs/lustre";
my $obdstats = "stats";

# Subroutine for printing usages information
sub usage()
{
    print STDERR "Usage: $pname [-c] <stats_file> [<interval>]\n";
    print STDERR "       <stats_file> : lustre stats file, full /proc path or substring search\n";
    print STDERR "       <interval>   : Time in seconds to repeat statistics print cycle\n";
    print STDERR "       -c           : zero stats first\n";
    print STDERR "eg: $pname ost 1  --  monitors /proc/fs/lustre/ost/OSS/ost/stats\n";
    print STDERR "Use CTRL + C to stop statistics printing\n";
    exit 1;
}


my $statspath = "None";
my $interval = 0;
my $argpos = 0;
# check for number of auguments
if (($#ARGV < 0) || ($#ARGV > 2)) {
    usage();
} else {   # Process arguments
    if ( $ARGV[0] =~ /help$/ ) {
	usage();
    }
    if ($#ARGV == 1) { 
	if (($ARGV[0] eq "-c") || ($ARGV[0] eq "-C")) {
	    $argpos = 1;
	} else {
	    $interval = $ARGV[1];
	}
    } 
    if ( $#ARGV == 2 ) {
	$interval = $ARGV[2];
	$argpos = 1;
    } 
    if ( -f $ARGV[$argpos] ) {
	$statspath = $ARGV[$argpos];
    } elsif ( -f "$ARGV[$argpos]/$obdstats" ) {
	$statspath = "$ARGV[$argpos]/$obdstats";
    } else {
	my $st = `ls $defaultpath/*/$ARGV[$argpos]/$obdstats 2> /dev/null`;
	chop $st;
	if ( -f "$st" ) {
	    $statspath = $st;
	} else {
	    $st = `ls $defaultpath/*/*/$ARGV[$argpos]/$obdstats 2> /dev/null`;
	    chop $st;
	    if ( -f "$st" ) {
	        $statspath = $st;
	    }
	}
    }
    if ( $statspath =~ /^None$/ ) {
	die "Cannot locate stat file for: $ARGV[$argpos]\n";
    }
    if ($#ARGV == 2) {
	# Clears stats file before printing information in intervals
	if ( ($ARGV[0] eq "-c") || ($ARGV[0] eq "-C" ) ) {
	    open ( STATS, "> $statspath") || die "Cannot clear $statspath: $!\n";
	    print STATS " ";
	    close STATS;
	    sleep($interval);	    
	} else {
	    usage();
	}
    }
}

print "$pname on $statspath\n";

my %cumulhash;
my %sumhash;
my $anysum = 0;
my $anysumsquare = 0;
my $mhz = 0;
my $falg = 0;

sub get_cpumhz()
{
    my $cpu_freq;
    my $itc_freq; # On Itanium systems use this
    if (open(CPUINFO, "/proc/cpuinfo")==0) {
	return;
    }
    while (<CPUINFO>) {
	if (/^cpu MHz\s+:\s*([\d\.]+)/) { $cpu_freq=$1; }
	elsif (/^itc MHz\s+:\s*([\d\.]+)/) { $itc_freq=$1; }
    }
    if (defined($itc_freq)) { $mhz = $itc_freq; }
    elsif (defined($cpu_freq)) { $mhz = $cpu_freq; }
    else { $mhz = 1; }
    close CPUINFO;
}

get_cpumhz();
print "Processor counters run at $mhz MHz\n";

# readstats subroutine reads and processes statistics from stats file.
# This subroutine gets called after every interval specified by user.
sub readstat()
{
    seek STATS, 0, 0;
    while (<STATS>) {
	chop;
	($name, $cumulcount, $samples, $unit, $min, $max, $sum, $sumsquare) 
	    = split(/\s+/, $_);

	$prevcount = %cumulhash->{$name};
	if (defined($prevcount)) {
	    $diff = $cumulcount - $prevcount;
	    if ($name eq "snapshot_time") {
		$tdiff = $diff;
                printf "\n%-10.0f", $cumulcount;
		$| = 1;
	    }
	    elsif ($cumulcount!=0) {
		
		printf "   %s %lu %lu",
		        $name,  ($diff/$tdiff), $cumulcount;
		
		if (defined($sum)) {
		    my $sum_orig = $sum;
		    my $sum_diff = $sum - %sumhash->{$name};

	    #printf "\n%-25s diff=$diff, sum=$sum sumhash=%10s sum_diff=$sum_diff\n", $name, %sumhash->{$name};
		    if ($diff == 0) {
			$diff = 1; # avoid division by zero
		    }
		    if (($unit eq "[cycles]") && ($mhz != 1)) {
			$unit = "[usecs]";
			$min = $min/$mhz;
			$sum = $sum/$mhz;
			$sum_diff = $sum_diff/$mhz;
			$max = $max/$mhz;
		    }
		    printf " %lu %.2f %lu", $min,($sum/$cumulcount),$max;
		    if (defined($sumsquare)) {
			my $s = $sumsquare - (($sum_orig*$sum_orig)/$cumulcount);
			if ($s >= 0) {
			    my $cnt = ($cumulcount >= 2) ? $cumulcount : 2 ;
			    my $stddev = sqrt($s/($cnt - 1));
			    if (($unit eq "[usecs]") && ($mhz != 1)) {
				$stddev = $stddev/$mhz;
			    }
			    printf " %.2f ", $stddev;
			}
		    }
		}
		$| = 1;
	    }
	}
	else {
	    if ($cumulcount!=0) {
		printf "%-25s $cumulcount\n", $name	# print info when interval is not specified.
	    }
	    if (defined($sum)) {
		$anysum = 1;
	    }
	    if (defined($sumsquare)) {
		$anysumsquare = 1;
	    }
	}
	%cumulhash->{$name} = $cumulcount;
	%sumhash->{$name} = $sum;
    }
    if ( !$flag && $interval) {
	printf "Timestamp [Name Rate Total";
	if ($anysum) {
	    printf " min avg max";
	}
	if ($anysumsquare) {
	    printf " stddev";
	}
	printf " ]...";
	printf "\n--------------------------------------------------------------------";
	$flag = 1;
    }
}

open(STATS, $statspath) || die "Cannot open $statspath: $!\n";
do {
    readstat();
    if ($interval) { 
	sleep($interval);
    }
} while ($interval);
close STATS;
