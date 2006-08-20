#!/usr/bin/perl

my $pname = $0;

my $defaultpath = "/proc/fs/lustre";
my $obdstats = "stats";

sub usage()
{
    print STDERR "Usage: $pname <stats_file> [<interval>]\n";
    exit 1;
}


my $statspath = "None";
my $interval = 0;

if (($#ARGV < 0) || ($#ARGV > 1)) {
    usage();
} else {
    if ( $ARGV[0] =~ /help$/ ) {
	usage();
    }
    if ( -f $ARGV[0] ) {
	$statspath = $ARGV[0];
    } elsif ( -f "$ARGV[0]/$obdstats" ) {
	$statspath = "$ARGV[0]/$obdstats";
    } else {
	my $st = `ls $defaultpath/*/$ARGV[0]/$obdstats 2> /dev/null`;
	chop $st;
	if ( -f "$st" ) {
	    $statspath = $st;
	} else {
	    $st = `ls $defaultpath/*/*/$ARGV[0]/$obdstats 2> /dev/null`;
	    chop $st;
	    if ( -f "$st" ) {
	        $statspath = $st;
	    }
	}
    }
    if ( $statspath =~ /^None$/ ) {
	die "Cannot locate stat file for: $ARGV[0]\n";
    }
    if ($#ARGV == 1) {
	$interval = $ARGV[1];
    } 
}

print "$pname on $statspath\n";

my %cumulhash;
my %sumhash;
my $anysum = 0;
my $anysumsquare = 0;
my $mhz = 0;

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
		# printf "%-25s prev=$prevcount, cumul=$cumulcount diff=$diff, tdiff=$tdiff\n", $name;
		printf "$statspath @ $cumulcount\n";
		printf "%-25s %-10s %-10s %-10s", "Name", "Cur.Count", "Cur.Rate", "#Events";
		if ($anysum) {
		    printf "%-8s %10s %10s %12s %10s", "Unit", "last", "min", "avg", "max";
		}
		if ($anysumsquare) {
		    printf "%10s", "stddev";
		}
                printf "\n";
		$| = 1;
	    }
	    elsif ($cumulcount!=0) {
		printf "%-25s %-10lu %-10lu %-10lu",
		       $name, $diff, ($diff/$tdiff), $cumulcount;
		
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
		    printf "%-8s %10.2f %10lu %12.2f %10lu", $unit, ($sum_diff/$diff), $min,($sum/$cumulcount),$max;
		    if (defined($sumsquare)) {
			my $s = $sumsquare - (($sum_orig*$sum_orig)/$cumulcount);
			if ($s >= 0) {
			    my $cnt = ($cumulcount >= 2) ? $cumulcount : 2 ;
			    my $stddev = sqrt($s/($cnt - 1));
			    if (($unit eq "[usecs]") && ($mhz != 1)) {
				$stddev = $stddev/$mhz;
			    }
			    printf " %10.2f", $stddev;
			}
		    }
		}
		printf "\n";
		$| = 1;
	    }
	}
	else {
	    if ($cumulcount!=0) {
		printf "%-25s $cumulcount\n", $name	
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
}

open(STATS, $statspath) || die "Cannot open $statspath: $!\n";
do {
    readstat();
    if ($interval) { 
	sleep($interval);
    }
} while ($interval);
close STATS;
