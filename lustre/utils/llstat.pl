#!/usr/bin/perl

my $pname = $0;

sub usage()
{
    print STDERR "Usage: $pname <stats_file> [<interval>]\n";
    exit 1;
}


my $statspath;
my $interval = 0;

if (($#ARGV < 0) || ($#ARGV > 1)) {
    usage();
} else {
    $statspath = $ARGV[0];
    if ($#ARGV == 1) {
	$interval = $ARGV[1];
    } 
}



my %namehash;
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
}

get_cpumhz();
print "Processor counters run at $mhz MHz\n";

sub readstat()
{
    open(STATS, $statspath) || die "Cannot open $statspath: $!\n";
    while (<STATS>) {
	chop;
	($name, $cumulcount, $samples, $unit, $min, $max, $sum, $sumsquare) 
	    = split(/\s+/, $_);

	$prevcount = %namehash->{$name};
	if (defined($prevcount)) {
	    $diff = $cumulcount - $prevcount;
	    if ($name eq "snapshot_time") {
		$tdiff = $diff;
		# printf "%-25s prev=$prevcount, cumul=$cumulcount diff=$diff, tdiff=$tdiff\n", $name;
		printf "$statspath @ $cumulcount\n";
		printf "%-25s %-10s %-10s %-10s", "Name", "Cur.Count", "Cur.Rate", "#Events";
		if ($anysum) {
		    printf "%-8s %10s %12s %10s", "Unit", "min", "avg", "max";
		}
		if ($anysumsquare) {
		    printf "%10s", "stddev";
		}
                printf "\n";
	    }
	    elsif ($cumulcount!=0) {
		printf "%-25s %-10Lu %-10Lu %-10Lu",
		       $name, $diff, ($diff/$tdiff), $cumulcount;
		
		if (defined($sum)) {
		    my $sum_orig = $sum;
		    if (($unit eq "[cycles]") && ($mhz != 1)) {
			$unit = "[usecs]";
			$min = $min/$mhz;
			$sum = $sum/$mhz;
			$max = $max/$mhz;
		    }
		    printf "%-8s %10Lu %12.2f %10Lu", $unit, $min, ($sum/$cumulcount), $max;
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
	%namehash->{$name} = $cumulcount;
    }
}

do {
    readstat();
    if ($interval) { 
	sleep($interval);
    }
} while ($interval);
