#!/usr/bin/perl

my $pname = $0;

my $defaultpath = "/proc/fs/lustre";
my $obdstats = "stats";

sub usage()
{
    print STDERR "Usage: $pname <stats_file> [<interval>]\n";
    print STDERR "example: $pname help (to get help message)\n";
    print STDERR "example: $pname ost1 1 (monitor /proc/fs/lustre/obdfilter/ost1/stats\n";
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

my %cur;
my %last;
my $mhz = 0;
my ($read_bytes, $read, $write_bytes, $write, $getattr, $setattr, $open, $close,    $create, $destroy, $statfs, $punch, $snapshot_time) = 
    ("read_bytes", "read", "write_bytes", "write", "getattr", "setattr", "open",    "close", "create", "destroy", "statfs", "punch", "snapshot_time"); 

my @extinfo = ($setattr, $open, $close, $create, $destroy, $statfs, $punch);
my %shortname = ($setattr => "sa", $open => "op", $close => "cl", 
		$create => "cx", $destroy => "dx", $statfs => "st", $punch => "pu");

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
	my $prevcount;
	my @iodata;

	seek STATS, 0, 0;
    	while (<STATS>) {
		chop;
#		($name, $cumulcount, $samples, $unit, $min, $max, $sum, $sumsquare) 
		@iodata = split(/\s+/, $_);
		my $name = $iodata[0];

		$prevcount = $cur{$name};
		if (defined($prevcount)) {
	    		$last{$name} = $prevcount; 
		} 
		if ($name =~ /^read_bytes$/ || $name =~ /^write_bytes$/) {
	  		$cur{$name} = $iodata[6];
		}
		elsif ($name =~ /^snapshot_time$/) {
#			$cumulcount =~ /(\d+)/;
	    		$cur{$name} = $iodata[1];
		}
		else {
	    		$cur{$name} = $iodata[1];
		}
    	}
}

sub process_stats()
{
	my $delta;
	my $data;
	my $last_time = $last{$snapshot_time};
	if (!defined($last_time)) {
		printf "R %-g/%-g W %-g/%-g attr %-g/%-g open %-g/%-g create %-g/%-g stat %-g punch %-g\n",
		$cur{$read_bytes}, $cur{$read}, 
		$cur{$write_bytes}, $cur{$write}, 
		$cur{$getattr}, $cur{$setattr}, 
		$cur{$open}, $cur{$close}, 
		$cur{$create}, $cur{$destroy}, 
		$cur{$statfs}, $cur{$punch}; 
	}
	else {
		my $timespan = $cur{$snapshot_time} - $last{$snapshot_time};
	
		my $rdelta = $cur{$read} - $last{$read};
		my $rvdelta = int ($rdelta / $timespan);
		my $rrate = ($cur{$read_bytes} - $last{$read_bytes}) /
			   ($timespan * ( 1 << 20 ));
		my $wdelta = $cur{$write} - $last{$write};
		my $wvdelta = int ($wdelta / $timespan);
		my $wrate = ($cur{$write_bytes} - $last{$write_bytes}) /
			   ($timespan * ( 1 << 20 ));
		printf "R %6lu (%5lu %6.2fMB)/s W %6lu (%5lu %6.2fMB)/s",
			$rdelta, $rvdelta, $rrate,
			$wdelta, $wvdelta, $wrate;

		$delta = $cur{$getattr} - $last{$getattr};
		if ( $delta != 0 ) {
			$rdelta = int ($delta/$timespan);
			print " ga:$delta,$rdelta/s";
		}
		
		for $data ( @extinfo ) {
			$delta = $cur{$data} - $last{$data};
			if ($delta != 0) {
				print " $shortname{$data}:$delta";
			}
		}
		print "\n";
		$| = 1;
	}
}

open(STATS, $statspath) || die "Cannot open $statspath: $!\n";
do {
	readstat();
	process_stats();
    	if ($interval) { 
		sleep($interval);
		%last = %cur;
    	}
} while ($interval);
close STATS;
