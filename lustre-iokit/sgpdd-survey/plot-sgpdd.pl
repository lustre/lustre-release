#!/usr/bin/perl -w
# Report generation for plot-sgpdd.pl
# ===================================
#        The plot-sgpdd.pl script is used to generate csv file and
# instructions files for gnuplot from the output of sgpdd-survey.pl script.
#
#        The plot-sgpdd.pl also creates .scr file that contains instructions
# for gnuplot to plot the graph. After generating .dat and .scr files this
# script invokes gnuplot to display graph.
#
# Syntax:
# $ plot-sgpdd.pl <log_filename>
# [Note: 1. This script may need modifications whenever there will be
#           modifications in output format of sgpdd-survey.pl script.
#        2. Gnuplot version 4.0 or above is required.]

# arg 0 is filename
sub usages_msg() {
	print "Usage: $0 <log_filename> \n";
	print "       The $0 parses and plots graph for output of sgpdd-survey.pl using gnuplot,\n";
	print "       it generates .dat and .scr files for results graphing\n";
	print "e.g.> perl $0 sgpdd-log \n";
	exit 1;
}

my @GraphTitle;
if ( !$ARGV[0] ) {
	usages_msg();
}
$file = $ARGV[0];
$region = 0;
$thread = 0;
$count = 0;
open ( PFILE, "$file") or die "Can't open results";
LABEL: while ( <PFILE> ) {
	chomp;
	@line = split( /\s+/ );
	if ($count == 0) {
		@GraphTitle = @line;
		$count++;
		next LABEL;
	}
	$rindex = 18;
	if ($line[9]) {
	    if ($line[10] eq "failed") {
		$rindex = 12;
	    } else {
		$out{$line[7]}{$line[5]} = $line[9];	
	    }
	}
	#print "rg$line[5] th$line[7] w$line[9] r$line[$rindex]\n";
	if ($line[$rindex]) {
	    if (!($line[$rindex+1] eq "failed")) {
		if ($line[5] <= 1 ) {
			$out{$line[7]}{$line[5] - 1} = $line[$rindex];
		} else {
			$out{$line[7]}{$line[5] + 1} = $line[$rindex];
		}
	    }
	}
	if ( $region < $line[7] ) {
		$region = $line[7];
	}
	if ( $thread < $line[5] ) {
		$thread = $line[5];
	}
	$count++;
}
close PFILE;

print "@GraphTitle\n";
# Open .csv file for writting required columns from log file.
open ( DATAFILE, "> $file.dat" ) or die "Can't open csv file for writting";
print DATAFILE "0  ";
for ($j = 1; $j <= $thread ; $j = $j + $j) {
	print DATAFILE "  write$j  read$j";
}
for ( $i = 1; $i <= $region; $i = $i + $i ) {
	printf DATAFILE "\n%-4s", $i;
	for ($j = 1; $j <= $thread ; $j = $j + $j) {
		if ( $out{$i}{$j} ) {
			print DATAFILE "  $out{$i}{$j}";
		    } else {
			print DATAFILE "      -";
		    }
		if ( $j <= 1 && $out{$i}{$j - 1}) {
		    print DATAFILE "  $out{$i}{$j - 1}";
		} elsif ($out{$i}{$j + 1}) {
		    print DATAFILE "  $out{$i}{$j + 1}";
		} else {
		    print DATAFILE "      -";
		}
	}
}
close DATAFILE;
open ( SCRFILE, "> $file.scr" ) or die "Can't open scr file for writting";
print SCRFILE "set title \"@GraphTitle\"\n";
print SCRFILE "set xlabel \"Threads\"\n";
print SCRFILE "set ylabel \"Speeds(MB/s)\"\n";
my $plot = "plot";
$i = 2;
$xrange = 1;
# generate instructions for gnuplot, with adjusting X-axes ranges
for ($j = 1; $j <= $thread ; $j = $j + $j) {
	if ($j > 15 ) {
		$xrange = 2;
	}
	printf SCRFILE "$plot \"$file.dat\" using 1:$i axes x%dy1 title \"write$j\" with line\n", $xrange;
	$plot = "replot";
	$i++;
	printf SCRFILE "$plot \"$file.dat\" using 1:$i axes x%dy1 title \"read$j\" with line\n", $xrange;
	$i++;
}
print SCRFILE "pause -1\n";
close SCRFILE;
system ("gnuplot $file.scr") == 0 or die "ERROR: while ploting graph.\nMake sure that gnuplot is working properly";
