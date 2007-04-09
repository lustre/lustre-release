#!/usr/bin/perl -w

# parses obdfilter output from our script goop
# arg 0 input filename
# arg 1 is 'w' 'r'

$file = $ARGV[0];

$type = $ARGV[1];
print "$file\n";


open ( PFILE, "$file") or die "Can't open results";
while ( <PFILE> ) {
	chomp;
	@line = split( /\s+/ );
	if ( $type eq 'w' ) {
		# print "$line[5] $line[7] $line[9]\n";
		# if( $line[9]) {
		$out{$line[7]}{$line[9]} = $line[11];	
		# }
	} elsif ( $type eq 'r' ) {
		# if( $line[18]) {
		# print "$line[5] $line[7] $line[18]\n";
		$out{$line[7]}{$line[9]} = $line[21];	
        } else {
		# if( $line[18]) {
		# print "$line[5] $line[7] $line[18]\n";
		$out{$line[7]}{$line[9]} = $line[16];	
	}
}

	foreach $crg ( sort { $a <=> $b }  ( keys %out )) {
		print "$crg";
		@list = ( sort { $a <=> $b } ( keys %{ $out{$crg} } ));
		 foreach $thr ( @list ) {
			# These are the headers
			 print ",$thr";
		 }
		 print "\n";
		 print "$crg";
		 foreach $tthr ( @list ) {
			 print ",$out{$crg}{$tthr}";
		 }
		print "\n";
	}
	

