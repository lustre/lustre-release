#!/usr/bin/perl
# Author: Hariharan Thantry
# Date: 12/13/2002

package llparser;
require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(parse_file $e_subsys $e_mask $e_processor $e_time $e_file $e_line $e_function $e_pid $e_stack $e_fmtstr $e_backref $e_treeparent $e_numchildren $e_youngestchild $e_next $e_pidhead);

($e_subsys, 
 $e_mask, 
 $e_processor, 
 $e_time, 
 $e_file, 
 $e_line, 
 $e_function, 
 $e_pid, 
 $e_stack, 
 $e_fmtstr, 
 $e_treeparent, 
 $e_numchildren,
 $e_youngestchild, 
 $e_pidhead,
 $e_next, 
 $e_backref) = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

$REGEX=qr/^\s*(\w+)\s*:\s*(\d+)\s*:\s*(\d+)\s*:\s*(\d+\.(?:\d+))\s*\(\s*([^:]+)\s*:\s*(\d+)\s*:\s*([^()]+)\s*\(\)\s*(\d+)\s*\+\s*(\d+)\s*(?:.*)\):(.*)$/;

# Create backlinks between array entries based on the calling sequence
# For each new PID encountered, the first entry will be present in the 
# PID hash.

sub create_links {
    my $arrayref = shift @_;
    my $pidhashref = shift @_;
    my %local_hash;
    my $hash_lineref;
    #my $lineref;
    my $firstlineaftermarker = 0;

    foreach $lineref (@$arrayref) {
	my $pidprevious = $pidhashref->{$lineref->[$e_pid]};
	if ($pidprevious->[$e_next] == 0) {
	    $pidprevious->[$e_next] = $lineref;
	    if (exists $local_hash{$lineref->[$e_pid]} && $firstlineaftermarker) {
		$hash_lineref=$local_hash{$lineref->[$e_pid]};
		$hash_lineref->[$e_next] =$lineref;
		$firstlineaftermarker = 0;
		#print "LINE UPDATED: [@$hash_lineref]\n";
		#print "NEXT LINE ADDR:$lineref, CONTENT: @$lineref \n";
	    } 
	} elsif ($local_hash{$lineref->[$e_pid]} == 0) {
		# True only for the first line, the marker line.
	    	$local_hash{$lineref->[$e_pid]}=$lineref;
		#print "LINE ADDED TO HASH: @$lineref\n";
		$firstlineaftermarker = 1; 
	}
	# Stack grows upward (assumes x86 kernel)
	if ($lineref->[$e_stack] < $pidprevious->[$e_stack]) {
	    # lineref is not a child of pidprevious, find its parent
	  LINE: while($lineref->[$e_stack] < $pidprevious->[$e_stack]) {
	      last LINE if ($pidprevious->[$e_backref] == 0); 
	      $pidprevious = $pidprevious->[$e_backref];
	  }
	}
	if ($lineref->[$e_stack] > $pidprevious->[$e_stack]) {
	    # lineref is child of pidprevious
	    $lineref->[$e_backref] = $pidprevious;
	    $pidprevious->[$e_numchildren]++;
	} else {
	    # lineref is sibling of pidprevious
	    $lineref->[$e_numchildren] = 0;
	    $lineref->[$e_backref] = $pidprevious->[$e_backref];
	    ($lineref->[$e_backref])->[$e_numchildren]++;
	}

	$pidhashref->{$lineref->[$e_pid]}=$lineref;
	$lineref->[$e_youngestchild] = $lineref;
	while ($pidprevious->[$e_backref] != 0) {
	    $pidprevious->[$e_youngestchild] = $lineref;
	    $pidprevious = $pidprevious->[$e_backref];
	}
	$pidprevious->[$e_youngestchild] = $lineref;
	$lineref->[$e_pidhead]=$pidprevious;
    }
    return $arrayref;
}

# Main loop, parses the debug log

sub parse_file {
    my %hasharray;
    $backref = 0;
    $treeparent = 0;
    $numchildren = 0;
    $youngestchild = 0;
    $next = 0;
    $pidhead = 0;
			
    while(<>){
	if (/$REGEX/) {
	    @parsed_line=($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $treeparent, $numchildren, $youngestchild, $pidhead, $next, $backref);
	    if (!exists($hasharray{$parsed_line[$e_pid]})) {
		# Push a marker for the beginning of this PID
    		my @marker_line;
		$marker_line[$e_subsys] = 0;
		$marker_line[$e_mask] = 0;
		$marker_line[$e_processor] = 0;
		$marker_line[$e_time] = $parsed_line[$e_time];
		$marker_line[$e_file] = 0;
		$marker_line[$e_line] = 0;
		$marker_line[$e_function] = 0;
		$marker_line[$e_pid] = $parsed_line[$e_pid];
		$marker_line[$e_stack] = 0; # marker lines are everyone's parent
		$marker_line[$e_fmtstr] = "";
		$marker_line[$e_treeparent] = 0;
		$marker_line[$e_numchildren] = 0;
		$marker_line[$e_youngestchild] = 0;
		$marker_line[$e_pidhead] = 0;
		$marker_line[$e_next]= \@parsed_line;
		$marker_line[$e_backref] = 0;
		$hasharray{$parsed_line[$e_pid]} = \@marker_line;
		push @$array_parsed, [ @marker_line ];
		
	    }
	    push @$array_parsed, [ @parsed_line ];
	}
    }
    $array_parsed=create_links($array_parsed, \%hasharray);
    #print_array($array_parsed);
    return $array_parsed;
}

sub print_array {

    my $arrayref = shift;
    foreach $lineref(@$arrayref){
	if ($lineref->[$e_backref]==0){
		print "MARKER LINE(addr): $lineref contents: [ @$lineref ]\n";
	} else {

		print "REGULAR LINE (addr) :$lineref contents: [ @$lineref ]\n";
	}
    }
    
}
1;
#$array_parsed=parse_file();
#print_array($array_parsed);
