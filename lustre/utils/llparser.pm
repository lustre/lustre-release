#!/usr/bin/perl

# Author: Hariharan Thantry
# Date: 12/13/2002

package llparser;
require Exporter;

@ISA = qw(Exporter);
@EXPORT = qw(parse_file, $e_subsys, $e_mask, $e_processor, $e_time, $e_file, $e_line, $e_function, $e_pid, $e_stack, $e_fmtstr, $e_backref, $e_treeparent);

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
 $e_backref, 
 $e_treeparent) = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);

$REGEX=qr/^\s*(\w+)\s*:\s*(\d+)\s*:\s*(\d+)\s*:\s*(\d+\.(?:\d+))\s*\(\s*([^:]+)\s*:\s*(\d+)\s*:\s*([^()]+)\s*\(\)\s*(\d+)\s*\+\s*(\d+)\s*(?:.*)\):(.*)$/;

# Generic mechanism to add sets of key/value pairs to a hash table.
# This routine must be called with arguments being specified in the
# following fashion. 
# $Hashtableref update(0|1) $key, $val.
# the value is updated if update == 1
# returns the current value in the hash table
sub add_var{
	my $hasharrayref=shift;
	my $update=shift;
	my $key=shift;
	my $value=shift;
	if (not ref($hasharrayref) eq "HASH"){
		unshift @_, $value;
		unshift @_, $key;
		unshift @_, $boolupdate; 
		unshift @_, $hasharrayref;
		die "You need to pass a reference to a hash object\n";
		return;
	}
	if (exists($hasharrayref->{$key})){
	    if($update) {
		    $hasharrayref->{$key}=0;	
		    $hasharrayref->{$key}=$value;
	    }
	} else {
		# create the hash entry, 
		$hasharrayref->{$key}=$value;		  	
	}	
	return $hasharrayref->{$key};


}
# Create backlinks between array entries based on the calling sequence
# For each new PID encountered, the first entry will be present in the 
# PID hash.

sub create_links {
	my $arrayref=shift @_;
	my %pidhash;
	my $pidparent;
	foreach $lineref(@$arrayref){
		$pidparent = add_var(\%pidhash, 0, $lineref->[$e_pid], 0);
		if ($pidparent == 0){
			$lineref->[$e_backref]=$lineref;	
		       	add_var(\%pidhash, 1, $lineref->[$e_pid], $lineref);
		} else {
			if($lineref->[$e_stack] lt $pidparent->[$e_stack]) {
				$lineref->[$e_backref]=$pidparent;
				add_var(\%pidhash,1, $lineref->[$e_pid], $lineref);
			} elsif($lineref->[$e_stack] gt $pidparent->[$e_stack]) {
			     LINE:while($pidparent->[$e_stack] le $lineref->[$e_stack]){
						last LINE if ($pidparent eq $pidparent->[$e_backref]);
						$pidparent=$pidparent->[$e_backref];
				}
				$lineref->[$e_backref]=$pidparent;
				add_var(\%pidhash, 1, $lineref->[$e_pid], $lineref);
				
			} else {
				$lineref->[$e_backref]=$pidparent->[$e_backref];			
			}
		}
	}
	return $arrayref;
}

# Main loop, parses the debug log

sub parse_file {
    while(<>){
	if (/$REGEX/) {
	    @parsed_line=($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $parent, $treeparent);
	    push @$array_parsed, [ @parsed_line ];
	
	}
	
    }
    $array_parsed=create_links($array_parsed);
    return $array_parsed;
}

sub print_array {

    my $arrayref = shift;
    foreach $lineref(@$arrayref){
	print "LINE = [@$lineref]\n";

    }
    
}

