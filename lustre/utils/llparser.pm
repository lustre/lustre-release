#!/usr/bin/perl
# Copyright (C) 2002 Cluster File Systems, Inc.
# Author: Hariharan Thantry <thantry@users.sourceforge.net>

#   This file is part of Lustre, http://www.lustre.org.
#
#   Lustre is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License as published by the Free Software Foundation.
#
#   Lustre is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with Lustre; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#


package llparser;
require Exporter;
@ISA = qw(Exporter);
@EXPORT = qw(parse_file print_rpcrelations parse_foptions %ll_subsystems 
	%subsysnum %trace_masks $e_subsys $e_mask $e_processor $e_time 
	$e_file $e_line $e_function $e_pid $e_stack $e_fmtstr $e_backref 
	$e_treeparent $e_numchildren $e_youngestchild $e_next $e_pidhead 
	$e_rpcsndrcv $e_rpcpid $e_rpcxid $e_rpcnid $e_rpcopc $e_rpcnext 
	$e_curlineref $SEND $RCV);

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

($e_rpcpid,
 $e_rpcxid,
 $e_rpcnid,
 $e_rpcopc,
 $e_rpcnext, 
 $e_rpcsndrcv,
 $e_curlineref) = (0, 1, 2, 3, 4, 5, 6); 

$SEND = 0;
$RCV  = 1;

$REGEX=qr/^\s*(\w+)\s*:\s*(\d+)\s*:\s*(\d+)\s*:\s*(\d+\.(?:\d+))\s*\(\s*([^:]+)\s*:\s*(\d+)\s*:\s*([^()]+)\s*\(\)\s*(?:(?:\d+)\s*\|\s*)?(\d+)\s*\+\s*(\d+)\s*(?:.*)\):(.*)$/;

$RPCREGEX = qr/^\s*(?:Sending|Handling)\s*RPC\s*pid:xid:nid:opc\s*(\d+):(?:0x)?(\w+):(?:0x)?(\w+):(\d+)\s*$/;
$FILEOPTIONREGEX = qr/(--server)|(-s)/;
$SENDING = qr/Sending/;


# Needs to match definition in portals/include/linux/kp30.h
%ll_subsystems = ("00" => "UNDEFINED", "01" => "MDC", "02" => "MDS", 
		  "03" => "OSC",  "04" => "OST",  "05" => "CLASS",
	 	  "06" => "OBDFS","07" => "LLITE","08" => "RPC",
		  "09" => "EXT2OBD","0a" => "PORTALS","0b" => "SOCKNAL",
		  "0c" => "QSWNAL","0d" => "PINGER","0e" => "FILTER",
		  "0f" => "TRACE","10" => "ECHO","11" => "LDLM",
		  "12" => "LOV", "13" => "GMNAL","14" => "PTLROUTER" );

%subsysnum;
$subsysnum->{UNDEFINED} = 0;
$subsysnum->{MDC} = 1;
$subsysnum->{MDS} = 2;
$subsysnum->{OSC} = 3;
$subsysnum->{OST} = 4;
$subsysnum->{CLASS} = 5;
$subsysnum->{OBDFS} = 6;
$subsysnum->{LLITE} = 7;
$subsysnum->{RPC} = 8;
$subsysnum->{EXT2OBD} = 9;
$subsysnum->{PORTALS} = 10;
$subsysnum->{SOCKNAL} = 11;
$subsysnum->{QSWNAL} = 12;
$subsysnum->{PINGER} = 13;
$subsysnum->{FILTER} = 14;
$subsysnum->{TRACE} = 15; # obdtrace, not to be confused with D_TRACE */
$subsysnum->{ECHO} = 16;
$subsysnum->{LDLM} = 17;
$subsysnum->{LOV} = 18;
$subsysnum->{GMNAL} = 19;
$subsysnum->{PTLROUTER} = 20;

%tracemasks;
$tracemasks->{TRACE} = 1 << 0; # /* ENTRY/EXIT markers */
$tracemasks->{INODE} = 1 << 1; #
$tracemasks->{SUPER} = 1 << 2; #
$tracemasks->{EXT2} = 1 << 3; # /* anything from ext2_debug */
$tracemasks->{MALLOC} = 1 << 4; # /* print malloc, free information */
$tracemasks->{CACHE} = 1 << 5; # /* cache-related items */
$tracemasks->{INFO} = 1 << 6; # /* general information */
$tracemasks->{IOCTL} = 1 << 7; # /* ioctl related information */
$tracemasks->{BLOCKS} = 1 << 8; # /* ext2 block allocation */
$tracemasks->{NET} = 1 << 9; # /* network communications */
$tracemasks->{WARNING} = 1 << 10; #
$tracemasks->{BUFFS} = 1 << 11; #
$tracemasks->{OTHER} = 1 << 12; #
$tracemasks->{DENTRY} = 1 << 13; #
$tracemasks->{PORTALS} = 1 << 14; # /* ENTRY/EXIT markers */
$tracemasks->{PAGE} = 1 << 15; # /* bulk page handling */
$tracemasks->{DLMTRACE} = 1 << 16; #
$tracemasks->{ERROR} = 1 << 17; # /* CERROR} = ...) == CDEBUG} = D_ERROR, ...) */
$tracemasks->{EMERG} = 1 << 18; # /* CEMERG} = ...) == CDEBUG} = D_EMERG, ...) */
$tracemasks->{HA} = 1 << 19; # /* recovery and failover */
$tracemasks->{RPCTRACE} = 1 << 19; # /* recovery and failover */

# Contains all the file names, the first filename is the 
# client. After that are all servers.
my @filearray = ();


# Create backlinks between array entries based on the calling sequence
# For each new PID encountered, the first entry will be present in the 
# PID hash.

sub create_links {
    my $arrayref = shift @_;
    my $pidhashref = shift @_;
    my $stitchref = shift @_;
    my %local_hash;
    my $hash_lineref;
    my $tmpfmtref;
    my $tmpref;
    my $firstlineaftermarker = 0;

    foreach $lineref (@$arrayref) {
	next if ($lineref->[$e_time] == 0); # Skip the client marker line
	my $pidprevious = $pidhashref->{$lineref->[$e_pid]};
	if ($pidprevious->[$e_next] == 0) {
	    $pidprevious->[$e_next] = $lineref;
	    if (exists $local_hash{$lineref->[$e_pid]} 
	        && $firstlineaftermarker) {
		$hash_lineref=$local_hash{$lineref->[$e_pid]};
		$hash_lineref->[$e_next] =$lineref;
		$firstlineaftermarker = 0;
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
	  LINE: while(($lineref->[$e_stack] < $pidprevious->[$e_stack]) &&
		      ($lineref->[$e_function] == $pidprevious->[$e_function])
		      ) {
	                  #This second part of the comparision is a HACK  
	                  last LINE if ($pidprevious->[$e_backref] == 0); 
	                  $pidprevious = $pidprevious->[$e_backref];
	  }
	}
	if ($lineref->[$e_stack] > $pidprevious->[$e_stack]) {
	    # lineref is child of pidprevious, with the caveat that they must
            # belong to different functions. This is a HACK 
	    # until CDEBUG is modified
	    while($lineref->[$e_function] eq $pidprevious->[$e_function]) {
	      last if ($pidprevious->[$e_backref] == 0);
              $pidprevious = $pidprevious->[$e_backref];
	    }	

	    $lineref->[$e_backref] = $pidprevious;
	    $pidprevious->[$e_numchildren]++;
	} else {
	    # lineref is sibling of pidprevious
	    $lineref->[$e_numchildren] = 0;
	    $lineref->[$e_backref] = $pidprevious->[$e_backref];
	    ($lineref->[$e_backref])->[$e_numchildren]++;
	}

	$pidhashref->{$lineref->[$e_pid]} = $lineref;
	$lineref->[$e_youngestchild] = $lineref;
	while ($pidprevious->[$e_backref] != 0) {
	    $pidprevious->[$e_youngestchild] = $lineref;
	    $pidprevious = $pidprevious->[$e_backref];
	}
	$pidprevious->[$e_youngestchild] = $lineref;
	$lineref->[$e_pidhead]=$pidprevious;
	
        # Stitch together rpc's
	if($lineref->[$e_fmtstr] =~ $RPCREGEX) {
	    #print "RPC LINE: @$lineref\n";
	    $tmpfmtref = [$1, $2, $3, $4, 0, 0, 0];
	    if ($lineref->[$e_fmtstr] =~ $SENDING) {
		$tmpfmtref->[$e_rpcsndrcv] = $SEND;
	    } else { $tmpfmtref->[$e_rpcsndrcv] = $RCV; }
	    $tmpfmtref->[$e_curlineref] = $lineref;
	    $stitchref->{$lineref->[$e_time]} = $tmpfmtref;
	    
	}
	    
    }
match_rpcs($stitchref);
return $arrayref;	
}




# Main loop, parses the debug log

sub parse_file {
    my %hasharray;
    my $input_files = shift;
    
    my $stitch_ref = shift;
    my $pid = shift;
    my $rpctrace = shift;
    my $trace = shift;
    my $nodlm = shift;
    my $noclass = shift;
    my $nonet = shift;

    print "$pid, $rpctrace, $nodlm, $noclass, $nonet\n";
    $backref = 0;
    $treeparent = 0;
    $numchildren = 0;
    $youngestchild = 0;
    $next = 0;
    $pidhead = 0;
    $iter = 0;
			
    foreach $file (@$input_files) {
	
	open(FILEHANDLE, $file) or die "Can't open file: $file\n";
	while(<FILEHANDLE>) {
	    if (/$REGEX/) {
		@parsed_line=($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 
			      $treeparent, $numchildren, $youngestchild, 
			      $pidhead, $next, $backref);
		next if (($parsed_line[$e_pid] != $pid) && 
			 ($pid) && ($iter == 0));
		next if (($parsed_line[$e_mask] != $tracemasks->{RPCTRACE}) 
			 && ($rpctrace));
		next if ($trace && $parsed_line[$e_mask] != 
			 $tracemasks->{TRACE});
		next if ($nodlm && hex($parsed_line[$e_subsys]) == 
			 $subsysnum->{LDLM});
		next if ($noclass && hex($parsed_line[$e_subsys]) == 
			 $subsysnum->{CLASS});
		next if ($nonet && (hex($parsed_line[$e_subsys]) == 
				    $subsysnum->{RPC} ||
				    hex($parsed_line[$e_subsys]) == 
				    $subsysnum->{NET} ||	
				    hex($parsed_line[$e_subsys]) == 
				    $subsysnum->{PORTALS} ||
				    hex($parsed_line[$e_subsys]) == 
				    $subsysnum->{SOCKNAL} ||
				    hex($parsed_line[$e_subsys]) == 
				    $subsysnum->{QSWNAL} ||
				    hex($parsed_line[$e_subsys]) == 
				    $subsysnum->{GMNAL})); 	
		
		
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
                   # marker lines are everyone's parent, so stack value zero
		    $marker_line[$e_stack] = 0; 
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
	close(FILEHANDLE);
	if ($iter == 0) {
	    # Insert end of client line marker, an all zero pattern;
	    @marker_line = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	    push @$array_parsed, [ @marker_line ]; 
	    
	}
	$iter ++;
    }
    
    $array_parsed=create_links($array_parsed, \%hasharray, $stitch_ref);
    #print_array($array_parsed);
    return $array_parsed;
}

sub print_array {

    my $arrayref = shift;
    foreach $lineref(@$arrayref){
	if ($lineref->[$e_backref]==0){
		print "MARKER LINE(addr): $lineref contents: [@$lineref]\n";
	} else {

		print "REGULAR LINE (addr) :$lineref contents:[@$lineref]\n";
	}
    }
    
}

sub print_rpcrelations {

    my $rpchashref = shift;
    foreach $rpckeys (sort keys %$rpchashref) {
	$tmpref = $rpchashref->{$rpckeys};
	#print "Key: $rpckeys, Contents: @$tmpref\n";

    }

}
sub match_rpcs {
    my $rpchashref = shift;
    foreach $rpckeys (sort keys %$rpchashref) {
	$tmpref = $rpchashref->{$rpckeys};
	#print "MATCHING: $@tmpref...\n";
	foreach $cmpkeys (sort keys %$rpchashref) {
	    next if($cmpkeys == $rpckeys);
	    $cmpref = $rpchashref->{$cmpkeys};
	 #   print "Line compared: @$cmpref\n";
	    next if ($tmpref->[$e_rpcsndrcv] == $cmpref->[$e_rpcsndrcv]);
	    next if ($tmpref->[$e_rpcpid] != $cmpref->[$e_rpcpid]);
	    next if ($tmpref->[$e_rpcxid] != $cmpref->[$e_rpcxid]);
	    if ($tmpref->[$e_rpcsndrcv] == $SEND) {
		$tmpref->[$e_rpcnext] = $cmpkeys;
		#print "MACTHED: KEY 1: $rpckeys CONTENTS: @$tmpref", 
		#"KEY2: $cmpkeys CONTENTS: @$cmpref\n"
		
	    }
	    	    
	}

    }

}

sub getnextchild {
    my $rootline = shift;
    my $lineref = shift;
    my $tempref = $lineref->[$e_next];
    if ($tempref == 0)  {
	return 0;
    }

    if (($tempref->[$e_stack] > $rootline->[$e_stack]) ||
	(($tempref->[$e_stack] <= $rootline->[$e_stack]) &&
	 ($tempref->[$e_function] == $rootline->[$e_function])
	 )){
	# Child
	return $tempref;
	
    }
	return 0;
	
	
}


sub parse_foptions {
    
    my $inarg = shift;
    my $idx = 0;
    foreach $elem(@$inarg) {
	next if ($elem =~ /$FILEOPTIONREGEX/);
	$filearray[$idx] = $elem;
	$idx++;    
    }
    return \@filearray;
}

1;
#$array_parsed=parse_file();
#print_array($array_parsed);
