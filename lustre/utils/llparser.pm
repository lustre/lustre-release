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
@EXPORT = qw(parse_file print_rpcrelations parse_foptions
	     %ll_subsystems %subsysnum %trace_masks $e_subsys $e_mask 
	     $e_processor $e_time $e_file $e_line $e_function $e_pid 
	     $e_stack $e_fmtstr $e_backref $e_marked $e_treeparent 
	     $e_numchildren $e_youngestchild $e_next $e_pidhead 
	     $e_rpcsndrcv $e_rpcpid $e_rpcxid $e_rpcnid $e_rpcopc 
	     $e_rpcnext $e_curlineref $SEND $RCV);

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
 $e_backref,
 $e_marked) = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);

($e_rpcxid,
 $e_rpcopc,
 $e_rpcreint,
 $e_rpcsndrcv,
 $e_rpcpid,
 $e_rpcnid,
 $e_rpcmarked) = (0, 1, 2, 3, 4, 5, 6);

($e_curline,
 $e_cliRPCent,
 $e_srvRPCent,
 $e_srvRPCexit,
 $e_cliRPCexit) = ($e_rpcmarked+1, $e_rpcmarked+2, $e_rpcmarked+3, $e_rpcmarked+4, $e_rpcmarked+5);

$CLI_SEND   = 1;
$SRV_RCV    = 2;
$SRV_REPLY  = 3;
$CLI_COMPLETE = 4;
$MDS_REINT  = 5;

# Data structure for pidhashref
($e_lineref, $e_pidcmd) = (0, 1); 

# Define the lowest stack values for MARKER/VFS
$MARKER_STACK_VAL = 0;
$VFS_STACK_VAL = 1;

# Main parser regexes, these break down each line into all its components

# Previous REGEXP (kept here just in case....)
$UMLREGEX = qr/^\s*(\w+)\s*:\s*(\d+)\s*:\s*(\d+)\s*:\s*(\d+\.(?:\d+))\s*\(\s*([^:]+)\s*:\s*(\d+)\s*:\s*([^()]+)\s*\(\)\s*(\d+)\s*\|\s*(?:\d+)\s*\+\s*(\d+)\s*\):(.*)$/;
$HOSTREGEX= qr/^\s*(\w+)\s*:\s*(\d+)\s*:\s*(\d+)\s*:\s*(\d+\.(?:\d+))\s*\(\s*([^:]+)\s*:\s*(\d+)\s*:\s*([^()]+)\s*\(\)\s*(?:(?:\d+)\s*\|\s*)?(\d+)\s*\+\s*(\d+)\s*(?:.*)\):(.*)$/;

# Regexpression that is used (works for both HOST and UML log files)
$HOSTREGEX2= qr/^(\w+):(\d+):(\d+):(\d+\.(?:\d+))\s\(\s*([^:]+):(\d+):([^()]+)\(\)\s(\d+)(?:\s\|\s(?:\d+))?\+(\d+)\):(.*)$/;


#RPC REGEXES BELOW
$SENDING = "Sending";
$COMPLETED = "Completed";
$HANDLING = "Handling";
$HANDLED = "Handled";
$RPCREGEX = qr/^\s*($SENDING|$HANDLING|$HANDLED|$COMPLETED)\s*RPC\s*pid:xid:ni:nid:opc\s*(\d+):(?:0x)?(\w+):(?:\w+):(?:0x)?(\w+):(\d+)\s*$/;

#VFS REGEX BELOW
$VFS_REGEX = qr/VFS Op:(.+)/;

# DEBUG_REQ parser
( $e_drq_str, $e_drq_reqadr, $e_drq_xid, $e_drq_transno, $e_drq_opcode, 
  $e_drq_uuid , $e_drq_portal, $e_drq_reqlen, $e_drq_replen, 
  $e_drq_refcnt, $e_drq_rqflags, $e_drq_reqmsgflags, $e_drq_repmsgflags,
  $e_drq_rc) = (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14);

$DEBUGREQ_REGEX= qr/@@@\s([^@]+)\sreq@([a-f\d]+)\sx(\d+)\/t(\d+)\so(\d+)->([<?>\w]+):([-\d]+)\slens\s(\d+)\/(\d+)\sref\s(\d+)\sfl\s([-a-f\d]+)\/([-a-f\d]+)\/([-a-f\d]+)\src\s([-a-f\d]+)/;


#LDLMREGEX BELOW
# This needs to change when I understand the LDLM statemachine better
$LDLM_REGEX = qr/^\s*###/;

$LDLM_TEMP_REGEX = qr/^\s*client-side enqueue START/;
$LDLM_TEMP_REGEX_2 = qr/^\s*client-side enqueue END/; 
#OTHER REGEXES


$FILEOPTIONREGEX = qr/(--server)|(-s)/;
$PROCESS_MARKER = qr/Process (entered)|(leaving)/;
$MARKER_REGEX = qr/DEBUG MARKER:\s*====([\d+])=(.*)/;

#Global variables

#Needs to match opcode definitions in lustre/include/linux/lustre_idl.h

%ll_opcodes = ("0" => "OST_REPLY", "1" => "OST_GETATTR", "2" => "OST_SETATTR",
	       "3" => "OST_READ", "4" => "OST_WRITE", 
	       "5" => "OST_CREATE", "6" => "OST_DESTROY", 
	       "7" => "OST_GET_INFO", "8" => "OST_CONNECT", 
	       "9" => "OST_DISCONNECT", "10" => "OST_PUNCH", 
	       "11" => "OST_OPEN", "12" => "OST_CLOSE", "13" => "OST_STATFS", 
	       "33" => "MDS_GETATTR", "34" => "MDS_GETATTR_NAME", 
	       "35" => "MDS_CLOSE", "36" => "MDS_REINT", 
	       "37" => "MDS_READPAGE", "38" => "MDS_CONNECT", 
	       "39" => "MDS_DISCONNECT", "40" => "MDS_GETSTATUS", 
	       "41" => "MDS_STATFS", "42" => "MDS_GETLOVINFO",
	       "101" => "LDLM_ENQUEUE", "102" => "LDLM_CONVERT", 
	       "103" => "LDLM_CANCEL", "104" => "LDLM_BL_CALLBACK", 
	       "105" => "LDLM_CP_CALLBACK" );
	     
%ll_reint_opcodes = ("1" => "setattr", "2" => "create", "3" => "link",
		     "4" => "unlink", "5" => "rename", "6" => "open" );

# Needs to match definition in portals/include/linux/kp30.h
%ll_subsystems = ("00" => "UNDEFINED", "01" => "MDC", "02" => "MDS", 
		  "03" => "OSC",  "04" => "OST",  "05" => "CLASS",
	 	  "06" => "OBDFS","07" => "LLITE","08" => "RPC",
		  "09" => "EXT2OBD", "0a" => "PORTALS", "0b" => "SOCKNAL",
		  "0c" => "QSWNAL", "0d" => "PINGER", "0e" => "FILTER",
		  "0f" => "TRACE", "10" => "ECHO", "11" => "LDLM",
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
$tracemasks->{TRACE} = sprintf "%06x", 1 << 0 ; # /* ENTRY/EXIT markers */
$tracemasks->{INODE} = sprintf "%06x", 1 << 1; #
$tracemasks->{SUPER} = sprintf "%06x", 1 << 2; #
$tracemasks->{EXT2} =  sprintf "%06x", 1 << 3; # /* anything from ext2_debug */
$tracemasks->{MALLOC} = sprintf "%06x", 1 << 4; # /* print malloc, free info */
$tracemasks->{CACHE} = sprintf "%06x", 1 << 5; # /* cache-related items */
$tracemasks->{INFO}  = sprintf "%06x", 1 << 6; # /* general information */
$tracemasks->{IOCTL} = sprintf "%06x", 1 << 7; # /* ioctl related info */
$tracemasks->{BLOCKS} = sprintf "%06x", 1 << 8; # /* ext2 block allocation */
$tracemasks->{NET} = sprintf "%06x", 1 << 9; # /* network communications */
$tracemasks->{WARNING} = sprintf "%06x", 1 << 10; #
$tracemasks->{BUFFS} = sprintf "%06x", 1 << 11; #
$tracemasks->{OTHER} = sprintf "%06x", 1 << 12; #
$tracemasks->{DENTRY} = sprintf "%06x", 1 << 13; #
$tracemasks->{PORTALS} = sprintf "%06x", 1 << 14; # /* ENTRY/EXIT markers */
$tracemasks->{PAGE} = sprintf "%06x", 1 << 15; # /* bulk page handling */
$tracemasks->{DLMTRACE} = sprintf "%06x", 1 << 16; #
$tracemasks->{ERROR} = sprintf "%06x", 1 << 17; # /* CERROR
$tracemasks->{EMERG} = sprintf "%06x", 1 << 18; # /* CEMERG
$tracemasks->{HA} = sprintf "%06x", 1 << 19; # /* recovery and failover */
$tracemasks->{RPCTRACE} = sprintf "%06x", 1 << 20; #
$tracemasks->{VFSTRACE} = sprintf "%06x", 1 << 21;
# Contains all the file names, the first filename is the 
# client. After that are all servers.
my @filearray = ();

# Setup parent/child/sibling relationship between
# this line and the preceding line
sub setup_relations
{
    my $lineref = shift;
    my $pidprevious = shift;

	if ($lineref->[$e_stack] < $pidprevious->[$e_stack]) {
	    # lineref is not a child of pidprevious, find its parent
	while($lineref->[$e_stack] < $pidprevious->[$e_stack]) {
	    last if ($pidprevious->[$e_backref] == 0); 
	                  $pidprevious = $pidprevious->[$e_backref];
	  }
	}
	if ($lineref->[$e_stack] > $pidprevious->[$e_stack]) {
	# lineref is child of pidprevious, 
	    $lineref->[$e_backref] = $pidprevious;
	    $pidprevious->[$e_numchildren]++;
	} else {
	    # lineref is sibling of pidprevious
	    $lineref->[$e_numchildren] = 0;
	    $lineref->[$e_backref] = $pidprevious->[$e_backref];
	    ($lineref->[$e_backref])->[$e_numchildren]++;
	}
	$lineref->[$e_youngestchild] = $lineref;
	while ($pidprevious->[$e_backref] != 0) {
	    $pidprevious->[$e_youngestchild] = $lineref;
	    $pidprevious = $pidprevious->[$e_backref];
	}
	$pidprevious->[$e_youngestchild] = $lineref;
    $lineref->[$e_pidhead] = $pidprevious;
}

# Update the RPC hash table, if this line is an RPC (or
# related) line. 
	
sub update_RPC
{
    my $rpcref = shift;
    my $lineref = shift;
    
    my $tmpfmtref;
    my $contextstr;
	    
    if ($lineref->[$e_fmtstr] =~ $RPCREGEX) {
	$tmpfmtref = [$3, $5, 0, 0, $2, $4, 0];
	if ($1 eq $SENDING) {
	    $tmpfmtref->[$e_rpcsndrcv] = $CLI_SEND;
	} elsif ($1 eq $HANDLING) { 
	    $tmpfmtref->[$e_rpcsndrcv] = $SRV_RCV;
	} elsif ($1 eq $HANDLED) {
	    $tmpfmtref->[$e_rpcsndrcv] = $SRV_REPLY;
	} elsif ($1 eq $COMPLETED) {
	    $tmpfmtref->[$e_rpcsndrcv] = $CLI_COMPLETE;
	}
	else {
	    print STDERR "Unknown RPC Expression: $lineref->[$e_fmtstr]\n";
	}
	insert_rpcref($rpcref, $tmpfmtref, $lineref);
    }
}
	    
sub insert_rpcref
{
    my $rpcref = shift;
    my $tmpfmtref = shift;
    my $lineref = shift;

    $tmpfmtref->[$e_cliRPCent] = 0;
    $tmpfmtref->[$e_srvRPCent] = 0;
    $tmpfmtref->[$e_srvRPCexit] = 0;
    $tmpfmtref->[$e_cliRPCexit] = 0;
    
    $tmpfmtref->[$e_curline] = $lineref;
    # print_RPCfields($tmpfmtref);
    $rpcref->{$lineref->[$e_time]} = $tmpfmtref;
}

sub update_debugreqs
{
    my $rpcref = shift;
    my $lineref = shift;
	
    @fields = $lineref->[$e_fmtstr] =~ $DEBUGREQ_REGEX;
    if ($#fields) {
	my $str = $fields[$e_drq_str];
	my $xid = $fields[$e_drq_xid];
	my $opc = $fields[$e_drq_opcode];
	# printf STDERR "str=%s\n", $str;
	# Check for MDS_REINT subopcode
	if (($opc == 36) && ($str =~ /reint \((\w+)\).*/)) {
	    my $subopcode = $1;
	    my $pid = $lineref->[$e_pid];
	    #print STDERR "reint $xid $opc $subopcode $pid\n";
	    my $tmpfmtref = [ $xid, $opc, $subopcode, $MDS_REINT, $pid, 0 ,0];
	    insert_rpcref($rpcref, $tmpfmtref, $lineref);
	}
    } else {
	printf STDERR "Failed to match DEBUGREQ line %d *********** str=%s\n",
	$debugreq,  $lineref->[$e_fmtstr];
    }
}

# Create backlinks between array entries based on the calling sequence
# For each new PID encountered, the first entry will be present in the 
# PID hash.

sub sort_by_number_descending
{
    $b <=> $a;
}

sub process_array 
{
    my $arrayref = shift @_;
    my $pidhashref = shift @_;
    my $marker_ref = shift @_;
    my $rpc_ref = shift @_;
    my $vfs_ref = shift @_;
    my $ldlm_ref = shift @_;

    my %lastline; # Hash of last line by pid

    print STDERR "Building PID/RPC list.....\n";
    $debugreq=0;

    foreach $lineref (@$arrayref) {
	next if ($lineref->[$e_time] == 0);

	my $pidprevious = $lastline->{$lineref->[$e_pid]};
	if ($pidprevious == 0) {
	    # True only for the first line, the PID marker line.
	    $pidhashref->{$lineref->[$e_pid]}->[$e_lineref] = $lineref;
	    $pidhashref->{$lineref->[$e_pid]}->[$e_pidcmd] = "unknown command line";
	    # print STDERR "LINE ADDED TO HASH: @$lineref\n";
	    $pidprevious = $lineref;
	}
	else {
	    if ($pidprevious->[$e_next] != 0) {
		print STDERR "Fatal: Previous line next field !=0\n";
		print STDERR "Line: @$pidprevious\n";
		exit 1;
	    }
	    # Path for all lines except the PID marker
	    $pidprevious->[$e_next] = $lineref;
	}
	# Match VFS lines & force VFS Stack Value to be 1 (markers are 0)
	if ($lineref->[$e_fmtstr] =~ $VFS_REGEX) {
	    $vfs_ref->{$lineref->[$e_time]} = $lineref;
	    $lineref->[$e_stack] = $VFS_STACK_VAL;
	}
	# Match Markers
	elsif ($lineref->[$e_fmtstr] =~ $MARKER_REGEX) {
	    $marker_ref->{$lineref->[$e_time]} = [$1, $2, $lineref];
	}
	# Match LDLM
	elsif ($lineref->[$e_fmtstr] =~ $LDLM_REGEX) {
	    $ldlm_ref->{$lineref->[$e_time]} = $lineref;
	}
	# Match DEBUGREQ Lines
	if ($lineref->[$e_fmtstr] =~ qr/@@@ /) {
	    $debugreq++;
	    update_debugreqs($rpc_ref, $lineref);
	}
	# Is this a process name ?
	elsif (($lineref->[$e_pid] == 0) &&
	       ($lineref->[$e_subsys] == $subsysnum->{RPC}) &&
	       ($lineref->[$e_mask] == $tracemasks->{VFSTRACE})) {
	    if ($lineref->[$e_fmtstr] =~ /\s*(\d+)\s+(\w+)/) {
		# first is pid, second is cmd
		my $pid = $1;
		my $cmdline = $2;
		if (exists $pidhashref->{$pid}) {
		    $pidhashref->{$pid}->[$e_pidcmd] = $cmdline;
		    # printf "XXX pid=%d, cmd=%s\n", $1, $2;
		}
	    }
	}
	# Match RPCs
	else {
	    update_RPC($rpc_ref, $lineref);
	}
	# For all lines create parent/child relations
	setup_relations($lineref, $pidprevious);
	# Remember last line for this pid
	$lastline->{$lineref->[$e_pid]} = $lineref;
    }
    print STDERR "#debugreq= $debugreq\n";

    foreach $pid (sort (sort_by_number_descending keys %$pidhashref)) {
	# print STDERR "pid: $pid \[$pidhashref->{$pid}->[$e_pidcmd]\]\n";
	my $linecnt = 0;
	my $pidlines_ref = $pidhashref->{$pid}->[$e_lineref];
	my $next = 0;
	do {
	    $next = $pidlines_ref->[$e_next];
	    $linecnt++;
	    $pidlines_ref = $next;
	} until ($next == 0);
	if ($pid) { # Skip pid 0 which are the lines listing all PIDs
	    print STDERR "pid=$pid \[$pidhashref->{$pid}->[$e_pidcmd]\] lines=$linecnt\n";
	}
    }

    print STDERR "Matching RPCs.....\n";

    match_RPC($rpc_ref);
    # print_RPCmatrix($rpc_ref);
    #exit 0;
    #match_LDLM($ldlm_ref);
    return $arrayref;	
}

# Main loop, parses the debug log

sub parse_file 
{
    my $input_files = shift;
    my $marker_ref = shift;
    my $rpc_ref = shift;
    my $vfs_ref = shift;
    my $ldlm_ref = shift;
    my $pid_ref = shift;
    
    my $pid = shift;
    my $rpctrace = shift;
    my $trace = shift;
    my $nodlm = shift;
    my $noclass = shift;
    my $nonet = shift;
    my $uml = shift;

    $backref = 0;
    $treeparent = 0;
    $numchildren = 0;
    $youngestchild = 0;
    $next = 0;
    $pidhead = 0;
    $marked = 0;
    $iter = 0;
			
    foreach $file (@$input_files) {
	my $linecnt = 0;
	open(FILEHANDLE, $file) or die "Can't open file: $file\n";
	while(<FILEHANDLE>) {
		
	    $linecnt++;
	    @parsed_line = get_parsed_line($uml, $file, $linecnt, $_);
	    next if ($#parsed_line == 0);

	    next if (ignore_conditions(\@parsed_line, $pid, 
				      $rpctrace, $trace, $nodlm,
				      $noclass, $nonet, $iter));
		
	    if (!exists($pid_ref{$parsed_line[$e_pid]})) {
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
		    $marker_line[$e_fmtstr] = "XRT";
		    $marker_line[$e_treeparent] = 0;
		    $marker_line[$e_numchildren] = 0;
		    $marker_line[$e_youngestchild] = 0;
		    $marker_line[$e_pidhead] = 0;
		$marker_line[$e_next]= 0; # No, no, no:  \@parsed_line;
		    $marker_line[$e_backref] = 0;
		$marker_line[$e_marked] = 0;
		$pid_ref{$parsed_line[$e_pid]} = \@marker_line;
		    push @$array_parsed, [ @marker_line ];
		    
		}
		push @$array_parsed, [ @parsed_line ];
	    }
	close(FILEHANDLE);
	if ($iter == 0) {
	    # Insert end of client line marker, an all zero pattern;
	    @marker_line = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	    push @$array_parsed, [ @marker_line ]; 
	}
	$iter++;
    }
    $array_parsed = process_array($array_parsed, $pid_ref, $marker_ref,
				  $rpc_ref, $vfs_ref, $ldlm_ref);
    # print_array($array_parsed);
    return $array_parsed;
}

sub match_RPC {
    my $rpc_ref = shift;
    my @sorted_key_list = sort keys %$rpc_ref; 
    my $num_rpc = 0;
    my $i = 0;
	
    my $rpclistcnt = $#sorted_key_list ;

    foreach $rpckeys (@sorted_key_list) {
	my $rpc_refcnt = 1;
	$i++;
	$tmpref = $rpc_ref->{$rpckeys};
	next if ($tmpref->[$e_rpcmarked] == 1);
	$tmpref->[$e_rpcmarked] = 1;
	# This has to be the first for this xid & opcode
	if ($tmpref->[$e_rpcsndrcv] == $CLI_SEND) {
	    $tmpref->[$e_cliRPCent] = $tmpref->[$e_curline];
	    $num_rpc++;
	} else {
	    print STDERR "SKIPPING RPC LINE (INCORRECT ENTRY):", 
	    "$tmpref->[$e_curline]->[$e_fmtstr]\n";
	    next;
	}
	#print "CLIENT ENTRY POINT :$tmpref->[$e_curline]->[$e_fmtstr]\n";
	foreach $j ($i .. $rpclistcnt) {
	    $cmpkeys = $sorted_key_list[$j];
	    # next if ($cmpkeys == $rpckeys);
	    
	    $cmpref = $rpc_ref->{$cmpkeys};
	    next if ($cmpref->[$e_rpcxid] != $tmpref->[$e_rpcxid]);
	    next if ($cmpref->[$e_rpcopc] != $tmpref->[$e_rpcopc]);
	    if ($cmpref->[$e_rpcsndrcv] == $SRV_RCV) { 
		$tmpref->[$e_srvRPCent] = $cmpref->[$e_curline];
		$rpc_refcnt++;
	    }
	    elsif ($cmpref->[$e_rpcsndrcv] == $SRV_REPLY) {
		$tmpref->[$e_srvRPCexit] = $cmpref->[$e_curline];
		$rpc_refcnt++;
	    }
	    elsif ($cmpref->[$e_rpcsndrcv] == $CLI_COMPLETE) {
		$tmpref->[$e_cliRPCexit] = $cmpref->[$e_curline];
		$rpc_refcnt++;
	    }
	    elsif ($cmpref->[$e_rpcsndrcv] == $MDS_REINT) {
		$tmpref->[$e_rpcreint] = $cmpref->[$e_rpcreint];
	    }
	    else {
		print STDERR "Unexpected RPC sndrcv value $cmpref->[$e_rpcsndrcv] for line $tmpref->[$e_curline]->[$e_fmtstr]\n";
	    }
	    $cmpref->[$e_rpcmarked] = 1;
	    if ($rpc_refcnt == 4) {
		break;
	    }
	}
    }
    
    # Now delete all unmatched RPC hashes & set all marked back to zero
    foreach $rpckeys (@sorted_key_list) {
	$rpc_line = $rpc_ref->{$rpckeys};
	if ($rpc_line->[$e_cliRPCent] == 0 ||
	    $rpc_line->[$e_cliRPCexit] == 0) {
	    # printf "Unmatched RPC Line: %s\n", $rpc_line->[$e_curline]->[$e_fmtstr];
	    delete $rpc_ref->{$rpckeys};
	}
	else {
	    $rpc_line->[$e_rpcmarked] = 0;
	}
    }
    printf STDERR "Matched $num_rpc RPCs\n";
}
    
sub getnextchild 
{
    my $rootline = shift;
    my $lineref = shift;
    my $tempref = $lineref->[$e_next];
    if (($tempref != 0) && ($tempref->[$e_stack] > $rootline->[$e_stack])) {
	return $tempref;
    }
    return 0;
}

# Parse out the file names given on the command line
sub parse_foptions 
{
    my $inarg = shift;
    my $idx = 0;
    foreach $elem (@$inarg) {
	next if ($elem =~ /$FILEOPTIONREGEX/);
	$filearray[$idx] = $elem;
	$idx++;    
    }
    return \@filearray;
}

sub compute_time_diff
{
    my $first = shift;
    my $second = shift;
    
    my $diff = 
	sprintf "%8.0f", 
	((($second->[$e_time]) - ($first->[$e_time])) *1000000);
    return $diff;
}


# Given a line, compute the duration that this particular
# invocation took. Relies on pointers being set up correctly.
# For the last function, performs an approximation.
# Useful for timing analysis


sub compute_time
{
    my $lineref = shift;
    my $starttime = $lineref->[$e_time];
    my $pidheadtime = ($lineref->[$e_pidhead])->[$e_time];
    my $offset_usecs =
	sprintf "%8.0f", (($starttime - $pidheadtime) * 1000000);
   
    my $youngestchild = $lineref->[$e_youngestchild];
    my $nextofyoungest = $youngestchild->[$e_next];
    my $youngesttime = 0;
    if ($nextofyoungest != 0) {
	$youngesttime = $nextofyoungest->[$e_time];
    } else {
	#This is an approximation, at best for the last tree
	$youngesttime=$youngestchild->[$e_time];
    }
	 
    my $isleaf = ($lineref->[$e_numchildren] == 0);
    my $nexttime = 0;
    if ($lineref->[$e_next] != 0) {
	$nexttime =  ($lineref->[$e_next])->[$e_time];
    } else {
	# Approximation..
	$nexttime = $lineref->[$e_time];
    }
    my $duration_usecs =
	sprintf "%8.0f", 
	((($isleaf ? $nexttime : $youngesttime) - $starttime) * 1000000);

    return [$offset_usecs, $duration_usecs];
}

# Get the parsed line.
sub get_parsed_line()
{
    my $uml = shift;
    my $file = shift;
    my $linecnt = shift;
    my $in_line = shift;
   
    if ($uml) {
	# This if clause is redundant as now HOSTREGEX2 matches both UML
        # and HOST CDEBUG log files (the --uml option kept just in case)
	if($in_line =~ /$UMLREGEX/) {
	    @parsed_line = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 
			    0, 0, 0, 0, 0, 0, 0);
	    #print "$1, $2, $3, $4, $5, $6, $7, $8, $9, $10\n";
	}
	else {
	    chop $in_line;
	    print "Mismatch in UML regular expression (file:$file, line:$linecnt)\n", 
	    "\tOffending line: <$in_line>\n";
	    return 0;
	}
    } else {
	if ($in_line =~ /$HOSTREGEX2/) {
	    @parsed_line = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 
			    0, 0, 0, 0, 0, 0, 0); 
	    #print "$1, $2, $3, $4, $5, $6, $7, $8, $9, $10\n";
	} else {
	    chop $in_line;
	    print "Mismatch in the host file (file:$file, line:$linecnt)\n", 
	    "\tOffending line: <$in_line>\n";
	    return 0;
	}
    }
    return @parsed_line;
}

# Function to skip over all stuff that the user
# doesn't want

sub ignore_conditions
{
    my $parsed_line = shift;

    my $pid = shift;
    my $rpctrace = shift;
    my $trace = shift;
    my $nodlm = shift;
    my $noclass = shift;
    my $nonet = shift;
    my $iter = shift;

   
    if (($pid) && ($iter == 0) && ($parsed_line->[$e_pid] != $pid)) {
	return 1;
    }
    if (($rpctrace) && ($parsed_line->[$e_mask] != $tracemasks->{RPCTRACE})) {
	print "From rpctrace\n";
	return 1;
    }
    if ($trace && $parsed_line->[$e_mask] != $tracemasks->{TRACE}) {
	return 1;
    }
    if ($nodlm && hex($parsed_line->[$e_subsys]) == $subsysnum->{LDLM}) {
        return 1;
    }
    if ($noclass && hex($parsed_line->[$e_subsys]) == $subsysnum->{CLASS}) {
        return 1;
    }
    if ($nonet && (hex($parsed_line->[$e_subsys]) == $subsysnum->{RPC} ||
		   hex($parsed_line->[$e_subsys]) == $subsysnum->{NET} ||
		   hex($parsed_line->[$e_subsys]) == $subsysnum->{PORTALS} ||
		   hex($parsed_line->[$e_subsys]) == $subsysnum->{SOCKNAL} ||
		   hex($parsed_line->[$e_subsys]) == $subsysnum->{QSWNAL} ||
		   hex($parsed_line->[$e_subsys]) == $subsysnum->{GMNAL})) {
	return 1;
    }
    # No use for ENTRY/EXIT markers
    if ($parsed_line->[$e_fmtstr] =~ $PROCESS_MARKER) {
	return 1; 
    }
    return 0;
}

# All print functions reside below here.

sub print_RPCmatrix 
{
    my $rpc_ref = shift;
    foreach $rpckeys (sort keys %$rpc_ref) {
	$rpc_line = $rpc_ref->{$rpckeys};
	$cl_ent_line = $rpc_line->[$e_cliRPCent];
	$cl_ext_line = $rpc_line->[$e_cliRPCexit];
	$srv_ent_line = $rpc_line->[$e_srvRPCent];
	$srv_ext_line = $rpc_line->[$e_srvRPCexit];
	print "*************************\n";
	print "Client entry(Time: $cl_ent_line->[$e_time]): $cl_ent_line->[$e_fmtstr]\n";
	print "Client exit(Time: $cl_ext_line->[$e_time]): $cl_ext_line->[$e_fmtstr]\n";
	print "Server entry(Time: $srv_ent_line->[$e_time]): $srv_ent_line->[$e_fmtstr]\n";
	print "Server exit(Time: $srv_ext_line->[$e_time]): $srv_ext_line->[$e_fmtstr]\n";
	print "**************************\n";
    }
}

sub print_array 
{
    my $arrayref = shift;
    my $cnt=0;
    foreach $lineref (@$arrayref) {
	$cnt++;
	if ($cnt < 20) {
	    if ($lineref->[$e_backref] == 0) {
		print "MARKER LINE(addr): $lineref contents: [@$lineref]\n";
	} else {
		print "REGULAR LINE (addr) :$lineref contents:[@$lineref]\n";
	}
    }
    }
}
    
sub print_RPCfields
{
    my $rpc_line = shift;
    print "RPC LINE: ";
    print "XID: $rpc_line->[$e_rpcxid], OPC: $rpc_line->[$e_rpcopc],",
    "REINT:  $rpc_line->[$e_rpcreint],",
    "SNDRCV: $rpc_line->[$e_rpcsndrcv], MARKED: $rpc_line->[$e_rpcmarked] ",
    "PID: $rpc_line->[$e_rpcpid], NID: $rpc_line->[$e_rpcnid]\n";
}

my $summary_indent = 0;
my $summary_indent_string = "    ";

sub indent_print {
    my $text = shift;
    my $i;
    for ($i=0; $i < $summary_indent; $i++) {
	printf "%s", $summary_indent_string;
    }
    print "$text\n";
}

sub print_tx_totals {
    my $pid = shift;
    my $markercnt = shift;
    my $showtime = shift;
    my $tx_total_vfs_time = shift;
    my $tx_rpc_cli_time = shift;
    my $tx_rpc_srv_time = shift;
    my $tx_rpc_net_time = shift;
    my $tx_total_rpcs = shift;
    my $vfs_idx = shift;
    
    my $cli_compute_time;

    if ($tx_total_rpcs == 0) {
	$cli_compute_time = $tx_total_vfs_time;
    }
    else {
	$cli_compute_time = $tx_total_vfs_time - $tx_rpc_cli_time;
    }
    if ($tx_rpc_srv_time == 0) {
	$tx_rpc_srv_time = "unknown";
	$tx_rpc_net_time = "unknown";
    }
    if ($tx_total_vfs_time != 0) {
	my $textheader = "+++marker summary[$pid.$markercnt]:";
	my $textheaderlen = length($textheader);
	my $text = "$textheader\t[#ll_ops=$vfs_idx, #rpcs=$tx_total_rpcs";
	
	if ($showtime =~ /m/) {
	    $text .= ", $tx_total_vfs_time usecs/total (client=$cli_compute_time, server=$tx_rpc_srv_time, network= $tx_rpc_net_time)";
	}
	$text .= "]";

	print "\n"; 
	indent_print($text);

	if (($showtime =~ /c/) && ($showtime =~ /m/)) {
	    my $avgrpc_concurrency = $tx_rpc_cli_time / $tx_total_vfs_time; 
	    my $pct_client = ($cli_compute_time *100) /  $tx_total_vfs_time;
	    my $pct_srv = 0;
	    my $pct_net = 0;
	    if ($tx_rpc_srv_time != 0) {
		$pct_srv = ($tx_rpc_srv_time *100) /  $tx_total_vfs_time; 
		$pct_net = 100 - $pct_client - $pct_srv;
	    }
	    my $ccline = sprintf "%${textheaderlen}s\t[rpc_concurrency=%d/%d= %.1f (avg), (client=%.0f%%, server=%.0f%%, network=%.0f%%)]", " ", $tx_rpc_cli_time, $tx_total_vfs_time, $avgrpc_concurrency, $pct_client, $pct_srv, $pct_net ;
	    indent_print($ccline);
	}
	print "\n"; 
    }
}

sub print_summary_terse
{
    my $showtime = shift;
    my $array_ref = shift;
    my $marker_ref = shift;
    my $vfs_ref = shift;
    my $rpc_ref = shift;
    my $ldlm_ref = shift;
    my $pid_ref = shift;
    my $ldlmdebug = shift;

    foreach $pid (sort (sort_by_number_descending keys %$pid_ref)) {
	next if ($pid==0);
	my $linecnt = 0;
	my $lineref = $pid_ref->{$pid}->[$e_lineref];
        # print STDERR "pid=$pid \[$pid_ref->{$pid}->[$e_pidcmd]\]\n";	
	$summary_indent = 0;
	indent_print("Process $lineref->[$e_pid] \[$pid_ref->{$pid}->[$e_pidcmd]\]");
	my $vfs_rpc_cli_time;
	my $vfs_rpc_srv_time;
	my $vfs_rpc_net_time;
	my $vfs_time;
	my $rpc_idx;
	my $vfs_idx;
	my $tx_total_rpcs;
	my $tx_rpc_cli_time;
	my $tx_rpc_srv_time;
	my $tx_rpc_net_time;
	my $tx_total_vfs_time;
	my $markercnt = 0;
	my $clearcnts = 1;
	my $vfs_line;

	$lineref = $lineref->[$e_next];

	do {
	    $linecnt++;
	    # Clear counts
	    if ($clearcnts) {
		$rpc_idx = 0;
		$vfs_idx = 0;
		$tx_total_rpcs = 0;
		$clearcnts = 0;
		$vfs_rpc_cli_time = 0;
		$vfs_rpc_srv_time = 0;
		$vfs_rpc_net_time = 0;
		$vfs_time = 0;
		$tx_rpc_cli_time = 0;
		$tx_rpc_srv_time = 0;
		$tx_rpc_net_time = 0;
		$tx_total_vfs_time = 0;
		$vfs_line = 0;
	    }
	    # $lineref = getnextchild($vfs_line, $lineref);
	    my $next = $lineref->[$e_next];
	    # LDLM ?
	    if (($ldlmdebug) && (exists($ldlm_ref->{$lineref->[$e_time]}))) {
		# Needs to get better
		$summary_indent++;
		indent_print("LDLM op: $lineref->[$e_fmtstr]");
		$summary_indent--;
		# $ldlm_time = compute_time ($lineref);
		# print "\t\t\t Completion time (us) : $ldlm_time->[1]\n";
	    }

	    # Known as Client RPC ?
	    my $rpc_line = $rpc_ref->{$lineref->[$e_time]};	    
	    if ($rpc_line) {
		if (($rpc_line->[$e_cliRPCent] != 0) && 
		    ($rpc_line->[$e_cliRPCexit] != 0)) {
		    $rpc_idx++;
		    #
		    my $srv_time;
		    my $net_time;
		    # RPC time computation
		    my $cl_time = compute_time_diff($rpc_line->[$e_cliRPCent],
						    $rpc_line->[$e_cliRPCexit]);
		    $vfs_rpc_cli_time += $cl_time;
		    if (($rpc_line->[$e_srvRPCent] != 0) &&
			($rpc_line->[$e_srvRPCexit] != 0)) {
			$srv_time = compute_time_diff($rpc_line->[$e_srvRPCent],
						      $rpc_line->[$e_srvRPCexit]);
			$net_time = $cl_time - $srv_time;
			$vfs_rpc_srv_time += $srv_time;
			$vfs_rpc_net_time += $net_time;
		    } else {
			$srv_time = "unknown";
			$net_time = "unknown";
		    }
		    my $rpcopcode = $ll_opcodes{$rpc_line->[$e_rpcopc]};
		    my $line = "rpcxid #$rpc_line->[$e_rpcxid] $rpcopcode";
		    if ($rpcopcode eq "MDS_REINT") {
			my $reint_opcode = $rpc_line->[$e_rpcreint];
			$line .= "($reint_opcode)";
		    }	
		    if ($showtime =~ /r/) {
			$cl_time =~ /\s+([0-9]+)/;
			my $cl_time2 = $1;
			$srv_time =~ /\s+([0-9]+)/;
			my $srv_time2 = $1;
			$line .= "\t\t[$cl_time2 usecs/rpc = (server=$srv_time2, network=$net_time)]";
		    }
		    $summary_indent = 3;
		    indent_print($line);
		}
	    }
	    # Check Marker line
	    my $marker_line = $marker_ref->{$lineref->[$e_time]};
	    # Check VFS Op
	    my $next_vfs_line = $vfs_ref->{$lineref->[$e_time]};
	    if (($showtime =~ /v/) && ($vfs_line) &&
		(($next == 0) || ($next_vfs_line)|| ($marker_line))) {	    
		# Print per-VFS call RPC statistics
		my $client_time = int($vfs_time);
		my $srv_time = 0;
		my $net_time = 0;
		if ($rpc_idx != 0) {
		    if ($vfs_rpc_srv_time == 0) {
			$srv_time = "unknown";
			$net_time = "unknown";
		    } else {
			$srv_time = $vfs_rpc_srv_time;
			$net_time = $vfs_rpc_net_time;
		    } 
		    $client_time = $vfs_time - $vfs_rpc_cli_time;
		}
		my $vfs_time2 = int($vfs_time);
		my $text = "($vfs_line->[$e_function] summary: \t\t[#rpcs=$rpc_idx, $vfs_time2 usecs/total = (client=$client_time, server=$srv_time, network=$net_time)])";
		$summary_indent = 3;
		indent_print($text);
	    }
	    # Process the VFS call
	    if ($next_vfs_line) {
		$vfs_line = $next_vfs_line;
		$tx_total_rpcs += $rpc_idx;
		$vfs_idx++;
		
		$tx_rpc_cli_time += $vfs_rpc_cli_time;
		$tx_rpc_srv_time += $vfs_rpc_srv_time;
		$tx_rpc_net_time += $vfs_rpc_net_time;
		$tx_total_vfs_time += $vfs_time;
		
		$vfs_rpc_cli_time = 0;
		$vfs_rpc_srv_time = 0;
		$vfs_rpc_net_time = 0;
		$vfs_time = 0;
		
		$vfs_tmp_time = compute_time($vfs_line);
		$vfs_time = $vfs_tmp_time->[1];
		
		$vfs_line->[$e_fmtstr] =~ $VFS_REGEX;
		$summary_indent = 2;
		indent_print("$vfs_line->[$e_function]\($1\)");
		$rpc_idx = 0;
	    }
	    # Process Marker Line
	    if (($next == 0) || ($marker_line)) {
		$summary_indent = 1;
		if (($next == 0) || ($linecnt > 1)) {
		    $tx_total_rpcs += $rpc_idx;
		    $tx_rpc_cli_time += $vfs_rpc_cli_time;
		    $tx_rpc_srv_time += $vfs_rpc_srv_time;
		    $tx_rpc_net_time += $vfs_rpc_net_time;
		    $tx_total_vfs_time += $vfs_time;
		    # Print total Transaction time of previous TxN
		    print_tx_totals($pid, $markercnt, $showtime,
				    $tx_total_vfs_time, $tx_rpc_cli_time, 
				    $tx_rpc_srv_time, $tx_rpc_net_time, 
				    $tx_total_rpcs, $vfs_idx);
		}
		if ($marker_line) {
		    $markercnt++;
		    indent_print("+++marker[$pid.$markercnt]: $marker_line->[1]\n");
		}
		$clearcnts = 1;
	    }
	    $lineref = $next;
	} until ($lineref == 0);
    }
}
		
sub print_summary_verbose 
{
    my $showtime = shift;
    my $array_ref = shift;
    my $marker_ref = shift;
    my $vfs_ref = shift;
    my $rpc_ref = shift;
    my $ldlm_ref = shift;
    my $pid_ref = shift;
    my $ldlmdebug = shift;

    my $bool = 0;
    my $firsttime;

    foreach $lineref (@$array_ref) {
	next if ($lineref->[$e_time] == 0);
	
	if($lineref->[$e_backref] == 0) {
	    $firsttime = 1;
		
	}
	# First see if any marker exists
	if (exists $marker_ref->{$lineref->[$e_time]}) {
	    if ($bool) {
		# Print total Transaction time of previous TxN
		
		if ($tx_total_vfs_time == 0) {
		    print "\n\t TX SUMMARY : No VFS Operation invoked for this transaction\n";
		} else {
		    print "\n\t TX SUMMARY : Operation Time (total): $tx_total_vfs_time\n ";
		    if ($tx_total_rpcs == 0) {
			print "\t TX SUMMARY : NO RPCs performed for this transaction\n";
		    } else {
			print "\t TX SUMMARY : Total No of RPCs done : $tx_total_rpcs\n";
			print "\t TX SUMMARY : Operation Time (client): $tx_rpc_cli_time\n ";
			if ($tx_rpc_srv_time == 0) {
			    print "\t TX SUMMARY : Operation Time (server): UNKNOWN\n ";
			    print "\t TX SUMMARY : Operation Time (network): UNKNOWN\n ";
			    
			} else {
			    print "\t TX SUMMARY : Operation Time (server): $tx_rpc_srv_time\n ";
			    print "\t TX SUMMARY : Operation Time (network): $tx_rpc_net_time\n ";
			    
			}
		    }
	    }
	    	    
		print "\n\n\t +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
	}

	    $marker_line = $marker_ref->{$lineref->[$e_time]};
	    if ($firsttime && $prevpid != $lineref->[$e_pid]) {
		print "\n*******************************Process $lineref->[$e_pid] Summary**************************************\n";
		$firsttime = 0;
		$prevpid = $lineref->[$e_pid];
	    }
	    print "\n\t ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
	    print "\tOPERATION PERFORMED: $marker_line->[1]\n";
	    $vfs_idx = 0;
	    $bool = 1;
	    $tx_total_rpcs = 0;
	    $tx_rpc_cli_time = 0;
	    $tx_rpc_srv_time = 0;
	    $tx_rpc_net_time = 0;
	    $tx_total_vfs_time = 0;
	    
	}
	# Next see if there is any VFS op this one's performing
	
	if (exists $vfs_ref->{$lineref->[$e_time]}) {
	    $vfs_line = $vfs_ref->{$lineref->[$e_time]};
	    $vfs_idx++;
	    
	    $vfs_rpc_cli_time = 0;
	    $vfs_rpc_srv_time = 0;
	    $vfs_rpc_net_time = 0;
	    $vfs_time = 0;
	    
	    print "\n\t\t%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
	    print "\t\t LLITE/VFS Operation # $vfs_idx: $vfs_line->[$e_function]:$vfs_line->[$e_time]\n";
		$vfs_tmp_time = compute_time($vfs_line);
	    $vfs_time = $vfs_tmp_time->[1];
	    print "\t\t Total time for completion: $vfs_time\n"; 
	    # Now iterate over for this VFS operation
	    $tmpref = $vfs_line;
	    $rpc_idx = 0;
	    do {
		
		if ((exists($ldlm_ref->{$tmpref->[$e_time]})) && 
		    ($ldlmdebug)) {
		    # Needs to get better
		    print "\n\t\t\t LDLM Operation: $tmpref->[$e_fmtstr]\n";
		    $ldlm_time = compute_time ($tmpref);
		    print "\t\t\t Completion time (us) : $ldlm_time->[1]\n";
		}
		if (exists($rpc_ref->{$tmpref->[$e_time]})) {
		    $rpc_line = $rpc_ref->{$tmpref->[$e_time]};
		    if (($rpc_line->[$e_cliRPCent] != 0) && 
			($rpc_line->[$e_cliRPCexit] != 0)) {
			$rpc_idx ++;
			print "\n\t\t\t$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n";
			print "\t\t\t RPC  # $rpc_idx\n";
			print "\t\t\t RPC-TxID: $rpc_line->[$e_rpcxid]\n";
			print "\t\t\t RPC-OpCde:$ll_opcodes{$rpc_line->[$e_rpcopc]}\n";
			print "\t\t\t RPC-Starttime(Client): $rpc_line->[$e_cliRPCent]->[$e_time]\n";
			print "\t\t\t RPC-Endtime(Client): $rpc_line->[$e_cliRPCexit]->[$e_time]\n";
			$cl_time = compute_time_diff($rpc_line->[$e_cliRPCent],
						     $rpc_line->[$e_cliRPCexit]);
			$vfs_rpc_cli_time += $cl_time;
			print "\t\t\t Client RPC Completion Time(us): $cl_time\n";
			if (($rpc_line->[$e_srvRPCent] != 0) &&
			    ($rpc_line->[$e_srvRPCexit] != 0)) {
				
				$srv_time = compute_time_diff($rpc_line->[$e_srvRPCent],
							      $rpc_line->[$e_srvRPCexit]);
				$net_time = $cl_time - $srv_time;
				$vfs_rpc_srv_time += $srv_time;
				$vfs_rpc_net_time += $net_time;
				print "\t\t\t Server RPC Start time (us): $rpc_line->[$e_srvRPCent]->[$e_time]\n";
				print "\t\t\t Server RPC End time (us): $rpc_line->[$e_srvRPCexit]->[$e_time]\n";

				print "\t\t\t Server RPC Time (us): $srv_time\n";
				print "\t\t\t Network RPC Time (us): $net_time\n";
				
			    } else {
				print "\t\t\t Server RPC Time (us): UNKNOWN\n";
				print "\t\t\t Network RPC Time (us): UNKNOWN\n";
	
    }
    }

		}

		$tmpref = getnextchild($vfs_line, $tmpref);
	    } until ($tmpref == 0);

	    # Print BASIC RPC statistics
	    if ($rpc_idx != 0) {
		print "\n\t\t LLite Op $vfs_line->[$e_function] # RPCs: $rpc_idx\n";
    }
	    if ($vfs_rpc_cli_time != 0) {
		print "\t\t LLITE Op $vfs_line->[$e_function] RPC Client Time (us): $vfs_rpc_cli_time\n";
		if ($vfs_rpc_srv_time == 0) {
		    print "\t\t LLITE Op $vfs_line->[$e_function] RPC Server Time (us): UNKNOWN\n";
		    print "\t\t LLITE OP $vfs_line->[$e_function] RPC Network Time (us) : UNKNOWN\n";
		} else {

		    print "\t\t LLITE OP $vfs_line->[$e_function] RPC Server Time (us): $vfs_rpc_srv_time\n";
		    print "\t\t LLITE OP $vfs_line->[$e_function] NET Network time (us): $vfs_rpc_net_time\n";
		} 
	
	    } else {
		print "\n\t\t No RPCs performed for this operation\n";
    }
	
	    $tx_total_rpcs += $rpc_idx;
	    $tx_rpc_cli_time += $vfs_rpc_cli_time;
	    $tx_rpc_srv_time += $vfs_rpc_srv_time;
	    $tx_rpc_net_time += $vfs_rpc_net_time;
	    $tx_total_vfs_time += $vfs_time;
	
	}

    }
    if ($bool) {
	# Print total Transaction time of previous TxN

	if ($tx_total_vfs_time == 0) {
	    print "\n\t TX SUMMARY : No VFS Operation invoked for this transaction\n";
	} else {
	    print "\n\t TX SUMMARY : Operation Time (total): $tx_total_vfs_time\n ";
	    if ($tx_total_rpcs == 0) {
		print "\t TX SUMMARY : NO RPCs performed for this transaction\n";
	    } else {
		print "\t TX SUMMARY : Total No of RPCs done : $tx_total_rpcs\n";
		print "\t TX SUMMARY : Operation Time (client): $tx_rpc_cli_time\n ";
		if ($tx_rpc_srv_time == 0) {
		    print "\t TX SUMMARY : Operation Time (server): UNKNOWN\n ";
		    print "\t TX SUMMARY : Operation Time (network): UNKNOWN\n ";
		    
		} else {
		    print "\t TX SUMMARY : Operation Time (server): $tx_rpc_srv_time\n ";
		    print "\t TX SUMMARY : Operation Time (network): $tx_rpc_net_time\n ";
    
    }
	    }
	}  
	
	print "\n\n\t +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n";
    }
	
}

1;

