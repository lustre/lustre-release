#!/usr/bin/perl
# -*- mode: cperl; cperl-indent-level: 4; cperl-continued-statement-offset: 0; cperl-extra-newline-before-brace: t; -*-
#
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
	     $e_time $e_displaystr $e_function $e_pid
	     $e_stack $e_fmtstr $e_backref $e_marked $e_treeparent
	     $e_numchildren $e_youngestchild $e_next $e_pidhead
	     $e_rpcsndrcv $e_rpcpid $e_rpcxid $e_rpcnid $e_rpcopc
	     $e_rpcnext $e_curlineref $SEND $RCV);

($e_subsys,
 $e_mask,
 $e_time,
 $e_displaystr,
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
 $e_marked,
 $e_rpcref) = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

($e_rpcuuid,
 $e_rpcxid,
 $e_rpcopc,
 $e_rpcreint,
 $e_rpcsndrcv,
 $e_rpcpid,
 $e_rpcnid) = (0, 1, 2, 3, 4, 5, 6);

 ($e_cliRPCent,
 $e_srvRPCent,
 $e_srvRPCexit,
 $e_cliRPCexit) = ($e_rpcnid+1, $e_rpcnid+2, $e_rpcnid+3, $e_rpcnid+4);

($e_clirpctime,
 $e_srvrpctime) = ($e_cliRPCexit+1, $e_cliRPCexit+2);

# Data structure for pidhashref
($e_lineref, $e_pidcmd) = (0, 1);

# Data structure for ldlmref
($e_rpckey, $e_ltype, $e_reqres, $e_grantedres, $e_reqmode, $e_grantmode) = (0, 1, 2, 3, 4, 5);


# Data structure for HTML

($e_htmline, $e_htmwritten, $e_htmbgcolor) = (0, 1, 2);

# Define the lowest stack values for MARKER/VFS
$MARKER_STACK_VAL = 0;
$VFS_STACK_VAL = 1;

# Main parser regexes, these break down each line into all its components
$REGEX= qr/^(\w+):(\d+):(\d+):(\d+\.(?:\d+))\s\(\s*([^:]+):(\d+):([^()]+)\(\)\s(\d+)(?:\s\|\s(?:\d+))?\+(\d+)\):(.*)$/;


#RPC REGEXES BELOW
$SENDING = "Sending";
$COMPLETED = "Completed";
$HANDLING = "Handling";
$HANDLED = "Handled";
$RPCREGEX = qr/($SENDING|$HANDLING|$HANDLED|$COMPLETED)\sRPC\spname:cluuid:pid:xid:ni:nid:opc\s([-\w]+):([-\w]+):(\d+):(?:0x)?(\w+):(?:\w+):(?:0x)?(\w+):(\d+)/;


#VFS REGEX BELOW
$VFS_REGEX = qr/VFS Op:(.+)/;

# DEBUG_REQ parser
( $e_drq_str, $e_drq_reqadr, $e_drq_xid, $e_drq_transno, $e_drq_opcode, 
  $e_drq_uuid , $e_drq_portal, $e_drq_reqlen, $e_drq_replen, 
  $e_drq_refcnt, $e_drq_rqflags, $e_drq_reqmsgflags, $e_drq_repmsgflags,
  $e_drq_rc) = (0,1,2,3,4,5,6,7,8,9,10,11,12,13,14);


$DEBUGREQ_REGEX= qr/@@@\s([^@]+)\sreq@([a-f\d]+)\sx(\d+)\/t(\d+)\so(\d+)->([<?>\w]+):([-\d]+)\slens\s(\d+)\/(\d+)\sref\s(\d+)\sfl\s([-a-f\d]+)\/([-a-f\d]+)\/([-a-f\d]+)\src\s([-a-f\d]+)/;


#LDLMREGEX 
$LDLM_REGEX = qr/^\s*###/;
$LDLM_FIELDS = qr/ns: ([-\w]+) lock: ([a-f\d]+)\/0x([a-f\d]+) lrc: (\d+)\/(\d+),(\d+) mode: ([-\w]+)\/([-\w]+) res: (\d+)\/(\d+) rrc: (\d+) type: (\w+)(?: \[(\d+)->(\d+)\])? remote: 0x([a-f\d]+)/;

$PLAIN = "PLN";
$EXT = "EXT";
$EMPTY = "EMPTY";
$NOLOCK = "--";
$INVALID = "invalid";

#OTHER REGEXES

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

@graph_colors;
$graph_colors[0] = "#00cccc"; 
$graph_colors[1] = "#ff0000";
$graph_colors[2] = "#ffff66";
$graph_colors[3] = "#99ff99";
$graph_colors[4] = "#3333ff";
$graph_colors[5] = "#cc9933";

$MAX_GRAPH_COLOR = 5;
$DEFAULT_BG_COLOR = "#ffffff";



# Contains all the file names, the first filename is the 
# client. After that are all servers.
my @filearray = ();

my @start_idx = ();

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


sub handle_ldlm
{
    my $rpctype = shift;
    my $rpckey = shift;
    my $ldlmref = shift;
    my $lineref = shift;
    #LDLM ENQUEUE operation on SERVER
    if ($rpctype eq $HANDLING) {
	#print STDERR "***************************\n";
	#print STDERRR "1st $lineref->[$e_fmtstr]\n";
	if (exists $ldlmref->{$lineref->[$e_pid]}) {
	    # Reset for future LDLM on this service thread.
	    $ldlmref->{$lineref->[$e_pid]}->[$e_rpckey] = $rpckey;
	    $ldlmref->{$lineref->[$e_pid]}->[$e_reqres] = $EMPTY;
	    $ldlmref->{$lineref->[$e_pid]}->[$e_ltype] = 0;
	    $ldlmref->{$lineref->[$e_pid]}->[$e_grantedres] = 0;
	    $ldlmref->{$lineref->[$e_pid]}->[$e_reqmode] = $EMPTY;
	    $ldlmref->{$lineref->[$e_pid]}->[$e_grantmode] = 0;
	} else {
		    # First time for this service thread
	    $ldlmref->{$lineref->[$e_pid]} = [$rpckey, 0, 0, 0, 0, 0];
	    $ldlmref->{$lineref->[$e_pid]}->[$e_reqres] = $EMPTY; 
	    $ldlmref->{$lineref->[$e_pid]}->[$e_reqmode] = $EMPTY;
	}
    } elsif ($rpctype eq $HANDLED) {
	$newkey = $ldlmref->{$lineref->[$e_pid]}->[$e_rpckey];
	$ldlmref->{$newkey} = $ldlmref->{$lineref->[$e_pid]};
	$ldlmcontent = $ldlmref->{$newkey};
	delete $ldlmref->{$lineref->[$e_pid]};

    }

}

sub update_ldlm
{
    my $ldlmref = shift;
    my $lineref = shift;

    my $tmpres;

    if (exists($ldlmref->{$lineref->[$e_pid]})) {
	$lineref->[$e_fmtstr] =~ $LDLM_FIELDS;
	if (defined $12) {
	    $ldlmref->{$lineref->[$e_pid]}->[$e_ltype] = $12;
	    if ($ldlmref->{$lineref->[$e_pid]}->[$e_ltype] eq $PLAIN) {
		if ($ldlmref->{$lineref->[$e_pid]}->[$e_reqres] eq $EMPTY) {
		    $ldlmref->{$lineref->[$e_pid]}->[$e_reqres] = "$9/$10";
		    $ldlmref->{$lineref->[$e_pid]}->[$e_reqmode] = "$8";
		    $ldlmref->{$lineref->[$e_pid]}->[$e_grantedres] = "$9/$10";
		    $ldlmref->{$lineref->[$e_pid]}->[$e_grantmode] = "$7";
		}
		$tmpres = "$9/$10";
	    } elsif ($ldlmref->{$lineref->[$e_pid]}->[$e_ltype] eq $EXT){
		if (($ldlmref->{$lineref->[$e_pid]}->[$e_reqres] eq $EMPTY) && ($14 != 0)) {
		    $ldlmref->{$lineref->[$e_pid]}->[$e_reqres] = "$9/$10\{$13:$14\}";
		    $ldlmref->{$lineref->[$e_pid]}->[$e_reqmode] = "$8";
		    $ldlmref->{$lineref->[$e_pid]}->[$e_grantedres] = "$9/$10\{$13:$14\}";
		    $ldlmref->{$lineref->[$e_pid]}->[$e_grantmode] = "$7";
		}
		$tmpres = "$9/$10\{$13:$14\}";
	    }
	    # Update some fields, if there is any reason to do so.
	    if ($ldlmref->{$lineref->[$e_pid]}->[$e_grantmode] eq $NOLOCK) {
		$ldlmref->{$lineref->[$e_pid]}->[$e_grantmode] = $ldlmref->{$lineref->[$e_pid]}->[$e_reqmode];
	    }
	    if (($tmpres ne $ldlmref->{$lineref->[$e_pid]}->[$e_grantedres]) &&
		($tmpres ne $ldlmref->{$lineref->[$e_pid]}->[$e_reqres])) {
		$ldlmref->{$lineref->[$e_pid]}->[$e_grantedres] = $tmpres;
	    }
	    $tmpmode = "$7";
	    if (($tmpmode ne $ldlmref->{$lineref->[$e_pid]}->[$e_grantmode]) &&
		($tmpmode ne $ldlmref->{$lineref->[$e_pid]}->[$e_reqmode])) {
		$ldlmref->{$lineref->[$e_pid]}->[$e_grantmode] = $tmpmode;
	    }
	    #$ldlmcontent = $ldlmref->{$lineref->[$e_pid]};
	    #print STDERR "LINE: $lineref->[$e_fmtstr]\n";
	    #print STDERR "(KEY): $lineref->[$e_pid] (CONTENT): $ldlmcontent->[$e_reqres],",
	    #"$ldlmcontent->[$e_ltype], $ldlmcontent->[$e_reqmode], $ldlmcontent->[$e_grantmode],",
	    #"$ldlmcontent->[$e_grantedres]\n";
	}
    }
}


# Update the RPC hash table, if this line is an RPC (or
# related) line. 

sub update_RPC
{
    my $rpcref = shift;
    my $ldlmref = shift;
    my $pidref = shift;
    my $lineref = shift;

    my $tmpfmtref;
    if ($lineref->[$e_fmtstr] =~ $RPCREGEX) {
	my $rpcuuid =$3;
	my $processname = $2;
	my $rpctype = $1;
	my $rpcxid = $5;
	my $rpcopc = $7;
	my $rpcpid = $4;
	my $rpcnid = $6;
	my $rpckey;

	if ($rpcopc < 104) {
	    $rpckey = "$rpcopc:$rpcxid:$rpcpid:$rpcuuid";
	} else {
	    $rpckey = "$rpcopc:$rpcxid:$rpcpid";
	}
	if ($rpcopc >= 101) {
	    handle_ldlm($rpctype, $rpckey, $ldlmref, $lineref);
	}
	my $thisrpc =  $rpcref->{$rpckey};
	if (!$thisrpc) {
	    # Initialize new RPC entry and insert into RPC hash
	    $thisrpc = [$rpcuuid, $rpcxid, $rpcopc, 0, 0, $rpcpid, $rpcnid, 0, 0, 0, 0, -1, -1];
	    $rpcref->{$rpckey} = $thisrpc;
	}
	# Backlink line to RPC
	$lineref->[$e_rpcref] = $thisrpc;
	# Now update Fields for this RPC
	my $index;
	if ($rpctype eq $SENDING) {
	    $index = $e_cliRPCent;
	} elsif ($rpctype eq $HANDLING) {
	    $index = $e_srvRPCent;
	} elsif ($rpctype eq $HANDLED) {
	    $index = $e_srvRPCexit;
	} elsif ($rpctype eq $COMPLETED) {
	    $index = $e_cliRPCexit;
	} else {
	    print STDERR "Unknown RPC Expression ($rpctype): $lineref->[$e_fmtstr]\n";
	    $index = -1;
	}
	if ($index >= 0) {
	    if ($thisrpc->[$index]==0) {
		# This index is empty - add the current line to RPC
		$thisrpc->[$index] = $lineref;
	    } else {
		print STDERR "Duplicate $rpctype record for RPC [",
		"uuid=$thisrpc->[$e_rpcuuid],",
		"pid=$thisrpc->[$e_rpcpid],",
		"xid=$thisrpc->[$e_rpcxid],",
		"opc=$thisrpc->[$e_rpcopc]]\n";
		print STDERR "Previous line: $thisrpc->[$index]\n";
		print STDERR "Current line: $lineref\n";
	    }
	}
	# Update the name
	$pidref->{$lineref->[$e_pid]}->[$e_pidcmd] = $processname;

	# Check if client entry/exit times are present
	if (($thisrpc->[$e_cliRPCent] != 0) && ($thisrpc->[$e_cliRPCexit] != 0)) {
	    $thisrpc->[$e_clirpctime] = compute_time_diff($thisrpc->[$e_cliRPCent], 
							  $thisrpc->[$e_cliRPCexit]);
	    #print STDERR "Client time: $rpcxid, $thisrpc->[$e_clirpctime]\n";
	}
	if(($thisrpc->[$e_srvRPCent] != 0) && ($thisrpc->[$e_srvRPCexit] != 0)) {
	    $thisrpc->[$e_srvrpctime] = compute_time_diff($thisrpc->[$e_srvRPCent], 
							  $thisrpc->[$e_srvRPCexit]);
	    #print STDERR "Server time: $rpcxid, $thisrpc->[$e_srvrpctime]\n";
	}
	$rpcref->{$rpckey} = $thisrpc;

    } elsif ($lineref->[$e_fmtstr] =~ qr/### /) {
	update_ldlm($ldlmref, $lineref);
    }
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
	    # No UUID ?
	    # insert_rpcref($rpcref, $tmpfmtref, $lineref);
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
    my $newarrayref = shift @_;
    my $pidhashref = shift @_;
    my $marker_ref = shift @_;
    my $rpc_ref = shift @_;
    my $vfs_ref = shift @_;
    my $ldlm_ref = shift @_;

    my %lastline; # Hash of last line by pid
    print STDERR "Building PID/RPC list.....\n";
    
    my $filearrayidx = 0;

    while ($filearrayidx <= $#$newarrayref) {
	my $arrayref = $newarrayref->[$filearrayidx];
	my $arrayindex = 0;
	my $start = times();
	while ($arrayindex <= $#$arrayref) {
	    my $actualidx = ($arrayindex+$start_idx[$filearrayidx])%($#$arrayref+1);
	    my $lineref = $arrayref->[$actualidx];
	    $arrayindex++;
	    next if ($lineref->[$e_time] == 0); #Ignoring all filemarker lines
	    next if ($lineref->[$e_fmtstr] eq $INVALID);  
	    my $pidprevious = $lastline{$lineref->[$e_pid]};
	    if ($pidprevious == 0) {
		# True only for the first line, the PID marker line.
		$pidhashref->{$lineref->[$e_pid]}->[$e_lineref] = $lineref;
		$pidprevious = $lineref;
	    }
	    else {
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
	    else {
		if (($lineref->[$e_fmtstr] =~ qr/($SENDING|$HANDLING|$HANDLED|$COMPLETED)/) || 
		   (($lineref->[$e_fmtstr] =~ $LDLM_REGEX))
		  ) {
		    update_RPC($rpc_ref, $ldlm_ref, $pidhashref, $lineref);
		}
	    }
	    # For all lines create parent/child relations
	    setup_relations($lineref, $pidprevious);
	    # Remember last line for this pid
	    $lastline{$lineref->[$e_pid]} = $lineref;
	}
	my $end = times();
	my $tottime = $end-$start;
	my $fileline = $arrayref->[0]->[$e_fmtstr];
	print STDERR "Processed $fileline, time: $tottime\n"; 
	$filearrayidx++;
    }
    #print_rpc($rpc_ref);
    #print_hash($ldlm_ref);
    return $newarrayref;
}

sub print_hash
{
  my $ht = shift;
  foreach $hashkey (%$ht) {
      print STDERR "KEY: $hashkey CONTENT: $ht->{$hashkey}\n";
  }

}

sub HTML_leftpane
{
    my $htmfile = shift;
    my $arrayref = shift;
    my $pidref = shift;
    my $nograph = shift;
    my $arrayindex = 0;

    # Create the left pane HTML file
    $htmlfilename = sprintf "%s_left.html", $htmfile;
    open (LEFTHTML, ">$htmlfilename");
    print LEFTHTML "<HTML>";
    print LEFTHTML "<HEAD>";
    print LEFTHTML "<TITLE> llhtml view </TITLE>";
    print LEFTHTML "</HEAD>";
    print LEFTHTML "<BODY>\n";

    while ($arrayindex <= $#$arrayref) {
	my $fileline = $arrayref->[$arrayindex]->[0];
	my $graphhtmfile = $fileline->[$e_fmtstr];
	my $fmtline = $fileline->[$e_pid];
	my @pidlist = split(/,/, $fmtline);
	my $element = $pidlist[0];
	$element =~ /(\d+):(.*)/;
	my $numericpid = $1;
	print LEFTHTML "<b>$2</b>";
	if (!$nograph) {
	    print LEFTHTML "   [  <A HREF = \"${htmfile}_${graphhtmfile}.html\" target=\"right\">graph</A>  ]";
	}
	print LEFTHTML "<BR>";
	for($idx = 1; $idx <= $#pidlist; $idx++) {
	    if (($numericpid) && ($pidref->{$element}->[$e_pidcmd] ne "")) {
		my $anchorlinkpid = sprintf "%s_%s", ${numericpid}, ${graphhtmfile};
		print LEFTHTML "<a href = \"${htmfile}_right.html#$anchorlinkpid\" target=\"right\">$numericpid</a>";
		print LEFTHTML "\[$pidref->{$element}->[$e_pidcmd]\]<br>\n";
	    }
	    $element = $pidlist[$idx];
	    $element =~ /(\d+):.*/;
	    $numericpid = $1;
	}
	$arrayindex++;
    }
    print LEFTHTML "</BODY>";
    print LEFTHTML "</HTML>\n";
    close(LEFTHTML);


}


# Main loop, parses the debug log

# 100 microseconds is each table element
$timebase = 1000;

%gblstarttime;

sub parse_file
{
    # File names that need to be slurped
    my $input_files = shift;

    # Hash tables that need to be populated
    my $marker_ref = shift;
    my $rpc_ref = shift;
    my $vfs_ref = shift;
    my $ldlm_ref = shift;
    my $pid_ref = shift;

    # All the options that should be processed 
    my $pid = shift;
    my $rpctrace = shift;
    my $trace = shift;
    my $nodlm = shift;
    my $noclass = shift;
    my $nonet = shift;
    my $sline = shift;
    my $eline = shift;
    my $htmfile = shift;

    my $backref = 0;
    my $treeparent = 0;
    my $numchildren = 0;
    my $youngestchild = 0;
    my $next = 0;
    my $pidhead = 0;
    my $marked = 0;
    my $numfiles = 0;
    foreach $file (@$input_files) {
	my $linecnt = 0;
	my $curridx = 0;
	my $prev_time = 0;
	# Initialize the starting index for this file to be zero
	$start_idx[$numfiles] = 0;
	# Initialize the starting time to be zero
	open(FILEHANDLE, $file) or die "Can't open file: $file\n";
	# Insert beginning of file marker, an all zero pattern
	my $fileline = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
	my $new_file = join('_', split(/[\/, \.]/, $file)); 
	$fileline->[$e_fmtstr] = $new_file;
	my $start = times();
	push @{$array_parsed->[$numfiles]}, $fileline;
	while(<FILEHANDLE>) {
	    $linecnt++;
	    my @parsed_line = get_parsed_line($file, $linecnt, $_, $sline);
	    next if ($#parsed_line == 0);
	    last if ($eline && ($linecnt > $eline));
	    next if (ignore_conditions(\@parsed_line, $pid, 
				      $rpctrace, $trace, $nodlm,
				      $noclass, $nonet));
	    if (!exists($gblstarttime{$new_file})) {
		$gblstarttime{$new_file} = $parsed_line[$e_time];
	    }
	    $curridx++;
	    if ($prev_time > $parsed_line[$e_time]) {
		# Wrapped log
		if ($start_idx[$numfiles] != 0) {
		    print STDERR "Cannot repair file, log broken at lines: $start_idx[$numfiles]",
		    " AND at $linecnt \n";
		    exit;
		}
		print STDERR "Wrapped log at $linecnt in file $file\n";
		$start_idx[$numfiles] = $curridx; # Accounting for the dummy file line
		$gblstarttime{$new_file} = $parsed_line[$e_time];
		# Invalidate all the pid marker lines for this file, until now
		@pids_file = split(/,/, $fileline->[$e_pid]);
		foreach $pid (@pids_file) {
		    $invalid_ref = $pid_ref->{$pid};
		    $invalid_ref->[$e_fmtstr] = "invalid";
		    # Store in a temporary reference 
		    $temp_ref->{$pid} = $pid_ref->{$pid};
		    delete $pid_ref->{$pid};
		}
		# remove all the fileline's pid value
		$fileline->[$e_pid] = 0;
	    }
	    if (!exists($pid_ref->{$parsed_line[$e_pid]})) {
		    # Push a marker for the beginning of this PID
		    my @marker_line;
		    $marker_line[$e_subsys] = 0;
		    $marker_line[$e_mask] = 0;
		    $marker_line[$e_time] = $parsed_line[$e_time];
		    $marker_line[$e_displaystr] = 0;
		    $marker_line[$e_function] = 0;
		    $marker_line[$e_pid] = $parsed_line[$e_pid];
                   # marker lines are everyone's parent, so stack value zero
		    $marker_line[$e_stack] = 0; 
		    $marker_line[$e_fmtstr] = "XRT";
		    $marker_line[$e_treeparent] = 0;
		    $marker_line[$e_numchildren] = 0;
		    $marker_line[$e_youngestchild] = 0;
		    $marker_line[$e_pidhead] = 0;
		    $marker_line[$e_next]= 0; 
		    $marker_line[$e_backref] = 0;
		    $marker_line[$e_marked] = 0;
		    $pid_ref->{$parsed_line[$e_pid]}->[$e_lineref] = $marker_line;
		    $pid_ref->{$parsed_line[$e_pid]}->[$e_pidcmd] = "";
		    # Update the current file line to provide info about all PIDS
		    if ($fileline->[$e_pid] == 0) {
			$fileline->[$e_pid] = $parsed_line[$e_pid];
		    } elsif ($parsed_line[$e_pid] != 0) {
			$fileline->[$e_pid] = sprintf "%s,%s", $fileline->[$e_pid], $parsed_line[$e_pid];
		    }
		    if (exists($temp_ref->{$parsed_line[$e_pid]})) {
			delete $temp_ref->{$parsed_line[$e_pid]};
		    }
		    push @{$array_parsed->[$numfiles]}, [ @marker_line ];
		}
	    push @{$array_parsed->[$numfiles]}, [ @parsed_line ];
	    $prev_time = $parsed_line[$e_time];
	}
	# Determine if there are any outstanding pids that did not reappear
	# in the log
	foreach $pid (keys %$temp_ref) {
	    if (!exists($pid_ref->{$pid})) {
		$valid_ref = $temp_ref->{$pid};
		$valid_ref->[$e_fmtstr] = "XRT";
		$pid_ref->{$pid} = $valid_ref;
		$fileline->[$e_pid] = sprintf "%s,%s", $fileline->[$e_pid], $pid;
		delete $temp_ref->{$pid};
	    }
	}
	close(FILEHANDLE);
	$end = times();
	$tottime = $end - $start;
	print STDERR "Parsed $file in $tottime\n";
	$numfiles++;
    }
    return $array_parsed;
}

sub HTML_graph
{
    my $gbl_array_parsed = shift;
    my $htmfile = shift;
    my $pid_ref = shift;

    my $start = times();
    my $file_idx = 0;
    while ($file_idx <= $#$gbl_array_parsed) {
	my $array_parsed = $gbl_array_parsed->[$file_idx];
	my $lineref = $array_parsed->[0];
	# Prepare the graph file for this file

	my @allpids = split(',', $lineref->[$e_pid]);
	my @actpids = ();
	for($idx = 0; $idx <= $#allpids; $idx ++) {
	    next if ($pid_ref->{$allpids[$idx]}->[$e_pidcmd] eq "");
	    push @actpids, $allpids[$idx];
	}
	@allpids = ();
	undef @allpids;
	if (!exists $actpids[0]) {
    	    next;
	}
	my $colwidth = int 100/($#actpids+2);
	my $graph_file = sprintf "%s_%s.html", $htmfile, $lineref->[$e_fmtstr];
	open(GRAPHHTML, ">$graph_file");
	print GRAPHHTML "<HTML><HEAD><TITLE> Graphical view </TITLE></HEAD><BODY>";
	print GRAPHHTML "<table cellpadding=\"0\" cellspacing=\"0\" border=\"1\" width=\"100\%\"><tbody><tr>";
	print GRAPHHTML "<td valign=\"top\" width=\"$colwidth\%\"><font size=\"-1\">Time<br></font></td>";
	my $lasthtm = $pid_ref->{$actpids[0]}->[$e_lineref];
	for ($idx = 0; $idx <= $#actpids; $idx ++) {
	    my $graphidx = $idx%$MAX_GRAPH_COLOR;
	    my $pid_name = $pid_ref->{$actpids[$idx]}->[$e_pidcmd];
	    my $anchortag = join('_', split(/[\/,:, \.]/, $actpids[$idx]));
	    print GRAPHHTML "<td valign=\"top\" bgcolor=\"$graph_colors[$graphidx]\" width=\"$colwidth\%\">";
	    print GRAPHHTML "<a href = \"${htmfile}_right.html#$anchortag\" target=\"right\">";
	    print GRAPHHTML "<font size = \"-1\">$pid_name</font></a>";
	    print GRAPHHTML "</td>";
	    # Initialize the time origin
	    if (($pid_ref->{$actpids[$idx]}->[$e_lineref]->[$e_time]) < $lasthtm->[$e_time]) {
		$lasthtm = $pid_ref->{$actpids[$idx]}->[$e_lineref];
	    }
	    # Initialize the html state variables for this PID. Note that every PID can doing 
	    # at most 2 RPCs at any time, i.e in the HANDLING, it could do a SENDING. We need
	    # to distinguish between the two, i.e we always maintain two html data structures
	    # for every PID
	    # Store the following for htm initialization, apart from the time origin
	    # (a) current RPC linereference, if any
	    # (b) iswritten : flag determining if the current text for RPC has already been written to HTML
	    # (c) colorcode
	    $htmstate{$actpids[$idx]}[0] = [0, 0, $graph_colors[$graphidx]];
	    $htmstate{$actpids[$idx]}[1] = [0, 0, $graph_colors[($graphidx+2)%$MAX_GRAPH_COLOR]];
	    $currtime = 0;
	}
	#print STDERR "File: $lineref->[$e_fmtstr]\n";
	#print STDERR "Graph starttime: $lasthtm->[$e_time]\n";
	#print STDERR "Txt starttime: $gblstarttime{$lineref->[$e_fmtstr]}\n";
	print GRAPHHTML "</tr>";
	# Do the first line again, we'll pass over it again, if it happens to be the fileline
	my $arrayidx = 0;
	while( $arrayidx <= $#$array_parsed ) {
	    my $lineref = $array_parsed->[($arrayidx+$start_idx[$file_idx])%($#$array_parsed+1)];
	    $arrayidx++;
	    next if ($lineref->[$e_rpcref] == 0);
	    my $l_rpcline = $lineref->[$e_rpcref];
	    my $allexist = ($l_rpcline->[$e_cliRPCent] && 
			    $l_rpcline->[$e_cliRPCexit] && 
			    $l_rpcline->[$e_srvRPCent] && 
			    $l_rpcline->[$e_srvRPCexit]);
	    next if ($allexist == 0);
	    # this is an rpc line:
	    $htmduration = compute_time_diff($lasthtm, $lineref);
	    $flt_htmrows = $htmduration/$timebase;
	    $num_htmrows = sprintf("%.0f", $flt_htmrows);
	    # print everything upto now
	    for ($nrows = 0; $nrows <= $num_htmrows; $nrows ++) { 
		print GRAPHHTML "<tr>";
		if ($nrows == 0) {
		    $newtime = pidoffset_time($lasthtm);
		    print GRAPHHTML "<td valign=\"top\" width=\"$colwidth\%\"><font size=\"-2\">$newtime</font></td>";
		    # Fill upto the next timebase
		    $more = $timebase-($newtime%$timebase);
		    if ($more > $htmduration) {
			$more = $htmduration/2;
		    }
		    $newtime = $newtime + $more;
		} else {
		    #Find if the current timebase will exceed the end of this RPC
		    print GRAPHHTML "<td valign=\"top\" width=\"$colwidth\%\"><font size=\"-2\">$newtime</font></td>";
		    $newtime += $timebase;
		}
		for ($idx = 0; $idx <= $#actpids; $idx ++) {
		    $current_htm = $htmstate{$actpids[$idx]}[1];
		    if ($current_htm->[$e_htmline] == 0) {
			$current_htm = $htmstate{$actpids[$idx]}[0];
		    }
		    if ($current_htm->[$e_htmline] != 0) {
			$bgcolor = $current_htm->[$e_htmbgcolor];
			$text = $current_htm->[$e_htmwritten];
			if ($text == 0) {
			    $htmline = $current_htm->[$e_htmline];
			    $htmrpcline = $htmline->[$e_rpcref];
			    $htmtmdisp = pidoffset_time($htmline);
			    if ($htmrpcline->[$e_rpcpid] == $htmline->[$e_pid]) {
				$duration = $htmrpcline->[$e_clirpctime];
			    } else {
				$duration = $htmrpcline->[$e_srvrpctime];
			    }
			    $until = $htmtmdisp+$duration;
			    $text = "$ll_opcodes{$htmrpcline->[$e_rpcopc]}\@$htmtmdisp\-$until";
			    $anchortxt = "TxID:$htmrpcline->[$e_rpcxid]\{$duration\}";
			    $current_htm->[$e_htmwritten] = 1;
			} else {
			    $text = "";
			}
		    } else {
			$bgcolor = $DEFAULT_BG_COLOR;
			$text = "";
		    }
		    # Now write it
		    if ($text ne "") {
			$print_line = $current_htm->[$e_htmline];
			$print_rpc_line = $print_line->[$e_rpcref];
			$clientline = (($print_rpc_line->[$e_cliRPCent] == $print_line) ||
				       ($print_rpc_line->[$e_cliRPCexit] == $print_line));
			if ($print_rpc_line->[$e_rpcopc] < 104) {
			    if ($clientline) {
				$anchortag = sprintf "cli_%s_%s_%s_%s", $print_rpc_line->[$e_rpcopc],
				$print_rpc_line->[$e_rpcxid],$print_rpc_line->[$e_rpcpid],
				$print_rpc_line->[$e_rpcuuid];
			    } else {
				$anchortag = sprintf "%s_%s_%s_%s", $print_rpc_line->[$e_rpcopc],
				$print_rpc_line->[$e_rpcxid],$print_rpc_line->[$e_rpcpid], 
				$print_rpc_line->[$e_rpcuuid];
			    }
			} else {
			    if ($clientline) {
				$anchortag = sprintf "cli_%s_%s_%s", $print_rpc_line->[$e_rpcopc],
				$print_rpc_line->[$e_rpcxid],$print_rpc_line->[$e_rpcpid];
			    } else {
				$anchortag = sprintf "%s_%s_%s", $print_rpc_line->[$e_rpcopc],
				$print_rpc_line->[$e_rpcxid],$print_rpc_line->[$e_rpcpid];
			    }
			}
			print GRAPHHTML "<td valign=\"top\" bgcolor=\"$bgcolor\" width=\"$colwidth\%\">";
			print GRAPHHTML "<font size = \"-3\">";
			print GRAPHHTML "<a href = \"${htmfile}_right.html#$anchortag\" target = \"right\">$anchortxt</a>";
			print GRAPHHTML " $text";
			print GRAPHHTML "</font></td>";
		    } else {
			print GRAPHHTML "<td valign=\"top\" bgcolor=\"$bgcolor\" width=\"$colwidth\%\">";
			print GRAPHHTML "</td>";
		    }
		}
		print GRAPHHTML "</tr>";
	    }
	    #$currtime = $newtime;
	    $rpc_line = $lineref->[$e_rpcref];
	    $clientry = ($rpc_line->[$e_cliRPCent] == $lineref);
	    $srventry = ($rpc_line->[$e_srvRPCent] == $lineref);
	    $lasthtm = $lineref;
	    $htm_elem = $htmstate{$lineref->[$e_pid]}[1];
	    if ($htm_elem->[$e_htmline] != 0) {
		if ($clientry || $srventry) {
		    print STDERR "Impossible condition, third RPC entry point\n";
		    print STDERR "$lineref->[$e_pid], $lineref->[$e_fmtstr]\n";
		    exit ;
		}
		$htm_elem->[$e_htmline] = 0;
		$htm_elem->[$e_htwritten] = 0;
		next;
	    }
	    $next_elem = $htmstate{$lineref->[$e_pid]}[0];
	    if ($next_elem->[$e_htmline] != 0) {
		if ((!$clientry) && (!$srventry)) {
		    # i.e. this is an exit line
		    $next_elem->[$e_htmline] = 0;
		    $next_elem->[$e_htmwritten] = 0;
		} else {
		    $htm_elem->[$e_htmline] = $lineref;
		    $htm_elem->[$e_htmwritten] = 0;
		}
	    } else {
		$next_elem->[$e_htmline] = $lineref;
		$next_elem->[$e_htmwritten] = 0;
	    }
	}
	print GRAPHHTML "</BODY></HTML>";
	close (GRAPHHTML);
	$file_idx ++;
    }
    my $end = times();
    my $time = $end-$start;
    print STDERR "HTML: Graphing $time secs\n";
}

# Parse out the file names given on the command line
sub parse_foptions 
{
    my $inarg = shift;
    my $idx = 0;
    #print stderr "Files : ";
    foreach $elem (@$inarg) {
	$filearray[$idx] = $elem;
	#print stderr "$filearray[$idx] ";
	$idx++;    
    }
    #print stderr "\n";
    return \@filearray;
}

sub compute_time_diff
{
    my $first = shift;
    my $second = shift;
    my $diff = 
	sprintf "%8.0f", 
	((($second->[$e_time]) - ($first->[$e_time])) *1000000);
    return int($diff);
}

sub pidoffset_time
{
    my $lineref = shift;
    my $starttime = $lineref->[$e_time];
    #my $pidheadtime = ($lineref->[$e_pidhead])->[$e_time];
    my @tmpfilename = split(/:/, $lineref->[$e_pid]);
    my $keyfilename = join('_', split(/[\/, \.]/, $tmpfilename[1]));
    my $pidheadtime = $gblstarttime{$keyfilename};
    my $offset_usecs =
	sprintf "%8.0f", (($starttime - $pidheadtime) * 1000000);
    return int($offset_usecs);
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
    my $file = shift;
    my $linecnt = shift;
    my $in_line = shift;
    my $sline = shift;
    if (($sline) && ($linecnt < $sline)) {
	return 0;
    }
    if ($in_line =~ /$REGEX/) {
	my $tagged_pid = "${8}:${file}";
	my $display_str = "${5}:{6}";
	@parsed_line = ($1, $2, $4, $display_str, $7, $tagged_pid, $9, $10, 
			0, 0, 0, 0, 0, 0, 0, 0); 
	#print "$1, $2, $3, $4, $5, $6, $7, $8, $9, $10\n";
    } else {
	chop $in_line;
	print "MALFORMED LINE :$in_line IN FILE :$file @ $linecnt\n";
	return 0;
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

    if (($pid) && ($parsed_line->[$e_pid] != $pid)) {
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

sub print_array 
{
    my $arrayref = shift;
    foreach $lineref (@$arrayref) {
	if ($lineref->[$e_backref] == 0) {
	    print "MARKER LINE(addr): $lineref contents: [@$lineref]\n";
	} else {
	    print "REGULAR LINE (addr) :$lineref contents:[@$lineref]\n";
	}
    }
}

sub print_RPCfields
{
    my $rpckey = shift;
    my $rpc_line = shift;

    print STDERR "RPC LINE: <$rpckey> ";
    print STDERR "XID: $rpc_line->[$e_rpcxid], OPC: $rpc_line->[$e_rpcopc],",
    "REINT:  $rpc_line->[$e_rpcreint],",
    "SNDRCV: $rpc_line->[$e_rpcsndrcv],",
    "PID: $rpc_line->[$e_rpcpid], NID: $rpc_line->[$e_rpcnid]\n";
    print STDERR "CLIENT ENTRY: $rpc_line->[$e_cliRPCent]->[$e_fmtstr]\n";
    print STDERR "SRV ENTRY: $rpc_line->[$e_srvRPCent]->[$e_fmtstr]\n";
    print STDERR "SRV EXIT: $rpc_line->[$e_srvRPCexit]->[$e_fmtstr]\n";
    print STDERR "CLIENT EXIT: $rpc_line->[$e_cliRPCexit]->[$e_fmtstr]\n";
}

my $summary_indent = 0;
my $summary_indent_string = "  ";

$BREAK_LDLM_REGEXP=qr/(LDLM.+\) => \([^\(]+\))(.+)/;

sub HTML_rightpane
{
    my $text = shift;
    my $HTMHANDLE = shift;

    my $htmlspacing;
    print $HTMHANDLE "<PRE>";
    if ($text =~ /Process\s*(\d+):(.*)/) {
	@tmp = split(" ", $2);
	$newtag = join('_', split(/[\/, \.]/, $tmp[0]));
	$anchortag = sprintf "%s_%s", $1, $newtag;
	print $HTMHANDLE "<A NAME = \"$anchortag\">";
	print $HTMHANDLE $summary_indent_string x $summary_indent;
	print $HTMHANDLE "$text\n</A>";
    } elsif ($text =~ /rpcxid #(\d+)(.*)/) {
	$tmprpc = shift;
	my $allexist = ($tmprpc->[$e_srvRPCent] &&
			$tmprpc->[$e_srvRPCexit] &&
			$tmprpc->[$e_cliRPCent] &&
			$tmprpc->[$e_cliRPCexit]);
	if ($text =~ /link=/) {
	    $pidhashref = shift;
	    if ($tmprpc->[$e_rpcopc] < 104) {
		$anchortag = sprintf "%s_%s_%s_%s", 
		$tmprpc->[$e_rpcopc], $tmprpc->[$e_rpcxid],
		$tmprpc->[$e_rpcpid], $tmprpc->[$e_rpcuuid];
	    } else {
		$anchortag = sprintf "%s_%s_%s",
		$tmprpc->[$e_rpcopc], $tmprpc->[$e_rpcxid],
		$tmprpc->[$e_rpcpid];
	    }
	    my $rpcpidname = ($tmprpc->[$e_cliRPCent])->[$e_pid];
	    my $clipidcmdname = ($pidhashref->{$rpcpidname})->[$e_pidcmd];
	    if ($allexist) {
		print $HTMHANDLE "<A NAME = \"$anchortag\">";
	    }
	    print $HTMHANDLE $summary_indent_string x $summary_indent;
	    # Creating back reference to the client
	    $text =~ qr/(rpcxid\s)(#\d+)(.+)\(link=.+\)/;
	    print $HTMHANDLE "[${clipidcmdname}]:";
	    if ($allexist) {
		print $HTMHANDLE "</A><A HREF = \"#cli_$anchortag\">";
	    }
	    print $HTMHANDLE "xid $2";
	    if ($allexist) {
		print $HTMHANDLE "</A>";
	    }
	    my $rpctext = $3;
	    if ($rpctext =~ /LDLM_.+/) {
		$rpctext =~ $BREAK_LDLM_REGEXP;
		print $HTMHANDLE " $1\n";
		print $HTMHANDLE $summary_indent_string x $summary_indent;
		print $HTMHANDLE "                      $2\n";
	    } else {
		print $HTMHANDLE "$rpctext\n";
	    }
	} else {
	    if ($tmprpc->[$e_rpcopc] < 104) {
		$anchorref = sprintf "%s_%s_%s_%s", 
		$tmprpc->[$e_rpcopc], $tmprpc->[$e_rpcxid], $tmprpc->[$e_rpcpid], $tmprpc->[$e_rpcuuid];
	    } else {
		$anchorref = sprintf "%s_%s_%s",
		$tmprpc->[$e_rpcopc], $tmprpc->[$e_rpcxid], $tmprpc->[$e_rpcpid];
	    }
	    # Only true if the server entry is not zero
	    if ($allexist) {
		print $HTMHANDLE "<A NAME = \"cli_$anchorref\">";
	    }
	    print $HTMHANDLE $summary_indent_string x $summary_indent;
	    if ($allexist) {
		print $HTMHANDLE "</A><A HREF = \"#$anchorref\">";
	    }
	    print $HTMHANDLE "rpcxid #$1";
	    if ($allexist) {
		print $HTMHANDLE "</A>";
	    }
	    my $rpctext = $2;
	    if ($rpctext =~ /LDLM_.+/) {
		$rpctext =~ $BREAK_LDLM_REGEXP;
		print $HTMHANDLE " $1\n";
		print $HTMHANDLE $summary_indent_string x $summary_indent;
		print $HTMHANDLE "                      $2\n";
	    } else {
		print $HTMHANDLE "$rpctext\n";
	    }
	}
    } elsif ($text =~ qr/\+\+\+marker\[([^\]]*)\](.*)/) { 
	print $HTMHANDLE $summary_indent_string x $summary_indent;
	print $HTMHANDLE "+++marker\[<A HREF = \"#$1\">$1</A>\]$2\n";
    } elsif ($text =~ qr/\+\+\+marker summary\[([^\]]*)\](.*)/ ){
	print $HTMHANDLE "<A NAME = \"$1\">";
	print $HTMHANDLE $summary_indent_string x $summary_indent;
	print $HTMHANDLE "+++marker summary\[$1\]$2</A>";
    }else{
	print $HTMHANDLE $summary_indent_string x $summary_indent;
	print $HTMHANDLE "$text\n";
    }
    print $HTMHANDLE "</PRE>";
}


sub indent_print {
    my $text = shift;
    my $HTMHANDLE = shift;
    my $temprpc = shift;
    my $pidhashref = shift;
    my $i;

    # Print the regular stuff
    print $summary_indent_string x $summary_indent;
    print "$text\n";
    # Print HTML
    if ($HTMHANDLE) {
	HTML_rightpane($text, $HTMHANDLE, $temprpc, $pidhashref);
    }
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
    my $HTMHANDLE = shift;

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
	    $text .= ", $tx_total_vfs_time usecs/total (client=$cli_compute_time, server=$tx_rpc_srv_time, network=$tx_rpc_net_time)";
	}
	$text .= "]";

	print "\n"; 
	indent_print($text, $HTMHANDLE, 0, 0);

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
	    indent_print($ccline, $HTMHANDLE, 0, 0);
	}
	print "\n"; 
    }
}

sub print_summary_terse
{
    my $showtime = shift;
    my $marker_ref = shift;
    my $vfs_ref = shift;
    my $rpc_ref = shift;
    my $ldlm_ref = shift;
    my $pid_ref = shift;
    my $ldlmdebug = shift;
    my $htmfile = shift;

    my $start = times();
    my @ignored_pids;
    # HTML stuff
    if ($htmfile ne "") {
	my $htmfilename = sprintf "%s_right.html", $htmfile;
	open(HTMLOG, ">$htmfilename");	
	print HTMLOG "<HTML><HEAD><TITLE> Outputlog </TITLE></HEAD><BODY>";
    }
    foreach $pid (sort (sort_by_number_descending keys %$pid_ref)) {
	$pid =~ /(\d+):(.+)/;
	my $currentpid = $1;
	my $curr_file = $2;
	if ($pid_ref->{$pid}->[$e_pidcmd] eq "") {
	    push @{$ignored_pids{$curr_file}}, $currentpid;
	    next;
	}
	my $linecnt = 0;
	my $lineref = $pid_ref->{$pid}->[$e_lineref];
        #print STDERR "pid=$pid \[$pid_ref->{$pid}->[$e_pidcmd]\]\n";	
	$summary_indent = 0;
	indent_print("Process $lineref->[$e_pid] \[$pid_ref->{$pid}->[$e_pidcmd]\]", HTMLOG, 0, 0);
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

	    if ($lineref->[$e_fmtstr] = "") {
		$lineref = $next;
		next;
	    }
	    # LDLM ?
	    if (($ldlmdebug) && (exists($ldlm_ref->{$lineref->[$e_time]}))) {
		# Needs to get better
		$summary_indent++;
		indent_print("LDLM op: $lineref->[$e_fmtstr]", HTMLOG, 0, 0);
		$summary_indent--;
		# $ldlm_time = compute_time ($lineref);
		# print "\t\t\t Completion time (us) : $ldlm_time->[1]\n";
	    }

	    # Known as RPC ?
	    my $rpc_line = $lineref->[$e_rpcref];
	    if ($rpc_line) {

		my $clientside = ($rpc_line->[$e_rpcpid])==$currentpid;
		my $client_entry = ($rpc_line->[$e_cliRPCent]==$lineref);
		my $server_entry = ($rpc_line->[$e_srvRPCent]==$lineref);
		#print STDERR "Clientside: $clientside, Cliententry: $client_entry",
		#"Serverentry: $server_entry, clienttime: $rpc_line->[$e_clirpctime], srv_time: $rpc_line->[$e_srvrpctime]\n";

		my $srv_time;
		my $net_time;
		my $cl_time;
		my $pidoffset_time;
		if ((($clientside) && ($client_entry)) ||
		    ((!$clientside) && ($server_entry))) {
		    $rpc_idx++;
		    if (($clientside) && ($client_entry) && 
			($rpc_line->[$e_clirpctime] != -1)) {
			# Client Side RPC 
			$cl_time = $rpc_line->[$e_clirpctime];
			#print STDERR "CLIENT TIME: $cl_time\n";
			$pidoffset_time 
			= pidoffset_time($rpc_line->[$e_cliRPCent]);
			$vfs_rpc_cli_time += $cl_time;
			if ($rpc_line->[$e_srvrpctime] != -1){
			    $srv_time = $rpc_line->[$e_srvrpctime];
			    #print STDERR "SERVER TIME: $srv_time\n";
			    $net_time = $cl_time - $srv_time;
			    $vfs_rpc_srv_time += $srv_time;
			    $vfs_rpc_net_time += $net_time;
			} else {
			    $srv_time = "unknown";
			    $net_time = "unknown";
			}
		    } elsif ((!$clientside) && ($server_entry) &&
			     ($rpc_line->[$e_srvrpctime] != -1)) {
			# Server side RPC
			$cl_time = $rpc_line->[$e_srvrpctime];
			#print STDERR "Server time: $cl_time\n";
			$pidoffset_time 
			= pidoffset_time($rpc_line->[$e_srvRPCent]);
		    } else {
			$cl_time = "unknown";
		    }
		    my $rpcopcode = $ll_opcodes{$rpc_line->[$e_rpcopc]};
		    my $line = "rpcxid #$rpc_line->[$e_rpcxid] $rpcopcode";
		    if ($rpcopcode eq "MDS_REINT") {
			my $reint_opcode = $rpc_line->[$e_rpcreint];
			$line .= "($reint_opcode)";
		    }
		    if (($rpcopcode eq "LDLM_ENQUEUE") || ($rpcopcode eq "LDLM_CANCEL")) {
			my $rpckey = "$rpc_line->[$e_rpcopc]:$rpc_line->[$e_rpcxid]:$rpc_line->[$e_rpcpid]:$rpc_line->[$e_rpcuuid]";
			my $lockrec = $ldlm_ref->{$rpckey};
			#print STDERR "LOCKREC: $lockrec->[$e_ltype]\n";
			$line .= "($lockrec->[$e_ltype], $lockrec->[$e_reqres], $lockrec->[$e_reqmode])";
			$line .= " => ($lockrec->[$e_grantedres], $lockrec->[$e_grantmode])";
		    }
		    if (($rpcopcode eq "LDLM_CP_CALLBACK") || ($rpcopcode eq "LDLM_BL_CALLBACK")) {
			my $rpckey = "$rpc_line->[$e_rpcopc]:$rpc_line->[$e_rpcxid]:$rpc_line->[$e_rpcpid]";
			my $lockrec = $ldlm_ref->{$rpckey};
			$line .= "($lockrec->[$e_ltype], $lockrec->[$e_reqres], $lockrec->[$e_reqmode])";
			$line .= " => ($lockrec->[$e_grantedres], $lockrec->[$e_grantmode])";
		    }
		    if ($showtime =~ /r/) {
			$cl_time =~ /\s*([0-9]+)/;
			my $cl_time2 = $1;
			$srv_time =~ /\s*([0-9]+)/;
			my $srv_time2 = $1;
			$line .= "\t\t[$cl_time2 usecs/rpc";
			if ($clientside) {
			    $line .= " (server=$srv_time2, network=$net_time)";
			}
			$line .= "] @ $pidoffset_time";
		    }
		    if (!$clientside) {
			$line .= "\t(link=$rpc_line->[$e_rpcuuid])";
			}
		    $summary_indent = 3;
		    indent_print($line, HTMLOG, $rpc_line, $pid_ref);
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
		my $text = "($vfs_line->[$e_function] summary: \t\t[#rpcs=$rpc_idx, $vfs_time2 usecs/total = (c=$client_time, s=$srv_time, n=$net_time)])";
		$summary_indent = 3;
		indent_print($text, HTMLOG, 0, 0);
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
		indent_print("$vfs_line->[$e_function]\($1\) @ $vfs_tmp_time->[0]", HTMLOG, 0, 0);
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
				    $tx_total_rpcs, $vfs_idx, HTMLOG);
		}
		if ($marker_line) {
		    $markercnt++;
		    indent_print("+++marker[$pid.$markercnt]: $marker_line->[1]\n", HTMLOG, 0, 0);
		}
		$clearcnts = 1;
	    }
	    $lineref = $next;
	} until ($lineref == 0);
    }
    foreach $filename (keys %ignored_pids) {
	print STDERR "Ignoring zero-RPC PIDS in file $filename: ";
	while(@{$ignored_pids{$filename}}) {
	    my $pidnum = pop(@{$ignored_pids{$filename}});
	    print STDERR "$pidnum, ";
	}
	print STDERR "\n";
    }
    if ($htmfile) {
	print HTMLOG "<PRE>\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n</PRE>";
	print HTMLOG "</BODY></HTML>";
	close(HTMLOG);
    }

    my $end = times();
    my $tottime = $end-$start;
    print STDERR "ASCII generation: $tottime\n";
}

sub print_rpc {
    $rpc_ref = shift;
    foreach $rpckey (sort keys %$rpc_ref) {
	print_RPCfields($rpckey, $rpc_ref->{$rpckey}); 	
    }
}

sub gen_HTML 
{
    my $htmname = shift;
    if ($htmname ne "") {
	my $mainhtml = sprintf "%s.html", $htmname;
	open (HTMHANDLE, ">$mainhtml");
	print HTMHANDLE "<HTML><HEAD><TITLE>\"Visualize Log\"</TITLE></HEAD>";
	print HTMHANDLE "<FRAMESET COLS=\"20%, 80%\">";
	print HTMHANDLE "<FRAME NAME=\"left\" SRC=\"${htmname}_left.html\">";
	print HTMHANDLE "<FRAME NAME=\"right\" SRC=\"${htmname}_right.html\">";	
	print HTMHANDLE "</FRAMESET></HTML>";
    }
}




1;
