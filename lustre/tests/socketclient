#!/usr/bin/perl -w
use Socket;
use strict;
my ($rendezvous, $line);

$rendezvous = shift || <@ARGV>;
socket(SOCK, AF_UNIX, SOCK_STREAM, 0)	|| die "socket: $!";
connect(SOCK, sockaddr_un($rendezvous))	|| die "connect: $!";
while (defined($line = <SOCK>)) {
	print $line;
}
exit;  
