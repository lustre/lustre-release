#! /usr/bin/perl -w
use strict;
use Socket;

BEGIN { $ENV{PATH} = '/usr/ucb:/bin' }
sub logmsg { print "$0 $$: @_ at ", scalar localtime, "\n" }

my $NAME = <@ARGV>;
my $uaddr = sockaddr_un($NAME);

socket(Server,AF_UNIX,SOCK_STREAM,0) 	|| die "socket: $!";
unlink($NAME);
bind  (Server, $uaddr) 			|| die "bind: $!";
listen(Server,SOMAXCONN)			|| die "listen: $!";

logmsg "server started on $NAME";

my $rc = fork();
if ($rc > 0) { #parent
    exit();
} elsif ($rc < 0) { # error
    logmsg "fork failed: $rc";
    exit();
}

accept(Client,Server);
logmsg "connection on $NAME";
print Client "from server\n";
close Client;
