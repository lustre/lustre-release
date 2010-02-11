#!/usr/bin/perl -w

use IO::Handle;

STDOUT->autoflush(1);
STDERR->autoflush(1);

my ($line, $memory);
my $debug_line = 0;

my $total = 0;
my $max = 0;

my @parsed;
my %cpu;
my $start_time = 0;

if (!defined($ARGV[0])) {
        print "No log file specified\n";
        exit
}

open(INFILE, $ARGV[0]);
while ($line = <INFILE>) {
    if ($line =~ m/^(.*)\((.*):(\d+):(.*)\(\)\)/) {
        @parsed = split(":", $1);
        if (substr ($parsed[2], -1, 1) eq "F") {
            chop $parsed[2];
            $cpu{$parsed[2]} = 0;
        } else {
            if (!defined($cpu{$parsed[2]})) {
                $cpu{$parsed[2]} = $parsed[3];
            }
        }
    }
}

foreach $time (values %cpu) {
    if ($start_time < $time) {
        $start_time = $time;
    }
}

print "Starting analysis since $start_time\n";

seek(INFILE, 0, 0);
while ($line = <INFILE>) {
    $debug_line++;
    my ($file, $func, $lno, $name, $size, $addr, $type);
    if ($line =~ m/^(.*)\((.*):(\d+):(.*)\(\)\) (k|v|slab-)(.*) '(.*)': (\d+) at ([\da-f]+)/){
        @parsed = split(":", $1);
        if ($parsed[3] <= $start_time) {
                next;
        }
        
        $file = $2;
        $lno  = $3;
        $func = $4;
        $type = $6;
        $name = $7;
        $size = $8;
        $addr = $9;

	# we can't dump the log after portals has exited, so skip "leaks"
	# from memory freed in the portals module unloading.
	if ($func eq 'portals_handle_init') {
	    next;
	}
        printf("%8s %6d bytes at %s called %s (%s:%s:%d)\n", $type, $size,
               $addr, $name, $file, $func, $lno);
    } else {
        next;
    }

    if (index($type, 'alloced') >= 0) {
        if (defined($memory->{$addr})) {
            print STDERR "*** Two allocs with the same address ($size bytes at $addr, $file:$func:$lno)\n";
            print STDERR "    first malloc at $memory->{$addr}->{file}:$memory->{$addr}->{func}:$memory->{$addr}->{lno}, second at $file:$func:$lno\n";
            next;
        }

        $memory->{$addr}->{name} = $name;
        $memory->{$addr}->{size} = $size;
        $memory->{$addr}->{file} = $file;
        $memory->{$addr}->{func} = $func;
        $memory->{$addr}->{lno} = $lno;
        $memory->{$addr}->{debug_line} = $debug_line;

        $total += $size;
        if ($total > $max) {
            $max = $total;
        }
    } else {
        if (!defined($memory->{$addr})) {
            print STDERR "*** Free without malloc ($size bytes at $addr, $file:$func:$lno)\n";
            next;
        }
        my ($oldname, $oldsize, $oldfile, $oldfunc, $oldlno) = $memory->{$addr};

        if ($memory->{$addr}->{size} != $size) {
            print STDERR "*** Free different size ($memory->{$addr}->{size} alloced, $size freed).\n";
            print STDERR "    malloc at $memory->{$addr}->{file}:$memory->{$addr}->{func}:$memory->{$addr}->{lno}, free at $file:$func:$lno\n";
            next;
        }

        delete $memory->{$addr};
        $total -= $size;
    }
}
close(INFILE);

# Sort leak output by allocation time
my @sorted = sort {
    return $memory->{$a}->{debug_line} <=> $memory->{$b}->{debug_line};
} keys(%{$memory});

my $key;
foreach $key (@sorted) {
    my ($oldname, $oldsize, $oldfile, $oldfunc, $oldlno) = $memory->{$key};
    print STDERR "*** Leak: $memory->{$key}->{size} bytes allocated at $key ($memory->{$key}->{file}:$memory->{$key}->{func}:$memory->{$key}->{lno}, debug file line $memory->{$key}->{debug_line})\n";
}

print STDERR "maximum used: $max, amount leaked: $total\n";
