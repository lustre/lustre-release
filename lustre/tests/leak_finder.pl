#!/usr/bin/perl -w

use IO::Handle;

STDOUT->autoflush(1);
STDERR->autoflush(1);

my ($line, $memory);
my $debug_line = 0;

while ($line = <>) {
    $debug_line++;
    my ($file, $func, $lno, $name, $size, $addr, $type);
    if ($line =~ m/^.*\((.*):(\d+):(.*)\(\) (\d+ \| )?\d+\+\d+\): [vk](.*) '(.*)': (\d+) at (.*) \(tot .*$/) {
        $file = $1;
        $lno = $2;
        $func = $3;
        $type = $5;
        $name = $6;
        $size = $7;
        $addr = $8;
        printf("%8s %6d bytes at %s called %s (%s:%s:%d)\n", $type, $size,
               $addr, $name, $file, $func, $lno);
    } else {
        next;
    }

    if ($type eq 'malloced') {
        $memory->{$addr}->{name} = $name;
        $memory->{$addr}->{size} = $size;
        $memory->{$addr}->{file} = $file;
        $memory->{$addr}->{func} = $func;
        $memory->{$addr}->{lno} = $lno;
        $memory->{$addr}->{debug_line} = $debug_line;
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
    }
}

# Sort leak output by allocation time
my @sorted = sort {
    return $memory->{$a}->{debug_line} <=> $memory->{$b}->{debug_line};
} keys(%{$memory});

my $key;
foreach $key (@sorted) {
    my ($oldname, $oldsize, $oldfile, $oldfunc, $oldlno) = $memory->{$key};
    print STDERR "*** Leak: $memory->{$key}->{size} bytes allocated at $key ($memory->{$key}->{file}:$memory->{$key}->{func}:$memory->{$key}->{lno}, debug file line $memory->{$key}->{debug_line})\n";
}

print "Done.\n";
