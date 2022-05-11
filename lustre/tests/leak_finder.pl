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
    print "Usage: leak_finder.pl <debug_file> [--option]\n";
    print "    --by_func show leak logs by function name in ascending order.\n";
    print "    --summary implies --by_func, print a summary report by \n";
    print "              the number of total leak bytes of each function \n";
    print "              in ascending order in YAML format.\n";
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
    # message format here needs to match OBD_ALLOC_POST()/OBD_FREE_PRE()
    # mask:subs:cpu:epoch second.usec:?:pid:?:(filename:line:function_name())
    #    alloc-type 'var_name': size at memory_address.
    if ($line =~ m/^(.*)\((.*):(\d+):(.*)\(\)\) (k[m]?|v[m]?|slab-|)(alloc(ed)?|free[d]?(_rcu)?) '(.*)': (\d+) at ([\da-f]+)/) {
        @parsed = split(":", $1);
        if ($parsed[3] <= $start_time) {
                next;
        }

        $file = $2;
        $lno  = $3;
        $func = $4;
        $type = $6;
        $name = $9;
        $size = $10;
        $addr = $11;

	# we can't dump the log after portals has exited, so skip "leaks"
	# from memory freed in the portals module unloading.
	if ($func eq 'portals_handle_init') {
	    next;
	}
        printf("%8s %6d bytes at %s called %s (%s:%s:%d)\n", $type, $size,
               $addr, $name, $file, $func, $lno);
    } elsif ($line =~ m/(alloc(ed)?|free[d]?).*at [0-9a-f]*/) {
        # alloc/free line that didn't match regexp, notify user of missed line
        print STDERR "Couldn't parse line $debug_line, script needs to be fixed:\n$line";
        next;
    } else {
        # line not related to alloc/free, skip it silently
        #print STDERR "Couldn't parse $line";
        next;
    }

    if (index($type, 'alloc') >= 0) {
        if (defined($memory->{$addr})) {
            print STDOUT "*** Two allocs with the same address ($size bytes at $addr, $file:$func:$lno)\n";
            print STDOUT "    first malloc at $memory->{$addr}->{file}:$memory->{$addr}->{func}:$memory->{$addr}->{lno}, second at $file:$func:$lno\n";
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
            print STDOUT "*** Free without malloc ($size bytes at $addr, $file:$func:$lno)\n";
            next;
        }
        my ($oldname, $oldsize, $oldfile, $oldfunc, $oldlno) = $memory->{$addr};

        if ($memory->{$addr}->{size} != $size) {
            print STDOUT "*** Free different size ($memory->{$addr}->{size} alloced, $size freed).\n";
            print STDOUT "    malloc at $memory->{$addr}->{file}:$memory->{$addr}->{func}:$memory->{$addr}->{lno}, free at $file:$func:$lno\n";
            next;
        }

        delete $memory->{$addr};
        $total -= $size;
    }
}
close(INFILE);

my $aa;
my $bb;
my @sorted = sort {
    if (defined($ARGV[1])) {
        if ($ARGV[1] eq "--by_func" or $ARGV[1] eq "--summary") {
            # Sort leak output by source code position
            $aa = "$memory->{$a}->{func}:$memory->{$a}->{lno}:$memory->{$a}->{name}:$memory->{$a}->{size}";
            $bb = "$memory->{$b}->{func}:$memory->{$b}->{lno}:$memory->{$b}->{name}:$memory->{$b}->{size}";
            $aa cmp $bb;
        }
    } else {
        # Sort leak output by allocation time
        $memory->{$a}->{debug_line} <=> $memory->{$b}->{debug_line};
    }
} keys(%{$memory});

$aa = "";
$bb = "";
my $key;
my $leak_count = 1;
my @records;
my $leak_size = 0;
my $leak_func;
my $i = 0;
foreach $key (@sorted) {
    if (defined($ARGV[1]) and $ARGV[1] eq "--summary") {
        $aa = "$memory->{$key}->{func}:$memory->{$key}->{lno}:$memory->{$key}->{name}:$memory->{$key}->{size}";
        if ($bb eq $aa) {
            $leak_count++;
        } elsif ($bb ne ""){
            $records[$i]->{func} = $leak_func;
            $records[$i]->{size} = $leak_size;
            $records[$i]->{count} = $leak_count;
            $records[$i]->{total} = $leak_count * $leak_size;;
            $bb = $aa;
            $i++;
            $leak_count = 1;
        } else {
            $bb = $aa;
        }
        $leak_func = "$memory->{$key}->{func}:$memory->{$key}->{lno}:$memory->{$key}->{name}";
        $leak_size = $memory->{$key}->{size};
    } else {
        print STDOUT "*** Leak: $memory->{$key}->{size} bytes allocated at $key ($memory->{$key}->{file}:$memory->{$key}->{func}:$memory->{$key}->{lno}:$memory->{$key}->{name}, debug file line $memory->{$key}->{debug_line})\n";
    }
}

if (defined($ARGV[1]) and $ARGV[1] eq "--summary") {
    # print a summary report by total leak bytes in ASC order
    my @sorted_records = sort {
        $a->{total} <=> $b->{total};
    } @records;
    foreach $key (@sorted_records) {
        printf("- { func: %-58s, alloc_bytes: %-8d, leak_count: %-6d, leak_bytes: %-8d },\n",
               $key->{func}, $key->{size}, $key->{count}, $key->{total});
    }
}
print STDOUT "maximum used: $max, amount leaked: $total\n";
