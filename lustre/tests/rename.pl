#!/usr/bin/perl
use strict;
use diagnostics;
use Getopt::Long;

sub usage () {
    print "Usage: $0 <mount point prefix> <iterations>\n";
    print "example: $0 --count=2 /mnt/lustre 2 50\n";
    print "         will test in /mnt/lustre1 and /mnt/lustre2\n";
    print "         $0 --count=0 /mnt/lustre 50\n";
    print "         will test in /mnt/lustre only\n";
    exit;
}
my ($j, $k, $d, $f1, $f2, $path, $silent);
my $count = 0;
my $create = 10;

GetOptions("silent!"=> \$silent,
           "count=i" => \$count,
           "create=i" => \$create);

my $mtpt = shift || usage();
my $i = shift || usage();
my $total = $i;
my $files = 6;
my $dirs = 3;
my $mcreate = 0; # should we use mcreate or open?

my $which = "";
if ($count > 0) {
    $which = int(rand() * $count) + 1;
}

$k = $dirs;
if ($create == 0) {
    $k = 0;
}
while ($k--) {
    $path = "$mtpt$which/$k";
    my $rc = mkdir $path, 0755;
    print "mkdir $path failed: $!\n" if !$rc;
    $j = $files;
    while ($j--) {
        `./mcreate $path/$j`;
    }
}

while ($i--) {
    my $which = "";
    if ($count > 0) {
        $which = int(rand() * $count) + 1;
    }
    $d = int(rand() * $dirs);
    $f1 = int(rand() * $files);
    $f2 = int(rand() * $files);
    print "[$$] $mtpt$which/$d/$f1 $mtpt$which/$d/$f2 ...\n" if !$silent;
    my $rc = rename "$mtpt$which/$d/$f1", "$mtpt$which/$d/$f2";
    print "[$$] done: $rc\n" if !$silent;
    if (($total - $i) % 100 == 0) {
        print STDERR "[" . $$ . "]" . ($total - $i) . " operations\n";
    }
}
print "Done.\n";
