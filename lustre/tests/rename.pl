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
my ($j, $k, $d, $f1, $f2, $path, $count, $silent);
my $create = 0;

GetOptions("silent!"=> \$silent,
           "count=i" => \$count,
           "create=i" => \$create);

my $mtpt = shift || usage();
my $i = shift || usage();
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
    mkdir $path, 0755;
    $j = $files;
    while ($j--) {
        `./mcreate $path/$j`
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
    print "[$$] $mtpt$which/$d/$f1 $mtpt$which/$d/$f2 ...\n";
    rename "$mtpt$which/$d/$f1", "$mtpt$which/$d/$f2";
    print "[$$] done\n" if !$silent;

}
print "Done.\n";
