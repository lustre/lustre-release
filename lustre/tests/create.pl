#!/usr/bin/perl

my $mtpt = shift || die;
my $mount_count = shift || die;
my $i = shift || die;
my $size = 2;

while ($i--) {
    $which = int(rand() * $mount_count) + 1;
    $path = "$mtpt$which/";

    $d = int(rand() * $size);
    print `./mcreate $path$d`;

    $which = int(rand() * $mount_count) + 1;
    $path = "$mtpt$which/";

    $d = int(rand() * $size);
    unlink("$path$d") || print "unlink($path$d): $!\n"
}
print "Done.\n";
