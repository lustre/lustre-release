#!/usr/bin/perl

$mtpt = shift || die;
$mount_count = shift || die;
$i = shift || die;

while ($i--) {
    $which = int(rand() * $mount_count) + 1;
    $path = "$mtpt$which/";

    $d = int(rand() * 5);
    print `./mcreate $path$d`;

    $which = int(rand() * $mount_count) + 1;
    $path = "$mtpt$which/";

    $d = int(rand() * 5);
    unlink("$path$d") || print "unlink($path$d): $!\n"
}
