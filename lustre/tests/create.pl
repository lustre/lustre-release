#!/usr/bin/perl

sub usage () {
    print "Usage: $0 <mount point prefix> <mount count> <iterations>\n";
    print "example: $0 /mnt/lustre 2 50\n";
    print "         will test in /mnt/lustre1 and /mnt/lustre2\n";
    exit;
}

my $mtpt = shift || usage();
my $mount_count = shift || usage();
my $i = shift || usage();
my $files = 2;

while ($i--) {
    $which = int(rand() * $mount_count) + 1;
    $d = int(rand() * $files);
    $path = "$mtpt$which/$d";
    my $tmp = `./mcreate $path`;
    if ($tmp) {
        $tmp =~ /.*error: (.*)\n/;
        print "Created  $path: $1\n";
    } else {
        print "Created  $path: Success\n";
    }

    $which = int(rand() * $mount_count) + 1;
    $d = int(rand() * $files);
    $path = "$mtpt$which/$d";
    if (unlink($path)) {
        print "Unlinked $path: Success\n";
    } else {
        print "Unlinked $path: $!\n";
    }
}
print "Done.\n";
