#!/usr/bin/perl

my $mtpt = shift || usage();
my $mount_count = shift || usage();
my $i = shift || usage();
my $files = 5;
my $mcreate = 0; # should we use mcreate or open?

sub usage () {
    print "Usage: $0 <mount point prefix> <mount count> <iterations>\n";
    print "example: $0 /mnt/lustre 2 50\n";
    print "         will test in /mnt/lustre1 and /mnt/lustre2\n";
    print "         $0 /mnt/lustre -1 50\n";
    print "         will test in /mnt/lustre only\n";
    exit;
}

sub do_open($) {
    my $path = shift;

    if ($mcreate) {
        my $tmp = `./mcreate $path`;
        if ($tmp) {
            $tmp =~ /.*error: (.*)\n/;
            print "Created  $path: $1\n";
        } else {
            print "Created  $path: Success\n";
        }
    } else {
        open(FH, ">$path") || die "open($PATH): $!";
        print "Opened   $path: Success\n";
        close(FH) || die;
    }
}

while ($i--) {
    my $which = "";
    if ($mount_count > 0) {
        $which = int(rand() * $mount_count) + 1;
    }
    $d = int(rand() * $files);
    do_open("$mtpt$which/$d");

    if ($mount_count > 0) {
        $which = int(rand() * $mount_count) + 1;
    }
    $d = int(rand() * $files);
    $path = "$mtpt$which/$d";
    if (unlink($path)) {
        print "Unlinked $path: Success\n";
    } else {
        print "Unlinked $path: $!\n";
    }
}
print "Done.\n";
