#!/usr/bin/perl
use Getopt::Long;

my $silent = 0;
my $mcreate = 1; # should we use mcreate or open?
my $files = 5;

GetOptions("silent!" => \$silent,
           "mcreate=i" => \$mcreate,
           "files=i" => \$files);

my $mtpt = shift || usage();
my $mount_count = shift || usage();
my $i = shift || usage();
my $count = $i;

sub usage () {
    print "Usage: $0 [--silent] [--mcreate=n] [--files=n] <mnt prefix> <mnt count> <iterations>\n";
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
            print  "Creating $path [" . $$."]...\n" if !$silent;
            $tmp =~ /.*error: (.*)\n/;
            print  "Create done [$$] $path: $!\n" if !$silent;
        } else {
            print  "Create done [$$] $path: Success\n"if !$silent;
        }
    } else {
        print  "Opening $path [" . $$."]...\n"if !$silent;
        open(FH, ">$path") || die "open($PATH): $!";
        print  "Open done [$$] $path: Success\n"if !$silent;
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
    print  "Unlink $path start [" . $$."]...\n"if !$silent;
    if (unlink($path)) {
        print  "Unlink done [$$] $path: Success\n"if !$silent;
    } else {
        print  "Unlink done [$$] $path: $!\n"if !$silent;
    }
    if (($count - $i) % 100 == 0) {
        print STDERR ($count - $i) . " operations [" . $$ . "]\n";
    }
}

my $which = "";
if ($mount_count > 0) {
    $which = int(rand() * $mount_count) + 1;
}
for ($d = 0; $d < $files; $d++) {
    unlink("$mtpt$which/$d");
}

print "Done.\n";
