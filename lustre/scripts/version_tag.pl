#!/usr/bin/perl
# -*- Mode: perl; indent-tabs-mode: nil; cperl-indent-level: 4 -*-

use strict;
use diagnostics;
use IO::File;
use Time::Local;

my $pristine = 1;
my $kernver = "";

# Use the CVS tag first otherwise use the portals version
sub get_tag()
{
    my $tag;
    my $line;

    my $tagfile = new IO::File;
    if (!$tagfile->open("lustre/CVS/Tag")) {
        # is there a good way to do this with git or should the git case just
        # fall through to use config.h?  it is always nice to know if we are
        # working on a tag or branch.
        my $verfile = new IO::File;
        if (!$verfile->open("config.h")) {
          return "UNKNOWN";
        }
        while(defined($line = <$verfile>)) {
            $line =~ /\#define VERSION "(.*)"/;
            if ($1) {
                $tag = $1;
                last;
            }
        }
        $verfile->close();
        return $tag
    } else {
        my $tmp = <$tagfile>;
        $tagfile->close();

        $tmp =~ m/[TN](.*)/;
        return $1;
    }
}

sub get_latest_mtime()
{
    my %months=("Jan" => 0, "Feb" => 1, "Mar" => 2, "Apr" => 3, "May" => 4,
                "Jun" => 5, "Jul" => 6, "Aug" => 7, "Sep" => 8, "Oct" => 9,
                "Nov" => 10, "Dec" => 11);

    my $last_mtime = 0;

    # a CVS checkout
    if (-d "CVS") {
        # if we got here, we are operating in a CVS checkout
        my @entries = `find . -name Entries`;
        my $entry_file;
        foreach $entry_file (@entries) {
            chomp($entry_file);
            my $entry = new IO::File;
            if (!$entry->open($entry_file)) {
                die "unable to open $entry_file: $!\n";
            }
            my $line;
            while (defined($line = <$entry>)) {
                chomp($line);
                #print "line: $line\n";
                my ($junk, $file, $version, $date) = split(/\//, $line);

                #print "junk: $junk\nfile: $file\nver: $version\ndate: $date\n";
                #print "last_mtime: " . localtime($last_mtime) . "\n";

                if ($junk eq "D" ||
                    $file eq "lustre.spec.in") {
                    # also used to skip: "$file !~ m/\.(c|h|am|in)$/" but I see
                    # no good reason why only the above file patterns should
                    # count towards pristine/changed.  it should be any file,
                    # surely.
                    next;
                }

                my $cur_dir = $entry_file;
                $cur_dir =~ s/\/CVS\/Entries$//;
                my @statbuf = stat("$cur_dir/$file");
                my $mtime = $statbuf[9];
                if (!defined($mtime)) {
                    next;
                }
                my $local_date = gmtime($mtime);
                if ($local_date ne $date &&
                    $file ne "lustre.spec.in") {
                    #print "$file : " . localtime($mtime) . "\n";
                    $pristine = 0;
                }

                if ($mtime > $last_mtime) {
                    $last_mtime = $mtime;
                }

                if ($date) {
                    my @t = split(/ +/, $date);
                    if (int(@t) != 5) {
                        #print "skipping: $date\n";
                        next;
                    }
                    my ($hours, $min, $sec) = split(/:/, $t[3]);
                    my ($mon, $mday, $year) = ($t[1], $t[2], $t[4]);
                    my $secs = 0;
                    $mon = $months{$mon};
                    $secs = timelocal($sec, $min, $hours, $mday, $mon, $year);
                    if ($secs > $last_mtime) {
                        $last_mtime = $secs;
                    }
                }
            }
            $entry->close();
        }
    } elsif (-d ".git") {
        # a git checkout
        # TODO: figure out how to determine the most recently modified file
        #       in a git working copy.
        #       NOTE: this is not simply the newest file in the whole tree,
        #             but the newest file in the tree that is from the
        #             repository.
        $last_mtime = time();
    } else {
        my $tree_status = new IO::File;
        if (!$tree_status->open("tree_status")) {
            die "unable to open the tree_status file: $!\n";
        }
        my $line;
        while (defined($line = <$tree_status>)) {
            if ($line =~ /^PRISTINE\s*=\s*(\d)/) {
                $pristine = $1;
            } elsif  ($line =~ /^MTIME\s*=\s*(\d+)/) {
                $last_mtime = $1;
            }
        }
    }
    return $last_mtime;

}

sub get_linuxdir()
{
    my $config = new IO::File;
    my ($line, $dir, $objdir);
    if (!$config->open("autoMakefile")) {
        die "Run ./configure first\n";
    }
    while (defined($line = <$config>)) {
        chomp($line);
        if ($line =~ /LINUX :?= (.*)/) {
            $dir = $1;
        } elsif ($line =~ /LINUX_OBJ :?= (.*)/) {
            $objdir = $1;
            last;
        }
    }
    $config->close();
    my $ver = new IO::File;
    if (!$ver->open("$objdir/include/linux/utsrelease.h") &&
        !$ver->open("$objdir/include/linux/version.h") &&
        !$ver->open("$dir/include/linux/utsrelease.h") &&
        !$ver->open("$dir/include/linux/version.h")) {
            die "Run make dep on $dir\n";
        }
    while(defined($line = <$ver>)) {
        $line =~ /\#define UTS_RELEASE "(.*)"/;
        if ($1) {
            $kernver = $1;
            last;
        }
    }
    $ver->close();
    chomp($kernver);
    $dir =~ s/\//\./g;
    return $dir;
}

sub mtime2date($)
{
    my $mtime = shift;

    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) =
      localtime($mtime);
    $year += 1900;
    $mon++;
    my $show_last = sprintf("%04d%02d%02d%02d%02d%02d", $year, $mon, $mday,
                            $hour, $min, $sec);

    return $show_last;
}

sub generate_ver($$$)
{
    my $tag = shift;
    my $mtime = shift;
    my $linuxdir = shift;

    #print "localtime: " . localtime($mtime) . "\n";

    my $lustre_vers = $ENV{LUSTRE_VERS};

    print "#define BUILD_VERSION \"";

    if ($lustre_vers) {
        print "$tag-$lustre_vers\"\n";
        return 0;
    }

    my $show_last = mtime2date($mtime);

    # if we want to get rid of the PRISTINE/CHANGED thing, get rid of these
    # lines.  maybe we only want to print -CHANGED when something is changed
    # and print nothing when it's pristine
    if ($pristine) {
        print "$tag-$show_last-PRISTINE-$linuxdir-$kernver\"\n";
    } else {
        print "$tag-$show_last-CHANGED-$linuxdir-$kernver\"\n";
    }
}

my $progname = $0;
$progname =~ s/.*\///;

if ($progname eq "tree_status.pl" && !-d "CVS" && !-d ".git") {
    die("a tree status can only be determined in an source code control system checkout\n");
}

chomp(my $cwd = `pwd`);

# ARGV[0] = srcdir
# ARGV[1] = builddir

# for get_latest_mtime and get_tag you need to be in srcdir

if ($ARGV[0]) {
    chdir($ARGV[0]);
}
my $tag = get_tag();
my $mtime = get_latest_mtime()
    if (!defined($ENV{LUSTRE_VERS}));

if ($progname eq "version_tag.pl") {
    my $linuxdir = get_linuxdir();
    $linuxdir =~ s/\//\./g;
    generate_ver($tag, $mtime, $linuxdir);
} elsif ($progname eq "tree_status.pl") {
    print "PRISTINE = $pristine\n";
    print "MTIME = $mtime\n";
}

exit(0);
