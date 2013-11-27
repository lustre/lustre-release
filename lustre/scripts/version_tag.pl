#!/usr/bin/perl
# -*- Mode: perl; indent-tabs-mode: nil; cperl-indent-level: 4 -*-

use IO::File;

# get all of the values we want out of the autoMakefile
sub read_autoMakefile() {

    my $file = new IO::File;
    my ($line, $dir, $objdir, $modules, $version, $local_version, $buildid);
    if (!$file->open("autoMakefile")) {
        die "Run ./configure first\n";
    }
    $modules = 1;
    while (defined($line = <$file>)) {
        chomp($line);
        if ($line =~ /^LINUX :?= (.*)/) {
            $dir = $1;
        } elsif ($line =~ /^LINUX_OBJ :?= (.*)/) {
            $objdir = $1;
        } elsif ($line =~ /^MODULES_TRUE = #/ ||
                 $line =~ /^MODULE_TARGET = $/) {
            # modules are not being built
            $modules = 1;
        } elsif ($line =~ /^VERSION = (.*)/) {
            $version = "$1";
        } elsif ($line =~ /^DOWNSTREAM_RELEASE = (.*)/ && $1 ne "") {
            $local_version = "$1";
        } elsif ($line =~ /^BUILDID = (.*)/ && $1 ne "") {
            $buildid = "$1";
        }
    }
    $file->close();

    return ($dir, $objdir, $modules, $version, $local_version, $buildid);

}

sub get_kernver($$)
{

    my $dir = shift;
    my $objdir = shift;

    my $ver = new IO::File;
    if (!$ver->open("$objdir/include/generated/utsrelease.h") &&
	!$ver->open("$objdir/include/linux/utsrelease.h") &&
        !$ver->open("$objdir/include/linux/version.h") &&
	!$ver->open("$dir/include/generated/utsrelease.h") &&
        !$ver->open("$dir/include/linux/utsrelease.h") &&
        !$ver->open("$dir/include/linux/version.h")) {
            die "Run make dep on '$dir'\n";
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
    return $kernver;

}

sub generate_ver($$$$$$$)
{

    my $tag = shift;
    my $local_version = shift;
    my $buildid = shift;
    my $linuxdir = shift;
    my $pristine = shift;
    my $kernver = shift;
    my $env_vers = shift;

    print "#define BUILD_VERSION \"$tag";

    if ($env_vers) {
        print "-$env_vers\"\n";
        return 0;
    }

    if ($local_version ne "") {
        print "-$local_version";
    }

    print "-$buildid";
    # if we want to get rid of the PRISTINE/CHANGED thing, get rid of these
    # lines.  maybe we only want to print -CHANGED when something is changed
    # and print nothing when it's pristine
    if ($pristine) {
        print "-PRISTINE";
    } else {
        print "-CHANGED";
    }

    if ($kernver ne "") {
        print "-$kernver";
    }

    print "\"\n";

}

my $progname = $0;
$progname =~ s/.*\///;

chomp(my $cwd = `pwd`);

my $path = $0;
$path =~ s/(.+)\/.*/\1/;
push(@INC, $cwd . "/" . $path);

# The _first_ argument on the command line may be --make_META
# Remove it from ARGV if found
if ($ARGV[0] eq "--make_META") {
    shift @ARGV;
    $make_meta = 1;
}

# ARGV[0] = srcdir
# ARGV[1] = builddir

# need to be in srcdir
if ($ARGV[0]) {
    chdir($ARGV[0]);
}

if (-d ".git") {
    require "version_tag-git.pl";
} else {
    die("a tree status can only be determined in an source code control system checkout\n")
        if ($make_meta);
    require "version_tag-none.pl";
}

($am_linuxdir, $am_linuxobjdir, $am_modules, $am_version, $local_version,
 $am_buildid) = read_autoMakefile();

my $tag = get_tag();
my $pristine = is_pristine();
my $buildid = get_buildid();

if (!$make_meta) {
    my $kernver = "";
    $kernver = get_kernver($am_linuxdir, $am_linuxobjdir)
        if ($am_linuxdir ne "");

    my $linuxdir =~ s/\//\./g;
    generate_ver($tag, $local_version, $buildid, $linuxdir, $pristine, $kernver,
                 $ENV{LUSTRE_VERS});
} else {
    print "TAG = $tag\n";
    print "VERSION = $am_version\n";
    print "BUILDID = $buildid\n";
    print "PRISTINE = $pristine\n";
    print "LOCAL_VERSION = $local_version\n";
}

exit(0);
