#!/usr/bin/perl -w

#
# VERY basic functionality test for sysio.  To run, just type ./test_all.pl
# Absolutely no guarantees for running on alpha/cplant 
#

use strict;
use FindBin;

use Cwd 'abs_path';	    

my $alpha_arg = "";
my $use_system = 1;
my $is_broke = 1; # Don't test certain areas known to not work on Cplant
my $arg_count = @ARGV;
foreach my $arg (@ARGV) {
    if ($arg eq "-alpha") {
			$alpha_arg = "-alpha";
    } elsif ($arg eq "-nosystem") {
			$use_system = 0;
    }
}
my $alpha_env = $ENV{"IS_ALPHA"};
# Check the environment vars
if (defined($alpha_env) && ($alpha_env eq "yes")) {
    $alpha_arg = "-alpha";
}

my $failures = 0;
my $success = 0;
# Get cwd..
my $cwd = $ENV{PWD};

# Get tests directory
my $testdir = $FindBin::Bin;

my $namespace_env = "SYSIO_NAMESPACE";
my $home = $ENV{"HOME"};
my $auto_mount = $ENV{"SYSIO_AUTOMOUNT"};
my $root_flags = "0";
my $extras = "";
if ((defined($auto_mount)) && ($auto_mount == "xyes")) {
	$root_flags = "2";

	#
	# Add a /auto directory for automounted file systems. We
	# craft one automount that mounts /usr/home from the native
	# file system. Further automounts in the sub-mounts are not enabled.
	#
	$extras=" \
		{mnt,	dev=\"incore:0755+0+0\",dir=\"/mnt\",fl=2} \
		{creat, ft=dir,nm=\"/mnt/home\",pm=0755,ow=0,gr=0} \
		{creat, ft=file,nm=\"/mnt/home/.mount\",pm=0600, \
			str=\"native:/usr/home\"}";
}
$ENV{$namespace_env} = "\
	{mnt,	dev=\"native:/\",dir=/,fl=$root_flags} \
	{mnt,	dev=\"incore:0755+0+0\",dir=\"/dev\"} \
	{creat,	ft=chr,nm=\"/dev/stdin\",pm=0400,mm=0+0} \
	{creat,	ft=chr,nm=\"/dev/stdout\",pm=0200,mm=0+1} \
	{creat,	ft=chr,nm=\"/dev/stderr\",pm=0200,mm=0+2} \
	{creat,	ft=dir,nm=\"/dev/fd\",pm=0755,ow=0,gr=0} \
	{creat,	ft=chr,nm=\"/dev/fd/0\",pm=0400,mm=0+0} \
	{creat,	ft=chr,nm=\"/dev/fd/1\",pm=0200,mm=0+1} \
	{creat,	ft=chr,nm=\"/dev/fd/2\",pm=0200,mm=0+2} \
	{cd,	dir=\"$home\"} \
	$extras ";

my $res;

if ($use_system == 1) {
  # Will use this directory...
  system("mkdir -p $cwd/tmp_dir");

  # Create a couple of files and subdirectories for use in the tests
  system("mkdir -p $cwd/tmp_dir/test1");
  system("mkdir -p $cwd/tmp_dir/test2");

  system("cp $testdir/helper.pm $cwd/tmp_dir/test1");
} else {
    $res = `perl $testdir/setup.pl $alpha_arg $cwd`;
    chop($res);
    if ($res ne "setup successful") {
			print "Test setup failed with $res, bailing out\n";
			exit 1;
    }
}


if (($alpha_arg eq "") || ($is_broke == 0)) {
    # Test getdirentries
    $res = `perl $testdir/test_list.pl $alpha_arg $cwd/tmp_dir`;
    chop($res);
    if ($res ne "list test successful") {
			print "Basic getdirentries test failed with message: $res\n";
			$failures++;
    } else {
			print "test_list finished successfully\n";
			$success++;
    }
}

# Test path
my $path1 = abs_path($testdir);
my @resarr = `perl $testdir/test_path.pl $alpha_arg $path1 $cwd $cwd/tmp_dir`;
$res = $path1.": d\n";
if ($resarr[0] ne $res) {
    print "path test returned $resarr[0] instead of $res\n";
    $failures++;
} else {
	$res = $cwd.": d\n";
	if ($resarr[1] ne $res) {
		print "path test returned $resarr[1] instead of $res\n";
		$failures++;
	} else {
		$res = $cwd."/tmp_dir: d\n";
		if ($resarr[2] ne $res) {
	    print "path test returned $resarr[2] instead of $res\n";
	    $failures++;
		} else {
	    print "test_path finished successfully\n";
	    $success++;
		}
	}
}

# Test getcwd
$res = `perl $testdir/test_getcwd.pl $alpha_arg $cwd/tmp_dir/test1`;
chop($res);
if ($res ne "getcwd test successful") {
    print "getcwd test failed with message: $res\n";
    $failures++;
} else {
    $success++;
    print "test_getcwd finished successfully\n";
}

# Test copy
$res = `perl $testdir/test_copy.pl $alpha_arg $cwd/tmp_dir/test1/helper.pm $cwd/tmp_dir/helper.pm`;
chop($res);
if ($res ne "copy test successful") {
  print "copy test failed with message: $res\n";
  $failures++;
} else {
  $success++;
  print "test_copy finished successfully\n";
}

# Test stats
$res = `perl $testdir/test_stats.pl $alpha_arg $use_system $cwd/tmp_dir/test1/helper.pm`;
chop($res);
if ($res ne "stat test successful") {
  print "stat test failed with message: $res\n";
  $failures++;
} else {
  $success++;
  print "test_stats finished successfully\n";
}

# Test stdfd
$res = `echo "foobar" | perl $testdir/test_copy.pl $alpha_arg -o /dev/stdin /dev/stdout`;
chop($res);
if ($res ne "copy test successful") {
  print "stdfd test failed with message: $res\n";
  $failures++;
} else {
  $success++;
  print "test_stdfd finished successfully\n";
}

# Test symlink
$res = `perl $testdir/test_symlink.pl $alpha_arg $cwd/tmp_dir/test1/helper.pm $cwd/tmp_dir/helper.foo`;
chop($res);
if ($res ne "Symlink test successful") {
  print "symlink test failed with message: $res\n";
  $failures++;
} else {
  $success++;
  print "test_symlink finished successfully\n";
}

# Test r/w calls
$res = `perl $testdir/test_rw.pl $alpha_arg $cwd/tmp_dir/tmp.foo`;
chop($res);
if ($res ne "rw test successful") {
  print "rw test failed with message: $res\n";
  $failures++;
} else {
  $success++;
  print "rw test finished successfully\n";
}

# Test strided I/O
$res = `perl $testdir/test_strided.pl $alpha_arg $cwd/tmp_dir/tmp2.foo`;
chop($res);
if ($res ne "strided IO test successful") {
  print "strided IO test failed with message: $res\n";
  $failures++;
} else {
  $success++;
  print "strided IO test finished successfully\n";
}

print "$failures tests failed and $success tests succeeded\n";

# cleanup -- only if no failures
if ($failures == 0) {
	if ($use_system == 1) {
    system(`rm -rf $cwd/tmp_dir`);
	} else {
    $res = `perl $testdir/cleanup.pl $alpha_arg $cwd`;
    chop($res);
    if ($res ne "cleanup successful") {
			print "Test cleanup failed with $res, bailing out\n";
			exit 1;
    }   
	}
}
exit $failures;
