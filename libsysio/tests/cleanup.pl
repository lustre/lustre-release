#!/usr/bin/perl -w

use IPC::Open2;

use strict;
use FindBin;
use lib "$FindBin::Bin";
use helper;

sub usage
{
    print "Usage: ./cleanup.pl <cwd> : Remove system directories used for test\n";
    exit(-1);
}

sub do_remove
{
    my ($cmdfh, $outfh, $type, $cwd, $lastdir) = @_;
    my $cmd;
    if ($type eq "dir") {
	$cmd = "rmdir";
    } else {
	$cmd = "unlink";
    }
    my $cmdstr = "CALL $cmd $cwd/$lastdir\n";

    # Now remove the file/dir
    helper::send_cmd($cmdfh, $outfh, $cmd, $cmdstr);  

    # Verify the directory was made correctly
    helper::verify_cmd($cmdfh, $outfh, $cmd);      
 }


my $currarg = 0;
my $is_alpha = 0;
my $alpha_arg = "";
if (@ARGV == 0) {
    usage();
}
if ((@ARGV > 1) && ($ARGV[$currarg++] eq "-alpha")){
    $is_alpha = 1;
    $alpha_arg = $ARGV[$currarg-1];
} 

my $cwd = $ARGV[$currarg];

# Get tests directory
my $testdir = $FindBin::Bin;
  
eval {
    if ($is_alpha == 0) {
	open2(\*OUTFILE, \*CMDFILE, "$testdir/test_driver --np");
    } else {
	open2(\*OUTFILE, \*CMDFILE, 
	      "yod -batch -quiet -sz 1 $testdir/test_driver --np");
    }
};

if ($@) {
    if ($@ =~ /^open2/) {
	warn "open2 failed: $!\n$@\n";
	return;
    }
    die;
}

my $outfh = \*OUTFILE;
my $cmdfh = \*CMDFILE;

if ($is_alpha == 0) {
    helper::send_cmd($cmdfh, $outfh, "init", "CALL init\n");
}

# Remove the helper.pms
do_remove($cmdfh, $outfh, "file", $cwd, "tmp_dir/helper.pm");
do_remove($cmdfh, $outfh, "file", $cwd, "tmp_dir/test1/helper.pm");

# Remove directories
do_remove($cmdfh, $outfh, "dir", $cwd, "tmp_dir/test1");
do_remove($cmdfh, $outfh, "dir", $cwd, "tmp_dir/test2");
do_remove($cmdfh, $outfh, "dir", $cwd, "tmp_dir");

print $cmdfh "exit\n";
close $outfh;

# Give test_driver time to finish
sleep 0.000001;

print STDOUT "cleanup successful\n";

exit 0;




