#!/usr/bin/perl -w

use IPC::Open2;

use strict;
use FindBin;
use lib "$FindBin::Bin";
use helper;

sub usage
{
    print "Usage: ./setup.pl <cwd> : Setup initial system directories for test\n";
    exit(-1);
}

sub do_makedir
{
    my ($cmdfh, $outfh, $cwd, $lastdir) = @_;
    my $cmd = "CALL mkdir $cwd/$lastdir 0777\n";

    # Now create newdir
    helper::send_cmd($cmdfh, $outfh, "mkdir", $cmd);  

    # Verify the directory was made correctly
    helper::verify_cmd($cmdfh, $outfh, "mkdir");      
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


# Create tmp_dir
do_makedir($cmdfh, $outfh, $cwd, "tmp_dir");
do_makedir($cmdfh, $outfh, $cwd, "tmp_dir/test1");
do_makedir($cmdfh, $outfh, $cwd, "tmp_dir/test2");

# Copy helper.pm
print STDERR "Copying $testdir/helper.pm to $cwd/tmp_dir/test1/helper.pm\n";
my $res = `perl $testdir/test_copy.pl $alpha_arg $testdir/helper.pm $cwd/tmp_dir/test1/helper.pm`;
chop($res);

if ($res ne "copy test successful") {
  print STDERR "setup (copy test) failed with message: $res\n";
  print $cmdfh "exit\n";
  close $outfh;

  # Give test_driver time to finish
  sleep 0.000001;

  print STDOUT "Copying of helper.pm failed\n";
  exit 1;
} 

 print $cmdfh "exit\n";
close $outfh;

# Give test_driver time to finish
sleep 0.000001;

print STDOUT "setup successful\n";

exit 0;




