use Time::Local;

my ($last_mtime, $pristine);

# for CVS, the buildid is that old "latest mtime" process
sub get_buildid()
{

    return mtime2date($last_mtime);

}

# Use the CVS tag first otherwise use the portals version
sub get_tag()
{

    my $tag;
    my $line;

    my $tagfile = new IO::File;
    if (!$tagfile->open("lustre/CVS/Tag")) {
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
    my $pristine = 1;

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
                die "unable to get mtime of $cur_dir/$file: $!\n";
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
    return $last_mtime, $pristine;

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

sub is_pristine()
{

    return $pristine;

}

($last_mtime, $pristine) = get_latest_mtime();

1;
