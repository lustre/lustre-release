my ($tag, $version, $buildid, $pristine);

sub get_tag()
{

    return $tag;

}

sub get_buildid()
{

    return $buildid;

}

sub is_pristine()
{

    return $pristine;

}

my $META = new IO::File;
if (!$META->open("META")) {
    die "unable to open the META file: $!\n";
}
my $line;
while (defined($line = <$META>)) {
    if ($line =~ /^TAG\s*=\s*(.+)/) {
        $tag = $1;
    } elsif ($line =~ /^VERSION\s*=\s*([\d\.])/) {
        $version = $1;
    } elsif ($line =~ /^BUILDID\s*=\s*([a-g\d]+)/) {
        $buildid = $1;
    } elsif  ($line =~ /^PRISTINE\s*=\s*([01])/) {
        $pristine = $1;
    }
}

1;
