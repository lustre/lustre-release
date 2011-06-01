my ($tag, $fcoms, $hash);

sub get_buildid()
{

    return $main::am_buildid;

}

sub is_pristine()
{

    if ($fcoms > 0) {
        return 0;
    }

    my $diffcount=`git diff | wc -l`;
    if ($diffcount > 0) {
        return 0;
    }

    return 1;

}

sub get_tag()
{

    return $tag;

}

my $desc=`git describe --tags`;
$desc =~ /([^-]+)(?:-(.+)-(.+))?\n/;
$tag = $1;
$fcoms = $2;
$hash = $3;

1;
