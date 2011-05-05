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

# "git describe" will just return a tag name if the current commit is
# tagged.  Otherwise, the output will look something like this:
#
#     <tag name>-<commits beyong tag>-g<hash>
#
# Examples:
#     2.0.59-1-g4c20b1f
#     2.0.59-1somecompany-1-g4c20b1f
#     foobar-15-g2e937ca
#
my $desc=`git describe --tags`;
if ($desc =~ /(.+?)(?:-(\d)+-g([0-9a-f]+))\n?/) {
    # tag with describe info added
    $tag = $1;
    $fcoms = $2;
    $hash = $3;
} else {
    # plain tag
    $tag = $desc;
    chomp $tag;
    $fcoms = 0;
    $hash = "";
}

1;
