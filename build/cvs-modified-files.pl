#!/usr/bin/env perl

my $mode = "NONE";
my @modified, @added, @removed;

while($line = <>) {
  if ($line =~ /Modified Files:/) {
    $mode = "MODIFIED";
    next;
  }

  if ($line =~ /Added Files:/) {
    $mode = "ADDED";
    next;
  }

  if ($line =~ /Removed Files:/) {
    $mode = "REMOVED";
    next;
  }

  if ($mode eq "NONE") { next; }
  if ($line =~ /-------/) { next; }

  chop($line);
  $line =~ s/^CVS:\s+//;
  $line =~ s/\s+$//;
  # print "processing $line for $mode\n";
  @files = split(/ /, $line);
  # print "new files for $mode: ", join(', ', @files), "\n";

  if ($mode eq "MODIFIED") {
    push(@modified, @files);
  } elsif ($mode eq "ADDED") {
    push(@added, @files);
  } elsif ($mode eq "REMOVED") {
    push(@removed, @files);
  } else {
    die "Unknown mode $mode!";
  }
}

print join(' ', @modified);
if ($ENV{"SHOW_ALL_FILES"} ne "no") {
  print ' ', join(' ', @added), ' ', join(' ', @removed);
}
print "\n";
