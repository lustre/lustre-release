#!/usr/bin/perl

#	Check the stack usage of functions
#
#	Copyright Joern Engel <joern@wh.fh-wedel.de>
#	Inspired by Linus Torvalds
#	Original idea maybe from Keith Owens
#
#	Usage:
#	objdump -d vmlinux | checkstack.pl <arch>
#
#	find <moduledir> -name "*.o" | while read M; do
#		objdump -d $M | perl ~/checkstack.pl <arch> | \
#			sed "s/^/`basename $M`: /" ; done | \
#	awk '/esp/ { print $5, $2, $4 }' | sort -nr
#
#	TODO :	Port to all architectures (one regex per arch)
#		Speed this puppy up

# check for arch
# 
# $re is used for three matches:
# $& (whole re) matches the complete objdump line with the stack growth
# $1 (first bracket) matches the code that will be displayed in the output
# $2 (second bracket) matches the size of the stack growth
#
# use anything else and feel the pain ;)
{
	my $arch = shift;
	$x	= "[0-9a-f]";	# hex character
	$xs	= "[0-9a-f ]";	# hex character or space
	if ($arch =~ /^i[3456]86$/) {
		#c0105234:       81 ec ac 05 00 00       sub    $0x5ac,%esp
		$re = qr/^.*(sub/s\$(0x$x{3,5}),\%esp)$/o;
	} elsif ($arch =~ /^ia64$/) {
		#                                        adds r12=-384,r12
		$re = qr/.*(adds/sr12=-($x{3,5}),r12)/o;
	} elsif ($arch =~ /^ppc$/) {
		#c00029f4:       94 21 ff 30     stwu    r1,-208(r1)
		$re = qr/.*(stwu/sr1,-($x{3,5})\(r1\))/o;
	} elsif ($arch =~ /^s390x?$/) {
		#   11160:       a7 fb ff 60             aghi   %r15,-160
		$re = qr/.*(ag?hi.*\%r15,-(([0-9]{2}|[3-9])[0-9]{2}))/o;
	} else {
		print("wrong or unknown architecture\n");
		exit
	}
}

sub bysize($) {
	($asize = $a) =~ s/$re/\2/;
	($bsize = $b) =~ s/$re/\2/;
	$bsize <=> $asize
}

#
# main()
#
$funcre = qr/^$x* \<(.*)\>:$/;
while ($line = <STDIN>) {
	if ($line =~ m/$funcre/) {
		($func = $line) =~ s/$funcre/\1/;
		chomp($func);
	}

	if ($line =~ m/$re/) {
		(my $addr = $line) =~ s/^($xs{8}).*/0x\1/o;
		chomp($addr);

		my $intro = "$addr $func:";
		my $padlen = 56 - length($intro);
		while ($padlen > 0) {
			$intro .= '	';
			$padlen -= 8;
		}
		(my $code = $line) =~ s/$re/\1/;

		$stack[@stack] = "$intro $code";
	}
}

@sortedstack = sort bysize @stack;

foreach $i (@sortedstack) {
	print("$i");
}
--
Andreas Dilger
http://sourceforge.net/projects/ext2resize/
http://www-mddsp.enel.ucalgary.ca/People/adilger/


