#!/usr/bin/perl
#	Check the stack usage of functions
#
#	Copyright Joern Engel <joern@wh.fh-wedel.de>
#	Inspired by Linus Torvalds
#	Original idea maybe from Keith Owens
#	s390 port and big speedup by Arnd Bergmann <arnd@bergmann-dalldorf.de>
#	Modified to have simpler output format by Dan Kegel
#
#	Usage:
#	objdump -d vmlinux | stackcheck.pl [arch]
#
#	find <moduledir> -name "*.o" | while read M; do
#		objdump -d $M | perl ~/checkstack.pl <arch> | \
#			sed "s/^/`basename $M`: /" ; done | \
#	awk '/esp/ { print $5, $2, $4 }' | sort -nr

#	TODO :	Port to all architectures (one regex per arch)

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
	$x	= "[0-9a-f]{1,5}";		# hex number
	$d	= "[0-9]{1,5}";	# decimal number
	if ($arch eq "") {
		$arch = `uname -m`;
	}
	if ($arch =~ /^i[3456]86$/) {
		#c0105234:       81 ec ac 05 00 00       sub    $0x5ac,%esp
		$re = qr/^.*(sub    \$(0x$x),\%esp)$/o;
		$todec = sub { return hex($_[0]); };
	} elsif ($arch =~ /^ia64$/) {
		#e0000000044011fc:       01 0f fc 8c     adds r12=-384,r12
		$re = qr/.*(adds.*r12=-($d),r12)/o;
		$todec = sub { return $_[0]; };
	} elsif ($arch =~ /^mips64$/) {
		#8800402c:       67bdfff0        daddiu  sp,sp,-16
		$re = qr/.*(daddiu.*sp,sp,-($d))/o;
		$todec = sub { return $_[0]; };
	} elsif ($arch =~ /^mips$/) {
		#88003254:       27bdffe0        addiu   sp,sp,-32
		$re = qr/.*(addiu.*sp,sp,-($d))/o;
		$todec = sub { return $_[0]; };
	} elsif ($arch =~ /^ppc$/) {
		#c00029f4:       94 21 ff 30     stwu    r1,-208(r1)
		$re = qr/.*(stwu.*r1,-($x)\(r1\))/o;
		$todec = sub { return hex($_[0]); };
	} elsif ($arch =~ /^s390x?$/) {
		#   11160:       a7 fb ff 60             aghi   %r15,-160
		$re = qr/.*(ag?hi.*\%r15,-($d))/o;
		$todec = sub { return $_[0]; };
	} else {
		print "Usage:  objdump -d vmlinux | checkstack.pl [arch]\n";
		print "where arch is i386, ia64, mips, mips64, ppc, or s390\n";
		print "Each output line gives a function's stack usage, name\n";
		print "Lines are output in order of decreasing stack usage\n";
		die("wrong or unknown architecture\n");
	}
}

$funcre = qr/^[0-9a-f]* \<(.*)\>:$/;
while ($line = <STDIN>) {
	if ($line =~ m/$funcre/) {
		($func = $line) =~ s/$funcre/\1/;
		chomp($func);
	}
	if ($line =~ m/$re/) {
		push(@stack, &$todec($2)." ".$func);
		# don't expect more than one stack allocation per function
		$func .= " ** bug **";
	}
}

foreach (sort { $b - $a } (@stack)) {
	print $_."\n";
}
