package Pack;
use Carp;
use Exporter;
@EXPORT = qw(LOGL, UNLOGL, LOGU32, UNLOGU32, LLOGU32, LUNLOGU32, LOGU64, UNLOGU64, LLOGU64, LUNLOGU64);

sub round_len {
    return ($_[0] + 3) & ~0x3;
}

sub roundq_len {
    return ($_[0] + 3) & ~0x7;
}

# pack a string $_[2]
#  at $offset ($_[1]) 
#  in $buf ($_[0]) 
#  padd to 32bit alignment move $_[1] forward

sub LOGL{
    my $len = length($_[2]);
    my $rlen = round_len($len);
    my $padd = $rlen + $off - length($_[0]);

    if ($padd > 0) {
        $_[0] .= pack "x$padd";
    }
    substr $_[0], $_[1], $len, $_[2];
    $_[1] += $rlen;
}

# pack $_[2], a u32, into $_[0] at offset $_[1]
sub LOGU32 {
    if ($_[1] != round_len($_[1])) {
        confess "packing I on non-word boundary";
    } 
    my $padd = 4 + $off - length($_[0]);

    if ($padd > 0) {
        $_[0] .= pack "L", $_[2];
    } else {
        substr $_[0], $_[1], $len, pack "L", $_[2];
    }
    $_[1] += 4;
}

# pack $_[2], a u32, into $_[0] at offset $_[1]
# use little endian
sub LLOGU32 {
    if ($_[1] != round_len($_[1])) {
        confess "packing V on non-word boundary";
    } 
    my $padd = 4 + $off - length($_[0]);

    if ($padd > 0) {
        $_[0] .= pack "V", $_[2];
    } else {
        substr $_[0], $_[1], $len, pack "V", $_[2];
    }
    $_[1] += 4;
}

sub LLOGU64 {
    if ($_[1] != roundq_len($_[1])) {
        confess "packing Q on non-word boundary";
    } 
    my $padd = 8 + $off - length($_[0]);

    if ($padd > 0) {
        $_[0] .= pack "VV", $_[3], $_[2];
    } else {
        substr $_[0], $_[1], $len, pack "VV", $_[3], $_[2];
    }
    $_[1] += 8;
}

sub LLOGU64 {
    if ($_[1] != roundq_len($_[1])) {
        confess "packing Q on non-word boundary";
    } 
    my $padd = 8 + $off - length($_[0]);

    if ($padd > 0) {
        $_[0] .= pack "LL", $_[3], $_[2];
    } else {
        substr $_[0], $_[1], $len, pack "LL", $_[3], $_[2];
    }
    $_[1] += 8;
}

sub UNLOGL { 
    if (length($_[0]) < $_[1] + round_len($_[2]) ) {
        confess "unpacking buf beyond string length";
    }
    
    $_[3] = unpack "x$_[1]a$_[2]", $_[0];
    $_[1] += round_len($_[2]);
    return $_[3];
}

sub UNLOGU32 { 
    if (length($_[0]) < $_[1] + 4) {
        confess "unpacking u32 beyond string length";
    }
    
    $_[2] = unpack "x$_[1]L", $_[0];
    $_[1] += 4;
    return $_[2];
}

sub LUNLOGU32 { 
    if (length($_[0]) < $_[1] + 4) {
        confess "lunpacking u32 beyond string length";
    }
    $_[2] = unpack "x$_[1]V", $_[0];
    $_[1] += 4;
    return $_[2];
}

sub UNLOGU64 {
    if (length($_[0]) < $_[1] + 8) {
        confess "unpacking u64 beyond string length";
    }
    
    ($_[3], $_[2]) = unpack "x$_[1]LL", $_[0];
    $_[1] += 8;
    return ($_[2], $_[3]);
}

sub LUNLOGU64 {
    if (length($_[0]) < $_[1] + 8) {
        confess "lunpacking u64 beyond string length";
    }
    
    ($_[3], $_[2]) = unpack "x$_[1]VV", $_[0];
    $_[1] += 8;
    return ($_[2], $_[3]);
}

sub test {
    $buf = "";
    $off = 0;
    
    LOGL($buf, $off, "moose");
    print "off $off\n";
    printf "len %d\n", length($buf);
    LLOGU64($buf, $off, 0x01020304, 0x05060708);
    print "off $off\n";
    printf "len %d\n", length($buf);
    LLOGU32($buf, $off, 0x01020304);
    print "off $off\n";
    printf "len %d\n", length($buf);
    $off = 0;
    UNLOGL($buf, $off, length("moose"), $str);
    print "off $off $str\n";
    LUNLOGU64($buf, $off, $high, $low);
    printf "off $off high %x low %x\n", $high, $low;
    LUNLOGU32($buf, $off, $low);
    printf "off $off long %x\n", $low;
    
    $off = 0;
    $str = UNLOGL($buf, $off, length("moose"));
    print "assigned off $off $str\n";
    ($high, $low) = LUNLOGU64($buf, $off);
    printf "assigned off $off high %x low %x\n", $high, $low;
    $low = LUNLOGU32($buf, $off, $low);
    printf "assigned off $off long %x\n", $low;
    
    sysopen F, "/tmp/out", 2;
    syswrite F, $buf, length($buf);
}

# test();
