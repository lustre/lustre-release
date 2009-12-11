#!/usr/bin/perl

# vim:expandtab:shiftwidth=4:softtabstop=4:tabstop=4:

#
# convert an lmc batch file to a csv file for lustre_config
#
use strict; use warnings;

use Data::Dumper;

sub get_arg_val {
    my $arg = shift;
    my ($aref) = @_;
    for (my $i = 0; $i <= $#$aref; $i++) {
        if ($$aref[$i] eq "--" . $arg) {
            my @foo = splice(@$aref, $i, 2);
            return $foo[1];
        }
    }
}

sub get_arg {
    my $arg = shift;
    my ($aref) = @_;
    for (my $i = 0; $i <= $#$aref; $i++) {
        if ($$aref[$i] eq "--" . $arg) {
            splice(@$aref, $i, 1);
            return 1;
        }
    }

    return 0;
}

sub add_net {
    my $net = {};
    $net->{"node"} = get_arg_val("node", \@_);
    $net->{"nid"} = get_arg_val("nid", \@_);
    $net->{"nettype"} = get_arg_val("nettype", \@_);
    $net->{"port"} = get_arg_val("port", \@_);
    if ($#_ > 0) {
        print STDERR "Unknown arguments to \"--add net\": @_\n";
        exit(1);
    }
    return $net;
}

sub add_mds {
    my $mds = {};
    $mds->{"node"} = get_arg_val("node", \@_);
    $mds->{"mds"} = get_arg_val("mds", \@_);
    $mds->{"fstype"} = get_arg_val("fstype", \@_);
    $mds->{"dev"} = get_arg_val("dev", \@_);
    $mds->{"size"} = get_arg_val("size", \@_);
    if ($#_ > 0) {
        print STDERR "Unknown arguments to \"--add mds\": @_\n";
        exit(1);
    }
    return $mds;
}

sub add_lov {
    my $lov = {};
    $lov->{"lov"} = get_arg_val("lov", \@_);
    $lov->{"mds"} = get_arg_val("mds", \@_);
    $lov->{"stripe_sz"} = get_arg_val("stripe_sz", \@_);
    $lov->{"stripe_cnt"} = get_arg_val("stripe_cnt", \@_);
    $lov->{"stripe_pattern"} = get_arg_val("stripe_pattern", \@_);
    if ($#_ > 0) {
        print STDERR "Unknown arguments to \"--add lov\": @_\n";
        exit(1);
    }
    return $lov;
}

sub add_ost {
    my $ost = {};
    $ost->{"node"} = get_arg_val("node", \@_);
    $ost->{"ost"} = get_arg_val("ost", \@_);
    $ost->{"fstype"} = get_arg_val("fstype", \@_);
    $ost->{"dev"} = get_arg_val("dev", \@_);
    $ost->{"size"} = get_arg_val("size", \@_);
    $ost->{"lov"} = get_arg_val("lov", \@_);
    $ost->{"mountfsoptions"} = get_arg_val("mountfsoptions", \@_);
    $ost->{"failover"} = get_arg("failover", \@_);
    if ($#_ > 0) {
        print STDERR "Unknown arguments to \"--add ost\": @_\n";
        exit(1);
    }
    return $ost;
}

sub add_mtpt {
    my $mtpt = {};
    $mtpt->{"node"} = get_arg_val("node", \@_);
    $mtpt->{"path"} = get_arg_val("path", \@_);
    $mtpt->{"mds"} = get_arg_val("mds", \@_);
    $mtpt->{"lov"} = get_arg_val("lov", \@_);
    if ($#_ > 0) {
        print STDERR "Unknown arguments to \"--add mtpt\": @_\n";
        exit(1);
    }
    return $mtpt;
}

no strict 'refs';

sub find_obj {
    my $type = shift;
    my $key = shift;
    my $value = shift;
    my @objs = @_;

    foreach my $obj (@objs) {
        if ($obj->{$key} eq $value) {
            return $obj;
        }
    }
}

sub lnet_options {
    my $net = shift;

    my $options_str = "options lnet networks=" . $net->{"nettype"} .
                   " accept=all";
    if (defined($net->{"port"})) {
        $options_str .= " accept_port=" . $net->{"port"};
    }
    return $options_str;

}

# main

my %objs;
my @mgses;

my $MOUNTPT = "/mnt";
if (defined($ENV{"MOUNTPT"})) {
    $MOUNTPT = $ENV{"MOUNTPT"};
}

while(<>) {
    my @args = split;

    for (my $i = 0; $i <= $#args; $i++) {
        if ($args[$i] eq "--add") {
            my $type = "$args[$i + 1]";
            my $subref = "add_$type";
            splice(@args, $i, 2);
            push(@{$objs{$type}}, &$subref(@args));
            last;
        }
        if ($i == $#args) {
            print STDERR "I don't know how to handle @args\n";
            exit(1);
        }
    }
}

# link lovs to mdses
foreach my $lov (@{$objs{"lov"}}) {
    my $mds = find_obj("mds", "mds", $lov->{"mds"}, @{$objs{"mds"}});
    $mds->{"lov"} = $lov;
}
# XXX could find failover pairs of osts and mdts here and link them to
# one another and then fill in their details in the csv generators below
my $COUNT = 1;
foreach my $mds (@{$objs{"mds"}}) {
    # find the net for this node
    my $net = find_obj("net", "node", $mds->{"node"}, @{$objs{"net"}});
    my $lov = $mds->{"lov"};
    my $mkfs_options="";
    if (defined($lov->{"stripe_sz"})) {
        $mkfs_options .= "lov.stripesize=" . $lov->{"stripe_sz"} . " ";
    }
    if (defined($lov->{"stripe_cnt"})) {
        $mkfs_options .= "lov.stripecount=" . $lov->{"stripe_cnt"} . " ";
    }
    if (defined($lov->{"stripe_pattern"})) {
        $mkfs_options .= "lov.stripetype=" . $lov->{"stripe_pattern"} . " ";
    }
    chop($mkfs_options);
    if ($mkfs_options ne "") {
        $mkfs_options = " --param=\"$mkfs_options\"";
    }

    if ($COUNT == 1) {
        # mgs/mdt
        printf "%s,%s,%s,$MOUNTPT/%s,mgs|mdt,,,,--device-size=%s --noformat%s,,noauto\n", 
        $mds->{"node"},
        lnet_options($net),
        $mds->{"dev"},
        $mds->{"mds"},
        $mds->{"size"},
        $mkfs_options;

        push(@mgses, $net->{"nid"});
    } else {
        # mdt
        printf "%s,%s,%s,$MOUNTPT/%s,mdt,,\"%s\",,--device-size=%s --noformat,,noauto\n",
        $mds->{"node"},
        lnet_options($net),
        $mds->{"dev"},
        $mds->{"mds"},
        join(",", @mgses),
        $mds->{"size"};
    }
    $COUNT++;
}

foreach my $ost (@{$objs{"ost"}}) {
    # find the net for this node
    my $mount_opts="noauto";
    if (defined($ost->{"mountfsoptions"})) {
        $mount_opts .= "," . $ost->{"mountfsoptions"};
    }
    my $net = find_obj("net", "node", $ost->{"node"}, @{$objs{"net"}});
    printf "%s,%s,%s,$MOUNTPT/%s,ost,,\"%s\",,--device-size=%s --noformat,,\"%s\"\n", 
    $ost->{"node"},
    lnet_options($net),
    $ost->{"dev"},
    $ost->{"ost"},
    join(",", @mgses),
    $ost->{"size"},
    $mount_opts;
}
