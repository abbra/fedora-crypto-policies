#!/usr/bin/perl

use strict;
use warnings;

my ($output_dir) = @ARGV;

if (!defined ${output_dir}) {
    print "usage: generate-policies.pl [install_dir]\n";
    exit 1;
}

my $libdir = "./back-ends/";
use lib "back-ends/";

my @profiles = ("EMPTY", "DEFAULT", "FUTURE", "LEGACY");
my @modules = ("gnutls", "gnutls28", "openssl", "bind", "java", "krb5", "nss", "openssh");
my ($mod, $contents, $profile);
my @reloadcmds = ();
my @tempcmds = ();

foreach $mod (@modules) {
	require "$libdir/$mod.pl";
	my $tmp = '';

    foreach $profile (@profiles) {

        if ($profile eq "DEFAULT") {
        	$tmp = generate_temp_policy($profile, 0, $libdir, \@reloadcmds);
        } else {
                #ignore redundant reload cmds
        	$tmp = generate_temp_policy($profile, 0, $libdir, \@tempcmds);
        }
	$contents = '';

	mkdir "${output_dir}/$profile", 0755;
        open my $fh, '>', "${output_dir}/$profile/$mod.txt" or die($!);
        print $fh $tmp;
        close $fh;
    }
}

my $cmd;
open my $fh, '>', "${output_dir}/reload-cmds.sh" or die($!);
foreach $cmd (@reloadcmds) {
    print $fh $cmd;
}
close $fh;

exit 0;
