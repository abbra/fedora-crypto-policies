#!perl

require 5.000;
use strict;

use profiles::common;

use File::Temp qw/ tempfile /;
use File::Copy;

my $print_init = 0;
my $string     = '';

sub append {
	my $arg = $_[0];
	return if $arg eq '';

	if ( $print_init != 0 ) {
		$string .= ':';
	}
	$string .= $arg;
	$print_init = 1;
}

my %cipher_not_map = (
	'AES-256-CTR'       => '',
	'AES-128-CTR'       => '',
	'AES-256-GCM'  => '!AES-256-GCM',
	'AES-128-GCM'  => '!AES-128-GCM',
	'CHACHA20-POLY1305'  => '!CHACHA20-POLY1305',
	'SEED-CBC'  => '!SEED',
	'IDEA-CBC'  => '!IDEA',
	'DES-CBC'   => '!DES',
	'RC4-40'    => '',
	'DES40-CBC' => '',
	'3DES-CBC'  => '!3DES',
	'RC4-128'   => '!RC4',
	'RC2-CBC'   => '!RC2',
	'NULL'      => '!eNULL:!aNULL'
);

my %key_exchange_map = (
	'RSA'       => 'kRSA',
	'ECDHE'     => 'kEECDH',
	'PSK'       => 'kPSK',
	'DHE-PSK'   => 'kDHEPSK',
	'DHE-RSA'   => 'kEDH',
	'DHE-DSS'   => 'kEDH',
	'ECDHE-PSK' => 'kECDHEPSK'
);

my %key_exchange_not_map = (
	'ANON'       => '',
	'DH'         => '',
	'ECDH'       => '',
	'EXPORT' => '!EXP',
	'RSA'       => '!kRSA',
	'ECDHE'     => '!kEECDH',
	'DHE-RSA'   => '!aRSA',
	'DHE-DSS'   => '!aDSS',
	'PSK'       => '!kPSK',
	'DHE-PSK'   => '!kDHEPSK',
	'ECDHE-PSK' => '!kECDHEPSK'
);

my %mac_not_map = ( 'HMAC-MD5' => '!MD5',
	'HMAC-SHA1' => '!SHA1'
);

sub generate_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $libdir  = shift(@_);

	if (!-e "$libdir/profiles/$profile.pl") {
		print STDERR "Cannot file $profile.pl in $libdir/profiles\n";
		exit 1;
	}
	do "$libdir/profiles/$profile.pl";

	$string = '';
	$print_init = 0;

	foreach (@key_exchange_list) {

		my $val = $key_exchange_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "openssl: unknown: $_\n";
		}
	}

	foreach (@key_exchange_not_list) {
		my $val = $key_exchange_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "openssl: unknown: $_\n";
		}
	}

	foreach (@tls_cipher_not_list) {
		my $val = $cipher_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "openssl: unknown: $_\n";
		}
	}

	foreach (@mac_not_list) {
		my $val = $mac_not_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "openssl: unknown: $_\n";
		}
	}

	append('!SSLv2');
	append('!ADH');

	# SECLEVEL bit and security level calculations
	# do not align 100% with our levels, and they
	# combine may aspects of policy (e.g., increasing
	# level will disable DH instead of key sizes).
	#
	# 0: 80-bits
	# 1: 112: 512-bit DH allowed
	# 2: 128 (no-ssl3): all DH disallowed
	# 3: 192 TLS1.1+
	# 4: 256 TLS1.2+
	if ($sec_bits < 80) {
		append('@SECLEVEL=0');
	} elsif ($sec_bits < 112) {
		append('@SECLEVEL=1');
	} else {
		append('@SECLEVEL=3');
	}

	return $string;
}

sub test_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $gstr    = shift(@_);

	if (-e "/usr/bin/openssl") {
		my ( $fh, $filename ) = tempfile();
		print $fh $gstr;
		close $fh;
		system("openssl ciphers `cat $filename` >/dev/null");
		my $ret = $?;

		if ( $ret != 0 ) {
			unlink($filename);
			print STDERR "There is an error in openssl generated policy\n";
			print STDERR "policy: $gstr\n";
			exit 1;
		}

		my $res = qx(openssl ciphers `cat $filename`);
		unlink($filename);

		if ($res =~ /NULL|ADH/ ) {
			print STDERR "There is NULL or ADH in openssl generated policy\n";
			print STDERR "policy: $gstr\n";
			exit 1;
		}
	}
}

1;
