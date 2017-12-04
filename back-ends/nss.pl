#!perl

require 5.000;
use strict;

use profiles::common;

my $print_init = 0;
my $string     = '';

sub append {
	my $arg = $_[0];
	return if ( $arg eq '' );

	if ( $print_init != 0 ) {
		$string .= ':';
	}
	$string .= $arg;
	$print_init = 1;
}

my %mac_map = (
	'AEAD'		=> '',
	'HMAC-SHA1'     => 'HMAC-SHA1',
	'HMAC-MD5'      => 'HMAC-MD5',
	'HMAC-SHA2-256' => 'HMAC-SHA256',
	'HMAC-SHA2-384' => 'HMAC-SHA384',
	'HMAC-SHA2-512' => 'HMAC-SHA512'
);

my %hash_map = (
	'SHA1'     => 'SHA1',
	'MD5'      => 'MD5',
	'SHA2-224' => 'SHA224',
	'SHA2-256' => 'SHA256',
	'SHA2-384' => 'SHA384',
	'SHA2-512' => 'SHA512',
	'SHA3-256' => '',
	'SHA3-384' => '',
	'SHA3-512' => '',
	'GOST' => ''
);

my %curve_map = (
	'X25519' => '',
	'X448' => '',
	'SECP256R1' => 'SECP256R1',
	'SECP384R1' => 'SECP384R1',
	'SECP521R1' => 'SECP521R1'
);

my %cipher_map = (
	'AES-256-CTR'       => '',
	'AES-128-CTR'       => '',
	'RC2-CBC'           => 'rc2',
	'RC4-128'           => 'rc4',
	'AES-256-GCM'       => 'aes256-gcm',
	'AES-128-GCM'       => 'aes128-gcm',
	'AES-256-CBC'       => 'aes256-cbc',
	'AES-128-CBC'       => 'aes128-cbc',
	'CAMELLIA-256-CBC'  => 'camellia256-cbc',
	'CAMELLIA-128-CBC'  => 'camellia128-cbc',
	'CAMELLIA-256-GCM'  => '',
	'CAMELLIA-128-GCM'  => '',
	'AES-256-CCM'       => '',
	'AES-128-CCM'       => '',
	'CHACHA20-POLY1305' => 'chacha20-poly1305',
	'3DES-CBC'          => 'des-ede3-cbc'
);

my %key_exchange_map = (
	'RSA-EXPORT'   => 'RSA-EXPORT',
	'PSK'   => '',
	'DHE-PSK'   => '',
	'ECDHE-PSK'   => '',
	'RSA'   => 'RSA',
	'ECDHE' => 'ECDHE-RSA:ECDHE-ECDSA',
	'DHE'   => 'DHE-RSA:DHE-DSS',
	'ECDH' => 'ECDH-RSA:ECDH-ECDSA',
	'DH'   => 'DH-RSA:DH-DSS'
);

my %protocol_map = (
	'SSL3.0'  => 'ssl3.0',
	'TLS1.0'  => 'tls1.0',
	'TLS1.1'  => 'tls1.1',
	'TLS1.2'  => 'tls1.2',
	'DTLS1.0' => 'dtls1.0',
	'DTLS1.2' => 'dtls1.2'
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

	$string .= "library=\n";
	$string .= "name=Policy\n";
	$string .= "NSS=flags=policyOnly,moduleDB\n";
	$string .= "config=\"disallow=ALL allow=";
	foreach (@mac_list) {
		my $val = $mac_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "nss: unknown: $_\n";
		}
	}
	foreach (@group_list) {
		my $val = $curve_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "nss: unknown: $_\n";
		}
	}
	foreach (@cipher_list) {
		my $val = $cipher_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "nss: unknown: $_\n";
		}
	}
	foreach (@hash_list) {
		my $val = $hash_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "nss: unknown: $_\n";
		}
	}
	foreach (@key_exchange_list) {
		my $val = $key_exchange_map{$_};
		if ( defined($val) ) {
			append($val);
		}
		else {
			print STDERR "nss: unknown: $_\n";
		}
	}

	append( "tls-version-min=" . $protocol_map{$min_tls_version} );
	append( "dtls-version-min=" . $protocol_map{$min_dtls_version} );

	append("DH-MIN=$min_dh_size");
	append("DSA-MIN=$min_dsa_size");
	append("RSA-MIN=$min_rsa_size");
	$string .= "\"\n\n\n";

	return $string;
}

sub test_temp_policy() {
	return;
}

1;
