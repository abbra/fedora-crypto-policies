#!perl

require 5.000;
use strict;

use profiles::common;
use File::Temp qw/ tempfile tmpnam /;

my $host_key_filename;

# XXX copy&paste ciphers definitions from profiles/openssh.pl

my $print_init = 0;
my $string     = '';

sub append {
	my $arg = shift;
	my $buf = shift;

	return if $arg eq '';

	if ( $print_init != 0 ) {
		$$buf .= ',';
	}
	$$buf .= $arg;
	$print_init = 1;
}

my %cipher_map = (
	'AES-256-GCM'	   => 'aes256-gcm@openssh.com',
	'AES-256-CTR'	   => 'aes256-ctr',
	'AES-128-GCM'	   => 'aes128-gcm@openssh.com',
	'AES-128-CTR'	   => 'aes128-ctr',
	'CHACHA20-POLY1305' => 'chacha20-poly1305@openssh.com',
	'CAMELLIA-256-GCM' => '',
	'AES-128-CCM'	   => '',
	'AES-256-CCM'	   => '',
	'CAMELLIA-128-GCM' => '',
	
	'AES-256-CBC'      => 'aes256-cbc',
	'AES-128-CBC'      => 'aes128-cbc',
	'CAMELLIA-256-CBC' => '',
	'CAMELLIA-128-CBC' => '',
	'RC4-128'          => '',
	'DES-CBC'          => '',
	'CAMELLIA-128-CTS' => '',
	'3DES-CBC'         => '3des-cbc'
);

my %gss_hash_map = (
	'SHA1'     => 'gss-gex-sha1-,gss-group14-sha1-',
	'SHA2-256'     => '',
	'SHA2-384'     => '',
	'SHA2-512'     => '',
	'SHA3-256'     => '',
	'SHA3-384'     => '',
	'SHA3-512'     => '',
	'MD5'     => '',
	'GOST'     => '',
);

my %mac_map_etm = (
	'HMAC-MD5'	=> 'hmac-md5-etm@openssh.com',
	'UMAC-64'       => 'umac-64-etm@openssh.com',
	'UMAC-128'      => 'umac-128-etm@openssh.com',
	'HMAC-SHA1'     => 'hmac-sha1-etm@openssh.com',
	'HMAC-SHA2-256' => 'hmac-sha2-256-etm@openssh.com',
	'HMAC-SHA2-512' => 'hmac-sha2-512-etm@openssh.com'
);

my %mac_map = (
	'HMAC-MD5'	=> 'hmac-md5',
	'UMAC-64'       => 'umac-64@openssh.com',
	'UMAC-128'      => 'umac-128@openssh.com',
	'HMAC-SHA1'     => 'hmac-sha1',
	'HMAC-SHA2-256' => 'hmac-sha2-256',
	'HMAC-SHA2-512' => 'hmac-sha2-512'
);

my %kx_map = (
	'ECDHE-SECP521R1-SHA2-512' => 'ecdh-sha2-nistp521',
	'ECDHE-SECP256R1-SHA2-384' => 'ecdh-sha2-nistp384',
	'ECDHE-SECP256R1-SHA2-256' => 'ecdh-sha2-nistp256',
	'ECDHE-X25519-SHA2-256' => 'curve25519-sha256@libssh.org',
	'DHE-SHA1'   => 'diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1',
	'DHE-SHA2-256' => 'diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256',
	'DHE-SHA2-256' => 'diffie-hellman-group-exchange-sha256',
	'DHE-SHA2-512' => 'diffie-hellman-group16-sha512,diffie-hellman-group18-sha512'
);

sub generate_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $libdir  = shift(@_);
	my $reloadcmd_ref = shift(@_);

	if (!-e "$libdir/profiles/$profile.pl") {
		print STDERR "Cannot file $profile.pl in $libdir/profiles\n";
		exit 1;
	}
	do "$libdir/profiles/$profile.pl";

	$string = '';
	$print_init = 0;

	my $tmp = '';
	foreach (@cipher_list) {
		my $val = $cipher_map{$_};
		if ( defined($val) ) {
			append($val, \$tmp);
		}
		else {
			print STDERR "openssh-server: unknown: $_\n";
		}
	}

	if ($tmp ne '') {
		$string .= "-oCiphers=$tmp ";
	}

	$print_init = 0;
	$tmp = '';
	foreach (@mac_list) {
		my $val = $mac_map_etm{$_};
		if ( defined($val) ) {
			append($val, \$tmp);
		}
		else {
			print STDERR "openssh-server: unknown MAC: $_\n";
		}
	}
	foreach (@mac_list) {
		my $val = $mac_map{$_};
		if ( defined($val) ) {
			append($val, \$tmp);
		}
		else {
			print STDERR "openssh-server: unknown MAC: $_\n";
		}
	}

	if ($tmp ne '') {
		$string .= "-oMACs=$tmp ";
	}

	$print_init = 0;
	$tmp='';
	foreach (@hash_list) {
		my $val = $gss_hash_map{$_};
		if ( defined($val) ) {
			append($val, \$tmp);
		}
		else {
			print STDERR "openssh-server: unknown: $_\n";
		}
	}

	if ($tmp eq '') {
		$string .= "-oGSSAPIKeyExchange=no ";
	} else {
		$string .= "-oGSSAPIKexAlgorithms=$tmp ";
	}

	$print_init = 0;
	$tmp = '';
	foreach (@key_exchange_list) {
		my $kx = $_;
		foreach (@hash_list) {
			my $hash = $_;
			if ($kx eq 'ECDHE') {
				foreach (@group_list) {
					my $mval = $kx.'-'.$_.'-'.$hash;
					my $val = $kx_map{$mval};
					if ( defined($val) ) {
						append($val, \$tmp);
					}
				}
			} else {
				my $mval = $kx.'-'.$hash;
				my $val = $kx_map{$mval};
				if ( defined($val) ) {
					append($val, \$tmp);
				}
			}
		}
	}

	if ($tmp ne '') {
		$string .= "-oKexAlgorithms=$tmp";
	}

	# we need restart here, since systemd needs to pick up a new command line options
	push(@{$reloadcmd_ref}, "test -e /usr/lib/systemd/system/sshd.service && systemctl restart sshd\n");

	return "CRYPTO_POLICY='$string'";
}

sub test_setup() {
	$host_key_filename = tmpnam();
	system("/usr/bin/ssh-keygen -t rsa -b 2048 -f $host_key_filename -N '' >/dev/null");
}

sub test_temp_policy() {
	my $profile = shift(@_);
	my $dir     = shift(@_);
	my $gstr = shift(@_);

	if (-e "/usr/sbin/sshd") {
		test_setup();
		my ( $fh, $filename ) = tempfile();
		print $fh $gstr;
		close $fh;

		system("/usr/bin/bash -c 'source $filename && /usr/sbin/sshd -T \$CRYPTO_POLICY -h $host_key_filename -f /dev/null' >/dev/null");
		my $ret = $?;
		unlink($filename);
		test_cleanup();

		if ( $ret != 0 ) {
			print STDERR "There is an error in openssh-server generated policy\n";
			exit 1;
		}

		if (($gstr !~ /diffie-hellman-group18-sha512/) || ($gstr !~ /aes256-gcm\@openssh.com/) ||
		    ($gstr !~ /hmac-sha2-256-etm\@openssh.com/)) {
			print STDERR "Most likely we miss an openssh cipher\n";
			print STDERR "policy: $gstr\n";
			exit 1;
		}
	}
	return;
}

sub test_cleanup() {
	unlink($host_key_filename);
}

1;
