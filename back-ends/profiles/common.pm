package profiles::common;

use strict;
use warnings;

BEGIN {
    require Exporter;
    our $VERSION = 1.00;
    our @ISA = qw(Exporter);
    our @EXPORT = qw(@full_hash_list @full_protocol_list @full_mac_list @full_group_list @full_sign_list @full_tls_cipher_list @full_cipher_list @full_key_exchange_list $sec_bits $min_tls_version $min_dtls_version $min_dsa_size @hash_list @hash_not_list @ike_protocol_list @ike_protocol_not_list @protocol_list @protocol_not_list $min_dh_size $min_rsa_size @mac_list @mac_not_list @group_list @curve_not_list @sign_list @sign_not_list @cipher_list @tls_cipher_list @cipher_not_list @tls_cipher_not_list @key_exchange_list @key_exchange_not_list update_rev_lists);
}

our @full_hash_list = ('SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'SHA1', 'MD5', 'GOST');
our @full_mac_list = ('AEAD', 'UMAC-128', 'HMAC-SHA1', 'HMAC-SHA2-256', 'HMAC-SHA2-384', 'HMAC-SHA2-512', 'UMAC-64', 'HMAC-MD5');

# we disable curves <= 256 bits by default in Fedora
our @full_group_list = ('X25519', 'SECP256R1', 'SECP384R1', 'SECP521R1', 'X448',
		'FFDHE-1536', 'FFDHE-2048', 'FFDHE-3072', 'FFDHE-4096', 'FFDHE-6144', 'FFDHE-8192');

our @full_sign_list = ('RSA-MD5', 'RSA-SHA1', 'DSA-SHA1', 'ECDSA-SHA1',
    'RSA-SHA2-224', 'DSA-SHA2-224', 'ECDSA-SHA2-224',
    'RSA-SHA2-256', 'DSA-SHA2-256', 'ECDSA-SHA2-256',
    'RSA-SHA2-384', 'DSA-SHA2-384', 'ECDSA-SHA2-384',
    'RSA-SHA2-512', 'DSA-SHA2-512', 'ECDSA-SHA2-512',
    'RSA-SHA3-256', 'DSA-SHA3-256', 'ECDSA-SHA3-256',
    'RSA-SHA3-384', 'DSA-SHA3-384', 'ECDSA-SHA3-384',
    'RSA-SHA3-512', 'DSA-SHA3-512', 'ECDSA-SHA3-512',
    'EDDSA-ED25519', 'EDDSA-ED448',
    'RSA-PSS-SHA1', 'RSA-PSS-SHA2-256', 'RSA-PSS-SHA2-384', 'RSA-PSS-SHA2-512');

our @full_tls_cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'AES-128-GCM', 'AES-128-CCM',
    'CHACHA20-POLY1305', 'CAMELLIA-256-GCM', 'CAMELLIA-128-GCM',
    'AES-256-CTR', 'AES-256-CBC', 'AES-128-CTR', 'AES-128-CBC', 'CAMELLIA-256-CBC', 'CAMELLIA-128-CBC',
    '3DES-CBC', 'DES-CBC', 'RC4-40', 'RC4-128', 'DES40-CBC', 'RC2-CBC',
    'IDEA-CBC', 'SEED-CBC', 'NULL');

our @full_cipher_list = @full_tls_cipher_list;

our @full_key_exchange_list = ('PSK', 'DHE-PSK', 'ECDHE-PSK', 'ECDHE', 'RSA', 'DHE', 'DHE-RSA', 'DHE-DSS', 'EXPORT', 'ANON', 'DH', 'ECDH');
our @full_protocol_list = ('SSL2.0', 'SSL3.0', 'TLS1.0', 'TLS1.1', 'TLS1.2', 'DTLS1.0', 'DTLS1.2');

our @full_ike_protocol_list = ('IKEv1', 'IKEv2');

our @mac_list = ();
our @mac_not_list = ();

our @group_list = ();
our @curve_not_list = ();

our @hash_list = ();
our @hash_not_list = ();

our @sign_list = ();
our @sign_not_list = ();

our @cipher_list = ();
our @cipher_not_list = ();

our @tls_cipher_list = ();
our @tls_cipher_not_list = ();

our @key_exchange_list = ();
our @key_exchange_not_list = ();

our @protocol_list = ();
our @protocol_not_list = ();

our @ike_protocol_list = ();
our @ike_protocol_not_list = ();

# minimum versions
our $min_tls_version;
our $min_dtls_version;

# Parameter sizes
our $sec_bits;
our $min_dh_size;
our $min_dsa_size;
our $min_rsa_size;

sub update_rev_lists {
    my %mac_list=map{$_ => 1} @mac_list;
    @mac_not_list = grep(!defined($mac_list{$_}), @full_mac_list);

    my %group_list=map{$_ => 1} @group_list;
    @curve_not_list = grep(!defined($group_list{$_}), @full_group_list);

    my %hash_list=map{$_ => 1} @hash_list;
    @hash_not_list = grep(!defined($hash_list{$_}), @full_hash_list);
    
    my %sign_list=map{$_ => 1} @sign_list;
    @sign_not_list = grep(!defined($sign_list{$_}), @full_sign_list);

    my %cipher_list=map{$_ => 1} @cipher_list;
    @cipher_not_list = grep(!defined($cipher_list{$_}), @full_cipher_list);

    my %tls_cipher_list=map{$_ => 1} @tls_cipher_list;
    @tls_cipher_not_list = grep(!defined($tls_cipher_list{$_}), @full_tls_cipher_list);

    my %key_exchange_list=map{$_ => 1} @key_exchange_list;
    @key_exchange_not_list = grep(!defined($key_exchange_list{$_}), @full_key_exchange_list);

    my %protocol_list=map{$_ => 1} @protocol_list;
    our @protocol_not_list = grep(!defined($protocol_list{$_}), @full_protocol_list);

    my %ike_protocol_list=map{$_ => 1} @ike_protocol_list;
    our @ike_protocol_not_list = grep(!defined($ike_protocol_list{$_}), @full_ike_protocol_list);
}

1;
