# A level that will provide security on a conservative level that is
# believed to withstand any near-term future attacks. That will be
# an 112-bit security level, without including protocols with known
# attacks available (e.g. SSL 3.0). This level may prevent communication
# with many used systems that provide weaker security levels (e.g.,
# systems that use SHA-1 as signature algorithm).

# MACs: All HMAC with SHA256 or better + all modern MACs (poly1305 etc)
# Curves: all prime >= 384 bits (including bernstein curves)
# Signature algorithms: SHA-384 hash or better (not DSA)
# TLS Ciphers: >= 256-bit key, >= 128-bit block, only Authenticated Encryption (AE) ciphers
# non-TLS Ciphers: >= 256-bit key, >= 128-bit block
# key exchange: ECDHE, DHE (not DHE-DSS)
# DH params size: >= 3072
# RSA params size: >= 3072
# TLS protocols: TLS >= 1.2

sub update_lists {

    @mac_list = ('AEAD', 'UMAC-128', 'HMAC-SHA2-256', 'HMAC-SHA2-384', 'HMAC-SHA2-512');
    @group_list = ('X448', 'SECP384R1', 'SECP521R1',
        'FFDHE-3072', 'FFDHE-4096', 'FFDHE-6144', 'FFDHE-8192');
    @hash_list = ('SHA2-384', 'SHA2-512', 'SHA3-256', 'SHA3-384', 'SHA3-512');
    @sign_list = (
        'RSA-SHA2-224', 'ECDSA-SHA2-224',
        'RSA-SHA2-256', 'ECDSA-SHA2-256',
        'RSA-SHA2-384', 'ECDSA-SHA2-384',
        'RSA-SHA2-512', 'ECDSA-SHA2-512',
        'RSA-SHA3-256', 'ECDSA-SHA3-256',
        'RSA-SHA3-384', 'ECDSA-SHA3-384',
        'RSA-SHA3-512', 'ECDSA-SHA3-512',
        'EDDSA-ED448',
        'RSA-PSS-SHA2-384', 'RSA-PSS-SHA2-512');

    @tls_cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'CHACHA20-POLY1305', 'CAMELLIA-256-GCM');
    @cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'CHACHA20-POLY1305', 'CAMELLIA-256-GCM',
		    'AES-256-CTR', 'AES-256-CBC', 'CAMELLIA-256-CBC');
    @key_exchange_list = ('ECDHE', 'RSA', 'DHE', 'DHE-RSA', 'PSK', 'DHE-PSK', 'ECDHE-PSK');
    @protocol_list = ('TLS1.2', 'DTLS1.2');
    @ike_protocol_list = ('IKEv2');

    $min_tls_version = 'TLS1.2';
    $min_dtls_version = 'DTLS1.2';

    # Parameter sizes
    $sec_bits = 112;
    $min_dh_size = 3072;
    $min_dsa_size = 3072;
    $min_rsa_size = 3072;

    update_rev_lists();
}

update_lists();
