# A level that will ensure maximum compatibility with legacy systems.
# It should provide at least 64-bit security and include RC4 and MD5 (for HMAC).

# MACs: All HMAC with SHA1 or better + all modern MACs (poly1305 etc)
# Curves: all prime >= 255 bits (including bernstein curves)
# Signature algorithms: SHA-1 hash or better (not RIPEMD)
# TLS Ciphers: all available > 112-bit key, >= 128-bit block (no rc4, but with 3DES)
# non-TLS Ciphers: all available > 112-bit key, >= 128-bit block (no rc4, but with 3DES)
# key exchange: ECDHE, RSA, DHE
# DH params size: >=1023
# RSA params size: >=1023
# TLS protocols: TLS >= 1.0

sub update_lists {

    @mac_list = ('AEAD', 'UMAC-128', 'HMAC-SHA1', 'HMAC-SHA2-256', 'HMAC-SHA2-384', 'HMAC-SHA2-512');
    @group_list = ('X25519', 'X448', 'SECP256R1', 'SECP384R1', 'SECP521R1',
        'FFDHE-2048', 'FFDHE-3072', 'FFDHE-4096', 'FFDHE-6144', 'FFDHE-8192');
    @hash_list = ('SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'SHA1');
    @sign_list = ('RSA-SHA1', 'DSA-SHA1', 'ECDSA-SHA1',
        'RSA-SHA2-224', 'DSA-SHA2-224', 'ECDSA-SHA2-224',
        'RSA-SHA2-256', 'DSA-SHA2-256', 'ECDSA-SHA2-256',
        'RSA-SHA2-384', 'DSA-SHA2-384', 'ECDSA-SHA2-384',
        'RSA-SHA2-512', 'DSA-SHA2-512', 'ECDSA-SHA2-512',
        'RSA-SHA3-256', 'DSA-SHA3-256', 'ECDSA-SHA3-256',
        'RSA-SHA3-384', 'DSA-SHA3-384', 'ECDSA-SHA3-384',
        'RSA-SHA3-512', 'DSA-SHA3-512', 'ECDSA-SHA3-512',
        'EDDSA-ED25519', 'EDDSA-ED448',
        'RSA-PSS-SHA1', 'RSA-PSS-SHA2-256', 'RSA-PSS-SHA2-384', 'RSA-PSS-SHA2-512');

    @tls_cipher_list = ('AES-256-GCM', 'AES-256-CCM', 'CHACHA20-POLY1305', 'CAMELLIA-256-GCM',
        'AES-256-CTR', 'AES-256-CBC', 'CAMELLIA-256-CBC', 
        'AES-128-GCM', 'AES-128-CCM', 'CAMELLIA-128-GCM', 'AES-128-CTR', 'AES-128-CBC', 'CAMELLIA-128-CBC',
        '3DES-CBC', 'RC4-128');
    @cipher_list = @tls_cipher_list;
    @key_exchange_list = ('ECDHE', 'RSA', 'DHE', 'DHE-RSA', 'DHE-DSS', 'PSK', 'DHE-PSK', 'ECDHE-PSK');
    @protocol_list = ('TLS1.2', 'TLS1.1', 'TLS1.0', 'DTLS1.2', 'DTLS1.0');
    @ike_protocol_list = ('IKEv1');

    $min_tls_version = 'TLS1.0';
    $min_dtls_version = 'TLS1.0';

    # Parameter sizes
    $sec_bits = 64;
    $min_dh_size = 1023;
    $min_dsa_size = 1023;
    $min_rsa_size = 1023;

    update_rev_lists();
}

update_lists();
