# GREYWARD hardening layered on Fedora DEFAULT.
# Keep RSA-2048 compatibility while removing legacy protocol/cipher/hash use.
hash = -SHA1
sign = -*-SHA1
sha1_in_certs = 0
__openssl_block_sha1_signatures = 1

# Keep TLS 1.2/1.3 but remove CBC suites and static RSA key exchange.
cipher@TLS = -AES-*-CBC
key_exchange = -RSA

# Remove legacy Camellia and 2048-bit finite-field DH without raising RSA
# minimums, so current Fedora package and HTTPS signatures remain compatible.
cipher = -CAMELLIA-*
group = -FFDHE-2048
min_dh_size = 3072
min_rsa_size = 2048
