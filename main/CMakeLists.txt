idf_component_register(
    SRCS "device.c" "ctaphid.c" "secret.c" "ctap-parser.c" "main.c" "secret.c" "u2f.c"  "ctap.c" "common.c" "fs.c"
    "crypto/ecc.c" "crypto/hmac.c" "crypto/algo.c" "crypto/sha.c" "crypto/sha3.c" "crypto/memzero.c" "crypto/rand.c" "crypto/sm3.c" "crypto/block-cipher.c" "crypto/aes.c" "crypto/mbedtls_ed25519.c"
    "littlefs/lfs.c" "littlefs/lfs_util.c"
    INCLUDE_DIRS "." "crypto/include" "littlefs"
    REQUIRES driver mbedtls efuse esp_partition esp_timer
    EMBED_FILES "cert/u2f_cert.bin" "cert/u2f_cert_key.bin" "cert/u2f_aaguid.bin"
    )

option(USE_MBEDCRYPTO "Use mbed-crypto as the crypto library" ON)
if (USE_MBEDCRYPTO)
    add_definitions(-DUSE_MBEDCRYPTO)
endif (USE_MBEDCRYPTO)