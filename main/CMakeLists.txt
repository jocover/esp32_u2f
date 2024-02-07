idf_component_register(
    SRCS "device.c" "main.c"  "common.c" "fs.c" "apdu.c" "applets.c" "fs.c" "key.c" "pin.c" 
    "usb/ccid/ccid_device.c" "usb/ccid/ccid.c" "usb/ctaphid/ctaphid.c"
    "applets/admin/admin.c" "applets/ctap/ctap.c" "applets/ctap/ctap-parser.c" "applets/ctap/secret.c" "applets/ctap/u2f.c" "applets/meta/meta.c" "applets/oath/oath.c" "applets/ndef/ndef.c" "applets/openpgp/key.c"  "applets/openpgp/openpgp.c" "applets/piv/piv.c"
    "crypto/ecc.c" "crypto/hmac.c" "crypto/algo.c" "crypto/sha.c" "crypto/sha3.c" "crypto/memzero.c" "crypto/rand.c" "crypto/sm3.c" "crypto/block-cipher.c" "crypto/aes.c"  "crypto/rsa.c" "crypto/des.c" "crypto/esp32_ed25519.c"
    "littlefs/lfs.c" "littlefs/lfs_util.c"
    INCLUDE_DIRS "include" "crypto/include" "littlefs" 
    REQUIRES driver mbedtls efuse esp_partition esp_timer
    EMBED_FILES "cert/u2f_cert.bin" "cert/u2f_cert_key.bin" "cert/u2f_aaguid.bin"
    )

option(USE_MBEDCRYPTO "Use mbed-crypto as the crypto library" ON)
if (USE_MBEDCRYPTO)
    add_definitions(-DUSE_MBEDCRYPTO)
endif (USE_MBEDCRYPTO)