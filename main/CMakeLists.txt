idf_component_register(
    SRCS "u2f_hid.c" "main.c" "u2f.c" "u2f_data.c"
    INCLUDE_DIRS "."
    REQUIRES driver mbedtls efuse
    EMBED_FILES "cert/u2f_cert.bin" "cert/u2f_cert_key.bin"
    )

