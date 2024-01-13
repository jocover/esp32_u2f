idf_component_register(
    SRCS "u2f_hid.c" "main.c" "u2f.c" "u2f_data.c"
    INCLUDE_DIRS "." "public_include"
    REQUIRES driver mbedtls usb efuse
    EMBED_FILES "cert/u2f_cert.bin" "cert/u2f_cert_key.bin"
    )

idf_component_get_property(tusb_lib espressif__tinyusb COMPONENT_LIB)
target_include_directories(${tusb_lib} PRIVATE public_include)
