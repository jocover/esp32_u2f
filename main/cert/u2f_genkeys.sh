#!/bin/bash
set -e


if [ \! -e esp32key.pem ]; then
    openssl ecparam -genkey -out esp32key.pem -name prime256v1
fi

openssl ec -in esp32key.pem -outform DER -no_public | tail -c +8 | head -c 32  > u2f_cert_key.bin

openssl req -new -key esp32key.pem -out esp32cert.req -subj "/CN=ESP32 U2F"
openssl x509 -req -in esp32cert.req -signkey esp32key.pem -days 3650 -out esp32cert.pem
openssl x509 -in esp32cert.pem -outform der -out u2f_cert.bin

rm esp32cert.req esp32cert.pem
