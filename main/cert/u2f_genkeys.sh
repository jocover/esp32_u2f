#!/bin/bash
set -e


if [ \! -e esp32key.pem ]; then
    openssl ecparam -genkey -out esp32key.pem -name prime256v1
fi

openssl ecparam -genkey -name prime256v1 -out root_key.pem
openssl req -new -key root_key.pem -out root_key.pem.csr  -subj "/C=US/ST=Maine/O=OpenSourceSecurity/OU=Root CA/CN=ROOT CA/emailAddress=example@example.com"
openssl x509 -trustout -req -days 18250  -in root_key.pem.csr -signkey root_key.pem -out root_cert.pem -sha256

openssl ec -in esp32key.pem -outform DER -no_public | tail -c +8 | head -c 32  > u2f_cert_key.bin

openssl req -new -key esp32key.pem -out esp32cert.req -subj "/C=US/ST=Maine/O=OpenSourceSecurity/OU=Authenticator Attestation/CN=ESP32 U2F/emailAddress=example@example.com"
openssl x509 -req -in esp32cert.req -CA root_cert.pem -CAkey root_key.pem -extfile v3.ext -set_serial 01 -days 18250 -out esp32cert.pem -sha256
openssl x509 -in esp32cert.pem -outform der -out u2f_cert.bin

rm root_key.pem.csr esp32cert.req esp32cert.pem
