#!/bin/bash
set -e
openssl ecparam -out ec_key.pem -name secp256r1 -genkey -out dev.key
openssl req -config ./attestation-device-cert.cnf -new -key dev.key -nodes -out dev.csr
openssl x509 -extfile ./attestation-device-cert.cnf -extensions extensions_sec -days 3560 -req -in dev.csr -CA ca.pem -CAserial ca.srl -CAkey ca.key -out dev.pem
openssl x509 -outform der -in dev.pem -out u2f_cert.bin
rm dev.csr

openssl ec -in dev.key -outform DER -no_public | tail -c +8 | head -c 32  > u2f_cert_key.bin

