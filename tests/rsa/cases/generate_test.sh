#!/bin/bash
for BITS in 1024 2048 4096
do
  for CASES in 1 2
  do
    PRIVATE_KEY="./${BITS}bit_${CASES}_private.pem"
    PUBLIC_KEY="./${BITS}bit_${CASES}_public.pub"
    openssl genrsa -out $PRIVATE_KEY $BITS
    openssl rsa -in $PRIVATE_KEY -pubout > $PUBLIC_KEY

    CIPER="./${BITS}bit_${CASES}_ciper_oaep_sha256.txt"
    openssl pkeyutl -in plain.txt -encrypt -inkey $PRIVATE_KEY -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 > $CIPER

    CIPER="./${BITS}bit_${CASES}_ciper_oaep_sha1.txt"
    openssl pkeyutl -in plain.txt -encrypt -inkey $PRIVATE_KEY -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 -pkeyopt rsa_mgf1_md:sha1 > $CIPER

    CIPER="./${BITS}bit_${CASES}_ciper_pkcs1.txt"
    openssl pkeyutl -in plain.txt -encrypt -inkey $PRIVATE_KEY -pkeyopt rsa_padding_mode:pkcs1 > $CIPER
  done
done