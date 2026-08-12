This is a set of Linux kernel modules implementing GOST cryptographic algorithms:

 - GOST 28147 cipher (RFC 5830)
 - GOST 28147 "Imitovstavka" (MAC mode) (RFC 5830)
 - GOST R 34.11-94 digest (RFC 5831)
   - HMAC using GOST R 34.11-94 (RFC 4357)
 - GOST R 34.12-2015 ciphers (Magma and Kuznyechik) (RFC 7801)
   - x86-64 SIMD Kuznyechik (`ecb(kuznyechik-simd)`,
     `ctr(kuznyechik-simd)` and `cmac(kuznyechik-simd)`)
   - direct SG Kuznyechik CTR-OMAC fast path for `l2tap`
   - CMAC using GOST R 34.12-2015 (as required by GOST R 34.13-2015)
   - Kuznyechik CTR-CMAC AEAD (`kuznyechik-ctr-cmac`)
 - GOST R 34.11-2012 digest is provided from external source, developed by Vitaly Chikunov

[![Build Status](https://travis-ci.com/GostCrypt/linux-crypto.svg?branch=master)](https://travis-ci.com/GostCrypt/linux-crypto)
