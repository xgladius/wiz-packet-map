# wiz-packet-map
Wizard101 tool that dynamically dumps packet data and decrypts packets to and from the server that use aes-gcm encryption

Wizard101 has very recently (11/18/2020) started encrypting important packets using a symmetric-key cryptographic block cipher operation mode called Galois/Counter Mode (GCM) using an implementation from an open source crypto library written in C++ (https://github.com/weidai11/cryptopp/blob/master/gcm.h) 

IV and nonce are both 16 bytes, this project just completely bypasses the encryption entirely.

(mainly to be used in the aid of cheating software I guess, since custom implementation using this method is possible but not recommended or viable or good!)

It is also not a token that is generated every few minutes. It is a IV/nonce and a new iv and nonce are generated every time a zone change occurs, and is generated when the initial login packet is sent.
