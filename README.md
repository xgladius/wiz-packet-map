# wiz-packet-map
2/28/2021 Update: Kingsisle (you should hire me) decided to patch this by detecting if AuthenticatedSymmetricCipherBase functions were hooked in the function with the sig of `55 8D AC 24 ? ? ? ? 81 EC ? ? ? ? 6A FE`. As of 2/28/2021 this tool is fully funtional and working.

Wizard101 tool that dynamically dumps packet data and decrypts packets to and from the server that use aes-gcm encryption

Wizard101 has very recently (11/18/2020) started encrypting important packets using a symmetric-key cryptographic block cipher operation mode called Galois/Counter Mode (GCM) using an implementation from an open source crypto library written in C++ (https://github.com/weidai11/cryptopp/blob/master/gcm.h) 

IV and nonce are both 16 bytes. This project hooks a function in Crypto++ called `AuthenticatedSymmetricCipherBase::ProcessData` to retrieve the inString and outString to retrieve the packet buffer before encryption (or after decryption).

Shoutout to Kingsisle (who is lurking on this repo !!) again, you should hire me! I will write you better security.
