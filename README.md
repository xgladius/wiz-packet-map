
# wiz-packet-map preface
2/28/2021 Update: Kingsisle decided to patch this by detecting if AuthenticatedSymmetricCipherBase functions were hooked in the function with the sig of `55 8D AC 24 ? ? ? ? 81 EC ? ? ? ? 6A FE`. As of 2/28/2021 this tool is fully funtional and working.

Wizard101 tool that dynamically dumps packet data and decrypts packets to and from the server that use aes-gcm encryption. IV and nonce are both 16 bytes, and are generated on each zone load (when MSG_ATTACH is sent)

Wizard101 has very recently (11/18/2020) started encrypting important packets using a symmetric-key cryptographic block cipher operation mode called Galois/Counter Mode (GCM) using an implementation from an open source crypto library written in C++ (https://github.com/weidai11/cryptopp/blob/master/gcm.h) 

# How it's done & what broke?
This project hooks a function in Crypto++ called `AuthenticatedSymmetricCipherBase::ProcessData` to retrieve the inString and outString. These uint8_t buffers can be used to retrieve the packet buffer before encryption, or after decryption.

At some unknown time, KingsIsle pushed a patch to break this tool, which checks the validity of Crypto++ class member functions. In V1 of the tool, it was using a classic trampoline hook which changed the first few bytes of `AuthenticatedSymmetricCipherBase::ProcessData` to jump to the hook handling function, then call the original function. This was problematic, as KI now checks the first two bytes of those functions to ensure they were not hooked.

# The bypass
The bypass is trivially simple, overwrite the bytes pointing to the original function with new bytes pointing to our function.

This is the function table of the AuthenticatedSymmetricCipherBase class.
![Bytes of original function](https://i.imgur.com/CEhqNRk.png)

By setting `base + 0x2259240` to `&ogProcessData_hook`, we overwrite the function that they want to call, with ours, allowing us to intercept all calls to `AuthenticatedSymmetricCipherBase::ProcessData`

Then, by calling the original, we have maintained the functionality of the original function, while being able to intercept arguments passed to it.
