#pragma once // This is used to prevent the same file from being included more than once during compilation
#include <NTL/ZZ.h>
#include <vector>
#include <string>

using namespace NTL;
using namespace std;

// SHA-256 of a ZZ value 
// Using encoding ZZ to bytes
vector<unsigned char> sha256_of_ZZ(const ZZ& x);

// Encryption function
vector<unsigned char> aes256gcm_encrypt(
    const vector<unsigned char>& key32,
    const vector<unsigned char>& plaintext
);

// Decryption function
vector<unsigned char> aes256gcm_decrypt(
    const vector<unsigned char>& key32,
    const vector<unsigned char>& blob
);
