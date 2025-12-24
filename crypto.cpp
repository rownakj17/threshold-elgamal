/* This file handles the symmetric (shared-key) part of the project.
   After threshold ElGamal decryption, we obtain a shared secret S.
   We hash S using SHA-256 to derive a fixed-size symmetric key.
   This key is used for AES encryption and decryption of the message. 
*/

#include "crypto.h"
#include <openssl/sha.h>  // This header gives us SHA-256 functions (hashing)
#include <openssl/evp.h>  // This header gives us OpenSSL’s “EVP” interface
#include <openssl/rand.h> // This header provides access to OpenSSL’s CSPRNG
						  // CSPRNG stands for Cryptographically Secure Pseudo-Random Number Generator
#include <stdexcept>      // This is used for exception handling

/*
Cryptographic hash and AES functions operate on bytes, not on big integers.
The following function provides a stable byte encoding of ZZ values.
*/
static vector<unsigned char> zz_to_bytes(const ZZ& x) { //Convert a big integer into a sequence of bytes
    long n = NumBytes(x);
    if (n == 0) n = 1; // If the number is zero, force it to use 1 byte instead of 0 bytes

    vector<unsigned char> out(n);
    BytesFromZZ(out.data(), x, n);
    return out;
}


//********************************************************
//****************** Hashing begins **********************
//********************************************************
/* 
The following function computes SHA-256 hash of a big integer.
This is used to derive a 32-byte symmetric key from the shared secret S.
Using a hash ensures a fixed size and good randomness for the key.
*/

vector<unsigned char> sha256_of_ZZ(const ZZ& x) {
    vector<unsigned char> data = zz_to_bytes(x);

    vector<unsigned char> digest(SHA256_DIGEST_LENGTH); // SHA256_DIGEST_LENGTH is a constant which is 32
    SHA256(data.data(), data.size(), digest.data()); // Take the bytes in data, 
													 // hash them with SHA-256, 
													 // and store the 32-byte result in digest
    return digest; // returns 32 bytes
}
//******************************************************
//****************** Hashing ends **********************
//******************************************************



//-----------------------------------------------------
//-------------Encryption function begins--------------
//-----------------------------------------------------

vector<unsigned char> aes256gcm_encrypt(  //Encrypt a message using AES-256 in GCM mode
    const vector<unsigned char>& key32, // 32 bytes symmetric key derived from SHA-256
    const vector<unsigned char>& plaintext // The original message
) {
    if (key32.size() != 32) throw runtime_error("Error! AES-256 key must be 32 bytes!");

    const int NONCE_LEN = 12;
    const int TAG_LEN = 16;

    vector<unsigned char> nonce(NONCE_LEN); // Declaring a 12 byte nonce
											// A nonce is a random value which is used once per encryption
    if (RAND_bytes(nonce.data(), NONCE_LEN) != 1) throw runtime_error("RAND_bytes nonce failed!!");
	
	// RAND_bytes returns 1 if successful
	
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); // Creating a new encryption workspace
    if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed!!");

    vector<unsigned char> ciphertext(plaintext.size());
    vector<unsigned char> tag(TAG_LEN);
	// tag is a security check value that is produced by AES-GCM to detect tampering and wrong keys
    
	int len = 0;
	int ciphertext_len = 0;

	// Chosing the encryption algorithm
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw runtime_error("EncryptInit failed!!");

	// Telling OpenSSL the nonce length which is 12 bytes
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1)
        throw runtime_error("SET_IVLEN failed");

	// Providing OpenSSL the actual secret key and the nonce
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce.data()) != 1)
        throw runtime_error("EncryptInit key/nonce failed!!");

	// Main encryption step: Encrypting the plaintext bytes and writing the encrypted bytes into "ciphertext"
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size()) != 1)
        throw runtime_error("EncryptUpdate failed!!");
    ciphertext_len = len; // Remembering how many bytes of ciphertext we got

	// It's time to finish up encryption and output any remaining bytes
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &len) != 1)
        throw runtime_error("EncryptFinal failed!!");
    ciphertext_len += len;

	// Getting the tamper-check value
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag.data()) != 1)
        throw runtime_error("GET_TAG failed!!");

    EVP_CIPHER_CTX_free(ctx); // Freeing the encryption context, done encrypting, cleaning up memory

    // Output format is: nonce || ciphertext || authentication tag
    vector<unsigned char> full_enc_data; // Creating an empty list of bytes to hold the final encrypted output
    
	full_enc_data.reserve(NONCE_LEN + ciphertext_len + TAG_LEN);
    full_enc_data.insert(full_enc_data.end(), nonce.begin(), nonce.end());
    full_enc_data.insert(full_enc_data.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    full_enc_data.insert(full_enc_data.end(), tag.begin(), tag.end());
    
	return full_enc_data; // full_enc_data contains three things stuck together
}

//-----------------------------------------------------
//--------------Encryption function ends---------------
//-----------------------------------------------------


//-----------------------------------------------------
//-------------Decryption function begins--------------
//-----------------------------------------------------

vector<unsigned char> aes256gcm_decrypt(  // Decrypt a message using AES-256 in GCM mode
    const vector<unsigned char>& key32,   // 32 bytes symmetric key derived from SHA-256
    const vector<unsigned char>& full_enc_data // The encrypted data: nonce || ciphertext || tag
) {
    // Checking if the key length is correct
    if (key32.size() != 32) throw runtime_error("Error! AES-256 key must be 32 bytes!");

    const int NONCE_LEN = 12;
    const int TAG_LEN = 16;

    // The encrypted data must at least contain a nonce and a tag
    if ((int)full_enc_data.size() < NONCE_LEN + TAG_LEN)
        throw runtime_error("Encrypted data is too short!");

    // Extracting the nonce (first 12 bytes)
    const unsigned char* nonce = full_enc_data.data();

    // Extracting the authentication tag (last 16 bytes)
    const unsigned char* tag = full_enc_data.data() + full_enc_data.size() - TAG_LEN;

    // Calculating the ciphertext length
    size_t ciphertext_len = full_enc_data.size() - NONCE_LEN - TAG_LEN;

    // Extracting the ciphertext (the middle part)
    const unsigned char* ciphertext = full_enc_data.data() + NONCE_LEN;

    // Creating a new decryption workspace
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed!!");

    // Preparing space to store the decrypted message
    vector<unsigned char> plaintext(ciphertext_len);

    int len = 0;
    int plaintext_len = 0;

    // Choosing the decryption algorithm (AES-256-GCM)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw runtime_error("DecryptInit failed!!");

    // Telling OpenSSL the nonce length (12 bytes)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1)
        throw runtime_error("SET_IVLEN failed!!");

    // Providing OpenSSL the actual secret key and the nonce
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), nonce) != 1)
        throw runtime_error("DecryptInit key/nonce failed!!");

    // Main decryption step: Decrypting ciphertext bytes and writing the plaintext bytes
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, (int)ciphertext_len) != 1)
        throw runtime_error("DecryptUpdate failed!!");
    plaintext_len = len; // Remembering how many plaintext bytes we got

    // Setting the expected authentication tag for verification
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1)
        throw runtime_error("SET_TAG failed!!");

    // Final step: verifies the tag and finishes decryption
    int ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len);
    EVP_CIPHER_CTX_free(ctx); // Freeing the decryption context, cleaning up memory

    // If the key is wrong or the ciphertext is modified, decryption fails here
    if (ok != 1)
        throw runtime_error("DecryptFinal failed (tag mismatch / wrong key)");

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return plaintext; // Returning the successfully decrypted message
}


//---------------------------------------------------
//-------------Decryption function ends--------------
//---------------------------------------------------