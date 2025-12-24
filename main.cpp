// ==============================
// Threshold-ElGamal Project
// ==============================

#include <iostream>
#include <vector>
#include <NTL/ZZ.h>
#include "params.h"
#include "shamir.h"
#include "threshold.h"
#include "lagrange.h"
#include "crypto.h"

using namespace std;
using namespace NTL;

int main() {

    // ------------------------------------------------
    // Part 1: Load parameters and basic ElGamal setup
    // ------------------------------------------------

    load_parameters();

    cout << "Global parameters are loaded successfully!" << endl;
    //cout << "bitlen(p) = " << NumBits(p) << endl;
    //cout << "bitlen(q) = " << NumBits(q) << endl;

    // Random secret a in [0, q-1]
    ZZ a = RandomBnd(q);

    // Public key A = g^a mod p
    ZZ A = PowerMod(g, a, p);

    cout << "Generated a random secret a and public key A = g^a mod p." << endl;

    // Checking PowerMod function with ZZ (test only)
    ZZ test = PowerMod(g, ZZ(12345678), p);

    // -----------------------------------------------------
    // Part 2: Shamir secret sharing (Choosing t = 2, n = 5)
    // -----------------------------------------------------

    int t = 2;
    int n = 5;
    cout << endl << "We will use threshold t = " << t
         << " (i.e., we need t+1 = " << (t+1) << " shares), n = " << n << " players." << endl;

    // Splitting secret a into n shares using threshold t
    auto shares = shamir_split(a, t, n, q); // Using auto to let the compiler figure out the type for me

   cout << endl << "Shares are being created for each player!" << endl;
	for (auto& s : shares) {
    cout << "Player " << s.index << " received a share." << endl;
}


    // Picking ANY 3 shares (because t=2, so we need t+1=3 shares)
    vector<Share> subset = { shares[0], shares[2], shares[4] };

    /*
    /*********************************************************
    // Reconstruct (test only)
    ZZ recovered = shamir_reconstruct(subset, q);

    cout << "Recovered a = " << recovered << endl;
    cout << (recovered == a ? "SUCCESS" : "FAILURE") << endl;
    /*********************************************************
    */

    //--------------------------------------------
    // ----- Part 3: Partial decryption test -----
    //--------------------------------------------

    // Choose random b and compute B = g^b mod p
    ZZ b = RandomBnd(q);
    ZZ B = PowerMod(g, b, p);

    cout << endl << "Testing partial decryptions:" << endl;

    // Each player computes a partial decryption D_i = B^(a_i) mod p
    for (auto& s : shares) {
        ZZ Di = partial_decrypt(B, s.value, p);
        cout << "Player " << s.index << " computed D_" << s.index << endl;
    }

    // -------------------------------------------
    // Part 4: Combine partial decryptions
    // -------------------------------------------

    // Indices of selected players (needed for Lagrange weights)
    vector<long> idx = { subset[0].index, subset[1].index, subset[2].index };

    // Building partial decryptions for the selected players: D_i = B^(a_i)
    vector<ZZ> partials;
    for (auto& sh : subset) {
        partials.push_back(partial_decrypt(B, sh.value, p));
    }

    // Computing Lagrange weights at x=0 (mod q), because the secret is at point 0
    vector<ZZ> weights = lagrange_weights_at_zero(idx, q);

    // Combining partial decryptions using weights to get S_threshold
    ZZ S_threshold = combine_partials(partials, weights, p);

    // TEST ONLY PART: direct compute S_direct = B^a mod p
    ZZ S_direct = PowerMod(B, a, p);

    cout << endl << "S_direct == S_threshold ? " << (S_direct == S_threshold ? "SUCCESS" : "FAILURE") << endl;

    // ---------------------------------------------------
    // Part 5: Hybrid encryption: k = SHA256(S), AES_k(m)
    // ---------------------------------------------------

    // Deriving a 32-byte AES key from the shared secret S_threshold
    auto key = sha256_of_ZZ(S_threshold); // this key has 32 bytes (AES-256 key)

    // Converting message string into bytes (plaintext)
    string msg = "Welcome to my Threshold ElGamal project!";
    vector<unsigned char> pt(msg.begin(), msg.end());

    // Encrypting plaintext using AES-256-GCM
    auto full_enc_data = aes256gcm_encrypt(key, pt);

    // Decrypting back using the same key (test that encryption/decryption works)
    auto dec = aes256gcm_decrypt(key, full_enc_data);

    // full_enc_data is a vector of bytes
    // It contains: nonce || ciphertext || authentication_tag
    string recovered(dec.begin(), dec.end());
    cout << endl << "Recovered message: " << endl << "------------------" << endl << recovered << endl << endl;

    return 0;
}
