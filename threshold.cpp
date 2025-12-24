#include "threshold.h"

// A player's partial decryption is being computed here using their secret share

/*
	In the following definition,
	
	** B is the first part of ElGamal ciphertext (created during encryption)
	** share_ai is player i’s share of the secret key
	** p is the prime modulus
*/
ZZ partial_decrypt(const ZZ& B, const ZZ& share_ai, const ZZ& p) {
    return PowerMod(B, share_ai, p); // Computing partial decryption, D_i = B^(a_i) mod p
}

/*
	The following function combines all the partial values:
	
	** partials = list of partial decryptions: [D_1, D_2, D_3, ...]
	** weights = list of Lagrange weights: [λ_1, λ_2, λ_3, ...]
	** p = modulus
*/
ZZ combine_partials(const vector<ZZ>& partials, const vector<ZZ>& weights, const ZZ& p) {
    ZZ result(1);

    for (size_t i = 0; i < partials.size(); i++) {
        ZZ term = PowerMod(partials[i], weights[i], p);
        result = MulMod(result, term, p);
		// We combine the result by multiplying the partial decryptions
		// because multiplication adds exponents and reconstructs the correct power
		// without rebuilding the secret key
    }

    return result;
}
