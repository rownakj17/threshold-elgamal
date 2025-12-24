/*
This file computes the correct weights needed to combine partial decryptions 
so that the final result is the same as using the original secret key, 
without ever rebuilding that key.
*/

#include "lagrange.h"
#include <NTL/ZZ_p.h>

vector<ZZ> lagrange_weights_at_zero(const vector<long>& indices, const ZZ& q) { // we are reconstructing value at x = 0
                                                                                // the secret is hidden as f(0)
	ZZ_p::init(q);   // This line indicates that all math from now on happens modulo q                                               

    long k = (long)indices.size(); // k = The number of players we are using
    vector<ZZ> w(k);

    for (long j = 0; j < k; j++) { // This is the outer loop, one player at a time
        ZZ_p num(1); // num is for numerator
        ZZ_p den(1); // den is for denominator

        ZZ_p xj = conv<ZZ_p>(indices[j]); // Converting player number into a nmuber usable in modular math
		// indices represents which players are participating (like player 1, 3, 5) 

        for (long m = 0; m < k; m++) { // This is the inner loop to look at all other players
            if (m == j) continue;

            ZZ_p xm = conv<ZZ_p>(indices[m]);

            num *= (ZZ_p(0) - xm);   // (0 - x_m), Numerator uses other players’ positions
            den *= (xj - xm);        // (x_j - x_m), Denominator measures how far player j is from other players
        }

        ZZ_p lambda = num / den;     // lambda = num × (inverse of den mod q)
                                     // lambda is representing a weight (multiplier) for one player.
		w[j] = rep(lambda);          // Player j gets weight w[j]
    }

    return w; // Returning all weights
}
