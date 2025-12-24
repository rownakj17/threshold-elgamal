#include "shamir.h"
#include <NTL/ZZ_pX.h>

vector<Share> shamir_split(const ZZ& secret, long t, long n, const ZZ& q) {
    ZZ_p::init(q); // Setting modulo q

    // f(x) = a + r1*x + r2*x^2   (for t = 2)
    ZZ_pX f;

    // Setting constant term = secret
    SetCoeff(f, 0, conv<ZZ_p>(secret));

    // Random coefficients
    for (long i = 1; i <= t; i++) {
        ZZ r = RandomBnd(q);
        SetCoeff(f, i, conv<ZZ_p>(r)); // converts integer r into mod-q type
    }

    vector<Share> shares;

    // Compute a_i = f(i)
    for (long i = 1; i <= n; i++) {
        ZZ_p y = eval(f, conv<ZZ_p>(i)); // The eval(f, x) function computes f(x) mod q

        Share s;
        s.index = i;
        s.value = rep(y); // rep is a library function defined by NTL, it converts ZZ_p into a ZZ

        shares.push_back(s); // adding element to the vector
    }

    return shares;
}

ZZ shamir_reconstruct(const vector<Share>& shares, const ZZ& q) {
    ZZ_p::init(q); // It sets the global modulus q for the type ZZ_p
                   // ZZ_p is a modular integer type in NTL library

    long k = shares.size(); // k = number of shares used

    vec_ZZ_p xs, ys;
    xs.SetLength(k);
    ys.SetLength(k);

    for (long i = 0; i < k; i++) {
        xs[i] = conv<ZZ_p>(shares[i].index);
        ys[i] = conv<ZZ_p>(shares[i].value);
    }

    ZZ_pX f;
    interpolate(f, xs, ys); // constructs the unique polynomial that passes through those points

    // secret = f(0)
    return rep(eval(f, ZZ_p(0)));
}
