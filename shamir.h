#pragma once // This is used to prevent the same file from being included more than once during compilation
#include <NTL/ZZ.h>
#include <vector>

using namespace NTL;
using namespace std;

// This represents One Shamir share
struct Share {
    long index;   // player number i
    ZZ value;     // a_i = f(i)
};

// Spliting secret into n shares with threshold t
vector<Share> shamir_split(
    const ZZ& secret,
    long t,
    long n,
    const ZZ& q
);

// Reconstruct secret from t+1 shares 
// This part is for TESTING ONLY
ZZ shamir_reconstruct(
    const vector<Share>& shares,
    const ZZ& q
);
