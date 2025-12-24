#pragma once // This is used to prevent the same file from being included more than once during compilation
#include <NTL/ZZ.h>
#include <vector>

using namespace NTL;
using namespace std;

// A player's partial decryption is being computed here using their secret share
ZZ partial_decrypt(const ZZ& B, const ZZ& share_ai, const ZZ& p);

// The following function combines all the partial values
ZZ combine_partials(const vector<ZZ>& partials, const vector<ZZ>& weights, const ZZ& p);
