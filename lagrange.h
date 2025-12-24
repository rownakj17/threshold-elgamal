#pragma once // This is used to prevent the same file from being included more than once during compilation
#include <NTL/ZZ.h>
#include <vector>

using namespace NTL;
using namespace std;

// Given indices like {1,3,5}, compute weights λ_j for interpolation at x=0 (mod q)
// Because the secret is at point 0
vector<ZZ> lagrange_weights_at_zero(const vector<long>& indices, const ZZ& q);
