#pragma once // This is used to prevent the same file from being included more than once during compilation
#include <NTL/ZZ.h>

using namespace NTL;

// Global parameters for all functions
extern ZZ p;
extern ZZ q;
extern ZZ g;

// Loading p,q and g into the global parameters
void load_parameters();
