#pragma once

#include <stdexcept>
#include "fake_crypto.h"


std::tuple<vector_t, vector_t, vector_t> FakeSign(const std::string& string, RWEPublicKey publicKey) {
    vector_t c = {};
    vector_t z1 = {};
    vector_t z2 = {};
    auto ase = publicKey.getASEVector();
    auto a = publicKey.getAVector();
    auto module = publicKey.getModule();
    auto hash = ComputeSimpleHash(string);
    // your solution here;

    for(auto& i: c) {
        i = 1;
    }
    for(auto& i : z1) {
        i = 1;
    }
    z2 = c * ase + c - hash - a * z1;
    z2 = z2 % module;

    return std::make_tuple(c, z1, z2);
}