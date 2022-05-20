#pragma once

#include <stdexcept>
#include "fake_crypto.h"


std::tuple<vector_t, vector_t, vector_t> FakeSign(const std::string&, RWEPublicKey) {
    vector_t c = {};
    vector_t z1 = {};
    vector_t z2 = {};

    // your solution here;

    throw std::runtime_error("Not implemented");

    return std::make_tuple(c, z1, z2);
}