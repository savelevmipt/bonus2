#pragma once

#include <array>
#include <iterator>
#include <algorithm>
#include <random>
#include <iostream>
#include <string>
#include <tuple>


using vector_t = std::array<int, 128>;

// Arrays as vectors to compile-time optimisation
vector_t operator+(const vector_t &a, const vector_t &b);

vector_t operator-(const vector_t &a, const vector_t &b);

vector_t operator%(const vector_t &a, int mod);

vector_t operator*(const vector_t &a, const vector_t &b);

vector_t operator/(const vector_t &a, const vector_t &b);

// Public key definition
class RWEPublicKey {
public:
    RWEPublicKey(int module, vector_t ase_vector, vector_t a_vector) :
            module_(module),
            ASEVector_(ase_vector),
            AVector_(a_vector) {
    }

    [[nodiscard]] int getModule() const {
        return module_;
    }

    [[nodiscard]] const vector_t &getASEVector() const {
        return ASEVector_;
    }

    [[nodiscard]] const vector_t &getAVector() const {
        return AVector_;
    }

private:
    int module_;
    vector_t ASEVector_;
    vector_t AVector_;
};


// Private key definition
class RWEPrivateKey {
public:
    RWEPrivateKey(int module, vector_t s_vector, vector_t e_vector, vector_t a_vector) :
            module_(module),
            SVector_(s_vector),
            EVector_(e_vector),
            AVector_(a_vector) {
    }

    [[nodiscard]] int getModule() const {
        return module_;
    }

    [[nodiscard]] const vector_t &getSVector() const {
        return SVector_;
    }

    [[nodiscard]] const vector_t &getEVector() const {
        return EVector_;
    }

    [[nodiscard]] const vector_t &getAVector() const {
        return AVector_;
    }

private:
    int module_;
    vector_t SVector_;
    vector_t EVector_;
    vector_t AVector_;
};


// Generates keypair
std::tuple<RWEPublicKey, RWEPrivateKey> GenerateKeyPair(int module);

// Computes 128 byte hash of string message
vector_t ComputeSimpleHash(const std::string &string);

// Sign message via private key
std::tuple<vector_t, vector_t, vector_t> Sign(const std::string &message, RWEPrivateKey private_key);

template<typename T_Sign>
bool Verify(const std::string &message, RWEPublicKey public_key, T_Sign sign);



#include "fake_crypto.h"

template<typename T_Sign>
bool Verify(const std::string &message, RWEPublicKey public_key, T_Sign sign) {
    auto message_hash = ComputeSimpleHash(message);
    auto module = public_key.getModule();
    auto ase_vector = public_key.getASEVector();
    auto a_vector = public_key.getAVector();

    auto[c, z1, z2] = sign;

    if (std::find_if(z1.begin(), z1.end(), [](int x) -> bool { return x != 0; }) == z1.end()) {
        return false;
    }

    if (std::find_if(z2.begin(), z2.end(), [](int x) -> bool { return x != 0; }) == z2.end()) {
        return false;
    }

    auto tmp = (a_vector * z1 + z2 - ase_vector * c);
    tmp = (tmp + message_hash) % module - c;
    for (size_t i = 0; i < message_hash.size(); ++i) {
        if (tmp[i] != 0) {
            return false;
        }
    }
    return true;
}

std::tuple<vector_t, vector_t, vector_t> Sign(const std::string &message, RWEPrivateKey private_key) {
    auto s_vector = private_key.getSVector();
    auto e_vector = private_key.getEVector();
    auto a_vector = private_key.getAVector();
    auto module = private_key.getModule();

    auto message_hash = ComputeSimpleHash(message);

    vector_t y1 = {};
    vector_t y2 = {};
    vector_t w = {};
    vector_t c = {};
    vector_t z1 = {};
    vector_t z2 = {};

    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> uniform_distribution;

    // Uniform distribution without zeros
    uniform_distribution = std::uniform_int_distribution<int>(-(module / 2) + 1, module / 2);
    auto generator = [&uniform_distribution, &mt]() -> int {
        return uniform_distribution(mt);
    };
    std::generate(y1.begin(), y1.end(), generator);
    std::generate(y2.begin(), y2.end(), generator);

    // Compute w
    w = (a_vector * y1 + y2) % module;

    // Compute c
    c = (w + message_hash) % module;

    // Compute z1
    z1 = (s_vector * c + y1) % module;

    // Compute z2
    z2 = (e_vector * c + y2) % module;

    return std::make_tuple(c, z1, z2);
}

vector_t ComputeSimpleHash(const std::string &string) {
    vector_t result_hash = {};
    for (int &elem : result_hash) {
        elem = 1;
    }
    for (size_t i = 0; i < string.size(); ++i) {
        result_hash[i % 128] += (static_cast<int>(string[i]) * i) % (string[i] % 32 + 1);
    }
    return result_hash;
}

std::tuple<RWEPublicKey, RWEPrivateKey> GenerateKeyPair(int module) {
    std::random_device rd;
    std::mt19937 mt(rd());

    vector_t s_vector = {};
    vector_t e_vector = {};
    vector_t a_vector = {};
    vector_t ase_vector = {};

    std::uniform_int_distribution<int> uniform_distribution;

    // Uniform distribution without zeros
    uniform_distribution = std::uniform_int_distribution<int>(-(module / 2) + 1, module / 2);
    auto generator = [&uniform_distribution, &mt]() -> int {
        return uniform_distribution(mt);
    };
    std::generate(s_vector.begin(), s_vector.end(), generator);
    std::generate(e_vector.begin(), e_vector.end(), generator);

    // Uniform distribution without zeros too
    uniform_distribution = std::uniform_int_distribution<int>(1, module);
    std::generate(a_vector.begin(), a_vector.end(), generator);

    ase_vector = (a_vector * s_vector + e_vector) % module;

    return std::make_tuple(RWEPublicKey(module, ase_vector, a_vector),
                           RWEPrivateKey(module, s_vector, e_vector, a_vector));
}

vector_t operator%(const vector_t &a, int mod) {
    vector_t result{};
    for (size_t i = 0; i < result.size(); ++i) {
        // To avoid -5 % 4 = -1
        if (a[i] >= 0) {
            result[i] = a[i] % mod;
        } else {
            result[i] = mod - ((-a[i]) % mod);
        }
    }
    return result;
}

vector_t operator*(const vector_t &a, const vector_t &b) {
    vector_t result{};
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = a[i] * b[i];
    }
    return result;
}

vector_t operator-(const vector_t &a, const vector_t &b) {
    vector_t result{};
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = a[i] - b[i];
    }
    return result;
}

vector_t operator+(const vector_t &a, const vector_t &b) {
    vector_t result{};
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = a[i] + b[i];
    }
    return result;
}

vector_t operator/(const vector_t &a, const vector_t &b) {
    vector_t result{};
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] = a[i] / b[i];
    }
    return result;
}
