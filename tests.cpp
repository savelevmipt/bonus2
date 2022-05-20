#include "fake_crypto.h"
#include "solution.h"
#include "gtest/gtest.h"

class RandomMessagesGenerator {
public:
    RandomMessagesGenerator(size_t max_length) :
        mt_(std::random_device()()),
        char_distribution_('a', 'z' + 1),
        length_distribution_(1, max_length + 1) {
    }

    std::string Generate() const {
        size_t length = length_distribution_(mt_);
        std::vector<char> result(length);
        auto generator = [this]() -> char {
            return this->char_distribution_(this->mt_);
        };
        std::generate(result.begin(), result.end(), generator);

        return {result.begin(), result.end()};
    }

private:
    mutable std::mt19937 mt_;
    mutable std::uniform_int_distribution<char> char_distribution_;
    mutable std::uniform_int_distribution<size_t> length_distribution_;
};


TEST(cryptosystem, pre_defined_with_fixed_keypair) {
    std::vector<std::string> data({"hello", "cryptography", "and", "hacking"});

    auto [public_key, private_key] = GenerateKeyPair(929);

    for (const auto& message: data) {
        auto sign = Sign(message, private_key);
        ASSERT_TRUE(Verify(message, public_key, sign));
    }
}

TEST(cryptosystem, is_correct) {
    RandomMessagesGenerator gen(1000);

    for (size_t i = 0; i < 1000; ++i) {
        auto [public_key, private_key] = GenerateKeyPair(929);
        std::string message = gen.Generate();
        auto sign = Sign(message, private_key);
        ASSERT_TRUE(Verify(message, public_key, sign));
    }
}

TEST(small_strings, pre_defined_with_fixed_keypair) {
    std::vector<std::string> data({"hello", "cryptography", "and", "hacking"});

    auto [public_key, _] = GenerateKeyPair(929);

    for (const auto& message: data) {
        auto sign = FakeSign(message, public_key);
        ASSERT_TRUE(Verify(message, public_key, sign));
    }
}


TEST(small_strings, pre_defined_with_random_keypair) {
    std::vector<std::string> data({"hello", "cryptography", "and", "hacking"});

    for (const auto& message: data) {
        auto [public_key, _] = GenerateKeyPair(929);
        auto sign = FakeSign(message, public_key);
        ASSERT_TRUE(Verify(message, public_key, sign));
    }
}

TEST(big_strings, random_keypair) {
    RandomMessagesGenerator gen(1000);

    for (size_t i = 0; i < 1000; ++i) {
        auto [public_key, _] = GenerateKeyPair(929);
        std::string message = gen.Generate();
        auto sign = FakeSign(message, public_key);
        ASSERT_TRUE(Verify(message, public_key, sign));
    }
}
