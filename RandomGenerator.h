#pragma once

#include <cstdint>
#include <limits>
#include <random>
#include <type_traits>
#include <vector>

class CryptoRandomGenerator {
public:
    using result_type = std::random_device::result_type;

    CryptoRandomGenerator();

    result_type operator()();

    void generate_bytes(std::uint8_t* buffer, std::size_t size);
    std::vector<std::uint8_t> generate_bytes(std::size_t size);

    template<typename IntType>
    IntType generate_integer(IntType min, IntType max) {
        static_assert(std::is_integral<IntType>::value, "Integer type required");
        std::uniform_int_distribution<IntType> dist(min, max);
        return dist(rd_);
    }

    template<typename RealType>
    RealType generate_real(RealType min, RealType max) {
        static_assert(std::is_floating_point<RealType>::value, "Floating-point type required");
        std::uniform_real_distribution<RealType> dist(min, max);
        return dist(rd_);
    }

    static constexpr result_type min() {
        return std::random_device::min();
    }

    static constexpr result_type max() {
        return std::random_device::max();
    }

private:
    std::random_device rd_;
};