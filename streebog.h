// streebog.h
#ifndef STREEBOG_H
#define STREEBOG_H

#include <vector>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

class GOST {
private:
    static const std::array<uint64_t, 64> A;
    static const std::array<uint8_t, 256> Sbox;
    static const std::array<uint8_t, 64> Tau;
    static const std::array<std::array<uint8_t, 64>, 12> C;

    std::array<uint8_t, 64> iv;
    std::array<uint8_t, 64> N;
    std::array<uint8_t, 64> Sigma;
    int outLen;

    // Приватные методы
    std::array<uint8_t, 64> addMod512(const std::array<uint8_t, 64>& a, const std::array<uint8_t, 64>& b);
    std::array<uint8_t, 64> addMod512(const std::array<uint8_t, 64>& a, const std::array<uint8_t, 8>& b);
    std::array<uint8_t, 64> xor512(const std::array<uint8_t, 64>& a, const std::array<uint8_t, 64>& b);
    std::array<uint8_t, 64> S(const std::array<uint8_t, 64>& state);
    std::array<uint8_t, 64> P(const std::array<uint8_t, 64>& state);
    std::array<uint8_t, 64> L(const std::array<uint8_t, 64>& state);
    std::array<uint8_t, 64> keySchedule(const std::array<uint8_t, 64>& K, int i);
    std::array<uint8_t, 64> E(const std::array<uint8_t, 64>& K, const std::array<uint8_t, 64>& m);
    std::array<uint8_t, 64> g_N(const std::array<uint8_t, 64>& N_val, const std::array<uint8_t, 64>& h, const std::array<uint8_t, 64>& m);
    std::array<uint8_t, 8> uint64ToBigEndian(uint64_t value);

public:
    GOST(int outputLength);
    std::vector<uint8_t> getHash(const std::vector<uint8_t>& message);
    std::string hashToHexString(const std::vector<uint8_t>& hash);


    // Утилитарные методы
    //std::string hashString(const std::string& input);
};

#endif // STREEBOG_H