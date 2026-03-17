#include "RandomGenerator.h"
#include <algorithm>
#include <stdexcept>

CryptoRandomGenerator::CryptoRandomGenerator()
try : rd_() {
    // Инициализация успешна
}
catch (const std::exception& e) {
    throw std::runtime_error("Failed to initialize random device: " + std::string(e.what()));
}

CryptoRandomGenerator::result_type CryptoRandomGenerator::operator()() {
    return rd_();
}

void CryptoRandomGenerator::generate_bytes(std::uint8_t* buffer, std::size_t size) {
    constexpr std::size_t chunk_size = sizeof(result_type);
    std::size_t i = 0;

    for (; i + chunk_size <= size; i += chunk_size) {
        result_type value = rd_();
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&value), chunk_size, buffer + i);
    }

    if (i < size) {
        result_type value = rd_();
        std::copy_n(reinterpret_cast<const std::uint8_t*>(&value), size - i, buffer + i);
    }
}

std::vector<std::uint8_t> CryptoRandomGenerator::generate_bytes(std::size_t size) {
    std::vector<std::uint8_t> result(size);
    generate_bytes(result.data(), size);
    return result;
}