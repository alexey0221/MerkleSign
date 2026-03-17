#pragma once
#ifndef LAMPORTUTILS_H
#define LAMPORTUTILS_H

#include "LamportSignature.h"
#include "streebog.h"
//#include "Utilities.h"
#include <vector>
#include <array>

class LamportUtils {
public:
    using block256 = LamportSignature::block256;

    /**
     * @brief Восстановить публичный ключ из подписи и хеша сообщения
     */
    static std::array<std::array<block256, 256>, 2> recoverPublicKey(
        const std::vector<uint8_t>& messageHash,
        const std::vector<block256>& signature) {

        if (signature.size() != 256) {
            throw std::invalid_argument("Invalid signature size");
        }

        std::array<std::array<block256, 256>, 2> recoveredKey;
        GOST hasher(256);

        for (int bitIndex = 0; bitIndex < 256; ++bitIndex) {
            int byte_idx = bitIndex / 8;
            int bit_in_byte = bitIndex % 8;
            uint8_t current_byte = messageHash[byte_idx];
            int bitValue = (current_byte >> (7 - bit_in_byte)) & 1;

            const auto& block = signature[bitIndex];
            std::vector<uint8_t> blockVec(block.begin(), block.end());
            auto hashedBlock = hasher.getHash(blockVec);

            std::copy(hashedBlock.begin(), hashedBlock.end(),
                recoveredKey[bitValue][bitIndex].begin());
        }

        return recoveredKey;
    }

    /**
     * @brief Сериализовать публичный ключ в вектор байт
     */
    static std::vector<uint8_t> serializePublicKey(
        const std::array<std::array<block256, 256>, 2>& publicKey) {

        std::vector<uint8_t> result;
        result.reserve(2 * 256 * 32);

        for (int part = 0; part < 2; ++part) {
            for (int i = 0; i < 256; ++i) {
                const auto& block = publicKey[part][i];
                result.insert(result.end(), block.begin(), block.end());
            }
        }

        return result;
    }

    /**
     * @brief Получить хеш листа для дерева Меркла из публичного ключа
     */
    static std::vector<uint8_t> getLeafHash(
        const std::array<std::array<block256, 256>, 2>& publicKey,
        int hashLength = 256) {

        auto serialized = serializePublicKey(publicKey);
        //printVectorBytes(serialized, 10, "Lamport sig verifi: ");
        GOST hasher(hashLength);
        return hasher.getHash(serialized);
    }
};

#endif // LAMPORTUTILS_H