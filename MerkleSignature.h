#pragma once
#ifndef MERKLESIGNATURE_H
#define MERKLESIGNATURE_H

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <memory>
#include <iostream>  // Добавлено для cout, cerr
#include <cstring>   // Добавлено для memcpy
#include "LamportSignature.h"
#include "MerkleTreeGost.h"
#include "LamportUtils.h"  // Добавлено для LamportUtils



/**
 * @brief Класс для создания и проверки подписи Меркла
 *
 * Использует дерево Меркла для управления несколькими ключами Лэмпорта.
 * Позволяет подписывать до N сообщений (N = 2^n) одним корневым ключом.
 */
class MerkleSignature {
private:
    struct SignatureData {
        size_t messageIndex;                 // индекс сообщения
        std::vector<LamportSignature::block256> lamportSignature;  // подпись Лэмпорта
        std::array<std::array<LamportSignature::block256, 256>, 2> pubKeyLemporte; // открытый ключ подписи Лэмпорта для проверки 
        std::vector<std::pair<std::vector<uint8_t>, bool>> merkleProof;  // доказательство Меркла
    };

    // MerkleSignature.h - добавим новую структуру для хранения полного ключа Лэмпорта
    struct FullLamportKey {
        std::array<std::array<LamportSignature::block256, 256>, 2> privateKey;
        std::array<std::array<LamportSignature::block256, 256>, 2> publicKey;

        FullLamportKey() = default;

        // Конструктор из LamportSignature
        explicit FullLamportKey(const LamportSignature& key)
            : privateKey(key.getPrivateKey())
            , publicKey(key.getPublicKey()) {
        }
    };
    // Структура для публичного ключа (только для верификации)
    struct PublicKeyData {
        size_t height;
        int hashLength;
        std::vector<uint8_t> rootHash;

        // Сериализация
        std::vector<uint8_t> serialize() const {
            std::vector<uint8_t> data;

            // Магическое число
            const char* magic = "MERKLEPK";
            data.insert(data.end(), magic, magic + 8);

            // Параметры
            data.insert(data.end(),
                reinterpret_cast<const uint8_t*>(&height),
                reinterpret_cast<const uint8_t*>(&height) + sizeof(size_t));

            data.insert(data.end(),
                reinterpret_cast<const uint8_t*>(&hashLength),
                reinterpret_cast<const uint8_t*>(&hashLength) + sizeof(int));

            // Корневой хеш
            size_t rootSize = rootHash.size();
            data.insert(data.end(),
                reinterpret_cast<const uint8_t*>(&rootSize),
                reinterpret_cast<const uint8_t*>(&rootSize) + sizeof(size_t));
            data.insert(data.end(), rootHash.begin(), rootHash.end());

            return data;
        }

        // Десериализация
        static PublicKeyData deserialize(const std::vector<uint8_t>& data) {
            PublicKeyData result;
            size_t offset = 0;

            // Проверяем магическое число
            if (data.size() < 8 || std::string(data.begin(), data.begin() + 8) != "MERKLEPK") {
                throw std::runtime_error("Invalid public key format");
            }
            offset += 8;

            // Читаем параметры
            std::memcpy(&result.height, data.data() + offset, sizeof(size_t));
            offset += sizeof(size_t);

            std::memcpy(&result.hashLength, data.data() + offset, sizeof(int));
            offset += sizeof(int);

            // Читаем корневой хеш
            size_t rootSize;
            std::memcpy(&rootSize, data.data() + offset, sizeof(size_t));
            offset += sizeof(size_t);

            result.rootHash.resize(rootSize);
            std::memcpy(result.rootHash.data(), data.data() + offset, rootSize);

            return result;
        }
    };

    size_t m_height;                         // высота дерева
    size_t m_maxSignatures;                   // максимальное количество подписей
    int m_hashLength;                         // длина хеша в битах
    //std::vector<std::unique_ptr<LamportSignature>> m_lamportKeys;  // все ключи Лэмпорта
    std::vector<std::unique_ptr<FullLamportKey>> m_lamportKeys;  // Изменено!
    std::unique_ptr<MerkleTreeGost> m_tree;    // дерево Меркла для ключей
    std::vector<bool> m_usedIndices;           // использованные индексы

    // Вспомогательные функции для построения дерева
    void buildMerkleTree();
    std::vector<uint8_t> serializeLamportPublicKey(const LamportSignature& key) const;
    std::vector<uint8_t> serializeLamportPrivateKey(const LamportSignature& key) const;
    std::unique_ptr<LamportSignature> deserializeLamportPrivateKey(const std::vector<uint8_t>& data) const;

    // Сериализация/десериализация подписи
    static std::vector<uint8_t> serializeSignature(const SignatureData& sig);
    static SignatureData deserializeSignature(const std::vector<uint8_t>& data);

    // Новые методы сериализации
    std::vector<uint8_t> serializeFullLamportKey(const FullLamportKey& key) const;
    std::unique_ptr<FullLamportKey> deserializeFullLamportKey(const std::vector<uint8_t>& data) const;

public:
    /**
     * @brief Конструктор для генерации новой пары ключей
     * @param height Высота дерева (n). Количество подписей = 2^n
     * @param hashLength Длина хеша в битах (256 или 512)
     */
    MerkleSignature(size_t height, int hashLength = 256);

    /**
     * @brief Загрузка существующего ключа из файла
     * @param filename Имя файла с ключом
     */
    explicit MerkleSignature(const std::string& filename);

    /**
     * @brief Подписать сообщение
     * @param message Сообщение для подписи
     * @param messageIndex Индекс сообщения (0 .. maxSignatures-1)
     * @return Подпись в виде байтового вектора
     */
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message, size_t messageIndex);

    /**
     * @brief Проверить подпись
     * @param message Исходное сообщение
     * @param signature Подпись
     * @param messageIndex Индекс сообщения
     * @param publicKeyFile Файл с открытым ключом
     * @return true если подпись верна
     */
    static bool verify(const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature,
        size_t messageIndex,
        const std::string& publicKeyFile);

    /**
     * @brief Сохранить приватный ключ в файл
     * @param filename Имя файла
     */
    void savePrivateKey(const std::string& filename) const;

    /**
     * @brief Сохранить публичный ключ в файл
     * @param filename Имя файла
     */
    void savePublicKey(const std::string& filename) const;

    /**
     * @brief Получить корневой хеш (публичный ключ)
     */
    std::vector<uint8_t> getPublicKey() const { return m_tree ? m_tree->getRoot() : std::vector<uint8_t>(); }

    /**
     * @brief Получить максимальное количество подписей
     */
    size_t getMaxSignatures() const { return m_maxSignatures; }

    /**
 * @brief Загрузить публичный ключ из файла
 * @param filename Имя файла с публичным ключом
 * @return структура с данными публичного ключа
 */
    static PublicKeyData loadPublicKey(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open public key file: " + filename);
        }

        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());

        return PublicKeyData::deserialize(data);
    }

/**
 * @brief Проверить подпись (статический метод, не требует объекта)
 * @param message Исходное сообщение
 * @param signature Подпись
 * @param publicKey Публичный ключ (структура PublicKeyData)
 * @return true если подпись верна
 */
    static bool verify(const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature,
        const PublicKeyData& publicKey) {
        try {
            // Десериализуем подпись
            auto sigData = deserializeSignature(signature);

            // Хешируем сообщение
            GOST hasher(publicKey.hashLength);
            auto messageHash = hasher.getHash(message);

            // Создаем временный объект LamportSignature для верификации
            LamportSignature lamportSig;
            bool validLamport = lamportSig.verifyWithPublicKey(
                message,
                sigData.lamportSignature,
                sigData.pubKeyLemporte
            );

            if (!validLamport) {
                std::cout << "Lamport signature is invalid" << std::endl;
                return false;
            }

            // Получаем хеш листа для дерева Меркла
            auto leafHash = LamportUtils::getLeafHash(sigData.pubKeyLemporte, publicKey.hashLength);

            // Проверяем доказательство Меркла
            return MerkleTreeGost::verifyProof(
                leafHash,
                sigData.merkleProof,
                publicKey.rootHash,
                publicKey.hashLength
            );
        }
        catch (const std::exception& e) {
            std::cerr << "Verification error: " << e.what() << std::endl;
            return false;
        }
    }

};

#endif // MERKLESIGNATURE_H