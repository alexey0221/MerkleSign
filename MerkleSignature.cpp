#include "MerkleSignature.h"
#include "RandomGenerator.h"
#include "LamportUtils.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include "Utilities.h"

// Вспомогательные функции для сериализации
namespace {
    template<typename T>
    void writeToStream(std::ostream& os, const T& value) {
        os.write(reinterpret_cast<const char*>(&value), sizeof(T));
    }

    template<typename T>
    void readFromStream(std::istream& is, T& value) {
        is.read(reinterpret_cast<char*>(&value), sizeof(T));
    }

    void writeVector(std::ostream& os, const std::vector<uint8_t>& vec) {
        size_t size = vec.size();
        writeToStream(os, size);
        os.write(reinterpret_cast<const char*>(vec.data()), size);
    }

    std::vector<uint8_t> readVector(std::istream& is) {
        size_t size;
        readFromStream(is, size);
        std::vector<uint8_t> vec(size);
        is.read(reinterpret_cast<char*>(vec.data()), size);
        return vec;
    }
}

// Обновленный конструктор MerkleSignature
MerkleSignature::MerkleSignature(size_t height, int hashLength)
    : m_height(height)
    , m_maxSignatures(1 << height)
    , m_hashLength(hashLength)
    , m_usedIndices(m_maxSignatures, false)
{
    std::cout << "Generating " << m_maxSignatures << " Lamport keys..." << std::endl;
    m_lamportKeys.reserve(m_maxSignatures);

    for (size_t i = 0; i < m_maxSignatures; ++i) {
        // Создаем ключ Лэмпорта
        auto lamportKey = std::make_unique<LamportSignature>();

        // Сохраняем полную информацию о ключе
        auto fullKey = std::make_unique<FullLamportKey>(*lamportKey);
        m_lamportKeys.push_back(std::move(fullKey));
    }

    buildMerkleTree();
}

MerkleSignature::MerkleSignature(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open private key file: " + filename);
    }

    char magic[8] = { 0 };
    file.read(magic, 8);
    if (std::string(magic, 8) != "MERKLESK") {
        throw std::runtime_error("Invalid private key file format");
    }

    readFromStream(file, m_height);
    readFromStream(file, m_hashLength);
    m_maxSignatures = 1 << m_height;

    // Читаем использованные индексы
    m_usedIndices.resize(m_maxSignatures);
    for (size_t i = 0; i < m_maxSignatures; ++i) {
        bool used;
        readFromStream(file, used);
        m_usedIndices[i] = used;
        std::cout << "Loaded used index " << i << ": " << used << std::endl;  // Отладка
    }

    // Читаем количество ключей
    size_t numKeys;
    readFromStream(file, numKeys);
    std::cout << "Loading " << numKeys << " keys from file..." << std::endl;

    if (numKeys != m_maxSignatures) {
        throw std::runtime_error("Key count mismatch in private key file");
    }

    // Загружаем ключи
    m_lamportKeys.reserve(numKeys);
    for (size_t i = 0; i < numKeys; ++i) {
        auto keyData = readVector(file);
        std::cout << "Loading key " << i << ", data size: " << keyData.size() << " bytes" << std::endl;

        auto key = deserializeFullLamportKey(keyData);
        m_lamportKeys.push_back(std::move(key));
    }

    // ВАЖНО: Перестраиваем дерево Меркла из загруженных публичных ключей
    buildMerkleTree();

    // Проверяем корень дерева
    if (m_tree) {
        auto root = m_tree->getRoot();
        std::cout << "Rebuilt Merkle tree root: ";
        printVectorBytes(root, 8, "");
    }
}

void MerkleSignature::buildMerkleTree() {
    std::vector<std::vector<uint8_t>> publicKeys;
    publicKeys.reserve(m_lamportKeys.size());

    for (const auto& fullKey : m_lamportKeys) {
        // Сериализуем публичную часть для дерева
        std::vector<uint8_t> serializedPub;
        serializedPub.reserve(2 * 256 * 32);  // 16384 байта

        for (int part = 0; part < 2; ++part) {
            for (size_t i = 0; i < 256; ++i) {
                const auto& block = fullKey->publicKey[part][i];
                serializedPub.insert(serializedPub.end(), block.begin(), block.end());
            }
        }
        publicKeys.push_back(serializedPub);
    }

    m_tree = std::make_unique<MerkleTreeGost>(publicKeys, m_hashLength);

    // Отладка
    std::cout << "Built Merkle tree with " << publicKeys.size() << " leaves" << std::endl;
    auto root = m_tree->getRoot();
    printVectorBytes(root, 8, "Tree root: ");
}


std::vector<uint8_t> MerkleSignature::serializeLamportPublicKey(const LamportSignature& key) const {
    const auto& pubKey = key.getPublicKey();
    std::vector<uint8_t> serializedKey;

    for (int part = 0; part < 2; ++part) {
        for (size_t i = 0; i < 256; ++i) {
            const auto& block = pubKey[part][i];
            serializedKey.insert(serializedKey.end(), block.begin(), block.end());
        }
    }
    return serializedKey;
}

std::vector<uint8_t> MerkleSignature::serializeLamportPrivateKey(const LamportSignature& key) const {
    const auto& privKey = key.getPrivateKey();
    std::vector<uint8_t> serializedKey;

    for (int part = 0; part < 2; ++part) {
        for (size_t i = 0; i < 256; ++i) {
            const auto& block = privKey[part][i];
            serializedKey.insert(serializedKey.end(), block.begin(), block.end());
        }
    }
    return serializedKey;
}

std::unique_ptr<LamportSignature> MerkleSignature::deserializeLamportPrivateKey(const std::vector<uint8_t>& data) const {
    // Проверяем размер данных
    if (data.size() != 2 * 256 * 32) {  // 2 части * 256 блоков * 32 байта
        throw std::runtime_error("Invalid Lamport private key data size");
    }

    // Создаем массивы для приватного ключа
    std::array<std::array<LamportSignature::block256, 256>, 2> privKey;

    size_t offset = 0;
    for (int part = 0; part < 2; ++part) {
        for (size_t i = 0; i < 256; ++i) {
            std::memcpy(privKey[part][i].data(), data.data() + offset, 32);
            offset += 32;
        }
    }

    // Создаем ключ Лэмпорта с загруженным приватным ключом
    // Примечание: нужно добавить соответствующий конструктор в LamportSignature
    return std::make_unique<LamportSignature>(privKey);
}

// Сериализация ПОЛНОГО ключа Лэмпорта (и приватный, и публичный)
std::vector<uint8_t> MerkleSignature::serializeFullLamportKey(const FullLamportKey& key) const {
    std::vector<uint8_t> serializedKey;

    // Сначала сохраняем приватную часть
    for (int part = 0; part < 2; ++part) {
        for (size_t i = 0; i < 256; ++i) {
            const auto& block = key.privateKey[part][i];
            serializedKey.insert(serializedKey.end(), block.begin(), block.end());
        }
    }

    // Затем сохраняем публичную часть
    for (int part = 0; part < 2; ++part) {
        for (size_t i = 0; i < 256; ++i) {
            const auto& block = key.publicKey[part][i];
            serializedKey.insert(serializedKey.end(), block.begin(), block.end());
        }
    }

    return serializedKey;
}

// Десериализация ПОЛНОГО ключа Лэмпорта
std::unique_ptr<MerkleSignature::FullLamportKey> MerkleSignature::deserializeFullLamportKey(const std::vector<uint8_t>& data) const {
    if (data.size() != 4 * 256 * 32) {  // 2 части * 2 (приват+публик) * 256 блоков * 32 байта
        throw std::runtime_error("Invalid full Lamport key data size");
    }

    auto key = std::make_unique<FullLamportKey>();
    size_t offset = 0;

    // Восстанавливаем приватную часть
    for (int part = 0; part < 2; ++part) {
        for (size_t i = 0; i < 256; ++i) {
            std::memcpy(key->privateKey[part][i].data(), data.data() + offset, 32);
            offset += 32;
        }
    }

    // Восстанавливаем публичную часть
    for (int part = 0; part < 2; ++part) {
        for (size_t i = 0; i < 256; ++i) {
            std::memcpy(key->publicKey[part][i].data(), data.data() + offset, 32);
            offset += 32;
        }
    }

    return key;
}

std::vector<uint8_t> MerkleSignature::serializeSignature(const SignatureData& sig) {
    std::vector<uint8_t> data;

    // 1. Индекс сообщения (size_t)
    data.insert(data.end(),
        reinterpret_cast<const uint8_t*>(&sig.messageIndex),
        reinterpret_cast<const uint8_t*>(&sig.messageIndex) + sizeof(size_t));

    // 2. Подпись Лэмпорта (256 блоков по 32 байта) - это приватные значения
    for (const auto& block : sig.lamportSignature) {
        data.insert(data.end(), block.begin(), block.end());
    }

    // 3. Публичный ключ Лэмпорта (2 части * 256 блоков * 32 байта)
    for (int part = 0; part < 2; ++part) {
        for (size_t i = 0; i < 256; ++i) {
            const auto& block = sig.pubKeyLemporte[part][i];
            data.insert(data.end(), block.begin(), block.end());
        }
    }

    // 4. Количество элементов в доказательстве Меркла
    size_t proofSize = sig.merkleProof.size();
    data.insert(data.end(),
        reinterpret_cast<const uint8_t*>(&proofSize),
        reinterpret_cast<const uint8_t*>(&proofSize) + sizeof(size_t));

    // 5. Доказательство Меркла
    for (const auto& [hash, isLeft] : sig.merkleProof) {
        // Размер хеша
        size_t hashSize = hash.size();
        data.insert(data.end(),
            reinterpret_cast<const uint8_t*>(&hashSize),
            reinterpret_cast<const uint8_t*>(&hashSize) + sizeof(size_t));

        // Хеш
        data.insert(data.end(), hash.begin(), hash.end());

        // Флаг is_left
        data.push_back(isLeft ? 1 : 0);
    }

    std::cout << "Serialized signature size: " << data.size() << " bytes" << std::endl;
    std::cout << "  - Index: " << sizeof(size_t) << " bytes" << std::endl;
    std::cout << "  - Lamport signature: " << (256 * 32) << " bytes" << std::endl;
    std::cout << "  - Lamport public key: " << (2 * 256 * 32) << " bytes" << std::endl;
    std::cout << "  - Merkle proof: variable" << std::endl;

    return data;
}


MerkleSignature::SignatureData MerkleSignature::deserializeSignature(const std::vector<uint8_t>& data) {
    SignatureData sig;
    size_t offset = 0;

    // 1. Индекс сообщения
    if (offset + sizeof(size_t) > data.size()) {
        throw std::runtime_error("Signature data too short for message index");
    }
    std::memcpy(&sig.messageIndex, data.data() + offset, sizeof(size_t));
    offset += sizeof(size_t);
    std::cout << "Message index: " << sig.messageIndex << std::endl;

    // 2. Подпись Лэмпорта (256 блоков по 32 байта)
    const size_t lamportSigSize = 256 * 32;
    if (offset + lamportSigSize > data.size()) {
        throw std::runtime_error("Signature data too short for Lamport signature");
    }

    sig.lamportSignature.resize(256);
    for (size_t i = 0; i < 256; ++i) {
        LamportSignature::block256 block;
        std::memcpy(block.data(), data.data() + offset + i * 32, 32);
        sig.lamportSignature[i] = block;
    }
    offset += lamportSigSize;

    printBlock256VectorBytes(sig.lamportSignature, 4, 3, "Lamport signature (private values): ");

    // 3. Публичный ключ Лэмпорта (2 части * 256 блоков * 32 байта)
    const size_t pubKeySize = 2 * 256 * 32;
    if (offset + pubKeySize > data.size()) {
        throw std::runtime_error("Signature data too short for Lamport public key");
    }

    for (int part = 0; part < 2; ++part) {
        for (size_t i = 0; i < 256; ++i) {
            std::memcpy(sig.pubKeyLemporte[part][i].data(),
                data.data() + offset + (part * 256 * 32) + (i * 32), 32);
        }
    }
    offset += pubKeySize;

    std::cout << "Lamport public key loaded: " << (2 * 256 * 32) << " bytes" << std::endl;

    // 4. Размер доказательства
    if (offset + sizeof(size_t) > data.size()) {
        throw std::runtime_error("Signature data too short for proof size");
    }
    size_t proofSize;
    std::memcpy(&proofSize, data.data() + offset, sizeof(size_t));
    offset += sizeof(size_t);
    std::cout << "Proof size: " << proofSize << std::endl;

    // 5. Доказательство Меркла
    sig.merkleProof.clear();
    for (size_t i = 0; i < proofSize; ++i) {
        // Размер хеша
        if (offset + sizeof(size_t) > data.size()) {
            throw std::runtime_error("Signature data too short for hash size");
        }
        size_t hashSize;
        std::memcpy(&hashSize, data.data() + offset, sizeof(size_t));
        offset += sizeof(size_t);

        // Хеш
        if (offset + hashSize > data.size()) {
            throw std::runtime_error("Signature data too short for hash");
        }
        std::vector<uint8_t> hash(hashSize);
        std::memcpy(hash.data(), data.data() + offset, hashSize);
        offset += hashSize;

        // Флаг is_left
        if (offset + 1 > data.size()) {
            throw std::runtime_error("Signature data too short for is_left flag");
        }
        bool isLeft = (data[offset++] != 0);

        sig.merkleProof.emplace_back(hash, isLeft);
        printVectorBytes(hash, 8, "Proof hash " + std::to_string(i) + ": ");
    }

    std::cout << "Total deserialized size: " << offset << " bytes" << std::endl;

    return sig;
}

std::vector<uint8_t> MerkleSignature::sign(const std::vector<uint8_t>& message, size_t messageIndex) {
    if (messageIndex >= m_maxSignatures) {
        throw std::out_of_range("Message index out of range");
    }

    if (m_usedIndices[messageIndex]) {
        throw std::runtime_error("This index has already been used for signing");
    }

    if (!m_tree) {
        throw std::runtime_error("Merkle tree not initialized");
    }

    // Временно создаем LamportSignature из сохраненного приватного ключа
    LamportSignature tempKey(m_lamportKeys[messageIndex]->privateKey);
    auto lamportSig = tempKey.signMessage(message);

    auto merkleProof = m_tree->getProof(messageIndex);
    m_usedIndices[messageIndex] = true;

    SignatureData sigData;
    sigData.messageIndex = messageIndex;
    sigData.pubKeyLemporte = tempKey.getPublicKey();
    sigData.lamportSignature = lamportSig;
    sigData.merkleProof = merkleProof;

    std::cout << "Signing message at index " << messageIndex << std::endl;
    std::cout << "  - Lamport signature size: " << (lamportSig.size() * 32) << " bytes" << std::endl;
    std::cout << "  - Public key size: " << (2 * 256 * 32) << " bytes" << std::endl;
    std::cout << "  - Merkle proof size: " << merkleProof.size() << " elements" << std::endl;


    return serializeSignature(sigData);
}


//bool MerkleSignature::verify(const std::vector<uint8_t>& message,
//    const std::vector<uint8_t>& signature,
//    size_t messageIndex,
//    const std::string& publicKeyFile) {
//    try {
//        // Загружаем публичный ключ
//        std::ifstream file(publicKeyFile, std::ios::binary);
//        if (!file) {
//            throw std::runtime_error("Cannot open public key file");
//        }
//
//        char magic[8] = { 0 };
//        file.read(magic, 8);
//        if (std::string(magic, 8) != "MERKLEPK") {
//            throw std::runtime_error("Invalid public key file format");
//        }
//
//        size_t height;
//        int hashLength;
//        readFromStream(file, height);
//        readFromStream(file, hashLength);
//
//        std::vector<uint8_t> rootHash = readVector(file);
//        printVectorBytes(rootHash, 10, "Root hash verifi: ");
//
//        // Десериализуем подпись
//        auto sigData = deserializeSignature(signature);
//
//        if (sigData.messageIndex != messageIndex) {
//            std::cerr << "Message index mismatch" << std::endl;
//            return false;
//        }
//
//        // Хешируем сообщение
//        GOST hasher(hashLength);
//        auto messageHash = hasher.getHash(message);
//
//
//        LamportSignature LamportSig;
//        bool verifiLemportSig = LamportSig.verifyWithPublicKey(message, sigData.lamportSignature, sigData.pubKeyLemporte);
//
//        if (!verifiLemportSig) {
//            std::cout << "Lemport signature is INCORRECT" << std::endl;
//            return false;
//        }
//
//        // Получаем хеш листа для дерева Меркла
//        auto leafHash = LamportUtils::getLeafHash(sigData.pubKeyLemporte, hashLength);
//
//        // Проверяем доказательство Меркла
//        return MerkleTreeGost::verifyProof(leafHash, sigData.merkleProof, rootHash, hashLength);
//
//    }
//    catch (const std::exception& e) {
//        std::cerr << "Verification error: " << e.what() << std::endl;
//        return false;
//    }
//}

// MerkleSignature.cpp - обновить существующий метод verify

bool MerkleSignature::verify(const std::vector<uint8_t>& message,
    const std::vector<uint8_t>& signature,
    size_t messageIndex,
    const std::string& publicKeyFile) {
    try {
        // Загружаем публичный ключ
        auto publicKey = loadPublicKey(publicKeyFile);

        // Десериализуем подпись
        auto sigData = deserializeSignature(signature);

        // Проверяем индекс
        if (sigData.messageIndex != messageIndex) {
            std::cerr << "Message index mismatch: expected " << messageIndex
                << ", got " << sigData.messageIndex << std::endl;
            return false;
        }

        // Используем статический метод для проверки
        return verify(message, signature, publicKey);
    }
    catch (const std::exception& e) {
        std::cerr << "Verification error: " << e.what() << std::endl;
        return false;
    }
}

// Обновленное сохранение приватного ключа
void MerkleSignature::savePrivateKey(const std::string& filename) const {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot create private key file: " + filename);
    }

    file.write("MERKLESK", 8);
    writeToStream(file, m_height);
    writeToStream(file, m_hashLength);

    for (bool used : m_usedIndices) {
        writeToStream(file, used);
    }

    size_t numKeys = m_lamportKeys.size();
    writeToStream(file, numKeys);

    std::cout << "Saving " << numKeys << " full Lamport keys to private key file..." << std::endl;

    for (size_t i = 0; i < m_lamportKeys.size(); ++i) {
        auto keyData = serializeFullLamportKey(*m_lamportKeys[i]);
        std::cout << "Key " << i << " size: " << keyData.size() << " bytes" << std::endl;
        printVectorBytes(keyData, 8, "First 8 bytes: ");
        writeVector(file, keyData);
    }

    std::cout << "Private key saved to " << filename << std::endl;
}

void MerkleSignature::savePublicKey(const std::string& filename) const {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot create public key file: " + filename);
    }

    // Магическое число
    file.write("MERKLEPK", 8);

    // Параметры
    writeToStream(file, m_height);
    writeToStream(file, m_hashLength);

    // Корневой хеш
    if (m_tree) {
        writeVector(file, m_tree->getRoot());
    }
    else {
        writeVector(file, std::vector<uint8_t>());
    }
    printVectorBytes(m_tree->getRoot(),10, "Pub key (root)");
    std::cout << "Public key saved to " << filename << std::endl;
}
