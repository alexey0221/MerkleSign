// main.cpp
#include <iostream>
#include "streebog.h"
#include "RandomGenerator.h"
#include "LamportSignature.h"
#include "MerkleTree.h"
#include "MerkleTreeGost.h"
#include "MerkleSignature.h"
#include "Utilities.h"
//#include <openssl/sha.h>

std::string simple_hash(const std::string& data) {
    return "hash(" + data + ")";
}

std::string combine(const std::string& left, const std::string& right) {
    return "combine(" + left + "," + right + ")";
}

// Вспомогательная функция для преобразования строки в вектор байт
std::vector<uint8_t> stringToBytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// Печать хеша в шестнадцатеричном виде (используем метод hashToHexString класса GOST)
void printHash(const std::vector<uint8_t>& hash) {
    GOST temp(256); // временный объект для вызова метода
    std::cout << temp.hashToHexString(hash);
}

void printFirst8(const std::vector<uint8_t>& vec, const std::string& prefix = "") {
    if (!prefix.empty()) {
        std::cout << prefix;
    }

    std::cout << "First 8 bytes: ";
    for (int i = 0; i < 8 && i < vec.size(); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(vec[i]) << " ";
    }

    if (vec.size() < 8) {
        std::cout << "(vector has only " << vec.size() << " bytes)";
    }

    std::cout << std::dec << std::endl; // возвращаем десятичный формат
}

// Пример использования подписи Меркла
void testMerkleSignature() {
    try {
        //Utilities util;
        // Создаем подпись Меркла с высотой 3 (8 подписей)
        std::cout << "=== Creating Merkle Keys ===" << std::endl;
        MerkleSignature merkleSign(3, 256);

        // Сохраняем ключи
        merkleSign.savePrivateKey("merkle_private.key");
        merkleSign.savePublicKey("merkle_public.key");

        // Подписываем несколько сообщений
        std::vector<std::string> messages = {
            "Hello, World!",
            "Second message",
            "Third message"
        };

        std::cout << "\n=== Signing messages ===" << std::endl;
        for (size_t i = 0; i < messages.size(); ++i) {
            auto msgBytes = stringToBytes(messages[i]);
            auto signature = merkleSign.sign(msgBytes, i);

            printVectorBytes(signature,10, "Sig: ");


            // Сохраняем подпись в файл
            std::ofstream sigFile("signature_" + std::to_string(i) + ".sig", std::ios::binary);
            sigFile.write(reinterpret_cast<const char*>(signature.data()), signature.size());

            std::cout << "Message " << i << " is signed, the signature is saved" << std::endl;
        }

        // Проверяем подписи
        std::cout << "\n=== Verification of signatures ===" << std::endl;
        for (size_t i = 0; i < messages.size(); ++i) {
            // Загружаем подпись из файла
            std::ifstream sigFile("signature_" + std::to_string(i) + ".sig", std::ios::binary);
            std::vector<uint8_t> signature((std::istreambuf_iterator<char>(sigFile)),
                std::istreambuf_iterator<char>());
            printVectorBytes(signature, 10, "Sig verifi");
            auto msgBytes = stringToBytes(messages[i]);
            bool valid = MerkleSignature::verify(msgBytes, signature, i, "merkle_public.key");

            std::cout << "The signature " << i << ": " << (valid ? "is correct" : "is incorrect") << std::endl;
        }

        // Загружаем приватный ключ из файла
        std::cout << "\n=== Downloading a key from a file ===" << std::endl;
        MerkleSignature loadedKey("merkle_private.key");

        // Подписываем еще одно сообщение загруженным ключом
        std::string newMessage = "Message from loaded key";
        auto msgBytes = stringToBytes(newMessage);
        auto signature = loadedKey.sign(msgBytes, 0);

        bool valid = MerkleSignature::verify(msgBytes, signature, 0, "merkle_public.key");
        std::cout << "Signature with the uploaded key: " << (valid ? "is correct" : "is incorrect") << std::endl;

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void testPublicKeyVerification() {
    try {
        // Загружаем публичный ключ
        auto publicKey = MerkleSignature::loadPublicKey("merkle_public.key");

        std::cout << "Loaded public key:" << std::endl;
        std::cout << "  Height: " << publicKey.height << std::endl;
        std::cout << "  Hash length: " << publicKey.hashLength << std::endl;
        std::cout << "  Root hash: ";
        printVectorBytes(publicKey.rootHash, 8, "");

        // Загружаем подпись
        std::ifstream sigFile("signature_0.sig", std::ios::binary);
        std::vector<uint8_t> signature((std::istreambuf_iterator<char>(sigFile)),
            std::istreambuf_iterator<char>());

        // Проверяем подпись
        std::string message = "Hello, World";
        auto msgBytes = stringToBytes(message);

        bool valid = MerkleSignature::verify(msgBytes, signature, publicKey);
        std::cout << "Signature verification: " << (valid ? "VALID" : "INVALID") << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main() {
    setlocale(LC_ALL, "Russian");

    try {
        //GOST gost512(512);
        //std::string test = "Hello, World!";
        //std::vector<uint8_t> data(test.begin(), test.end());

        //auto hash = gost512.getHash(data);
        //std::cout << "Хеш 512 бит: " << gost512.hashToHexString(hash) << std::endl;
        //uint8_t buff;
        //size_t size = 64;
        //CryptoRandomGenerator generator;

        //auto bytes = generator.generate_bytes(buff, size);
        //auto bytes = generator.generate_bytes(64); // возвращает вектор
        //for (int i = 0; i < bytes.size(); i++) {
        //    std::cout << std::hex << (int)bytes[i];
        //}

        //LamportSignature LSign;
        //keys.printKey(LamportSignature::KeyType::Public, LamportSignature::OutputFormat::Hex);
        //keys.printKey(LamportSignature::KeyType::Private, LamportSignature::OutputFormat::Base64);
        //std::vector<LamportSignature::block256> sign = LSign.signMessage(data);
        //std::cout << LSign.signVerification(data, sign);

        //std::vector<std::string> leaves = { "a", "b", "c", "d" };
        //GOST gost512(512);
        //MerkleTree<std::string> tree(leaves, simple_hash, combine);

        //std::cout << "Root: " << tree.getRoot() << std::endl;

        //auto proof = tree.getProof(1);
        //std::cout << "Proof for leaf 1:\n";
        //for (const auto& [h, is_left] : proof) {
        //    std::cout << "  hash: " << h << ", is_left: " << is_left << std::endl;
        //}

        //bool ok = MerkleTree<std::string>::verifyProof(
        //    tree.getLeafHash(1), proof, tree.getRoot(), combine);
        //std::cout << "Verification: " << (ok ? "OK" : "FAIL") << std::endl;

        //return 0;

        // Листовые данные
        //std::vector<std::vector<uint8_t>> leaves = {
        //    stringToBytes("message 1"),
        //    stringToBytes("message 2"),
        //    stringToBytes("message 3"),
        //    stringToBytes("message 4")
        //};

        //// Построение дерева с хешем Стрибог-256
        //MerkleTreeGost tree(leaves, 256);

        //std::cout << "Root of tree: ";
        //printHash(tree.getRoot());
        //std::cout << std::endl;

        //// Доказательство для листа с индексом 1 (второй лист)
        //auto proof = tree.getProof(1);
        //std::cout << "Proof for list 1:\n";
        //for (const auto& [hash, is_left] : proof) {
        //    std::cout << "  hahs: ";
        //    printHash(hash);
        //    std::cout << ", is_left: " << is_left << std::endl;
        //}

        //// Проверка доказательства
        //bool valid = MerkleTreeGost::verifyProof(tree.getLeafHash(1), proof, tree.getRoot(), 256);
        //std::cout << "resalt of proofing: " << (valid ? "OK" : "FAIL") << std::endl;
        testMerkleSignature();
        //testPublicKeyVerification();

        return 0;

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}