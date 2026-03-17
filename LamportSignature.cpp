#include "LamportSignature.h"
#include "RandomGenerator.h"
#include "streebog.h"

#include <iostream>
#include <iomanip>
#include <bitset>
#include <vector>
#include <string>
#include <cstdint>

const size_t KEY_SIZE = 256;  // количество бит (и элементов в каждой половине)
using block256 = std::array<std::uint8_t, 32>;  // 32 байта = 256 бит

static const std::array<std::array<block256, 256>, 2> privKey;
static const std::array<std::array<block256, 256>, 2> pubKey;

namespace {
    // Кодирование Base64
    const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string base64_encode(const std::vector<uint8_t>& data) {
        std::string ret;
        int i = 0;
        uint8_t char_array_3[3];
        uint8_t char_array_4[4];
        for (uint8_t byte : data) {
            char_array_3[i++] = byte;
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                for (int j = 0; j < 4; ++j)
                    ret += base64_chars[char_array_4[j]];
                i = 0;
            }
        }
        if (i) {
            for (int j = i; j < 3; ++j)
                char_array_3[j] = '\0';
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            for (int j = 0; j < i + 1; ++j)
                ret += base64_chars[char_array_4[j]];
            while (i++ < 3)
                ret += '=';
        }
        return ret;
    }
}


LamportSignature::LamportSignature() {
	generatePrivKey();
	generatePubKey();
}

LamportSignature::LamportSignature(const std::array<std::array<block256, 256>, 2>& privateKey)
    : privKey(privateKey) {
    generatePubKey();
}


void LamportSignature::generatePrivKey() {
	CryptoRandomGenerator RNG;
	for (int j = 0; j < 2; j++) {
		for (int i = 0; i < KEY_SIZE; i++) {
			std::vector<uint8_t> randomBytes = RNG.generate_bytes(32);
			std::copy(randomBytes.begin(), randomBytes.end(), privKey[j][i].begin());
		}
	}
}

void LamportSignature::generatePubKey() {

	GOST hash256(KEY_SIZE);
	for (int j = 0; j < 2; j++) {
		for (int i = 0; i < KEY_SIZE; i++) {
			//auto block = privKey[j][i];
			//auto hash_block = hash256.getHash(block);
			const auto& block = privKey[j][i];
			std::vector<uint8_t> block_vec(block.begin(), block.end());
			auto hash_block = hash256.getHash(block_vec);
			std::copy(hash_block.begin(), hash_block.end(), pubKey[j][i].begin());
		} 
	}
}

// Единая функция вывода ключей
void LamportSignature::printKey(KeyType type, OutputFormat format) const {
    const auto& key = (type == KeyType::Private) ? privKey : pubKey;
    const char* keyName = (type == KeyType::Private) ? "Private" : "Public";

    switch (format) {
    case OutputFormat::Hex:
        for (int part = 0; part < 2; ++part) {
            std::cout << keyName << " key part " << part << " (hex):\n";
            for (size_t i = 0; i < KEY_SIZE; ++i) {
                for (size_t k = 0; k < 32; ++k) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0')
                        << static_cast<int>(key[part][i][k]);
                }
                std::cout << ' ';
                if ((i + 1) % 8 == 0) std::cout << '\n';
            }
            std::cout << '\n';
        }
        std::cout << std::dec; // возврат к десятичному формату
        break;

    case OutputFormat::Bin:
        for (int part = 0; part < 2; ++part) {
            std::cout << keyName << " key part " << part << " (binary):\n";
            for (size_t i = 0; i < KEY_SIZE; ++i) {
                for (size_t k = 0; k < 32; ++k) {
                    std::bitset<8> bits(key[part][i][k]);
                    std::cout << bits;
                    if (k < 31) std::cout << ' ';
                }
                std::cout << '\n';
            }
        }
        break;

    case OutputFormat::Dec:
        for (int part = 0; part < 2; ++part) {
            std::cout << keyName << " key part " << part << " (decimal):\n";
            for (size_t i = 0; i < KEY_SIZE; ++i) {
                for (size_t k = 0; k < 32; ++k) {
                    std::cout << static_cast<int>(key[part][i][k]);
                    if (k < 31) std::cout << ' ';
                }
                std::cout << '\n';
            }
        }
        break;

    case OutputFormat::Base64:
    {
        std::vector<uint8_t> allBytes;
        allBytes.reserve(2 * KEY_SIZE * 32);
        for (int part = 0; part < 2; ++part)
            for (size_t i = 0; i < KEY_SIZE; ++i)
                allBytes.insert(allBytes.end(), key[part][i].begin(), key[part][i].end());
        std::string base64 = base64_encode(allBytes);
        std::cout << keyName << " key (base64):\n" << base64 << std::endl;
    }
    break;
    }
}

std::vector<block256> LamportSignature::signMessage(const std::vector<uint8_t>& message) {

    // Подпись будет состоять из выбранных блоков приватного ключа
    std::vector<block256> signature;
    signature.reserve(256);  // 256 элементов

    GOST hash256(256);
    auto hash_message = hash256.getHash(message);

    for (int bit_index = 0; bit_index < 256; ++bit_index) {
        // Определяем, в каком байте находится текущий бит
        int byte_idx = bit_index / 8;
        int bit_in_byte = bit_index % 8;

        // Получаем байт
        uint8_t current_byte = hash_message[byte_idx];

        // Извлекаем значение бита (0 или 1)
        // Порядок: старший бит байта считается первым (7 - bit_in_byte)
        int bit_value = (current_byte >> (7 - bit_in_byte)) & 1;

        // Выбираем соответствующую половину приватного ключа:
        // bit_value = 0 -> первая половина (j=0), bit_value = 1 -> вторая половина (j=1)
        const auto& selected_block = privKey[bit_value][bit_index];

        // Добавляем выбранный блок в подпись
        signature.push_back(selected_block);
    }

    return signature;

}

bool LamportSignature::signVerification(const std::vector<uint8_t>& message,
    const std::vector<block256>& signature) {
    // Проверка размера подписи
    if (signature.size() != KEY_SIZE) {
        std::cout << "Invalid signature size!" << std::endl;
        return false;
    }

    // Вычисляем хеш сообщения
    GOST hash256(256);
    auto hash_message = hash256.getHash(message); // вектор байт (32)

    // Определяем, какие блоки публичного ключа должны соответствовать подписи
    std::vector<block256> expected_pub_blocks;
    expected_pub_blocks.reserve(KEY_SIZE);

    for (int bit_index = 0; bit_index < KEY_SIZE; ++bit_index) {
        int byte_idx = bit_index / 8;
        int bit_in_byte = bit_index % 8;
        uint8_t current_byte = hash_message[byte_idx];
        int bit_value = (current_byte >> (7 - bit_in_byte)) & 1;
        expected_pub_blocks.push_back(pubKey[bit_value][bit_index]);
    }

    // Проверяем каждый блок подписи
    for (int i = 0; i < KEY_SIZE; ++i) {
        // Преобразуем блок подписи (std::array) в вектор для хеширования
        std::vector<uint8_t> sig_block_vec(signature[i].begin(), signature[i].end());
        auto hash_of_sig_block = hash256.getHash(sig_block_vec); // вектор

        // Сравниваем с ожидаемым публичным блоком (std::array)
        if (!std::equal(hash_of_sig_block.begin(), hash_of_sig_block.end(),
            expected_pub_blocks[i].begin())) {
            std::cout << "The signature is incorrect at block " << i << "!" << std::endl;
            return false;
        }
    }

    std::cout << "Signature of Lamport is valid." << std::endl;
    return true;
}

bool LamportSignature::verifyWithPublicKey(
    const std::vector<uint8_t>& message,
    const std::vector<block256>& signature,
    const std::array<std::array<block256, 256>, 2>& publicKey) {

    // Проверка размера подписи
    if (signature.size() != KEY_SIZE) {
        std::cout << "Invalid signature size! Expected " << KEY_SIZE
            << ", got " << signature.size() << std::endl;
        return false;
    }

    // Вычисляем хеш сообщения
    GOST hash256(256);
    auto hash_message = hash256.getHash(message); // вектор байт (32)

    // Проверяем каждый блок подписи
    for (int bit_index = 0; bit_index < KEY_SIZE; ++bit_index) {
        // Определяем значение бита в хеше сообщения
        int byte_idx = bit_index / 8;
        int bit_in_byte = bit_index % 8;
        uint8_t current_byte = hash_message[byte_idx];
        int bit_value = (current_byte >> (7 - bit_in_byte)) & 1;

        // Получаем соответствующий блок из подписи (приватное значение)
        const auto& signature_block = signature[bit_index];

        // Хешируем блок подписи, чтобы получить ожидаемый публичный блок
        std::vector<uint8_t> sig_block_vec(signature_block.begin(), signature_block.end());
        auto hash_of_sig_block = hash256.getHash(sig_block_vec);

        // Получаем ожидаемый публичный блок из переданного открытого ключа
        const auto& expected_pub_block = publicKey[bit_value][bit_index];

        // Сравниваем
        if (!std::equal(hash_of_sig_block.begin(), hash_of_sig_block.end(),
            expected_pub_block.begin())) {
            std::cout << "Signature verification failed at bit index " << bit_index
                << " (bit value: " << bit_value << ")" << std::endl;

            // Для отладки можно вывести первые несколько байт
            std::cout << "  Computed hash: ";
            for (int j = 0; j < 4 && j < hash_of_sig_block.size(); ++j) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << (int)hash_of_sig_block[j];
            }
            std::cout << "..." << std::endl;

            std::cout << "  Expected hash: ";
            for (int j = 0; j < 4 && j < 32; ++j) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << (int)expected_pub_block[j];
            }
            std::cout << "..." << std::dec << std::endl;

            return false;
        }
    }

    std::cout << "Lamport signature is valid." << std::endl;
    return true;
}