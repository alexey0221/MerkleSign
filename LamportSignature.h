#pragma once
#ifndef LAMPORTSIGNATURE_H
#define LAMPORTSIGNATURE_H
#include <cstdint>
#include <array>
#include "RandomGenerator.h"

class LamportSignature
{

public:
	using block256 = std::array<std::uint8_t, 32>;
	std::vector<block256> signMessage(const std::vector<uint8_t>& message);
	bool signVerification(const std::vector<uint8_t>& message, const std::vector<block256>& signature);
	bool verifyWithPublicKey(
		const std::vector<uint8_t>& message,
		const std::vector<block256>& signature,
		const std::array<std::array<block256, 256>, 2>& publicKey);

	using block256 = std::array<std::uint8_t, 32>;  // 256 бит
	LamportSignature();  // конструктор генерирует ключи
	// Конструктор для загрузки существующего ключа
	LamportSignature(const std::array<std::array<block256, 256>, 2>& privateKey);

	const std::array<std::array<block256, 256>, 2>& getPrivateKey() const { return privKey; }
	const std::array<std::array<block256, 256>, 2>& getPublicKey() const { return pubKey; }

	// Перечисления для параметров вывода
	enum class KeyType { Private, Public };
	enum class OutputFormat { Hex, Bin, Dec, Base64 };

	// Единая функция вывода
	void printKey(KeyType type, OutputFormat format) const;

private:
	//using block256 = std::array<std::uint8_t, 32>;  // 32 байта = 256 бит
	CryptoRandomGenerator randomGenerator;
	// Объявление массива 2 x 256
	std::array<std::array<block256, 256>, 2> privKey;
	std::array<std::array<block256, 256>, 2> pubKey;

	void generatePrivKey();
	void generatePubKey();

};

#endif // LAMPORTSIGNATURE_H
