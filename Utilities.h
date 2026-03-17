//#pragma once
#include <iostream>
#include <vector>
#include <iomanip>
#include "LamportSignature.h"  // для block256

inline  void printVectorBytes(const std::vector<uint8_t>& vec,
    size_t count = 8,
    const std::string& prefix = "") {
    if (!prefix.empty()) {
        std::cout << prefix;
    }

    size_t bytesToPrint = std::min(count, vec.size());
    std::cout << "First " << bytesToPrint << " bytes: ";

    for (size_t i = 0; i < bytesToPrint; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(vec[i]);
        if (i < bytesToPrint - 1) std::cout << " ";
    }

    if (vec.size() < count) {
        std::cout << " (vector size: " << vec.size() << ")";
    }

    std::cout << std::dec << std::endl;
}

// Функция для вывода первых байтов из vector<block256>
inline void printBlock256VectorBytes(const std::vector<LamportSignature::block256>& blocks,
    size_t bytesPerBlock = 4,     // сколько байт из каждого блока показывать
    size_t maxBlocks = 8,          // максимальное количество блоков для показа
    const std::string& prefix = "") {

    if (!prefix.empty()) {
        std::cout << prefix;
    }

    size_t blocksToShow = std::min(maxBlocks, blocks.size());
    std::cout << "First " << blocksToShow << " blocks (first " << bytesPerBlock << " bytes each):" << std::endl;

    for (size_t i = 0; i < blocksToShow; ++i) {
        std::cout << "  Block " << i << ": ";

        size_t bytesToPrint = std::min(bytesPerBlock, size_t(32)); // block256 имеет 32 байта
        for (size_t j = 0; j < bytesToPrint; ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(blocks[i][j]);
            if (j < bytesToPrint - 1) std::cout << " ";
        }

        if (bytesPerBlock < 32) {
            std::cout << "...";
        }
        std::cout << std::endl;
    }

    if (blocks.size() > maxBlocks) {
        std::cout << "  ... and " << (blocks.size() - maxBlocks) << " more blocks" << std::endl;
    }

    std::cout << std::dec;
}

// Функция для вывода всех байтов из всех блоков (компактно)
inline void printBlock256VectorCompact(const std::vector<LamportSignature::block256>& blocks,
    size_t maxBlocks = 8,
    const std::string& prefix = "") {

    if (!prefix.empty()) {
        std::cout << prefix;
    }

    size_t blocksToShow = std::min(maxBlocks, blocks.size());
    std::cout << "First " << blocksToShow << " blocks (all 32 bytes):" << std::endl;

    for (size_t i = 0; i < blocksToShow; ++i) {
        std::cout << "  Block " << std::setw(2) << i << ": ";
        for (size_t j = 0; j < 32; ++j) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(blocks[i][j]);
        }
        std::cout << std::dec << std::endl;
    }

    if (blocks.size() > maxBlocks) {
        std::cout << "  ... and " << (blocks.size() - maxBlocks) << " more blocks" << std::endl;
    }
}

// Функция для вывода конкретного блока
inline void printBlock256(const LamportSignature::block256& block,
    size_t bytesToShow = 8,
    const std::string& prefix = "") {

    if (!prefix.empty()) {
        std::cout << prefix;
    }

    std::cout << "Block (first " << bytesToShow << " bytes): ";
    for (size_t j = 0; j < std::min(bytesToShow, size_t(32)); ++j) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(block[j]);
        if (j < bytesToShow - 1) std::cout << " ";
    }

    if (bytesToShow < 32) {
        std::cout << "...";
    }
    std::cout << std::dec << std::endl;
}