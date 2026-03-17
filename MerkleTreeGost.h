#ifndef MERKLETREEGOST_H
#define MERKLETREEGOST_H

#include "MerkleTree.h"
#include "streebog.h"   // заголовочный файл класса GOST
#include <vector>
#include <cstdint>

/**
 * @brief Класс дерева Меркла, использующий хеш-функцию Стрибог (256 или 512 бит).
 *
 * Внутри используется шаблонный MerkleTree с типом хеша std::vector<uint8_t>.
 */
class MerkleTreeGost {
public:
    /**
     * @param leaves       Вектор листовых данных (каждый элемент - std::vector<uint8_t>).
     * @param outputLength Длина выходного хеша в битах (256 или 512).
     */
    MerkleTreeGost(const std::vector<std::vector<uint8_t>>& leaves, int outputLength);

    /// Возвращает корневой хеш.
    std::vector<uint8_t> getRoot() const;

    /// Количество листьев.
    size_t getLeafCount() const;

    /// Высота дерева (n).
    size_t getHeight() const;

    /// Хеш листа по индексу.
    std::vector<uint8_t> getLeafHash(size_t leaf_idx) const;

    /// Доказательство включения для листа.
    std::vector<std::pair<std::vector<uint8_t>, bool>> getProof(size_t leaf_idx) const;

    /**
     * @brief Проверка доказательства включения.
     * @param leaf_hash   Хеш листа.
     * @param proof       Доказательство.
     * @param root        Корневой хеш, с которым сравниваем.
     * @param outputLength Длина хеша (256 или 512), должна совпадать с использованной при построении.
     * @return true если доказательство верно.
     */
    static bool verifyProof(const std::vector<uint8_t>& leaf_hash,
        const std::vector<std::pair<std::vector<uint8_t>, bool>>& proof,
        const std::vector<uint8_t>& root,
        int outputLength);

private:
    MerkleTree<std::vector<uint8_t>> m_tree;   ///< Внутреннее шаблонное дерево
};

#endif // MERKLETREEGOST_H