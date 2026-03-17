// Файл содержит определения шаблонных методов класса MerkleTree.
// Обратите внимание: для шаблонного класса определения должны быть видны
// в момент инстанцирования, поэтому этот файл включается в конце
// заголовочного файла MerkleTree.h (обычная практика для шаблонных классов).

#include "MerkleTree.h"
#include <stdexcept>
#include <cmath>

template<typename HashType, typename DataType>
MerkleTree<HashType, DataType>::MerkleTree(const std::vector<DataType>& leaves,
    HashFunction leaf_hasher,
    CombineFunction combiner)
    : m_leaf_hasher(std::move(leaf_hasher))
    , m_combiner(std::move(combiner))
{
    size_t N = leaves.size();
    if (N == 0 || (N & (N - 1)) != 0) {
        throw std::invalid_argument("Number of leaves must be a power of two");
    }
    m_N = N;
    m_n = static_cast<size_t>(std::log2(N));   // высота дерева
    m_tree.resize(2 * N - 1);                   // всего узлов в полном бинарном дереве

    // Заполняем листья (последние N позиций в массиве)
    for (size_t i = 0; i < N; ++i) {
        m_tree[N - 1 + i] = m_leaf_hasher(leaves[i]);
    }

    // Строим внутренние узлы снизу вверх
    for (int i = static_cast<int>(N) - 2; i >= 0; --i) {
        m_tree[i] = m_combiner(m_tree[2 * i + 1], m_tree[2 * i + 2]);
    }
}

template<typename HashType, typename DataType>
HashType MerkleTree<HashType, DataType>::getRoot() const {
    return m_tree[0];
}

template<typename HashType, typename DataType>
size_t MerkleTree<HashType, DataType>::getLeafCount() const {
    return m_N;
}

template<typename HashType, typename DataType>
size_t MerkleTree<HashType, DataType>::getHeight() const {
    return m_n;
}

template<typename HashType, typename DataType>
HashType MerkleTree<HashType, DataType>::getLeafHash(size_t leaf_idx) const {
    if (leaf_idx >= m_N) throw std::out_of_range("Leaf index out of range");
    return m_tree[m_N - 1 + leaf_idx];
}

template<typename HashType, typename DataType>
std::vector<std::pair<HashType, bool>> MerkleTree<HashType, DataType>::getProof(size_t leaf_idx) const {
    if (leaf_idx >= m_N) throw std::out_of_range("Leaf index out of range");

    std::vector<std::pair<HashType, bool>> proof;
    size_t idx = m_N - 1 + leaf_idx;   // глобальный индекс узла в массиве

    while (idx > 0) {
        size_t sibling;
        bool is_left_sibling;

        if (idx % 2 == 0) {
            // Текущий узел — правый ребёнок (чётный индекс)
            sibling = idx - 1;
            is_left_sibling = true;   // sibling (левый) будет первым аргументом combiner
        }
        else {
            // Текущий узел — левый ребёнок (нечётный индекс)
            sibling = idx + 1;
            is_left_sibling = false;  // sibling (правый) будет вторым аргументом combiner
        }

        proof.emplace_back(m_tree[sibling], is_left_sibling);
        idx = (idx - 1) / 2;   // переход к родителю
    }

    return proof;
}

template<typename HashType, typename DataType>
bool MerkleTree<HashType, DataType>::verifyProof(const HashType& leaf_hash,
    const std::vector<std::pair<HashType, bool>>& proof,
    const HashType& root,
    CombineFunction combiner) {
    HashType current = leaf_hash;
    for (const auto& [sibling_hash, is_left] : proof) {
        if (is_left) {
            current = combiner(sibling_hash, current);   // sibling слева + текущий
        }
        else {
            current = combiner(current, sibling_hash);   // текущий + sibling справа
        }
    }
    return current == root;
}