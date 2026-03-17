#include "MerkleTreeGost.h"

MerkleTreeGost::MerkleTreeGost(const std::vector<std::vector<uint8_t>>& leaves, int outputLength)
    : m_tree(
        leaves,
        // Хеширование листа: просто вызываем GOST::getHash
        [outputLength](const std::vector<uint8_t>& data) {
            GOST hasher(outputLength);
            return hasher.getHash(data);
        },
        // Комбинирование двух дочерних хешей: конкатенация + хеш
        [outputLength](const std::vector<uint8_t>& left, const std::vector<uint8_t>& right) {
            std::vector<uint8_t> combined;
            combined.reserve(left.size() + right.size());
            combined.insert(combined.end(), left.begin(), left.end());
            combined.insert(combined.end(), right.begin(), right.end());

            GOST hasher(outputLength);
            return hasher.getHash(combined);
        }
    )
{
}

std::vector<uint8_t> MerkleTreeGost::getRoot() const {
    return m_tree.getRoot();
}

size_t MerkleTreeGost::getLeafCount() const {
    return m_tree.getLeafCount();
}

size_t MerkleTreeGost::getHeight() const {
    return m_tree.getHeight();
}

std::vector<uint8_t> MerkleTreeGost::getLeafHash(size_t leaf_idx) const {
    return m_tree.getLeafHash(leaf_idx);
}

std::vector<std::pair<std::vector<uint8_t>, bool>> MerkleTreeGost::getProof(size_t leaf_idx) const {
    return m_tree.getProof(leaf_idx);
}

bool MerkleTreeGost::verifyProof(const std::vector<uint8_t>& leaf_hash,
    const std::vector<std::pair<std::vector<uint8_t>, bool>>& proof,
    const std::vector<uint8_t>& root,
    int outputLength) {
    // Для проверки используем ту же логику комбинирования
    auto combiner = [outputLength](const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        std::vector<uint8_t> combined;
        combined.reserve(a.size() + b.size());
        combined.insert(combined.end(), a.begin(), a.end());
        combined.insert(combined.end(), b.begin(), b.end());

        GOST hasher(outputLength);
        return hasher.getHash(combined);
        };

    return MerkleTree<std::vector<uint8_t>>::verifyProof(leaf_hash, proof, root, combiner);
}