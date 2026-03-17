#ifndef MERKLETREE_H
#define MERKLETREE_H

#include <vector>
#include <functional>
#include <stdexcept>
#include <cmath>
#include <utility>

/**
 * @brief Реализация дерева Меркла (Merkle tree) для фиксированного числа листьев N = 2^n.
 *
 * @tparam HashType   Тип хеш-значения (например, std::string, std::vector<uint8_t>).
 * @tparam DataType   Тип данных, хранящихся в листьях (по умолчанию совпадает с HashType).
 */
template<typename HashType, typename DataType = HashType>
class MerkleTree {
public:
    /// Функция, вычисляющая хеш от одного элемента данных (для листа).
    using HashFunction = std::function<HashType(const DataType&)>;
    /// Функция, комбинирующая два дочерних хеша в родительский.
    using CombineFunction = std::function<HashType(const HashType&, const HashType&)>;

    /**
     * @brief Конструктор дерева Меркла.
     *
     * @param leaves       Вектор данных для листьев. Размер должен быть степенью двойки.
     * @param leaf_hasher  Функция хеширования листовых данных.
     * @param combiner     Функция объединения двух дочерних хешей.
     * @throws std::invalid_argument если количество листьев не является степенью двойки.
     */
    MerkleTree(const std::vector<DataType>& leaves,
        HashFunction leaf_hasher,
        CombineFunction combiner);

    /// Возвращает корневой хеш дерева.
    HashType getRoot() const;

    /// Возвращает количество листьев (N = 2^n).
    size_t getLeafCount() const;

    /// Возвращает высоту дерева (n).
    size_t getHeight() const;

    /// Возвращает хеш листа по его порядковому номеру (от 0 до N-1).
    HashType getLeafHash(size_t leaf_idx) const;

    /**
     * @brief Построение доказательства включения (Merkle proof) для заданного листа.
     *
     * @param leaf_idx Индекс листа (0 .. N-1).
     * @return Вектор пар (хеш sibling'а, флаг "sibling является левым").
     *         Флаг true означает, что sibling стоит слева от текущего узла при объединении.
     * @throws std::out_of_range при неверном индексе.
     */
    std::vector<std::pair<HashType, bool>> getProof(size_t leaf_idx) const;

    /**
     * @brief Статический метод проверки доказательства включения.
     *
     * @param leaf_hash   Хеш листа, для которого строилось доказательство.
     * @param proof       Доказательство (вектор пар, полученный от getProof).
     * @param root        Корневой хеш, который должен получиться.
     * @param combiner    Функция объединения, использовавшаяся при построении дерева.
     * @return true, если доказательство корректно (восстановленный корень совпадает с root).
     */
    static bool verifyProof(const HashType& leaf_hash,
        const std::vector<std::pair<HashType, bool>>& proof,
        const HashType& root,
        CombineFunction combiner);

private:
    size_t m_n;                       // высота дерева
    size_t m_N;                       // количество листьев
    std::vector<HashType> m_tree;      // все узлы дерева (индексация как в куче: корень 0, листья с N-1 до 2N-2)
    HashFunction m_leaf_hasher;
    CombineFunction m_combiner;
};

// Включаем файл с реализацией шаблонных методов
#include "MerkleTree.cpp"

#endif // MERKLETREE_H