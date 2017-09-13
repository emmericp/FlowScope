#include <array>
#include <tuple.hpp>
#include <tbb/concurrent_hash_map.h>
#include <nmmintrin.h>

namespace var_hash_map {
    template<typename K>
    struct var_crc_hash {
        var_crc_hash() = default;
        var_crc_hash(const var_crc_hash& h) = default;

        inline bool equal(const K& j, const K& k) const noexcept {
            return j == k;
        }

        /* Specialized hash functions for known array sizes */
        template<typename U = K>
        inline size_t hash(const U& k, typename std::enable_if<std::tuple_size<U>::value == 8>::type* = 0) const noexcept {
            return _mm_crc32_u64(0, *k.data());
        }

        template<typename U = K>
        inline size_t hash(const U& k, typename std::enable_if<std::tuple_size<U>::value == 16>::type* = 0) const noexcept {
            uint64_t hash = 0;
            hash = _mm_crc32_u64(hash, *k.data());
            return _mm_crc32_u64(hash, *(k.data() + 8));
        }

        template<typename U = K>
        inline size_t hash(const U& k, typename std::enable_if<std::tuple_size<U>::value == 32>::type* = 0) const noexcept {
            uint64_t hash = 0;
            hash = _mm_crc32_u64(hash, *k.data());
            hash = _mm_crc32_u64(hash, *(k.data() + 8));
            hash = _mm_crc32_u64(hash, *(k.data() + 16));
            return _mm_crc32_u64(hash, *(k.data() + 24));
        }

        template<typename U = K>
        inline size_t hash(const U& k, typename std::enable_if<std::tuple_size<U>::value == 64>::type* = 0) const noexcept {
            uint64_t hash = 0;
            hash = _mm_crc32_u64(hash, *k.data());
            hash = _mm_crc32_u64(hash, *(k.data() + 8));
            hash = _mm_crc32_u64(hash, *(k.data() + 16));
            hash = _mm_crc32_u64(hash, *(k.data() + 24));
            hash = _mm_crc32_u64(hash, *(k.data() + 32));
            hash = _mm_crc32_u64(hash, *(k.data() + 40));
            hash = _mm_crc32_u64(hash, *(k.data() + 48));
            return _mm_crc32_u64(hash, *(k.data() + 56));
        }

        /* Generic version for arrays of any length */
        inline size_t hash(const K& k) const noexcept {
            uint64_t hash = 0;
            for (auto &i: k) {
                hash = _mm_crc32_u8(hash, i);
            }
            return hash;
        }
    };

    template<size_t key_size> using K = std::array<std::uint8_t, key_size>;
    template<size_t value_size> using V = std::array<std::uint8_t, value_size>;
}

extern "C" {
using namespace var_hash_map;

#define MAP_IMPL(key_size, value_size) \
    template class tbb::concurrent_hash_map<K<key_size>, V<value_size>, var_crc_hash<K<key_size>>>; \
    using hmapk##key_size##v##value_size = tbb::concurrent_hash_map<K<key_size>, V<value_size>, var_crc_hash<K<key_size>>>; \
    hmapk##key_size##v##value_size* hmapk##key_size##v##value_size##_create() { \
        return new hmapk##key_size##v##value_size; \
    } \
    void hmapk##key_size##v##value_size##_delete(hmapk##key_size##v##value_size* map) { \
        delete map; \
    } \
    void hmapk##key_size##v##value_size##_clear(hmapk##key_size##v##value_size* map) { \
        map->clear(); \
    } \
    hmapk##key_size##v##value_size::accessor* hmapk##key_size##v##value_size##_new_accessor() { \
        return new hmapk##key_size##v##value_size::accessor; \
    } \
    void hmapk##key_size##v##value_size##_accessor_free(hmapk##key_size##v##value_size::accessor* a) { \
        a->release(); \
        delete a; \
    } \
    void hmapk##key_size##v##value_size##_accessor_release(hmapk##key_size##v##value_size::accessor* a) { \
        a->release(); \
    } \
    bool hmapk##key_size##v##value_size##_access(hmapk##key_size##v##value_size* map, hmapk##key_size##v##value_size::accessor* a, const K<key_size>* tpl) { \
        return map->insert(*a, *tpl); \
    } \
    std::uint8_t* hmapk##key_size##v##value_size##_accessor_get_value(hmapk##key_size##v##value_size::accessor* a) { \
        return (*a)->second.data(); \
    } \
    bool hmapk##key_size##v##value_size##_erase(hmapk##key_size##v##value_size* map, hmapk##key_size##v##value_size::accessor* a) { \
        if (a->empty()) std::terminate();\
        return map->erase(*a); \
    }

#define MAP_VALUES(value_size) \
    MAP_IMPL(8, value_size) \
    MAP_IMPL(16, value_size) \
    MAP_IMPL(32, value_size) \
    MAP_IMPL(64, value_size)

MAP_VALUES(8)
MAP_VALUES(16)
MAP_VALUES(32)
MAP_VALUES(64)
MAP_VALUES(128)

}
