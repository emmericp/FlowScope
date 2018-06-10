#include <array>
#include <tbb/concurrent_hash_map.h>
#include <nmmintrin.h>

namespace var_hash_map {
    /* Secret hash cookie */
    constexpr uint32_t secret = 0xF00BA;

    template<typename K, typename std::enable_if<std::is_pod<K>::value>::type* = nullptr>
    struct var_crc_hash {
        var_crc_hash() = default;
        var_crc_hash(const var_crc_hash& h) = default;

        inline bool equal(const K& j, const K& k) const noexcept {
            return j == k;
        }

        // Safety check
        static_assert(sizeof(K) == K::size, "sizeof(K) != K::size");

        /* Specialized hash functions for known key_buf sizes */
        template<typename U = K>
        inline size_t hash(const U& k, typename std::enable_if<U::size == 8>::type* = 0) const noexcept {
            size_t hash = secret;
            return _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 0));
        }

        template<typename U = K>
        inline size_t hash(const U& k, typename std::enable_if<U::size == 16>::type* = 0) const noexcept {
            size_t hash = secret;
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 0));
            return _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 8));
        }

        template<typename U = K>
        inline size_t hash(const U& k, typename std::enable_if<U::size == 32>::type* = 0) const noexcept {
            size_t hash = secret;
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 0));
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 8));
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 16));
            return _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 24));;
        }

        template<typename U = K>
        inline size_t hash(const U& k, typename std::enable_if<U::size == 64>::type* = 0) const noexcept {
            size_t hash = secret;
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 0));
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 8));
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 16));
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 24));
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 32));
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 40));
            hash = _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 48));
            return _mm_crc32_u64(hash, *reinterpret_cast<const uint64_t*>(k.data + 56));;
        }

        /* Generic version for key_bufs of any length
         * TODO: Maybe do something fancy for size mod 4 = 0
         */
        /*
        inline size_t hash(const K& k) const noexcept {
            uint64_t hash = 0;
            for (size_t i = 0; i < K::size; ++i) {
                hash = _mm_crc32_u8(hash, k.data[i]);
            }
            return hash;
        }
        */
    };

    template<size_t key_size>
    struct key_buf {
        static constexpr size_t size = key_size;
        uint8_t data[key_size];
    } __attribute__((__packed__));

    template<size_t key_size>
    inline bool operator==(const key_buf<key_size>& lhs, const key_buf<key_size>& rhs) noexcept {
        return std::memcmp(lhs.data, rhs.data, key_size) == 0;
    }

    template<size_t key_size> using K = key_buf<key_size>;
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
    bool hmapk##key_size##v##value_size##_access(hmapk##key_size##v##value_size* map, hmapk##key_size##v##value_size::accessor* a, const void* key) { \
        return map->insert(*a, *static_cast<const K<key_size>*>(key)); \
    } \
    std::uint8_t* hmapk##key_size##v##value_size##_accessor_get_value(hmapk##key_size##v##value_size::accessor* a) { \
        return (*a)->second.data(); \
    } \
    bool hmapk##key_size##v##value_size##_erase(hmapk##key_size##v##value_size* map, hmapk##key_size##v##value_size::accessor* a) { \
        if (a->empty()) std::terminate();\
        return map->erase(*a); \
    } \
    bool hmapk##key_size##v##value_size##_find(hmapk##key_size##v##value_size* map, hmapk##key_size##v##value_size::accessor* a, const void* key) { \
        return map->find(*a, *static_cast<const K<key_size>*>(key)); \
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
