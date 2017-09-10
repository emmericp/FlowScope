#include <array>
#include <tuple.hpp>
#include <tbb/concurrent_hash_map.h>
#include <smmintrin.h>

namespace var_hash_map {
    struct v4_crc_hash {
        v4_crc_hash() = default;
        v4_crc_hash(const v4_crc_hash& h) = default;

        inline bool equal(const flowtracker::ipv4_5tuple& j, const flowtracker::ipv4_5tuple& k) const noexcept {
            return j.ip_dst == k.ip_dst &&
                   j.ip_src == k.ip_src &&
                   j.port_dst == k.port_dst &&
                   j.port_src == k.port_src &&
                   j.proto == k.proto;
        }

        inline std::size_t hash(const flowtracker::ipv4_5tuple& k) const noexcept {
            uint32_t hash = 0;
            hash = _mm_crc32_u32(hash, k.ip_dst);
            hash = _mm_crc32_u32(hash, k.ip_src);
            hash = _mm_crc32_u16(hash, k.port_dst);
            hash = _mm_crc32_u16(hash, k.port_src);
            hash = _mm_crc32_u16(hash, k.proto);
            return hash;
        }
    };

    using K = flowtracker::ipv4_5tuple;
    template<size_t value_size> using V = std::array<std::uint8_t, value_size>;
}

extern "C" {
using namespace var_hash_map;

#define MAP_IMPL(size) \
    template class tbb::concurrent_hash_map<K, V<size>, v4_crc_hash>; \
    using hmap##size = tbb::concurrent_hash_map<K, V<size>, v4_crc_hash>; \
    hmap##size* hmap##size##_create() { \
        return new hmap##size; \
    } \
    void hmap##size##_delete(hmap##size* map) { \
        delete map; \
    } \
    void hmap##size##_clear(hmap##size* map) { \
        map->clear(); \
    } \
    hmap##size::accessor* hmap##size##_new_accessor() { \
        return new hmap##size::accessor; \
    } \
    void hmap##size##_accessor_free(hmap##size::accessor* a) { \
        a->release(); \
        delete a; \
    } \
    void hmap##size##_accessor_release(hmap##size::accessor* a) { \
        a->release(); \
    } \
    bool hmap##size##_access(hmap##size* map, hmap##size::accessor* a, const K* tpl) { \
        return map->insert(*a, *tpl); \
    } \
    std::uint8_t* hmap##size##_accessor_get_value(hmap##size::accessor* a) { \
        return (*a)->second.data(); \
    } \
    bool hmap##size##_erase(hmap##size* map, hmap##size::accessor* a) { \
        if (a->empty()) std::terminate();\
        return map->erase(*a); \
    }

MAP_IMPL(8)
MAP_IMPL(16)
MAP_IMPL(32)
MAP_IMPL(64)
MAP_IMPL(128)
}
