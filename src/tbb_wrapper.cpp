#include <tbb/concurrent_hash_map.h>
#include <tuple.hpp>
#include <rte_jhash.h>
#include <chrono>
#include <x86intrin.h>

namespace tbb_wrapper {
    template<typename Key>
    struct my_hash {
        my_hash() = default;
        my_hash(const my_hash& h) = default;
        
        bool equal(const Key& j, const Key& k) const {
            return j == k;
        }
        
        static std::size_t hash(const Key& k) {
            return rte_jhash(&k, sizeof(Key), 0);
        }
        static_assert(sizeof(std::size_t) == 8, "size_t not 8 byte!");
    };
    
    struct v4_crc_hash {
        v4_crc_hash() = default;
        v4_crc_hash(const v4_crc_hash& h) = default;
        
        inline bool equal(const flowtracker::ipv4_5tuple& j, const flowtracker::ipv4_5tuple& k) const {
            return j.ip_dst == k.ip_dst &&
                    j.ip_src == k.ip_src &&
                    j.port_dst == k.port_dst &&
                    j.port_src == k.port_src &&
                    j.proto == k.proto;
        }
        
        inline std::size_t hash(const flowtracker::ipv4_5tuple& k) const {
            uint32_t hash = 0;
            hash = _mm_crc32_u32(hash, k.ip_dst);
            hash = _mm_crc32_u32(hash, k.ip_src);
            hash = _mm_crc32_u16(hash, k.port_dst);
            hash = _mm_crc32_u16(hash, k.port_src);
            hash = _mm_crc32_u16(hash, k.proto);
            return hash;
        }
        
        static std::size_t hash_s(const flowtracker::ipv4_5tuple& k) {
            uint32_t hash = 0;
            hash = _mm_crc32_u32(hash, k.ip_dst);
            hash = _mm_crc32_u32(hash, k.ip_src);
            hash = _mm_crc32_u16(hash, k.port_dst);
            hash = _mm_crc32_u16(hash, k.port_src);
            hash = _mm_crc32_u16(hash, k.proto);
            return hash;
        }
    };
}

extern "C" {
    using D = flowtracker::ttl_flow_data;
    using v4tpl = flowtracker::ipv4_5tuple;
    using v6tpl = flowtracker::ipv6_5tuple;
    using hash_v4 = tbb_wrapper::my_hash<v4tpl>;
    using hash_v6 = tbb_wrapper::my_hash<v6tpl>;
//     using tbb_map_v4 = tbb::concurrent_hash_map<v4tpl, D, hash_v4>;
    using tbb_map_v4 = tbb::concurrent_hash_map<v4tpl, D, tbb_wrapper::v4_crc_hash>;
    using tbb_map_v6 = tbb::concurrent_hash_map<v6tpl, D, hash_v6>;
    
    tbb_map_v4* tbb_map_create_v4(std::size_t pre_alloc) {
        return new tbb_map_v4(pre_alloc);
    }
    
    void tbb_map_delete_v4(tbb_map_v4* map) {
        delete map;
    }
    
    void tbb_map_clear_v4(tbb_map_v4* map) {
        map->clear();
    }
    
    const D* tbb_map_get_v4(tbb_map_v4* map, const v4tpl* tpl) {
        tbb_map_v4::const_accessor a;
        if (map->find(a, *tpl)) {
            return &a->second;
        } else {
            return nullptr;
        }
    }
    
    bool tbb_map_exists_v4(tbb_map_v4* map, const v4tpl* tpl) {
        tbb_map_v4::const_accessor a;
        return map->find(a, *tpl);
    }
    
    // Returns the average TTL if it differs more than epsilon from ttl.
    // Returns 0 if no flow for tpl exists or the tll is within bounds.
    std::uint16_t tbb_map_check_and_update_ttl_v4(tbb_map_v4* map, const v4tpl* tpl, const std::uint16_t ttl, const std::uint16_t epsilon) {
#if 0
        auto entry = std::chrono::steady_clock::now();
        tbb_map_v4::accessor a;

        auto n = 0ull - 1;
        int r = 0;
        auto pre_find = std::chrono::steady_clock::now();
        auto found = map->find(a, *tpl);
        auto post_find = std::chrono::steady_clock::now();
        if (found) {
            r = 1;
            a->second.running_sum += ttl;
            a->second.packets++;
            a.release();
        }
        std::printf("C++ find %lf ms -> %i, %zu, n %llu\n", std::chrono::duration<double, std::milli>(post_find - pre_find).count(), found, tbb_wrapper::v4_hash::hash_s(*tpl), n);
        if (!found) {
            tbb_map_v4::accessor b;
            r = 2;
            auto pre_insert = std::chrono::steady_clock::now();
            if (!map->insert(b, *tpl)) {
                r = 3;
            }
            auto post_insert = std::chrono::steady_clock::now();
            b->second.running_sum += ttl;
            b->second.packets++;
            n = b->second.packets;
            std::printf("C++ insert %lf ms -> %i, %zu, n %llu\n", std::chrono::duration<double, std::milli>(post_insert - pre_insert).count(), r, tbb_wrapper::v4_hash::hash_s(*tpl), n);
        }
        std::printf("C++ map size %zu\n", map->size());
        return false;
#endif
#if 1
        tbb_map_v4::accessor a;
        if (map->insert(a, *tpl)) {
            // New flow set inital data and return
            a->second.running_sum = ttl;
            a->second.packets = 1;
            a.release();
            return 0;
        }
        auto avrg = a->second.get_and_update_TTL(ttl);
        a.release();
        if (ttl > avrg + epsilon || ttl < avrg - epsilon)
            return avrg;
        else
            return 0;
#else
        return 0;
#endif
    }
}
