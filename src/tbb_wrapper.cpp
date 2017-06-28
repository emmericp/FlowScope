#include <tbb/concurrent_hash_map.h>
#include <tuple.hpp>
#include <rte_jhash.h>
#include <chrono>
#include <x86intrin.h>
#include <thread>
#include <vector>

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
    
    // CRC is ~5-10% faster than jhash
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
    
    /* TBB hash_map with build-in swapping */
    using D = flowtracker::ttl_flow_data;
    using v4tpl = flowtracker::ipv4_5tuple;
    using v6tpl = flowtracker::ipv6_5tuple;
    using hash_v4 = tbb_wrapper::my_hash<v4tpl>;
    using hash_v6 = tbb_wrapper::my_hash<v6tpl>;
    using tbb_map_v4 = tbb::concurrent_hash_map<v4tpl, D, tbb_wrapper::v4_crc_hash>;
    using tbb_map_v6 = tbb::concurrent_hash_map<v6tpl, D, hash_v6>;
    
    /*
     * Keep interface generic, split value access and modification
     * Using flowscope with own datatype should be possible with only changing D
     */
    
    struct tbb_tracker {
        tbb_tracker(std::size_t pre_alloc) {
            last_swap = std::chrono::steady_clock::now();
            current4 = new tbb_map_v4(pre_alloc);
            old4 = new tbb_map_v4(pre_alloc);
        }
        ~tbb_tracker() {
            delete current4;
            delete old4;
        }
        
        std::size_t iterative_swapper(v4tpl* buf, std::size_t sz) {
            /*
             * Idea:
             *  1. Wait 30 sec since last swap
             *  2. old is not used anymore, safe to iterate over
             *  3. Iterate over old:
             *      - Check if 5-tuple still exists in current
             *      - If not, issue rule deletion to dumpers
             *      - If yes, ignore
             *  4. Clear old
             *  5. Swap old and current
             * 
             * Analyzers seeing an empty map should be not problem: Every TTL change is an anomaly,
             * base value does not matter.
             * Also solves TTL counter overflow problem. Maybe even switch back to smaller uint32_t.
             * 
             * Maybe make the swapper a member function so that it can be run in a shared task.
             */
            std::printf("[Swapper]: Entering\n");
            std::this_thread::sleep_until(last_swap + std::chrono::seconds(120));
            std::printf("[Swapper]: 30 sec over\n");
            std::printf("[Swapper]: Entries in old: %lu\n", old4->size());
            auto cur = current4.load();
            std::size_t i = 0;
            std::uint64_t purge_counter = 0;
            std::uint64_t expire_counter = 0;
            for (auto it = old4->begin(); it != old4->end(); ++it) {
                tbb_map_v4::const_accessor a;
                if (!cur->find(a, it->first)) {
                    // Mark for deletion, 
                    if (i >= sz) {
                        break;
                    }
                    if (it->second.tracked) {
                        buf[i++] = it->first;
                        ++purge_counter;
                    }
                    ++expire_counter;
                }
            }
            old4->clear();
            tbb_map_v4 *temp = current4.exchange(old4);
            old4 = temp;
            last_swap = std::chrono::steady_clock::now();
            std::printf("[Swapper]: Done. Expired %lu/%lu [tracked/total]\n", purge_counter, expire_counter);
            return i;
        }
        
        std::atomic<tbb_map_v4*> current4;
        std::atomic<tbb_map_v6*> current6;
        tbb_map_v4 *old4;
        tbb_map_v6 *old6;
        std::chrono::steady_clock::time_point last_swap;
    private:
        tbb_map_v4::iterator it;
    };
}

extern "C" {
    /* TBB hash_map with build-in swapping */
    using namespace tbb_wrapper;
    tbb_tracker* tbb_tracker_create(std::size_t pre_alloc) {
        return new tbb_tracker(pre_alloc);
    }
    
    void tbb_tracker_clear(tbb_tracker* tr) {
        tr->old4->clear();
        tr->current4.load()->clear();
    }
    
    void tbb_tracker_delete(tbb_tracker* tr) {
        delete tr;
    }
    
    std::size_t tbb_tracker_swapper(tbb_tracker* tr, v4tpl* buf, std::size_t sz) {
        return tr->iterative_swapper(buf, sz);
    }
    
    tbb_map_v4::const_accessor* tbb_tracker_const_access4(tbb_tracker* tr, const v4tpl* tpl) {
        auto a = new tbb_map_v4::const_accessor;
        tr->current4.load()->insert(*a, *tpl);
        return a;
    }
    
    const D* tbb_tracker_const_get4(tbb_map_v4::const_accessor* a) {
        return &(*a)->second;
    }
    
    void tbb_tracker_const_release4(tbb_map_v4::const_accessor* a) {
        a->release();
        delete a;
    }
    
    tbb_map_v4::accessor* tbb_tracker_access4(tbb_tracker* tr, const v4tpl* tpl) {
        auto a = new tbb_map_v4::accessor;
        tr->current4.load()->insert(*a, *tpl);
        return a;
    }
    
    D* tbb_tracker_get4(tbb_map_v4::accessor* a) {
        return &(*a)->second;
    }
    
    void tbb_tracker_free4(tbb_map_v4::accessor* a) {
        a->release();
        delete a;
    }
    
    void tbb_tracker_release4(tbb_map_v4::accessor* a) {
        a->release();
    }
    
    tbb_map_v4::accessor* tbb_tracker_accessor4() {
        return new tbb_map_v4::accessor;
    }
    
    bool tbb_tracker_access42(tbb_tracker* tr, tbb_map_v4::accessor* a,const v4tpl* tpl) {
        tr->current4.load()->insert(*a, *tpl);
        return a;
    }
    
    
    /* Simple TBB hash_map wrapper */
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
