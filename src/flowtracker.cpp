#include <tuple.hpp>

#include <cstdint>
#include <vector>

#include <scoped_allocator>
#include <rte_allocator.hpp>

#include <rte_common.h>
#include <rte_config.h>
#include <rte_lcore.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_malloc.h>

template<typename T> using alloc = std::scoped_allocator_adaptor<rte_allocator<T>>;

namespace flowtracker {
    constexpr std::size_t batch_size = 64;
    static_assert(batch_size <= RTE_HASH_LOOKUP_BULK_MAX, "batch size too large");
    
    template<typename T>
    struct flowtracker {
        explicit flowtracker(const std::uint32_t max_flows = 1024) :
                ipv4_flowdata(std::vector<T>(max_flows)),
                //ipv4_flowdata(std::vector<T, alloc<T>>(max_flows)),
                ipv6_flowdata(std::vector<T>(max_flows)) {
            rte_hash_parameters params = {};
            params.entries = max_flows;
            params.key_len = sizeof(ipv4_5tuple);
            params.hash_func = rte_jhash;
            params.hash_func_init_val = 0;
            params.socket_id = rte_socket_id();
            params.name = "ipv4_flow_map";
            params.extra_flag |= (RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD);
            ipv4_map = rte_hash_create(&params);
            if(ipv4_map == NULL)
                rte_panic("Could not create IPv4 flow hash map, errno = %d (%s)\n", rte_errno, rte_strerror(rte_errno));
            params.key_len = sizeof(ipv6_5tuple);
            params.name = "ipv6_flow_map";
            ipv6_map = rte_hash_create(&params);
            if(ipv6_map == NULL)
                rte_panic("Could not create IPv6 flow hash map, errno = %d (%s)\n", rte_errno, rte_strerror(rte_errno));
        }
        
        ~flowtracker() {
            rte_hash_free(const_cast<rte_hash*>(ipv4_map));
            rte_hash_free(const_cast<rte_hash*>(ipv6_map));
        }
        
        std::int32_t add_flow(const ipv4_5tuple& flow_tuple, const T* flow_data) {
            std::int32_t ret = rte_hash_add_key(this->ipv4_map, &flow_tuple);
            if (ret < 0)
                return ret;
            this->ipv4_flowdata[ret] = *flow_data;
            return ret;
        }
        
        std::int32_t add_flow(const ipv6_5tuple& flow_tuple, const T* flow_data) {
            std::int32_t ret = rte_hash_add_key(this->ipv6_map, &flow_tuple);
            if (ret < 0)
                return ret;
            this->ipv6_flowdata[ret] = *flow_data;
            return ret;
        }
        
        T* get_flow_data(const ipv4_5tuple& flow_tuple) {
            std::int32_t ret = rte_hash_lookup(this->ipv4_map, &flow_tuple);
            if (ret < 0)
                return NULL;
            return &this->ipv4_flowdata[ret];
        }
        
        T* get_flow_data(const ipv6_5tuple& flow_tuple) {
            std::int32_t ret = rte_hash_lookup(this->ipv6_map, &flow_tuple);
            if (ret < 0)
                return NULL;
            return &this->ipv6_flowdata[ret];
        }
        
        int get_flow_data_bulk(const void* keys[], std::uint32_t num_keys, T* data[]) {
            std::int32_t positions[num_keys] = {};
            int ret = rte_hash_lookup_bulk(this->ipv4_map, reinterpret_cast<const void**>(keys), num_keys, positions);
            if (ret != 0) {
                return ret;
            }
            for (std::uint32_t i = 0; i < num_keys; ++i) {
                if (positions[i] > 0)
                    data[i] = &this->ipv4_flowdata[positions[i]];
                else
                    data[i] = NULL;
            }
            return 0;
        }
        
        // FIXME: return flowdata, not lookup results
        int get_flow_data_bulk(const ipv6_5tuple** keys, std::uint32_t num_keys, std::int32_t* positions) {
            return rte_hash_lookup_bulk(this->ipv4_map, reinterpret_cast<const void**>(keys), num_keys, positions);
        }
        
        std::int32_t remove_flow(const ipv4_5tuple& flow_tuple) {
            return rte_hash_del_key(this->ipv4_map, &flow_tuple);
        }
        
        std::int32_t remove_flow(const ipv6_5tuple& flow_tuple) {
            return rte_hash_del_key(this->ipv6_map, &flow_tuple);
        }
        
        
    private:
        const struct rte_hash* ipv4_map;
        const struct rte_hash* ipv6_map;
        std::vector<T> ipv4_flowdata;
        //std::vector<T, alloc<T>> ipv4_flowdata;
        std::vector<T> ipv6_flowdata;
    };
}



extern "C" {
    // Copied from QQ.hpp
    struct packet_header {  
        std::uint64_t timestamp:48;  //!< Stores a timestamp. Unit is microseconds.
        std::uint64_t vlan:12;       //!< Field to store the VLAN tag. Prevents messy Ethernet header.
        std::uint16_t len;           //!< Holds the length of the data array.
        std::uint8_t data[];         //!< Flexible array member. Valid since C99, not really in C++.
    } __attribute__((__packed__));
    
    struct foo_flow_data {
        std::uint64_t start_ts;
        std::uint64_t end_ts;
        std::uint8_t observed_ttl;
    } __attribute__((__packed__));
    
    struct ttl_flow_data {
        std::uint64_t rolling_sum;
        std::uint64_t packet_counter;
    } __attribute__((__packed__));
    
    using D = ttl_flow_data;
    using tracker = flowtracker::flowtracker<D>;
    using v4tpl = flowtracker::ipv4_5tuple;
    using v6tpl = flowtracker::ipv6_5tuple;
    
    tracker* flowtracker_create(std::uint32_t max_flows) {
        void* temp = rte_malloc(NULL, sizeof(tracker), 0);
        if (temp == NULL)
            rte_panic("Unable to allocate memory for flowtracker\n");
#if 0
        auto* tr = new(temp) tracker(max_flows);
        printf("new()\n");
        return tr;
#endif
        return new(temp) tracker(max_flows);
    }
    
    void flowtracker_delete(tracker* tr) {
        rte_free(tr);
    }
    
    /*
    int32_t flowtracker_add_flow_v4(tracker* tr, uint32_t ip_src, uint16_t port_src,
                                    uint32_t ip_dst, uint16_t port_dst, uint8_t proto,
                                    const D* flow_data) {
        flowtracker::ipv4_5tuple tpl {
            ip_dst, ip_src, port_dst, port_src, proto
        };
#ifdef DNDEBUG
        return tr->add_flow(tpl, flow_data);
#else
        int ret = tr->add_flow(tpl, flow_data);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Unable to add key to ipv4_map: %d = %s\n", ret, rte_strerror(-ret));
        return ret;
#endif
    }
    */
    
    std::int32_t flowtracker_add_flow_v4(tracker* tr, const v4tpl* const tpl, const D* flow_data) {
        return tr->add_flow(*tpl, flow_data);
    }
    
    std::int32_t flowtracker_add_flow_v6(tracker* tr, const v6tpl* const tpl, const D* flow_data) {
        return tr->add_flow(*tpl, flow_data);
    }
    
    std::int32_t flowtracker_remove_flow_v4(tracker* tr, const v4tpl* const tpl) {
        return tr->remove_flow(*tpl);
    }
    
    std::int32_t flowtracker_remove_flow_v6(tracker* tr, const v6tpl* const tpl) {
        return tr->remove_flow(*tpl);
    }
    
    D* flowtracker_get_flow_data_v4(tracker* tr, const v4tpl* const tpl) {
        return tr->get_flow_data(*tpl);
    }
    
    D* flowtracker_get_flow_data_v6(tracker* tr, const v6tpl* const tpl) {
        return tr->get_flow_data(*tpl);
    }
    
    int flowtracker_get_flow_data_bulk_v4(tracker* tr, const void* keys[], std::uint32_t num_keys, D* data[]) {
        return tr->get_flow_data_bulk(keys, num_keys, data);
    }
    
    void analyze(tracker* tr, const packet_header* const pkt_hdr);
    
    void analyze_v4(tracker* tr, std::uint64_t ts, const flowtracker::ipv4_5tuple* const tpl, const std::uint8_t ttl);
    
    void analyze_v6(tracker* tr, std::uint64_t ts, const flowtracker::ipv6_5tuple* const tpl, const std::uint8_t ttl);
    
    
    /* low-level rte_hash wrapper */
    
    struct rte_hash* rte_hash_create_v4(std::uint32_t max_flows, const char* name) {
        rte_hash_parameters params = {};
        params.entries = max_flows;
        params.key_len = sizeof(flowtracker::ipv4_5tuple);
        params.hash_func = rte_jhash;
        params.hash_func_init_val = 0;
        params.socket_id = rte_socket_id();
        params.name = name;
        params.extra_flag |= (RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD);
        auto ipv4_map = rte_hash_create(&params);
        if(ipv4_map == NULL)
            rte_panic("Could not create IPv4 flow hash map %s, %d = %s\n", name, rte_errno, rte_strerror(rte_errno));
        
        return ipv4_map;
    }
}
