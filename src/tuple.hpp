#include <cstdint>
#include <atomic>

#include <rte_jhash.h>

namespace flowtracker {
    constexpr std::uint8_t IPV6_ADDR_LEN = 16;
    
    struct ipv4_5tuple {
        std::uint32_t ip_dst;
        std::uint32_t ip_src;
        std::uint16_t port_dst;
        std::uint16_t port_src;
        std::uint8_t  proto;
        
        std::uint32_t hash() const { return rte_jhash(this, sizeof(*this), 0); }
    } __attribute__((__packed__));
    static_assert(sizeof(ipv4_5tuple) == 13, "Unexpected IPv4 5-tuple size");

    bool operator==(const flowtracker::ipv4_5tuple& lhs, const flowtracker::ipv4_5tuple& rhs) noexcept;
    
    struct ipv6_5tuple {
        std::uint8_t  ip_dst[IPV6_ADDR_LEN];
        std::uint8_t  ip_src[IPV6_ADDR_LEN];
        std::uint16_t port_dst;
        std::uint16_t port_src;
        std::uint8_t  proto;
        
        std::uint32_t hash() const { return rte_jhash(this, sizeof(*this), 0); }
    } __attribute__((__packed__));
    static_assert(sizeof(ipv6_5tuple) == 37, "Unexpected IPv6 5-tuple size");
    
    struct ttl_flow_data {
        std::uint64_t running_sum;  // Sum of all seen TTL values
        std::uint64_t packets;      // Number of observed TTL values
        bool tracked;
        
        inline std::uint16_t get_average_TTL() const noexcept {
            return running_sum / packets;
        }
        
        inline void update_TTL(std::uint16_t observed_ttl) noexcept {
            running_sum += observed_ttl;
            ++packets;
        }
        
        inline std::uint16_t get_and_update_TTL(std::uint16_t ttl) noexcept {
            auto prev = get_average_TTL();
            update_TTL(ttl);
            return prev;
        }
        
        inline std::uint16_t update_and_get_TTL(std::uint16_t ttl) noexcept {
            update_TTL(ttl);
            return get_average_TTL();
        }
    };
}

extern "C" {
    std::uint32_t ipv4_5tuple_hash(const struct flowtracker::ipv4_5tuple* tpl);
    std::uint32_t ipv6_5tuple_hash(const struct flowtracker::ipv6_5tuple* tpl);
    
    /* Bindings for ttl_flow_data functions */
    std::uint16_t ttl_check_and_update_TTL(flowtracker::ttl_flow_data *data, const std::uint16_t observed_ttl, const std::uint16_t epsilon);
    
    std::uint16_t ttl_update_and_check_TTL(flowtracker::ttl_flow_data *data, const std::uint16_t observed_ttl, const std::uint16_t epsilon);
}
