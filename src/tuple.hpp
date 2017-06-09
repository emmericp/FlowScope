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

    bool operator==(const flowtracker::ipv4_5tuple& lhs, const flowtracker::ipv4_5tuple& rhs);
    
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
        
        inline std::uint16_t get_average_TTL() const noexcept {
            return running_sum / packets;
        }
        
        inline void update_TTL(std::uint16_t observed_ttl) {
            running_sum += observed_ttl;
            ++packets;
        }
        
        inline std::uint16_t get_and_update_TTL(std::uint16_t ttl) {
            auto prev = get_average_TTL();
            update_TTL(ttl);
            return prev;
        }
    };
}

extern "C" {
    std::uint32_t ipv4_5tuple_hash(const struct flowtracker::ipv4_5tuple* tpl);
    std::uint32_t ipv6_5tuple_hash(const struct flowtracker::ipv6_5tuple* tpl);
    
    
    // Since Leapfrog only allows ints or pointers as values, we try to squeze
    // as much as possible out of a uint64_t.
    // To store the average TTL of a flow, the running sum of all
    // observed TTL values and the number of observed values are needed.
    // Assuming an average TTL value of 128 = 2^7, the int storing the TTL sum
    // must be 2^7 times larger than the int counting the packets.
    // This also prevents generationo of the values 0 and 1, which are reserved by Leapfrog.
    // Thus the uint64_t is split as follows:
    struct ttl_uint64_t {
        std::uint64_t running_sum:36; // max 68719476736
        std::uint64_t     packets:28; // max 268435456
    };
    static_assert(sizeof(ttl_uint64_t) == sizeof(std::uint64_t), "Unexpected TTL in uint64_t size");
    
    std::uint16_t get_average_TTL(std::uint64_t val);
    std::uint64_t update_TTL(std::uint64_t val, std::uint16_t new_ttl);

}
