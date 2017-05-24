#include <cstdint>

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
    
    
    struct ipv6_5tuple {
        std::uint8_t  ip_dst[IPV6_ADDR_LEN];
        std::uint8_t  ip_src[IPV6_ADDR_LEN];
        std::uint16_t port_dst;
        std::uint16_t port_src;
        std::uint8_t  proto;
        
        std::uint32_t hash() const { return rte_jhash(this, sizeof(*this), 0); }
    } __attribute__((__packed__));
    static_assert(sizeof(ipv6_5tuple) == 37, "Unexpected IPv6 5-tuple size");
}

extern "C" {
    std::uint32_t ipv4_tuple_hash(const struct flowtracker::ipv4_5tuple* tpl);
    std::uint32_t ipv6_tuple_hash(const struct flowtracker::ipv6_5tuple* tpl);
}
