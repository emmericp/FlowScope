#include <tuple.hpp> 

extern "C" {
    std::uint32_t ipv4_5tuple_hash(const struct flowtracker::ipv4_5tuple* tpl) {
        return tpl->hash();
    }
    std::uint32_t ipv6_5tuple_hash(const struct flowtracker::ipv6_5tuple* tpl) {
        return tpl->hash();
    }
    
    std::uint16_t get_average_TTL(std::uint64_t val) {
        auto sum = val >> 28;
        auto packets = val & ((1ull<<28) - 1);
        return sum/packets;
    }
    
    std::uint64_t update_TTL(std::uint64_t val, std::uint16_t new_ttl) {
        val += (static_cast<uint64_t>(new_ttl)<<28);
        val += 1;
        return val;
    }
}
