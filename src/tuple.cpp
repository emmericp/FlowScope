#include <tuple.hpp> 

extern "C" {
    std::uint32_t ipv4_tuple_hash(const struct flowtracker::ipv4_5tuple* tpl) {
        return tpl->hash();
    }
    std::uint32_t ipv6_tuple_hash(const struct flowtracker::ipv6_5tuple* tpl) {
        return tpl->hash();
    }
}
