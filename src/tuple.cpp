#include <tuple.hpp> 

bool flowtracker::operator==(const flowtracker::ipv4_5tuple& lhs, const flowtracker::ipv4_5tuple& rhs) noexcept {
    return lhs.ip_dst == rhs.ip_dst &&
            lhs.ip_src == rhs.ip_src &&
            lhs.port_dst == rhs.port_dst &&
            lhs.port_src == rhs.port_src &&
            lhs.proto == rhs.proto;
}

extern "C" {    
    std::uint32_t ipv4_5tuple_hash(const struct flowtracker::ipv4_5tuple* tpl) {
        return tpl->hash();
    }
    std::uint32_t ipv6_5tuple_hash(const struct flowtracker::ipv6_5tuple* tpl) {
        return tpl->hash();
    }
    
    std::uint16_t ttl_check_and_update_TTL(flowtracker::ttl_flow_data *data, const std::uint16_t observed_ttl, const std::uint16_t epsilon) {
        auto avrg = data->get_and_update_TTL(observed_ttl);
        if (observed_ttl > avrg + epsilon || observed_ttl < avrg - epsilon)
            return avrg;
        else
            return 0;
    }
    
    std::uint16_t ttl_update_and_check_TTL(flowtracker::ttl_flow_data *data, const std::uint16_t observed_ttl, const std::uint16_t epsilon) {
        auto avrg = data->update_and_get_TTL(observed_ttl);
        if (observed_ttl > avrg + epsilon || observed_ttl < avrg - epsilon)
            return avrg;
        else
            return 0;
    }
}
