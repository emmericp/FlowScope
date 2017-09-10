local ffi = require "ffi"
local ip4 = require "proto.ip4"

ffi.cdef [[
    struct ipv4_5tuple {
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
    } __attribute__((__packed__));

    struct ipv6_5tuple {
        uint8_t  ip_dst[16];
        uint8_t  ip_src[16];
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
    } __attribute__((__packed__));
]]

local ip4Tuple = {}
function ip4Tuple:__tostring()
    local template = "ipv4_5tuple{ip_dst: %s, ip_src: %s, port_dst: %i, port_src: %i, proto: %s}"
    local ip4AddrDst = ffi.new("union ip4_address")
    local ip4AddrSrc = ffi.new("union ip4_address")
    ip4AddrDst:set(self.ip_dst)
    ip4AddrSrc:set(self.ip_src)
    -- L4 Protocol
    local proto = ""
    if self.proto == ip4.PROTO_UDP then
        proto = "udp"
    elseif self.proto == ip4.PROTO_TCP then
        proto = "tcp"
    else
        proto = tonumber(self.proto)
    end
    return template:format(ip4AddrDst:getString(), ip4AddrSrc:getString(), tonumber(self.port_dst), tonumber(self.port_src), proto)
end
ffi.metatype("struct ipv4_5tuple", ip4Tuple)
