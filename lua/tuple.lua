local ffi = require "ffi"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip4 = require "proto.ip4"
local ip6 = require "proto.ip6"

local module = {}

ffi.cdef [[
    struct ipv4_5tuple {
        union ip4_address ip_a;
        union ip4_address ip_b;
        uint16_t port_a;
        uint16_t port_b;
        uint8_t  proto;
    } __attribute__((__packed__));

    struct ipv6_5tuple {
        union ip6_address ip_a;
        union ip6_address ip_b;
        uint16_t port_a;
        uint16_t port_b;
        uint8_t  proto;
    } __attribute__((__packed__));
]]

assert(ffi.sizeof("struct ipv4_5tuple") == 13)

module.flowKeys = {
    "struct ipv4_5tuple",
    "struct ipv6_5tuple",
}

local ip4Tuple = {}

local stringTemplate = "ipv4_5tuple{ip_a: %s, ip_b: %s, port_a: %i, port_b: %i, proto: %s}"
function ip4Tuple:__tostring()
    local proto
    if self.proto == ip4.PROTO_UDP then
        proto = "udp"
    elseif self.proto == ip4.PROTO_TCP then
        proto = "tcp"
    else
        proto = tostring(tonumber(self.proto))
    end
    return stringTemplate:format(self.ip_a:getString(), self.ip_b:getString(), self.port_a, self.port_b, proto)
end

-- TODO: Rearrange expressions to generate better lua code in pflua
local pflangTemplateUni = "src host %s src port %i dst host %s dst port %i %s"
function ip4Tuple:getPflangUni()
    local proto
    if self.proto == ip4.PROTO_UDP then
        proto = "udp"
    elseif self.proto == ip4.PROTO_TCP then
        proto = "tcp"
    else
        proto = tostring(tonumber(self.proto))
    end
    return pflangTemplateUni:format(self.ip_a:getString(), self.port_a, self.ip_b:getString(), self.port_b, proto)
end

local pflangTemplate = "ip proto %i and host %s and host %s and port %i and port %i"
function ip4Tuple:getPflang()
    return pflangTemplate:format(self.proto, self.ip_a:getString(), self.ip_b:getString(), self.port_a, self.port_b)
end

ip4Tuple.__index = ip4Tuple
ffi.metatype("struct ipv4_5tuple", ip4Tuple)

local ip6Tuple = {}

local pflangTemplate6 = "ip6 proto %i and host %s and host %s and port %i and port %i"
function ip6Tuple:getPflang()
    return pflangTemplate6:format(self.proto, self.ip_a:getString(), self.ip_b:getString(), self.port_a, self.port_b)
end

ip6Tuple.__index = ip6Tuple
ffi.metatype("struct ipv6_5tuple", ip6Tuple)

-- Uni-directional
function module.extractIP5TupleUni(buf, keyBuf)
    local ethPkt = pktLib.getEthernetPacket(buf)
    if ethPkt.eth:getType() == eth.TYPE_IP then
        -- actual L4 type doesn't matter
        keyBuf = ffi.cast("struct ipv4_5tuple&", keyBuf)
        local parsedPkt = pktLib.getUdp4Packet(buf)
        -- IPs are copied in network byte order so that the getString() functions work
        keyBuf.ip_a.uint32 = parsedPkt.ip4.src.uint32
        keyBuf.ip_b.uint32 = parsedPkt.ip4.dst.uint32
        -- port is always at the same position as UDP
        keyBuf.port_a = parsedPkt.udp:getSrcPort()
        keyBuf.port_b = parsedPkt.udp:getDstPort()
        local proto = parsedPkt.ip4:getProtocol()
        if proto == ip4.PROTO_UDP or proto == ip4.PROTO_TCP or proto == ip4.PROTO_SCTP then
            keyBuf.proto = proto
            return true, 1
        end
    elseif ethPkt.eth:getType() == eth.TYPE_IP6 then
        keyBuf = ffi.cast("struct ipv6_5tuple&", keyBuf)
        local parsedPkt = pktLib.getUdp6Packet(buf)
        keyBuf.ip_a.uint64[0] = parsedPkt.ip6.src.uint64[0]
        keyBuf.ip_a.uint64[1] = parsedPkt.ip6.src.uint64[1]
        keyBuf.ip_b.uint64[0] = parsedPkt.ip6.dst.uint64[0]
        keyBuf.ip_b.uint64[1] = parsedPkt.ip6.dst.uint64[1]
        keyBuf.port_a = parsedPkt.udp:getSrcPort()
        keyBuf.port_b = parsedPkt.udp:getDstPort()
        local proto = parsedPkt.ip6:getProtocol()
        if proto == ip6.PROTO_UDP or proto == ip6.PROTO_TCP or proto == ip6.PROTO_SCTP then
            keyBuf.proto = proto
            return true, 2
        end
    end
    return false
end

-- Bi-directional
function module.extractIP5Tuple(buf, keyBuf)
    local ok, idx = module.extractIP5TupleUni(buf, keyBuf)
    if ok and idx == 1 then
        keyBuf = ffi.cast("struct ipv4_5tuple&", keyBuf)
        if keyBuf.ip_a.uint32 > keyBuf.ip_b.uint32 then
            keyBuf.ip_a.uint32, keyBuf.ip_b.uint32 = keyBuf.ip_b.uint32, keyBuf.ip_a.uint32
            keyBuf.port_a, keyBuf.port_b = keyBuf.port_b, keyBuf.port_a
        end
        return ok, idx
    end
    if ok and idx == 2 then
        keyBuf = ffi.cast("struct ipv6_5tuple&", keyBuf)
        if keyBuf.ip_a < keyBuf.ip_b then
            keyBuf.ip_a, keyBuf.ip_b = keyBuf.ip_b:get(), keyBuf.ip_a:get()
            keyBuf.port_a, keyBuf.port_b = keyBuf.port_b, keyBuf.port_a
        end
        return ok, idx
    end
    return false
end

return module
