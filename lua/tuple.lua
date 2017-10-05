local ffi = require "ffi"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip4 = require "proto.ip4"
local ip6 = require "proto.ip6"

local module = {}

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

module.flowKeys = {
    "struct ipv4_5tuple",
    "struct ipv6_5tuple",
}

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

local pflangTemplate = "src host %s src port %i dst host %s dst port %i %s"
function ip4Tuple:getPflang()
    local ip4AddrDst = ffi.new("union ip4_address")
    local ip4AddrSrc = ffi.new("union ip4_address")
    ip4AddrDst:set(self.ip_dst)
    ip4AddrSrc:set(self.ip_src)
    local proto = ""
    if self.proto == ip4.PROTO_UDP then
        proto = "udp"
    elseif self.proto == ip4.PROTO_TCP then
        proto = "tcp"
    else
        proto = tostring(tonumber(self.proto))
    end
    return pflangTemplate:format(ip4AddrSrc:getString(), tonumber(self.port_src), ip4AddrDst:getString(), tonumber(self.port_dst), proto)
end

ip4Tuple.__index = ip4Tuple
ffi.metatype("struct ipv4_5tuple", ip4Tuple)

function module.extractIP5Tuple(buf, keyBuf)
    local ethPkt = pktLib.getEthernetPacket(buf)
    if ethPkt.eth:getType() == eth.TYPE_IP then
        -- actual L4 type doesn't matter
        keyBuf = ffi.cast("struct ipv4_5tuple&", keyBuf)
        local parsedPkt = pktLib.getUdp4Packet(buf)
        keyBuf.ip_dst = parsedPkt.ip4:getDst()
        keyBuf.ip_src = parsedPkt.ip4:getSrc()
        local TTL = parsedPkt.ip4:getTTL()
        -- port is always at the same position as UDP
        keyBuf.port_dst = parsedPkt.udp:getDstPort()
        keyBuf.port_src = parsedPkt.udp:getSrcPort()
        local proto = parsedPkt.ip4:getProtocol()
        if proto == ip4.PROTO_UDP or proto == ip4.PROTO_TCP or proto == ip4.PROTO_SCTP then
            keyBuf.proto = proto
            return true, 1
        end
    elseif ethPkt.eth:getType() == eth.TYPE_IP6 then
        -- FIXME: Add IPv6
    end
    return false
end

return module
