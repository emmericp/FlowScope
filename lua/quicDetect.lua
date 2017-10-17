local ffi = require "ffi"
local lm = require "libmoon"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip4 = require "proto.ip4"
local ip6 = require "proto.ip6"
local tuple = require "tuple"
local log = require "log"
local hmap = require "hmap"
local namespace = require "namespaces"
local band = bit.band

ffi.cdef [[
    int memcmp(const void *s1, const void *s2, size_t n);
]]

local module = {}

-- A protocol detector/tracker for quic as of RFC version 00

ffi.cdef [[
    struct conn_id {
        uint64_t id;
    };
]]
module.flowKeys = {
    "struct ipv4_5tuple",
    --"struct conn_id"
}

ffi.cdef [[
    struct quic_flow_state {
        uint64_t last_seen;
        uint64_t first_seen;
        uint64_t connection_id;
        uint16_t initial_port;
        uint32_t initial_ip;
        uint8_t tracked;
    };
]]
module.stateType = "struct quic_flow_state"
module.defaultState = {}

module.mode = "qq"


local shared = namespace:get()
local IDtable = nil
local acc = nil

shared.lock(function()
if shared.tbl == nil then
    shared.tbl = hmap.createHashmap(8, ffi.sizeof("struct ipv4_5tuple"))
end
IDtable = shared.tbl
acc = IDtable.newAccessor()
ffi.gc(acc, acc.free)
end)


function module.extractFlowKey(buf, keyBuf)
    local success, idx = tuple.extractIP5Tuple(buf, keyBuf) -- Reuse 5-tuple extractor
    if success and idx == 1 then
        keyBuf = ffi.cast("struct ipv4_5tuple&", keyBuf)
        if keyBuf.proto == ip4.PROTO_UDP and (keyBuf.port_a == 443 or keyBuf.port_b == 443) then
            return success, idx
        end
    end
    return false
end

function module.handlePacket(flowKey, state, buf, isFirstPacket)
    local t = buf:getTimestamp() * 10^6
    state.last_seen = t
    if isFirstPacket then
        state.first_seen = t
    end
    print(flowKey)

    local udpPkt = pktLib.getUdp4Packet(buf)
    --local quicFrame = udpPkt.payload.uint8
    local flags = udpPkt.payload.uint8[0]
    if band(flags, 0x08) ~= 0 then
        local dump = false
        local cid = ffi.cast("uint64_t*", udpPkt.payload.uint8 + 1)[0]
        print("has CID!", cid)
        if not isFirstPacket and cid ~= state.connection_id then
            log:warn("Connection ID changed for flow %s: %s -> %s", flowKey, tonumber(state.connection_id), tonumber(cid))
        end
        state.connection_id = cid
        -- Check ID -> 5-Tuple map
        local keyBuf = ffi.new("uint8_t[?]", IDtable.keyBufSize())
        ffi.copy(keyBuf, udpPkt.payload.uint8 + 1, 8)
        local new = IDtable:access(acc, keyBuf)
        local tpl = ffi.cast("struct ipv4_5tuple&", acc:get())
        if new then
            ffi.copy(tpl, flowKey, ffi.sizeof("struct ipv4_5tuple"))
        end
        if ffi.C.memcmp(tpl, flowKey, ffi.sizeof(flowKey)) ~= 0 then
            log:warn("Connection migration of id %i from %s to %s", tonumber(cid), tpl, flowKey)
            state.tracked = 1
            dump = true
        end
        acc:release()
        return dump
    else
        print("no CID!")
        if isFirstPacket then
            log:warn("First packet in flow and no connection ID!")
        end
    end
    return true
end


-- #### Checker configuration ####

module.checkInterval = 5

function module.checkExpiry(flowKey, state, checkState)
    local t = lm.getTime() * 10^6
    if state.tracked == 1 and tonumber(state.last_seen) + 30 * 10^6 < t then
        return true, tonumber(state.last_seen) / 10^6
    end
    return false
end

-- #### Dumper configuration ####
-- Only applicable if mode is set to "qq"

module.maxDumperRules = 100

-- Function that returns a packet filter string in pcap syntax from a given flow key
function module.buildPacketFilter(flowKey)
    return flowKey:getPflang()
end

return module
