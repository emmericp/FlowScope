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

-- A protocol detector/tracker for quic as of RFC version 01
-- https://tools.ietf.org/html/draft-ietf-quic-transport-01

ffi.cdef [[
    int memcmp(const void *s1, const void *s2, size_t n);
]]

local module = {}

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
        uint8_t cid_set;
        uint8_t tracked;
    };
]]
module.stateType = "struct quic_flow_state"
module.defaultState = {}

module.mode = "qq"


local shared = namespace:get()
local IDtable = nil
local acc = nil
local IDkeyBuf = nl

shared.lock(function()
if shared.tbl == nil then
    shared.tbl = hmap.createHashmap(8, ffi.sizeof("struct ipv4_5tuple"))
end
IDtable = shared.tbl
acc = IDtable.newAccessor()
ffi.gc(acc, acc.free)
IDkeyBuf = ffi.new("uint8_t[?]", IDtable.keyBufSize())
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

log:setLevel("INFO")

function module.handlePacket(flowKey, state, buf, isFirstPacket)
    local t = buf:getTimestamp() * 10^6
    state.last_seen = t
    if isFirstPacket then
        state.first_seen = t
    end

    local udpPkt = pktLib.getUdp4Packet(buf)
    local flags = udpPkt.payload.uint8[0]
    if band(flags, 0x80) ~= 0 then
        return false -- Reserved bit set, probably not quic
    end
    if band(flags, 0x08) ~= 0 then
        local cid = ffi.cast("uint64_t*", udpPkt.payload.uint8 + 1)[0]
        log:debug("[Analyzer]: Found CID %s", tostring(cid))
        if not isFirstPacket and cid ~= state.connection_id then
            log:info("Connection ID changed for flow %s: %s -> %s", flowKey, tonumber(state.connection_id), tonumber(cid))
        end
        state.connection_id = cid
        -- Check ID -> 5-Tuple map
        ffi.fill(IDkeyBuf, IDtable.keyBufSize())
        ffi.copy(IDkeyBuf, udpPkt.payload.uint8 + 1, 8)
        local new = IDtable:access(acc, IDkeyBuf)
        local tpl = ffi.cast("struct ipv4_5tuple&", acc:get())
        if new then
            ffi.copy(tpl, flowKey, ffi.sizeof("struct ipv4_5tuple"))
        end
        local dump = false
        if ffi.C.memcmp(tpl, flowKey, ffi.sizeof("struct ipv4_5tuple")) ~= 0 then
            log:warn("Connection migration of id %i from %s to %s", tonumber(cid), tpl, flowKey)
            state.tracked = 1
            dump = true
        end
        acc:release()
        return dump
    else
        log:debug("[Analyzer]: No CID")
        if isFirstPacket then
            log:info("First packet in flow and no connection ID in %s", flowKey)
        else
            ffi.fill(IDkeyBuf, IDtable.keyBufSize())
            ffi.cast("uint64_t*", IDkeyBuf)[0] = state.connection_id
            local exists = IDtable:find(acc, IDkeyBuf)
            local dump = false
            if exits then
                local tpl = ffi.cast("struct ipv4_5tuple&", acc:get())
                if ffi.C.memcmp(tpl, flowKey, ffi.sizeof("struct ipv4_5tuple")) ~= 0 then
                    log:warn("Connection migration of id %i from %s to %s", tonumber(state.connection_id), tpl, flowKey)
                    state.tracked = 1
                    dump = true
                end
            end
            acc:release()
            return dump
        end
    end
    return false
end


-- #### Checker configuration ####

module.checkInterval = 5

function module.checkExpiry(flowKey, state, checkState)
    local t = lm.getTime() * 10^6
    if state.tracked == 1 and tonumber(state.last_seen) + 30 * 10^6 < t then
        ffi.fill(IDkeyBuf, IDtable.keyBufSize())
        ffi.cast("uint64_t*", IDkeyBuf)[0] = state.connection_id
        --ffi.copy(IDkeyBuf, state.connection_id, 8)
        local new = IDtable:access(acc, IDkeyBuf)
        assert(new == false) -- Must hold or we have missed an ID before
        IDtable:erase(acc)
        acc:release()
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
