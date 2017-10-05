local ffi = require "ffi"
local lm = require "libmoon"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip = require "proto.ip4"
local log = require "log"

local module = {}

-- Define wanted flow keys and flow state
-- must be done on top level to be available/defined in all threads
ffi.cdef [[
    struct my_flow_state {
        uint64_t packet_counter;
        uint64_t byte_counter;
        uint64_t first_seen;
        uint64_t last_seen;
        uint8_t some_flags;
        uint16_t some_fancy_data[20];
    };

    struct my_primary_flow_key {
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
    } __attribute__((__packed__));

    struct my_secondary_flow_key {
        uint8_t  ip_dst[16];
        uint8_t  ip_src[16];
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
    } __attribute__((__packed__));
]]

-- Set buffer mode
-- "direct" for direct access to the NIC without additional buffering or dumping
-- "qq" for the QQ ringbuffer
module.mode = "qq"

-- Export flow keys
-- Position in the array corresponds to the index returned by extractFlowKey()
module.flowKeys = {
    "struct my_primary_flow_key",
    "struct my_secondary_flow_key",
}

-- Export flow state type
module.stateType = "struct my_flow_state"

-- Custom default state for new flows
-- See ffi.new() for table initializer rules
module.defaultState = {packet_counter = 0, some_flags = 0xab}

-- Function that builds the appropriate flow key for the packet given in buf
-- return true and the hash map index for successful extraction, false if a packet should be ignored
-- Use libmoons packet library to access common protocol fields
-- See tuple.lua for classic IPv4/v6 5-tuple keys
function module.extractFlowKey(buf, keyBuf)
    local ethPkt = pktLib.getEthernetPacket(buf)
    if ethPkt.eth:getType() == eth.TYPE_IP then
        -- actual L4 type doesn't matter
        keyBuf = ffi.cast("struct my_primary_flow_key&", keyBuf)
        local parsedPkt = pktLib.getUdp4Packet(buf)
        keyBuf.ip_dst = parsedPkt.ip4:getDst()
        keyBuf.ip_src = parsedPkt.ip4:getSrc()
        local TTL = parsedPkt.ip4:getTTL()
        -- port is always at the same position as UDP
        keyBuf.port_dst = parsedPkt.udp:getDstPort()
        keyBuf.port_src = parsedPkt.udp:getSrcPort()
        local proto = parsedPkt.ip4:getProtocol()
        if proto == ip.PROTO_UDP or proto == ip.PROTO_TCP or proto == ip.PROTO_SCTP then
            keyBuf.proto = proto
            return true, 1
        end
    else
        log:info("Packet not IP")
    end
    return false
end

-- state starts out empty if it doesn't exist yet; buf is whatever the device queue or QQ gives us
-- flowKey will be a ctype of one of the above defined flow keys
function module.handlePacket(flowKey, state, buf, isFirstPacket)
    -- qq bufs (mode == "qq") always hold their timestamp of arival at the NIC in seconds
    -- lm.getTime() is sourced from the same clock (TSC) and can be directly compared to these
    local ts = buf:getTimestamp() * 10^6 -- Shift float to get more digits to store in a uint
    state.packet_counter = state.packet_counter + 1
    state.byte_counter = state.byte_counter + buf:getSize()
    if isFirstPacket then
        state.first_seen = ts
    end
    state.last_seen = ts
    return false
end


-- #### Checker configuration ####

-- Set the interval in which the checkExpiry function should be called.
-- Don't define it or set it do nil to disable the checker task
-- float in seconds
module.checkInterval = 5

-- Per checker run persistent state, e.g., to track overall flow changes
ffi.cdef [[
    struct check_state {
        uint64_t start_time;
    };
]]
module.checkState = "struct check_state"

-- Function that gets called in regular intervals to decide if a flow is still active.
-- Returns false for active flows.
-- Returns true and a timestamp in seconds for flows that are expired.
function module.checkExpiry(flowKey, state, checkState)
    if math.random(0, 200) == 0 then
        return true, tonumber(state.last_seen) / 10^6 -- Convert back to seconds
    else
        return false
    end
end

-- Function that gets called once per checker run at very beginning, before any flow is touched
function module.checkInitializer(checkState)
    checkState.start_time = lm.getTime() * 10^6
end

-- Function that gets called once per checker run at very end, after all flows have been processed
function module.checkFinalizer(checkState, keptFlows, purgedFlows)
    local t = lm.getTime() * 10^6
    log:info("[Checker]: Done, took %fs, flows %i/%i/%i [purged/kept/total]", (t - tonumber(checkState.start_time)) / 10^6, purgedFlows, keptFlows, purgedFlows+keptFlows)
end


-- #### Dumper configuration ####
-- Only applicable if mode is set to "qq"

module.maxDumperRules = 1000

-- Function that returns a packet filter string in pcap syntax from a given flow key
function module.buildPacketFilter(flowKey)
    return ""
end

return module
