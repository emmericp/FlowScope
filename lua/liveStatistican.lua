local ffi = require "ffi"
local lm = require "libmoon"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip = require "proto.ip4"
local tuple = require "tuple"

local module = {}

ffi.cdef [[
    struct live_flow_state {
        uint64_t packet_counter;
        uint64_t byte_counter;
        uint64_t first_seen;
        uint64_t last_seen;
    };
]]

module.flowKeys = tuple.flowKeys
module.stateType = "struct live_flow_state"
module.defaultState = {}
module.extractFlowKey = tuple.extractIP5Tuple

function module.handlePacket(flowKey, state, buf, isFirstPacket)
    local t = lm.getTime() * 10^6
    state.packet_counter = state.packet_counter + 1
    state.byte_counter = state.byte_counter + buf:getSize()
    if isFirstPacket then
        state.first_seen = t
    end
    state.last_seen = t
end

function module.checkExpiry(flowKey, state)
    local t = lm.getTime() * 10^6
    if state.last_seen + 30 * 10^6 < t then
        return true
    else
        return false
    end
end

module.checkInterval = 5

return module
