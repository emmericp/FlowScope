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


module.checkInterval = 5

ffi.cdef [[
    struct check_state {
        uint64_t start_time;
        uint64_t active_flows;
        uint64_t cumulative_packets;
        uint64_t cumulative_bytes;
    };
]]
module.checkState = "struct check_state"

function module.checkExpiry(flowKey, flowState, checkState)
    local t = lm.getTime() * 10^6
    if flowState.last_seen + 30 * 10^6 < t then
        return true
    else
        checkState.active_flows = checkState.active_flows + 1
        checkState.cumulative_packets = checkState.cumulative_packets + flowState.packet_counter
        checkState.cumulative_bytes = checkState.cumulative_bytes + flowState.byte_counter
        return false
    end
end

function module.checkInitializer(checkState)
    checkState.start_time = lm.getTime() * 10^6
end

function module.checkFinalizer(checkState)
    local t = lm.getTime() * 10^6
    print(string.format("Active flows %i, cumulative packets %i, cumulative bytes %i, took %fs", tonumber(checkState.active_flows), tonumber(checkState.cumulative_packets), tonumber(checkState.cumulative_bytes), (t - tonumber(checkState.start_time)) / 10^6))
end

return module
