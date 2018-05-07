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
-- module.checkState = ffi.new("struct check_state")
-- module.checkState = {}

function module.checkExpiry(flowKey, flowState, checkState)
    local t = lm.getTime() * 10^6

    local b = flowState.byte_counter
    local p = flowState.packet_counter
    table.insert(checkState.tops, {b, p, flowKey})
    table.sort(checkState.tops, function(a, b)
        return a[1] > b[1]
    end)
    while #checkState.tops > 10 do
        table.remove(checkState.tops)
    end
    -- Reset flow counter for most active flow in last 5 seconds, maybe use separate counter or expire faster
    flowState.byte_counter = 0
    flowState.packet_counter = 0
    if flowState.last_seen + 30 * 10^6 < t then
        return true, t / 10^6
    else
        checkState.active_flows = checkState.active_flows + 1
        checkState.cumulative_packets = checkState.cumulative_packets + p
        checkState.cumulative_bytes = checkState.cumulative_bytes + b
        return false
    end
end

function module.checkInitializer(checkState)
    checkState.start_time = lm.getTime() * 10^6
    checkState.active_flows = 0ull
    checkState.cumulative_packets = 0ull
    checkState.cumulative_bytes = 0ull
    checkState.tops = {}
end

function module.checkFinalizer(checkState)
    local t = lm.getTime() * 10^6

    print("Top flows in this run [" .. module.checkInterval .. " s]:")
    print("#", "Bytes", "Packets", "Flow")
    for k,v in pairs(checkState.tops) do
        print(k, v[1], v[2], v[3])
    end

    print(string.format("Active flows %i, cumulative packets %i [%f/s], cumulative bytes %i [%f/s], took %fs", tonumber(checkState.active_flows), tonumber(checkState.cumulative_packets), tonumber(checkState.cumulative_packets) / module.checkInterval, tonumber(checkState.cumulative_bytes), tonumber(checkState.cumulative_bytes) / module.checkInterval, (t - tonumber(checkState.start_time)) / 10^6))
end

return module
