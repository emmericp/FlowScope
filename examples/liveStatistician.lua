local ffi = require "ffi"
local lm = require "libmoon"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip = require "proto.ip4"
local tuple = require "tuple"

local module = {}

local inactiveFlowExpiry = 30 -- seconds

ffi.cdef [[
    struct live_flow_state {
        uint64_t packets_interval;
        uint64_t bytes_interval;
        uint64_t packets_total;
        uint64_t bytes_total;
        uint64_t last_seen;
        uint64_t interval_start;
        uint64_t first_seen;
    };
]]

module.flowKeys = tuple.flowKeys
module.stateType = "struct live_flow_state"
module.defaultState = {}
module.extractFlowKey = tuple.extractIP5Tuple

function module.handlePacket(flowKey, state, buf, isFirstPacket)
    local t = lm.getTime() * 10^6
    state.packets_interval = state.packets_interval + 1
    state.bytes_interval = state.bytes_interval + buf:getSize()
    state.packets_total = state.packets_total + 1
    state.bytes_total = state.bytes_total + buf:getSize()
    if isFirstPacket then
        state.first_seen = t
        state.interval_start = t
    end
    state.last_seen = t
end

module.checkInterval = 5

function module.checkInitializer(checkState)
    checkState.start_time = lm.getTime() * 10^6
    checkState.active_flows = 0ull
    checkState.cumulative_packets = 0ull
    checkState.cumulative_bytes = 0ull
    checkState.tops = {}
end

local function sortedInsert(t, max, entry, cmpFn)
    if #t < max then
        table.insert(t, entry)
        table.sort(t, cmpFn)
    else
        for i=1, #t do
            if cmpFn(entry, t[i]) then
                table.insert(t, i, entry)
                table.remove(t)
                break
            end
        end
    end
end

function module.checkExpiry(flowKey, flowState, checkState)
    local t = lm.getTime() * 10^6

    local d = tonumber(t - flowState.interval_start) / 10^6
    local bps = tonumber(flowState.bytes_interval * 8) / d
    local pps = tonumber(flowState.packets_interval) / d
    local e = {bps, pps, flowKey, flowState.interval_start, t, flowState.bytes_interval, flowState.packets_interval}
    local cmpFn = function(a, b) return a[1] > b[1] end
    sortedInsert(checkState.tops, 10, e, cmpFn)
    
    checkState.cumulative_packets = checkState.cumulative_packets + flowState.packets_interval
    checkState.cumulative_bytes = checkState.cumulative_bytes + flowState.bytes_interval
    
    -- Reset interval counter
    flowState.bytes_interval = 0
    flowState.packets_interval = 0
    flowState.interval_start = t

    if flowState.last_seen + inactiveFlowExpiry * 10^6 < t then
        return true, t / 10^6
    else
        checkState.active_flows = checkState.active_flows + 1
        return false
    end
end

function module.checkFinalizer(checkState)
    local t = lm.getTime() * 10^6
    print("Top flows over sliding " .. module.checkInterval .. "s window:")
    print("#", "bps", "pps", "Flow")
    for k,v in pairs(checkState.tops) do
        print(string.format("%i %.2f %.2f %s", k, v[1], v[2], v[3]))
    end    
    print(string.format("Active flows %i, cumulative packets %i [%.2f/s], cumulative bytes %i [%.2f/s], took %.2fs", tonumber(checkState.active_flows), tonumber(checkState.cumulative_packets), tonumber(checkState.cumulative_packets) / module.checkInterval, tonumber(checkState.cumulative_bytes), tonumber(checkState.cumulative_bytes) / module.checkInterval, (t - tonumber(checkState.start_time)) / 10^6))
end

return module
