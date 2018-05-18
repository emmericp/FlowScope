local ffi = require "ffi"
local lm = require "libmoon"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip = require "proto.ip4"
local tuple = require "tuple"

local module = {}


-- IPv4 5-Tuples are not really no-ops, but doing exactly nothing would result in 0 flows in the hash tables. Not exactly a very good benchmark
module.flowKeys = tuple.flowKeys
module.extractFlowKey = tuple.extractIP5Tuple

ffi.cdef [[
    struct flow_state {
    };
]]
module.stateType = "struct flow_state"
module.defaultState = {}

function module.handlePacket(flowKey, state, buf, isFirstPacket)
    local t = lm.getTime() * 10^6
end

module.checkInterval = 5

function module.checkInitializer(checkState)
    checkState.start_time = lm.getTime() * 10^6
end

function module.checkExpiry(flowKey, flowState, checkState)
    local t = lm.getTime() * 10^6

    return false
end

function module.checkFinalizer(checkState)
    local t = lm.getTime() * 10^6
end

return module
