local ffi = require "ffi"
local C = ffi.C
local flowtrackerlib = ffi.load("../build/flowtracker")
local hmap = require "hmap"
local lm = require "libmoon"
local log = require "log"

local mod = {}

local flowtracker = {}
flowtracker.__index = flowtracker

-- Get tbb hash map with fitting value size
function getTable(valueSize)
    if valueSize <= 8 then
        return flowtrackerlib.hmap8_create()
    elseif valueSize <= 16 then
        return flowtrackerlib.hmap16_create()
    elseif valueSize <= 32 then
        return flowtrackerlib.hmap32_create()
    elseif valueSize <= 64 then
        return flowtrackerlib.hmap64_create()
    elseif valueSize <= 128 then
        return flowtrackerlib.hmap128_create()
    else
        log:error("Values of size %d are not supported", valueSize)
        return nil
    end
end

function mod.new(args)
    -- get size of stateType and round up to something
    -- in C++: force template instantiation of several hashtable types (4,8,16,32,64,....?) bytes value?
    -- get appropriate hashtables
    -- check parameters here
    for k,v in pairs(args) do
        log:info("%s: %s", k, v)
    end
    local obj = setmetatable(args, flowtracker)
    obj.table4 = getTable(ffi.sizeof(obj.stateType))
    obj.defaultState = obj.defaultState or ffi.new(obj.stateType)
    lm.startTask("__FLOWTRACKER_SWAPPER", obj)
    return obj
end

function flowtracker:analyzer(queue)
    local handler4 = _G[self.ip4Handler]
    assert(handler4)
    local accessor = flowtrackerlib.hmap8_new_accessor()
    while lm.running() do
        local bufs = nil -- perform the usual DPDK incantations to get packets
        for buf in ipairs(bufs) do
            -- also handle IPv4/6/whatever
            local tuple = extractTuple(buf)
            -- copy-constructed
            local isNew = flowtrackerlib.hmap8_access(self.table4, accessor, tuple)
            local valuePtr = flowtrackerlib.hmap8_accessor_get_value(accessor)
            if isNew then
                C.memcpy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))
            end
            handler4(tuple, valuePtr, buf, isNew)
            flowtrackerlib.hmap8_accessor_release(accessor)
        end
    end
end

-- usual libmoon threading magic
__FLOWTRACKER_ANALYZER = flowtracker.analyzer
flowtracker.analyzerTask = "__FLOWTRACKER_ANALYZER"

-- don't forget the usual magic in __serialize for thread-stuff


-- swapper goes here

return mod
