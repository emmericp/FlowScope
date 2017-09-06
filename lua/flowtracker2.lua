local ffi = require "ffi"
local C = ffi.C
local flowtrackerlib = ffi.load("../build/flowtracker")
local hmap = require "hmap"
local lm = require "libmoon"
local log = require "log"

local mod = {}

local flowtracker = {}
flowtracker.__index = flowtracker

function mod.new(args)
    -- get size of stateType and round up to something
    -- in C++: force template instantiation of several hashtable types (4,8,16,32,64,....?) bytes value?
    -- get appropriate hashtables
    -- check parameters here
    for k,v in pairs(args) do
        log:info("%s: %s", k, v)
    end
    local obj = setmetatable(args, flowtracker)
    obj.table4 = hmap.createTable(ffi.sizeof(obj.stateType))
    obj.defaultState = obj.defaultState or ffi.new(obj.stateType)
    lm.startTask("__FLOWTRACKER_SWAPPER", obj)
    return obj
end

function flowtracker:analyzer(queue)
    local handler4 = _G[self.ip4Handler]
    assert(handler4)
    local accessor = self.table4.newAccessor()
    while lm.running() do
        local bufs = nil -- perform the usual DPDK incantations to get packets
        for buf in ipairs(bufs) do
            -- also handle IPv4/6/whatever
            local tuple = extractTuple(buf)
            -- copy-constructed
            local isNew = self.table4:access(accessor, tuple)
            local valuePtr = accessor:get()
            if isNew then
                C.memcpy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))
            end
            handler4(tuple, valuePtr, buf, isNew)
            accessor:release()
        end
    end
    accessor:free()
end

-- usual libmoon threading magic
__FLOWTRACKER_ANALYZER = flowtracker.analyzer
mod.analyzerTask = "__FLOWTRACKER_ANALYZER"

-- don't forget the usual magic in __serialize for thread-stuff


-- swapper goes here

return mod
