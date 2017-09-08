local ffi = require "ffi"
local C = ffi.C
local memory = require "memory"
local flowtrackerlib = ffi.load("../build/flowtracker")
local hmap = require "hmap"
local lm = require "libmoon"
local log = require "log"
local stats = require "stats"
local pktLib = require "packet"
local eth = require "proto.ethernet"
local ip = require "proto.ip4"

local mod = {}

local flowtracker = {}
flowtracker.__index = flowtracker

function mod.new(args)
    -- get size of stateType and round up to something
    -- in C++: force template instantiation of several hashtable types (4,8,16,32,64,....?) bytes value?
    -- get appropriate hashtables

    -- Check parameters
    for k, v in pairs(args) do
        log:info("%s: %s", k, v)
    end
    if args.stateType == nil then
        log:error("Module has no stateType")
    end

    local obj = setmetatable(args, flowtracker)
    obj.table4 = hmap.createTable(ffi.sizeof(obj.stateType))
    -- FIXME: ffi.new is garbage collected, can't be used here!
    obj.defaultState = ffi.cast("void*", obj.defaultState or ffi.new(obj.stateType))
    --lm.startTask("__FLOWTRACKER_SWAPPER", obj)
    return obj
end

local function extractTuple(buf, tuple)
    local ethPkt = pktLib.getEthernetPacket(buf)
    if ethPkt.eth:getType() == eth.TYPE_IP then
        -- actual L4 type doesn't matter
        local parsedPkt = pktLib.getUdp4Packet(buf)
        tuple.ip_dst = parsedPkt.ip4:getDst()
        tuple.ip_src = parsedPkt.ip4:getSrc()
        local TTL = parsedPkt.ip4:getTTL()
        if parsedPkt.ip4:getProtocol() == ip.PROTO_UDP then
            tuple.port_dst = parsedPkt.udp:getDstPort()
            tuple.port_src = parsedPkt.udp:getSrcPort()
            tuple.proto = parsedPkt.ip4:getProtocol()
            return true
        elseif parsedPkt.ip4:getProtocol() == ip.PROTO_TCP then
            -- port at the same position as UDP
            tuple.port_dst = parsedPkt.udp:getDstPort()
            tuple.port_src = parsedPkt.udp:getSrcPort()
            tuple.proto = parsedPkt.ip4:getProtocol()
            return true
        elseif parsedPkt.ip4:getProtocol() == ip.PROTO_SCTP then
            -- port at the same position as UDP
            tuple.port_dst = parsedPkt.udp:getDstPort()
            tuple.port_src = parsedPkt.udp:getSrcPort()
            tuple.proto = parsedPkt.ip4:getProtocol()
            return true
        end
    else
        log:info("Packet not IP")
    end
    return false
end

function flowtracker:analyzer(userModule, queue)
    userModule = loadfile(userModule)()
    -- Cast back to correct type
    local stateType = ffi.typeof(userModule.stateType .. "*")
    self.defaultState = ffi.cast(stateType, self.defaultState)
    local handler4 = userModule.handleIp4Packet
    assert(handler4)
    local accessor = self.table4.newAccessor()
    local bufs = memory.bufArray()
    local rxCtr = stats:newPktRxCounter("Analyzer")
    -- FIXME: would be nice to make this customizable as well?
    local tuple = ffi.new("struct ipv4_5tuple")
    --require("jit.p").start("a")
    while lm.running() do
        local rx = queue:tryRecv(bufs)
        for i = 1, rx do
            local buf = bufs[i]
            rxCtr:countPacket(buf)
            -- also handle IPv4/6/whatever
            local success = extractTuple(buf, tuple)
            if success then
                -- copy-constructed
                local isNew = self.table4:access(accessor, tuple)
                local t = accessor:get()
                local valuePtr = ffi.cast(stateType, t)
                if isNew then
                    ffi.copy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))
                    --log:info("New flow! %s", tuple)
                end
                handler4(tuple, valuePtr, buf, isNew)
                accessor:release()
            end
        end
        bufs:free(rx)
        rxCtr:update()
    end
    --require("jit.p").stop()
    accessor:free()
    rxCtr:finalize()
end

function flowtracker:delete()
    self.table4:delete()
end

-- usual libmoon threading magic
__FLOWTRACKER_ANALYZER = flowtracker.analyzer
mod.analyzerTask = "__FLOWTRACKER_ANALYZER"

-- don't forget the usual magic in __serialize for thread-stuff


-- swapper goes here

return mod
