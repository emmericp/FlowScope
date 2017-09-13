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
local pipe = require "pipe"
local timer = require "timer"

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
        return nil
    end
    if args.primaryFlowKey == nil then
        log:error("Module has no primary flow key")
        return nil
    end
    if args.defaultState == nil then
        log:info("Module has no default flow state, using {}")
        args.defaultState = {}
    end
    if args.extractFlowKey == nil then
        log:error("Module has no extractFlowKey function")
        return nil
    end

    local obj = setmetatable(args, flowtracker)
    obj.primaryTable = hmap.createTable(ffi.sizeof(obj.primaryFlowKey), ffi.sizeof(obj.stateType))
    log:info("%s", obj.primaryTable)
    -- Create temporary object with zero bytes or user-defined initializers
    local tmp = ffi.new(obj.stateType, obj.defaultState)
    -- Allocate persistent (non-GC) memory
    obj.defaultState = memory.alloc("void*", ffi.sizeof(obj.stateType))
    -- Make temporary object persistent
    ffi.copy(obj.defaultState, tmp, ffi.sizeof(obj.stateType))

    -- Setup expiry checker pipes
    obj.pipes = {}

    --lm.startTask("__FLOWTRACKER_CHECKER", obj)
    return obj
end

-- Starts a new analyzer
function flowtracker:startNewAnalyzer(userModule, queue)
    self.pipes[#self.pipes + 1] = pipe.newFastPipe()
    lm.startTask("__FLOWTRACKER_ANALYZER", self, userModule, queue)
end

-- Starts the flow expiry checker
-- Must only be called after all analyzers are set up
function flowtracker:startChecker(userModule)
    lm.startTask("__FLOWTRACKER_CHECKER", self, userModule)
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
    local newFlowPipe = self.pipes[#self.pipes]
    print("#pipes", #self.pipes, newFlowPipe)
    -- Cast back to correct type
    local stateType = ffi.typeof(userModule.stateType .. "*")
    self.defaultState = ffi.cast(stateType, self.defaultState)
    local handler = userModule.handlePacket
    assert(handler)
    local primaryAccessors = self.primaryTable.newAccessor()
    local bufs = memory.bufArray()
    local rxCtr = stats:newPktRxCounter("Analyzer")
    --local primaryFlowKey = ffi.new(userModule.primaryFlowKey)
    local buf = ffi.new("uint8_t[64]", {})
    local primaryFlowKey = ffi.cast(userModule.primaryFlowKey .. "*", buf)
    print(buf, primaryFlowKey, self.primaryTable.keyBufSize())
    --require("jit.p").start("a")
    while lm.running() do
        local rx = queue:tryRecv(bufs)
        for i = 1, rx do
            local buf = bufs[i]
            rxCtr:countPacket(buf)
            -- also handle IPv4/6/whatever
            local success = userModule.extractFlowKey(buf, primaryFlowKey)
            if success then
                local isNew = self.primaryTable:access(primaryAccessors, primaryFlowKey)
                local t = primaryAccessors:get()
                local valuePtr = ffi.cast(stateType, t)
                if isNew then
                    -- copy-constructed
                    ffi.copy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))
                    -- Alloc new primaryFlowKey and copy flow into it
                    local t = memory.alloc(userModule.primaryFlowKey .. "*", self.primaryTable.keyBufSize())
                    ffi.fill(t, self.primaryTable.keyBufSize())
                    ffi.copy(t, primaryFlowKey, ffi.sizeof(userModule.primaryFlowKey))
                    --log:info("%s %s", primaryFlowKey, t)
                    newFlowPipe:trySend(t)
                    --log:info("New flow! %s", primaryFlowKey)
                end
                handler(primaryFlowKey, valuePtr, buf, isNew)
                primaryAccessors:release()
            end
        end
        bufs:free(rx)
        rxCtr:update()
    end
    --require("jit.p").stop()
    primaryAccessors:free()
    rxCtr:finalize()
end

function flowtracker:checker(userModule)
    userModule = loadfile(userModule)()
    local stateType = ffi.typeof(userModule.stateType .. "*")
    local checkTimer = timer:new(self.checkInterval)
    local flows = {}
    local addToList = function(flow)
        flows[#flows + 1] = flow
    end
    local removeFromList = function(idx)
        memory.free(flows[idx])
        table.remove(flows, idx)
    end
    local primaryAccessors = self.primaryTable.newAccessor()
    while lm.running() do
        for _, pipe in ipairs(self.pipes) do
            local newFlow = pipe:tryRecv(10)
            if newFlow ~= nil then
                newFlow = ffi.cast(userModule.primaryFlowKey .. "&", newFlow)
                --print("checker", newFlow)
                addToList(newFlow)
            end
        end
        if checkTimer:expired() then
            local t1 = time()
            local purged, keep = 0, 0
            for i = #flows, 1, -1 do
                local flow = flows[i]
                local isNew = self.primaryTable:access(primaryAccessors, flow)
                assert(isNew == false) -- Must hold or we have an error
                local valuePtr = ffi.cast(stateType, primaryAccessors:get())
                if userModule.checkExpiry(flow, valuePtr) then
                    purged = purged + 1
                    removeFromList(i)
                    self.primaryTable:erase(primaryAccessors)
                else
                    keep = keep + 1
                end
                primaryAccessors:release()
            end
            local t2 = time()
            log:info("[Checker]: Timer expired, took %fs, flows %i/%i/%i [purged/kept/total]", t2 - t1, purged, keep, purged+keep)
            checkTimer:reset()
        end
    end
    primaryAccessors:free()
end

function flowtracker:delete()
    memory.free(self.defaultState)
    self.primaryTable:delete()
end

-- usual libmoon threading magic
__FLOWTRACKER_ANALYZER = flowtracker.analyzer
mod.analyzerTask = "__FLOWTRACKER_ANALYZER"

__FLOWTRACKER_CHECKER = flowtracker.checker
mod.checkerTask = "__FLOWTRACKER_CHECKER"

-- don't forget the usual magic in __serialize for thread-stuff

return mod
