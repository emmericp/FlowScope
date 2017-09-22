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

ffi.cdef[[
    struct new_flow_info {
        uint8_t index;
        void* flow_key;
    };
]]

local flowtracker = {}

function mod.new(args)
    -- Check parameters
    for k, v in pairs(args) do
        log:info("%s: %s", k, v)
    end
    if args.stateType == nil then
        log:error("Module has no stateType")
        return nil
    end
    if type(args.flowKeys) ~= "table" then
        log:error("Module has no flow keys table")
        return nil
    end
    if #args.flowKeys < 1 then
        log:error("Flow key array must contain at least one entry")
        return nil
    end
    if args.defaultState == nil then
        log:info("Module has no default flow state, using {}")
        args.defaultState = {}
    end
    if type(args.extractFlowKey) ~= "function" then
        log:error("Module has no extractFlowKey function")
        return nil
    end

    local obj = setmetatable(args, flowtracker)
    obj.maps = {}
    for _, v in ipairs(args.flowKeys) do
        local m = hmap.createHashmap(ffi.sizeof(v), ffi.sizeof(obj.stateType))
        log:info("{%s -> %s}: %s", v, obj.stateType, m)
        table.insert(obj.maps, m)
    end
    -- Create temporary object with zero bytes or user-defined initializers
    local tmp = ffi.new(obj.stateType, obj.defaultState)
    -- Allocate persistent (non-GC) memory
    obj.defaultState = memory.alloc("void*", ffi.sizeof(obj.stateType))
    -- Make temporary object persistent
    ffi.copy(obj.defaultState, tmp, ffi.sizeof(obj.stateType))

    -- Setup expiry checker pipes
    obj.pipes = {}

    return obj
end

-- Starts a new analyzer
function flowtracker:startNewAnalyzer(userModule, queue)
    local p = pipe.newFastPipe()
    self.pipes[#self.pipes + 1] = p -- Store pipes so the checker can access them
    lm.startTask("__FLOWTRACKER_ANALYZER", self, userModule, queue, p)
end

-- Starts the flow expiry checker
-- Must only be called after all analyzers are set up
function flowtracker:startChecker(userModule)
    lm.startTask("__FLOWTRACKER_CHECKER", self, userModule)
end

function flowtracker:analyzer(userModule, queue, flowPipe)
    userModule = loadfile(userModule)()

    -- Cast flow state + default back to correct type
    local stateType = ffi.typeof(userModule.stateType .. "*")
    self.defaultState = ffi.cast(stateType, self.defaultState)

    -- Cache functions
    local handler = userModule.handlePacket
    local extractFlowKey = userModule.extractFlowKey

    -- Allocate hash map accessors
    local accs = {}
    for _, v in ipairs(self.maps) do
        table.insert(accs, v.newAccessor())
    end

    -- Allocate flow key buffer
    local sz = hmap.getLargestKeyBufSize(self.maps)
    local keyBuf = ffi.new("uint8_t[?]", sz)
    log:info("Key buffer size: %i", sz)

    local bufs = memory.bufArray()
    local rxCtr = stats:newPktRxCounter("Analyzer")

    --require("jit.p").start("a2")
    while lm.running() do
        local rx = queue:tryRecv(bufs, 10)
        for i = 1, rx do
            local buf = bufs[i]
            rxCtr:countPacket(buf)
            ffi.fill(keyBuf, sz) -- Clear shared key buffer
            local success, index = extractFlowKey(buf, keyBuf)
            if success then
                local isNew = self.maps[index]:access(accs[index], keyBuf)
                local t = accs[index]:get()
                local valuePtr = ffi.cast(stateType, t)
                if isNew then
                    -- copy-constructed
                    ffi.copy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))
                    -- Alloc new keyBuf and copy flow into it
                    local t = memory.alloc("void*", sz)
                    ffi.fill(t, sz)
                    ffi.copy(t, keyBuf, sz)
                    local info = memory.alloc("struct new_flow_info*", ffi.sizeof("struct new_flow_info"))
                    info.index = index
                    info.flow_key = t
                    flowPipe:trySend(info)
                end
                handler(keyBuf, valuePtr, buf, isNew)
                accs[index]:release()
            end
        end
        bufs:free(rx)
        rxCtr:update()
    end
    --require("jit.p").stop()
    for _, v in ipairs(accs) do
        v:free()
    end
    rxCtr:finalize()
end

function flowtracker:checker(userModule)
    userModule = loadfile(userModule)()
    local stateType = ffi.typeof(userModule.stateType .. "*")
    local checkTimer = timer:new(self.checkInterval)
    local initializer = userModule.checkInitializer or function() end
    local finalizer = userModule.checkFinalizer or function() end
    local checkState = userModule.checkState or "void*"

    -- Flow list
    local flows = {}
    local addToList = function(l, flow)
        l[#l + 1] = flow
    end
    local deleteFlow = function(flow)
        memory.free(flow.flow_key)
        memory.free(flow)
    end

    -- Allocate hash map accessors
    local accs = {}
    for _, v in ipairs(self.maps) do
        table.insert(accs, v.newAccessor())
    end

    require("jit.p").start("a2")
    while lm.running() do
        for _, pipe in ipairs(self.pipes) do
            local newFlow = pipe:tryRecv(10)
            if newFlow ~= nil then
                newFlow = ffi.cast("struct new_flow_info&", newFlow)
                --print("checker", newFlow)
                addToList(flows, newFlow)
            end
        end
        if checkTimer:expired() then
            log:info("[Checker]: Started")
            local t1 = time()
            local purged, keep = 0, 0
            local keepList = {}
            local cs = ffi.new(checkState)
            initializer(cs)
            for i = #flows, 1, -1 do
                local index, flowKey = flows[i].index, flows[i].flow_key
                local isNew = self.maps[index]:access(accs[index], flowKey)
                assert(isNew == false) -- Must hold or we have an error
                local valuePtr = ffi.cast(stateType, accs[index]:get())
                if userModule.checkExpiry(flowKey, valuePtr, cs) then
                    deleteFlow(flows[i])
                    self.maps[index]:erase(accs[index])
                    purged = purged + 1
                else
                    addToList(keepList, flows[i])
                    keep = keep + 1
                end
                accs[index]:release()
            end
            flows = keepList
            finalizer(cs, keep, purged)
            local t2 = time()
            log:info("[Checker]: Done, took %fs, flows %i/%i/%i [purged/kept/total]", t2 - t1, purged, keep, purged+keep)
            checkTimer:reset()
        end
    end
    require("jit.p").stop()
    for _, v in ipairs(accs) do
        v:free()
    end
    log:info("[Checker]: Shutdown")
end

function flowtracker:delete()
    memory.free(self.defaultState)
    for _, v in ipairs(self.maps) do
        v:delete()
    end
    for _, v in ipairs(self.pipes) do
        v:delete()
    end
end

flowtracker.__index = flowtracker

-- usual libmoon threading magic
__FLOWTRACKER_ANALYZER = flowtracker.analyzer
mod.analyzerTask = "__FLOWTRACKER_ANALYZER"

__FLOWTRACKER_CHECKER = flowtracker.checker
mod.checkerTask = "__FLOWTRACKER_CHECKER"

-- don't forget the usual magic in __serialize for thread-stuff

return mod
