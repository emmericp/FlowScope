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
local pcap = require "pcap"
local ev = require "event"
local qqLib = require "qq"


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

    -- Create hash maps
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

    -- Setup filter pipes for dumpers
    obj.filterPipes = {}

    -- Setup table for QQs
    if args.mode == "qq" then
        obj.qq = {}
    end

    return obj
end

-- Starts a new analyzer
function flowtracker:startNewAnalyzer(userModule, queue)
    local p = pipe.newFastPipe()
    self.pipes[#self.pipes + 1] = p -- Store pipes so the checker can access them
    if ffi.istype("qq_t", queue) then
        log:info("QQ mode")
        lm.startTask("__FLOWTRACKER_ANALYZER_QQ", self, userModule, queue, p)
    else
        log:info("direct mode")
        lm.startTask("__FLOWTRACKER_ANALYZER", self, userModule, queue, p)
    end
end

-- Starts the flow expiry checker
-- Must only be called after all analyzers are set up
function flowtracker:startChecker(userModule)
    lm.startTask("__FLOWTRACKER_CHECKER", self, userModule)
end

-- Starts a new dumper
-- Must be started before any analyzer
function flowtracker:startNewDumper(path, qq)
    local p = pipe.newSlowPipe()
    table.insert(self.filterPipes, p)
    lm.startTask("__FLOWTRACKER_DUMPER", self, qq, path, p)
end

-- Starts a new task that inserts packets from a NIC queue into a QQ
function flowtracker:startNewInserter(rxQueue, qq)
    lm.startTask("__FLOWTRACKER_INSERTER", rxQueue, qq)
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

function flowtracker:analyzerQQ(userModule, queue, flowPipe)
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

    local rxCtr = stats:newPktRxCounter("Analyzer")

    --require("jit.p").start("a2")
    while lm.running() do
        local storage = queue:tryPeek()
        if storage ~= nil then
            for i = 0, storage:size() - 1 do
                local buf = storage:getPacket(i)
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
            storage:release()
        end
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

    require("jit.p").start("a")
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
            checkTimer:reset() -- Reseting the timer first makes the checker self-clocking
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
        end
    end
    require("jit.p").stop()
    for _, v in ipairs(accs) do
        v:free()
    end
    log:info("[Checker]: Shutdown")
end

function flowtracker:dumper(qq, path, filterPipe)
    pcap:setInitialFilesize(2^21) -- 2 MiB
    local ruleSet = {} -- Used to maintain the rules
    local ruleList = {} -- Build from the ruleSet for performance
    local needRebuild = false
    local maxRules = self.maxDumperRules
    local rxCtr = stats:newManualRxCounter("Dumper", "plain")
    local lastTS = 0

    local handleEvent = function(event)
        if event == nil then
            return
        end
        log:debug("[Dumper %i]: Got event %i, %s, %i", id, event.action, event.filter, event.timestamp or 0)
        if event.action == ev.create and ruleSet[event.id] == nil and #ruleList < maxRules then
            local triggerWallTime = wallTime()
            local pcapFileName = path .. "/" .. ("FlowScope-dump " .. os.date("%Y-%m-%d %H-%M-%S", triggerWallTime) .. " " .. event.id .. " part " .. id .. ".pcap"):gsub("[ /\\]", "_")
            local pcapWriter = pcap:newWriter(pcapFileName, triggerWallTime)
            ruleSet[event.id] = {pfFn = pf.compile_filter(event.filter), pcap = pcapWriter}
            needRebuild = true
        elseif event.action == ev.delete and ruleSet[event.id] ~= nil then
            ruleSet[event.id].timestamp = event.timestamp
            log:info("[Dumper]: Marked rule %s as expired", event.id)
        end
    end

    while lm.running() do
        -- Get new filters
        repeat
            local event = filterPipe:tryRecv(0)
            handleEvent(event)
        until event == nil

        -- Check for expired rules
        for k, v in pairs(ruleSet) do
            if v.timestamp ~= nil and lastTS > v.timestamp then
                ruleSet[k].pcap:close()
                log:info("[Dumper %i#]: Expired rule %s, %i > %i", id, k, lastTS, v.timestamp)
                ruleSet[k] = nil
                needRebuild = true
            end
        end

        -- Rebuild ruleList from ruleSet
        if needRebuild then
            ruleList = {}
            for _, v in pairs(ruleSet) do
                table.insert(ruleList, {v.pfFn, v.pcap})
            end
            log:info("[Dumper]: total number of rules: %i", #ruleList)
        end

        -- Filter packets
        local storage = qq:tryDequeue()
        if storage ~= nil then
            rxCtr:updateWithSize(storage:size(), 0)
            for i = 0, storage:size() - 1 do
                local pkt = storage:getPacket(i)
                local timestamp = pkt:getTimestamp()
                local data = pkt:getData()
                local len = pkt:getSize()
                lastTS = timestamp
                -- Do not use ipairs() here
                for j = 1, #ruleList do
                    local filterFn = ruleList[j][1]
                    local pcap = ruleList[j][2]
                    if filterFn(data, len) then
                        pcap:write(timestamp, data, len)
                    end
                end
            end
            storage:release()
        end
    end
    require("jit.p").stop()
    rxCtr:finalize()
    for _, rule in pairs(ruleSet) do
        rule.pcap:close()
    end
    log:info("[Dumper]: Shutdown")
end

function flowtracker.inserter(rxQueue, qq)
    qq:inserterLoop(rxQueue)
    log:info("[Inserter]: Shutdown")
end

function flowtracker:delete()
    memory.free(self.defaultState)
    for _, v in ipairs(self.maps) do
        v:delete()
    end
    for _, v in ipairs(self.pipes) do
        v:delete()
    end
    for _, v in ipairs(self.filterPipes) do
        v:delete()
    end
    for _, v in ipairs(self.qq) do
        v:delete()
    end
end

flowtracker.__index = flowtracker

-- usual libmoon threading magic
__FLOWTRACKER_ANALYZER = flowtracker.analyzer
mod.analyzerTask = "__FLOWTRACKER_ANALYZER"

__FLOWTRACKER_ANALYZER_QQ = flowtracker.analyzerQQ
mod.analyzerQQTask = "__FLOWTRACKER_ANALYZER_QQ"

__FLOWTRACKER_CHECKER = flowtracker.checker
mod.checkerTask = "__FLOWTRACKER_CHECKER"

__FLOWTRACKER_DUMPER = flowtracker.dumper
mod.dumperTask = "__FLOWTRACKER_DUMPER"

__FLOWTRACKER_INSERTER = flowtracker.inserter
mod.inserterTask = "__FLOWTRACKER_INSERTER"

-- don't forget the usual magic in __serialize for thread-stuff

return mod
