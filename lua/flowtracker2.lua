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
local pf = require "pf"
local match = require "pf.match"


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
    obj.qq = {}

    -- Shutdown delay to catch packets hanging in QQ. In ms
    obj.shutdownDelay = 3000

    return obj
end

-- Starts a new analyzer
function flowtracker:startNewAnalyzer(userModule, queue)
    local p = pipe.newFastPipe()
    table.insert(self.pipes, p) -- Store pipes so the checker can access them
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
    lm.startTask("__FLOWTRACKER_DUMPER", self, #self.filterPipes, qq, path, p)
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

    --require("jit.p").start("a")
    while lm.running(self.shutdownDelay) do
        local rx = queue:tryRecv(bufs, 10)
        for i = 1, rx do
            local buf = bufs[i]
            rxCtr:countPacket(buf)
            ffi.fill(keyBuf, sz) -- Clear shared key buffer
            local success, index = extractFlowKey(buf, keyBuf)
            if success then
                local flowKey = ffi.cast(userModule.flowKeys[index] .. "*", keyBuf) -- Correctly cast alias to the key buffer
                local isNew = self.maps[index]:access(accs[index], keyBuf)
                local t = accs[index]:get()
                local valuePtr = ffi.cast(stateType, t)
                if isNew then
                    -- Copy-construct default state
                    ffi.copy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))

                    -- Copy keyBuf and inform checker about new flow
                    if userModule.checkInterval then -- Only bother if there are dumpers
                        local t = memory.alloc("void*", sz)
                        ffi.fill(t, sz)
                        ffi.copy(t, keyBuf, sz)
                        local info = memory.alloc("struct new_flow_info*", ffi.sizeof("struct new_flow_info"))
                        info.index = index
                        info.flow_key = t
                        -- we use send here since we know a checker exists and deques/frees our flow keys
                        flowPipe:send(info)
                    end
                end
                -- direct mode has no dumpers, so we can ignore dump requests of the handler
                handler(flowKey, valuePtr, buf, isNew)
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
    local buildPacketFilter = userModule.buildPacketFilter

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

    --require("jit.p").start("a")
    while lm.running(self.shutdownDelay) do
        local storage = queue:tryPeek()
        if storage ~= nil then
            for i = 0, storage:size() - 1 do
                local buf = storage:getPacket(i)
                rxCtr:countPacket(buf)
                ffi.fill(keyBuf, sz) -- Clear shared key buffer
                local success, index = extractFlowKey(buf, keyBuf)
                if success then
                    local flowKey = ffi.cast(userModule.flowKeys[index] .. "*", keyBuf) -- Correctly cast alias to the key buffer
                    local isNew = self.maps[index]:access(accs[index], keyBuf)
                    local t = accs[index]:get()
                    local valuePtr = ffi.cast(stateType, t)
                    if isNew then
                        -- Copy-construct default state
                        ffi.copy(valuePtr, self.defaultState, ffi.sizeof(self.defaultState))

                        -- Copy keyBuf and inform checker about new flow
                        if userModule.checkInterval then -- Only bother if there are dumpers
                            local t = memory.alloc("void*", sz)
                            ffi.fill(t, sz)
                            ffi.copy(t, keyBuf, sz)
                            local info = memory.alloc("struct new_flow_info*", ffi.sizeof("struct new_flow_info"))
                            info.index = index
                            info.flow_key = t
                            -- we use send here since we know a checker exists and deques/frees our flow keys
                            flowPipe:send(info)
                        end
                    end
                    if handler(flowKey, valuePtr, buf, isNew) then
                        local event = ev.newEvent(buildPacketFilter(flowKey), ev.create)
                        log:debug("[Analyzer]: Handler requested dump of flow %s", flowKey)
                        for _, pipe in ipairs(self.filterPipes) do
                            pipe:send(event)
                        end
                    end
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
    if not userModule.checkInterval then
        log:info("[Checker]: Disabled by user module")
        return
    end
    local stateType = ffi.typeof(userModule.stateType .. "*")
    local checkTimer = timer:new(self.checkInterval)
    local initializer = userModule.checkInitializer or function() end
    local finalizer = userModule.checkFinalizer or function() end
    local buildPacketFilter = userModule.buildPacketFilter or function() end
    local checkState = userModule.checkState or {}

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

--     require("jit.p").start("a")
    while lm.running(self.shutdownDelay) do
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
--             require("jit.p").start("a")
            local t1 = time()
            local purged, keep = 0, 0
            local keepList = {}
            initializer(checkState)
            for i = #flows, 1, -1 do
                local index, keyBuf = flows[i].index, flows[i].flow_key
                local isNew = self.maps[index]:access(accs[index], keyBuf)
                assert(isNew == false) -- Must hold or we have an error
                local valuePtr = ffi.cast(stateType, accs[index]:get())
                local flowKey = ffi.cast(userModule.flowKeys[index] .. "*", keyBuf)
                local expired, ts = userModule.checkExpiry(flowKey, valuePtr, checkState)
                if expired then
                    assert(ts)
                    self.maps[index]:erase(accs[index])
                    local event = ev.newEvent(buildPacketFilter(flowKey), ev.delete, nil, ts)
                    for _, pipe in ipairs(self.filterPipes) do
                        pipe:send(event)
                    end
                    deleteFlow(flows[i])
                    purged = purged + 1
                else
                    addToList(keepList, flows[i])
                    keep = keep + 1
                end
                accs[index]:release()
            end
            flows = keepList
            finalizer(checkState, keep, purged)
            local t2 = time()
            log:info("[Checker]: Done, took %fs, flows %i/%i/%i [purged/kept/total]", t2 - t1, purged, keep, purged+keep)
--             require("jit.p").stop()
        end
    end
--     require("jit.p").stop()
    for _, v in ipairs(accs) do
        v:free()
    end
    log:info("[Checker]: Shutdown")
end

function flowtracker:dumper(id, qq, path, filterPipe)
    pcap:setInitialFilesize(2^19) -- 0.5 MiB
    local ruleSet = {} -- Used to maintain the filter strings and pcap handles
    local handlers = {} -- Holds handle functions for the matcher
    local matcher = nil
    local currentTS = 0 -- Timestamp of the current packet. Used to expire rules and to pass a ts to the pcap writer
    local ruleCtr = 0
    local maxRules = self.maxDumperRules
    local needRebuild = true
    local rxCtr = stats:newManualRxCounter("Dumper", "plain")

    log:setLevel("INFO")

    require("jit.p").start("a")
    local handleEvent = function(event)
        if event == nil then
            return
        end
        log:debug("[Dumper]: Got event %i, %s, %i", event.action, event.filter, event.timestamp or 0)
        if event.action == ev.create and ruleSet[event.id] == nil and ruleCtr < maxRules then
            local triggerWallTime = wallTime()
            local pcapFileName = path .. "/" .. ("FlowScope-dump " .. os.date("%Y-%m-%d %H-%M-%S", triggerWallTime) .. " " .. event.id .. " part " .. id .. ".pcap"):gsub("[ /\\]", "_")
            local pcapWriter = pcap:newWriter(pcapFileName, triggerWallTime)
            ruleSet[event.id] = {filter = event.filter, pcap = pcapWriter}
            ruleCtr = ruleCtr + 1
            needRebuild = true
        elseif event.action == ev.delete and ruleSet[event.id] ~= nil then
            ruleSet[event.id].timestamp = event.timestamp
            log:info("[Dumper]: Marked rule %s as expired at %f, now %f", event.id, event.timestamp, currentTS)
        end
    end

    while lm.running(self.shutdownDelay) do
        -- Get new filters
        local event
        repeat
            event = filterPipe:tryRecv(10)
            handleEvent(event)
        until event == nil

        -- Check for expired rules
        for k, _ in pairs(ruleSet) do
            if ruleSet[k].timestamp and currentTS > ruleSet[k].timestamp then
                ruleSet[k].pcap:close()
                log:info("[Dumper #%i]: Expired rule %s, %f > %f", id, k, currentTS, ruleSet[k].timestamp)
                ruleSet[k] = nil
                ruleCtr = ruleCtr - 1
                needRebuild = true
            end
        end

        -- Rebuild matcher from ruleSet
        if needRebuild then
            handlers = {}
            local lines = {}
            local idx = 0
            for _, v in pairs(ruleSet) do
                idx = idx + 1
                handlers["h" .. idx] = function(data, l) v.pcap:write(currentTS, data, l) end -- We can't pass a timestamp through the pflua matcher directly, so we keep it in a local variable before calling it
                table.insert(lines, v.filter .. " => " .. "h" .. idx .. "()") -- Build line in pfmatch syntax
            end
            log:info("[Dumper]: total number of rules: %i", idx)
            local allLines = table.concat(lines, "\n")
            log:debug("[Dumper]: all rules:\n%s", allLines)
            --print(match.compile("match {" .. allLines .. "}", {source = true}))
            matcher = match.compile("match {" .. allLines .. "}")
            needRebuild = false
        end

        -- Filter packets
        local storage = qq:tryDequeue()
        if storage ~= nil then
            rxCtr:updateWithSize(storage:size(), 0)
            for i = 0, storage:size() - 1 do
                local pkt = storage:getPacket(i)
                local timestamp = pkt:getTimestamp()
                local data = pkt:getBytes()
                local len = pkt:getSize()
                currentTS = timestamp
                matcher(handlers, data, len)
            end
            storage:release()
        else
           lm.sleepMicrosIdle(10)
        end
        rxCtr:update(0, 0)
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
