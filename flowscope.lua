local moon   = require "libmoon"
local device = require "device"
local stats  = require "stats"
local pktLib = require "packet"
local eth    = require "proto.ethernet"
local ip     = require "proto.ip4"
local ns     = require "namespaces"
local log    = require "log"
local pcap   = require "pcap"
local pf     = require "pf"
local qq     = require "qq"
local S      = require "syscall"
local ffi    = require "ffi"
local colors = require "colors"
local pipe   = require "pipe"
local timer  = require "timer"
local flowtracker = require "flowtracker"

function configure(parser)
	parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
	parser:option("--size", "Storage capacity of the in-memory ring buffer in GiB."):convert(tonumber):default("8")
	parser:option("--rate", "Rate of the generated traffic in buckets/s."):convert(tonumber):default("10")
	parser:option("--rx-threads", "Number of rx threads per device. If --generate is give, then number of traffic generator threads."):convert(tonumber):default("1"):target("rxThreads")
	parser:option("--analyze-threads", "Number of analyzer threads."):convert(tonumber):default("1"):target("analyzeThreads")
	parser:option("--dump-threads", "Number of dump threads."):convert(tonumber):default("1"):target("dumperThreads")
	parser:option("--path", "Path for output pcaps."):default(".")
	parser:flag("--generate", "Generate traffic instead of reading from a device"):default(False)
	local args = parser:parse()
	return args
end

local trigger = ns.get()

function master(args)
	if not args.generate then
		for i, dev in ipairs(args.dev) do
			args.dev[i] = device.config{
				port = dev,
				rxQueues = args.rxThreads,
				rssQueues = args.rxThreads
			}
		end
		device.waitForLinks()
	end
	
	local qq = qq.createQQ(args.size)
	for i, dev in ipairs(args.dev) do
		for i = 0, args.rxThreads - 1 do
			if args.generate then
				moon.startTask("traffic_generator", qq, i, nil, 0.00001, args.rate)
			else
				moon.startTask("inserter", dev:getRxQueue(i), qq)
			end
		end
	end
	
	local pipes = {}
	for i = 1, args.dumperThreads do
		pipes[i] = pipe.newSlowPipe()
		moon.startTask("continuousDumper", qq, i, "./dumps", pipes[i])
	end
	
-- 	local tracker = flowtracker.createHashmap(2^24, "map 0")
	local tracker = flowtracker.createFlowtracker(2^24, "map 0")
-- 	local tracker = flowtracker.createLeapfrog()
	for i = 1, args.analyzeThreads do
-- 		moon.startTask("batched_rte_hash_Analyzer", qq, i, tracker, pipes)
		moon.startTask("batched_flowtracker_Analyzer", qq, i, tracker, pipes)
-- 		moon.startTask("dummyAnalyzer", qq, i)
-- 		moon.startTask("leapfrogAnalyzer", qq, i, tracker, pipes[i])
	end
	
	for i, v in ipairs(pipes) do
		-- libmoon has no destroy function for pipes
	end
	
	--moon.startSharedTask("signalTrigger")
	moon.startSharedTask("fillLevelChecker", qq)
	--moon.startTask("fillLevelChecker", qq)
	moon.waitForTasks()
	tracker:delete()
	qq:delete()
end

function inserter(rxQueue, qq)
	-- the inserter is C++ in libqq to get microsecond-level software timestamping precision
	qq:inserterLoop(rxQueue)
end

function traffic_generator(qq, id, packetSize, newFlowRate, rate)
	local packetSize = packetSize or 64
	local newFlowRate = newFlowRate or 0.5 -- new flows/s
	local concurrentFlows = 1
	local rate = rate or 20 -- buckets/s
	local baseIP = parseIPAddress("10.0.0.2")
	local txCtr = stats:newManualTxCounter("Generator Thread #" .. id, "plain")
	local rateLimiter = timer:new(1.0 / rate)
	local newFlowTimer = timer:new(1.0 / newFlowRate)
	
	local buf = {}
	buf["ptr"] = ffi.new("uint8_t[?]", packetSize)
	buf["getData"] = function() return ffi.cast("void*", buf.ptr) end
	local pkt = pktLib.getUdp4Packet(buf)
	pkt:fill{pktLength = packetSize}
	pkt.ip4.src:set(baseIP - 1)
	pkt.ip4.dst:set(baseIP)
	pkt.ip4:setProtocol(ip.PROTO_UDP)
	pkt.ip4:setTTL(64)
	pkt.udp:setSrcPort(1000)
	pkt.udp:setDstPort(2000)
	pkt:dump()
	
	while moon.running() do
		local s1 = qq:enqueue()
		local ts = moon.getTime()
		repeat
-- 			pkt.ip4.dst:set(baseIP)
			pkt.ip4.dst:set(baseIP + math.random(0, concurrentFlows))
			if math.random(0, 10000000) == 0 then
				pkt.ip4:setTTL(70)
			else
				pkt.ip4:setTTL(64)
			end
		until not s1:store(ts, 0, packetSize, buf.ptr)
		txCtr:updateWithSize(s1:size(), packetSize)
		s1:release()
		if newFlowTimer:expired() then
-- 			baseIP = baseIP + 1
			newFlowTimer:reset()
		end
		rateLimiter:wait()
		rateLimiter:reset()
	end
	txCtr:finalize()
end

local function handleTrigger(pkt)
	trigger.lock(function()
		if trigger.triggered then
			-- only one concurrent dumper at the moment
			log:warn("Found second trigger packet while dumper is running - concurrent dumpers are NYI.")
			return
		end
		log:info("Found trigger packet, notifying dumper thread.")
		if pkt then 
			pkt:dump()
			trigger.pkt = pkt:clone()
			trigger.triggered = pkt:getTimestamp()
		else -- not triggered by a packet but a signal
			trigger.triggered = moon.getTime()
		end
	end)
end

function fillLevelChecker(qq)
	while moon.running() do
		print(green("[QQ] Stored buckets: ") .. qq:size() .. "/" .. qq:capacity() .. green(" Overflows: ") .. qq:getEnqueueOverflowCounter())
		moon.sleepMillisIdle(1000)
	end
end

local signallib = ffi.load("build/sigusr")
ffi.cdef[[
	void install_signal_handler();
	bool check_signal();
]]

-- I'm too stupid to use the syscall library with SIGUSR1, so this is done in C
function signalTrigger()
	signallib.install_signal_handler()
	while moon.running() do
		if signallib.check_signal() then
			handleTrigger()
		end
		moon.sleepMillisIdle(1)
	end
end

fooModule = {
	rxCtr = stats:newManualRxCounter("FooModule #1", "plain"),
	bar = function(pkt) end
}

function fooModule:analyze(pkt)
	self.rxCtr:updateWithSize(1, pkt:getLength())
end

function fooModule:done()
	self.rxCtr:finalize()
end

-- TODO
function buildFilterExpr(pkt)
	return "src host " .. pkt.ip4.src:getString() .. " src port " .. pkt.udp:getSrcPort() .. 
			" dst host " .. pkt.ip4.dst:getString() .. " dst port " .. pkt.udp:getDstPort()
end

function leapfrogAnalyzer(qq, id, hashmap, filterPipe)
	local hashmap = hashmap
	local ctx = flowtracker.QSBRCreateContext()
	local rxCtr = stats:newManualRxCounter("QQ Leapfrog Thread #" .. id, "plain")
	local epsilon = 2  -- allowed area around the avrg. TLL
	
	-- dummy filter for testing
	filterPipe:send("src host 10.0.0.1")
	
	local tuple = ffi.new("struct ipv4_5tuple")
	
	while moon.running() do
		local storage = qq:peek()
		for i = 0, storage:size() - 1 do
-- 			print("leapfrog 0", i)
			local pkt = storage:getPacket(i)
			rxCtr:updateWithSize(1, pkt.len)
			local parsedPkt = pktLib.getUdp4Packet(pkt)
			tuple.ip_dst = parsedPkt.ip4:getDst()
			tuple.ip_src = parsedPkt.ip4:getSrc()
			tuple.port_dst = parsedPkt.udp:getDstPort()
			tuple.port_src = parsedPkt.udp:getSrcPort()
			tuple.proto = parsedPkt.ip4:getProtocol()

			local hash = tuple:hash()
-- 			print("leapfrog 1", hash)
			local TTL = parsedPkt.ip4:getTTL()
			
			local res = hashmap:get(hash)
			if res ~= 0ULL and 
					(TTL > flowtracker.getAverageTTL(res) + epsilon or
					TTL < flowtracker.getAverageTTL(res) - epsilon) then
				print("Anomaly detected")
			end
			
-- 			print("leapfrog 2", "TTL:", TTL, "res:", res)
			local val = flowtracker.updateTTL(res, TTL)
-- 			if val == 0ULL or val == 1ULL then
-- 				print("hash can not be 0 or 1")
-- 				moon.stop()
-- 			end
-- 			print("leapfrog 3", val)
			local other = hashmap:exchange(hash, val)
-- 			print("leapfrog 4", other)
			
			-- Analyze
			
			-- Send new filters
			--local newFilter = "udp port 1111"
			--filterPipe:send(newFilter)
			
-- 			if res == 0ULL then -- 0 = not found
-- 				local val = flowtracker.updateTTL(0ULL, parsedPkt.ip4:getTTL())
-- 				hashmap:set(tuple:hash(), val)
-- 			else
-- 				local val = flowtracker.updateTTL(res, parsedPkt.ip4:getTTL())
-- 				hashmap:set(tuple:hash(), val)
-- 			end
		end
		
		
		storage:release()
		flowtracker.QSBRUpdateContext(ctx)
	end
	
	rxCtr:finalize()
	flowtracker.QSBRDestroyContext(ctx)
end

function batched_rte_hash_Analyzer(qq, id, tracker, pipes)
	local batchsize = 64
	local addCtr = 0
	local flowdata = ffi.new("struct foo_flow_data")
	local tupleBatch = ffi.new("struct ipv4_5tuple[?]", batchsize)
	local keyPtr = ffi.new("const void *[?]", batchsize)
	for i = 0, batchsize do
		keyPtr[i] = tupleBatch + i
	end
	print(keyPtr[3], tupleBatch + 3)
	local positionsBatch = ffi.new("int32_t[?]", batchsize)
	local rxCtr = stats:newManualRxCounter("QQ Analyzer Thread #" .. id, "plain")
	while moon.running() do
		local storage = qq:peek()
		
		for i = 0, storage:size() - 1 - batchsize, batchsize do
			for j = 0, batchsize - 1 do
				--print("Build phase", "i:", i, "j:", j)
				local pkt = storage:getPacket(i + j)
				rxCtr:updateWithSize(1, pkt.len)
				local parsedPkt = pktLib.getUdp4Packet(pkt)
				tupleBatch[j].ip_dst = parsedPkt.ip4:getDst()
				tupleBatch[j].ip_src = parsedPkt.ip4:getSrc()
				tupleBatch[j].port_dst = parsedPkt.udp:getDstPort()
				tupleBatch[j].port_src = parsedPkt.udp:getSrcPort()
				tupleBatch[j].proto = parsedPkt.ip4:getProtocol()
			end
			
			--print("Performing lookup")
			local r = tracker:lookupBatch(keyPtr, batchsize, positionsBatch)
			--print("Lookup done")
			if r < 0 then
				print("Batch lookup failed")
				break
			end
			
			for i = 0, batchsize - 1 do
				if positionsBatch[i] < 0 then
					local r = tracker:add_key(tupleBatch[i])
					if r < 0 then
						print(id, "Add error:", r, "inserted items:", addCtr)
						moon:stop()
					end
					addCtr = addCtr + 1
				end
			end
		end
		-- TODO handle rest
		storage:release()
	end
	rxCtr:finalize()
	print("[QQ Analyzer] Added flows:", addCtr)
end

function dummyAnalyzer(qq, id)
	local rxCtr = stats:newManualRxCounter("QQ Dummy Analyzer Thread #" .. id, "plain")
	while moon.running() do
		local storage = qq:peek()
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			rxCtr:updateWithSize(1, pkt.len)
		end
		storage:release()
	end
	rxCtr:finalize()
end

function batched_flowtracker_Analyzer(qq, id, tracker, pipes)
	for i, pipe in ipairs(pipes) do
		print("Analyzer", pipe)
	end
	
	print("got", #pipes, "pipes")
	local epsilon = 2
	local batchsize = 64
	local addCtr = 0
	local flowdata = ffi.new("D") -- Reuse for every packet, the hash table copies it anyway
	flowdata.rolling_sum = 0
	flowdata.packet_counter = 1 -- Wrong, but atleast not a div by zero
	local tupleBatch = ffi.new("struct ipv4_5tuple[?]", batchsize)
	local keyPtr = ffi.new("const void *[?]", batchsize) -- needed for DPDK bulk lookup, cf. "bulk lookup explained.svg"
	for i = 0, batchsize do
		keyPtr[i] = tupleBatch + i
	end
	local dataPtrs = ffi.new("D* [?]", batchsize)
	local positionsBatch = ffi.new("int32_t[?]", batchsize)
	local rxCtr = stats:newManualRxCounter("QQ Analyzer Thread #" .. id, "plain")
	while moon.running() do
		local storage = qq:peek()
		
		-- TODO handle uneven batch sizes
		for i = 0, storage:size() - 1 - batchsize, batchsize do
			local TTLs = {}
			for j = 0, batchsize - 1 do
				local pkt = storage:getPacket(i + j)
				rxCtr:updateWithSize(1, pkt.len)
				local parsedPkt = pktLib.getUdp4Packet(pkt)
				tupleBatch[j].ip_dst = parsedPkt.ip4:getDst()
				tupleBatch[j].ip_src = parsedPkt.ip4:getSrc()
				tupleBatch[j].port_dst = parsedPkt.udp:getDstPort()
				tupleBatch[j].port_src = parsedPkt.udp:getSrcPort()
				tupleBatch[j].proto = parsedPkt.ip4:getProtocol()
				TTLs[j] = parsedPkt.ip4:getTTL()
			end
			
			::try_again::
			local r = tracker:lookupBatch4(keyPtr, batchsize, dataPtrs)
			if r < 0 then
				print("Batch lookup failed")
				break
			end
			
			for j = 0, batchsize - 1 do
				if dataPtrs[j] == nil then
					flowdata.rolling_sum = TTLs[j]  -- Set inital TTL
					local r = tracker:addFlow4(tupleBatch[j], flowdata)
					if r < 0 then
						print(id, "Add error:", r, "inserted items:", addCtr)
						moon:stop()
					end
					print(bred("[QQ Analyzer Thread #".. id .."]") .. ": New flow!", tupleBatch[j].ip_dst, tupleBatch[j].port_dst, tupleBatch[j].ip_src, tupleBatch[j].port_src)
					addCtr = addCtr + 1
					goto try_again -- This is crucial. If a new flow got added, the batch is worthless since it could contain multiple packets of the flow that just got added
				else
					local avrgTTL = dataPtrs[j].rolling_sum / dataPtrs[j].packet_counter
					if (TTLs[j] > avrgTTL + epsilon or
							TTLs[j] < avrgTTL - epsilon) then
						local parsedPkt = pktLib.getUdp4Packet(storage:getPacket(i + j))
						local event = {action = "create", filter = buildFilterExpr(parsedPkt)}
						print(bred("[QQ Analyzer Thread #".. id .."]") .. ": Anomaly detected", dataPtrs[j].rolling_sum, dataPtrs[j].packet_counter, avrgTTL, TTLs[j], event.action, event.filter)
						for _, pipe in ipairs(pipes) do
							pipe:send(event)
						end
					end
					-- FIXME: make atomic
					dataPtrs[j].rolling_sum = dataPtrs[j].rolling_sum + TTLs[j]
					dataPtrs[j].packet_counter = dataPtrs[j].packet_counter + 1
				end
			end
		end
		storage:release()
	end
	rxCtr:finalize()
	print("[QQ Analyzer #" .. id .. "] Added flows:", addCtr)
end

function analyzer(qq, id, tracker)
	local tracker = tracker or flowtracker.createHashmap(2^20, "map " .. tostring(id))
	local flowdata = ffi.new("struct foo_flow_data")
	local tuple = ffi.new("struct ipv4_5tuple")
	local rxCtr = stats:newManualRxCounter("QQ Analyzer Thread #" .. id, "plain")
	while moon.running() do
		local storage = qq:peek()
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			rxCtr:updateWithSize(1, pkt.len)
			
			local parsedPkt = pktLib.getUdp4Packet(pkt)
			tuple.ip_dst = parsedPkt.ip4:getDst()
			tuple.ip_src = parsedPkt.ip4:getSrc()
			tuple.port_dst = parsedPkt.udp:getDstPort()
			tuple.port_src = parsedPkt.udp:getSrcPort()
			tuple.proto = parsedPkt.ip4:getProtocol()
			
			if tracker:lookup(tuple) < 0 then
				local r = tracker:add_key(tuple)
				if r < 0 then
					print("Add error:", r)
				end
			end
		end
		storage:release()
	end
	rxCtr:finalize()
	--tracker:delete()
end

local function filterDumperPacket(pkt)
	local udpPkt = pktLib.getUdpPacket(pkt)
	local triggerUdpPkt = pktLib.getUdpPacket(triggerPkt)
	if udpPkt.ip4:getSrc() == triggerUdpPkt.ip4:getSrc() then
		return true
	end
end

-- replace $foo in the dumper filter with values from the trigger packet
local function fillExprFromPacket(expr, triggerPkt)
	-- default values
	local replacements = {
		srcIP = "0.0.0.0", 
		dstIP = "0.0.0.0",
		srcPort = 0,
		dstPort = 0,
		proto = "udp"
	}
	if triggerPkt then -- triggerPkt will be nil if triggered by SIGUSR1
		local pkt = pktLib.getEthPacket(triggerPkt)
		if pkt.eth:getType() == eth.TYPE_IP then
			-- actual L4 type doesn't matter
			local pkt = pktLib.getUdp4Packet(triggerPkt)
			replacements.srcIP = pkt.ip4:getSrcString()
			replacements.dstIP = pkt.ip4:getDstString()
			if pkt.ip4:getProtocol() == ip.PROTO_UDP then
				replacements.srcPort = pkt.udp:getSrcPort()
				replacements.dstPort = pkt.udp:getDstPort()
				replacements.proto = "udp"
			elseif pkt.ip4:getProtocol() == ip.PROTO_TCP then
				-- port at the same position as UDP
				replacements.srcPort = pkt.udp:getSrcPort()
				replacements.dstPort = pkt.udp:getDstPort()
				replacements.proto = "tcp"
			elseif pkt.ip4:getProtocol() == ip.PROTO_SCTP then
				-- port at the same position as UDP
				replacements.srcPort = pkt.udp:getSrcPort()
				replacements.dstPort = pkt.udp:getDstPort()
				replacements.proto = "sctp"
			else
				replacements.proto = "ip"
			end
		elseif pkt.eth:getType() == eth.TYPE_IP6 then
			local pkt = pktLib.getUdp6Packet(triggerPkt)
			replacements.srcIP = pkt.ip6:getSrcString()
			replacements.dstIP = pkt.ip6:getDstString()
			if pkt.ip6:getNextHeader() == ip.PROTO_UDP then
				replacements.srcPort = pkt.udp:getSrcPort()
				replacements.dstPort = pkt.udp:getDstPort()
				replacements.proto = "udp"
			elseif pkt.ip6:getNextHeader() == ip.PROTO_TCP then
				-- port at the same position as UDP
				replacements.srcPort = pkt.udp:getSrcPort()
				replacements.dstPort = pkt.udp:getDstPort()
				replacements.proto = "tcp"
			elseif pkt.ip6:getNextHeader() == ip.PROTO_SCTP then
				-- port at the same position as UDP
				replacements.srcPort = pkt.udp:getSrcPort()
				replacements.dstPort = pkt.udp:getDstPort()
				replacements.proto = "sctp"
			else
				replacements.proto = "ip"
			end
		end
	end
	return (expr:gsub("(%$%w*)", function(m) return replacements[m:sub(2)] end))
end

local function clearTrigger()
	trigger.pkt = nil
	trigger.triggered = nil
end

function continuousDumper(qq, id, path, filterPipe)
	local ruleSet = {} -- Used to maintain the rules
	local ruleList = {} -- Build from the ruleSet for performance
	local rxCtr = stats:newManualRxCounter("QQ Dumper Thread   #" .. id, "plain")
	local ruleExpirationTimer = timer:new(30)
	
	while moon.running() do
-- 		if ruleExpirationTimer:expired() then
-- 			print("Filter rules expired")
-- 			for _, rule in ipairs(ruleList) do
-- 				if rule.pcap then
-- 					rule.pcap:close()
-- 				end
-- 			end
-- 			ruleExpirationTimer:reset()
-- 		end
		
		-- Get new filters
		local event = filterPipe:tryRecv(0)
		if event ~= nil then
			if event.action == "create" then
				ruleSet[event.filter] = {}
-- 				print("Dumper #" .. id .. ": new rule", ruleSet[#ruleSet], ruleSet[#ruleSet].pfFn, ruleSet[#ruleSet].pcap, ruleSet[#ruleSet].filter)
			elseif event.action == "delete" then
				-- TODO: handle expire etc
				ruleSet[event.filter] = nil
			end
			
			-- Update ruleList
			ruleList = {}
			for expr, _ in pairs(ruleSet) do
				local triggerWallTime = wallTime()
				local pcapFileName = path .. "/FlowScope-dump_" .. os.date("%Y-%m-%d %H:%M:%S", triggerWallTime) .. "_" .. event.filter .. ".pcap"
				local pcapWriter = pcap:newWriter(pcapFileName, triggerWallTime)
				ruleList[#ruleList+1] = {pfFn = pf.compile_filter(event.filter), pcap = pcapWriter}
-- 				ruleList[#ruleList+1] = {pfFn = function() end, pcap = nil}
			end
			print("Dumper #" .. id .. ": total number of rules:", #ruleList)
		end
		
		local storage = qq:dequeue()
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			local timestamp = pkt:getTimestamp()
			rxCtr:updateWithSize(1, pkt:getLength())
			
			-- ipairs: 20 Mpps
			-- pairs: 1.6 Mpps
			-- WTF??
			for _, rule in ipairs(ruleList) do
				if rule.pfFn(pkt.data, pkt.len) then
-- 						print("Dumper #" .. id .. ": Got match!")
						if rule.pcap then
							rule.pcap:write(timestamp, pkt.data, pkt.len)
						end
				end
			end
		end
		storage:release()
	end
	rxCtr:finalize()
	for _, rule in ipairs(ruleList) do
		if rule.pcap then
			rule.pcap:close()
		end
	end
end

function dumper(qq, path, dumpPast, dumpFuture, expr, code)
	-- this loop currently supports only one running dumper
	while moon.running() do
		local triggered
		local triggerPkt
		while not triggered and moon.running() do
			trigger.lock(function()
				if trigger.triggered then
					triggered = trigger.triggered
					triggerPkt = trigger.pkt
				end
			end)
			moon.sleepMillisIdle(10)
		end
		if not moon.running() then
			return
		end
		local filter
		if expr then
			local substitutedExpr = fillExprFromPacket(expr, triggerPkt)
			log:info("Using filter '%s' to dump pcap", substitutedExpr)
			local pfFilter = pf.compile_filter(substitutedExpr)
			filter = function(pkt)
				return pfFilter(pkt.data, pkt.len)
			end
		else
			filter = dofile(code)(triggerPkt)
		end
		-- we currently only sync once to systime at the trigger point
		-- this clock will drift slightly for longer captures
		-- (no, reasonable NUMA setups are not a problem, TSC is synced across CPUs since they share the same reference clock and reset)
		local triggerWallTime = wallTime() - (moon.getTime() - triggered)
		local pcapFileName = path .. "/FlowScope-dump-" .. os.date("%Y-%m-%d %H:%M:%S", triggerWallTime) .. ".pcap"
		local pcapWriter = pcap:newWriter(pcapFileName, triggerWallTime - triggered)
		log:info("Dumper starting to write %s", pcapFileName)
		local stopDump = false
		local progressShown = -math.huge
		local dumpDuration
		while moon.running() and not stopDump do
			local storage = qq:tryDequeue()
			if storage ~= nil then
				local size = storage:size()
				for i = 0, storage:size() - 1 do
					local pkt = storage:getPacket(i)
					local timestamp = pkt:getTimestamp()
					local relativeTimestamp = timestamp - triggered
					if relativeTimestamp > dumpFuture then
						stopDump = true
						break
					end
					if relativeTimestamp > -dumpPast then
						if not dumpDuration then
							dumpDuration = dumpFuture - relativeTimestamp
							log:info("Dumper starting at %.1f seconds before trigger", -math.abs(relativeTimestamp))
						end
						if relativeTimestamp > progressShown + dumpDuration / 10 then
							log:info("Dumper at %.1f/%.1f seconds", relativeTimestamp, dumpFuture)
							progressShown = relativeTimestamp
						end
						if filter(pkt) then
							pcapWriter:write(timestamp, pkt.data, pkt.len)
						end
					end
				end
				storage:release()
			end
		end
		clearTrigger()
		log:info("Flushing pcap file")
		pcapWriter:close()
	end
end

