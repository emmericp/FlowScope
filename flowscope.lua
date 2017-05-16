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
	parser:option("--rx-threads", "Number of rx threads per device."):convert(tonumber):default("1"):target("rxThreads")
	parser:option("--analyze-threads", "Number of analyzer threads."):convert(tonumber):default("1"):target("analyzeThreads")
	parser:option("--dump-past", "Time to dump before the trigger point in seconds. (default: as far back as possible)"):convert(tonumber):default(math.huge):target("dumpPast")
	parser:option("--dump-future", "Time to dump after the trigger point in seconds."):convert(tonumber):default("10"):target("dumpFuture")
	parser:option("--path", "Path for output pcaps."):default(".")
	parser:mutex(
		parser:option("--trigger-expr", "pcap filter for trigger packets."):target("triggerExpr"),
		parser:option("--trigger-code", "Lua file returning a filter function (see filter-examples/trigger-*.lua)."):target("triggerCode")
	)
	parser:mutex(
		parser:option("--dumper-expr", "pcap filter for dumping packets. Use $srcIP $dstIP $srcPort $dstPort $proto to refer to the packet that triggered the dumper."):target("dumperExpr"),
		parser:option("--dumper-code", "Lua file returning a function that builds a filter function from the trigger packet (see filter-examples/dumper-*.lua)."):target("dumperCode")
	)
	local args = parser:parse()
	if not args.triggerExpr and not args.triggerCode then
		parser:error("either --trigger-expr or --trigger-code must be specified")
	end
	if not args.dumperExpr and not args.dumperCode then
		parser:error("either --dumper-expr or --dumper-code must be specified")
	end
	return args
end

local trigger = ns.get()

function master(args)
-- 	for i, dev in ipairs(args.dev) do
-- 		args.dev[i] = device.config{
-- 			port = dev,
-- 			rxQueues = args.rxThreads,
-- 			rssQueues = args.rxThreads
-- 		}
-- 	end
-- 	device.waitForLinks()
	
	local qq = qq.createQQ(args.size)
	for i, dev in ipairs(args.dev) do
		for i = 0, args.rxThreads - 1 do
			moon.startTask("traffic_generator", qq, i)
			--moon.startTask("inserter", dev:getRxQueue(i), qq)
		end
	end
	local tracker = flowtracker.createHashmap(2^24, "map 0")
	for i = 1, args.analyzeThreads do
		moon.startTask("batchedAnalyzer", qq, i, tracker)
	end
	for i = 1, 1 do
		moon.startTask("continuousDumper", qq, i)
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


-- FIXME: Use libmoon packet library instead of zeroed buffer
function traffic_generator(qq, id, packetSize, newFlowRate, rate)
	local packetSize = packetSize or 64
	local newFlowRate = newFlowRate or 3000
	local rate = rate or 10
	local baseIP = parseIPAddress("10.0.0.2")
	local txCtr = stats:newManualTxCounter("Generator Thread #" .. id, "plain")
	local rateLimiter = timer:new(1.0 / rate) -- buckets/s
	local newFlowTimer = timer:new(1.0 / newFlowRate) -- new flows/s
	
	local buf = {}
	buf["ptr"] = ffi.new("uint8_t[?]", packetSize)
	buf["getData"] = function() return ffi.cast("void*", buf.ptr) end
	local pkt = pktLib.getUdp4Packet(buf)
	pkt:fill{pktLength = packetSize}
	pkt.ip4.src:set(baseIP - 1)
	pkt.ip4.dst:set(baseIP)
	pkt.ip4:setProtocol(ip.PROTO_UDP)
	pkt.udp:setSrcPort(1000)
	pkt.udp:setDstPort(2000)
	pkt:dump()
	
	while moon.running() do
		local s1 = qq:enqueue()
		local ts = moon.getTime()
		repeat
			pkt.ip4.dst:set(baseIP + math.random(0, 2^8))
		until not s1:store(ts, 0, packetSize, buf.ptr)
		txCtr:updateWithSize(s1:size(), packetSize)
		s1:release()
		if newFlowTimer:expired() then
			baseIP = baseIP + 1
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
		print(green("[QQ] Stored buckets: ") .. qq:size() .. "/" .. qq:capacity())
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

function batchedAnalyzer(qq, id, tracker)
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

function continuousDumper(qq, id, path)
	local rxCtr = stats:newManualRxCounter("QQ Dumper Thread   #" .. id, "plain")
	while moon.running() do
		local storage = qq:dequeue()
		local size = storage:size()
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			local timestamp = pkt:getTimestamp()
			rxCtr:updateWithSize(1, pkt:getLength())
		end
		storage:release()
	end
	rxCtr:finalize()
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

