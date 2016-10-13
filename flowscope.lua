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
	for i, dev in ipairs(args.dev) do
		args.dev[i] = device.config{
			port = dev,
			rxQueues = args.rxThreads,
			rssQueues = args.rxThreads
		}
	end
	device.waitForLinks()
	
	local qq = qq.createQQ(args.size)
	for i, dev in ipairs(args.dev) do
		for i = 0, args.rxThreads - 1 do
			moon.startTask("inserter", dev:getRxQueue(i), qq)
		end
	end
	for i = 1, args.analyzeThreads do
		moon.startTask("analyzer", qq, i, args.triggerExpr, args.triggerCode)
	end
	moon.startSharedTask("dumper", qq, args.path, args.dumpPast, args.dumpFuture, args.dumperExpr, args.dumperCode)
	moon.startSharedTask("signalTrigger")
	moon.waitForTasks()
	qq:delete()
end

function inserter(rxQueue, qq)
	-- the inserter is C++ in libqq to get microsecond-level software timestamping precision
	qq:inserterLoop(rxQueue)
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

function analyzer(qq, id, expr, code)
	local filter
	if expr then
		local pfFilter = pf.compile_filter(expr)
		filter = function(pkt)
			return pfFilter(pkt.data, pkt.len)
		end
	else
		filter = dofile(code)
	end
	local rxCtr = stats:newManualRxCounter("QQ Analyzer Thread #" .. id, "plain")
	while moon.running() do
		local storage = qq:peek()
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			rxCtr:updateWithSize(1, pkt.len)
			if filter(pkt) then
				handleTrigger(pkt)
			end
		end
		storage:release()
	end
	rxCtr:finalize()
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

