local phobos = require "phobos"
local device = require "device"
local stats  = require "stats"
local pktLib = require "packet"
local ns     = require "namespaces"
local log    = require "log"
local pcap   = require "pcap"

local qq          = require "qq"

function configure(parser)
	parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
	parser:option("--rx-threads", "Number of rx threads per device."):convert(tonumber):default(1):target("rxThreads")
	parser:option("--analyze-threads", "Number of analyzer threads."):convert(tonumber):default(1):target("analyzeThreads")
	parser:option("--path", "Path for output pcaps."):default(".")
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
	
	local qq = qq.createQQ()
	for i, dev in ipairs(args.dev) do
		for i = 0, args.rxThreads - 1 do
			phobos.startTask("inserter", dev:getRxQueue(i), qq)
		end
	end
	for i = 1, args.analyzeThreads do
		phobos.startTask("analyzer", qq, i)
	end
	phobos.startSharedTask("dumper", qq, args.path)
	phobos.waitForTasks()
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
			return
		end
		log:info("Found trigger packet, notifying dumper thread.")
		pkt:dump()
		trigger.pkt = pkt:clone()
		trigger.triggered = pkt:getTimestamp()
	end)
end

function analyzer(qq, id)
	local rxCtr = stats:newManualRxCounter("QQ Analyzer Thread #" .. id, "plain")
	while phobos.running() do
		local storage = qq:peek()
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			rxCtr:updateWithSize(1, pkt.len)
			local udpPkt = pktLib.getUdpPacket(pkt)
			if udpPkt.udp:getDstPort() == 60000 then
				handleTrigger(pkt)
			end
		end
		storage:release()
	end
	print("analyzer stopped")
	rxCtr:finalize()
end

function dumper(qq, path)
	-- this loop currently supports only one running dumper
	while phobos.running() do
		local triggered
		local triggerPkt
		while not triggered and phobos.running() do
			trigger.lock(function()
				if trigger.triggered then
					triggered = trigger.triggered
					triggerPkt = trigger.pkt
				end
			end)
			phobos.sleepMillisIdle(10)
		end
		if not phobos.running() then
			return
		end
		-- we currently only sync once to systime at the trigger point
		-- this clock will drift slightly for longer captures
		-- (no, NUMA is not a problem, TSC is synced across CPUs since they share the same reference clock and reset)
		local triggerWallTime = wallTime() - (phobos.getTime() - triggered)
		local pcapFileName = path .. "/FlowScope-dump-" .. os.date("%Y-%m-%d %H:%M:%S", triggerWallTime) .. ".pcap"
		local pcapWriter = pcap:newWriter(pcapFileName, triggerWallTime - triggered)
		log:info("Dumper starting to write %s", pcapFileName)
		while phobos.running() do
			local storage = qq:tryDequeue()
			if storage ~= nil then
				for i = 0, storage:size() - 1 do
					local pkt = storage:getPacket(i)
					local udpPkt = pktLib.getUdpPacket(pkt)
					local triggerUdpPkt = pktLib.getUdpPacket(triggerPkt)
				
					if udpPkt.ip4:getSrc() == triggerUdpPkt.ip4:getSrc() then
						local ts = pkt:getTimestamp()
						print(phobos.getTime(), ts - triggered)
						pcapWriter:write(pkt:getTimestamp(), pkt.data, pkt.len)
					end
				end
		
				storage:release()
			end
		end
		print("closing")
		pcapWriter:close()
	end
end

