local moon   = require "libmoon"
local device = require "device"
local stats  = require "stats"
local pktLib = require "packet"
local eth    = require "proto.ethernet"
local ip     = require "proto.ip4"
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
local ev = require "event"

local jit = require "jit"
jit.opt.start("maxrecord=10000", "maxirconst=1000", "loopunroll=40")


function configure(parser)
	parser:argument("dev", "Devices to use."):args("+"):convert(tonumber)
	parser:option("--size", "Storage capacity of the in-memory ring buffer in GiB."):convert(tonumber):default("8")
	parser:option("--rate", "Rate of the generated traffic in buckets/s."):convert(tonumber):default("10")
	parser:option("--rx-threads", "Number of rx threads per device. If --generate is give, then number of traffic generator threads."):convert(tonumber):default("1"):target("rxThreads")
	parser:option("--analyze-threads", "Number of analyzer threads."):convert(tonumber):default("1"):target("analyzeThreads")
	parser:option("--dump-threads", "Number of dump threads."):convert(tonumber):default("1"):target("dumperThreads")
	parser:option("--path", "Path for output pcaps."):default(".")
	parser:option("--log-level", "Log level"):default("WARN"):target("logLevel")
	parser:flag("--generate", "Generate traffic instead of reading from a device"):default(False)
	local args = parser:parse()
	return args
end

function master(args)
	log:setLevel(args.logLevel)
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
				moon.startTask("traffic_generator", args, qq, i, nil, 200, args.rate)
			else
				moon.startTask("inserter", dev:getRxQueue(i), qq)
			end
		end
	end
	
	local pipes = {}
	for i = 1, args.dumperThreads do
		pipes[i] = pipe.newSlowPipe()
		moon.startTask("continuousDumper", args, qq, i, args.path, pipes[i])
	end
	
-- 	local tracker = flowtracker.createTBBMapv4(2^20)

	local tracker = flowtracker.createTBBTracker(2^20)
	moon.startTask("swapper", args, tracker, pipes)
	
	for i = 1, args.analyzeThreads do
-- 		moon.startTask("dummyAnalyzer", qq, i)
-- 		moon.startTask("TBBAnalyzer", qq, i, tracker, pipes)
		moon.startTask("TBBTrackerAnalyzer", args, qq, i, tracker, pipes)
	end
	
	for i, v in ipairs(pipes) do
		-- libmoon has no destroy function for pipes
	end
	
	moon.startSharedTask("fillLevelChecker", args, qq)
	--moon.startTask("fillLevelChecker", args, qq)
	moon.waitForTasks()
	tracker:delete()
	qq:delete()
	log:info("[master]: Shutdown")
end

function inserter(rxQueue, qq)
	-- the inserter is C++ in libqq to get microsecond-level software timestamping precision
	qq:inserterLoop(rxQueue)
	log:info("[Inserter]: Shutdown")
end

function swapper(args, tracker, pipes)
	log:setLevel(args.logLevel)
	local sz = 256
	local buf = ffi.new("struct expired_flow4[?]", sz)
	while moon.running() do
		local c = tracker:swapper(buf, sz)
		for i = 0, tonumber(c) - 1 do
			local event = ev.newEvent(filterExprFromTuple(buf[i].tpl), ev.delete, nil, tonumber(buf[i].last_seen))
			log:info("[Swapper]: Sending event: %i, %s %i", event.action, event.filter, event.timestamp)
			for _, pipe in ipairs(pipes) do
				pipe:send(event)
			end
		end
	end
	log:info("[Swapper]: Shutdown")
end

function traffic_generator(args, qq, id, packetSize, newFlowRate, rate)
	log:setLevel(args.logLevel)
	local packetSize = packetSize or 64
	local newFlowRate = newFlowRate or 0.5 -- new flows/s
	local concurrentFlows = 1000
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
		local ts = moon.getTime() * 10^6
		repeat
-- 			pkt.ip4.dst:set(baseIP)
			pkt.ip4.dst:set(baseIP + math.random(0, concurrentFlows - 1))
			if math.random(0, 50000000) == 0 then
				pkt.ip4:setTTL(70)
			else
				pkt.ip4:setTTL(64)
			end
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
	log:info("[Traffic Generator]: Shutdown")
end

function fillLevelChecker(args, qq)
	log:setLevel(args.logLevel)
	while moon.running() do
		print(green("[QQ] Stored buckets: ") .. qq:size() .. "/" .. qq:capacity() .. green(" Overflows: ") .. qq:getEnqueueOverflowCounter())
		moon.sleepMillisIdle(1000)
	end
	log:info("[fillLevelChecker]: Shutdown")
end

function filterExprFromTuple(tpl)
	local s = ""
	local ipAddr = ffi.new("union ip4_address")
	ipAddr:set(tpl.ip_src)
	s = s .. "src host " .. ipAddr:getString()
	ipAddr:set(tpl.ip_dst)
	s = s .. " src port " .. tonumber(tpl.port_src)
	ipAddr:set(tpl.ip_dst)
	s = s .. " dst host " .. ipAddr:getString()
	s = s .. " dst port " .. tonumber(tpl.port_dst)

	-- L4 Protocol
	local proto = tpl.proto
	if proto == ip.PROTO_UDP then
		proto = " udp"
	elseif proto == ip.PROTO_TCP then
		proto = " tcp"
	else
		proto = ""
	end
	s = s .. proto
	return s
end

function TBBTrackerAnalyzer(args, qq, id, hashmap, pipes)
	log:setLevel(args.logLevel)
	local hashmap = hashmap
	local rxCtr = stats:newManualRxCounter("TBB Tracker Analyzer Thread #" .. id, "plain")
	local epsilon = 2  -- allowed area around the avrg. TLL
	local tuple = ffi.new("struct ipv4_5tuple")
	
	local acc = flowtracker.createAccessor()
	
	while moon.running() do
		local storage = qq:tryPeek()
		if storage == nil then
			goto continue
		end
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			rxCtr:updateWithSize(1, pkt.len)
			local TTL
			local lookup = false
			-- Parsing begins
			local ethPkt = pktLib.getEthernetPacket(pkt)
			if ethPkt.eth:getType() == eth.TYPE_IP then
				-- actual L4 type doesn't matter
				local parsedPkt = pktLib.getUdp4Packet(pkt)
				tuple.ip_dst = parsedPkt.ip4:getDst()
				tuple.ip_src = parsedPkt.ip4:getSrc()
				TTL = parsedPkt.ip4:getTTL()
				if parsedPkt.ip4:getProtocol() == ip.PROTO_UDP then
					tuple.port_dst = parsedPkt.udp:getDstPort()
					tuple.port_src = parsedPkt.udp:getSrcPort()
					tuple.proto = parsedPkt.ip4:getProtocol()
					lookup = true
				elseif parsedPkt.ip4:getProtocol() == ip.PROTO_TCP then
					-- port at the same position as UDP
					tuple.port_dst = parsedPkt.udp:getDstPort()
					tuple.port_src = parsedPkt.udp:getSrcPort()
					tuple.proto = parsedPkt.ip4:getProtocol()
					lookup = true
				elseif parsedPkt.ip4:getProtocol() == ip.PROTO_SCTP then
					-- port at the same position as UDP
					tuple.port_dst = parsedPkt.udp:getDstPort()
					tuple.port_src = parsedPkt.udp:getSrcPort()
					tuple.proto = parsedPkt.ip4:getProtocol()
					lookup = true
				end
-- 			elseif ethPkt.eth:getType() == eth.TYPE_IP6 then
-- 				local parsedPkt = pktLib.getUdp6Packet(pkt)
-- 				replacements.srcIP = pkt.ip6:getSrcString()
-- 				replacements.dstIP = pkt.ip6:getDstString()
-- 				TTL = parsedPkt.ip6:getTTL()
-- 				if parsedPkt.ip6:getNextHeader() == ip.PROTO_UDP then
-- 					tuple.port_dst = parsedPkt.udp:getDstPort()
-- 					tuple.port_src = parsedPkt.udp:getSrcPort()
-- 					tuple.proto = parsedPkt.ip4:getProtocol()
-- 				elseif parsedPkt.ip6:getNextHeader() == ip.PROTO_TCP then
-- 					-- port at the same position as UDP
-- 					tuple.port_dst = parsedPkt.udp:getDstPort()
-- 					tuple.port_src = parsedPkt.udp:getSrcPort()
-- 					tuple.proto = parsedPkt.ip4:getProtocol()
-- 				elseif parsedPkt.ip6:getNextHeader() == ip.PROTO_SCTP then
-- 					-- port at the same position as UDP
-- 					tuple.port_dst = parsedPkt.udp:getDstPort()
-- 					tuple.port_src = parsedPkt.udp:getSrcPort()
-- 					tuple.proto = parsedPkt.ip4:getProtocol()
-- 				else
-- 					
-- 				end
			end
			-- Parsing ends
			if not lookup then
				goto skipLookup
			end
			hashmap:access2(tuple, acc)
			local ttlData = acc:get()
			ttlData.last_seen = pkt.ts_vlan
			local ano = flowtracker.updateAndCheck(ttlData, TTL, epsilon)
			--local ano = math.random(0, 10000000) == 0 or 0
			if ano ~= 0 then
				ttlData.tracked = true
				local event = ev.newEvent(filterExprFromTuple(tuple), ev.create)
				log:warn("[TBB Analyzer Thread #%i]: Anomalous TTL: %i != %i, %s, ts %f", id, TTL, ano, event.filter, pkt:getTimestamp())
				for _, pipe in ipairs(pipes) do
					pipe:send(event)
				end
			end
			acc:release()
			::skipLookup::
		end
		storage:release()
		::continue::
	end
	rxCtr:finalize()
	acc:free()
	log:info("[Analyzer]: Shutdown")
end

function dummyAnalyzer(args, qq, id)
	log:setLevel(args.logLevel)
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

function continuousDumper(args, qq, id, path, filterPipe)
	log:setLevel(args.logLevel)
	local ruleSet = {} -- Used to maintain the rules
	local ruleList = {} -- Build from the ruleSet for performance
	local rxCtr = stats:newManualRxCounter("Dumper Thread   #" .. id, "plain")
	local lastTS = 0
	
	while moon.running() do
		-- Get new filters
		-- TODO: loop until all messages are read
		local needRebuild = false
		local event = filterPipe:tryRecv(0)
		if event ~= nil then
			print(event.action, event.filter, event.timestamp)
			if event.action == ev.create and ruleSet[event.id] == nil then
				local triggerWallTime = wallTime()
				local pcapFileName = path .. ("/FlowScope-dump " .. os.date("%Y-%m-%d %H-%M-%S", triggerWallTime) .. " " .. event.filter .. " part " .. id .. ".pcap"):gsub(" ", "_")
				local pcapWriter = pcap:newWriter(pcapFileName, triggerWallTime)
				ruleSet[event.id] = {pfFn = pf.compile_filter(event.filter), pcap = pcapWriter}
				--ruleSet[event.filter] = {pfFn = function() end, pcap = nil}
				needRebuild = true
			elseif event.action == ev.delete and ruleSet[event.id] ~= nil then
				ruleSet[event.id].timestamp = event.timestamp
				log:info("[Dumper %i#]: Marked rule %s as expired", id, event.id)
			end
		end

		-- Check for expired rules
		for k, v in pairs(ruleSet) do
			if v.timestamp ~= nil and lastTS > v.timestamp then
				if ruleSet[k].pcap then
					ruleSet[k].pcap:close()
				end
				log:info("[Dumper %i#]: Expired rule %s, %i > %i", id, k, lastTS, v.timestamp)
				ruleSet[k] = nil
				needRebuild = true
			end
		end

		-- Update ruleList
		if needRebuild then
			ruleList = {}
			for _, v in pairs(ruleSet) do
				ruleList[#ruleList+1] = v
			end
			log:info("Dumper #%i: total number of rules: %i", id, #ruleList)
		end
		
		local storage = qq:tryDequeue()
		if storage == nil then
			goto skip
		end
		for i = 0, storage:size() - 1 do
			local pkt = storage:getPacket(i)
			local timestamp = pkt:getTimestamp()
			lastTS = tonumber(pkt.ts_vlan)
			rxCtr:updateWithSize(1, pkt:getLength())
			
			for _, rule in ipairs(ruleList) do
				if rule.pfFn(pkt.data, pkt.len) then
-- 					print("Dumper #" .. id .. ": Got match!")
					if rule.pcap then
						rule.pcap:write(timestamp, pkt.data, pkt.len)
					end
				end
			end
		end
		storage:release()
		::skip::
	end
	rxCtr:finalize()
	for _, rule in pairs(ruleSet) do
		if rule.pcap then
			rule.pcap:close()
		else
			log:error("[Dumper #%i]: Rule got no pcap", id)
		end
	end
	log:info("[Dumper]: Shutdown")
end

