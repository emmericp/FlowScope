local phobos   = require "phobos"
local device	= require "device"
local memory	= require "memory"
local stats		= require "stats"
local pktLib	= require "packet"
local ffi		= require "ffi"
local namespaces= require "namespaces"
local utils		= require "utils"

local QQ		= require "qq"
local pcapLib	= require "qq_pcap_writer"


function master(txPort, rxPort, path)
	if not txPort or not rxPort then
		print("usage: txPort rxPort [path]")
		return
	end
	
	if not path then
		path = "./"
	end
	
	packet_size = 512
	
	
	local txDev = device.config{port = txPort, rxQueues = 1, txQueues = 3}
	local rxDev = device.config{port = rxPort, rxQueues = 2, txQueues = 1, rssQueues = 2}

	txDev:setRate(15000)
	
	device.waitForLinks()
	
	local qq = QQ.create_qq()
	
	phobos.startTask("qqInserterSlave", rxDev:getRxQueue(0), qq)
	phobos.startTask("qqInserterSlave", rxDev:getRxQueue(1), qq)
	local ns = namespaces.get()
	phobos.startTask("analyseSlave", qq, ns)
	phobos.startTask("dumpSlave", qq, path, ns)
	
	phobos.startTask("sentinelInserter", txDev:getTxQueue(0), packet_size)
	phobos.startTask("flowGen", txDev:getTxQueue(1), packet_size)
	
	phobos.waitForTasks()
	
	qq:delete()
end

function analyseSlave(qq, ns)
	ns["flag"] = 0
	ns["past"] = 0.0
	ns["future"] = 0.0

	local rxCtr = stats:newManualRxCounter("QQ analyse", "plain")
	
	while phobos.running() do
		local storage = qq:peek()
		
		for i = 0, tonumber(storage:size())-1 do
			local pkt = storage:getPacket(i)
			local udpPkt = pktLib.getUdpPacket(pkt)
			
			rxCtr:updateWithSize(1, pkt.len)
			
			if udpPkt.udp:getDstPort() ~= 80 then
				ns["flag"] = 1
				ns["past"] = 1
				ns["future"] = 3
				ns["ip_addr"] = udpPkt.ip4:getSrc()
				print("analyseSlave", udpPkt.ip4:getSrcString(), udpPkt.ip4:getSrc(), pkt:getTimestamp())
			end
		end
		
		storage:release()
	end
	rxCtr:finalize()
end

function dumpSlave(qq, path, ns)
	local pcap_writer = pcapLib.create_pcap_writer(path)
	
	while (ns["flag"] ~= 1) do
		phobos.sleepMillisIdle(10)
	end
	print("dumpSlave: starting ...")
	ns["flag"] = 0
	
	local past = math.floor(tonumber(qq:size()) * ns["past"])
	print("[dumpSlave] past:", past)
	
	local future = math.floor(tonumber(qq:capacity()) * ns["future"])
	print("[dumpSlave] future:", future)
	
	local match = ns["ip_addr"]
	print("[dumpSlave] match:", match, parseIP4Address(match))
	
	local poiCtr = stats:newManualRxCounter("Dump", "plain")
	local lastTimestamp = 0
	for progress=0, past+future do
		local storage = qq:dequeue()
		
		for i = 0, tonumber(storage:size())-1 do
			local pkt = storage:getPacket(i)
			local udpPkt = pktLib.getUdpPacket(pkt)
			
			if udpPkt.ip4:getSrc() == match then
				local ts = pkt:getTimestamp()
				if ts < lastTimestamp then print(ts, lastTimestamp) end
				lastTimestamp = ts
				pcap_writer:store(pkt:getTimestamp(), pkt.len, pkt.data)
				poiCtr:updateWithSize(1, pkt.len)
			end
		end
		
		storage:release()
		
		if progress % 64 == 0 then
			print("[dumpSlave] progress:", progress / (past+future))
		end
	end

	poiCtr:finalize()
	pcap_writer:delete()
	print("[dumpSlave] done")
end

function sentinelInserter(queue, packet_size)
	math.randomseed(os.time())
	phobos.sleepMillisIdle(15000) -- wait until the queue alread has some content, else the dump thread has no work to do
	
	--local target_IP = "10.0.0." .. math.random(31)
	local target_IP = "10.0.0.1"
	
	local mem = memory.createMemPool(function(buf)
		buf:getUdp4Packet():fill{
			ip4Src = target_IP,
			udpSrc = queue.id,
			udpDst = 22,
			pktLength = packet_size
		}
	end)
	local bufs = mem:bufArray(1)
	bufs:alloc(packet_size)
	queue:send(bufs)
	
	print("Send packet with IP", target_IP)
end

function flowGen(queue, packet_size)
	local baseIP = parseIPAddress("10.0.0.1")
	local mem = memory.createMemPool(function(buf)
		buf:getUdp4Packet():fill{
			udpSrc = queue.id,
			udpDst = 80,
			pktLength = packet_size
		}
	end)
	local bufs = mem:bufArray()
	local ctr = stats:newDevTxCounter(queue.dev, "plain")
	local i = 0
	while phobos.running() do
		bufs:alloc(packet_size)
		for idx, buff in ipairs(bufs) do
			local modPkt = buff:getUdp4Packet()
			modPkt.ip4.src:set(baseIP + math.random(0, 15))
			--modPkt.ip4.src:set(baseIP + i)
			--i = incAndWrap(i, 8)
		end
		queue:send(bufs)
		ctr:update()
	end
	ctr:finalize()
end


function qqInserterSlave(txQueue, qq)
	print("Inserter starting:", txQueue.id, txQueue.qid)
	qq:inserterLoop(txQueue.id, txQueue.qid)
end
