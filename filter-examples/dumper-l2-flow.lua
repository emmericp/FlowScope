local pktLib = require "packet"
local ffi    = require "ffi"
local eth    = require "proto.ethernet"

-- a dumper function that uses the MAC addresses of the trigger packet to dump the L2 flow
return function(triggerPkt)
	local triggerEthPkt = pktLib.getEthPacket(triggerPkt)
	local triggerEthSrc = triggerEthPkt.eth:getSrc()
	local triggerEthDst = triggerEthPkt.eth:getDst()
	return function(pkt)
		local ethPkt = pktLib.getEthPacket(pkt)
		local ethSrc = ethPkt.eth:getSrc()
		local ethDst = ethPkt.eth:getDst()
		return triggerEthSrc == ethSrc and triggerEthDst == ethDst
		    or triggerEthDst == ethSrc and triggerEthSrc == ethDst -- get the bidirectional flow
	end
end
