local pktLib = require "packet"
local ffi    = require "ffi"
local eth    = require "proto.ethernet"
local ip     = require "proto.ip4"

-- Checks if a UDP packet's payload begins with "EXAMPLE".
-- You can do arbitrary complex stuff here, e.g., attach a DPI library like nDPI.
return function(pkt)
	local udpPkt = pktLib.getUdp4Packet(pkt)
	if udpPkt.eth:getType() == eth.TYPE_IP
	and udpPkt.ip4:getProtocol() == ip.PROTO_UDP then
		local data = ffi.string(udpPkt.payload.uint8, #"EXAMPLE")
		return data == "EXAMPLE"
	end
	return false
end

