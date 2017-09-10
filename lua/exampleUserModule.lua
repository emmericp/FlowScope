local ffi = require "ffi"

local module = {}

-- must be done on top level to be available/defined in all threads
ffi.cdef [[
	struct my_flow_state {
		uint64_t packet_counter;
		uint64_t byte_counter;
		uint64_t first_seen;
		uint64_t last_seen;
		uint8_t some_flags;
		uint16_t some_fancy_data[20];
	};
]]

-- Export name of struct
module.stateType = "struct my_flow_state"

-- Custom default state for new flows
-- See ffi.new() for table initializer rules
module.defaultState = {packet_counter = 123, some_flags = 0xab}

-- state starts out empty if it doesn't exist yet; buf is whatever the device queue or QQ gives us
function module.handleIp4Packet(tuple, state, buf, isFirstPacket)
    -- implicit lock by TBB
    state.packet_counter = state.packet_counter + 1
    state.byte_counter = state.byte_counter + buf:getSize()
    if isFirstPacket then
        state.first_seen = time()
    end
    state.last_seen = time()
    -- can add custom "active timeout" (like ipfix) here
end

-- Function that gets called in regular intervals to decide if a flow is still active
-- Returns true for flows that are expired, false for active flows
function module.checkExpiry(tuple, state)
    return false
end

-- Set the interval in which the check function should be called
-- float in seconds
module.checkInterval = 5

return module
