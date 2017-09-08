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

function module.handleIp4Timeout(tuple, state)
    print("flow died, state was: %s", state) -- assume state has reasonable __tostring
end

return module
