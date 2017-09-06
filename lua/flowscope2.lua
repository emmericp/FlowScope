local lm = require "libmoon"
local device = require "device"
local ffi = require "ffi"
local flowtracker = require "flowtracker2"

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

local tracker = flowtracker.new {
    stateType = "struct my_flow_state",
    ip4Handler = "handleIp4Packet",
    ip4TimeoutHandler = "handleIp4Timeout",
    -- default = ffi.new("struct my_flow_state", { other defaults go here })
}

-- state starts out empty if it doesn't exist yet; buf is whatever the device queue or QQ gives us
function handleIp4Packet(tuple, state, buf, isFirstPacket)
    -- implicit lock by TBB
    state.packet_counter = state.packet_counter + 1
    state.byte_counter = state.byte_counter + buf:getSize()
    if isFirstPacket then
        state.first_seen = time()
    end
    state.last_seen = time()
    -- can add custom "active timeout" (like ipfix) here
end

function handleIp4Timeout(tuple, state)
    print("flow died, state was: %s", state) -- assume state has reasonable __tostring
end

function master()
    -- this part should be wrapped by flowscope and exposed via CLI arguments
    local dev = device.config { ... }
    for i = 0, 3 do
        -- get from QQ or from a device queue
        lm.startTask(flowtracker.analyzerTask, tracker, dev:getRxQueue(i))
    end
    -- end wrapped part
end