local ffi       = require "ffi"
local packetLib = require "packet"
local memory    = require "memory"

local qqlib = ffi.load("build/qq")

ffi.cdef [[
	typedef struct packet_header {
		uint64_t ts_vlan;
		uint16_t len;
		uint8_t data[];
	} packet_header_t;

	typedef struct qq { } qq_t;

	void qq_init();

	qq_t* qq_create(uint32_t storage_capacity);

	void qq_delete(qq_t*);

	size_t qq_size(qq_t*);

	size_t qq_capacity(qq_t*);

	typedef struct storage { } storage_t;

	storage_t* qq_storage_dequeue(qq_t*);

	storage_t* qq_storage_try_dequeue(qq_t*);

	storage_t* qq_storage_enqueue(qq_t*);

	storage_t* qq_storage_peek(qq_t*);

	storage_t* qq_storage_try_peek(qq_t*);

	size_t qq_get_enqueue_counter(qq_t*);

	size_t qq_get_dequeue_counter(qq_t*);
    
	size_t qq_get_enqueue_overflow_counter(qq_t*);

	void qq_set_priority(qq_t* q, const uint8_t new_priority);

	void qq_storage_release(storage_t*);

	size_t qq_storage_size(storage_t*);

	bool qq_storage_store(storage_t*, uint64_t ts, uint16_t vlan, uint16_t len, const uint8_t* data);

	const packet_header_t& qq_storage_get_packet(storage_t*, const size_t);

	uint64_t qq_packet_header_get_timestamp(const packet_header_t&);

	uint64_t qq_packet_header_get_vlan(const packet_header_t& h);

	uint16_t qq_packet_header_get_len(const packet_header_t& h);

	void* qq_packet_header_get_data(const packet_header_t& h);

	void dummy_enqueue(qq_t* q);

	void qq_inserter_loop(uint8_t device, uint16_t queue_id, qq_t* qq);
]]

local C = ffi.C

local mod = {}

--- @param storageSize desired storage capacity in GiB
function mod.createQQ(storageSize)
	qqlib.qq_init() -- idempotent
	return qqlib.qq_create(storageSize * 1024)
end

local qq = {}
qq.__index = qq
local storage = {}
storage.__index = storage
local packetHeader = {}
packetHeader.__index = packetHeader


function qq:delete()
	qqlib.qq_delete(self)
end

function qq:size()
	return tonumber(qqlib.qq_size(self))
end

function qq:capacity()
	return tonumber(qqlib.qq_capacity(self))
end

function qq:dequeue()
	return qqlib.qq_storage_dequeue(self)
end

function qq:tryDequeue()
	return qqlib.qq_storage_try_dequeue(self)
end

function qq:tryPeek()
	return qqlib.qq_storage_try_peek(self)
end

function qq:enqueue()
	return qqlib.qq_storage_enqueue(self)
end

function qq:peek()
	return qqlib.qq_storage_peek(self)
end

function qq:getEnqueueCounter()
	return tonumber(qqlib.qq_get_enqueue_counter(self))
end

function qq:getEnqueueOverflowCounter()
	return tonumber(qqlib.qq_get_enqueue_overflow_counter(self))
end

function qq:getDequeueCounter()
	return tonumber(qqlib.qq_get_dequeue_counter(self))
end

function qq:setPriority(new_priority)
	return qqlib.qq_set_priority(self, new_priority)
end

function qq:dummy()
	qqlib.dummy_enqueue(self)
end

function storage:release()
	qqlib.qq_storage_release(self)
end

function storage:size()
	return tonumber(qqlib.qq_storage_size(self))
end

function storage:store(ts, vlan, len, data)
	return qqlib.qq_storage_store(self, ts, vlan, len, data)
end

function storage:getPacket(idx)
	return qqlib.qq_storage_get_packet(self, idx)
end

local band, rshift, lshift = bit.band, bit.rshift, bit.lshift

function packetHeader:getTimestamp()
	-- timestamp relative to libmoon.getTime(), i.e. the TSC in seconds
	return tonumber(band(self.ts_vlan, 0xffffffffffffULL)) / 10^6
end

function packetHeader:getVlan()
	return rshift(self.ts_vlan, 48)
end

function packetHeader:getLength()
	return self.len
end

function packetHeader:getData()
	return ffi.cast("void*", self.data)
end

function packetHeader:dump()
	return packetLib.getEthernetPacket(self):resolveLastHeader():dump()
end

function packetHeader:clone()
	local pkt = memory.alloc("packet_header_t*", ffi.sizeof("packet_header_t") + self.len)
	pkt.ts_vlan = self.ts_vlan
	pkt.len = self.len
	ffi.copy(pkt.data, self.data, self.len)
	return pkt
end

function qq:inserterLoop(queue)
	qqlib.qq_inserter_loop(queue.id, queue.qid, self)
end

ffi.metatype("qq_t", qq)
ffi.metatype("storage_t", storage)
ffi.metatype("packet_header_t", packetHeader)

return mod

