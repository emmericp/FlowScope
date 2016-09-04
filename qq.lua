local ffi    = require "ffi"
local memory = require "memory"

local qqlib = ffi.load("build/flowscope")

ffi.cdef [[
	typedef struct packet_header {
		uint64_t ts_vlan;
		uint16_t len;
		uint8_t data[];
	} packet_header_t;
    
	typedef struct qq { } qq_t;
    
	void qq_init();

	qq_t* qq_create();
    
	void qq_delete(qq_t*);
    
	size_t qq_size(qq_t*);
    
	size_t qq_capacity(qq_t*);
    
	typedef struct { } storage_t;
    
	storage_t* qq_storage_dequeue(qq_t*);
    
	storage_t* qq_storage_enqueue(qq_t*);
	
	storage_t* qq_storage_peek(qq_t*);
	
	size_t qq_get_enqueue_counter(qq_t*);
	
	size_t qq_get_dequeue_counter(qq_t*);
	
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

function mod.create_qq()
	qqlib.qq_init() -- idempotent
	return qqlib.qq_create()
end

local qq = {}
qq.__index = qq
local storage = {}
storage.__index = storage
local packet_header = {}
packet_header.__index = packet_header


function qq:delete()
	qqlib.qq_delete(self)
end

function qq:size()
	return qqlib.qq_size(self)
end

function qq:capacity()
	return qqlib.qq_capacity(self)
end

function qq:dequeue()
	return qqlib.qq_storage_dequeue(self)
end

function qq:enqueue()
	return qqlib.qq_storage_enqueue(self)
end

function qq:peek()
	return qqlib.qq_storage_peek(self)
end

function qq:getEnqueueCounter()
	return qqlib.qq_get_enqueue_counter(self)
end

function qq:getDequeueCounter()
	return qqlib.qq_get_dequeue_counter(self)
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
	return qqlib.qq_storage_size(self)
end

function storage:store(ts, vlan, len, data)
	return qqlib.qq_storage_store(self, ts, vlan, len, data)
end

function storage:getPacket(idx)
 	return qqlib.qq_storage_get_packet(self, idx)
end

local band, rshift, lshift = bit.band, bit.rshift, bit.lshift

function packet_header:getTimestamp()
	return band(self.ts_vlan, 0xffffffffffff)
end

function packet_header:getVlan()
	return rshift(self.ts_vlan, 48)
end

function packet_header:getLength()
	return self.len
end

function packet_header:getData()
	return ffi.cast("void*", self.data)
end

function qq:inserterLoop(port_id, queue_id)
	qqlib.qq_inserter_loop(port_id, queue_id, self)
end

ffi.metatype("qq_t", qq)
ffi.metatype("storage_t", storage)
ffi.metatype("packet_header_t", packet_header)

return mod

