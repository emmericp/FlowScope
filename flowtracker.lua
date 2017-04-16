local ffi       = require "ffi"
local packetLib = require "packet"

local flowtrackerlib = ffi.load("build/flowtracker")


ffi.cdef [[
    struct foo_flow_data {
        uint64_t start_ts;
        uint64_t end_ts;
        uint8_t observed_ttl;
    } __attribute__((__packed__));
    
    struct ipv4_5tuple {
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
    } __attribute__((__packed__));
    
    struct ipv6_5tuple {
        uint8_t  ip_dst[16];
        uint8_t  ip_src[16];
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
    } __attribute__((__packed__));


    typedef struct flowtracker { } flowtracker_t;

    flowtracker_t* flowtracker_create(uint32_t max_flows);

    void flowtracker_delete(flowtracker_t* tr);
    
    int32_t flowtracker_add_flow_v4(flowtracker_t* tr, uint32_t ip_src, uint16_t port_src,
        uint32_t ip_dst, uint16_t port_dst, uint8_t proto,
        const struct foo_flow_data* flow_data);
    
    struct foo_flow_data* flowtracker_get_flow_data_v4(flowtracker_t* tr, uint32_t ip_src, uint16_t port_src,
        uint32_t ip_dst, uint16_t port_dst, uint8_t proto);
        
    /* rte_hash wrapper */
    struct rte_hash { };
    struct rte_hash* rte_hash_create_v4(uint32_t max_flows, const char* name);
    void rte_hash_free_v4(struct rte_hash *h);
    int32_t rte_hash_add_key_v4(const struct rte_hash *h, const void *key);
    int32_t rte_hash_lookup_v4(const struct rte_hash *h, const void *key);
    int rte_hash_lookup_bulk_v4(const struct rte_hash *h, const void **keys, uint32_t num_keys, int32_t *positions);
]]

local C = ffi.C

local mod = {}


function mod.createFlowtracker(maxFlows)
    return flowtrackerlib.flowtracker_create(maxFlows)
end

local flowtracker = {}
flowtracker.__index = flowtracker
local flowdata = {}
flowdata.__index = flowdata


function flowtracker:delete()
    flowtrackerlib.flowtracker_delete(self)
end

function flowtracker:add_flow_v4(ip_src, port_src, ip_dst, port_dst, proto, flow_data)
    return flowtrackerlib.flowtracker_add_flow_v4(self, ip_src, port_src, ip_dst, port_dst, proto, flow_data)
end

function flowtracker:get_flow_data_v4(ip_src, port_src, ip_dst, port_dst, proto)
    return flowtrackerlib.flowtracker_get_flow_data_v4(self, ip_src, port_src, ip_dst, port_dst, proto)
end

ffi.metatype("flowtracker_t", flowtracker)


-- rte_hash wrapper

function mod.createHashmap(maxFlows, name)
    return flowtrackerlib.rte_hash_create_v4(maxFlows, name)
end

local hash = {}
hash.__index = hash
ffi.metatype("struct rte_hash", hash)

function hash:add_key(v4Tuple)
    return flowtrackerlib.rte_hash_add_key_v4(self, v4Tuple)
end

function hash:lookup(v4Tuple)
    return flowtrackerlib.rte_hash_lookup_v4(self, v4Tuple)
end

function hash:delete()
    flowtrackerlib.rte_hash_free_v4(self)
end

function hash:lookupBatch(keys, numKeys, positions)
    return flowtrackerlib.rte_hash_lookup_bulk_v4(self, keys, numKeys, positions)
end

return mod
