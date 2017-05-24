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
    
    uint32_t ipv4_5tuple_hash(struct ipv4_5tuple* tpl);
    uint32_t ipv6_5tuple_hash(struct ipv6_5tuple* tpl);


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
    void rte_hash_free(struct rte_hash *h);
    int32_t rte_hash_add_key(const struct rte_hash *h, const void *key);
    int32_t rte_hash_lookup(const struct rte_hash *h, const void *key);
    int rte_hash_lookup_bulk(const struct rte_hash *h, const void **keys, uint32_t num_keys, int32_t *positions);
    int32_t rte_hash_iterate(const struct rte_hash *h, const void **key, void **data, uint32_t *next);
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


-- 5 tuple hash functions

local ipv4_5tuple = {}
ipv4_5tuple.__index = ipv4_5tuple
ffi.metatype("struct ipv4_5tuple", ipv4_5tuple)

function ipv4_5tuple:hash()
    return flowtrackerlib.ipv4_5tuple_hash(self)
end

local ipv6_5tuple = {}
ipv6_5tuple.__index = ipv6_5tuple
ffi.metatype("struct ipv6_5tuple", ipv6_5tuple)

function ipv6_5tuple:hash()
    return flowtrackerlib.ipv6_5tuple_hash(self)
end


-- rte_hash wrapper

function mod.createHashmap(maxFlows, name)
    return flowtrackerlib.rte_hash_create_v4(maxFlows, name)
end

local hash = {}
hash.__index = hash
ffi.metatype("struct rte_hash", hash)

function hash:add_key(v4Tuple)
    return C.rte_hash_add_key(self, v4Tuple)
end

function hash:lookup(v4Tuple)
    return C.rte_hash_lookup(self, v4Tuple)
end

function hash:delete()
    C.rte_hash_free(self)
end

function hash:lookupBatch(keys, numKeys, positions)
    return C.rte_hash_lookup_bulk(self, keys, numKeys, positions)
end


return mod
