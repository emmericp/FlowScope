local ffi       = require "ffi"
local packetLib = require "packet"

local flowtrackerlib = ffi.load("build/flowtracker")


ffi.cdef [[
    struct foo_flow_data {
        uint64_t start_ts;
        uint64_t end_ts;
        uint8_t observed_ttl;
    } __attribute__((__packed__));
    
    struct ttl_flow_data {
        uint64_t running_sum;  // Sum of all seen TTL values
        uint64_t packets;      // Number of observed TTL values
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
    
    typedef struct ttl_flow_data D;

    /* Flowtracker wrapper */
    typedef struct flowtracker { } flowtracker_t;
    flowtracker_t* flowtracker_create(uint32_t max_flows);
    void flowtracker_delete(flowtracker_t* tr);
    int32_t flowtracker_add_flow_v4(flowtracker_t*, const struct ipv4_5tuple* const, const D*);
    D* flowtracker_get_flow_data_v4(flowtracker_t* tr, uint32_t ip_src, uint16_t port_src, uint32_t ip_dst, uint16_t port_dst, uint8_t proto);
    int flowtracker_get_flow_data_bulk_v4(flowtracker_t* tr, const void* keys[], uint32_t num_keys, D* data[]);

    /* rte_hash wrapper */
    struct rte_hash { };
    struct rte_hash* rte_hash_create_v4(uint32_t max_flows, const char* name);
    void rte_hash_free(struct rte_hash *h);
    int32_t rte_hash_add_key(const struct rte_hash *h, const void *key);
    int32_t rte_hash_lookup(const struct rte_hash *h, const void *key);
    int rte_hash_lookup_bulk(const struct rte_hash *h, const void **keys, uint32_t num_keys, int32_t *positions);
    int32_t rte_hash_iterate(const struct rte_hash *h, const void **key, void **data, uint32_t *next);
    
    /* TTL helpers */
    uint16_t get_average_TTL(uint64_t val);
    uint64_t update_TTL(uint64_t val, uint16_t new_ttl);
    
    /* TBB wrapper */
    typedef struct ttl_flow_data D;
    typedef struct tbb_map_v4 tbb_map_v4;
    typedef struct ttl_flow_data D;
    tbb_map_v4* tbb_map_create_v4(size_t pre_alloc);
    void tbb_map_delete_v4(tbb_map_v4* map);
    void tbb_map_clear_v4(tbb_map_v4* map);
    const D* tbb_map_get_v4(tbb_map_v4* map, const struct ipv4_5tuple* tpl);
    bool tbb_map_exists_v4(tbb_map_v4* map, const struct ipv4_5tuple* tpl);
    uint16_t tbb_map_check_and_update_ttl_v4(tbb_map_v4* map, const struct ipv4_5tuple* tpl, const uint16_t ttl, const uint16_t epsilon);
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

function flowtracker:addFlow4(tuple, flow_data)
    return flowtrackerlib.flowtracker_add_flow_v4(self, tuple, flow_data)
end

function flowtracker:get_flow_data_v4(ip_src, port_src, ip_dst, port_dst, proto)
    return flowtrackerlib.flowtracker_get_flow_data_v4(self, ip_src, port_src, ip_dst, port_dst, proto)
end

function flowtracker:lookupBatch4(keys, numKeys, data)
    return flowtrackerlib.flowtracker_get_flow_data_bulk_v4(self, keys, numKeys, data)
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


-- TTL helpers
function mod.getAverageTTL(val)
    return flowtrackerlib.get_average_TTL(val)
end

function mod.updateTTL(val, ttl)
    return flowtrackerlib.update_TTL(val, ttl)
end


-- TBB wrapper
function mod.createTBBMapv4(preAlloc)
    return flowtrackerlib.tbb_map_create_v4(preAlloc)
end

local tbb4 = {}
tbb4.__index = tbb4
ffi.metatype("struct tbb_map_v4", tbb4)

function tbb4:delete()
    flowtrackerlib.tbb_map_delete_v4(self)
end

function tbb4:checkAndUpdate(v4Tuple, ttl, epsilon)
    return flowtrackerlib.tbb_map_check_and_update_ttl_v4(self, v4Tuple, ttl, epsilon)
end

function tbb4:get(v4Tuple)
    return flowtrackerlib.tbb_map_get_v4(self, v4Tuple)
end

return mod
