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
        bool tracked;
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
    
    /* TTL helpers */
    uint16_t ttl_check_and_update_TTL(struct ttl_flow_data *data, const uint16_t observed_ttl, const uint16_t epsilon);
    uint16_t ttl_update_and_check_TTL(struct ttl_flow_data *data, const uint16_t observed_ttl, const uint16_t epsilon);
    
    /* Simple TBB wrapper */
    typedef struct ttl_flow_data D;
    typedef struct tbb_map_v4 tbb_map_v4;
    typedef struct ttl_flow_data D;
    tbb_map_v4* tbb_map_create_v4(size_t pre_alloc);
    void tbb_map_delete_v4(tbb_map_v4* map);
    void tbb_map_clear_v4(tbb_map_v4* map);
    const D* tbb_map_get_v4(tbb_map_v4* map, const struct ipv4_5tuple* tpl);
    bool tbb_map_exists_v4(tbb_map_v4* map, const struct ipv4_5tuple* tpl);
    uint16_t tbb_map_check_and_update_ttl_v4(tbb_map_v4* map, const struct ipv4_5tuple* tpl, const uint16_t ttl, const uint16_t epsilon);
    
    /* TBB hash_map with build-in swapping */
    typedef struct tbb_tracker tbb_tracker;
    typedef struct const_accessor4 const_accessor4;
    typedef struct accessor4 accessor4;
    tbb_tracker* tbb_tracker_create(size_t pre_alloc);
    void tbb_tracker_clear(tbb_tracker* tr);
    void tbb_tracker_delete(tbb_tracker* tr);
    size_t tbb_tracker_swapper(tbb_tracker* tr, struct ipv4_5tuple* buf, size_t sz);
    const_accessor4* tbb_tracker_const_access4(tbb_tracker* tr, const struct ipv4_5tuple* tpl);
    const D* tbb_tracker_const_get4(const_accessor4* a);
    void tbb_tracker_const_release4(const_accessor4* a);
    accessor4* tbb_tracker_access4(tbb_tracker* tr, const struct ipv4_5tuple* tpl);
    bool tbb_tracker_access42(tbb_tracker* tr, accessor4 *a, const struct ipv4_5tuple* tpl);
    D* tbb_tracker_get4(accessor4* a);
    void tbb_tracker_release4(accessor4* a);
    void tbb_tracker_free4(accessor4* a);
    
    accessor4* tbb_tracker_accessor4();
]]

local C = ffi.C

local mod = {}

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


-- TTL helpers
function mod.checkAndUpdate(ttlData, ttl, epsilon)
    return flowtrackerlib.ttl_check_and_update_TTL(ttlData, ttl, epsilon)
end

function mod.updateAndCheck(ttlData, ttl, epsilon)
    --return flowtrackerlib.ttl_update_and_check_TTL(ttlData, ttl, epsilon)
    ttlData.running_sum = ttlData.running_sum + ttl
    ttlData.packets = ttlData.packets + 1
    
    local avrg = ttlData.running_sum / ttlData.packets
    if ttl > avrg + epsilon or ttl < avrg - epsilon then
        return avrg
    else
        return 0
    end
end


-- Simple TBB wrapper
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


-- TBB Tracker
function mod.createTBBTracker(preAlloc)
    return flowtrackerlib.tbb_tracker_create(preAlloc)
end

local tbbTracker = {}
tbbTracker.__index = tbbTracker
ffi.metatype("struct tbb_tracker", tbbTracker)

function tbbTracker:clear()
    flowtrackerlib.tbb_tracker_clear(self)
end

function tbbTracker:delete()
    flowtrackerlib.tbb_tracker_delete(self)
end

function tbbTracker:swapper(buf, sz)
    return flowtrackerlib.tbb_tracker_swapper(self, buf, sz)
end

function tbbTracker:constAccess(tpl)
    return flowtrackerlib.tbb_tracker_const_access4(self, tpl)
end

function tbbTracker:access(tpl)
    return flowtrackerlib.tbb_tracker_access4(self, tpl)
end

function tbbTracker:access2(tpl, acc)
    return flowtrackerlib.tbb_tracker_access42(self, acc, tpl)
end

local accessor4 = {}
accessor4.__index = accessor4
ffi.metatype("struct accessor4", accessor4)

function mod.createAccessor()
    return flowtrackerlib.tbb_tracker_accessor4()
end

function accessor4:get()
    return flowtrackerlib.tbb_tracker_get4(self)
end

function accessor4:free()
    return flowtrackerlib.tbb_tracker_free4(self)
end

function accessor4:release()
    return flowtrackerlib.tbb_tracker_release4(self)
end

local constAccessor4 = {}
constAccessor4.__index = constAccessor4
ffi.metatype("struct const_accessor4", constAccessor4)

function constAccessor4:get()
    return flowtrackerlib.tbb_tracker_const_get4(self)
end

function constAccessor4:release()
    return flowtrackerlib.tbb_tracker_const_release4(self)
end


return mod
