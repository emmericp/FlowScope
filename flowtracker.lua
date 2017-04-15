local ffi       = require "ffi"
local packetLib = require "packet"

local flowtrackerlib = ffi.load("build/flowtracker")


ffi.cdef [[
    struct foo_flow_data {
        uint64_t start_ts;
        uint64_t end_ts;
        uint8_t observed_ttl;
    } __attribute__((__packed__));

    typedef struct flowtracker { } flowtracker;

    flowtracker* flowtracker_create(uint32_t max_flows);

    void flowtracker_delete(flowtracker* tr);
    
    int32_t flowtracker_add_flow_v4(flowtracker* tr, uint32_t ip_src, uint16_t port_src,
        uint32_t ip_dst, uint16_t port_dst, uint8_t proto,
        const struct flow_data* flow_data);
    
    struct foo_flow_data* flowtracker_get_flow_data_v4(flowtracker* tr, uint32_t ip_src, uint16_t port_src,
        uint32_t ip_dst, uint16_t port_dst, uint8_t proto);
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
    return flowtrackerlib.flowtracker_add_flow_v4(self, ip_src, port_src, ip_dst, port_dst, proto, data)
end

function flowtracker:get_flow_data_v4(ip_src, port_src, ip_dst, port_dst, proto)
    return flowtrackerlib.flowtracker_get_flow_data_v4(self, ip_src, port_src, ip_dst, port_dst, proto)
end

ffi.metatype("flowtracker", flowtracker)

return mod
