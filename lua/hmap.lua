local ffi = require "ffi"
local flowtrackerlib = ffi.load("../build/flowtracker")
local tuple = require "tuple"
local C = ffi.C

local hmapTemplate = [[
typedef struct hmap{size} hmap{size};
typedef struct hmap{size}_accessor hmap{size}_accessor;
hmap{size}* hmap{size}_create();
void hmap{size}_delete(hmap{size}* map);
void hmap{size}_clear(hmap{size}* map);
hmap{size}_accessor* hmap{size}_new_accessor();
void hmap{size}_accessor_free(hmap{size}_accessor* a);
void hmap{size}_accessor_release(hmap{size}_accessor* a);
bool hmap{size}_access(hmap{size}* map, hmap{size}_accessor* a, const struct ipv4_5tuple* tpl);
uint8_t* hmap{size}_accessor_get_value(hmap{size}_accessor* a);
]]

local module = {}

local sizes = { 8, 16, 32, 64, 128 }

for _, v in pairs(sizes) do
    local definition, _ = hmapTemplate:gsub("{size}", v)
    ffi.cdef(definition)
end

-- Get tbb hash map with fitting value size
function module.createTable(valueSize)
    if valueSize <= 8 then
        return flowtrackerlib.hmap8_create()
    elseif valueSize <= 16 then
        return flowtrackerlib.hmap16_create()
    elseif valueSize <= 32 then
        return flowtrackerlib.hmap32_create()
    elseif valueSize <= 64 then
        return flowtrackerlib.hmap64_create()
    elseif valueSize <= 128 then
        return flowtrackerlib.hmap128_create()
    else
        log:error("Values of size %d are not supported", valueSize)
        return nil
    end
end


-- This should be generate dynamically for all sizes
local hmap128 = {}
hmap128.__index = hmap128
ffi.metatype("hmap128", hmap128)

function hmap128:clear()
    flowtrackerlib.hmap128_clear(self)
end

function hmap128:delete()
    flowtrackerlib.hmap128_delete(self)
end

function hmap128:access(a, tpl)
    flowtrackerlib.hmap128_access(self, a, tpl)
end

local hmap128Accessor = {}
hmap128Accessor.__index = hmap128Accessor
ffi.metatype("hmap128_accessor", hmap128Accessor)

function hmap128.newAccessor()
    return flowtrackerlib.hmap128_new_accessor()
end

function hmap128Accessor:get()
    return flowtrackerlib.hmap128_accessor_get_value(self)
end

function hmap128Accessor:free()
    return flowtrackerlib.hmap128_accessor_free(self)
end

function hmap128Accessor:release()
    return flowtrackerlib.hmap128_accessor_release(self)
end

return module