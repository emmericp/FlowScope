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

function makeHashmapFor(size)
    local map = {}
    map.__index = map
    function map:clear()
        flowtrackerlib["hmap" .. size .. "_clear"](self)
    end
    function map:delete()
        flowtrackerlib["hmap" .. size .. "_delete"](self)
    end
    function map:access(a, tpl)
        return flowtrackerlib["hmap" .. size .. "_access"](self, a, tpl)
    end
    function map.newAccessor()
        return flowtrackerlib["hmap" .. size .. "_new_accessor"]()
    end
    local accessor = {}
    accessor.__index = accessor
    function accessor:get()
        return flowtrackerlib["hmap" .. size .. "_accessor_get_value"](self)
    end
    function accessor:free()
        return flowtrackerlib["hmap" .. size .. "_accessor_free"](self)
    end
    function accessor:release()
        return flowtrackerlib["hmap" .. size .. "_accessor_release"](self)
    end
    ffi.metatype("hmap" .. size .. "_accessor", accessor)
    ffi.metatype("hmap" .. size, map)
    return map
end

local hmap8 = makeHashmapFor(8)
local hmap16 = makeHashmapFor(16)
local hmap32 = makeHashmapFor(32)
local hmap64 = makeHashmapFor(64)
local hmap128 = makeHashmapFor(128)

return module
