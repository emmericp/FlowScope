local ffi = require "ffi"
require "tuple"
local C = ffi.C

local hmapTemplate = [[
typedef struct hmap hmap{size};
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

local sizes = { 8, 16, 32, 64, 128 }

for _, v in pairs(sizes) do
    local definition, _ = hmapTemplate:gsub("{size}", v)
    ffi.cdef(definition)
end
