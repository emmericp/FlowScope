local log = require "log"

local mod = {}

mod.create = 1
mod.delete = 2

function mod.newEvent(filterString, action, id, timestamp)
    local id = id or filterString
    if action ~= mod.create and action ~= mod.delete then
        log:error("Invalid event action: %i", action)
        return nil
    end
    return {action = action, filter = filterString, id = id, timestamp = timestamp}
end

return mod
