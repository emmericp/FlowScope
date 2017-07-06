local log = require "log"

local mod = {}

mod.create = 1
mod.delete = 2

function mod.newEvent(filterString, action, id)
    local id = id or filterString
    if action ~= mod.create and action ~= mod.delete then
        log:warn("Invalid event action: %i", action)
        return nil
    end
    return {action = action, filter = filterString, id = id}
end

return mod
