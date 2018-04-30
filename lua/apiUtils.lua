local turbo = require 'turbo'
local event = require 'event'

local module = {}

module.filterIdRegex = "([a-zA-Z0-9.:-_]+)"

function module.checkForToken(requestHandler, allowedToken)
    local token = requestHandler.request.headers:get("X-Authorization-Token", true)
    if token ~= nil then
        for _, v in pairs(allowedToken) do
            if v == token then
                return true
            end
        end
    end
    return false
end

function module.ifAuthorized(requestHandler, allowedToken, fct)
    -- check for the X-Authorization-Token header and compare its value to the ones present in allowedToken
    if module.checkForToken(requestHandler, allowedToken) then
        fct()
    else
        error(turbo.web.HTTPError(401, { message = "Unauthorized." }))
    end
end

function module.checkFilterAttributes(filterObject)
    local requiredKeys = filterObject['id'] ~= nil and filterObject['filter'] ~= nil
    requiredKeys = requiredKeys and (string.match(filterObject['id'], module.filterIdRegex) ~= nil)
    -- pipes present => it should be an array of numbers (logical consequence)
    local pipesCorrect = not (filterObject['pipes'] ~= nil) or (type(filterObject['pipes']) == 'table')
    return requiredKeys and pipesCorrect
end

function module.prepareFilter(json, allowed_pipes)
    local filter = {
        id = tostring(json.id),
        filter = json.filter,
        timestamp = json.timestamp,
        action = event.create,
        pipes = {}
    }

    -- formatting of the pipes is already checked in apiUtils.checkFilterAttributes
    if json['pipes'] ~= nil then
        for i, pipe_number in ipairs(json['pipes']) do
            if (allowed_pipes[pipe_number] ~= nil) then
                filter.pipes[i] = pipe_number
            else
                error(turbo.web.HTTPError(400, { error = "Pipe number " .. tostring(pipe_number) .. " not allowed." }))
            end
        end
    else
        filter.pipes = allowed_pipes
    end
    return filter
end

function module.applyFilter(filter, filters, pipes)
    if filters[filter.id] ~= nil then
        error(turbo.web.HTTPError(400, { error = "Filter id is already in use. Choose another one." }))
    else
        filters[filter.id] = filter
        -- add filter to pipe (what if pipe argument is not present? => add to all)
        for i, pipe in ipairs(pipes) do
            if filter.pipes[i] ~= nil then
                pipe:send(event.newEvent(filter.filter, event.create, filter.id, filter.timestamp))
            end
        end
    end
end

return module
