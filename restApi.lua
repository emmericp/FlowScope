local apiUtils = require 'apiUtils'
local event = require 'event'

local mod = {}

-- args need to contain: args.apiToken and api.dumperThreads and we need access to the pipes
-- to interface the dumperThreads and apply new filters
function mod.start(turbo, args, pipes)
  -- this webhandler modifies specific filter (i.e given by an id)
  local SpecificFilterWebHandler = class("SpecificFilterWebHandler", turbo.web.RequestHandler)
  -- this Webhandler handles only creation of a filter and showing all (under the namespace /filter/)
  local FilterWebHandler = class("FilterWebHandler", turbo.web.RequestHandler)

  -- RegExes to check on the filter ids/paths
  local FILTER_ID_REGEX = "([a-zA-Z0-9]+)"
  local SPECIFIC_FILTER_REGEX = string.format("^/filter/%s$", FILTER_ID_REGEX)

  local filters = { }

  function SpecificFilterWebHandler:get()
    local function showFilter()
      local filterId = string.match(self.request.path, SPECIFIC_FILTER_REGEX)
      if filters[filterId] ~= nil then
        self:write(filters[filterId])
        self:finish()
      else
        error(turbo.web.HTTPError(404, {error = "Not found"}))
      end
    end
    apiUtils.ifAuthorized(self, args.apiToken, showFilter)
  end

  function SpecificFilterWebHandler:put()
    error(turbo.web.HTTPError(501, {error = "Update not implemented."}))
  end

  function SpecificFilterWebHandler:delete()
    local function deleteFilter()
      local filterId = string.match(self.request.path, SPECIFIC_FILTER_REGEX)
      if filters[filterId] ~= nil then
        local filter = filters[filterId]
        filters[filterId] = nil
        filter.action = event.delete
        -- Remove filter from flowscope
        for i,_ in ipairs(filter.pipes) do
          pipes[i]:send(event.newEvent(filter.filter, event.delete, filter.id, filter.timestamp))
        end
        self:write(filter)
        self:finish()
      else
        error(turbo.web.HTTPError(404, {error = "Not found."}))
      end
    end
    apiUtils.ifAuthorized(self, args.apiToken, deleteFilter)
  end

  function FilterWebHandler:post()
    local function createFilter()
      -- this will raise an error if json is not present
      local jsonBody = self:get_json(true)
      -- create the array of pipes where we want to apply the filter
      local insertToPipes = {}

      if jsonBody == nil or not apiUtils.checkFilterAttributes(jsonBody) then
        error(turbo.web.HTTPError(400, {error = "Filter json malformed."}))
      end
      --  Test the filter id


      for i = 1, args.dumperThreads do
        insertToPipes[i] = i
      end
      local filter = {
        id = tostring(jsonBody.id),
        filter = jsonBody.filter,
        timestamp = jsonBody.timestamp,
        action = event.create,
        pipes = {}
      }
      -- formatting of the pipes is already checked in apiUtils.checkFilterAttributes
      if jsonBody['pipes'] ~= nil then
        for i,pipe_number in ipairs(jsonBody['pipes']) do
          if(insertToPipes[pipe_number] ~= nil) then
            filter.pipes[i] = pipe_number
          else
            error(turbo.web.HTTPError(400, {error = "Pipe number " .. tostring(pipe_number) .. " not allowed."}))
          end
        end
      else
        filter.pipes = insertToPipes
      end

      if filters[filter.id] ~= nil then
        error(turbo.web.HTTPError(400, {error = "Filter id is already in use. Choose another one."}))
      else
        filters[filter.id] = filter
        -- add filter to pipe (what if pipe argument is not present? => add to all)
        for i, pipe in ipairs(pipes) do
          if insertToPipes[i] ~= nil then
            pipe:send(event.newEvent(filter.filter, event.create, filter.id, filter.timestamp))
          end
        end
        self:write(filter)
        self:finish()
      end
    end

    apiUtils.ifAuthorized(self, args.apiToken, createFilter)
  end

  function FilterWebHandler:get()
    local function showFilters()
      self:write(filters)
      self:finish()
    end
    apiUtils.ifAuthorized(self, args.apiToken, showFilters)
  end

  return {
    { SPECIFIC_FILTER_REGEX, SpecificFilterWebHandler},
    { "^/filter/$", FilterWebHandler}
  }
end

return mod
