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
    local SPECIFIC_FILTER_REGEX = string.format("^/filter/%s$", apiUtils.filterIdRegex)

    -- create the array of pipes where we want to apply the filter
    local ALLOWED_PIPES = {}
    for i = 1, args.dumperThreads do
        ALLOWED_PIPES[i] = i
    end

    local filters = {}

    function SpecificFilterWebHandler:get()
        local function showFilter()
            local filterId = string.match(self.request.path, SPECIFIC_FILTER_REGEX)
            if filters[filterId] ~= nil then
                self:write(filters[filterId])
                self:finish()
            else
                error(turbo.web.HTTPError(404, { error = "Not found" }))
            end
        end

        apiUtils.ifAuthorized(self, args.apiToken, showFilter)
    end

    function SpecificFilterWebHandler:put()
        error(turbo.web.HTTPError(501, { error = "Update not implemented." }))
    end

    function SpecificFilterWebHandler:delete()
        local function deleteFilter()
            local filterId = string.match(self.request.path, SPECIFIC_FILTER_REGEX)
            if filters[filterId] ~= nil then
                local filter = filters[filterId]
                filters[filterId] = nil
                filter.action = event.delete
                -- Remove filter from flowscope
                for i, _ in ipairs(filter.pipes) do
                    pipes[i]:send(event.newEvent(filter.filter, event.delete, filter.id, filter.timestamp))
                end
                self:write(filter)
                self:finish()
            else
                error(turbo.web.HTTPError(404, { error = "Not found." }))
            end
        end

        apiUtils.ifAuthorized(self, args.apiToken, deleteFilter)
    end

    function FilterWebHandler:post()
        local function createFilter()
            -- this will raise an error if json is not present
            local jsonBody = self:get_json(true)

            -- decide if we have an array of filters or only one filter
            -- specific to one filter are the keys 'filter' and 'id' - but should not have more than 'filter', 'id',
            -- 'timestamp' and 'pipes' - else we are ignoring them
            -- whereas the array does not have any of these
            if jsonBody == nil then
                return error(turbo.web.HTTPError(400, { error = "Filter json malformed." }))
            end

            local singleFilter = jsonBody['filter'] ~= nil and jsonBody['id'] ~= nil
            print("Single filter: " .. tostring(singleFilter))
            if singleFilter then
                if apiUtils.checkFilterAttributes(jsonBody) then
                    local filter = apiUtils.prepareFilter(jsonBody, ALLOWED_PIPES)
                    apiUtils.applyFilter(filter, filters, pipes)
                    self:write(filter)
                    self:finish()
                    return
                else
                    return error(turbo.web.HTTPError(400, { error = "Filter json malformed." }))
                end
            end

            -- know we handle the pipelined filter application
            local appliedFilter = {}
            for i, jsonFilter in ipairs(jsonBody) do
                if apiUtils.checkFilterAttributes(jsonFilter) then
                    local filter = apiUtils.prepareFilter(jsonFilter, ALLOWED_PIPES)
                    apiUtils.applyFilter(filter, filters, pipes)
                    appliedFilter[#appliedFilter + 1] = filter
                else
                    return error(turbo.web.HTTPError(400, { error = "Filter json malformed." }))
                end
            end
            self:write(appliedFilter)
            self:finish()
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
        { SPECIFIC_FILTER_REGEX, SpecificFilterWebHandler },
        { "^/filter/$", FilterWebHandler }
    }
end

return mod
