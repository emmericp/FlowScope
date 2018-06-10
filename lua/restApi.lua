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
        local function notImplemented()
            error(turbo.web.HTTPError(501, { error = "Update not implemented." }))
        end

        apiUtils.ifAuthorized(self, args.apiToken, notImplemented)
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

            local singleFilter = jsonBody['filter'] ~= nil or jsonBody['id'] ~= nil

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

            -- now we handle the pipelined filter application
            local appliedFilter = {}
            local filter_error = {}
            for _, jsonFilter in ipairs(jsonBody) do
                if apiUtils.checkFilterAttributes(jsonFilter) then
                    local filter = apiUtils.prepareFilter(jsonFilter, ALLOWED_PIPES)
                    apiUtils.applyFilter(filter, filters, pipes)
                    appliedFilter[#appliedFilter + 1] = filter
                else
                    filter_error[#filter_error + 1] = filter
                end
            end
            if #filter_error ~= 0 then
                return error(turbo.web.HTTPError(400, {
                    error = "Filter json malformed.",
                    error_ids = filter_error,
                    applied_filter = appliedFilter
                }))
            else
                self:write(appliedFilter)
            end
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

    function FilterWebHandler:delete()
        local function showFilters()
            local arguments = self.request.arguments
            local filter_ids = {}

            if arguments['filter_id'] ~= nil then
                if type(arguments['filter_id']) == 'table' then
                    filter_ids = arguments['filter_id']
                else
                    filter_ids[#filter_ids + 1] = arguments['filter_id']
                end
            else
                return error(turbo.web.HTTPError(400, { error = "URL parameter malformed." }))
            end
            -- arrays to keep track which filter_ids we have deleted and which we couldn't find
            local removed_filter = {}
            local filter_not_found = {}
            for _, filterId in pairs(filter_ids) do
                if filters[filterId] ~= nil then
                    local filter = filters[filterId]
                    filters[filterId] = nil
                    filter.action = event.delete
                    -- Remove filter from flowscope
                    for i, _ in ipairs(filter.pipes) do
                        pipes[i]:send(event.newEvent(filter.filter, event.delete, filter.id, filter.timestamp))
                    end
                    removed_filter[#removed_filter + 1] = filter
                else
                    filter_not_found[#filter_not_found + 1] = filterId
                end
            end

            if #filter_not_found ~= 0 then
                return error(turbo.web.HTTPError(404, { error = "Filter not found", not_found_ids = filter_not_found, removed_filter = removed_filter }))
            end

            self:write(removed_filter)
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
