local turbo = require 'turbo'

local module = {}

function module.checkForToken(requestHandler, allowedToken)
  local token = requestHandler.request.headers:get("X-Authorization-Token", true)
  if token ~= nil then
      for _,v in pairs(allowedToken) do
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
    error(turbo.web.HTTPError(401, {message = "Unauthorized."}))
  end
end

function module.checkFilterAttributes (filterObject)
  local requiredKeys = filterObject['id'] ~= nil and filterObject['filter'] ~= nil
  -- pipes present => it should be an array of numbers (logical consequence)
  local pipesCorrect = not (filterObject['pipes'] ~= nil) or (type(filterObject['pipes']) == 'table')
  return requiredKeys and pipesCorrect
end

return module
