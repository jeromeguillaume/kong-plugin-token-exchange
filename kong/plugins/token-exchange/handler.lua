-- handler.lua
local plugin = {
    PRIORITY = 1014,
    VERSION = "0.1",
  }

local resty_sha256  = require("resty.sha256")
local resty_str     = require("resty.string")
local http          = require "resty.http"
local utils         = require "kong.tools.utils"
local cjson         = require("cjson.safe").new()
        
  -- Function to hash a given key using SHA256 and return it as a hexadecimal string
local function hash_key(key)
  local sha256 = resty_sha256:new()
  sha256:update(key)
  return resty_str.to_hex(sha256:final())
end

-- Call the Token Exhcange endpoint
local function callTokenExchangeEndpoint(plugin_conf, bearer_token)
  local httpc = http.new()
  local headers = {}
  local body
  local errMsg
  local access_token = nil

  -- Remove leading spaces
  bearer_token = bearer_token:gsub("^%s+", "")

  if plugin_conf.token_endpoint_auth_method ~= "no" then
    
    if plugin_conf.token_endpoint_auth_method == "client_secret_basic" then
      if plugin_conf.client_id and plugin_conf.client_secret then      
        headers ["Authorization"] = "Basic " .. ngx.encode_base64(plugin_conf.client_id .. ":" .. plugin_conf.client_secret)
      end
    end
    
    if headers ["Authorization"] == nil then
      errMsg = "Unable to set the 'Authorization' header for token endpoint"
    end
  end
  
  if not errMsg then
    headers ["Content-Type"] = "application/x-www-form-urlencoded"
    body = ''
    if plugin_conf.param_value_audience then
      body = body .. "audience=" .. plugin_conf.param_value_audience .. "&"
    end
    if plugin_conf.param_value_grant_type then
      body = body .. "grant_type=" .. plugin_conf.param_value_grant_type .. "&" 
    end
    if plugin_conf.param_value_scope then
      body = body .. "scope=" .. plugin_conf.param_value_scope .. "&"
    end
    if plugin_conf.param_value_subject_token_type then
      body = body .. "subject_token_type=" .. plugin_conf.param_value_subject_token_type .. "&"
    end
    if plugin_conf.param_z_others then
      for k,v in pairs(plugin_conf.param_z_others) do
        body = body .. k .. "=" .. v .. "&"
      end        
    end
    body =  body .. plugin_conf.param_name_for_input_token .. "=" .. bearer_token
    
    if kong.configuration.log_level == "debug" then
      kong.log.debug("Headers:")
      kong.log.inspect(headers)
    end
    kong.log.debug("Body:", body)

    local res, err = httpc:request_uri(plugin_conf.token_endpoint, {
      method = "POST",
      headers = headers,
      body = body,
      keepalive_timeout = 60,
      keepalive_pool = 10
    })
    
    if err then
      errMsg =  "Token Exchange failed with '" .. err .. "' error"
    elseif res.status ~= 200 or res.body == nil then
      errMsg = "Token Exchange failed with status: " .. (res.status or 'nil') .. " and body: " .. (res.body or 'nil')
    else
      kong.log.debug("Token Exchange status: ", res.status, " body: ", res.body)
      local jwt, err = cjson.decode(res.body)
      
      if not err and jwt and jwt.access_token then
        access_token = jwt.access_token
      else
        errMsg = "Token Exchange response parsing failed, err: '" .. (err or 'nil') .. "' or 'access_token' claim is missing"        
      end    
    end
  end
    
  return access_token, errMsg

end

function plugin:access(plugin_conf)

  local entries
  local access_token
  local bearer_token
  local errMsg
  local client_authorization_header
  local client_authorization_header_part2
  local consumer_optional = plugin_conf.consumer_optional
  local consumer_claim = plugin_conf.consumer_claim
  local consumer_by = plugin_conf.consumer_by            
  local consumer_found = false
  local consumer
  local rc
  local claim
  local output_jwt
  local output_jwt_json
  local hit_level
  local errCode = 401
  
  -- Get the Header name from plugin configuration and try to split by ':' (for instance: 'Authorization:Bearer')
  -- for retrieving the Token Exchange
  entries = utils.split(plugin_conf.client_input_token_header, ":")
  if #entries == 2 then
    client_authorization_header = entries[1]        -- for instance: 'Authorization'
    client_authorization_header_part2 = entries[2]  -- for instance: 'Bearer'
  else
    client_authorization_header = plugin_conf.client_input_token_header  -- for instance: 'X-Token-Auth'
    client_authorization_header_part2 = ''
  end  
  
  local authorization_header = kong.request.get_header (client_authorization_header)
  
  -- If we found an Authorization Header
  if authorization_header ~= nil then
    -- Try to find a 2nd part in the Header value (for instance: 'Bearer')
    entries = utils.split(authorization_header, client_authorization_header_part2)
    if #entries == 2 then
      bearer_token = entries[2]
    else
      bearer_token = authorization_header
    end
  end

  -- If there is no Authorization Header
  if not bearer_token then
    
    -- If we must bypass the process (because there is no Authorization Header)
    if plugin_conf.bypasss_process_if_no_input_token == true then
      kong.log.debug("Bypass the token exchange process because there is no bearer token")  
      return
    else
      errMsg = "Unable to find the bearer token from '"..(client_authorization_header or 'nil').."' header"
    end
  end
  
  if not errMsg then
    
    local bearer_token_key = hash_key(bearer_token)
    -- If the cache is disabled
    if plugin_conf.cache_TTL == 0 then
      access_token, errMsg = callTokenExchangeEndpoint (plugin_conf, bearer_token)
    
    -- Else the cache is enabled
    else      
      for i = 1, 2 do
        access_token, errMsg, hit_level = kong.cache:get(bearer_token_key, { ttl = plugin_conf.cache_TTL }, callTokenExchangeEndpoint, plugin_conf, bearer_token)
        -- If there is no errMsg and hit_level is level 4, it means that an error has happened
        --    but the cache system is returning the stale value, 
        --    which doesn't make sense in the case where plugin_TTL = JWT_TTL (, which is the recommended configuration)
        -- See https://github.com/thibaultcha/lua-resty-mlcache?tab=readme-ov-file#get
        if errMsg == nil and hit_level == 4 then
          -- Remove the stale value from the cache
          kong.cache:invalidate(bearer_token_key)
          -- Loop again to try to get a fresh value
        else
          break
        end
      end
    end
    
    if not errMsg then
      -- Convert the JWT payload to a JSON
      if access_token then
        entries = utils.split(access_token, ".")
      end
      if #entries == 3 then
        output_jwt = entries[2]
        local decode_base64 = ngx.decode_base64
        local decoded = decode_base64(output_jwt)
        output_jwt_json, errMsg = cjson.decode(decoded)

        -- Check Expiration claim
        if not output_jwt_json and not errMsg then
          errMsg = "Unable to decode the output JWT payload"
        elseif not errMsg and ngx.time () > output_jwt_json.exp then
          errMsg = "The token exchange has expired"
        end

      else
        errMsg = "Inconsistent JWT: unable to get the typical structure Header.Payload.Signature"
      end
    end

    if not errMsg then

      -- Loop on all "consumer claim"; it could be: "sub", "cid", etc.
      for j = 1, #consumer_claim do
        
        -- Authenticate the consumer if needed       
        -- Loop on all "consumer by"; it could be: "id", "username", "custom_id",
        for i = 1, #consumer_by do
        
          consumer = nil
          claim = output_jwt_json[consumer_claim[j]]
          
          if claim then
            local result, err   
            if consumer_by[i]:find("username") then
              consumer, err = kong.db.consumers:select_by_username(claim)                
            elseif consumer_by[i]:find("custom_id") then
              consumer, err = kong.db.consumers:select_by_custom_id(claim)
            elseif consumer_by[i]:find("id") then
              consumer, err = kong.db.consumers:select({ id = claim })
            else
              errMsg = "Unsupported consumer_by: ".. consumer_by[i]
            end
            if not err and consumer then
              kong.client.authenticate(consumer, nil)
              consumer_found = true
              kong.log.notice("loading consumer by ", consumer_by[i], " using ", claim)
              break
            end
          end
        end
        
        if consumer_found == true then
          break
        end
      end

      -- If the consumer match is required and the consumer is not found
      if not consumer_optional and #consumer_claim > 0 and not consumer_found then
        errCode = 403
        errMsg = "Unable to authenticate the consumer using the output of token exchange"
      end
      
    end
    
    if not errMsg then
      -- Append the 'access_token' in Downstream header
      if plugin_conf.downstream_output_token_header then
        kong.response.set_header(plugin_conf.downstream_output_token_header, access_token)
      end
      
      local upstream_access_token = plugin_conf.upstream_output_token_header
      -- Append the 'access_token' in Upstream header
      if upstream_access_token then
        -- Split by : (for instance: 'authorization:bearer')
        entries = utils.split(upstream_access_token, ":")
        if #entries == 2 then
          kong.service.request.set_header(entries[1], entries[2] .. " " .. access_token)
        else
          kong.service.request.set_header(upstream_access_token, access_token)
        end
      end
    end
    
  end
    
  if errMsg then
    kong.log.err(errMsg)    
    return kong.response.exit(errCode, { message = errMsg },  {["Content-Type"] = "application/json"})
  end

  kong.log.debug("output_token=", access_token) 
end
  
return plugin