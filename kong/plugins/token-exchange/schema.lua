
local typedefs = require "kong.db.schema.typedefs"


return {
  name = "token-exchange",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { bypasss_process_if_no_input_token = { required = true, type = "boolean", default = true, }, },
          { cache_TTL = { required = false, type = "number", default = 0, }, },
          { client_id = { required = true, type = "string" }, },
          { client_input_token_header = { required = true, type = "string", default = "Authorization:Bearer", }, },
          { client_secret = { required = true, type = "string", }, },          
          { consumer_by = {
              required = false,
              type = "array",
              default = {
                "username",
                "custom_id",
              },
              elements = {
                type = "string",
                one_of = {
                  "id",
                  "username",
                  "custom_id",
                },
              },
            },
          },
          { consumer_claim = { required = false,
              type = "array",
              elements = {
                type = "string",
              },
            },
          },
          { consumer_optional = { required = false, type = "boolean", default = false, }, },
          { downstream_output_token_header = { required = false, type = "string" }, },
          { param_value_audience = { required = false, type = "string", default="api://default" }, },
          { param_value_grant_type = { required = false, type = "string", default="urn:ietf:params:oauth:grant-type:token-exchange" }, },
          { param_value_scope = { required = false, type = "string", default="api:access:read api:access:write" }, },
          { param_value_subject_token_type = { required = false, type = "string", default="urn:ietf:params:oauth:token-type:access_token" }, },
          { param_name_for_input_token = { required = true, type = "string", default="subject_token" }, },          
          { param_z_others = { type = "map", required = false, 
            keys = { type = "string", required = true },
            values = {type = "string", required = true},
          }},
          { token_endpoint_auth_method = { required = true, type = "string", default = "client_secret_basic",
              one_of = {
                "client_secret_basic",
                "no"
              },
            },
          },
          { upstream_output_token_header = { required = false, type = "string", default = "Authorization:Bearer",} , },
          { token_endpoint = typedefs.url {required = true}, },
        },
      }, 
    },
  },
}