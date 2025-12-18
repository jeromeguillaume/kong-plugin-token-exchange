# Kong plugin: `token-exchange` for OAuth2 Authorization Server (On-Behalf-Of Token Exchange)
The plugin offers an OAuth On-Behalf-Of Token Exchange. It exchanges one token for another between trust domains by alling an OAuth2 server. The plugin works for Kong EE and Konnect.

For the rest of the document:
- The **ìnput** (token) is the source of the token to be exchanged
- The **output** (token) is the new token exchanged when calling the `/token` endpoint on an OAuth2 server

The main capabilities are:
1) Get the input token from a request HTTP Header (`Authorization` header or another HTTP header)
2) Call the OAuth On-Behalf-Of Token Exchange endpoint
3) If the token endpoint call is successful, all these operations are optionally executed:
    - The output token is placed in an upstream HTTP request header
        - It can overwrite the input token (specially for `Authorization` header)
    - The output token is put in a cache (avoiding too many calls on the token exchange endpoint)
    - The Kong Consumer is loaded
        - The loading of Kong Consumer is optional
    - The output token is put in a downstream HTTP response header
4) If the token endpoint call fails or if the output token was cached & has expired:
    - HTTP `401` Error is sent to the client
5) If the Kong Consumer loading is enabled and fails:
    - HTTP `403` Error is sent to the client
    - No `403` error if `consumer_optional`=`true`

## Test the plugin with Okta
1) Create an Okta instance
    - See Integrator Free Plan: https://developer.okta.com/signup/
2) Set up Okta
    - [Set up OAuth 2.0 On-Behalf-Of Token Exchange](https://developer.okta.com/docs/guides/set-up-token-exchange/main/)
    - Okta asked to create 2 applications; copy the client_id/client_secret associated to them:
        - **Native app integration**
        - **Service app** (supporting the token exchange)
    - Create users for AuthZ code flow:
        - Open the menu: Directory/People
        - Create 2 users and replace `first.last` by your real firstname, lastname and domain name:
            - first.last@konghq.com
            - first.last+mcp@konghq.com
3) Other Okta configuration for `OpenId Connect` plugin:
    - Open the menu: Security / API
    - Open the `default` Authorization server
    - Add a `kong-scope` with:
        - User consent=`Implicit`
        - Default scope=`Set as a default scope`
    - Note: **if you don't append this scope , the `OpenId Connect` plugin is rejected by a 400 error**
4) Deploy Kong EE or Prepare your Konnect environment
    - For kong EE use `docker compose`:
    ```shell
    docker compose up -d
    ```
5) Apply the yaml decK configuration
    - Prerequisites (see step #2 for having the proper values to replace):
        - For **Native app integration**:
            - Replace `native_app_client_id` by the client_id
            - Replace `native_app_client_secret` by the client_secret
        - For **Service app**:
            - Replace `service_app_client_id` by the client_id
            - Replace `service_app_client_secret` by the client_secret
        - For `token_endpoint` and `issuer`:
            - Replace `https://integrator-YOUR-ID.okta.com/oauth2/default/v1/token` by your Okta token endpoint
        - For `Consumers`:
            - Replace first.last@konghq.com and first.last+mcp@konghq.com by your real firstname, lastname and domain name
    - Execute decK:
    ```shell
    `deck gateway sync --kong-addr=http://localhost:9002 --select-tag okta-token-exchange ./okta-token-exchange.yaml`
    ```
    Now there are 2 routes:
    - `/httpbinOkta`: the `OpenId Connect` plugin is configured
    - `/httpbinExchangeOkta`: the `token-exchange` plugin is configured
    
6) Test the Kong routes with a Client credentials grant
    - Call `/httpbinOkta` and provide an `Authorization:Basic` by using the client_id/client_secret of the **Native app integration**
        - Copy/Paste the **input** token from `Authorization:Bearer` in the Response Body
    - Call `/httpbinExchangeOkta` and put the **input** token in `Authorization:Bearer`
        - The **output** token can be seen in:
            - `Authorization:Bearer`: Rsponse Body
            - `X-Token-Exchange`: Reponse HTTP header
7) Compare input and output tokens
    - Open https://jwt.io
    - Copy/paste the 2 tokens
    - Pay attention to `cid` and `scp` claims:
        - input token `cid` is `native_app_client_id`
        - output token `cid` is `service_app_client_id`
        - input token `scp` is `kong-scope`
        - output token `cid` is `api:access:read api:access:write`
8) Test the Kong routes with an Authorization code flow
    - Get a JWT token:
        - Enable the AuthZ code flow (on `OIDC` plugin `/httpbinOkta`)
        - Use the Insomnia Auth tab (with Grant Type=Authorization code)
    - Use the JWT token as an input token on `/httpbinExchangeOkta` and Get the output token
    - Open https://jwt.io and see the `sub` claim with the user name

## Recommendation
- For `AI MCP Proxy` plugin:
    - By enabling `bypasss_process_if_no_input_token` the token exchange call itself is not executed when there is no input token during initialization phase (of AuthZ code flow)

## `token-exchange` plugin configuration reference
|FORM PARAMETER                 |DEFAULT          |DESCRIPTION                                                 |
|:------------------------------|:----------------|:-----------------------------------------------------------|
|config.bypasss_process_if_no_input_token|true|the token process is not processed in the event there is no input token given by `client_input_token_header`|
|config.cache_TTL|0|Put in the Kong Memory cache the output token. If `cache_TTL` = 0 there is no caching|
|config.client_id|N/A|Client ID to be used for authentication when `token_endpoint_auth_method` is set to `Authorization: Basic`|
|config.client_secret|N/A|Client Secret to be used for authentication when `token_endpoint_auth_method` is set to `Authorization: Basic`|
|client_input_token_header|Authorization:Bearer|HTTP Request header to look for the input token. If the `Bearer` part is specified, the plugin takes it into account|
|consumer_by|username,custom_id|Consumer fields used for mapping: - id: try to find the matching Consumer by id - username: try to find the matching Consumer by username - custom_id: try to find the matching Consumer by custom_id.|
|consumer_claim|N/A|The claim used for consumer mapping. If multiple values are set, it means the claim is inside a nested object of the token payload.|
|consumer_optional|false|Do not terminate the request if consumer mapping fails|
|downstream_output_token_header|N/A|The response downstream output token header|
|param_value_audience|api://default|The value of `audience` parameter passed to token endpoint|
|param_value_grant_type|urn:ietf:params:oauth:grant-type:token-exchange|The value of `grant_type` parameter passed to the token endpoint|
|param_value_scope|api:access:read api:access:write|The value of `scope` parameter passed to token endpoint|
|param_value_subject_token_type|urn:ietf:params:oauth:token-type:access_token|The value of `token_type` parameter passed to token endpoint|
|param_name_for_input_token|subject_token|The parameter name that receives the input token value|
|param_z_others|N/A|Map for other names of parameter and their associated values|
|token_endpoint_auth_method|client_secret_basic|The default authentication method is `client_secret_basic` (using `Authorization: Basic` header) for calling the token endpoint|
|upstream_output_token_header|Authorization:Bearer|The request upstream input token header|
|token_endpoint|N/A|URL OAuth2 token endpoint|

## Known limitations
- The search for `Bearer` in `Authorization:Bearer` (`config.client_input_token_header`) is case sensitive