# Session verification

Configure `AUTH_SECRETS` with the Auth.js secret. Use comma-separated keys during rotation.
Set `AUTH_SALT` and `AUTH_COOKIE_NAME` to the application cookie name, including its `__Secure-` prefix.

Private proxies can call `POST /verify` with `{"token":"<session JWE>"}`.
The service returns `{"success":true,"payload":{...}}` only after authentication, expiration, and subject checks.
Invalid sessions return 401. Invalid request bodies return 400. Responses prohibit caching.
The endpoint rejects caller-supplied keys and salts. Keep port 80 on a private service network.

`/auth` remains available for ForwardAuth integrations. It accepts complete cookies or consecutive Auth.js cookie chunks.
Both cookie formats reject duplicates, missing chunks, and mixed formats.
Leave `AUTHWALL_ENABLE_DEBUG_ENDPOINTS` unset in production. `/verify` does not require debugging.

The default cookie name is `authjs.session-token`. Deployments using the former underscore default must explicitly configure their cookie name.

```sh
go test ./...
go build .
```
