# Infisical bootstrap transport

HTTPS remains required by default. For an intentionally trusted private container
network, the operator may configure:

```dotenv
INFISICAL_API_URL=http://infisical-backend:8080
INFISICAL_ALLOW_INSECURE_HTTP=true
```

The existing `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_PROJECT_ID`
and `INFISICAL_ENV` are still required. The hostname must resolve on the private
network shared by the container and Infisical. Credentials and returned secrets
travel in plaintext on this connection; do not expose it publicly.

An unset/false exception rejects HTTP. Unsupported schemes, embedded URL credentials,
query strings and fragments are rejected even when the exception is enabled.
The SDK is not contacted when URL validation fails. No live service settings are
changed by adding this support; redeploy the new image with the intended environment.
