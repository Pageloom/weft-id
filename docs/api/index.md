# API

WeftId provides a RESTful API under `/api/v1/` for programmatic access to all platform features. The API uses OAuth2 bearer tokens for authentication.

## Interactive documentation

When OpenAPI documentation is enabled, interactive API reference is available at:

- **Swagger UI** — `/api/docs`
- **ReDoc** — `/api/redoc`
- **OpenAPI schema** — `/openapi.json`

## Authentication

API requests authenticate with an OAuth2 bearer token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Tokens are issued through the OAuth2 authorization code flow. See [Integrations](../admin-guide/index.md) in the admin guide for how to create OAuth2 clients.

## Conventions

- All endpoints return JSON
- List endpoints support pagination via `page` and `page_size` query parameters
- Errors return a JSON object with a `detail` field
- IDs are UUIDs represented as strings
