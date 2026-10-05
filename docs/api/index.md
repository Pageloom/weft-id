# API

WeftID provides a RESTful API under `/api/v1/` for programmatic access to all platform features. The API uses OAuth2 bearer tokens for authentication.

## Interactive documentation

When OpenAPI documentation is enabled, interactive API reference is available at:

- **Swagger UI**: `/api/docs`
- **ReDoc**: `/api/redoc`
- **OpenAPI schema**: `/openapi.json`

## Authentication

API requests authenticate with an OAuth2 bearer token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Tokens come from an OAuth2 client: an [app](../admin-guide/integrations/apps.md) acting for a user (authorization code flow or device sign-in), or a [service account](../admin-guide/integrations/b2b.md) acting as its own service user (client credentials flow).

## Conventions

- All endpoints return JSON
- List endpoints support pagination via `page` and `limit` query parameters
- Errors return a JSON object with a `detail` field
- IDs are UUIDs represented as strings
