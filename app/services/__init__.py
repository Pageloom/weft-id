"""Service layer modules.

The service layer sits between routes and the database layer, providing:
- Business logic (validation, side effects)
- Authorization (can this user do this action?)
- HTTP-agnostic operations that return Pydantic models

Routes handle authentication (who is this user?) and inject requesting_user.
"""
