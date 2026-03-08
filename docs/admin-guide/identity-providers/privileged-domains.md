# Privileged Domains

Privileged domains let you route users to a specific identity provider and auto-assign them to groups based on their email domain.

## Adding a domain

1. Navigate to **Settings > Privileged Domains**
2. Click **Add Domain**
3. Enter the email domain (e.g., `acme.com`)
4. Click **Add**

## Binding an IdP

Each domain can be bound to one identity provider. When a user with a matching email domain signs in, they are automatically directed to that IdP instead of seeing the IdP selection page.

To bind an IdP, select it from the domain's configuration panel.

## Linking groups

Link one or more groups to a domain. When a user is created with an email address matching that domain, they are automatically added to the linked groups.

This applies to both manually created users and JIT-provisioned users.

### Example

1. Add the domain `engineering.acme.com`
2. Link it to the "Engineering" group
3. When `alice@engineering.acme.com` is created, she is automatically added to the Engineering group

## Removing a domain

Unlink all groups and unbind the IdP before deleting a domain.
