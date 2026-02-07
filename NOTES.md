# Notes

Quick reminders to later build out into full backlog items.

- "Does user X have access to app Y?" function for admins. Overview and export of apps available to a specific user.
  (Depends on SAML IdP Phase 2 delivering the app assignment model.)
- Create an accessibility agent whose focus it is to make sure that the frontend has a good accessibility posture,
  according to some standard.
- Follow up on "Background Job Created" as an event type. Does it really need to exist? It doesn't change data.
- IP allowlist (or similar ability to restrict access to certain IPs or networks)
- E2E tests (API and Playwright) should live in the same repo, not a separate one.
- Automation and administration benevolence. What areas of the app can be automated for the admin personas,
  and what typical admin tasks are arduous and work-intensive that can be helped by automation or
  benevolent UIs for special cases?
- Backstop test that verifies all links in all frontend templates lead to actual frontend endpoints
- Establish a single baseline SQL schema rather than going through all migrations
