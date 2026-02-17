# Notes

Quick reminders to later build out into full backlog items.

## SAML Federation & IdP Capabilities

- Make WeftId itself one of the default IdPs alongside Entra ID, etc.
- Setting to add contact information attributes in metadata
- Fields on SPs and IdPs to add contact information to the records themselves so that
  you know who to reach out to if you need action from your counterpart. Optional fields.

## UX & Admin Experience

- Rethink from the ground up how to view groups. We want a hierarchical view,
  a nice big list view within each group of users, and a nice view for app relations.
- Make it possible to brand the "WeftID" mandala and the "WeftId" title.
- Automation and administration benevolence. What areas of the app can be automated
  for the admin personas, and what typical admin tasks are arduous and work-intensive
  that can be helped by automation or benevolent UIs for special cases?
- Add new Todo sub-section: "Users not in any group"
- Make it possible to make apps (SPs) available to all users regardless of their group membership.
- Make it possible to make any user into an SP manager - in the sense that they get to decide who
  has access to an SP. How does this interweave with groups.
- Add a feature that makes it possible to limit how many can sign in to an app. Like... seats. This will have
  to be on a first-come-first-served basis. So if you have a 100 seats - and we're already at 100 people having
  successfully authenticated to that app - then no more people will be able to authenticate. This also requires
  that admins are made aware of a reached limit. Either cleanup of users is needed, or seat limit increased.
  We already have the data in the event log - but I think it would be nice to have a table that actually tracks
  which users have successfully authenticated to which apps and when. That way we can easily count and compare with
  seats.

## Platform Operations & Security

- Backoffice functionality. How do we go about making it easy for someone who decides
  to host this for customers or for sub-organisations?
- Signin rate limiting should be aggressive at the tenant level, and much less aggressive
  on the global level. At least the IP rate limit.
- IP allowlist (or similar ability to restrict access to certain IPs or networks).

## Quality, Testing & Developer Experience

- Documentation of the entire app.
- Create an accessibility agent whose focus it is to make sure that the frontend has
  a good accessibility posture, according to some standard.
- E2E tests (API and Playwright) should live in the same repo, not a separate one.
- Backstop test that verifies all links in all frontend templates lead to actual
  frontend endpoints.

## Housekeeping

- Follow up on "Background Job Created" as an event type. Does it really need to
  exist? It doesn't change data.

