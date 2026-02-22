# Notes

Quick reminders to later build out into full backlog items.

## SAML Federation & IdP Capabilities

- Make WeftId itself one of the default IdPs alongside Entra ID, etc.
- Setting to add contact information attributes in metadata
- Fields on SPs and IdPs to add contact information to the records themselves so that
  you know who to reach out to if you need action from your counterpart. Optional fields.

## UX & Admin Experience
 
- Rethink from the ground up how to view groups. We want a plain list, where each column tells us how many parents
  and children the group has. How many members it has (including from child groups). We also want the "Actions" column,
  removed. Furthermore, we want to be able to pivot to a network graph view, some groups can appear in it in multiple
  places. Each group should have its own node, and the arrows should be be directed from child to parent(s). It should
  be possible to zoom in and out of the graph. At 100% zoom, the graph should attempt to show all groups in the network,
  however, this may not be possible due to the number of groups and the amount of information in each node. If so, since
  we're working with vector graphics, we can just make things smaller, even if the visibility is reduced, one will
  simply have to zoom. If you zoom in, things may very well fall outside the visible area - in which case the user
  should be able to pan around to see the rest of the graph.
- A "Group" is now a page with a very big control for name and description, followed by subsections to get into
  member management, assigned apps, parent groups and child groups. This needs to be reworked into a
  tabbed page, like the service provider detail page (or the IdP detail page). Furthermore, the parent 
  and child relationships should be represented in its own tab - with the group in the middle, and arrows to each
  parent and child group, they in turn have a hint of how many children (if they are a child), and parents (if)
  they are a parent. Clicking on a child or parent should lead to the exact same page on that group, in essence
  creating a navigable multi-trunked tree.
- Automation and administration benevolence. What areas of the app can be automated
  for the admin personas, and what typical admin tasks are arduous and work-intensive
  that can be helped by automation or benevolent UIs for special cases?
- Add new Todo sub-section: "Users not in any group"
- Make it possible to make any user into an SP manager - in the sense that they get to decide who
  has access to an SP. How does this interweave with groups? The user must themselves be a member of the group.
- Add a feature that makes it possible to limit how many can sign in to an app. Like... seats. This will have
  to be on a first-come-first-served basis. So if you have a 100 seats - and we're already at 100 people having
  successfully authenticated to that app - then no more people will be able to authenticate. This also requires
  that admins are made aware of a reached limit. Either cleanup of users is needed, or seat limit increased.
  We already have the data in the event log - but I think it would be nice to have a table that actually tracks
  which users have successfully authenticated to which apps and when. That way we can easily count and compare with
  seats.

# Automation

- Think of different ways that rules could be established that would allow admins and super admins to avoid
  repetitive tasks. Triggers could be: "new verified user", "new user with certain domain"

## Platform Operations & Security

- Backoffice functionality. How do we go about making it easy for someone who decides
  to host this for customers or for sub-organisations? Is this a separate product perhaps, with some
  sort of agent that connects to machines running this app? What are the considerations we need to take
  into account to make sure that this "master" backoffice-app is secure, audited etc? And how do we secure the
  connection between the master app and the machines running WeftId.
- Signin rate limiting should be aggressive at the tenant level, and much less aggressive
  on the global level. At least the IP rate limit.
- IP allowlist (or similar ability to restrict access to certain IPs or networks).

## Quality, Testing & Developer Experience

- Documentation of the entire app.
- Create an accessibility agent whose focus it is to make sure that the frontend has
  a good accessibility posture, according to some standard.
- Backstop test that verifies all links in all frontend templates lead to actual
  frontend endpoints.

## Housekeeping

- Follow up on "Background Job Created" as an event type. Does it really need to
  exist? It doesn't change data.

