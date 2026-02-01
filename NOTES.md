# Notes

Quick reminders to later build out into full backlog items.

- In the users list the auth-method is listed as None if a user has email/password. Given that that email
  possession must always be proved, lets list it as email/password.
- How do we make user to group assignment super easy and efficient and delightful in the UI? There must be ways to bulk select users
  and bulk select groups, there must also be some sort of way to get an efficient overview, perhaps a canvas with venn-diagrams that show the overlaps of groups somehow? What do we need to do here, because this is central to the usability of the app.
- Create an accessibility agent whose focus it is to make sure that the frontend has a good accessibility posture,
  according to some standard.
- Follow up on "Background Job Created" as an event type—does it really need to exist? It doesn't change data.
- IP allowlist (or similar ability to restrict access to certain IPs or networks)
- Separate repo for end-to-end API tests ramped up on the openAPI spec, or should they live with the codebase?
- Separate repo for playwright tests, or should they live with the codebase?
- Groups and groups of groups?
- Groups - something that can bring in groups from IdPs.
- Automation and administration benevolence - what areas of the app can be automated for the admin personas, 
  and what typical admin tasks do we see that are ardous and work-intesive that can be helped by automation OR
  benevolent UIs for special cases?
- Exports of users for different audiences (such as all logins)
- Backstop test that verifies all links in all frontend templates leads to actual frontend endpoints
- Establish a single baseline SQL schema rather than going through all migrations

