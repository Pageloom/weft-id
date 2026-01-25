# Notes

Quick reminders to later build out into full backlog items.

- Darkmode + auto switch depending on device mode
- Add backstop test that checks that all frontend endpoints that are not GET are csrf-protected
- With email based sign-in - verify email address on initial sign-in step.
- IP allow list
- Groups and groups of groups?
- Groups - something that can bring in groups from IdPs.
- Allow super admins to turn off MFA for a user (effectively resetting to email MFA)
- Verify all links in all frontend templates lead to actual frontend endpoints
- Establish a single baseline SQL schema rather than going through all migrations
- Ensure all events log required values (device, IP, User Agent, session ID hash) even without RequestingUser
- Add verbose descriptions for each Event Type in code, display on event details page
- Remove "Request Context" section from event detail pane (duplicates Event Metadata)

