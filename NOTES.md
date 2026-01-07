# Notes

Quick reminders to later build out into full backlog items.

- Rate limit sign in attempts
- With email based sign-in - verify email address on initial sign-in step.
- Allow super admins to turn off MFA for a user (effectively resetting to email MFA)
- Verify all links in all frontend templates lead to actual frontend endpoints
- Establish a single baseline SQL schema rather than going through all migrations
- Ensure all events log required values (device, IP, User Agent, session ID hash) even without RequestingUser

## Done
- Improve execution time of tests - which tests can be run in parallel?