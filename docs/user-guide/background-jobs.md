# Background Jobs

Some operations in WeftID run in the background, such as exporting the event log. You can check the status of these jobs and download their output from the Background Jobs page.

Navigate to your account menu and select **Background Jobs**.

## Job list

The page shows all jobs you have created, with their type, status, and available actions.

| Status | Meaning |
|--------|---------|
| Requested | Job is queued and waiting to be processed |
| Ongoing | Job is currently running |
| Completed | Job finished successfully |
| Failed | Job encountered an error |

If any jobs are still running, the page refreshes automatically every 10 seconds.

## Viewing output

Click **View Output** on a completed or failed job to see its details: when it was created, started, and completed, along with any output or error message.

## Downloading files

Jobs that produce a file (such as event exports) show a **Download** link. Export files are retained for 24 hours. After that, the link shows "File expired" and a new export must be created.

## Deleting jobs

Select completed or failed jobs using the checkboxes and click **Delete** to remove them from the list. Active jobs (requested or ongoing) cannot be deleted.
