# Background Jobs

Some operations run in the background: event log exports, bulk email operations, and other long-running tasks. Check their status from your account menu at **Background Jobs**.

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

### File passwords

Exported XLSX files are password-encrypted. The password appears in the **Password** column next to the download link. Copy the password before downloading. The password is only available on the Background Jobs page.

## Deleting jobs

Select completed or failed jobs using the checkboxes and click **Delete** to remove them from the list. Active jobs (requested or ongoing) cannot be deleted.
