### Unix Files

###### `/var/log/auth.log` 
 Has authorization information about user logins and authentication mechanisms used.
- Has the date, followed by the [[IP]] of the machine that the log was generated on, the process and process ID that generated the log , the description of the log.
###### `/var/log/*tmp` 
The `*tmp` files that hold logon history information.
- `/var/log/btmp` logs failed logon attempts.
- `/var/run/utmp` logs stats, including successful logons, boot time, logouts, and other events of the _current state_ of the system — i.e., since its last boot.
- `/var/log/wtmp` contains historical content of `utmp`, allowing you to peek back in time. Check `wtmp` [man page](https://linux.die.net/man/5/wtmp) for information on how to read the entries, and the types of entries.

The content in this file follows the `utmp` struct format.
- To read these files, either use `last` or use `utmpdump`.

###### `/var/log/kern`
Stores kernel related events.

###### `/var/log/httpd`
Stores [[HTTP]] request/response logs and any errors.
- Also has *Apache* related logs, which can also be found in `/var/log/apache`.

###### `/var/log/cron`
Events related to cron jobs.


---
### Windows Files

All windows logs can be viewed through the [[Event Viewer]] utility.

###### `C:\Windows\System32\winevt\Logs`

Has [[Windows Events Log]]s files.

---
