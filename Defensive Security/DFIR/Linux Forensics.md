
> Check out [[Linux Privilege Escalation]] for other important details.

### OS & Account Information

**Unix Logs**: Check out [[Logs#Unix Logs|Unix Logs]] for the different log files available for examination.

**OS Release Information**: The `/etc/os-release` file can be used to find the OS release information.

**User Accounts**: The `/etc/passwd` file contains information about the users that exist. It has information on the username, password, user id, group id, description, home directory, and the default shell.
- User created accounts have user id of 1000 or more.

**Groups**: The `/etc/group` file has information about the different user groups present on the system.

**Sudoers List**: The `/etc/sudoers` file shows which users are allowed to elevate privileges to `sudo`.

### System Configuration

**Hostname**: The system hostname is stored in the `/etc/hostname` file.

**Timezone**: The timezone information can be obtained from the `/etc/timezone` file.

**Network Configurations**: To view the network interfaces, we can use:
```
cat /etc/network/interfaces

ip address show
```

**Active Network Connections**: To view active connections, we can use the `netstat` utility. This showcases the connection by [[IP]] address, [[Port]], and process.
```
netstat -natp
```

**Running Processes**: To view the current running processes on the system, we can use the `ps` utility:
```
ps aux
```

**[[Domain Name System (DNS)]]**: The configuration for the DNS assignment is visible in the `/etc/hosts` file. Information about the servers used for DNS is visible in the `/etc/resolv.conf` file.

### Persistence Mechanisms

**Cron Jobs**: These are commands that run periodically as defined by a set period of time. These are located in `/etc/crontab`. It showcases the command to run, the username to run it, and where the command/script is located.

**Service Startups**: Services can be setup that will start and run in the background after every system boot. These services can be found in the `/etc/init.d` directory, by running `ls`.

**Bashrc**: The `.Bashrc` file is a list of actions to be performed when a bash shell is spawned. It is located at `~/.bashrc` for a certain user. System wide settings are located in `/etc/bash.bashrc` and `/etc/profile`.

### Evidence of Execution

**Sudo Execution History**: All commands run using `sudo` are stored in the `/var/log/auth.log` file.

**Command Execution History**: All other commands run without `sudo` are stored in the bash history. The bash history is unique per user, and it is found at `~/.bash_history`.

**Files Accessed Using `vim`**: Files accessed using the `vim` text editor are logged in the `~/.viminfo` file. Has command line history, search string history, ...

---
