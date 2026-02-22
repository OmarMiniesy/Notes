### General Notes

A lateral movement technique by stealing [[Kerberos]] *TGTs* and *TGSs* from the memory of a compromised system and reuses it to authenticate to services without knowing the user's passwords.
- Instead of using an [[NTLM]] hash to authenticate, the attacker uses a valid Kerberos ticket that was already issued by the [[Domain Controller]].

---
### Attack Path

The attacker first needs to gain initial access to a system, and then execute either `mimkatz` or `rubeus` to extract valid **TGT** or **TGS** tickets from the system memory.
- Using `rubeus`:
```powershell
.\Rubeus.exe monitor /interval:30
```
- This polls [[Windows Processes#`lsass.exe`|LSASS.exe]] every 30 seconds to enumerate all Kerberos tickets currently in memory.

Once a ticket is produced, the attacker can submit the extracted ticket for the current logon session and can authenticate to other systems with this ticket:
```
.\Rubeus.exe ptt /ticket:<ticket>
```

To check the current list of tickets in the session:
```
klist
```

---
### Detection

Check out [[Splunk Queries#Detecting Pass the Ticket]]
###### Technique 1
Detecting this attack from normal Kerberos authentication is to find a partial authentication process.
- Since an attacker imports a TGT ticket into a logon session and requests a TGS ticket for a remote service, the TGT was never requested.
- From the [[Domain Controller]] perspective, the imported TGT was never requested before from the attacker’s system, so there won't be an associated [[Windows Events Log]] Event ID `4768`.
- To do this, we can look for Event ID `4769` or `4770` which are for TGS request and renewal, without a prior `4768`, which is a TGT request.

###### Technique 2
Look for a discrepancy in the metadata of the event for the TGS request and the event for the network connection based on the injected ticket.
- Event ID `4769` has the TGS request data stating that the client will access a certain server/service.
- But event ID `3` for network connection data shows traffic going to a different service/server.

Event ID `4769` has the TGS request data and should contain:
- _Service Name (SPN)_ → the hostname and service being accessed.
- _Service ID_ → the service account associated with that SPN
- _Client Address_ → the [[IP]] of the host requesting the service ticket.

When the behavior is normal:
- The SPN and Service ID **must match the actual server** the client is going to access.
- The Client Address **must match the workstation originating the request**.

When the behavior is malicious:
- The attacker replays a ticket originally issued for _another host or another service_.
- So the **Service Name/Service ID reflect the stolen ticket**, not the attacker’s real target.
- The Client Address becomes the attacker’s machine → creating **inconsistent metadata**.

Event ID `3`, [[Sysmon]], has the network connection data and should contain:
   - _Source Address_ → the actual [[IP]] of the machine initiating the connection.
   - _Destination Address_ → the real IP/host the machine is communicating with.
   - _Destination [[Port]]_ → the port of the service being accessed.

When the behavior is normal:
   - The Destination Address should match the host in the SPN from Event ID `4769`.
   - Source Address should match the Client Address from `4769`.

When the behavior is malicious:
  - Destination Address ≠ SPN hostname from `4769`.
   - The SPN represents where the ticket _was originally intended to be used_, while Event ID 3 shows where the attacker is _actually_ using it.

###### Technique 3
Look for Event ID `4771` which is for [[Kerberos]] *pre-authentication failed*, and correlate the fields `Pre-Auth Type` and the `Failure Code`
- `Pre-Auth Type = 2` means that AS-REQ is sent, which is to create a TGT, is sent with an Encrypted Timestamp. This means that the client sent a timestamp encrypted with their own password hash. The [[Domain Controller]] decrypts the timestamp and checks for the matching passwords.
- `Failure Code = 0x18` means that the `pre-authentication information was invalid`, meaning that the [[Domain Controller]] couldn't decrypt the timestamp, hence, it was encrypted with a wrong key.

This happens because attacker's don't know the actual password, they have the ticket, therefore, they generate an incorrectly encrypted timestamp.
- This happens when the injected ticket tries to renew the session, or the attacker tries to access something requiring new authentication.
- This detection won't work in legitimate scenarios as a workstation will always produce a correct encryption of the timestamp.

---
