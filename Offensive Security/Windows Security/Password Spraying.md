### General Notes

This is a brute force attack were an attacker distributes their efforts. 
- They throw a set of easily guessed and known passwords on a lot of usernames, avoiding the lockout that happens when a single username has a lot of password attempts.

> The [Spray](https://github.com/Greenwolf/Spray) tool can be used to perform this attack.

---
### Detecting Password Spraying

This can be detected by observing the following [[Windows Events Log]] Event IDs:
- `4625` : Failed logon. If we see this event ID from different user accounts but originating from the same source [[IP]] address.
- `4768` and `ErrorCode 0x6 - Kerberos Invalid Users`
- `4768` and `ErrorCode 0x12 - Kerberos Disabled Users`
- `4776` and `ErrorCode 0xC0000064 - NTLM Invalid Users`
- `4776` and `ErrorCode 0xC000006A - NTLM Wrong Password`
- `4648` - Authenticate Using Explicit Credentials
- `4771` - [[Kerberos]] Pre-Authentication Failed

> Checkout the [[Splunk Attack Specific Queries#Detecting Password Spraying]].

---
## Event IDs & Their Meaning

### Kerberos Events (logged on the DC)

**4768 — Kerberos Authentication Service (AS-REQ) Ticket Request** Fired when a client requests a TGT from the KDC. Both successes and failures log here. The `Result Code` field tells you the outcome.

|Error Code|Meaning|Detection Value|
|---|---|---|
|`0x6`|`KDC_ERR_C_PRINCIPAL_UNKNOWN` — username does not exist in AD|Username enumeration, spray with bad userlist|
|`0x12`|`KDC_ERR_CLIENT_REVOKED` — account exists but is disabled or locked|Spraying against disabled/stale accounts|
|`0x18`|`KDC_ERR_PREAUTH_FAILED` — wrong password (pre-auth failed)|Password spray, brute force|

> `0x6` is especially useful for enumerating valid users — the KDC tells you the user doesn't exist, which means an attacker can distinguish valid vs. invalid names. Tools like Kerbrute exploit this.

---

**4771 — Kerberos Pre-Authentication Failed** Fired specifically when a user _exists_ but the pre-authentication data is wrong (bad password). Think of it as the bad-password companion to 4768. The key difference from 4768/0x18 is that 4771 fires on the DC and includes the client IP.

- High-value for password spray detection
- Correlate: many 4771s across many accounts from one IP = spray; many 4771s against one account = brute force

---

### NTLM Events (logged on the authenticating machine, not necessarily the DC)

**4776 — Credential Validation via NTLM (NTLM Authentication Attempt)** Fired on the machine that validated the credentials — usually a DC or local machine. Covers both domain and local account auth.

|Error Code|Meaning|Detection Value|
|---|---|---|
|`0xC0000064`|`STATUS_NO_SUCH_USER` — username doesn't exist|Username enumeration|
|`0xC000006A`|`STATUS_WRONG_PASSWORD` — user exists, wrong password|Password spray, brute force|
|`0xC000006D`|Generic logon failure (bad creds)|Broad failure|
|`0xC0000234`|Account locked out|Result of sustained brute force|

> Unlike Kerberos, 4776 doesn't give you a source IP in the event itself. You need to correlate with 4624/4625 to get the originating host.

---

### Explicit Credential Usage

**4648 — A Logon Was Attempted Using Explicit Credentials** Fires when a process uses credentials other than the currently logged-on user — e.g., `runas`, `net use`, `WMI` with alternate creds, or tools like Mimikatz's `sekurlsa::pth` (pass-the-hash).

- Legitimate use: sysadmins using `runas` to elevate
- Malicious use: lateral movement with harvested credentials, PTH, PTT
- Key fields: **Subject** (who initiated), **Account Whose Credentials Were Used**, **Target Server** (where they're trying to auth to)
- High-fidelity when: the Subject and target account differ AND the target is a sensitive system (DC, file server)

---

## Detection Logic Summary

|Scenario|Events to Chain|
|---|---|
|Username enumeration (Kerberos)|Many `4768/0x6` from one IP|
|Username enumeration (NTLM)|Many `4776/0xC0000064` from one source|
|Password spray (Kerberos)|Many `4771` or `4768/0x18` across many accounts, low rate per account|
|Password spray (NTLM)|Many `4776/0xC000006A` across many accounts|
|Brute force|Many failures against _one_ account → 4740 (lockout)|
|Lateral movement / PTH|`4648` with mismatched subject/target + `4624 Type 3` on remote host|