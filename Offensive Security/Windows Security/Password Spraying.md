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

> Checkout the [[Splunk Queries#Detecting Password Spraying]].

---
