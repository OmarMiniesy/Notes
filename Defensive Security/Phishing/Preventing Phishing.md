### General Notes

Modern systems use technical controls to detect and block phishing using:
- **Email filtering** based on IP and domain reputation.
- **Secure Email Gateways** scan messages to detect malicious techniques.
- **Link Rewriting** replaces suspicious or unknown URLs with safe and redirected ones to scan and verify the links.
- **Sandboxing**: Isolates and tests suspicious links and attachments to check for malicious behavior.

---
### Sender Policy Framework (SPF)

This is used to authenticate the sender of the email.
- SPF records are used to verify that a mail server is authorized to send emails for a domain.
- SPF records are DNS TXT records that contain a list of the IP addresses that are allowed to send emails on behalf of the domain.

When an email is sent, the receiving mail server checks the domain SPF records to verify if the sending server is authorized to send messages on behalf of the domain.

|Verification Result|Intended Action|
|---|---|
|Pass, Neutral, None|Accept (Allow and process the email)|
|SoftFail, PermError|Flag (Mark as suspicious but allow)|
|Fail, TempError|Reject (Immediately discard the email)|

---
### DomainKeys Identified Mail (DKIM)

This is used to authenticate the email being sent.
- DKIM records exist in the DNS.
- DKIM records survive email forwarding.

> This utilizes public and private key pairs for authentication.

When an email is sent, the sending mail server uses a private key to add a digital signature. The signature is added to the email in the `DKIM-Signature header`.
- The receiving server retrieves the public key from the domain's DKIM record to verify that the message came from the domain.

---
### Domain-Based Message Authentication, Reporting, and Conformance (DMARC)

DMARC uses *alignment* to tie the results of SPF and DKIM.
- It then tells the email recipient how to handle the message that does not comply using a *policy*.

- **Monitoring** (`p=none`) no impact on mail flows (only DMARC feedback is collected).
- **Quarantine** (`p=quarantine`) messages that fail DMARC (e.g. move to the spam folder)
- **Reject** (`p=reject`) messages that fail DMARC (don’t accept the mail at all).

---
### Secure/Multipurpose Internet Mail Extensions (S/MIME)

This is a standard protocol for sending digitally signed and encrypted messages, based on public key cryptography.
- The sender signs the message with their private key and the recipient verifies the sender identity using the sender's public key.
- The sender encrypts the message using the recipient public key, so that only the recipient can decrypt it with their private key.

---
