### General Notes

This is another authentication method used by [[Active Directory]], and it includes these terms:
- *LM*: LAN Manager
- *NTLM*: NT Lan Manager, NT Hash
- *NTLMv1*
- *NLTMv2*

LM and NTLM are the hash names, and NTLMv1 and v2 are the authentication protocols that use these hashes.

---
### LM

This is a password storage mechanism used by the Windows operating system, and they are stored on:
- *Security Account Manager (SAM)* database on windows hosts.
- `NTDS.DIT` database on the [[Domain Controller#NTDS.DIT|Domain Controller]].
- The use of LM hashes can be disallowed using [[Group Policy Object]]s.

> This hashing algorithm has been turned off by default as it is weak, and limits passwords to a maximum of 14 characters. The password is also case insensitive, and all characters are converted to upper case before generating the hash value. Very easy to crack using *Hashcat*.

Before hashing, the 14 character password is split into 2 seven character chunks.
- If password is less than 14 characters, it will be padded with `NULL` characters.
- Two *DES* keys are created from chunk, and then each chunk is encrypted using the string `KGS!@#$%`.
- The two values are then concatenated creating the LM hash.

---
###  NTLM

The NT hash is the MD4 hash of the little-endian UTF-16 value of the password.
- Stronger than LM but still susceptible to brute force attacks easily, and to the *pass the hash attack*, where the ciphertext of the password (hash) can be used without knowing the plaintext of the password.

> The NTLM is also stored in the SAM on Windows machines and in the `NTDS.DIT` on Domain Controllers.

Hashes are stored in this form:
```
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
```
- `Rachel` is the username.
- `500` is the [[Objects#RIDs|RID]]. 500 is known for the *administrator* account.
- First hash is the LM hash.
- Second hash is the NT hash.

---
### NTLMv1, Net-NTLMv1

The NTLM authentication works by using a challenge-response [[Protocol]].
1. Client sends a `NEGOTIATE_MESSAGE` to server with the username and the target domain name to authenticate to.
2. Server responds with `CHALLENGE_MESSAGE` to client to verify identity with a nonce.
3. Client responds with `AUTHENTICATE_MESSAGE` that is composed of the NT Hash of the password, which is encrypted with the nonce sent by the server.
4. The server verifies the response as it knows the NT hash from the database, so it computes the encryption with the nonce and verifies the user if they match.

---
### NTLMv2, Net-NTLMv2

This is the NTLM authentication protocol of choice as it used stronger cryptography, prevents replay attacks, and uses more contextual information.

The protocol works like this:
1. `NEGOTIATE_MESSAGE` by client with username.
2. Server responds with `CHALLENGE_MESSAGE` to client to verify identity with a nonce.
3. Client responds with `AUTHENTICATE_MESSAGE` that is composed of the NT hash with more data like the timestamp, a client nonce, and the domain name creating a tougher hash.
4. Server verifies response by doing the same calculations.

---

