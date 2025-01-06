### General Notes

This is an extension on [[Domain Name System (DNS)]].
- Provides integrity and authentication on all DNS messages sent.
- Confidentiality is not something needed, as DNS records contain information that is not private or sensitive.

> DNSSEC is important as it ensures that the records present in the system are real authentic records that point to legitimate servers and domains.

DNSSEC utilizes [[Digital Signatures]] so that only those that have the necessary private signing key can create records.
- The public key that checks the signature is known by all, hence, anyone can check the integrity and authenticity of that signature on the record.

DNSSEC creates a chain of trust from root server all the way down to nameservers.
- Trust is delegated from the root server and downwards throughout the chain.
- This defends against malicious nameservers sending out signed records that are malicious.

--- 
### DNSSEC Records

DNSSEC introduces some new records that are used to sign records and to create a chain of trust.

###### DNSKEY

This record stores the asymmetric [[Encryption]] keys that are used to verify [[Digital Signatures]].
- **Zone Signing Key (ZSK)**: This key is used to sign the actual DNS data inside of a zone, ensuring that these records have not been tampered with.
- **Key Signing Key (KSK)**: This key is used to sign the **ZSK** itself, ensuring that it can be trusted.

The reason why there is a **KSK** is to create a secret that is used less frequently to reduce the risk of compromise, and reduce its exposure.
- If the **ZSK** is compromised, then only the data in the zone needs to be signed.
- If the **KSK** is compromised, then the entire chain of trust is compromised.

> **KSK** signs the DNSKEY records, while **ZSK** signs DNS data. Both these operations produce RRSIG records.

###### RRSIG

This record stores the digital signatures for DNS records.
- This record is used by DNS resolvers and other servers to verify that the DNS data being sent alongside this record is authentic and has its integrity maintained.

> There is also an RRSIG record for the DNSKEY record.

###### DS (Delegation Signer)

This record is used to establish a chain of trust from the parent zone to the child zone.
- This record found in the parent zone has a hash of the value found in the child zone **KSK**.

> When a resolver receives response from a child zone, it can use the parent DS to verify the child's **KSK**, ensuring that the parent trusts the child.

---
### DNSSEC Process

#### Step 1: Zone Signing

- **Key Generation**:
    - **Description**: In the initial step, DNSSEC relies on asymmetric cryptography, which necessitates generating a pair of cryptographic keys: a public key and a private key. These keys are pivotal for signing and validating DNS data.
    - **Details**: Two key pairs are created: the Zone Signing Key (ZSK) and the Key Signing Key (KSK). The ZSK is used to sign the actual DNS data within a zone, while the KSK is used to sign the ZSK itself. This separation enhances security by limiting the exposure of the KSK, which is used less frequently than the ZSK.
- **Zone Signing**:
    - **Description**: Signing the zone data ensures that any DNS data provided can be verified for integrity and authenticity.
    - **Details**: Using the ZSK, each DNS record set (such as A, MX, and TXT records) within the zone is signed, generating a corresponding Resource Record Signature (RRSIG). These RRSIG records are critical because they allow resolvers to verify that the data has not been tampered with since it was signed.
- **Key Signing**:
    - **Description**: The final part of the signing process involves signing the ZSK with the KSK to establish a chain of trust within the zone.
    - **Details**: The KSK is used to sign the DNSKEY record that contains the ZSK, producing a signed DNSKEY record. This process ensures that the ZSK can be trusted by external parties, as it has been verified by the KSK.

#### Step 2: Distribution of Keys

- **Publish DNSKEY Records**:
    - **Description**: Making the public keys available to DNS resolvers is essential for the verification of signed DNS data.
    - **Details**: The DNSKEY records, which include the public parts of both the ZSK and KSK, are published in the zone file. When a resolver requests DNSSEC data, it retrieves these DNSKEY records to validate the signatures of the DNS records.
- **DS (Delegation Signer) Records**:
    - **Description**: DS records link the child zone's DNSKEY to the parent zone, creating a chain of trust from the parent to the child zone.
    - **Details**: The DS record contains a hash of the child zone’s KSK and is stored in the parent zone. When a resolver receives a DNS response, it can use the DS record from the parent zone to verify that the child zone’s KSK is valid, thus ensuring a continuous chain of trust.

#### Step 3: DNS Resolution with DNSSEC

- **DNS Query**:
    - **Description**: The process of resolving a domain name to an IP address involves requesting additional DNSSEC records to validate the response.
    - **Details**: When a DNS resolver queries a domain name, it indicates that it supports DNSSEC by requesting DNSSEC-related records (such as RRSIG, DNSKEY, and DS) alongside the standard DNS records.
- **Response with DNSSEC Records**:
    - **Description**: The authoritative DNS server responds with the requested DNS records and the corresponding DNSSEC records necessary for validation.
    - **Details**: The response includes the original DNS records (e.g., A or MX records) and their associated RRSIG records, along with the DNSKEY record. Also sent is the RRSIG for the DNSKEY record. This enables the resolver to validate the authenticity and integrity of the DNS data received.
- **Validation by Resolver**:
    - **Description**: The resolver verifies the DNS response by checking the signatures using the DNSSEC records.
    - **Details**: The resolver uses the DNSKEY record to verify the RRSIG signatures on the DNS data. It also checks the DS record from the parent zone to validate the KSK. If all signatures are valid, the resolver trusts the DNS data. If any signature fails, the data is considered compromised and is discarded.

---
### Results and Example

#### 1. **DNS Query**

A DNS resolver initiates a query to resolve the IP address for `www.google.com`. The resolver indicates that it supports DNSSEC by setting the DNSSEC OK (DO) flag in the query.

#### 2. **Response from Root Server**

The resolver first queries a root DNS server. The root server does not have the IP address but responds with a referral to the `.com` TLD (Top-Level Domain) servers. The response includes:

- **Referral to .com TLD servers**
- **RRSIG for the referral**
- **DNSKEY for the root zone**
- **RRSIG for the DNSKEY of the root zone**

The resolver uses the root DNSKEY to validate the RRSIG for the referral response, ensuring the referral is authentic.

#### 3. **Response from .com TLD Server**

Next, the resolver queries a `.com` TLD server. The TLD server responds with a referral to Google's authoritative DNS servers. The response includes:

- **Referral to Google’s authoritative servers**
- **RRSIG for the referral**
- **DNSKEY for the .com TLD**
- **RRSIG for the DNSKEY of the .com TLD**

The resolver uses the `.com` DNSKEY to validate the RRSIG for the referral response.

#### 4. **Response from Google’s Authoritative Server**

The resolver then queries Google's authoritative DNS server for `www.google.com`. The authoritative server responds with the IP address and DNSSEC-related records. The response includes:

- **A record for [www.google.com](http://www.google.com/) (e.g., 172.217.14.228)**
- **RRSIG for the A record**
- **DNSKEY for google.com**
- **RRSIG for the DNSKEY of google.com**
- **DS record for google.com (if available)**
- **RRSIG for the DS record**

#### 5. **Validation by Resolver**

The resolver performs the following validations:

- **Validate the DNSKEY**: The resolver uses the DS record from the `.com` TLD to validate the DNSKEY for `google.com`.
- **Validate the RRSIG for DNSKEY**: The resolver uses the validated DNSKEY to check the RRSIG for the DNSKEY record.
- **Validate the RRSIG for the A Record**: Finally, the resolver uses the validated DNSKEY for `google.com` to verify the RRSIG on the A record for `www.google.com`.

If all validations succeed, the resolver trusts the response and returns the IP address (e.g., 172.217.14.228) to the client.

> Note that we implicitly trust all signed messages from the root, because the root is our trust anchor. In practice, all DNS resolvers have the root’s public key hardcoded, and any messages verified with that hardcoded key are implicitly trusted. Since we trust the root, then we trust the DS record that verifies its child. Hence, we trust the child, and so on. This is the chain of trust.

---
