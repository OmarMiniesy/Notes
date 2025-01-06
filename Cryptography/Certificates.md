### General Notes

Public key certificates, also known as digital certificates, are electronic documents that certify the ownership of a public key. 

> Used in [[Encryption#Asymmetric Encryption]]

They include the:
* Public key being certified.
* Information about the owner that holds private key.
* The [[Digital Signatures]] of a trusted third party entity called Certificate Authority (CA).

---

### How Public Key Certificates Work

1. **Certificate Issuance**:
    - A person or organization (the certificate applicant) generates a key pair (a public key and a private key) and submits a certificate signing request (CSR) to a Certificate Authority (CA). The CSR includes the public key and identifying information, such as the organization's name and website address.
    - The CA verifies the applicant's identity and the legitimacy of the request. This process varies depending on the type of certificate and can range from simple domain validation to thorough vetting of the organization's legal identity.
    - Once verified, the CA creates a digital certificate containing the applicant's public key, information about the CA, and other relevant details. The CA then signs this certificate with its private key.
    
2. **Certificate Use**:
    - The certificate holder can then use the certificate to facilitate secure communications, prove their identity, or sign documents and code. For example, a website might use its certificate to establish a secure [[HTTPS]] connection with users' web browsers.
    - When a user (or user's software) receives the certificate, they can verify the signature on it using the CA's public key, which is typically included in a list of trusted CAs distributed with web browsers and operating systems. This verifies that the certificate is legitimate and not forged, as only the CA's private key could have created a valid signature for its public key.
    
3. **Trust Model**:
    - The trustworthiness of public key certificates relies on the trustworthiness of the CA issuing them. Users trust that the CA has properly verified the identity of the certificate holder before issuing the certificate.
    - This model allows users to trust a certificate they have never seen before based on their trust in the CA. If a CA's security is compromised or it fails to properly verify identities, this trust can be undermined.
    
4. **Revocation and Expiration**:
    - Certificates have a validity period after which they expire. To maintain security, certificates need to be renewed periodically.
    - If a private key is compromised or if a certificate is issued in error, the certificate can be revoked before its expiration. Certificate revocation lists (CRLs) or the Online Certificate Status Protocol (OCSP) are used to distribute information about revoked certificates.

---
### Certificate Transparency Logs

These are public *append only* records that hold the new SSL/[[Transport Layer Security (TLS)]] certificates.
- Basically, whenever a new certificate is issued by a Certificate Authority, it is added to multiple Transparency Logs.

> This is like a global registry of certificates.

Since CT logs provide a definitive record of certificates issued for a domain and its subdomains, it is very effective for [[Subdomain Enumeration]].
- Access to direct information.
- Access to old and expired certificates which might relate to subdomains that are no longer maintained.

---
