### General Notes

This is the server that allows the AD to have a public key cryptographic infrastructure with [[Digital Signatures]] and [[Certificates]].
- It allows for the creation and running of a *Certificate Authority*, which is the server that issues, signs, and manages digital certificates.

Certificates are usually valid for more than 1 year, and resetting a user's password does not invalidate the certificate.
- This makes this a target by attackers.
- If the private key of the Certificate Authority is compromised, *Golden Certificates* can be forged, which can be used to impersonate any user or computer in the [[Active Directory]].

> [Certificate Vulnerabilities](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf).

##### Certificates

The certificate has the following fields:
- *Subject* - The owner of the certificate.
- *Public Key* - Associates the Subject with a private key stored separately.
- *NotBefore* and *NotAfter* dates - Define the duration that the certificate is valid.
- *Serial Number* - An identifier for the certificate assigned by the CA. 
- *Issuer* - Identifies who issued the certificate (commonly a CA).
- *SubjectAlternativeName* - Defines one or more alternate names that the Subject may go by.
- *Basic Constraints* - Identifies if the certificate is a CA or an end entity, and if there are any constraints when using the certificate.
- *Extended Key Usages (EKUs)* - Object identifiers (OIDs) that describe how the certificate will be used. Common EKU OIDs include: 
	- Code Signing (OID 1.3.6.1.5.5.7.3.3) - The certificate is for signing executable code. 
	- Encrypting File System (OID 1.3.6.1.4.1.311.10.3.4) - The certificate is for encrypting file systems. 
	- Secure Email (1.3.6.1.5.5.7.3.4) - The certificate is for encrypting email. 
	- Client Authentication (OID 1.3.6.1.5.5.7.3.2) - The certificate is for authentication to another server (e.g., to AD).
	- Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2) - The certificate is for use in smart card authentication.
	- Server Authentication (OID 1.3.6.1.5.5.7.3.1) - The certificate is for identifying servers (e.g., [[HTTPS]] certificates).
- *Signature Algorithm* - Specifies the algorithm used to sign the certificate.
- *Signature* - The signature of the certificates body made using the issuer’s (e.g., a CA’s) private key.

---


