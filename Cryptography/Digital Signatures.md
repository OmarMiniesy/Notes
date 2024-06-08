### General Notes

Digital signatures are tools used to provide **authenticity**, **integrity**, and **non-repudiation** during [[Encryption]] processes and network communication.
* Used by Asymmetric [[Encryption]], or public key cryptography.

1. **Authentication**: Digital signatures help in verifying the identity of the sender of a message or the signer of a document. Because a digital signature can only be created by the owner of the private key, which is supposed to be kept secret, the signature is tied directly to the signer.
2. **Integrity**: A digital signature ensures that the content has not been altered since it was signed. If even a minor change is made to the original document or message after signing, the signature will fail to validate when checked. 
	* This is because digital signatures are based on hashing: the process of signing involves creating a hash of the message's contents, which is then encrypted with the signer's private key. 
	* The recipient (or verifier) generates a new hash from the received message and decrypts the signature with the public key to compare the hashes. If they match, the message is confirmed to be unchanged.
3. **Non-repudiation**: It prevents the signer from denying the authenticity of their signature on a document or the sending of a message that they signed. Since the digital signature is unique to both the signer and the document, the signer cannot claim they did not sign the document as long as the private key remains secure.

Therefore, digital signatures must:
* Depend on the message itself.
* Use information unique to sender.
* Be easy to produce, recognize, and verify.
* Hard to forge.

---
