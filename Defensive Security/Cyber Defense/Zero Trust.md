## General Notes

Zero trust assumes that an attacker is present in the environment, meaning the network is not safe.

- No implicit trust is assumed, with continuous analysis and evaluation of risks being conducted.
- Trust is never implicitly granted, but it must be continuously evaluated. If trust is granted, the minimum level of privileges is granted.
- Protections and mitigations are constantly applied such as minimizing access to resources and constantly requiring authentication and authorization of the identity posture of the requesting access.

<aside> 💡

Least privilege per-request access along with access control enforcement to become as granular as possible.

</aside>

This is mainly to prevent breaches, and to severely limit lateral movement.

- It is a set of guiding principles, system designs, and operations.
- The focus is on authentication and authorization while minimizing delays in authentication mechanisms.
- Access rules are granular to enforce least privilege to perform just the needed action in the request.

When any request is sent, the Zero Trust Policy Decision/Enforcement point checks the following:

- What is the level of confidence about the subject’s identity for this unique request?
- Is access to the resource allowable given the level of confidence in the subject’s identity?
- Does the device used for the request have the proper security posture?
- Are there other factors that should be considered and that change the confidence level (e.g., time, location of subject, subject’s security posture)

These policy enforcement points should be moved as close as possible to the resource being requested to ensure that there is a minimal area of implicit trust after a resource request is approved.

The enterprise should also have _dynamic risk based policies_ for requesting access, and there should be a system set up to ensure that these policies are both met and enforced correctly.

## Tenets of Zero Trust

These are the ideal goals of a zero trust architecture:

1. **All data sources and computing services are resources**
2. **All communication is secure regardless of network location:** Trust should not be automatically granted based on the device existing in the enterprise network.
3. **Access to individual enterprise resources should be granted based on sessions:**
    1. Access to resources is granted per individual session.
    2. Before access is granted, the system evaluates the trust of the requestor to ensure it is authorized.
    3. Access is then granted in a least privilege manner with only the necessary access to complete the task.
    4. Recent authentications are used to make decisions about the trust of the requestor.
    5. Each resource requires its own authorization process.
4. **Access is determined using a dynamic risk based policy:**
    1. The state of the client identity
    2. The application/service being accessed.
    3. The requesting asset.
    4. Behavioral and environmental attributes.
5. **The integrity and security posture of all assets is measured and monitored**: Assets with known vulnerabilities, known to be subverted, or personally owned devices can be treated differently.
6. **Resource authentication and authorization is dynamic and enforced before access is allowed.**
7. **Enterprise should collect information about the state of assets, the infrastructure, its network, and communications to improve its security posture.**

## Logical Components of Zero Trust Architecture

**Policy Engine (PE):** This is the decision granting point that grants/revokes access to a resource. It utilizes enterprise policy as well as input from other resources shown above to make its decision. This component also logs the decision chosen.

**Policy Administrator (PA):** Responsible for establishing the communication between the requestor and the resource once the _PE_ makes the decision. It either establishes the connection or shuts it down, and it does this using session specific authentication or credentials. This component communicates with the _Policy Enforcement Point_ and configures it to start the communication or shut it down.

**Policy Enforcement Point (PEP):** This is responsible for enabling, monitoring, and terminating connections between the requestor and the resource. It communicates with the _PA_ to forward and receive policy updates. After the _PEP_ is then the trusted zone.

### Data Sources as Input for the Policy Engine

**Continuous Diagnostics and Mitigation Systems (CDM):** Provides the _PE_ with information about the asset making a request such as its OS and its patching, the integrity of software installed, if the asset has known vulnerabilities, and so on. It is also responsible for applying policies on non-enterprise devices active on the enterprise infrastructure.

**Industry Compliance System:** Ensuring the enterprise is compliant with the regulations applied on it.

**Threat Intelligence:** Information from external or internal sources that include data on newly discovered attacks, vulnerabilities, software flaws, malware, or attacks on assets.

**Activity Logs:** Provides feedback on the security posture of the enterprise systems.

**Data Access Policies:** Rules that define access to resources, and they provide basic access privileges for accounts and applications in the enterprise.

**Public Key Infrastructure (PKI):** Responsible for generating and logging all certificates issued.

**ID Management:** Responsible for creating, storing, and managing user accounts and identity records with subject information like role, access attributes, name, email, and certificates.

**SIEM:** Used to refine policies and warn against attacks.

### Trust Algorithm

This is used by the Policy Engine to grant or deny access to a resource. It takes in the following:

- **Access Request:** This is the request from the subject and it contains the resource requested. It also contains information such as the OS version, patch level, and software used by the requestor.
- **Subject Database:** This is the information of the person requesting access to the resource, contains identity related information.
- **Asset Database:** This contains the known status of each asset, and it compares it to the observable status of the asset making the request. It compares the OS version, software present, integrity, location, and patch level.
- **Resource Requirements:** minimal requirements for access to the resource such as assurance levels, data sensitivity.
- **Threat Intelligence:** Information feed about threats and malware. Can also include communication information about assets that might be suspected.

---
### Resources

- [NIST SP 800-207](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf)

---
