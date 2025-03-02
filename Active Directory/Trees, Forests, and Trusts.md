### General Notes

Simple [[Active Directory/Active Directory|Active Directory]] setups can be built with a singular Windows domain.
- In the case that more than one domain needs to exists, then comes the concepts of _Trees_, _Forests_, and _Trusts_.

> To manage multiple domains in a single organization, a new Security Group needs to be introduced call Enterprise Admins. This group grants users admin privileges over all the domains in an enterprise.

---
### Trees

This is used to join domains that share the same namespace.
- For example, 2 subdomains of a single parent domain.

Here, the 2 subdomains will be the child nodes of the parent domain in the Tree structure.

---
### Forests

In the case of domains with different namespaces, there will be different _Trees_ present.
- Combining these trees with different namespaces creates a _Forest_.

---
### Trust Relationships

Domains arranged in _Trees_ and _Forests_ need to have _trust relationships_ configured between them to allow users to access content between these domains.

There are _one-way_ and _two-way_ trust relationships.
- Two-way trust relationships are formed by default when domains are joined in trees or forests.

The direction of trust is opposite to the direction of access.
- If a domain trusts another domain, then the trusted domain can access the resources of the domain that trusts it.

---
