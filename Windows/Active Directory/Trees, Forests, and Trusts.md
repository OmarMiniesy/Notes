### General Notes

Simple [[Active Directory|Active Directory]] setups can be built with a singular Windows domain.
- In the case that more than one domain needs to exists, then comes the concepts of _Trees_, _Forests_, and _Trusts_.

> To manage multiple domains in a single organization, a new Security Group needs to be introduced call Enterprise Admins. This group grants users admin privileges over all the domains in an enterprise.

---
### Trees

A group of one or more *Domains* that have the same namespace, that is, all the domains that are subdomains of a single domain.
- Domains and subdomains in the Tree share a parent-child *trust relationship*.

All domains in a tree share a standard *Global Catalog* which contains all information about objects that belong to the tree.

---
### Forests

A forest is a collection of [[Active Directory]] *trees*
- It is the biggest container in AD, and it can contain one or multiple domains.
- Forests can have *trust relationships* with other forests.

There is an automatic *two-way transitive [[Kerberos]] trust relationship* between all domains in the same forest.
- [[Domain Controller]]s in the parent domain trusts *TGTs* issued by Domain Controllers in the child, and vice versa.

---
### Trust Relationships

Trusts are used to establish forest to forest, or domain to domain authentication.
- This allows users to access resources in domains outside of their domains.

Trusts can be _transitive_ or _non-transitive_.
- A _transitive_ trust means that trust is extended to [[Objects]] that the child domain trusts.
- In a _non-transitive_ trust, only the child domain itself is trusted.

There are _one-way_ and _two-way_ (bidirectional) trust relationships.
- _Two-way_ trusts means users from both domains can access resources.
- _Two-way_ trust relationships are formed by default when domains are joined in trees or forests.
- _One-way_ trust relationships allow users in the the trusted domain to access resources in the trusting domain.

The direction of trust is opposite to the direction of access.
- If a domain trusts another domain, then the trusted domain can access the resources of the domain that trusts it.

---
