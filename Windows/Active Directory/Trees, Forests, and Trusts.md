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

---
### Trust Relationships

Domains arranged in _Trees_ and _Forests_ need to have _trust relationships_ configured between them to allow users to access content between these domains.

There are _one-way_ and _two-way_ trust relationships.
- Two-way trust relationships are formed by default when domains are joined in trees or forests.

The direction of trust is opposite to the direction of access.
- If a domain trusts another domain, then the trusted domain can access the resources of the domain that trusts it.

---
