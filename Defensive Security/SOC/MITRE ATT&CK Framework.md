### General Notes

This is a globally accessible knowledge base of techniques and tactics based on real world threats and threat actors.

- It is short hand for _Adversarial Tactics, Techniques and Common Knowledge_.
- It is a documentation for the _tactics_, _techniques_ and _sub-techniques_, and _procedures_ (TTPs) carried out by Advanced Persistent Threats (APTs).

> APTs are cyberattacks that use advanced techniques to perform attacks, and try to maintain long term access to a target's network (persistence).

The framework is organized in a matrix structure, and can be filtered based on several criteria like operating system and device type.

- [Enterprise](https://attack.mitre.org/matrices/enterprise/)
- [PRE](https://attack.mitre.org/matrices/enterprise/pre/)
- [Windows](https://attack.mitre.org/matrices/enterprise/windows/)
- [macOS](https://attack.mitre.org/matrices/enterprise/macos/)
- [Linux](https://attack.mitre.org/matrices/enterprise/linux/)
- [Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Network](https://attack.mitre.org/matrices/enterprise/network/)
- [Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [Mobile](https://attack.mitre.org/matrices/mobile/)
- [Android](https://attack.mitre.org/matrices/mobile/android/)
- [iOS](https://attack.mitre.org/matrices/mobile/ios/)
- [ICS](https://attack.mitre.org/matrices/ics/)

---

### Framework Uses

**Detection and Response** : The framework supports SOCs in devising detection and response plans based on recognized attacker TTPs, empowering security teams to pinpoint potential dangers and develop proactive countermeasures.

**Security Evaluation and Gap Analysis** : Organizations can leverage the ATT&CK framework to identify the strengths and weaknesses of their security posture, subsequently prioritizing security control investments to effectively defend against relevant threats.

**SOC Maturity Assessment** : The ATT&CK framework enables organizations to assess their Security Operations Center (SOC) maturity by measuring their ability to detect, respond to, and mitigate various TTPs. This assessment assists in identifying areas for improvement and prioritizing resources to strengthen the overall security posture.

**Threat Intelligence** : The framework offers a unified language and format to describe adversarial actions, enabling organizations to bolster their threat intelligence and improve collaboration among internal teams or with external stakeholders.

**Cyber Threat Intelligence Enrichment** : Leveraging the ATT&CK framework can help organizations enrich their cyber threat intelligence by providing context on attacker TTPs, as well as insights into potential targets and indicators of compromise (IOCs). This enrichment allows for more informed decision-making and effective threat mitigation strategies.

**Behavioral Analytics Development** : By mapping the TTPs outlined in the ATT&CK framework to specific user and system behaviors, organizations can develop behavioral analytics models to identify anomalous activities indicative of potential threats. This approach enhances detection capabilities and helps security teams proactively mitigate risks.

**Red Teaming and Penetration Testing** : The ATT&CK framework presents a systematic way to replicate genuine attacker techniques during red teaming exercises and penetration tests, ultimately assessing an organization's defensive capabilities.

**Training and Education** : The comprehensive and well-organized nature of the ATT&CK framework makes it an exceptional resource for training and educating security professionals on the latest adversarial tactics and methods.

---

### Framework Structure

The framework provides a model for adversarial behavior, and there is a unified nomenclature for this framework.

### **1. Tactics** - The phases of the attack lifecycle

The _tactics_ represents the phase of the attack, these are the names of the columns.

### **2. Techniques** - The actions implemented in that phase

Inside each _tactic_, there are several _techniques_ that can be used. These _techniques_ are the types of action taken in that phase of the attack.

- There are also _sub-techniques_ for these _techniques_, and these outline the implementation of a specific _technique_ in more detail, or for a more specific use case.

### **3. Procedures** - Examples of APTs performing these actions

For each _technique_ and _sub-technique_, there are _procedures_ which outline all of its known implementations of previous APTs that successfully managed to perform these actions.

- The software used in the attack.
- The operating systems they target.

### **4. Mitigations** - Defense strategies, detections and mitigations

For _techniques_, there are several defense and mitigation examples to help defend against such actions.

---
